"""Process-local runtime state: credentials, event hubs, and run heartbeats.

Credentials live only in memory: the operator types them at the start of a
session and they are never written to the database.

Each Migration gets one Hub that fans out log/progress events to any number
of SSE listeners.

Heartbeats are the one piece of state here that *is* written down: a row being
worked on gets `heartbeat_at` stamped every 30 seconds, which is how
`migrator.supervisor` tells "still running" from "the process died holding
this". WORKER_ID identifies this process, and changes on every boot.
"""

from __future__ import annotations

import logging
import os
import socket
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass

from django.db import connection
from django.utils import timezone


logger = logging.getLogger(__name__)

# Identifies this process for the lifetime of this process only: a restart
# always produces a new one, which is exactly what makes it useful.
WORKER_ID = f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:8]}"


@dataclass
class Credentials:
    old_password: str = ""
    new_password: str = ""


class Hub:
    """Per-migration event broadcaster, with a small replay buffer."""

    def __init__(self, history: int = 500) -> None:
        self._lock = threading.Lock()
        self._listeners: list[deque] = []
        self._history: deque = deque(maxlen=history)
        self._seq = 0

    def publish(self, event: dict) -> None:
        with self._lock:
            self._seq += 1
            event = {"seq": self._seq, "ts": time.time(), **event}
            self._history.append(event)
            for q in self._listeners:
                q.append(event)

    def subscribe(self, since_seq: int = 0) -> deque:
        q: deque = deque(maxlen=2000)
        with self._lock:
            for ev in self._history:
                if ev["seq"] > since_seq:
                    q.append(ev)
            self._listeners.append(q)
        return q

    def unsubscribe(self, q: deque) -> None:
        with self._lock:
            try:
                self._listeners.remove(q)
            except ValueError:
                pass

    def snapshot(self) -> tuple[list[dict], int]:
        """Return (history events, current max seq) without subscribing."""
        with self._lock:
            return list(self._history), self._seq


class _State:
    """Hubs and running threads are keyed by an opaque id: a Migration's int pk,
    or a namespaced string like ``backup:7`` for a standalone BackupJob. The two
    share this registry but can never collide."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._creds: dict[int, Credentials] = {}
        self._hubs: dict[int | str, Hub] = {}
        self._threads: dict[tuple[int | str, str], threading.Thread] = {}

    def set_credentials(self, migration_id: int, creds: Credentials) -> None:
        with self._lock:
            self._creds[migration_id] = creds

    def get_credentials(self, migration_id: int) -> Credentials | None:
        with self._lock:
            return self._creds.get(migration_id)

    def hub(self, key: int | str) -> Hub:
        with self._lock:
            h = self._hubs.get(key)
            if h is None:
                h = Hub()
                self._hubs[key] = h
            return h

    def is_running(self, key: int | str, phase: str) -> bool:
        with self._lock:
            t = self._threads.get((key, phase))
            return bool(t and t.is_alive())

    def register_thread(self, key: int | str, phase: str, thread: threading.Thread) -> None:
        with self._lock:
            self._threads[(key, phase)] = thread


STATE = _State()


def load_credentials(migration_id: int) -> Credentials | None:
    """Return credentials for a migration: in-memory first, falling back to
    decrypting from the Migration row. Hydrates the in-memory cache on a DB hit.
    Returns None only when neither RAM nor DB has anything."""
    creds = STATE.get_credentials(migration_id)
    if creds and (creds.old_password or creds.new_password):
        return creds

    # Lazy imports to avoid a circular dependency (models / crypto pull in settings).
    from .credentials import recall
    from .crypto import decrypt
    from .models import Migration

    try:
        row = Migration.objects.only(
            "owner_id", "old_password_enc", "new_password_enc",
            "old_host", "old_username", "new_host", "new_username",
        ).get(pk=migration_id)
    except Migration.DoesNotExist:
        return None

    old = decrypt(bytes(row.old_password_enc)) if row.old_password_enc else ""
    new = decrypt(bytes(row.new_password_enc)) if row.new_password_enc else ""
    # Nothing on the row: fall back to what the owner saved for that mailbox
    # elsewhere. Covers a migration created before this store existed, and a
    # row whose ciphertext this host's key cannot read.
    if not old:
        old = recall(row.owner_id, row.old_host, row.old_username)
    if not new:
        new = recall(row.owner_id, row.new_host, row.new_username)
    if not (old or new):
        return None

    hydrated = Credentials(old_password=old, new_password=new)
    STATE.set_credentials(migration_id, hydrated)
    return hydrated


# ---------------------------------------------------------------------------
# Heartbeats
# ---------------------------------------------------------------------------


class _Heartbeat:
    """Keeps one row's `heartbeat_at` fresh while its work is in flight.

    Runs a daemon thread that does a single narrow UPDATE every `every`
    seconds. It stops on its own as soon as the row is no longer "running", so
    a runner that returns down some path nobody thought about still can't leave
    a ticker behind — the row's own status ends it.
    """

    def __init__(self, obj, every: float) -> None:
        self._model = type(obj)
        self._pk = obj.pk
        self._every = every
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._run,
            name=f"heartbeat-{self._model.__name__}-{self._pk}",
            daemon=True,
        )

    def _touch(self) -> int:
        """Stamp the row. Returns rows updated: 0 means it is no longer running."""
        return self._model.objects.filter(pk=self._pk, status="running").update(
            heartbeat_at=timezone.now(), worker=WORKER_ID,
        )

    def _run(self) -> None:
        try:
            while not self._stop.wait(self._every):
                try:
                    if not self._touch():
                        return
                except Exception:
                    # A blip in the database must never take down the run it is
                    # only supposed to be watching. Drop the connection so the
                    # next beat reconnects: a heartbeat wedged on a dead socket
                    # would look exactly like a dead process, and the
                    # supervisor would start a second copy of live work.
                    logger.debug("Heartbeat update failed", exc_info=True)
                    try:
                        connection.close()
                    except Exception:
                        pass
        finally:
            # This thread opened its own connection; don't leave it dangling.
            try:
                connection.close()
            except Exception:
                pass

    def start(self) -> "_Heartbeat":
        try:
            self._touch()
        except Exception:
            logger.debug("Initial heartbeat failed", exc_info=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()


def start_heartbeat(obj, every: float | None = None) -> _Heartbeat:
    """Begin heartbeating `obj` (a LiveRun row). Call right after it goes
    running; it ends itself when the row stops being running."""
    from .models import RUN_HEARTBEAT_EVERY

    return _Heartbeat(obj, every or RUN_HEARTBEAT_EVERY).start()

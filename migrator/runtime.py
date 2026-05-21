"""Process-local runtime state: credentials and per-migration event hubs.

Credentials live only in memory: the operator types them at the start of a
session and they are never written to the database.

Each Migration gets one Hub that fans out log/progress events to any number
of SSE listeners.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass


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


class _State:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._creds: dict[int, Credentials] = {}
        self._hubs: dict[int, Hub] = {}
        self._threads: dict[tuple[int, str], threading.Thread] = {}

    def set_credentials(self, migration_id: int, creds: Credentials) -> None:
        with self._lock:
            self._creds[migration_id] = creds

    def get_credentials(self, migration_id: int) -> Credentials | None:
        with self._lock:
            return self._creds.get(migration_id)

    def hub(self, migration_id: int) -> Hub:
        with self._lock:
            h = self._hubs.get(migration_id)
            if h is None:
                h = Hub()
                self._hubs[migration_id] = h
            return h

    def is_running(self, migration_id: int, phase: str) -> bool:
        with self._lock:
            t = self._threads.get((migration_id, phase))
            return bool(t and t.is_alive())

    def register_thread(self, migration_id: int, phase: str, thread: threading.Thread) -> None:
        with self._lock:
            self._threads[(migration_id, phase)] = thread


STATE = _State()


def load_credentials(migration_id: int) -> Credentials | None:
    """Return credentials for a migration: in-memory first, falling back to
    decrypting from the Migration row. Hydrates the in-memory cache on a DB hit.
    Returns None only when neither RAM nor DB has anything."""
    creds = STATE.get_credentials(migration_id)
    if creds and (creds.old_password or creds.new_password):
        return creds

    # Lazy imports to avoid a circular dependency (models / crypto pull in settings).
    from .crypto import decrypt
    from .models import Migration

    try:
        row = Migration.objects.only(
            "old_password_enc", "new_password_enc"
        ).get(pk=migration_id)
    except Migration.DoesNotExist:
        return None

    old = decrypt(bytes(row.old_password_enc)) if row.old_password_enc else ""
    new = decrypt(bytes(row.new_password_enc)) if row.new_password_enc else ""
    if not (old or new):
        return None

    hydrated = Credentials(old_password=old, new_password=new)
    STATE.set_credentials(migration_id, hydrated)
    return hydrated

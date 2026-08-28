"""Restore: push archived messages into a mailbox over IMAP.

The reverse of backup.py. A `RestoreJob` reads its messages either from an
uploaded archive (parsed into RestoreMessage rows on upload) or straight from
an existing BackupJob, pairs the archive's folders against the destination's,
and APPENDs whatever isn't already there.

Nothing is ever deleted — not on the destination, not in the archive. A message
already present at the destination (same Message-ID) is skipped, so running an
import twice is safe.
"""

from __future__ import annotations

import csv
import io
import logging
import posixpath
import re
import threading
import traceback
import zipfile

from django.conf import settings
from django.core.mail import send_mail
from django.utils import timezone

from .backup import message_meta
from .crypto import decrypt
from .imap_client import (
    ImapClient, collect_dedup_ids, parse_message_id, synthetic_message_id,
)
from .models import (
    BackupMessage, RestoreFolder, RestoreJob, RestoreMessage, UserProfile,
)
from .runtime import STATE, WORKER_ID, start_heartbeat


logger = logging.getLogger(__name__)


def hub_key(job_id: int) -> str:
    return f"restore:{job_id}"


def _log(hub, level: str, message: str, **extra) -> None:
    hub.publish({"type": "log", "level": level, "message": message, **extra})


def _progress(hub, processed: int, total: int, **extra) -> None:
    hub.publish({
        "type": "progress", "phase": "restore",
        "processed": processed, "total": total, **extra,
    })


def _status(hub, status: str, **extra) -> None:
    hub.publish({"type": "phase", "phase": "restore", "status": status, **extra})


def connect(job: RestoreJob) -> ImapClient:
    password = decrypt(bytes(job.password_enc))
    if not password:
        raise RuntimeError(
            "No password saved for the destination mailbox. Edit it and enter it again."
        )
    return ImapClient(job.host, job.port, job.username, password, use_ssl=job.use_ssl)


# ---------------------------------------------------------------------------
# Reading an uploaded archive
# ---------------------------------------------------------------------------

# Paths the backup ZIP contains that are not messages.
_SKIP_NAMES = {"manifest.csv"}
_SKIP_DIRS = {"_attachments", "__MACOSX"}

MBOX_SEPARATOR = re.compile(rb"^From .*$", re.MULTILINE)
_HEADER_LINE = re.compile(rb"^[A-Za-z][A-Za-z0-9_-]*:")
# A file claiming to be a message has to have at least one of these.
_REQUIRED_HEADERS = (
    b"from:", b"to:", b"subject:", b"date:", b"message-id:",
    b"received:", b"mime-version:", b"return-path:",
)


def looks_like_message(raw: bytes) -> bool:
    """True if `raw` starts with something that reads as an RFC822 header block.

    Guards the "bare file" upload path: without this, any text file at all
    would be accepted and delivered into the destination mailbox as a message.
    """
    head = raw.lstrip()[:16384]
    if not head:
        return False
    lines = head.splitlines()
    seen_header = False
    for line in lines[:60]:
        if not line.strip():
            break                      # end of the header block
        if line[:1] in (b" ", b"\t"):
            continue                   # folded continuation of the line above
        if not _HEADER_LINE.match(line):
            return False               # not a header — this isn't a message
        seen_header = True
    if not seen_header:
        return False
    lowered = head.lower()
    return any(h in lowered for h in _REQUIRED_HEADERS)


class ArchiveError(Exception):
    """The uploaded file isn't something we can read messages out of."""


def _is_skipped(path: str) -> bool:
    parts = path.split("/")
    if any(p in _SKIP_DIRS for p in parts[:-1]):
        return True
    return parts[-1].lower() in _SKIP_NAMES or not parts[-1]


def split_mbox(raw: bytes) -> list[bytes]:
    """Split an mbox file into individual messages.

    Splits on lines starting with "From " at the start of a line, which is the
    separator our own .mbox export writes and what every mbox producer uses.
    """
    positions = [m.start() for m in MBOX_SEPARATOR.finditer(raw)]
    if not positions:
        return [raw] if raw.strip() else []
    messages = []
    for i, start in enumerate(positions):
        end = positions[i + 1] if i + 1 < len(positions) else len(raw)
        chunk = raw[start:end]
        # Drop the "From ..." separator line itself.
        nl = chunk.find(b"\n")
        body = chunk[nl + 1:] if nl != -1 else b""
        if body.strip():
            messages.append(body)
    return messages


def read_manifest(zf: zipfile.ZipFile) -> dict[str, dict]:
    """Read flags/internaldate per file out of a backup ZIP's manifest.csv.

    A .eml carries neither read-state nor the server's received date, so without
    the manifest a restored mailbox arrives entirely unread and stamped today.
    Archives without a manifest (or older ones without these columns) simply
    yield nothing here.
    """
    try:
        raw = zf.read("manifest.csv").decode("utf-8", "replace")
    except KeyError:
        return {}
    except Exception as exc:
        logger.warning("Could not read manifest.csv: %s", exc)
        return {}

    out: dict[str, dict] = {}
    try:
        for row in csv.DictReader(io.StringIO(raw)):
            path = (row.get("file") or "").strip()
            if not path:
                continue
            out[path] = {
                "flags": (row.get("flags") or "").strip(),
                "internaldate": (row.get("internaldate") or "").strip(),
            }
    except Exception as exc:
        logger.warning("Malformed manifest.csv, ignoring: %s", exc)
        return {}
    return out


def iter_archive_messages(data: bytes, filename: str):
    """Yield (folder, raw_bytes, flags, internaldate) from an uploaded archive.

    Understands: our backup ZIP (folder tree of .eml plus manifest.csv), any ZIP
    of .eml files, a ZIP of .mbox files (what the migration screen's Download
    backup produces), and a bare .eml or .mbox file. Only our own ZIP carries
    flags and dates; for everything else they come back empty.
    """
    lower = filename.lower()

    if not zipfile.is_zipfile(_as_stream(data)):
        # An mbox by extension, or by its leading "From " separator line.
        if lower.endswith(".mbox") or data.lstrip().startswith(b"From "):
            stem = posixpath.basename(filename)
            if stem.lower().endswith(".mbox"):
                stem = stem[: -len(".mbox")]
            for raw in split_mbox(data):
                yield (stem or "INBOX"), raw, "", ""
            return
        # A single message. Checked rather than assumed — an unrecognised file
        # must be rejected, not delivered into someone's mailbox as garbage.
        if looks_like_message(data):
            yield "INBOX", data, "", ""
            return
        raise ArchiveError(
            "That file isn't a mail archive. Upload a .zip from the Backups page, "
            "a .mbox file, or a single .eml message."
        )

    with zipfile.ZipFile(_as_stream(data)) as zf:
        manifest = read_manifest(zf)
        names = [n for n in zf.namelist() if not n.endswith("/") and not _is_skipped(n)]
        if not names:
            raise ArchiveError(
                "No messages found in that archive. Expected .eml or .mbox files inside."
            )
        found = False
        for name in sorted(names):
            lower_name = name.lower()
            folder = posixpath.dirname(name).strip("/")
            try:
                payload = zf.read(name)
            except Exception as exc:
                logger.warning("Could not read %s from archive: %s", name, exc)
                continue
            if lower_name.endswith(".eml"):
                found = True
                meta = manifest.get(name, {})
                yield (
                    folder or "INBOX", payload,
                    meta.get("flags", ""), meta.get("internaldate", ""),
                )
            elif lower_name.endswith(".mbox"):
                # One .mbox per folder — the folder name is the file name.
                stem = posixpath.basename(name)[: -len(".mbox")]
                target = f"{folder}/{stem}" if folder else stem
                for raw in split_mbox(payload):
                    found = True
                    yield (target or "INBOX"), raw, "", ""
        if not found:
            raise ArchiveError(
                "No .eml or .mbox files in that archive. If this is a backup ZIP, "
                "upload it exactly as it was downloaded."
            )


def _as_stream(data: bytes):
    return io.BytesIO(data)


def ingest_archive(job: RestoreJob, data: bytes, filename: str) -> dict:
    """Parse an uploaded archive into RestoreMessage rows.

    Returns {'messages': n, 'folders': n, 'duplicates': n}. Replaces anything
    previously ingested for this job, so re-uploading starts clean.
    """
    job.messages.all().delete()
    job.folders.all().delete()

    seen: set[tuple[str, str]] = set()
    duplicates = 0
    batch: list[RestoreMessage] = []
    per_folder: dict[str, int] = {}

    for folder, raw, flags, internaldate in iter_archive_messages(data, filename):
        if not raw or not raw.strip():
            continue
        msg_id = parse_message_id(raw) or synthetic_message_id(raw)
        if len(msg_id) > 255:
            msg_id = synthetic_message_id(raw)
        key = (folder, msg_id)
        if key in seen:
            duplicates += 1
            continue
        seen.add(key)

        meta = message_meta(raw)
        batch.append(RestoreMessage(
            job=job, folder=folder, message_id=msg_id,
            subject=meta["subject"], from_addr=meta["from_addr"],
            date_header=meta["date_header"], size=len(raw), raw_bytes=raw,
            flags=flags, internaldate=internaldate[:64],
        ))
        per_folder[folder] = per_folder.get(folder, 0) + 1
        if len(batch) >= 50:
            RestoreMessage.objects.bulk_create(batch)
            batch = []
    if batch:
        RestoreMessage.objects.bulk_create(batch)

    if not per_folder:
        raise ArchiveError("The archive contained no readable messages.")

    RestoreFolder.objects.bulk_create([
        RestoreFolder(job=job, source_folder=name, message_count=count)
        for name, count in sorted(per_folder.items())
    ])

    job.archive_name = filename
    job.archive_size = len(data)
    job.total = sum(per_folder.values())
    job.save(update_fields=["archive_name", "archive_size", "total"])
    return {
        "messages": sum(per_folder.values()),
        "folders": len(per_folder),
        "duplicates": duplicates,
    }


def load_from_backup(job: RestoreJob) -> dict:
    """Build the folder list for a restore whose source is an existing BackupJob.

    The messages themselves stay where they are — no copies — so restoring a
    2 GB mailbox doesn't put a second 2 GB in the database.
    """
    job.folders.all().delete()
    backup_job = job.source_backup
    if backup_job is None:
        raise ArchiveError("That backup no longer exists.")

    from django.db.models import Count
    counts = {
        row["folder"]: row["n"]
        for row in (
            BackupMessage.objects.filter(job=backup_job)
            .exclude(raw_bytes=b"")
            .values("folder")
            .annotate(n=Count("id"))
            .order_by("folder")
        )
    }
    if not counts:
        raise ArchiveError("That backup has no archived messages yet. Run it first.")

    # Keep each folder's raw IMAP name (needed to fetch its messages) together
    # with the delimiter that name uses, so the hierarchy can be rebuilt with
    # the destination's separator instead of being created as one flat folder.
    source_delims = dict(backup_job.folders.values_list("name", "delimiter"))
    RestoreFolder.objects.bulk_create([
        RestoreFolder(
            job=job, source_folder=name, message_count=count,
            source_delimiter=source_delims.get(name) or "/",
        )
        for name, count in sorted(counts.items())
    ])
    job.total = sum(counts.values())
    job.save(update_fields=["total"])
    return {"messages": job.total, "folders": len(counts), "duplicates": 0}


# ---------------------------------------------------------------------------
# Source iteration (upload vs existing backup)
# ---------------------------------------------------------------------------

def iter_source_messages(job: RestoreJob, folder: str):
    """Yield (message_id, raw, flags, internaldate) for one source folder."""
    if job.source_kind == RestoreJob.SOURCE_UPLOAD:
        rows = (
            RestoreMessage.objects.filter(job=job, folder=folder)
            .order_by("id").iterator(chunk_size=20)
        )
    else:
        rows = (
            BackupMessage.objects.filter(job=job.source_backup, folder=folder)
            .exclude(raw_bytes=b"")
            .order_by("id").iterator(chunk_size=20)
        )
    for row in rows:
        yield (
            row.message_id, bytes(row.raw_bytes),
            row.flags.split() if row.flags else [],
            getattr(row, "internaldate", "") or "",
        )


# ---------------------------------------------------------------------------
# Folder pairing
# ---------------------------------------------------------------------------

# Leaf names that mean the same thing as an IMAP special-use flag. Lets an
# archive's "Gelöschte Objekte" land in the destination's \Trash folder.
SPECIAL_BY_NAME = {
    "inbox": "\\Inbox",
    "sent": "\\Sent", "sent items": "\\Sent", "gesendet": "\\Sent",
    "gesendete objekte": "\\Sent", "sent messages": "\\Sent",
    "drafts": "\\Drafts", "entwürfe": "\\Drafts", "entwurf": "\\Drafts",
    "trash": "\\Trash", "deleted items": "\\Trash", "papierkorb": "\\Trash",
    "gelöschte objekte": "\\Trash", "gelöschte elemente": "\\Trash",
    "junk": "\\Junk", "spam": "\\Junk", "junk e-mail": "\\Junk",
    "archive": "\\Archive", "archiv": "\\Archive",
}


def split_source(source_folder: str, source_delimiter: str = "/") -> list[str]:
    """Break a source folder name into its hierarchy segments.

    The separator depends on where the name came from — "/" for a ZIP path,
    the source server's delimiter for a name read out of a stored backup — so
    it has to be passed in rather than assumed.
    """
    parts = [p for p in source_folder.split(source_delimiter or "/") if p.strip()]
    return parts or [source_folder.strip()] if source_folder.strip() else []


def _translate(source_folder: str, dest_delimiter: str, source_delimiter: str = "/") -> str:
    """Rewrite a source folder name using the destination's hierarchy separator.

    "INBOX.Berlin" from a "."-delimited server becomes "INBOX/Berlin" on a
    "/"-delimited one. Getting this wrong creates a single flat folder whose
    name contains the other server's separator.
    """
    parts = split_source(source_folder, source_delimiter)
    if not parts:
        return "INBOX"
    return (dest_delimiter or "/").join(parts)


def dest_delimiter(folders) -> str:
    """The destination server's hierarchy separator.

    INBOX's delimiter is the authoritative one — it exists on every server and
    can't be a stray value from an odd namespace. Falls back to the most
    commonly reported delimiter, then to "/".
    """
    for f in folders:
        if f.name.upper() == "INBOX" and f.delimiter:
            return f.delimiter
    counts: dict[str, int] = {}
    for f in folders:
        if f.delimiter:
            counts[f.delimiter] = counts.get(f.delimiter, 0) + 1
    if counts:
        return max(counts, key=counts.get)
    return "/"


def pair_folders(job: RestoreJob) -> list[RestoreFolder]:
    """Connect to the destination and decide where each archive folder goes.

    Rules, in order: exact name match, special-use match (Sent → \\Sent), leaf
    name match, otherwise create. Preserves nothing from a previous pairing —
    it's a fresh suggestion the user can then edit.
    """
    with connect(job) as client:
        dest = client.list_folders()

    delimiter = dest_delimiter(dest)
    by_lower = {f.name.lower(): f.name for f in dest}
    by_leaf = {}
    by_special = {}
    for f in dest:
        leaf = f.name.split(f.delimiter or delimiter)[-1].lower()
        by_leaf.setdefault(leaf, f.name)
        if f.special_use:
            by_special.setdefault(f.special_use, f.name)

    # Shallowest first, so a folder's parent has already been decided by the
    # time we get to it and children can follow their parent's destination.
    rows = sorted(
        job.folders.all(),
        key=lambda r: len(split_source(r.source_folder, r.source_delimiter)),
    )
    assigned: dict[tuple, str] = {}   # source segments (lowercased) -> destination

    for row in rows:
        segments = split_source(row.source_folder, row.source_delimiter)
        translated = _translate(row.source_folder, delimiter, row.source_delimiter)
        leaf = (segments[-1] if segments else row.source_folder).strip().lower()

        # Where the nearest already-decided ancestor went. Without this, an
        # "Archive" that maps onto the destination's "Archives" would leave its
        # "Archive/2026" child stranded in a second, parallel tree.
        inherited = ""
        for i in range(len(segments) - 1, 0, -1):
            parent = tuple(s.lower() for s in segments[:i])
            if parent in assigned:
                inherited = delimiter.join([assigned[parent]] + segments[i:])
                break

        if translated.lower() in by_lower:
            row.dest_folder = by_lower[translated.lower()]
            row.action = RestoreFolder.ACTION_MAP
            row.pairing_reason = "name"
        elif SPECIAL_BY_NAME.get(leaf) in by_special:
            row.dest_folder = by_special[SPECIAL_BY_NAME[leaf]]
            row.action = RestoreFolder.ACTION_MAP
            row.pairing_reason = "special-use"
        elif inherited:
            row.dest_folder = inherited
            row.action = (
                RestoreFolder.ACTION_MAP if inherited.lower() in by_lower
                else RestoreFolder.ACTION_CREATE
            )
            row.pairing_reason = "under parent"
        elif leaf in by_leaf:
            row.dest_folder = by_leaf[leaf]
            row.action = RestoreFolder.ACTION_MAP
            row.pairing_reason = "leaf-name"
        else:
            row.dest_folder = translated
            row.action = RestoreFolder.ACTION_CREATE
            row.pairing_reason = "new"

        assigned[tuple(s.lower() for s in segments)] = row.dest_folder
        row.save(update_fields=["dest_folder", "action", "pairing_reason"])

    job.paired_at = timezone.now()
    job.save(update_fields=["paired_at"])
    return rows


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_restore_job(job_id: int, resumed: bool = False) -> None:
    """Import every mapped folder into the destination mailbox.

    `resumed` marks a run restarted after its process died; messages the
    destination already holds are skipped either way, so it only carries the
    retry counter (see migrator.supervisor).
    """
    job = RestoreJob.objects.get(pk=job_id)
    hub = STATE.hub(hub_key(job_id))

    job.status = RestoreJob.STATUS_RUNNING
    job.started_at = timezone.now()
    job.finished_at = None
    job.processed = job.imported = job.skipped = job.failed = 0
    job.error = ""
    job.worker = WORKER_ID
    job.heartbeat_at = timezone.now()
    job.interrupted = False
    job.resumed_count = (job.resumed_count + 1) if resumed else 0
    job.save(update_fields=[
        "status", "started_at", "finished_at", "processed",
        "imported", "skipped", "failed", "error",
        "worker", "heartbeat_at", "interrupted", "resumed_count",
    ])
    start_heartbeat(job)
    _status(hub, "running")
    _log(hub, "info",
         ("Import resumed into " if resumed else "Import started into ")
         + f"{job.username} @ {job.host}")
    _log(hub, "info", f"Source: {job.source_label}")

    processed = imported = skipped = failed = 0
    try:
        mappings = list(
            job.folders.exclude(action=RestoreFolder.ACTION_SKIP).order_by("source_folder")
        )
        if not mappings:
            raise RuntimeError("Every folder is set to skip — nothing to import.")

        total = sum(m.message_count for m in mappings)
        job.total = total
        job.save(update_fields=["total"])
        _progress(hub, 0, total)
        _log(hub, "info", f"{total} message(s) across {len(mappings)} folder(s).")

        with connect(job) as client:
            existing = {f.name for f in client.list_folders()}

            for mapping in mappings:
                src = mapping.source_folder
                dst = mapping.dest_folder or src
                _log(hub, "info", f"{src} → {dst}")

                if dst not in existing:
                    _log(hub, "info", f"  creating {dst}")
                    try:
                        client.create_folder(dst)
                        existing.add(dst)
                    except Exception as exc:
                        _log(hub, "error", f"  could not create {dst}: {exc}")
                        failed += mapping.message_count
                        processed += mapping.message_count
                        continue

                # Dedup index: what's already in the destination folder. Uses
                # the shared id rule, so a message with no Message-ID header
                # isn't re-uploaded on every run.
                try:
                    client.select(dst, readonly=True)
                    present = collect_dedup_ids(client)
                except Exception as exc:
                    _log(hub, "warn", f"  could not read {dst}: {exc}")
                    present = set()
                _log(hub, "info", f"  destination holds {len(present)} message(s)")

                folder_imported = 0
                for msg_id, raw, flags, internaldate in iter_source_messages(job, src):
                    processed += 1
                    if msg_id and msg_id in present:
                        skipped += 1
                    else:
                        try:
                            client.append(dst, raw, flags=flags, internaldate=internaldate)
                            imported += 1
                            folder_imported += 1
                            if msg_id:
                                present.add(msg_id)
                        except Exception as exc:
                            failed += 1
                            _log(hub, "warn", f"  upload failed for {msg_id}: {exc}")
                    if processed % 25 == 0:
                        job.processed, job.imported = processed, imported
                        job.skipped, job.failed = skipped, failed
                        job.save(update_fields=[
                            "processed", "imported", "skipped", "failed",
                        ])
                        _progress(hub, processed, total, folder=src)

                mapping.imported = folder_imported
                mapping.save(update_fields=["imported"])
                _log(hub, "info",
                     f"  {folder_imported} imported, "
                     f"{mapping.message_count - folder_imported} already there or failed")

        job.processed, job.imported = processed, imported
        job.skipped, job.failed = skipped, failed
        job.status = RestoreJob.STATUS_SUCCESS
        job.finished_at = timezone.now()
        job.save(update_fields=[
            "processed", "imported", "skipped", "failed", "status", "finished_at",
        ])
        _progress(hub, processed, total)
        _log(hub, "info",
             f"Import complete. {imported} imported, {skipped} already present"
             + (f", {failed} failed" if failed else "") + ".")
        _status(hub, "success", processed=processed, total=total)
        _notify(job)
    except Exception as exc:
        job.status = RestoreJob.STATUS_FAILED
        job.finished_at = timezone.now()
        job.processed, job.imported = processed, imported
        job.skipped, job.failed = skipped, failed
        job.error = f"{exc}\n{traceback.format_exc()}"
        job.save(update_fields=[
            "status", "finished_at", "processed", "imported",
            "skipped", "failed", "error",
        ])
        _log(hub, "error", f"Import failed: {exc}")
        _status(hub, "failed", error=str(exc))
        _notify(job)


def _notify(job: RestoreJob) -> None:
    """Email the owner that the import finished, if they opted in.

    Always sent for both outcomes — unlike a scheduled backup, an import only
    ever happens because someone pressed the button, so there's no risk of
    flooding an inbox with routine successes. Best-effort: SMTP trouble is
    logged and swallowed, since the mail itself already arrived.
    """
    profile = UserProfile.objects.filter(user=job.owner).first()
    if not profile or not profile.notifications_enabled:
        return
    target = profile.resolved_email()
    if not target:
        return

    ok = job.status == RestoreJob.STATUS_SUCCESS
    subject = (
        f"[Mailbox Transfer] Import {'completed' if ok else 'failed'} — {job.label}"
    )
    lines = [
        f"Import: {job.label}",
        f"Destination: {job.username} @ {job.host}",
        f"Source: {job.source_label}",
        f"Status: {job.status}",
        "",
        f"Imported:      {job.imported}",
        f"Already there: {job.skipped}",
    ]
    if job.failed:
        lines.append(f"Failed:        {job.failed}")
    if job.started_at:
        lines.append("")
        lines.append(f"Started: {job.started_at.isoformat(timespec='seconds')}")
    if job.finished_at:
        lines.append(f"Finished: {job.finished_at.isoformat(timespec='seconds')}")
    if not ok and job.error:
        first = job.error.strip().splitlines()[0] if job.error.strip() else ""
        if first:
            lines += ["", f"Error: {first[:300]}"]

    try:
        send_mail(
            subject=subject,
            message="\n".join(lines) + "\n",
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[target],
            fail_silently=False,
        )
    except Exception:
        logger.exception("Import notification email failed (job=%s)", job.pk)


def launch_restore_job(job_id: int, resumed: bool = False) -> bool:
    key = hub_key(job_id)
    if STATE.is_running(key, "restore"):
        return False
    thread = threading.Thread(
        target=lambda: run_restore_job(job_id, resumed=resumed),
        name=f"restore-job-{job_id}", daemon=True,
    )
    STATE.register_thread(key, "restore", thread)
    thread.start()
    return True

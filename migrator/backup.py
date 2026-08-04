"""Standalone mailbox backup — download only, never upload.

A `BackupJob` points at exactly one IMAP account. Running it walks every
selected folder, stores each message's complete RFC822 source (attachments
included, since they live inside the message) in `BackupMessage.raw_bytes`,
and publishes log/progress events to the job's Hub so the page can follow along.

`build_archive` turns what's in the database into a ZIP: one directory per
folder, one `.eml` per message, plus an `_attachments/` subdirectory with the
files extracted so they can be browsed without opening a mail client.
"""

from __future__ import annotations

import csv
import io
import logging
import os
import re
import tempfile
import threading
import traceback
import zipfile
from email import message_from_bytes
from email.header import decode_header, make_header
from email.message import Message

from django.conf import settings
from django.core.mail import send_mail
from django.db.models import Sum
from django.utils import timezone

from .crypto import decrypt
from .imap_client import ImapClient, parse_message_id, synthetic_message_id
from .models import BackupFolder, BackupJob, BackupMessage, UserProfile
from .runtime import STATE


logger = logging.getLogger(__name__)


def hub_key(job_id: int) -> str:
    """Hub/thread key for a backup job. Namespaced so it can't collide with a
    Migration id, which uses a bare int in the same registry."""
    return f"backup:{job_id}"


# ---------------------------------------------------------------------------
# Event helpers (mirror phases.py so the front-end JS is interchangeable)
# ---------------------------------------------------------------------------

def _log(hub, level: str, message: str, **extra) -> None:
    hub.publish({"type": "log", "level": level, "message": message, **extra})


def _progress(hub, processed: int, total: int, **extra) -> None:
    hub.publish({
        "type": "progress", "phase": "backup",
        "processed": processed, "total": total, **extra,
    })


def _status(hub, status: str, **extra) -> None:
    hub.publish({"type": "phase", "phase": "backup", "status": status, **extra})


# ---------------------------------------------------------------------------
# Message parsing
# ---------------------------------------------------------------------------

def _decode_header(value: str) -> str:
    """RFC 2047 decode, tolerant of malformed input."""
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value


def _is_attachment(part: Message) -> bool:
    if part.is_multipart():
        return False
    disposition = (part.get_content_disposition() or "").lower()
    if disposition == "attachment":
        return True
    # Inline parts still count when they carry a filename (embedded images,
    # forwarded documents) — the user asked for the files, not for MIME purity.
    return disposition == "inline" and bool(part.get_filename())


def iter_attachments(raw: bytes):
    """Yield (filename, payload) for every attachment part of a raw message."""
    try:
        msg = message_from_bytes(raw)
    except Exception:
        return
    for part in msg.walk():
        if not _is_attachment(part):
            continue
        try:
            payload = part.get_payload(decode=True)
        except Exception:
            payload = None
        if not payload:
            continue
        name = _decode_header(part.get_filename() or "") or "attachment"
        yield name, payload


def message_meta(raw: bytes) -> dict:
    """Subject / From / Date / attachment count, for the manifest and UI."""
    meta = {"subject": "", "from_addr": "", "date_header": "", "attachment_count": 0}
    try:
        msg = message_from_bytes(raw)
    except Exception:
        return meta
    meta["subject"] = _decode_header(msg.get("Subject", ""))[:500]
    meta["from_addr"] = _decode_header(msg.get("From", ""))[:320]
    meta["date_header"] = (msg.get("Date", "") or "")[:120]
    count = 0
    for part in msg.walk():
        if _is_attachment(part):
            count += 1
    meta["attachment_count"] = count
    return meta


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def connect(job: BackupJob) -> ImapClient:
    password = decrypt(bytes(job.password_enc))
    if not password:
        raise RuntimeError(
            "No password saved for this mailbox. Open Edit and enter it again."
        )
    return ImapClient(job.host, job.port, job.username, password, use_ssl=job.use_ssl)


def sync_folders(job: BackupJob, client: ImapClient) -> tuple[list[BackupFolder], list[str], list[str]]:
    """LIST the mailbox on an already-open connection and sync BackupFolder rows.

    Returns (all rows, names added, names removed). New folders arrive selected
    so they get archived without anyone having to notice them; a folder the user
    deliberately unticked stays unticked, and folders deleted on the server are
    dropped (their archived messages stay in the database and in the ZIP).
    """
    found = client.list_folders()
    counts: dict[str, int] = {}
    for f in found:
        try:
            counts[f.name] = client.select(f.name, readonly=True)
        except Exception:
            # \Noselect containers (e.g. a parent namespace) can't be opened.
            counts[f.name] = 0

    existing = {f.name: f for f in job.folders.all()}
    added: list[str] = []
    seen: set[str] = set()
    for f in found:
        seen.add(f.name)
        row = existing.get(f.name)
        if row is None:
            BackupFolder.objects.create(
                job=job, name=f.name, delimiter=f.delimiter,
                special_use=f.special_use, server_count=counts.get(f.name, 0),
                selected=True,
            )
            added.append(f.name)
        else:
            row.delimiter = f.delimiter
            row.special_use = f.special_use
            row.server_count = counts.get(f.name, 0)
            row.save(update_fields=["delimiter", "special_use", "server_count"])
    removed = [name for name in existing if name not in seen]
    if removed:
        job.folders.filter(name__in=removed).delete()

    job.folders_listed_at = timezone.now()
    job.save(update_fields=["folders_listed_at"])
    return list(job.folders.all()), added, removed


def refresh_folders(job: BackupJob) -> list[BackupFolder]:
    """Connect and sync the folder list. Used by the Refresh folders button."""
    with connect(job) as client:
        rows, _added, _removed = sync_folders(job, client)
    return rows


def blocking_reason(job: BackupJob) -> str:
    """Why this job can't run right now — empty string if it can.

    A job with no folder rows at all is *not* blocked: the run lists the mailbox
    itself and discovers them. Only an explicit "user unticked everything"
    counts, so a mailbox whose folders were never loaded still gets backed up
    by the scheduler.
    """
    if not bytes(job.password_enc):
        return "no password saved"
    if job.folders.exists() and not job.folders.filter(selected=True).exists():
        return "every folder is unticked"
    return ""


def run_backup_job(job_id: int, scheduled: bool = False) -> None:
    """Archive every selected folder of one mailbox.

    `scheduled` marks a run started by the scheduler rather than by a person
    clicking Run: those only email the owner when something went wrong, so a
    daily backup doesn't produce a daily "success" email.
    """
    job = BackupJob.objects.get(pk=job_id)
    hub = STATE.hub(hub_key(job_id))

    job.status = BackupJob.STATUS_RUNNING
    job.started_at = timezone.now()
    job.finished_at = None
    job.processed = 0
    job.total = 0
    job.error = ""
    job.save(update_fields=[
        "status", "started_at", "finished_at", "processed", "total", "error",
    ])
    _status(hub, "running")
    _log(hub, "info",
         ("Scheduled backup" if scheduled else "Backup")
         + f" started for {job.username} @ {job.host}")

    processed = 0
    try:
        with connect(job) as client:
            # Always re-read the folder list first. Without this, a folder
            # created after the last manual refresh would never be archived —
            # which would quietly defeat the point of a recurring backup.
            _log(hub, "info", "Checking the folder list…")
            _rows, added, removed = sync_folders(job, client)
            if added:
                _log(hub, "info", f"  {len(added)} new folder(s): {', '.join(added)}")
            if removed:
                _log(hub, "info",
                     f"  {len(removed)} folder(s) no longer on the server: "
                     f"{', '.join(removed)} (already-archived messages are kept)")

            folders = list(job.folders.filter(selected=True).order_by("name"))
            if not folders:
                raise RuntimeError("No folders selected. Pick at least one folder.")

            # sync_folders just SELECTed every folder, so its counts are current;
            # no need to walk the mailbox twice to work out the total.
            total = sum(f.server_count for f in folders)
            _log(hub, "info",
                 f"Counted {total} message(s) across {len(folders)} folder(s).")
            job.total = total
            job.save(update_fields=["total"])
            _progress(hub, 0, total)

            for folder in folders:
                name = folder.name
                _log(hub, "info", f"Folder: {name}")
                try:
                    count = client.select(name, readonly=True)
                except Exception as exc:
                    _log(hub, "warn", f"  skipped ({exc})")
                    continue
                if count == 0:
                    _log(hub, "info", "  (empty)")
                    continue

                # Anything already stored with bytes is re-runnable-safe: skip
                # it without re-fetching from the server.
                already = set(
                    BackupMessage.objects
                    .filter(job=job, folder=name)
                    .exclude(raw_bytes=b"")
                    .values_list("message_id", flat=True)
                )

                uid_to_mid = client.fetch_message_ids() or {}
                stored = skipped = failed = 0
                for uid in sorted(uid_to_mid):
                    header_mid = (uid_to_mid.get(uid) or "").strip()
                    if header_mid and header_mid in already:
                        skipped += 1
                        processed += 1
                        continue

                    try:
                        raw, flags, internaldate = client.fetch_message(uid)
                    except Exception as exc:
                        _log(hub, "warn", f"  UID {uid} fetch failed: {exc}")
                        failed += 1
                        continue

                    msg_id = parse_message_id(raw) or synthetic_message_id(raw)
                    if len(msg_id) > 255:
                        # Too long for the column; the sha256 fallback is stable
                        # for the same bytes, so dedup still works on re-runs.
                        msg_id = synthetic_message_id(raw)
                    rec, _ = BackupMessage.objects.get_or_create(
                        job=job, folder=name, message_id=msg_id,
                        defaults={"size": len(raw)},
                    )
                    if rec.raw_bytes:
                        skipped += 1
                        processed += 1
                        continue

                    meta = message_meta(raw)
                    rec.subject = meta["subject"]
                    rec.from_addr = meta["from_addr"]
                    rec.date_header = meta["date_header"]
                    rec.attachment_count = meta["attachment_count"]
                    rec.size = len(raw)
                    rec.flags = " ".join(flags or [])
                    rec.internaldate = internaldate or ""
                    rec.source_uid = uid
                    fields = [
                        "subject", "from_addr", "date_header", "attachment_count",
                        "size", "flags", "internaldate", "source_uid",
                    ]
                    try:
                        rec.raw_bytes = raw
                        rec.save(update_fields=fields + ["raw_bytes"])
                        stored += 1
                    except Exception as exc:
                        # Almost always a message larger than MySQL's
                        # max_allowed_packet. Keep the row (so the manifest
                        # shows it) but without bytes, and say so.
                        _log(hub, "warn",
                             f"  Could not store {msg_id} ({len(raw)} bytes): {exc}")
                        rec.raw_bytes = b""
                        rec.save(update_fields=fields)
                        failed += 1

                    processed += 1
                    if processed % 25 == 0:
                        job.processed = processed
                        job.save(update_fields=["processed"])
                        _progress(hub, processed, job.total, folder=name)

                _log(hub, "info",
                     f"  {name}: {stored} new, {skipped} already archived"
                     + (f", {failed} failed" if failed else ""))
                job.processed = processed
                job.save(update_fields=["processed"])
                _progress(hub, processed, job.total, folder=name)

        job.processed = processed
        job.status = BackupJob.STATUS_SUCCESS
        job.finished_at = timezone.now()
        job.save(update_fields=["processed", "status", "finished_at"])
        _progress(hub, processed, job.total)
        _log(hub, "info", "Backup complete.")
        _status(hub, "success", processed=processed, total=job.total)
        _notify(job, only_on_failure=scheduled)
    except Exception as exc:
        job.status = BackupJob.STATUS_FAILED
        job.finished_at = timezone.now()
        job.processed = processed
        job.error = f"{exc}\n{traceback.format_exc()}"
        job.save(update_fields=["status", "finished_at", "processed", "error"])
        _log(hub, "error", f"Backup failed: {exc}")
        _status(hub, "failed", error=str(exc))
        _notify(job, only_on_failure=scheduled)


def launch_backup_job(job_id: int) -> bool:
    """Start the job in a background thread. False if it's already running."""
    key = hub_key(job_id)
    if STATE.is_running(key, "backup"):
        return False
    thread = threading.Thread(
        target=lambda: run_backup_job(job_id),
        name=f"backup-job-{job_id}", daemon=True,
    )
    STATE.register_thread(key, "backup", thread)
    thread.start()
    return True


def _notify(job: BackupJob, only_on_failure: bool = False) -> None:
    """Email the owner that the backup finished, if they opted in. Best-effort.

    `only_on_failure` is set for scheduled runs so a recurring backup emails
    the owner when it breaks, not every time it works."""
    ok = job.status == BackupJob.STATUS_SUCCESS
    if ok and only_on_failure:
        return
    profile = UserProfile.objects.filter(user=job.owner).first()
    if not profile or not profile.notifications_enabled:
        return
    target = profile.resolved_email()
    if not target:
        return

    subject = (
        f"[Mailbox Transfer] Backup {'completed' if ok else 'failed'} — {job.label}"
    )
    lines = [
        f"Backup: {job.label}",
        f"Mailbox: {job.username} @ {job.host}",
        f"Status: {job.status}",
        f"Messages: {job.processed} / {job.total}",
    ]
    if job.started_at:
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
        logger.exception("Backup notification email failed (job=%s)", job.pk)


# ---------------------------------------------------------------------------
# Archive building
# ---------------------------------------------------------------------------

# Path separators, characters Windows forbids in a filename, and control
# codes. Accented letters and other unicode are kept — ZIP entries are UTF-8,
# and mangling "Gelöschte Objekte" into "Gel_schte Objekte" helps nobody.
_UNSAFE = re.compile(r'[<>:"/\\|?*\x00-\x1f]+')
# Reserved device names on Windows: a file called CON.eml cannot be extracted.
_RESERVED = {
    "CON", "PRN", "AUX", "NUL",
    *{f"COM{i}" for i in range(1, 10)},
    *{f"LPT{i}" for i in range(1, 10)},
}


def _safe(component: str, fallback: str = "item", maxlen: int = 60) -> str:
    """Sanitise one path component: no separators, no reserved characters.

    Also strips leading/trailing dots and spaces, so '..' can never survive as
    a component and no archive entry can escape its directory.
    """
    cleaned = _UNSAFE.sub("_", (component or "")).strip(" .")
    cleaned = re.sub(r"_{2,}", "_", cleaned)
    cleaned = cleaned[:maxlen].strip(" .")
    if not cleaned:
        return fallback
    if cleaned.split(".")[0].upper() in _RESERVED:
        cleaned = "_" + cleaned
    return cleaned


def folder_path(name: str, delimiter: str) -> str:
    """IMAP folder name -> ZIP directory path, preserving hierarchy.

    'INBOX.Projects.2026' with delimiter '.' becomes 'INBOX/Projects/2026'.
    """
    parts = name.split(delimiter) if delimiter else [name]
    safe_parts = [_safe(p, "folder") for p in parts if p.strip()]
    return "/".join(safe_parts) or _safe(name, "folder")


class TempArchiveFile(io.FileIO):
    """A read handle that deletes its file once the response is done with it.

    Archives are built into a temp file and streamed back; without this the
    files accumulate on disk, one full mailbox copy per download.
    """

    def close(self) -> None:
        super().close()
        try:
            os.unlink(self.name)
        except OSError:
            pass


def archive_filename(job: BackupJob) -> str:
    stamp = timezone.now().strftime("%Y%m%d-%H%M")
    return f"{_safe(job.label, f'backup-{job.pk}')}-{stamp}.zip"


def build_archive(job: BackupJob) -> str:
    """Write the job's archive to a temp file and return its path.

    Layout::

        INBOX/0001-Invoice.eml
        INBOX/_attachments/0001/invoice.pdf
        manifest.csv

    Messages stream out of the database one at a time so a multi-gigabyte
    mailbox never has to fit in memory.
    """
    delimiters = dict(job.folders.values_list("name", "delimiter"))
    folders = list(
        BackupMessage.objects.filter(job=job)
        .exclude(raw_bytes=b"")
        .values_list("folder", flat=True)
        .distinct()
        .order_by("folder")
    )

    manifest = io.StringIO()
    writer = csv.writer(manifest)
    # `flags` and `internaldate` are here so the archive round-trips: a .eml
    # carries neither, so without them a restored mailbox would arrive entirely
    # unread and stamped with today's date. The Restore page reads them back.
    writer.writerow([
        "folder", "file", "date", "from", "subject",
        "size_bytes", "attachments", "message_id", "flags", "internaldate",
    ])

    tmp = tempfile.NamedTemporaryFile(
        prefix=f"mailbox-backup-{job.pk}-", suffix=".zip", delete=False,
    )
    try:
        with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
            for folder in folders:
                base = folder_path(folder, delimiters.get(folder, "/"))
                seq = 0
                rows = (
                    BackupMessage.objects.filter(job=job, folder=folder)
                    .exclude(raw_bytes=b"")
                    .order_by("id")
                    .iterator(chunk_size=20)
                )
                for rec in rows:
                    seq += 1
                    raw = bytes(rec.raw_bytes)
                    stem = f"{seq:04d}-{_safe(rec.subject, 'no-subject')}"
                    zf.writestr(f"{base}/{stem}.eml", raw)

                    used: set[str] = set()
                    for att_name, payload in iter_attachments(raw):
                        safe_name = _safe(att_name, "attachment", maxlen=80)
                        if "." not in safe_name:
                            safe_name += ".bin"
                        candidate = safe_name
                        n = 2
                        while candidate in used:
                            stem_part, dot, ext = safe_name.rpartition(".")
                            candidate = f"{stem_part}-{n}{dot}{ext}"
                            n += 1
                        used.add(candidate)
                        zf.writestr(
                            f"{base}/_attachments/{seq:04d}/{candidate}", payload,
                        )

                    writer.writerow([
                        folder, f"{base}/{stem}.eml", rec.date_header,
                        rec.from_addr, rec.subject, rec.size,
                        rec.attachment_count, rec.message_id,
                        rec.flags, rec.internaldate,
                    ])
            zf.writestr("manifest.csv", manifest.getvalue())
    except Exception:
        tmp.close()
        try:
            os.unlink(tmp.name)
        except OSError:
            pass
        raise
    tmp.close()
    return tmp.name


def job_stats(job: BackupJob) -> dict:
    """Totals shown on the backup detail page."""
    agg = BackupMessage.objects.filter(job=job).aggregate(
        messages=Sum("size"), attachments=Sum("attachment_count"),
    )
    stored = BackupMessage.objects.filter(job=job).exclude(raw_bytes=b"").count()
    return {
        "messages": BackupMessage.objects.filter(job=job).count(),
        "stored": stored,
        "bytes": agg["messages"] or 0,
        "attachments": agg["attachments"] or 0,
    }

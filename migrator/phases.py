"""The four migration phases: Backup, Transfer, Verify, Cleanup.

Each phase function takes a Migration id, runs to completion (or failure),
and publishes log/progress events to the Migration's Hub. Phases are launched
in their own thread by views.py.
"""

from __future__ import annotations

import logging
import threading
import traceback
from datetime import timedelta

from django.conf import settings
from django.core.mail import send_mail
from django.utils import timezone

from .imap_client import (
    ImapClient,
    parse_message_id,
    synthetic_message_id,
)
from .models import (
    FolderMapping,
    Migration,
    MessageRecord,
    PhaseRun,
    UserProfile,
    VerificationReport,
)
from .runtime import STATE, Credentials, load_credentials


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _start_phase(migration: Migration, phase: str) -> PhaseRun:
    run = PhaseRun.objects.create(
        migration=migration,
        phase=phase,
        status=PhaseRun.STATUS_RUNNING,
        started_at=timezone.now(),
    )
    return run


def _finish_phase(run: PhaseRun, ok: bool, error: str = "") -> None:
    run.status = PhaseRun.STATUS_SUCCESS if ok else PhaseRun.STATUS_FAILED
    run.finished_at = timezone.now()
    if error:
        run.error = error
    run.save()
    _notify_phase_finished(run)


PHASE_LABELS = {
    PhaseRun.PHASE_BACKUP: "Backup",
    PhaseRun.PHASE_TRANSFER: "Transfer",
    PhaseRun.PHASE_VERIFY: "Verify",
    PhaseRun.PHASE_CLEANUP: "Cleanup",
}


def _notify_phase_finished(run: PhaseRun) -> None:
    """Email the migration owner that a phase finished. Best-effort: SMTP
    failures are logged but never propagate (the migration itself succeeded)."""
    owner = run.migration.owner
    if owner is None:
        return
    profile = UserProfile.objects.filter(user=owner).first()
    if not profile or not profile.notifications_enabled:
        return
    target = profile.resolved_email()
    if not target:
        return

    phase_label = PHASE_LABELS.get(run.phase, run.phase.title())
    mig_label = run.migration.name or f"#{run.migration_id}"
    ok = run.status == PhaseRun.STATUS_SUCCESS
    status_word = "completed" if ok else "failed"
    subject = f"[Mailbox Transfer] {phase_label} {status_word} — {mig_label}"

    lines = [
        f"Migration: {mig_label}",
        f"Source: {run.migration.old_username} @ {run.migration.old_host}",
        f"Destination: {run.migration.new_username} @ {run.migration.new_host}",
        f"Phase: {phase_label}",
        f"Status: {run.status}",
    ]
    if run.total:
        lines.append(f"Processed: {run.processed} / {run.total}")
    if run.started_at:
        lines.append(f"Started: {run.started_at.isoformat(timespec='seconds')}")
    if run.finished_at:
        lines.append(f"Finished: {run.finished_at.isoformat(timespec='seconds')}")
    if not ok and run.error:
        first_line = run.error.strip().splitlines()[0] if run.error.strip() else ""
        if first_line:
            lines.append("")
            lines.append(f"Error: {first_line[:300]}")

    body = "\n".join(lines) + "\n"

    try:
        send_mail(
            subject=subject,
            message=body,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[target],
            fail_silently=False,
        )
    except Exception:
        logger.exception("Notification email failed (run=%s, to=%s)", run.pk, target)


def _log(hub, level: str, message: str, **extra) -> None:
    hub.publish({"type": "log", "level": level, "message": message, **extra})


def _progress(hub, phase: str, processed: int, total: int, **extra) -> None:
    hub.publish({
        "type": "progress",
        "phase": phase,
        "processed": processed,
        "total": total,
        **extra,
    })


def _phase_status(hub, phase: str, status: str, **extra) -> None:
    hub.publish({"type": "phase", "phase": phase, "status": status, **extra})


def _connect_old(migration: Migration, creds: Credentials) -> ImapClient:
    return ImapClient(
        migration.old_host, migration.old_port,
        migration.old_username, creds.old_password,
        use_ssl=migration.old_use_ssl,
    )


def _connect_new(migration: Migration, creds: Credentials) -> ImapClient:
    return ImapClient(
        migration.new_host, migration.new_port,
        migration.new_username, creds.new_password,
        use_ssl=migration.new_use_ssl,
    )


def _active_mappings(migration: Migration) -> list[FolderMapping]:
    return list(
        migration.folder_mappings.exclude(action=FolderMapping.ACTION_SKIP)
        .order_by("old_folder")
    )


def _collect_verify_ids(client: ImapClient) -> set[str]:
    """Dedup-id set for the currently-selected folder.

    Prefers the Message-ID header; for messages without one, falls back to a
    sha256 of the raw RFC822 — same key transfer uses, so headerless messages
    still pair up across old and new.
    """
    uid_to_mid = client.fetch_message_ids() or {}
    ids: set[str] = set()
    headerless: list[int] = []
    for uid, mid in uid_to_mid.items():
        mid = (mid or "").strip()
        if mid:
            ids.add(mid)
        else:
            headerless.append(uid)
    for uid in headerless:
        try:
            raw, _flags, _idate = client.fetch_message(uid)
        except Exception:
            continue
        ids.add(synthetic_message_id(raw))
    return ids


# ---------------------------------------------------------------------------
# Phase 1 - Backup
# ---------------------------------------------------------------------------


def run_backup(migration_id: int) -> None:
    migration = Migration.objects.get(pk=migration_id)
    creds = load_credentials(migration_id)
    hub = STATE.hub(migration_id)
    if creds is None:
        _log(hub, "error", "No credentials saved; re-enter on the configuration screen.")
        _phase_status(hub, "backup", "failed")
        return

    run = _start_phase(migration, PhaseRun.PHASE_BACKUP)
    _phase_status(hub, "backup", "running")
    _log(hub, "info", "Backup phase started.")

    total_messages = 0
    processed = 0
    error_msg = ""

    try:
        with _connect_old(migration, creds) as old:
            mappings = _active_mappings(migration)
            if not mappings:
                raise RuntimeError("No folders mapped. Configure mapping on Screen 1.")

            # Pre-count totals
            for m in mappings:
                count = old.select(m.old_folder, readonly=True)
                total_messages += count
            _log(hub, "info", f"Counted {total_messages} messages across {len(mappings)} folders.")
            run.total = total_messages
            run.save(update_fields=["total"])
            _progress(hub, "backup", 0, total_messages)

            for mapping in mappings:
                folder = mapping.old_folder
                _log(hub, "info", f"Backing up folder: {folder}")
                count = old.select(folder, readonly=True)
                if count == 0:
                    _log(hub, "info", f"  (empty)")
                    continue

                # Build per-folder dedup set from DB so we can skip already-backed-up messages.
                already_backed = set(
                    MessageRecord.objects.filter(
                        migration=migration, folder=folder, backed_up=True,
                    ).exclude(raw_bytes=b"").values_list("message_id", flat=True)
                )

                uid_to_mid = old.fetch_message_ids() or {}
                uids = sorted(uid_to_mid)
                skipped = 0
                new_in_folder = 0
                for uid in uids:
                    # Cheap skip: if Message-ID header is already known + backed up, don't fetch.
                    header_mid = (uid_to_mid.get(uid) or "").strip()
                    if header_mid and header_mid in already_backed:
                        skipped += 1
                        processed += 1
                        continue

                    try:
                        raw, flags, internaldate = old.fetch_message(uid)
                    except Exception as exc:
                        _log(hub, "warn", f"  UID {uid} fetch failed: {exc}")
                        continue
                    msg_id = parse_message_id(raw) or synthetic_message_id(raw)

                    rec, _ = MessageRecord.objects.get_or_create(
                        migration=migration,
                        folder=folder,
                        message_id=msg_id,
                        defaults={"size": len(raw)},
                    )
                    if rec.backed_up and rec.raw_bytes:
                        skipped += 1
                        processed += 1
                        continue

                    rec.size = len(raw)
                    rec.flags = " ".join(flags or [])
                    rec.internaldate = internaldate or ""
                    rec.source_uid = uid
                    rec.backed_up = True
                    try:
                        rec.raw_bytes = raw
                        rec.save(update_fields=[
                            "size", "flags", "internaldate", "source_uid",
                            "backed_up", "raw_bytes",
                        ])
                    except Exception as exc:
                        # Most likely: message exceeds MySQL max_allowed_packet.
                        _log(hub, "warn",
                             f"  DB insert failed for {msg_id} ({len(raw)} bytes): {exc}")
                        rec.raw_bytes = b""
                        rec.save(update_fields=[
                            "size", "flags", "internaldate", "source_uid", "backed_up",
                        ])
                    new_in_folder += 1
                    processed += 1
                    run.processed = processed
                    if processed % 25 == 0 or processed == total_messages:
                        run.save(update_fields=["processed"])
                        _progress(hub, "backup", processed, total_messages, folder=folder)
                _log(hub, "info",
                     f"  {folder}: {new_in_folder} new, {skipped} already in DB")

            run.processed = processed
            run.save(update_fields=["processed"])
            _progress(hub, "backup", processed, total_messages)
            _log(hub, "info", "Backup complete.")
            _phase_status(hub, "backup", "success", processed=processed, total=total_messages)
            _finish_phase(run, ok=True)
    except Exception as exc:
        error_msg = f"{exc}\n{traceback.format_exc()}"
        _log(hub, "error", f"Backup failed: {exc}")
        _phase_status(hub, "backup", "failed", error=str(exc))
        _finish_phase(run, ok=False, error=error_msg)


# ---------------------------------------------------------------------------
# Phase 2 - Transfer
# ---------------------------------------------------------------------------


def run_transfer(migration_id: int) -> None:
    migration = Migration.objects.get(pk=migration_id)
    creds = load_credentials(migration_id)
    hub = STATE.hub(migration_id)
    if creds is None:
        _log(hub, "error", "No credentials saved; re-enter on the configuration screen.")
        _phase_status(hub, "transfer", "failed")
        return

    backup_complete = migration.phase_runs.filter(
        phase=PhaseRun.PHASE_BACKUP, status=PhaseRun.STATUS_SUCCESS
    ).exists()
    if not backup_complete:
        _log(hub, "error", "Cannot transfer: Backup has not completed successfully.")
        _phase_status(hub, "transfer", "failed")
        return

    run = _start_phase(migration, PhaseRun.PHASE_TRANSFER)
    _phase_status(hub, "transfer", "running")
    _log(hub, "info", "Transfer phase started.")

    processed = 0
    total = 0

    try:
        with _connect_old(migration, creds) as old, _connect_new(migration, creds) as new:
            mappings = _active_mappings(migration)
            existing_new_folders = {f.name for f in new.list_folders()}

            # totals
            for m in mappings:
                total += old.select(m.old_folder, readonly=True)
            run.total = total
            run.save(update_fields=["total"])
            _progress(hub, "transfer", 0, total)

            for mapping in mappings:
                src = mapping.old_folder
                dst = mapping.new_folder or mapping.old_folder
                _log(hub, "info", f"Transfer: {src} -> {dst}")

                if mapping.action == FolderMapping.ACTION_CREATE or dst not in existing_new_folders:
                    _log(hub, "info", f"  Creating destination folder {dst}")
                    new.create_folder(dst)
                    existing_new_folders.add(dst)

                # Build dedup index from destination
                new.select(dst, readonly=True)
                dst_msgids = set((new.fetch_message_ids() or {}).values())
                _log(hub, "info", f"  Destination has {len(dst_msgids)} existing Message-IDs")

                # Iterate source
                old.select(src, readonly=True)
                src_uid_to_mid = old.fetch_message_ids()
                uids = sorted(src_uid_to_mid)

                # Index DB-stored backups for this folder so we can avoid re-fetching
                # the bytes from the old server when we have them locally.
                db_records = {
                    r.message_id: r for r in MessageRecord.objects.filter(
                        migration=migration, folder=src, backed_up=True,
                    )
                }

                for uid in uids:
                    mid = (src_uid_to_mid.get(uid) or "").strip()

                    raw = b""
                    flags: list[str] = []
                    internaldate = ""
                    rec = db_records.get(mid) if mid else None
                    if rec and rec.raw_bytes:
                        raw = bytes(rec.raw_bytes)
                        flags = rec.flags.split() if rec.flags else []
                        internaldate = rec.internaldate or ""
                    else:
                        try:
                            raw, flags, internaldate = old.fetch_message(uid)
                        except Exception as exc:
                            _log(hub, "warn", f"  UID {uid} fetch failed: {exc}")
                            continue
                        if not mid:
                            mid = parse_message_id(raw) or synthetic_message_id(raw)

                    if rec is None:
                        rec, _ = MessageRecord.objects.get_or_create(
                            migration=migration,
                            folder=src,
                            message_id=mid,
                            defaults={"size": len(raw)},
                        )
                    if mid in dst_msgids or rec.transferred:
                        rec.transferred = True
                        rec.save(update_fields=["transferred"])
                        processed += 1
                        continue

                    try:
                        new.append(dst, raw, flags=flags, internaldate=internaldate)
                        rec.transferred = True
                        rec.save(update_fields=["transferred"])
                        dst_msgids.add(mid)
                    except Exception as exc:
                        _log(hub, "warn", f"  APPEND failed for {mid}: {exc}")
                    processed += 1
                    run.processed = processed
                    if processed % 25 == 0:
                        run.save(update_fields=["processed"])
                        _progress(hub, "transfer", processed, total, folder=src)

            run.processed = processed
            run.save(update_fields=["processed"])
            _progress(hub, "transfer", processed, total)
            _log(hub, "info", "Transfer complete.")
            _phase_status(hub, "transfer", "success", processed=processed, total=total)
            _finish_phase(run, ok=True)
    except Exception as exc:
        err = f"{exc}\n{traceback.format_exc()}"
        _log(hub, "error", f"Transfer failed: {exc}")
        _phase_status(hub, "transfer", "failed", error=str(exc))
        _finish_phase(run, ok=False, error=err)


# ---------------------------------------------------------------------------
# Phase 3 - Verify
# ---------------------------------------------------------------------------


def run_verify(migration_id: int) -> None:
    migration = Migration.objects.get(pk=migration_id)
    creds = load_credentials(migration_id)
    hub = STATE.hub(migration_id)
    if creds is None:
        _log(hub, "error", "No credentials saved; re-enter on the configuration screen.")
        _phase_status(hub, "verify", "failed")
        return

    transfer_complete = migration.phase_runs.filter(
        phase=PhaseRun.PHASE_TRANSFER, status=PhaseRun.STATUS_SUCCESS
    ).exists()
    if not transfer_complete:
        _log(hub, "error", "Cannot verify: Transfer has not completed successfully.")
        _phase_status(hub, "verify", "failed")
        return

    run = _start_phase(migration, PhaseRun.PHASE_VERIFY)
    _phase_status(hub, "verify", "running")
    _log(hub, "info", "Verify phase started.")

    folders_report: dict[str, dict] = {}
    total_old = 0
    total_new = 0
    missing_total = 0

    try:
        with _connect_old(migration, creds) as old, _connect_new(migration, creds) as new:
            mappings = _active_mappings(migration)
            for mapping in mappings:
                src = mapping.old_folder
                dst = mapping.new_folder or src
                _log(hub, "info", f"Verifying {src} -> {dst}")
                old_count = old.select(src, readonly=True)
                old_ids = _collect_verify_ids(old)

                new_count = new.select(dst, readonly=True)
                new_ids = _collect_verify_ids(new)

                missing = sorted(old_ids - new_ids)
                folders_report[src] = {
                    "destination": dst,
                    "old_count": old_count,
                    "new_count": new_count,
                    "missing_count": len(missing),
                    "sample_missing": missing[:10],
                }
                total_old += old_count
                total_new += new_count
                missing_total += len(missing)

                if missing:
                    _log(hub, "warn", f"  {len(missing)} missing Message-IDs in {dst}")
                else:
                    _log(hub, "info", f"  OK ({old_count} messages)")

            report, _ = VerificationReport.objects.update_or_create(
                migration=migration,
                defaults={
                    "total_old": total_old,
                    "total_new": total_new,
                    "missing_total": missing_total,
                    "folders_json": folders_report,
                },
            )
            ok = report.all_green
            _log(hub, "info", f"Verify complete. Missing: {missing_total}")
            _phase_status(hub, "verify", "success" if ok else "failed",
                          missing=missing_total, total_old=total_old, total_new=total_new)
            _finish_phase(run, ok=ok, error="" if ok else f"{missing_total} missing message(s)")
    except Exception as exc:
        err = f"{exc}\n{traceback.format_exc()}"
        _log(hub, "error", f"Verify failed: {exc}")
        _phase_status(hub, "verify", "failed", error=str(exc))
        _finish_phase(run, ok=False, error=err)


# ---------------------------------------------------------------------------
# Phase 4 - Cleanup
# ---------------------------------------------------------------------------


class CleanupGate:
    """Six independent safety checks. All must pass before any deletion."""

    def __init__(self, migration: Migration, confirmed: bool) -> None:
        self.migration = migration
        self.confirmed = confirmed
        self.results: list[dict] = []

    def _check(self, name: str, ok: bool, detail: str = "") -> None:
        self.results.append({"name": name, "ok": ok, "detail": detail})

    def evaluate(self) -> bool:
        report = getattr(self.migration, "verification", None)

        # 1
        self._check(
            "Verification report exists",
            report is not None,
            "" if report else "Run Verify first.",
        )
        # 2
        if report:
            age = timezone.now() - report.created_at
            self._check(
                "Report is < 60 minutes old",
                age < timedelta(minutes=60),
                f"Report age: {int(age.total_seconds() // 60)} min.",
            )
        else:
            self._check("Report is < 60 minutes old", False, "No report.")
        # 3
        if report:
            self._check(
                "Every folder reports zero missing messages",
                report.missing_total == 0,
                f"{report.missing_total} missing.",
            )
        else:
            self._check("Every folder reports zero missing messages", False, "No report.")
        # 4
        mapped = {m.old_folder for m in _active_mappings(self.migration)}
        if report:
            reported = set(report.folders_json.keys())
            missing_folders = mapped - reported
            self._check(
                "Every mapped folder appears in the report",
                not missing_folders,
                ("Missing: " + ", ".join(sorted(missing_folders))) if missing_folders else "",
            )
        else:
            self._check("Every mapped folder appears in the report", False, "No report.")
        # 5
        self._check(
            "Operator confirmed deletion",
            self.confirmed,
            "" if self.confirmed else "Confirmation checkbox not ticked.",
        )
        # 6 is checked at run time inside the thread (live re-check)

        return all(r["ok"] for r in self.results)


def run_cleanup(migration_id: int, confirmed: bool) -> None:
    migration = Migration.objects.get(pk=migration_id)
    creds = load_credentials(migration_id)
    hub = STATE.hub(migration_id)
    if creds is None:
        _log(hub, "error", "No credentials saved; re-enter on the configuration screen.")
        _phase_status(hub, "cleanup", "failed")
        return

    gate = CleanupGate(migration, confirmed)
    ok = gate.evaluate()
    for r in gate.results:
        _log(
            hub,
            "info" if r["ok"] else "error",
            f"Safety {r['name']}: {'PASS' if r['ok'] else 'FAIL'} {r['detail']}",
        )
    if not ok:
        _phase_status(hub, "cleanup", "failed", error="Safety checks failed")
        return

    run = _start_phase(migration, PhaseRun.PHASE_CLEANUP)
    _phase_status(hub, "cleanup", "running")
    _log(hub, "info", "Cleanup phase started.")

    try:
        with _connect_old(migration, creds) as old, _connect_new(migration, creds) as new:
            # Safety 6 (live re-check)
            _log(hub, "info", "Live re-check against old server...")
            mappings = _active_mappings(migration)
            for mapping in mappings:
                src = mapping.old_folder
                dst = mapping.new_folder or src
                old.select(src, readonly=True)
                old_ids = _collect_verify_ids(old)
                new.select(dst, readonly=True)
                new_ids = _collect_verify_ids(new)
                missing = old_ids - new_ids
                if missing:
                    msg = (f"Live re-check FAIL on {src}: {len(missing)} message(s) "
                           f"present on old but not on new. Aborting deletion.")
                    raise RuntimeError(msg)
            _log(hub, "info", "Live re-check passed for all folders.")

            total_deleted = 0
            for mapping in mappings:
                src = mapping.old_folder
                _log(hub, "info", f"Emptying {src}...")
                deleted = old.expunge_all(src)
                total_deleted += deleted
                _log(hub, "info", f"  Deleted {deleted} message(s).")
            _log(hub, "info", f"Cleanup complete. {total_deleted} message(s) removed.")
            run.processed = total_deleted
            run.total = total_deleted
            run.save(update_fields=["processed", "total"])
            _phase_status(hub, "cleanup", "success", deleted=total_deleted)
            _finish_phase(run, ok=True)
    except Exception as exc:
        err = f"{exc}\n{traceback.format_exc()}"
        _log(hub, "error", f"Cleanup failed: {exc}")
        _phase_status(hub, "cleanup", "failed", error=str(exc))
        _finish_phase(run, ok=False, error=err)


# ---------------------------------------------------------------------------
# Launcher
# ---------------------------------------------------------------------------

PHASE_FUNCS = {
    PhaseRun.PHASE_BACKUP: run_backup,
    PhaseRun.PHASE_TRANSFER: run_transfer,
    PhaseRun.PHASE_VERIFY: run_verify,
}


def launch_phase(migration_id: int, phase: str, **kwargs) -> bool:
    if STATE.is_running(migration_id, phase):
        return False
    if phase == PhaseRun.PHASE_CLEANUP:
        target = lambda: run_cleanup(migration_id, kwargs.get("confirmed", False))
    else:
        fn = PHASE_FUNCS[phase]
        target = lambda: fn(migration_id)
    t = threading.Thread(target=target, name=f"phase-{phase}-{migration_id}", daemon=True)
    STATE.register_thread(migration_id, phase, t)
    t.start()
    return True

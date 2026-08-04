"""Scheduled backups: work out when each job is next due, and run what's due.

Ticked by ``manage.py run_scheduled_backups`` (see the `scheduler` service in
docker-compose.yml). Runs are sequential — one mailbox at a time — so a dozen
scheduled jobs can't open a dozen IMAP sessions at once.

Schedule times are in ``settings.TIME_ZONE`` (Europe/Berlin), because that is
what a user means when they pick 03:00. Everything is stored UTC as usual.
"""

from __future__ import annotations

import logging
from contextlib import contextmanager
from datetime import datetime, timedelta

from django.db import close_old_connections, connection
from django.utils import timezone

from .models import BackupJob, SchedulerHeartbeat


logger = logging.getLogger(__name__)

LOCK_NAME = "mtx_backup_scheduler"

# A job whose status is still "running" after this long is assumed dead (the
# container was killed mid-run), so the schedule isn't blocked forever.
STALE_RUN_AFTER = timedelta(hours=12)

# The UI warns when the last tick is older than this.
HEARTBEAT_STALE_AFTER = timedelta(minutes=15)


# ---------------------------------------------------------------------------
# Next-run calculation
# ---------------------------------------------------------------------------

def compute_next_run(job: BackupJob, after=None) -> datetime | None:
    """First moment strictly after `after` that matches the job's schedule.

    Returns None when the schedule is off. Builds the candidate as naive local
    time and then localises it, so the hour a user picked stays that hour on
    both sides of a daylight-saving change.
    """
    if not job.schedule_is_on:
        return None

    tz = timezone.get_current_timezone()
    now_local = timezone.localtime(after or timezone.now(), tz).replace(tzinfo=None)
    minute = min(int(job.schedule_minute or 0), 59)
    hour = min(int(job.schedule_hour or 0), 23)

    if job.schedule == BackupJob.SCHEDULE_HOURLY:
        candidate = now_local.replace(minute=minute, second=0, microsecond=0)
        while candidate <= now_local:
            candidate += timedelta(hours=1)

    elif job.schedule == BackupJob.SCHEDULE_6H:
        # Anchored to 00:mm, so the slots are 00, 06, 12, 18 — predictable
        # regardless of when the schedule was saved.
        candidate = now_local.replace(hour=0, minute=minute, second=0, microsecond=0)
        while candidate <= now_local:
            candidate += timedelta(hours=6)

    elif job.schedule == BackupJob.SCHEDULE_DAILY:
        candidate = now_local.replace(hour=hour, minute=minute, second=0, microsecond=0)
        if candidate <= now_local:
            candidate += timedelta(days=1)

    elif job.schedule == BackupJob.SCHEDULE_WEEKLY:
        candidate = now_local.replace(hour=hour, minute=minute, second=0, microsecond=0)
        days_ahead = (int(job.schedule_weekday or 0) - candidate.weekday()) % 7
        candidate += timedelta(days=days_ahead)
        if candidate <= now_local:
            candidate += timedelta(days=7)

    else:
        return None

    return timezone.make_aware(candidate, tz)


def reschedule(job: BackupJob, after=None, save: bool = True) -> datetime | None:
    """Set (and persist) the job's next_run_at. Call after saving a schedule
    and after every scheduled run."""
    job.next_run_at = compute_next_run(job, after=after)
    if save:
        job.save(update_fields=["next_run_at"])
    return job.next_run_at


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

def beat() -> None:
    SchedulerHeartbeat.objects.update_or_create(
        key="backup-scheduler", defaults={"last_seen": timezone.now()},
    )


def health() -> dict:
    """{'running': bool, 'last_seen': dt|None} — drives the UI warning."""
    row = SchedulerHeartbeat.objects.filter(key="backup-scheduler").first()
    if row is None:
        return {"running": False, "last_seen": None}
    return {
        "running": timezone.now() - row.last_seen <= HEARTBEAT_STALE_AFTER,
        "last_seen": row.last_seen,
    }


# ---------------------------------------------------------------------------
# Tick
# ---------------------------------------------------------------------------

@contextmanager
def exclusive_lock(name: str = LOCK_NAME):
    """Yield True only if this process holds the cluster-wide scheduler lock.

    Two scheduler containers (a stale one left running after a deploy, say)
    would otherwise both fire the same job. Non-MySQL backends — the test
    suite's SQLite — have no advisory locks, so there the lock is a no-op.
    """
    if connection.vendor != "mysql":
        yield True
        return
    with connection.cursor() as cur:
        cur.execute("SELECT GET_LOCK(%s, 0)", [name])
        row = cur.fetchone()
    acquired = bool(row and row[0] == 1)
    try:
        yield acquired
    finally:
        if acquired:
            with connection.cursor() as cur:
                cur.execute("SELECT RELEASE_LOCK(%s)", [name])


def due_jobs(now=None):
    """Jobs whose next run is in the past, oldest first."""
    now = now or timezone.now()
    return (
        BackupJob.objects
        .exclude(schedule=BackupJob.SCHEDULE_OFF)
        .filter(next_run_at__isnull=False, next_run_at__lte=now)
        .order_by("next_run_at")
    )


def _skip_reason(job: BackupJob) -> str:
    from .backup import blocking_reason

    if job.status == BackupJob.STATUS_RUNNING and job.started_at:
        if timezone.now() - job.started_at < STALE_RUN_AFTER:
            return "already running"
    return blocking_reason(job)


def run_due(stdout=None) -> int:
    """Run every due job once, sequentially. Returns how many ran.

    A job that raises is recorded as failed by run_backup_job itself; here we
    only make sure one bad mailbox can't stop the rest of the queue.
    """
    def say(msg: str) -> None:
        logger.info(msg)
        if stdout is not None:
            stdout.write(f"[{timezone.localtime():%Y-%m-%d %H:%M:%S}] {msg}")

    from .backup import run_backup_job

    ran = 0
    for job in list(due_jobs()):
        # Re-read: the row may have changed while an earlier job was running.
        job.refresh_from_db()
        if not job.schedule_is_on or job.next_run_at is None or job.next_run_at > timezone.now():
            continue

        reason = _skip_reason(job)
        if reason:
            say(f"Skipping backup #{job.pk} ({job.label}): {reason}.")
            # Still move the schedule forward, or we'd retry every single tick.
            reschedule(job)
            continue

        say(f"Running backup #{job.pk} ({job.username}) — {job.schedule_description()}")
        job.last_scheduled_at = timezone.now()
        job.save(update_fields=["last_scheduled_at"])
        try:
            run_backup_job(job.pk, scheduled=True)
        except Exception:
            logger.exception("Scheduled backup #%s crashed", job.pk)
            say(f"Backup #{job.pk} crashed — see the log.")
        finally:
            job.refresh_from_db()
            reschedule(job)
            ran += 1
        say(
            f"Backup #{job.pk} {job.status}: {job.processed}/{job.total} messages. "
            f"Next run {timezone.localtime(job.next_run_at):%Y-%m-%d %H:%M}"
            if job.next_run_at else f"Backup #{job.pk} {job.status}."
        )
    return ran


def tick(stdout=None) -> int:
    """One scheduler pass: take the lock, run what's due, record the heartbeat."""
    close_old_connections()
    with exclusive_lock() as acquired:
        if not acquired:
            logger.debug("Another scheduler holds the lock; skipping this tick.")
            return 0
        ran = run_due(stdout=stdout)
        beat()
        return ran

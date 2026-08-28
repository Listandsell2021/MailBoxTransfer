"""Revive work whose process died.

Every phase (Backup, Transfer, Verify) and every standalone Backup/Restore job
runs in a background thread. A thread dies with its process, so a deploy, an
OOM kill or a `reboot` leaves rows in the database that still say "running"
while nothing anywhere is working on them. Before this module existed those
rows stayed that way forever and the mailbox was simply left half-copied.

Two facts make recovery cheap:

* every runner stamps `heartbeat_at` every 30 seconds
  (``runtime.start_heartbeat``), so a row marked running whose heartbeat went
  quiet provably belongs to a process that is gone; and
* every phase already skips work it has already done — backup skips messages
  already stored, transfer skips Message-IDs already on the destination,
  restore skips what the destination already holds — so *restarting* a phase
  is the same thing as *resuming* it.

``recover()`` runs on every scheduler tick (once a minute), which means a
server restart repairs itself without anyone clicking anything. The same
functions back the Resume buttons in the UI and the ``recover_stuck_runs``
management command.

Cleanup is the one phase never resumed automatically: it deletes mail from the
source server and requires a fresh verification report plus a human ticking the
confirmation box. An interrupted cleanup is closed and left for a person.
"""

from __future__ import annotations

import logging
from datetime import timedelta

from django.db.models import Q
from django.utils import timezone

from .models import (
    RUN_STALE_AFTER,
    BackupJob,
    PhaseRun,
    RestoreJob,
)


logger = logging.getLogger(__name__)

# How many times in a row a job may be revived automatically. A run that dies
# the instant it starts would otherwise be restarted every minute forever; past
# this many attempts it is left failed for a human to look at.
MAX_AUTO_RESUMES = 5

# Only pick up work that stopped recently. A run interrupted twenty minutes ago
# is one somebody is still waiting on; one that stopped days ago is history, and
# opening IMAP sessions against a mailbox nobody asked about is not a decision
# this sweep should be making on its own. Older rows are closed as interrupted,
# and the Resume button is there for anyone who does want them back.
AUTO_RESUME_WITHIN = timedelta(hours=6)

# How much revived work may be in flight at once, across every kind of job.
# Ten mailboxes interrupted by one restart would otherwise all come back in the
# same second, against the same source servers, on a box sized for a couple of
# them. The rest wait for a later tick, a minute apart.
MAX_CONCURRENT_RESUMED = 3

INTERRUPTED_ERROR = (
    "Interrupted — the process running this disappeared "
    "(the server or container restarted)."
)


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

def _stale_filter(now=None) -> Q:
    """Rows whose last sign of life is older than RUN_STALE_AFTER.

    The `heartbeat_at__isnull` arms matter for rows written before heartbeats
    existed, and for a process that died in the seconds between going running
    and its first stamp.
    """
    cutoff = (now or timezone.now()) - RUN_STALE_AFTER
    return (
        Q(heartbeat_at__lt=cutoff)
        | Q(heartbeat_at__isnull=True, started_at__lt=cutoff)
        | Q(heartbeat_at__isnull=True, started_at__isnull=True)
    )


def stalled_phase_runs(now=None):
    return PhaseRun.objects.filter(
        _stale_filter(now), status=PhaseRun.STATUS_RUNNING,
    ).select_related("migration").order_by("id")


def stalled_backup_jobs(now=None):
    return BackupJob.objects.filter(
        _stale_filter(now), status=BackupJob.STATUS_RUNNING,
    ).order_by("id")


def stalled_restore_jobs(now=None):
    return RestoreJob.objects.filter(
        _stale_filter(now), status=RestoreJob.STATUS_RUNNING,
    ).order_by("id")


def _fresh_filter(now=None) -> Q:
    """The complement of `_stale_filter`, written out rather than negated:
    `NOT (... OR heartbeat_at IS NULL ...)` does not mean what it looks like it
    means once NULLs are involved."""
    cutoff = (now or timezone.now()) - RUN_STALE_AFTER
    return (
        Q(heartbeat_at__gte=cutoff)
        | Q(heartbeat_at__isnull=True, started_at__gte=cutoff)
    )


def running_now(now=None) -> int:
    """Jobs that are running and still answering — the live workload."""
    fresh = _fresh_filter(now)
    return (
        PhaseRun.objects.filter(fresh, status=PhaseRun.STATUS_RUNNING).count()
        + BackupJob.objects.filter(fresh, status=BackupJob.STATUS_RUNNING).count()
        + RestoreJob.objects.filter(fresh, status=RestoreJob.STATUS_RUNNING).count()
    )


def stalled_summary(now=None) -> dict:
    """What is currently stuck — for the command's --list and for logging."""
    return {
        "phases": list(stalled_phase_runs(now)),
        "backups": list(stalled_backup_jobs(now)),
        "restores": list(stalled_restore_jobs(now)),
    }


# ---------------------------------------------------------------------------
# Closing a dead row
# ---------------------------------------------------------------------------

def close_as_interrupted(obj, note: str = "") -> None:
    """Mark one dead row failed+interrupted. Never touches a live row."""
    model = type(obj)
    model.objects.filter(pk=obj.pk, status="running").update(
        status="failed",
        finished_at=timezone.now(),
        interrupted=True,
        error=(INTERRUPTED_ERROR + (f" {note}" if note else "")),
    )


def close_stalled_phase_runs(migration_id: int, phase: str) -> int:
    """Close any dead run of this migration+phase before a new one starts.

    Called from `_start_phase`, so pressing Resume in the UI tidies up the row
    the crash left behind instead of stacking a second "running" row on top of
    it. Only rows that are provably dead are touched.
    """
    stale = PhaseRun.objects.filter(
        _stale_filter(), migration_id=migration_id, phase=phase,
        status=PhaseRun.STATUS_RUNNING,
    )
    closed = 0
    for run in stale:
        close_as_interrupted(run)
        closed += 1
    return closed


# ---------------------------------------------------------------------------
# Resuming
# ---------------------------------------------------------------------------

def _phase_blocker(run: PhaseRun) -> str:
    """Why this interrupted phase can't just be started again — "" if it can."""
    from .runtime import load_credentials

    if run.phase == PhaseRun.PHASE_CLEANUP:
        return "cleanup is never resumed automatically; re-run it by hand"
    if run.resumed_count >= MAX_AUTO_RESUMES:
        return f"already resumed {run.resumed_count} times without finishing"
    if not load_credentials(run.migration_id):
        return "no credentials saved for this migration"
    return ""


def resume_phase_run(run: PhaseRun, force: bool = False) -> tuple[bool, str]:
    """Close a dead phase run and start the phase again. -> (resumed, reason)."""
    from .phases import launch_phase

    reason = "" if force else _phase_blocker(run)
    close_as_interrupted(run, note=f"Not resumed: {reason}" if reason else "")
    if reason:
        return False, reason
    if not launch_phase(run.migration_id, run.phase, resumed=True):
        return False, "already running in this process"
    return True, ""


def resume_backup_job(job: BackupJob, force: bool = False) -> tuple[bool, str]:
    from .backup import blocking_reason, launch_backup_job

    reason = ""
    if not force:
        if job.resumed_count >= MAX_AUTO_RESUMES:
            reason = f"already resumed {job.resumed_count} times without finishing"
        else:
            reason = blocking_reason(job)
    close_as_interrupted(job, note=f"Not resumed: {reason}" if reason else "")
    if reason:
        return False, reason
    if not launch_backup_job(job.pk, resumed=True):
        return False, "already running in this process"
    return True, ""


def resume_restore_job(job: RestoreJob, force: bool = False) -> tuple[bool, str]:
    from .restore import launch_restore_job

    reason = ""
    if not force:
        if job.resumed_count >= MAX_AUTO_RESUMES:
            reason = f"already resumed {job.resumed_count} times without finishing"
        elif not bytes(job.password_enc):
            reason = "no password saved for the destination mailbox"
    close_as_interrupted(job, note=f"Not resumed: {reason}" if reason else "")
    if reason:
        return False, reason
    if not launch_restore_job(job.pk, resumed=True):
        return False, "already running in this process"
    return True, ""


# ---------------------------------------------------------------------------
# The sweep
# ---------------------------------------------------------------------------

def recover(say=None, resume: bool = True, max_age=AUTO_RESUME_WITHIN,
            limit: int = MAX_CONCURRENT_RESUMED) -> dict:
    """Find everything stalled and pick it back up. Returns a count per outcome.

    `resume=False` only closes the dead rows (what you want when a mailbox is
    in a state you'd rather inspect before more traffic is sent at it).
    `max_age=None` lifts the "only recent work" rule, for someone asking for an
    old run back by hand. `limit` caps how much revived work runs at once.

    Safe to call on every tick: with nothing stalled it costs a few indexed
    queries and does nothing.
    """
    def note(msg: str) -> None:
        logger.info(msg)
        if say is not None:
            say(msg)

    counts = {"resumed": 0, "closed": 0, "deferred": 0}

    # Counted once and kept up to date locally: re-querying after each launch
    # would race the thread that has only just been handed the work.
    in_flight = running_now()

    def handle(obj, label: str, resumer) -> None:
        nonlocal in_flight

        if not resume:
            close_as_interrupted(obj, note="Left closed; resume was not requested.")
            counts["closed"] += 1
            note(f"{label}: closed (not resumed).")
            return

        seen = obj.last_sign_of_life
        if max_age is not None and seen is not None and timezone.now() - seen > max_age:
            close_as_interrupted(
                obj, note="Too old to pick up automatically; resume it by hand if you want it.",
            )
            counts["closed"] += 1
            note(f"{label}: interrupted too long ago to resume on its own; closed.")
            return

        if in_flight >= limit:
            # Left running so a later tick finds it again — nothing is lost,
            # it just waits its turn.
            counts["deferred"] += 1
            note(f"{label}: waiting for a free slot ({in_flight} job(s) already running).")
            return

        ok, reason = resumer(obj)
        if ok:
            in_flight += 1
            counts["resumed"] += 1
            note(f"{label}: interrupted by a restart - resumed.")
        else:
            counts["closed"] += 1
            note(f"{label}: interrupted and left failed - {reason}.")

    for run in stalled_phase_runs():
        handle(
            run,
            f"Migration #{run.migration_id} {run.phase} (run #{run.pk}, "
            f"{run.processed}/{run.total} done)",
            resume_phase_run,
        )

    for job in stalled_backup_jobs():
        handle(
            job,
            f"Backup #{job.pk} ({job.label}, {job.processed}/{job.total} done)",
            resume_backup_job,
        )

    for job in stalled_restore_jobs():
        handle(
            job,
            f"Restore #{job.pk} ({job.label}, {job.processed}/{job.total} done)",
            resume_restore_job,
        )

    return counts

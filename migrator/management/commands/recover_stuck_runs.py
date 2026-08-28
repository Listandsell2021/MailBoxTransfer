"""Find work left "running" by a process that died, and pick it back up.

    python manage.py recover_stuck_runs --list    # show what's stuck, change nothing
    python manage.py recover_stuck_runs           # resume everything stuck
    python manage.py recover_stuck_runs --close   # just mark them failed
    python manage.py recover_stuck_runs --force   # resume even past the retry cap

The scheduler container does this automatically every minute (see
migrator.scheduler.tick), so this command is for looking at the situation by
hand, or for a one-off recovery on a box where the scheduler isn't running:

    docker compose exec -T web python manage.py recover_stuck_runs --list
"""
from __future__ import annotations

from django.core.management.base import BaseCommand
from django.utils import timezone

from migrator import supervisor


class Command(BaseCommand):
    help = "Resume backups, transfers and restores whose process disappeared."

    def add_arguments(self, parser):
        parser.add_argument(
            "--list", action="store_true",
            help="Show what is stalled and exit without touching anything.",
        )
        parser.add_argument(
            "--close", action="store_true",
            help="Mark stalled runs failed instead of restarting them.",
        )
        parser.add_argument(
            "--force", action="store_true",
            help="Resume runs the sweep would leave alone: ones past the "
                 "automatic-retry cap, and ones interrupted too long ago.",
        )

    def handle(self, *args, **options):
        stalled = supervisor.stalled_summary()
        total = sum(len(v) for v in stalled.values())

        if not total:
            self.stdout.write(self.style.SUCCESS("Nothing is stalled."))
            return

        self.stdout.write(f"{total} stalled run(s):")
        for run in stalled["phases"]:
            self.stdout.write(
                f"  migration #{run.migration_id} {run.phase:8} run #{run.pk}  "
                f"{run.processed}/{run.total}  last seen {self._ago(run)}"
            )
        for job in stalled["backups"]:
            self.stdout.write(
                f"  backup     #{job.pk} {job.label}  "
                f"{job.processed}/{job.total}  last seen {self._ago(job)}"
            )
        for job in stalled["restores"]:
            self.stdout.write(
                f"  restore    #{job.pk} {job.label}  "
                f"{job.processed}/{job.total}  last seen {self._ago(job)}"
            )

        if options["list"]:
            self.stdout.write("\n--list: nothing was changed.")
            return

        if options["force"]:
            # Bypassing the cap is per-row state, so lift it by zeroing the
            # counter rather than threading a flag through the whole sweep.
            for row in stalled["phases"] + stalled["backups"] + stalled["restores"]:
                type(row).objects.filter(pk=row.pk).update(resumed_count=0)

        self.stdout.write("")
        counts = supervisor.recover(
            say=lambda m: self.stdout.write(f"  {m}"),
            resume=not options["close"],
            max_age=None if options["force"] else supervisor.AUTO_RESUME_WITHIN,
        )
        self.stdout.write(self.style.SUCCESS(
            f"Done: {counts['resumed']} resumed, {counts['closed']} closed, "
            f"{counts['deferred']} waiting for a free slot."
        ))
        if counts["deferred"]:
            self.stdout.write(
                "Deferred runs stay marked running and are picked up by a later "
                "scheduler tick, a few at a time."
            )

    @staticmethod
    def _ago(row) -> str:
        seen = row.last_sign_of_life
        if seen is None:
            return "never"
        mins = int((timezone.now() - seen).total_seconds() // 60)
        return f"{mins} min ago"

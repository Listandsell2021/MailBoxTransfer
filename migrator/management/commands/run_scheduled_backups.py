"""Run backup jobs whose schedule is due.

    python manage.py run_scheduled_backups            # one pass, then exit
    python manage.py run_scheduled_backups --loop     # tick forever (the container)
    python manage.py run_scheduled_backups --job 3    # force one job now

The `scheduler` service in docker-compose.yml runs the --loop form. A single
pass is also safe from cron:

    * * * * * cd /opt/app && docker compose exec -T web \
              python manage.py run_scheduled_backups
"""
from __future__ import annotations

import time

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from migrator.models import BackupJob
from migrator.scheduler import reschedule, tick


class Command(BaseCommand):
    help = "Run mailbox backups whose schedule is due."

    def add_arguments(self, parser):
        parser.add_argument(
            "--loop", action="store_true",
            help="Keep ticking until stopped, instead of a single pass.",
        )
        parser.add_argument(
            "--interval", type=int, default=60,
            help="Seconds between ticks in --loop mode (default 60).",
        )
        parser.add_argument(
            "--job", type=int,
            help="Ignore the schedule and run this job id right now.",
        )

    def handle(self, *args, **options):
        if options["job"]:
            self._run_one(options["job"])
            return

        if not options["loop"]:
            ran = tick(stdout=self.stdout)
            self.stdout.write(self.style.SUCCESS(f"Tick complete — {ran} job(s) ran."))
            return

        interval = max(10, options["interval"])
        self.stdout.write(self.style.SUCCESS(
            f"Backup scheduler started (every {interval}s, "
            f"timezone {timezone.get_current_timezone_name()}). Ctrl-C to stop."
        ))
        while True:
            try:
                tick(stdout=self.stdout)
            except KeyboardInterrupt:
                raise
            except Exception as exc:
                # Never let one bad tick kill the loop — a dropped database
                # connection would otherwise stop every future backup.
                self.stderr.write(f"Scheduler tick failed: {exc}")
            try:
                time.sleep(interval)
            except KeyboardInterrupt:
                self.stdout.write("\nScheduler stopped.")
                return

    def _run_one(self, job_id: int) -> None:
        from migrator.backup import run_backup_job

        try:
            job = BackupJob.objects.get(pk=job_id)
        except BackupJob.DoesNotExist:
            raise CommandError(f"No backup job with id {job_id}.")

        self.stdout.write(f"Running backup #{job.pk} ({job.username})…")
        run_backup_job(job.pk, scheduled=True)
        job.refresh_from_db()
        reschedule(job)
        style = self.style.SUCCESS if job.status == BackupJob.STATUS_SUCCESS else self.style.ERROR
        self.stdout.write(style(
            f"{job.status}: {job.processed}/{job.total} messages."
        ))
        if job.error:
            self.stderr.write(job.error.splitlines()[0])

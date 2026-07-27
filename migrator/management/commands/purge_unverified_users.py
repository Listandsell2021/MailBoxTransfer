"""Delete leftover spam signups: non-staff users with no verified email who
have never signed in. Dry-run by default — pass --yes to actually delete.

    python manage.py purge_unverified_users              # preview only
    python manage.py purge_unverified_users --yes        # delete
    python manage.py purge_unverified_users --min-age-hours 24 --yes

The --min-age-hours guard (default 0) skips recent signups so a legitimate
user who just registered and hasn't clicked their verification link yet is
never swept up.
"""
from __future__ import annotations

from datetime import timedelta

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand
from django.utils import timezone

from allauth.account.models import EmailAddress


class Command(BaseCommand):
    help = "Delete unverified, never-signed-in, non-staff user accounts (spam signups)."

    def add_arguments(self, parser):
        parser.add_argument(
            "--yes", action="store_true",
            help="Actually delete. Without this flag the command only previews.",
        )
        parser.add_argument(
            "--min-age-hours", type=int, default=0,
            help="Only purge accounts created at least this many hours ago (default 0).",
        )

    def handle(self, *args, **options):
        User = get_user_model()

        verified_user_ids = (
            EmailAddress.objects.filter(verified=True)
            .values_list("user_id", flat=True)
        )

        qs = User.objects.filter(
            is_staff=False,
            is_superuser=False,
            last_login__isnull=True,          # never signed in
        ).exclude(id__in=verified_user_ids)   # no verified email

        min_age = options["min_age_hours"]
        if min_age > 0:
            cutoff = timezone.now() - timedelta(hours=min_age)
            qs = qs.filter(date_joined__lte=cutoff)

        total = qs.count()
        if total == 0:
            self.stdout.write(self.style.SUCCESS("Nothing to purge — no matching accounts."))
            return

        self.stdout.write(f"Matched {total} unverified, never-signed-in account(s).")
        for u in qs.order_by("date_joined")[:20]:
            self.stdout.write(f"  - {u.email or u.get_username()}  (joined {u.date_joined:%Y-%m-%d})")
        if total > 20:
            self.stdout.write(f"  ... and {total - 20} more")

        if not options["yes"]:
            self.stdout.write(self.style.WARNING(
                "\nDry run. Re-run with --yes to delete these accounts."
            ))
            return

        deleted, _ = qs.delete()
        self.stdout.write(self.style.SUCCESS(f"\nDeleted {total} account(s) ({deleted} rows total)."))

"""One typed mailbox password serves every job for that mailbox."""
from django.contrib.auth import get_user_model
from django.test import TestCase

from migrator.credentials import recall, remember
from migrator.crypto import encrypt
from migrator.models import BackupJob, MailboxCredential, Migration
from migrator.runtime import STATE, load_credentials


class RememberRecallTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create(username="u")
        self.other = get_user_model().objects.create(username="other")

    def test_round_trip(self):
        remember(self.user.pk, "mail.example.com", "a@example.com", "hunter2")
        self.assertEqual(recall(self.user.pk, "mail.example.com", "a@example.com"), "hunter2")

    def test_host_is_case_insensitive_and_trimmed(self):
        remember(self.user.pk, " Mail.Example.COM ", " a@example.com ", "hunter2")
        self.assertEqual(recall(self.user.pk, "mail.example.com", "a@example.com"), "hunter2")
        self.assertEqual(MailboxCredential.objects.count(), 1)

    def test_a_new_password_replaces_the_old_one(self):
        remember(self.user.pk, "h", "u", "first")
        remember(self.user.pk, "h", "u", "second")
        self.assertEqual(MailboxCredential.objects.count(), 1)
        self.assertEqual(recall(self.user.pk, "h", "u"), "second")

    def test_blanks_are_never_stored(self):
        remember(self.user.pk, "h", "u", "")
        remember(None, "h", "u", "pw")
        remember(self.user.pk, "", "u", "pw")
        self.assertFalse(MailboxCredential.objects.exists())

    def test_one_users_password_is_not_offered_to_another(self):
        remember(self.user.pk, "h", "u", "hunter2")
        self.assertEqual(recall(self.other.pk, "h", "u"), "")

    def test_unknown_mailbox_recalls_nothing(self):
        self.assertEqual(recall(self.user.pk, "h", "u"), "")


class MigrationFallbackTests(TestCase):
    """A migration with nothing stored still runs, if the mailbox is known."""

    def setUp(self):
        self.user = get_user_model().objects.create(username="u")
        self.migration = Migration.objects.create(
            owner=self.user,
            old_host="old.example.com", old_username="a@example.com",
            new_host="new.example.com", new_username="b@example.com",
        )
        STATE._creds.clear()  # no in-memory shortcut; exercise the DB path

    def test_falls_back_to_the_saved_mailbox_password(self):
        remember(self.user.pk, "old.example.com", "a@example.com", "old-pw")
        remember(self.user.pk, "new.example.com", "b@example.com", "new-pw")
        creds = load_credentials(self.migration.pk)
        self.assertEqual(creds.old_password, "old-pw")
        self.assertEqual(creds.new_password, "new-pw")

    def test_the_row_wins_over_the_store(self):
        self.migration.old_password_enc = encrypt("on-the-row")
        self.migration.save(update_fields=["old_password_enc"])
        remember(self.user.pk, "old.example.com", "a@example.com", "in-the-store")
        STATE._creds.clear()
        self.assertEqual(load_credentials(self.migration.pk).old_password, "on-the-row")

    def test_nothing_anywhere_is_still_none(self):
        self.assertIsNone(load_credentials(self.migration.pk))


class BackupJobFallbackTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create(username="u")
        self.job = BackupJob.objects.create(
            owner=self.user, host="mail.example.com", username="a@example.com",
        )

    def test_connect_uses_the_saved_mailbox_password(self):
        from migrator import backup

        remember(self.user.pk, "mail.example.com", "a@example.com", "hunter2")
        client = backup.connect(self.job)
        self.assertEqual(client.password, "hunter2")

    def test_connect_still_complains_when_nothing_is_saved(self):
        from migrator import backup

        with self.assertRaisesMessage(RuntimeError, "No password saved"):
            backup.connect(self.job)

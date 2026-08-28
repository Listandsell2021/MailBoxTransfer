"""Recovery of runs whose process died (see migrator.supervisor)."""
from datetime import timedelta
from unittest import mock

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from migrator import supervisor
from migrator.models import BackupJob, Migration, PhaseRun, RestoreJob


def _ago(minutes):
    return timezone.now() - timedelta(minutes=minutes)


class StalledDetectionTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create(username="u")
        self.migration = Migration.objects.create(
            old_host="a", old_username="a", new_host="b", new_username="b",
            owner=self.user,
        )

    def _run(self, **kw):
        return PhaseRun.objects.create(
            migration=self.migration, phase=PhaseRun.PHASE_BACKUP,
            status=PhaseRun.STATUS_RUNNING, **kw,
        )

    def test_fresh_heartbeat_is_not_stalled(self):
        run = self._run(started_at=_ago(120), heartbeat_at=_ago(1))
        self.assertFalse(run.is_stalled)
        self.assertEqual(list(supervisor.stalled_phase_runs()), [])

    def test_quiet_heartbeat_is_stalled(self):
        run = self._run(started_at=_ago(120), heartbeat_at=_ago(30))
        self.assertTrue(run.is_stalled)
        self.assertEqual([r.pk for r in supervisor.stalled_phase_runs()], [run.pk])

    def test_rows_from_before_heartbeats_fall_back_to_started_at(self):
        """The rows already stuck in production have no heartbeat at all."""
        run = self._run(started_at=_ago(600), heartbeat_at=None)
        self.assertTrue(run.is_stalled)
        self.assertEqual([r.pk for r in supervisor.stalled_phase_runs()], [run.pk])

    def test_finished_runs_are_never_stalled(self):
        run = self._run(started_at=_ago(600))
        run.status = PhaseRun.STATUS_SUCCESS
        run.save()
        self.assertFalse(run.is_stalled)
        self.assertEqual(list(supervisor.stalled_phase_runs()), [])


class RecoverTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create(username="u")
        self.migration = Migration.objects.create(
            old_host="a", old_username="a", new_host="b", new_username="b",
            owner=self.user,
        )

    def _dead_run(self, minutes=30, **kw):
        """A run that went quiet `minutes` ago — long enough to be stalled,
        recent enough that the sweep is willing to pick it up."""
        return PhaseRun.objects.create(
            migration=self.migration, phase=PhaseRun.PHASE_BACKUP,
            status=PhaseRun.STATUS_RUNNING, started_at=_ago(minutes),
            processed=3750, total=4695, **kw,
        )

    @mock.patch("migrator.runtime.load_credentials")
    @mock.patch("migrator.phases.launch_phase")
    def test_dead_phase_is_closed_and_restarted(self, launch, creds):
        creds.return_value = object()
        launch.return_value = True
        run = self._dead_run()

        counts = supervisor.recover()

        run.refresh_from_db()
        self.assertEqual(run.status, PhaseRun.STATUS_FAILED)
        self.assertTrue(run.interrupted)
        self.assertIn("Interrupted", run.error)
        self.assertEqual(counts["resumed"], 1)
        launch.assert_called_once_with(
            self.migration.pk, PhaseRun.PHASE_BACKUP, resumed=True
        )

    @mock.patch("migrator.runtime.load_credentials")
    @mock.patch("migrator.phases.launch_phase")
    def test_a_run_that_keeps_dying_is_eventually_left_alone(self, launch, creds):
        creds.return_value = object()
        run = self._dead_run(resumed_count=supervisor.MAX_AUTO_RESUMES)

        counts = supervisor.recover()

        run.refresh_from_db()
        self.assertEqual(run.status, PhaseRun.STATUS_FAILED)
        self.assertEqual(counts["resumed"], 0)
        launch.assert_not_called()

    @mock.patch("migrator.runtime.load_credentials")
    @mock.patch("migrator.phases.launch_phase")
    def test_cleanup_is_never_resumed_automatically(self, launch, creds):
        creds.return_value = object()
        run = self._dead_run()
        run.phase = PhaseRun.PHASE_CLEANUP
        run.save()

        supervisor.recover()

        launch.assert_not_called()
        run.refresh_from_db()
        self.assertTrue(run.interrupted)

    @mock.patch("migrator.runtime.load_credentials", return_value=None)
    def test_a_migration_with_no_credentials_is_not_restarted(self, _creds):
        run = self._dead_run()
        counts = supervisor.recover()
        run.refresh_from_db()
        self.assertEqual(counts["resumed"], 0)
        self.assertIn("credentials", run.error)

    @mock.patch("migrator.backup.launch_backup_job", return_value=True)
    def test_dead_backup_job_is_resumed(self, launch):
        job = BackupJob.objects.create(
            owner=self.user, host="h", username="u", password_enc=b"x",
            status=BackupJob.STATUS_RUNNING, started_at=_ago(30),
            processed=25, total=6170,
        )
        counts = supervisor.recover()
        job.refresh_from_db()
        self.assertEqual(counts["resumed"], 1)
        self.assertTrue(job.interrupted)
        launch.assert_called_once_with(job.pk, resumed=True)

    def test_a_backup_with_no_password_is_not_resumed(self):
        job = BackupJob.objects.create(
            owner=self.user, host="h", username="u",
            status=BackupJob.STATUS_RUNNING, started_at=_ago(30),
        )
        counts = supervisor.recover()
        job.refresh_from_db()
        self.assertEqual(counts["resumed"], 0)
        self.assertEqual(job.status, BackupJob.STATUS_FAILED)

    @mock.patch("migrator.restore.launch_restore_job", return_value=True)
    def test_dead_restore_job_is_resumed(self, launch):
        job = RestoreJob.objects.create(
            owner=self.user, host="h", username="u", password_enc=b"x",
            status=RestoreJob.STATUS_RUNNING, started_at=_ago(30),
        )
        counts = supervisor.recover()
        self.assertEqual(counts["resumed"], 1)
        launch.assert_called_once_with(job.pk, resumed=True)

    @mock.patch("migrator.runtime.load_credentials")
    @mock.patch("migrator.phases.launch_phase", return_value=True)
    def test_close_only_mode_does_not_restart_anything(self, launch, creds):
        creds.return_value = object()
        self._dead_run()
        counts = supervisor.recover(resume=False)
        self.assertEqual((counts["resumed"], counts["closed"]), (0, 1))
        launch.assert_not_called()

    @mock.patch("migrator.runtime.load_credentials")
    @mock.patch("migrator.phases.launch_phase")
    def test_work_interrupted_long_ago_is_closed_not_restarted(self, launch, creds):
        """Nobody is waiting on a run from two days ago; don't open IMAP
        sessions for it on our own initiative."""
        creds.return_value = object()
        run = self._dead_run(minutes=60 * 48)

        counts = supervisor.recover()

        run.refresh_from_db()
        self.assertEqual(counts["resumed"], 0)
        self.assertTrue(run.interrupted)
        launch.assert_not_called()

    @mock.patch("migrator.runtime.load_credentials")
    @mock.patch("migrator.phases.launch_phase", return_value=True)
    def test_an_old_run_is_resumed_when_asked_for_explicitly(self, launch, creds):
        creds.return_value = object()
        self._dead_run(minutes=60 * 48)

        counts = supervisor.recover(max_age=None)

        self.assertEqual(counts["resumed"], 1)
        launch.assert_called_once()

    @mock.patch("migrator.runtime.load_credentials")
    @mock.patch("migrator.phases.launch_phase", return_value=True)
    def test_one_restart_does_not_start_every_mailbox_at_once(self, launch, creds):
        """Ten jobs killed by one restart come back a few at a time, not all
        in the same second against the same servers."""
        creds.return_value = object()
        for _ in range(10):
            BackupJob.objects.create(
                owner=self.user, host="h", username="u", password_enc=b"x",
                status=BackupJob.STATUS_RUNNING, started_at=_ago(30),
            )

        with mock.patch("migrator.backup.launch_backup_job", return_value=True):
            counts = supervisor.recover()

        self.assertEqual(counts["resumed"], supervisor.MAX_CONCURRENT_RESUMED)
        self.assertEqual(counts["deferred"], 10 - supervisor.MAX_CONCURRENT_RESUMED)
        # Deferred rows are left exactly as they were, so a later tick finds
        # them again. (The three that were resumed are closed here only because
        # the launch is mocked out; a real one puts the row back to running.)
        self.assertEqual(
            BackupJob.objects.filter(status=BackupJob.STATUS_RUNNING).count(),
            10 - supervisor.MAX_CONCURRENT_RESUMED,
        )

    @mock.patch("migrator.runtime.load_credentials")
    @mock.patch("migrator.phases.launch_phase")
    def test_a_healthy_run_elsewhere_counts_against_the_slot_limit(self, launch, creds):
        creds.return_value = object()
        for _ in range(supervisor.MAX_CONCURRENT_RESUMED):
            BackupJob.objects.create(
                owner=self.user, host="h", username="u", password_enc=b"x",
                status=BackupJob.STATUS_RUNNING, started_at=_ago(30),
                heartbeat_at=timezone.now(),
            )
        self._dead_run()

        counts = supervisor.recover()

        self.assertEqual((counts["resumed"], counts["deferred"]), (0, 1))
        launch.assert_not_called()


class StartPhaseTests(TestCase):
    """Starting a phase tidies up the row a crash left behind."""

    def setUp(self):
        self.migration = Migration.objects.create(
            old_host="a", old_username="a", new_host="b", new_username="b",
        )

    def test_a_new_run_closes_the_dead_one_and_counts_the_resume(self):
        from migrator.phases import _start_phase

        dead = PhaseRun.objects.create(
            migration=self.migration, phase=PhaseRun.PHASE_BACKUP,
            status=PhaseRun.STATUS_RUNNING, started_at=_ago(600), resumed_count=2,
        )

        run = _start_phase(self.migration, PhaseRun.PHASE_BACKUP, resumed=True)

        dead.refresh_from_db()
        self.assertEqual(dead.status, PhaseRun.STATUS_FAILED)
        self.assertTrue(dead.interrupted)
        self.assertEqual(run.resumed_count, 3)
        self.assertEqual(run.status, PhaseRun.STATUS_RUNNING)
        self.assertIsNotNone(run.heartbeat_at)
        self.assertTrue(run.worker)

    def test_a_run_started_by_hand_resets_the_resume_counter(self):
        from migrator.phases import _start_phase

        PhaseRun.objects.create(
            migration=self.migration, phase=PhaseRun.PHASE_BACKUP,
            status=PhaseRun.STATUS_FAILED, started_at=_ago(600), resumed_count=5,
        )
        run = _start_phase(self.migration, PhaseRun.PHASE_BACKUP)
        self.assertEqual(run.resumed_count, 0)

    def test_a_live_run_is_left_alone(self):
        from migrator.phases import _start_phase

        live = PhaseRun.objects.create(
            migration=self.migration, phase=PhaseRun.PHASE_BACKUP,
            status=PhaseRun.STATUS_RUNNING, started_at=_ago(10),
            heartbeat_at=timezone.now(),
        )
        _start_phase(self.migration, PhaseRun.PHASE_BACKUP)
        live.refresh_from_db()
        self.assertEqual(live.status, PhaseRun.STATUS_RUNNING)


class HeartbeatTests(TestCase):
    def test_the_ticker_stops_when_the_row_stops_running(self):
        from migrator.runtime import _Heartbeat

        migration = Migration.objects.create(
            old_host="a", old_username="a", new_host="b", new_username="b",
        )
        run = PhaseRun.objects.create(
            migration=migration, phase=PhaseRun.PHASE_BACKUP,
            status=PhaseRun.STATUS_RUNNING, started_at=timezone.now(),
        )
        hb = _Heartbeat(run, every=0.01)
        self.assertEqual(hb._touch(), 1)
        run.refresh_from_db()
        self.assertIsNotNone(run.heartbeat_at)
        self.assertTrue(run.worker)

        PhaseRun.objects.filter(pk=run.pk).update(status=PhaseRun.STATUS_SUCCESS)
        self.assertEqual(hb._touch(), 0)


class ResumePermissionTests(TestCase):
    """Who may press Resume. Admins act on every migration; a user who owns
    neither sees nothing at all."""

    def setUp(self):
        User = get_user_model()
        self.owner = User.objects.create_user("owner", password="x")
        self.admin = User.objects.create_user("admin", password="x", is_staff=True)
        self.other = User.objects.create_user("other", password="x")
        self.migration = Migration.objects.create(
            old_host="a", old_username="a", new_host="b", new_username="b",
            owner=self.owner,
        )

    def _sign_in(self, user):
        from django_otp.plugins.otp_static.models import StaticDevice

        device = StaticDevice.objects.create(user=user, name="test")
        self.client.force_login(user)
        session = self.client.session
        session["otp_device_id"] = device.persistent_id
        session.save()

    def _stalled_backup(self):
        return PhaseRun.objects.create(
            migration=self.migration, phase=PhaseRun.PHASE_BACKUP,
            status=PhaseRun.STATUS_RUNNING, started_at=_ago(60),
            processed=3750, total=4695,
        )

    def _post(self, phase=PhaseRun.PHASE_BACKUP):
        return self.client.post(
            f"/dashboard/{self.migration.pk}/resume/{phase}/", follow=False,
        )

    @mock.patch("migrator.views.load_credentials", return_value=object())
    @mock.patch("migrator.supervisor.resume_phase_run", return_value=(True, ""))
    def test_owner_can_resume(self, resume, _creds):
        self._stalled_backup()
        self._sign_in(self.owner)
        self.assertEqual(self._post().status_code, 302)
        resume.assert_called_once()

    @mock.patch("migrator.views.load_credentials", return_value=object())
    @mock.patch("migrator.supervisor.resume_phase_run", return_value=(True, ""))
    def test_admin_can_resume_someone_elses_interrupted_run(self, resume, _creds):
        self._stalled_backup()
        self._sign_in(self.admin)
        self.assertEqual(self._post().status_code, 302)
        resume.assert_called_once()

    @mock.patch("migrator.views.load_credentials", return_value=object())
    @mock.patch("migrator.views.launch_phase", return_value=True)
    def test_admin_can_start_a_phase_on_someone_elses_migration(self, launch, _creds):
        """Admins run this service; a mailbox belonging to a user who has gone
        home is theirs to move along."""
        self._sign_in(self.admin)
        self.assertEqual(self._post().status_code, 302)
        launch.assert_called_once()

    def test_a_stranger_gets_a_404(self):
        self._stalled_backup()
        self._sign_in(self.other)
        self.assertEqual(self._post().status_code, 404)

    def test_admin_can_open_a_dashboard_they_do_not_own(self):
        self._sign_in(self.admin)
        self.assertEqual(
            self.client.get(f"/dashboard/{self.migration.pk}/").status_code, 200,
        )

    def test_a_stranger_cannot_open_that_dashboard(self):
        self._sign_in(self.other)
        self.assertEqual(
            self.client.get(f"/dashboard/{self.migration.pk}/").status_code, 404,
        )

    def test_the_list_marks_every_row_manageable_for_an_admin(self):
        self._sign_in(self.admin)
        rows = self.client.get("/migrations/").context["migrations"]
        self.assertTrue(all(m.can_manage for m in rows))

    def test_the_list_marks_only_your_own_rows_manageable(self):
        self._sign_in(self.other)
        Migration.objects.create(old_host="a", old_username="a", new_host="b",
                                 new_username="b", owner=self.other)
        rows = self.client.get("/migrations/").context["migrations"]
        self.assertEqual([m.can_manage for m in rows], [True])

    def test_cleanup_is_not_resumable_from_here(self):
        self._sign_in(self.owner)
        self.assertEqual(self._post(PhaseRun.PHASE_CLEANUP).status_code, 400)


class MigrationListTests(TestCase):
    """Sorting and status filtering on the migrations list."""

    def setUp(self):
        User = get_user_model()
        self.admin = User.objects.create_user("admin", password="x", is_staff=True)
        self.zoe = User.objects.create_user("zoe", password="x")

        # Deliberately created in an order that matches none of the sorts.
        self.b = self._migration("beta", "b@x.de", owner=self.zoe)
        self.a = self._migration("alpha", "a@x.de", owner=self.admin)
        self.c = self._migration("gamma", "c@x.de", owner=self.admin)

        PhaseRun.objects.create(migration=self.a, phase=PhaseRun.PHASE_BACKUP,
                                status=PhaseRun.STATUS_SUCCESS)
        for phase in (PhaseRun.PHASE_BACKUP, PhaseRun.PHASE_TRANSFER):
            PhaseRun.objects.create(migration=self.b, phase=phase,
                                    status=PhaseRun.STATUS_SUCCESS)
        # self.c has no runs at all -> not-started

    def _migration(self, name, addr, owner):
        return Migration.objects.create(
            name=name, owner=owner,
            old_host="old.example.com", old_username=addr,
            new_host="new.example.com", new_username=addr,
        )

    def _sign_in(self):
        from django_otp.plugins.otp_static.models import StaticDevice

        device = StaticDevice.objects.create(user=self.admin, name="test")
        self.client.force_login(self.admin)
        session = self.client.session
        session["otp_device_id"] = device.persistent_id
        session.save()

    def _rows(self, query=""):
        self._sign_in()
        response = self.client.get("/migrations/" + query)
        self.assertEqual(response.status_code, 200)
        return [m.name for m in response.context["migrations"]]

    def test_sorts_by_label_both_ways(self):
        self.assertEqual(self._rows("?sort=label&dir=asc"), ["alpha", "beta", "gamma"])
        self.assertEqual(self._rows("?sort=label&dir=desc"), ["gamma", "beta", "alpha"])

    def test_sorts_by_source_address(self):
        self.assertEqual(self._rows("?sort=source&dir=asc"), ["alpha", "beta", "gamma"])

    def test_sorts_by_owner(self):
        self.assertEqual(self._rows("?sort=owner&dir=asc")[-1], "beta")  # zoe last

    def test_status_sorts_by_progress_not_alphabetically(self):
        """not-started < backed-up < transferred. Alphabetically 'backed-up'
        would lead and the ordering would mean nothing."""
        self.assertEqual(self._rows("?sort=status&dir=asc"), ["gamma", "alpha", "beta"])
        self.assertEqual(self._rows("?sort=status&dir=desc"), ["beta", "alpha", "gamma"])

    def test_filters_by_status(self):
        self.assertEqual(self._rows("?status=transferred"), ["beta"])
        self.assertEqual(self._rows("?status=not-started"), ["gamma"])

    def test_filter_and_sort_compose(self):
        rows = self._rows("?status=backed-up&sort=label&dir=desc")
        self.assertEqual(rows, ["alpha"])

    def test_counts_describe_everything_not_just_the_filtered_slice(self):
        self._sign_in()
        ctx = self.client.get("/migrations/?status=transferred").context
        self.assertEqual(ctx["total_count"], 3)
        self.assertEqual(ctx["shown_count"], 1)
        counts = {c["value"]: c["count"] for c in ctx["status_choices"]}
        self.assertEqual(counts["not-started"], 1)
        self.assertEqual(counts["backed-up"], 1)
        self.assertEqual(counts["transferred"], 1)

    def test_a_junk_sort_or_status_falls_back_instead_of_erroring(self):
        self._sign_in()
        response = self.client.get("/migrations/?sort=DROP+TABLE&dir=sideways&status=nope")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["sort"], "created")
        self.assertEqual(response.context["dir"], "desc")
        self.assertEqual(response.context["status_filter"], "")
        self.assertEqual(len(response.context["migrations"]), 3)

    def test_sort_links_keep_the_active_filter(self):
        self._sign_in()
        ctx = self.client.get("/migrations/?status=backed-up").context
        self.assertIn("status=backed-up", ctx["sortcols"]["label"]["url"])

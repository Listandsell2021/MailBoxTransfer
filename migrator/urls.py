from django.urls import path

from . import views

app_name = "migrator"

urlpatterns = [
    # Auth entry point. Anonymous users see the login page; authed users
    # are routed to 2FA setup/verify (in the two_factor namespace) or the app.
    path("login/", views.login, name="login"),
    path("login/continue/", views.after_login, name="after_login"),
    path("login/verify/", views.verify_otp, name="verify_otp"),

    path("", views.home, name="home"),
    path("profile/", views.profile, name="profile"),
    path("migrations/", views.index, name="index"),
    path("users/", views.users_list, name="users"),
    path("users/<int:user_id>/toggle-active/", views.toggle_user_active, name="toggle_user_active"),
    path("users/<int:user_id>/delete/", views.delete_user, name="delete_user"),

    # Backup-only mailbox archives (no destination server involved)
    path("backups/", views.backups, name="backups"),
    path("backups/new/", views.backup_config, name="backup_new"),
    path("backups/<int:job_id>/", views.backup_detail, name="backup_detail"),
    path("backups/<int:job_id>/edit/", views.backup_config, name="backup_edit"),
    path("backups/<int:job_id>/folders/", views.backup_refresh_folders, name="backup_refresh_folders"),
    path("backups/<int:job_id>/save-folders/", views.backup_save_folders, name="backup_save_folders"),
    path("backups/<int:job_id>/schedule/", views.backup_schedule, name="backup_schedule"),
    path("backups/<int:job_id>/start/", views.backup_start, name="backup_start"),
    path("backups/<int:job_id>/status/", views.backup_status, name="backup_status"),
    path("backups/<int:job_id>/stream/", views.backup_stream, name="backup_stream"),
    path("backups/<int:job_id>/log-snapshot/", views.backup_log_snapshot, name="backup_log_snapshot"),
    path("backups/<int:job_id>/download/", views.backup_download, name="backup_download"),
    path("backups/<int:job_id>/delete/", views.delete_backup_job, name="delete_backup_job"),

    # Restore — import an archive (uploaded or an existing backup) into a mailbox
    path("restores/", views.restores, name="restores"),
    path("restores/new/", views.restore_new, name="restore_new"),
    path("restores/<int:job_id>/", views.restore_detail, name="restore_detail"),
    path("restores/<int:job_id>/pair/", views.restore_pair, name="restore_pair"),
    path("restores/<int:job_id>/save-mapping/", views.restore_save_mapping, name="restore_save_mapping"),
    path("restores/<int:job_id>/start/", views.restore_start, name="restore_start"),
    path("restores/<int:job_id>/status/", views.restore_status, name="restore_status"),
    path("restores/<int:job_id>/stream/", views.restore_stream, name="restore_stream"),
    path("restores/<int:job_id>/log-snapshot/", views.restore_log_snapshot, name="restore_log_snapshot"),
    path("restores/<int:job_id>/delete/", views.delete_restore_job, name="delete_restore_job"),

    path("notifications/", views.notifications, name="notifications"),
    path("notifications/clear/", views.clear_notifications, name="clear_notifications"),

    path("config/new/", views.config, name="config_new"),
    path("config/<int:migration_id>/", views.config, name="config_edit"),
    path("config/<int:migration_id>/delete/", views.delete_migration, name="delete_migration"),
    path("config/<int:migration_id>/backup/download/", views.download_backup, name="download_backup"),
    path("report/<int:migration_id>/", views.report, name="report"),
    path("report/<int:migration_id>/download/", views.download_report_pdf, name="download_report_pdf"),
    path("config/<int:migration_id>/test/", views.test_connection, name="test_connection"),
    path("config/<int:migration_id>/save-mapping/", views.save_mapping, name="save_mapping"),

    path("dashboard/<int:migration_id>/", views.dashboard, name="dashboard"),
    path("dashboard/<int:migration_id>/start/<str:phase>/", views.start_phase, name="start_phase"),
    path("dashboard/<int:migration_id>/status/", views.phase_status, name="phase_status"),
    path("dashboard/<int:migration_id>/resume/<str:phase>/", views.resume_phase, name="resume_phase"),
    path("dashboard/<int:migration_id>/stream/", views.sse_stream, name="sse_stream"),
    path("dashboard/<int:migration_id>/log-snapshot/", views.log_snapshot, name="log_snapshot"),

    path("verify/<int:migration_id>/", views.verification, name="verification"),
    path("verify/<int:migration_id>/cleanup/", views.start_cleanup, name="start_cleanup"),
]

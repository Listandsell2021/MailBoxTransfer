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
    path("dashboard/<int:migration_id>/stream/", views.sse_stream, name="sse_stream"),

    path("verify/<int:migration_id>/", views.verification, name="verification"),
    path("verify/<int:migration_id>/cleanup/", views.start_cleanup, name="start_cleanup"),
]

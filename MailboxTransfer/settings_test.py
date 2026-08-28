"""Settings for running the test suite locally.

The application database is a shared MySQL server whose user cannot create the
`test_` database Django wants, so tests run against an in-memory SQLite:

    python manage.py test --settings=MailboxTransfer.settings_test
"""
from .settings import *  # noqa: F401,F403

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    }
}

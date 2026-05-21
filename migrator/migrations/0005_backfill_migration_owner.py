from django.db import migrations


def assign_orphans_to_first_superuser(apps, schema_editor):
    Migration = apps.get_model("migrator", "Migration")
    User = apps.get_model("auth", "User")
    admin = User.objects.filter(is_superuser=True).order_by("id").first()
    if admin is None:
        return
    Migration.objects.filter(owner__isnull=True).update(owner=admin)


def noop_reverse(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ("migrator", "0004_add_owner_to_migration"),
    ]

    operations = [
        migrations.RunPython(assign_orphans_to_first_superuser, noop_reverse),
    ]

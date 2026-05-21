from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('migrator', '0002_messagerecord_flags_messagerecord_internaldate_and_more'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='migration',
            name='backup_path',
        ),
    ]

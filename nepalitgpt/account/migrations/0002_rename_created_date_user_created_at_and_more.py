# Generated by Django 5.0.6 on 2024-06-19 11:37

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('account', '0001_initial'),
    ]

    operations = [
        migrations.RenameField(
            model_name='user',
            old_name='created_date',
            new_name='created_at',
        ),
        migrations.RenameField(
            model_name='user',
            old_name='updated_date',
            new_name='updated_at',
        ),
    ]

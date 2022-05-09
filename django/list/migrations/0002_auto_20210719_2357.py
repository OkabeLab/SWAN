# Generated by Django 3.2.4 on 2021-07-19 14:57

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('list', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='packet',
            name='dns_query',
            field=models.CharField(blank=True, max_length=256, null=True),
        ),
        migrations.AddField(
            model_name='packet',
            name='dns_responce',
            field=models.GenericIPAddressField(blank=True, null=True),
        ),
    ]
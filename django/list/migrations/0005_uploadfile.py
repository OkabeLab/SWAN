# Generated by Django 3.2.4 on 2021-08-10 12:19

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('list', '0004_auto_20210810_0033'),
    ]

    operations = [
        migrations.CreateModel(
            name='UploadFile',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('file', models.FileField(upload_to='', verbose_name='file')),
                ('analysis', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='list.analysis')),
            ],
        ),
    ]

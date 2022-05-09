# Generated by Django 3.2.4 on 2021-07-28 00:47

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('list', '0002_auto_20210719_2357'),
    ]

    operations = [
        migrations.AlterField(
            model_name='dnspolicy',
            name='domain',
            field=models.CharField(max_length=256),
        ),
        migrations.CreateModel(
            name='TLSPolicy',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('dst_ip', models.GenericIPAddressField()),
                ('dst_port', models.IntegerField()),
                ('counter', models.IntegerField()),
                ('policy', models.CharField(choices=[('SM', 'Simulate'), ('PX', 'Proxy')], default='SM', max_length=2)),
                ('analysis', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='list.analysis')),
            ],
        ),
    ]

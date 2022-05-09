# Generated by Django 3.2.4 on 2021-07-19 08:24

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Analysis',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('date', models.DateTimeField(auto_now_add=True)),
            ],
        ),
        migrations.CreateModel(
            name='Protocol',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=16)),
            ],
        ),
        migrations.CreateModel(
            name='Packet',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('timestamp', models.DateTimeField()),
                ('src_ip', models.GenericIPAddressField()),
                ('src_port', models.IntegerField()),
                ('dst_ip', models.GenericIPAddressField()),
                ('dst_port', models.IntegerField()),
                ('info', models.TextField()),
                ('analysis', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='list.analysis')),
                ('protocol', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='list.protocol')),
            ],
        ),
        migrations.CreateModel(
            name='DNSPolicy',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('domain', models.TextField()),
                ('policy', models.CharField(choices=[('SM', 'Simulate'), ('UB', 'Unbound')], default='SM', max_length=2)),
                ('analysis', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='list.analysis')),
            ],
        ),
    ]
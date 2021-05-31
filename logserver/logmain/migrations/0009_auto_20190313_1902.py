# -*- coding: utf-8 -*-
# Generated by Django 1.11.16 on 2019-03-13 18:02
from __future__ import unicode_literals

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('logmain', '0008_auto_20190305_1700'),
    ]

    operations = [
        migrations.CreateModel(
            name='CORSData',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('siteId', models.IntegerField()),
                ('url', models.CharField(max_length=2000)),
                ('stateLabel', models.CharField(max_length=200)),
                ('response', models.CharField(max_length=1000)),
            ],
        ),
        migrations.CreateModel(
            name='CORSRun',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('timestamp', models.CharField(blank=True, max_length=300, null=True)),
                ('hashId', models.CharField(max_length=300, unique=True)),
                ('Browser', models.CharField(blank=True, default='Chrome', max_length=300, null=True)),
                ('BrowserVersion', models.CharField(blank=True, max_length=300, null=True)),
            ],
        ),
        migrations.AddField(
            model_name='corsdata',
            name='run',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='cors_datas', to='logmain.CORSRun'),
        ),
        migrations.AlterUniqueTogether(
            name='corsdata',
            unique_together=set([('run', 'siteId', 'url', 'stateLabel', 'response')]),
        ),
    ]

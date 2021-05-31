# -*- coding: utf-8 -*-
# Generated by Django 1.11.16 on 2019-03-05 16:00
from __future__ import unicode_literals

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('logmain', '0007_auto_20190212_1205'),
    ]

    operations = [
        migrations.CreateModel(
            name='TimingAnalysisData',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('siteId', models.IntegerField()),
                ('url', models.CharField(max_length=2000)),
                ('stateLabel', models.CharField(max_length=200)),
                ('tag_name', models.CharField(max_length=200)),
                ('elpased_time', models.CharField(max_length=1000)),
            ],
        ),
        migrations.CreateModel(
            name='TimingAnalysisRun',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('timestamp', models.CharField(blank=True, max_length=300, null=True)),
                ('hashId', models.CharField(max_length=300, unique=True)),
                ('Browser', models.CharField(blank=True, default='Chrome', max_length=300, null=True)),
                ('BrowserVersion', models.CharField(blank=True, max_length=300, null=True)),
            ],
        ),
        migrations.AddField(
            model_name='timinganalysisdata',
            name='run',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='ta_datas', to='logmain.TimingAnalysisRun'),
        ),
        migrations.AlterUniqueTogether(
            name='timinganalysisdata',
            unique_together=set([('run', 'siteId', 'url', 'stateLabel', 'tag_name', 'elpased_time')]),
        ),
    ]

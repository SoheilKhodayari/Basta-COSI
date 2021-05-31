# -*- coding: utf-8 -*-

"""
	Copyright (C) 2019  Soheil Khodayari, IMDEA Software
	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU Affero General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.
	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU Affero General Public License for more details.
	You should have received a copy of the GNU Affero General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.
	
	Description:
	---------------
    Logging endpoints to use for the candidate COSI attack pages
"""


from django.conf.urls import url, include
from django.contrib import admin
from logmain import views

urlpatterns = [
    # postMessage
    url(r'^record-post-message/', views.recordPostMessage, name="recordPostMessage"),
    url(r'^post-message-export-csv/(?P<siteId>\d+)/(?P<opentype>\d+)/', views.postMessageExportCSVFromDB, name="postMessageExportCSVFromDB"),
    
    ## DEPRECATED
    # url(r'^exportMEM/', views.export_memory, name="exportMEM"),
    # url(r'^export/', views.export, name="export"),
    # url(r'^postFramedUrls/(?P<siteId>\d+)/', views.post_framed_urls, name="postFramedUrls"),
    # url(r'^getFramedUrls/', views.get_framed_urls, name="getFramedUrls"),
    # url(r'^clearMemory/', views.clear_memory, name="clearMemory"),
    
    # script inclusion and error 
    url(r'^record-script-message/(?P<testType>\d+)/', views.recordScriptMessage, name="recordScriptMessage"),
    url(r'^script-inclusion-export-csv/(?P<siteId>\d+)/(?P<testType>\d+)/$', views.ScriptVarsExportCSVFromDB, name="ScriptVarsExportCSVFromDB"),
     url(r'^script-errors-export-csv/(?P<siteId>\d+)/(?P<testType>\d+)/$', views.ScriptErrsExportCSVFromDB, name="ScriptErrsExportCSVFromDB"),
    
    # content-window-attack
    url(r'^record-content-window/(?P<siteId>\d+)/', views.recordContentWindowFrameCount, name="postContentWindow"),
    url(r'^export-csv-content-window/(?P<siteId>\d+)/', views.ContentWindowExportCSVFromDB, name="ContentWindowExportCSVFromDB"),
    url(r'^clear-content-window-memory/', views.clear_content_window_memory, name="clearContentWindowMemory"),
    url(r'^export-content-window/(?P<siteId>\d+)/', views.exportContentWindowFrameCount, name="exportContentWindowFrameCount"),
    url(r'^clear-content-window-memory/', views.clear_content_window_memory, name="clearContentWindowMemory"),
    url(r'^clear-cw-memory/', views.clearContentWindowMemory, name="clearContentWindowMemory2"),
    url(r'^peek-cw-memory/', views.peekContentWindowMemory, name="peekContentWindowMemory"),

    # event-count
    url(r'^record-event-count/(?P<siteId>\d+)/', views.recordEventFireCount, name="recordEventFireCount"),
    url(r'^event-fire-count-export-csv/(?P<siteId>\d+)/', views.eventFireCountExportCSVFromDB, name="eventFireCountExportCSVFromDB"),

    # object props
    url(r'^record-object-props/(?P<siteId>\d+)/', views.recordObjectProperties, name="recordObjectProperties"),
    url(r'^object-props-export-csv/(?P<siteId>\d+)/', views.ObjectPropertiesExportCSVFromDB, name="ObjectPropertiesExportCSVFromDB"),

    # content-secuirty-policy
    url(ur'^record-csp-violation/(?P<site_id>\d+)/(?P<state_status>.*)/(?P<tag_name>.*)/(?P<hash_id>.*)/$', views.record_csp_attack, name="record_csp_attack"),
    url(r'^csp-export-csv/(?P<site_id>\d+)/$', views.csp_export_csv_from_db, name="csp_export_csv_from_db"),

    # timing-analysis (ta)
    url(r'^record-ta-data/(?P<siteId>\d+)/', views.recordTimingAnalysisLog, name="recordTimingAnalysisLog"),
    url(r'^timing-analysis-export-csv/(?P<siteId>\d+)/', views.timingAnalysisExportCSVFromDB, name="timingAnalysisExportCSVFromDB"),

   # CORS
    url(r'^record-cors-data/(?P<siteId>\d+)/', views.recordCORSData, name="recordCORSData"),
    url(r'^cors-export-csv/(?P<siteId>\d+)/', views.CORSExportCSVFromDB, name="CORSExportCSVFromDB"),


]





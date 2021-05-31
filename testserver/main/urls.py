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
    
    Usage:
    ---------------
    testserver URL Configuration

    The `urlpatterns` list routes URLs to views. For more information please see:
        https://docs.djangoproject.com/en/1.11/topics/http/urls/
    Examples:
    Function views
        1. Add an import:  from my_app import views
        2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
    Class-based views
        1. Add an import:  from other_app.views import Home
        2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
    Including another URLconf
        1. Import the include() function: from django.conf.urls import url, include
        2. Add a URL to urlpatterns:  url(r'^blog/', include('blog.urls'))
"""
from django.conf.urls import url, include
from django.contrib import admin
from main import views

urlpatterns = [

    # general
    url(r'^$', views.index, name="index"),
    url(r'^getAttackPage/(?P<iframe_uri_pk>\d+)/(?P<state_status>[\w-]+)/(?P<open_type>\d+)/$', views.getAttackPage, name="getAttackPage"),
    url(r'^analyze/(?P<siteId>\d+)/', views.analyze, name="analyze"),
    url(r'^view/analysis/list/(?P<siteId>\d+)/', views.view_analysis_list, name="analysis-list"),
    url(r'^view/analysis/(?P<siteId>\d+)/(?P<timestamp>.+)/', views.view_analysis, name="analysis-view"),
    url(r'^report/(?P<siteId>\d+)/', views.comprehensive_report, name="analysis-report"),
    url(r'^frametest/', views.test_frameable, name="test-frameable"),

    # script inclusion: vars 
    url(r'^attack-page/script-vars/(?P<site_id>\d+)/(?P<state_status>[\w-]+)/$', views.getScriptAttackPageVars, name="getScriptAttackPageVars"),
    url(r'^script-inclusion/vars/analyze/(?P<siteId>\d+)/$', views.getAnalysisScriptInclusionVars, name="getAnalysisScriptInclusionVars"),

    # script inclusion: errors
    url(r'^attack-page/script-errs/(?P<site_id>\d+)/(?P<state_status>[\w-]+)/$', views.getScriptAttackPageErrors, name="getScriptAttackPageErrors"),
    url(r'^script-inclusion/errs/analyze/(?P<siteId>\d+)/$', views.getAnalysisScriptInclusionErrs, name="getAnalysisScriptInclusionErrs"),

    # content window
    url(r'^attack-page/content-window/(?P<site_id>\d+)/(?P<state_status>[\w-]+)/$', views.getContentWindowLengthPage, name="getContentWindowLengthPage"),
    
    # event fire count
    url(r'^attack-page/event-count/(?P<site_id>\d+)/(?P<state_status>[\w-]+)/$', views.getEventCountAttackPage, name="getEventCountAttackPage"),
    
    # csp
    url(r'^attack-page/csp/(?P<site_id>\d+)/(?P<state_status>[\w-]+)/$', views.getCSPAttackPage, name="getCSPAttackPage"),

    # timing attacks
    url(r'^attack-page/timing-analysis/(?P<site_id>\d+)/(?P<state_status>[\w-]+)/$', views.get_timing_analsis_attack_page, name="get_timing_analsis_attack_page"),

    # css
    url(r'^attack-page/css/$', views.cssTest, name="cssTest"),

    # cors misconfigurations
    url(r'^attack-page/cors/(?P<site_id>\d+)/(?P<state_status>[\w-]+)/$', views.get_cors_attack_page, name="get_cors_attack_page"),

]


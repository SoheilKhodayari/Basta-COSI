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

"""

from __future__ import unicode_literals
from django.shortcuts import render
from django.http import HttpResponse
from django.template import Template, Context
import page_generator as PGModule


def get_crawl_page(request):
	base64_url_list = request.GET.get("inc", None)
	if base64_url_list is None:
		return HttpResponse("[BadRequest] request does not contain inclusion urls!")

	_urls_string = base64_url_list.decode('base64')
	inclusion_urls = eval(_urls_string)
	str_inclusion_page = PGModule.get_str_crawler_request_page(inclusion_urls)
	return HttpResponse(str_inclusion_page)
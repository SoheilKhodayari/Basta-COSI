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

import json
from django.http import JsonResponse
from django.http import HttpResponse
from datetime import datetime

def _get_current_datetime():
	timestamp = str(datetime.now().strftime('%Y-%m-%d_%H-%M-%S'))
	return timestamp


def record_data(request):

	body = json.loads(request.body)
	p_target_url = body["target_url"]
	p_tag_name = body["tag"]
	p_tag_uuid = body["tag_uuid"]
	p_event_order = body["event_order"]
	p_event_count = body["event_count"]
	p_ks_lookup = body["ks_lookup"]

	lookup = json.loads(p_ks_lookup)
	events_count = json.loads(p_event_count)
	lookup_key = ""
	for event in events_count:
		lookup_key= lookup_key+ event + "-"+ str(events_count[event])
	try:
		victim_state = lookup[p_tag_name][lookup_key]
	except:
		# happens when the attack is not possible in that browser
		# hence, do not log
		response_status = 200
		return JsonResponse({'response_status':response_status})	
		
	with open("./report.log", "a+") as fp:
		fp.write("-------------------------------------------------------------\n")
		fp.write("[timestamp] %s\n"%(_get_current_datetime()))
		fp.write("[tag] %s\n"%(p_tag_name))
		fp.write("[events-triggered] %s\n"%(p_event_count))
		fp.write("[knowledge-db] %s\n"%p_ks_lookup)
		fp.write("VICTIM STATE: %s\n"%victim_state)
		fp.write("-------------------------------------------------------------\n")

	response_status = 200
	return JsonResponse({'response_status':response_status})



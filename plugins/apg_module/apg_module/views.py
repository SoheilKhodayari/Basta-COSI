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
	--------------
	Attack Page Generator Script (Version 1)
	
	@Deprecated:
	This module is deprecated and belongs to an older version of Basta-COSI.
	It is kept here only for future references.

"""


import urllib
import urlparse
import os
import sys
import uuid
import copy
import attack_page_generator_cls as APGModule
from sitemap import sitemap
from datetime import datetime
from django.http import HttpResponse

# ----------------------------------------------------------------------- #
#                  	Constants
# ----------------------------------------------------------------------- #

def _generate_uuid():
	return str(uuid.uuid4())


_uuid = _generate_uuid()
_kwargs = {"name": "attack-page"}
_apg_instance = APGModule.AttackPageGenerator(_uuid, **_kwargs)


# TODO: to be completed with all attacks as implementation is being completed!
ATTACK_TYPE = {"EF": 'ef', "OP": 'op', 'CW': 'cw', "ALL": 'general', "CSP": "csp"}

REPORT_ENDPOINT = "http://127.0.0.1:9876"
REPORT_ENDPOINT_EF = REPORT_ENDPOINT + "/record-data/ef/"
REPORT_ENDPOINT_OP = REPORT_ENDPOINT +  "/record-data/op/"
REPORT_ENDPOINT_CW = REPORT_ENDPOINT +  "/record-data/cw/"
REPORT_ENDPOINT_CSP = "http://127.0.0.1:3000/record-data/csp/"
REPORT_ENDPOINT_ALL = ''

# the root directory of the entire project
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# the root apg_module directory
BASE_DIR = (os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ATTACK_PAGES_DIR = os.path.join(BASE_DIR, "attack-pages")


# import site_dict
# local_settings_path = os.path.join(ROOT_DIR,"testserver/main")
# sys.path.insert(0, local_settings_path)
# from local_settings import site_dict

LOGOUT_STATE_LABEL = "Logout"
# ----------------------------------------------------------------------- #
#                  	Utils
# ----------------------------------------------------------------------- #


# input: {'a':'b', 'c':'d'}
# output: 'a=b&c=d'
def _get_urlencoded_dict(data_dict):
	return urllib.urlencode(data_dict)


# input: 'a=b&c=d'	
# output: {'a':'b', 'c':'d'}
def _get_urldecoded_dict(urlencoded_string):
	return urlparse.parse_qs(urlencoded_string)


# @param meta_http_user_agent: the value obtained from request.meta['HTTP_USER_AGENT'] 
# returns: the browser name
# --------
# Thanks to https://security.stackexchange.com/questions/126407/why-does-chrome-send-four-browsers-in-the-user-agent-header
# UserAgentFormat: Mozilla/[version] ([system and browser information]) [platform] ([platform details]) [extensions].
# -------- 
# EXAMPLES
# chrome: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.121 Safari/537.36
# edge: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.140 Safari/537.36 Edge/17.17134
# firefox: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0
# --------
# @TODO: test output for BROWSRES other than the EXAMPLES
def _get_browser_agent(meta_http_user_agent):
	splitted = meta_http_user_agent.split(" ")
	if "Safari" in splitted[-1]:
		browser = splitted[-2]
	else:
		browser = splitted[-1]

	tmp = browser.split("/")
	browserName, browserVersion = tmp[0], tmp[1]
	return browserName


def _get_user_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def _get_current_datetime():
	return datetime.now().strftime('%Y-%m-%d_%H-%M-%S') 

# ----------------------------------------------------------------------- #
#                 END Utils
# ----------------------------------------------------------------------- #


# ----------------------------------------------------------------------- #
#                  	Event Fire (EF)
# ----------------------------------------------------------------------- #


def _get_ef_ks_report_pathname(site_id):

	global ROOT_DIR
	path = os.path.join(ROOT_DIR, os.path.join("automator", os.path.join("%s"%str(site_id), os.path.join("TestReports", "EventFireCount"))))
	report_name = "summary-table-vulnerability.out"
	pathname = os.path.join(path, report_name)

	return pathname


def _get_ef_parsed_content(input_report_file):
	# store ks like: { URL :  { TestConfig: { States(comma-delimited): events-and-their-counts(dash and colon-delimited)}}}
	# eg. { 'myurl': {'chrome, 123.0.0.1, link': {'reviewer1, author1': 'onload-1;onerror-2'}}}
	ks = { }
	with open(input_report_file, "r") as fp:
		lines = fp.readlines()
		lastFoundedURL = None
		lastTestConfig = None
		lastStatesEventsPair = { }
		for line in lines:		
			if "URL:" in line:
				url = line.split(" ")[1].strip("\n").strip("\"")
				lastFoundedURL = url
				if lastFoundedURL not in ks:
						ks[lastFoundedURL] = {}
				continue
			if "TestConfig:" in line:
				if lastTestConfig != None:
					lastStatesEventsPair = { }
				config = line.split(":")[1].strip("\n").strip()
				lastTestConfig = config
			if "Events:" in line or "States:" in line:
				statesInLine = line[line.index("States:")+len("States:"):].strip("\n").strip()
				eventsInLine = line[line.index("{")+1:line.index("}")].strip()
				eventsInLine = eventsInLine.replace(":", "-").replace(",", ";")
				lastStatesEventsPair[statesInLine] = eventsInLine
				ks[lastFoundedURL][lastTestConfig] = lastStatesEventsPair
	return ks


def _get_ef_what_to_include(ks_lookup):
	res = { }
	for url in ks_lookup:
		if url not in res:
			res[url] = { }
		tags = ks_lookup[url]
		for tag in tags:
			if tag not in res[url]:
				res[url][tag] = []
			events = tags[tag]
			for event in events:
				eventsList = event.split(";")
				eventsList = [ev.split("-")[0].strip() for ev in eventsList]
				for e in eventsList:
					if e not in res[url][tag]:
						res[url][tag].append(e)
	return res

def _get_ef_attack_vectors(ks_object, target_browser, target_browser_version, target_state, recursion = 100, included_logout=False):
	returnMe = {"IncludeME": {}, "LookupME": {}}
	target_config_start = target_browser.capitalize() + ", "+ target_browser_version
	minStates = 10000 # number of other states sharing same results with target state
	minStateEventPair = None
	minTag = None
	minURL = None
	targetMinStateLine = None  # contains the target state in combination with the minimum number of other states
	# Disallow multiple logout detection
	alreadyHaveLoginDetection = included_logout
	maxRecursion = recursion
	for url in ks_object:
		configs = ks_object[url]
		for config in configs:
			if not config.startswith(target_config_start): continue
			tag = config.split(",")[2].strip()
			state_event_pair = configs[config]
			if target_state in state_event_pair:  #simple case - exact key match

				if url not in returnMe["LookupME"]:
					returnMe["LookupME"][url] = {}
				if tag not in returnMe["LookupME"][url]:
					returnMe["LookupME"][url][tag] = {}
				for st in state_event_pair:
					evnt = state_event_pair[st]
					returnMe["LookupME"][url][tag][evnt]=st

				events = state_event_pair[target_state].split(";") #['onerror-1', 'onload-2']
				eventnames = [ev.split("-")[0] for ev in events ]  #['onload', 'onerror']
				if url not in returnMe["IncludeME"]:
					returnMe["IncludeME"][url]  = {}
				returnMe["IncludeME"][url] = {tag : eventnames} 

				return returnMe
			# always add Logout case
			elif (LOGOUT_STATE_LABEL in state_event_pair):
				if alreadyHaveLoginDetection: continue # not sure here or in the above condition ??!
				if url not in returnMe["LookupME"]:
					returnMe["LookupME"][url] = {}
				if tag not in returnMe["LookupME"][url]:
					returnMe["LookupME"][url][tag] = {}
				for st in state_event_pair:
					evnt = state_event_pair[st]
					returnMe["LookupME"][url][tag][evnt]=st
				events = state_event_pair[LOGOUT_STATE_LABEL].split(";") #['onerror-1', 'onload-2']
				eventnames = [ev.split("-")[0] for ev in events ]  #['onload', 'onerror']
				if url not in returnMe["IncludeME"]:
					returnMe["IncludeME"][url]  = {}
				returnMe["IncludeME"][url] = {tag : eventnames} 
				alreadyHaveLoginDetection = True
				continue
			else:
				# find the row with min states containing that state
				for statesLine in state_event_pair:
					if target_state in statesLine:
						countStates = len(statesLine.split(", "))
						if countStates < minStates:
							minStates = countStates
							minStateEventPair= state_event_pair
							targetMinStateLine = statesLine
							minTag= tag
							minURL = url

	other_states = [st.strip() for st in targetMinStateLine.split(", ")]
	for state in other_states:
		if state == target_state:
			tag = minTag 
			url = minURL
			if url not in returnMe["LookupME"]:
				returnMe["LookupME"][url] = {}
			if tag not in returnMe["LookupME"][url]:
				returnMe["LookupME"][url][tag] = {}
			for st in minStateEventPair:
				evnt = minStateEventPair[st]
				returnMe["LookupME"][url][tag][evnt]=st

			# enough to include the events of the target state
			events = minStateEventPair[targetMinStateLine].split(";") #['onerror-1', 'onload-2']
			eventnames = [ev.split("-")[0] for ev in events ]  #['onload', 'onerror']
			if url not in returnMe["IncludeME"]:
				returnMe["IncludeME"][url]  = {}
			returnMe["IncludeME"][url] = {tag : eventnames} 
			# if maxRecursion:
			# 	maxRecursion = maxRecursion -1
			# 	if maxRecursion == 0:
			# 		return returnMe
		else:
			# if this state already distinguished by one recursion, then break
			for url in returnMe["LookupME"]:
				tags = returnMe["LookupME"][url]
				for tag in tags:
					events = tags[tag]
					for event in events:
						s = events[event]
						if state == s:
							return returnMe
			if maxRecursion:
				maxRecursion = maxRecursion -1
				if maxRecursion ==0:
					return returnMe
				# check if state is not anymore distinguishable
				ks_other = _get_ef_attack_vectors(ks_object, target_browser, target_browser_version, state, maxRecursion, alreadyHaveLoginDetection)
				for key, value in ks_other["IncludeME"].items():
					if key not in returnMe["IncludeME"]:
						# avoid overriding of keys (same url inclusion with different or same tag)
						returnMe["IncludeME"][key] = value
					else:
						for k, v in value.items():
							returnMe["IncludeME"][key][k] = v

				for key, value in ks_other["LookupME"].items():
					if key not in returnMe["LookupME"]:
						returnMe["LookupME"][key] = value
					else:
						for k, v in value.items():
							returnMe["LookupME"][key][k] = v
	return returnMe


# @TestCalls
# print _get_ks_data_ef(101, 'Chrome', '71.0.3578.98', 'Reviewer1-LoggedIn')
# print _get_ks_data_ef(101, 'Edge', '42.17134.1.0', 'Reviewer1-LoggedIn')
# print _get_ks_data_ef(101, 'Firefox', '65.0', 'Reviewer1-LoggedIn')
def _get_ks_data_ef(input_target_site_id, input_target_browser, input_browser_version, input_target_state, input_ks_report_file=None):
	if input_ks_report_file:
		input_report_file = input_ks_report_file
	else:
		input_report_file = _get_ef_ks_report_pathname(input_target_site_id)
	ks = _get_ef_parsed_content(input_report_file)
	attack_vectors = _get_ef_attack_vectors(ks, input_target_browser, input_browser_version, input_target_state)
	lookup =  attack_vectors["LookupME"]
	# relabel the other state comparable to Logout to Login

	u = None
	t = None
	for url in lookup:
		for tag in lookup[url]:
			for event in lookup[url][tag]:
				ev = lookup[url][tag][event]
				if ev == "Logout":
					u = url
					t= tag
	for ev in lookup[u][t]:
		if lookup[u][t][ev] == "Logout": continue
		lookup[u][t][ev] = "Logged" #loggedin

	include =  _get_ef_what_to_include(attack_vectors["LookupME"])
	returnMe = {"IncludeME": include, "LookupME": lookup}
	hasFrameTag = False
	return returnMe, hasFrameTag


# ----------------------------------------------------------------------- #
#                  	Object Properties (OP)
# ----------------------------------------------------------------------- #

def _get_op_what_to_include(ks_lookup):
	res = { }
	for url in ks_lookup:
		for tag in ks_lookup[url]:
			res[url] = { tag: [] } #empty event list to be in the same depth as EF
	return res

def _get_op_ks_report_pathname(site_id):

	global ROOT_DIR
	path = os.path.join(ROOT_DIR, os.path.join("automator", os.path.join("%s"%str(site_id), os.path.join("TestReports", "ObjectProperties"))))
	report_name = "summary-table-vulnerability.out"
	pathname = os.path.join(path, report_name)

	return pathname


def _get_op_parsed_content(input_report_file):
	# store ks like: { URL :  { TestConfig: { States(comma-delimited): props}}}
	ks = { }
	with open(input_report_file, "r") as fp:
		lines = fp.readlines()
		lastFoundedURL = None
		lastTestConfig = None
		lastStatesEventsPair = { }
		for line in lines:		
			if "URL:" in line:
				url = line.split(" ")[1].strip("\n").strip("\"")
				lastFoundedURL = url
				if lastFoundedURL not in ks:
						ks[lastFoundedURL] = {}
				continue
			if "TestConfig:" in line:
				if lastTestConfig != None:
					lastStatesEventsPair = { }
				config = line.split(":")[1].strip("\n").strip()
				lastTestConfig = config
			if "Props:" in line or "States:" in line:
				statesInLine = line[line.index("States:")+len("States:"):].strip("\n").strip()
				propsLine = line[line.index("["):line.index("]")+1].strip()
				evaluated_props = eval(propsLine) #eval string to list obj

				# fix data format
				newProps = []
				for item in evaluated_props:
					newItem = item
					if ("{" in item) or ("}" in item):
						newItem = item.replace("}", "").replace("{", "")
					newProps.append(newItem)

				lastStatesEventsPair[statesInLine] = str(newProps) # convert back to string 
				ks[lastFoundedURL][lastTestConfig] = lastStatesEventsPair
	return ks


def _get_op_attack_vectors(ks_object, target_browser, target_browser_version, target_state, recursion = 100, included_logout=False):
	
	"""
		@Note: event variables denote props in this function!
	"""
	returnMe = {"LookupME": {}}
	target_config_start = target_browser.capitalize() + ", "+ target_browser_version
	minStates = 10000 # number of other states sharing same results with target state
	minStateEventPair = None
	minTag = None
	minURL = None
	targetMinStateLine = None  # contains the target state in combination with the minimum number of other states
	# Disallow multiple logout detection
	alreadyHaveLoginDetection = included_logout
	maxRecursion = recursion
	for url in ks_object:
		configs = ks_object[url]
		for config in configs:
			if not config.startswith(target_config_start): continue
			tag = config.split(",")[2].strip()
			state_event_pair = configs[config]
			if target_state in state_event_pair:  #simple case - exact key match

				if url not in returnMe["LookupME"]:
					returnMe["LookupME"][url] = {}
				if tag not in returnMe["LookupME"][url]:
					returnMe["LookupME"][url][tag] = {}
				for st in state_event_pair:
					evnt = state_event_pair[st]
					returnMe["LookupME"][url][tag][evnt]=st

				return returnMe
			# always add Logout case
			elif (LOGOUT_STATE_LABEL in state_event_pair):
				if alreadyHaveLoginDetection: continue # not sure here or in the above condition ??!
				if url not in returnMe["LookupME"]:
					returnMe["LookupME"][url] = {}
				if tag not in returnMe["LookupME"][url]:
					returnMe["LookupME"][url][tag] = {}
				for st in state_event_pair:
					evnt = state_event_pair[st]
					returnMe["LookupME"][url][tag][evnt]=st

				alreadyHaveLoginDetection = True
				continue
			else:
				# find the row with min states containing that state
				for statesLine in state_event_pair:
					if target_state in statesLine:
						countStates = len(statesLine.split(", "))
						if countStates < minStates:
							minStates = countStates
							minStateEventPair= state_event_pair
							targetMinStateLine = statesLine
							minTag= tag
							minURL = url

	other_states = [st.strip() for st in targetMinStateLine.split(", ")]
	for state in other_states:
		if state == target_state:
			tag = minTag 
			url = minURL
			if url not in returnMe["LookupME"]:
				returnMe["LookupME"][url] = {}
			if tag not in returnMe["LookupME"][url]:
				returnMe["LookupME"][url][tag] = {}
			for st in minStateEventPair:
				evnt = minStateEventPair[st]
				returnMe["LookupME"][url][tag][evnt]=st

		else:
			# if this state already distinguished by one recursion, then break
			for url in returnMe["LookupME"]:
				tags = returnMe["LookupME"][url]
				for tag in tags:
					events = tags[tag]
					for event in events:
						s = events[event]
						if state == s:
							return returnMe
			if maxRecursion:
				maxRecursion = maxRecursion -1
				if maxRecursion ==0:
					return returnMe
				# check if state is not anymore distinguishable
				ks_other = _get_op_attack_vectors(ks_object, target_browser, target_browser_version, state, maxRecursion, alreadyHaveLoginDetection)
				for key, value in ks_other["LookupME"].items():
					if key not in returnMe["LookupME"]:
						# avoid overriding of keys (same url inclusion with different or same tag)
						returnMe["LookupME"][key] = value
					else:
						for k, v in value.items():
							returnMe["LookupME"][key][k] = v
	return returnMe


# @TestCall: _get_ks_data_op(105, 'Chrome', '72.0.3626.121', 'User2-LoggedIn')
# @TestCall: _get_ks_data_op(105, 'Chrome', '72.0.3626.121', 'Logout')
def _get_ks_data_op(input_target_site_id, input_target_browser, input_browser_version, input_target_state, input_ks_report_file=None):
	if input_ks_report_file:
		input_report_file = input_ks_report_file
	else:
		input_report_file = _get_op_ks_report_pathname(input_target_site_id)

	ks = _get_op_parsed_content(input_report_file)

	attack_vectors = _get_op_attack_vectors(ks, input_target_browser, input_browser_version, input_target_state)
	lookup =  attack_vectors["LookupME"]
	inc = _get_op_what_to_include(lookup)
	returnMe = {"IncludeME": inc, "LookupME": lookup}
	hasFrameTag = False

	return returnMe, hasFrameTag


def _get_all_inclusions(inc_ef, inc_op):
	ef_inc = copy.deepcopy(inc_ef)

	for url in inc_op:
		if url not in ef_inc:
			ef_inc[url] = inc_op[url]
		else:
			for tag in inc_op[url]:
				if tag not in ef_inc[url]:
					ef_inc[url][tag] = inc_op[url][tag]
	return ef_inc

# ----------------------------------------------------------------------- #
#               Content Window (CW) / Frame Count (FC)
# ----------------------------------------------------------------------- #

def _get_cw_ks_report_pathname(input_site_id):

	global ROOT_DIR
	path = os.path.join(ROOT_DIR, os.path.join("automator", os.path.join("%s"%str(input_site_id), os.path.join("TestReports", "ContentWindow"))))
	report_name = "summary-table-vulnerability.out"
	pathname = os.path.join(path, report_name)
	return pathname

def _get_cw_parsed_content(input_report_file):
	# store ks like: { URL :  { TestConfig: { States(comma-delimited): frame-count}}}
	ks = { }
	with open(input_report_file, "r") as fp:
		lines = fp.readlines()
		lastFoundedURL = None
		lastTestConfig = None
		lastStatesFrameCountPair = { }
		for line in lines:		
			if "URL:" in line:
				url = line.split(" ")[1].strip("\n").strip("\"")
				lastFoundedURL = url
				if lastFoundedURL not in ks:
						ks[lastFoundedURL] = {}
				continue
			if "TestConfig:" in line:
				if lastTestConfig != None:
					lastStatesFrameCountPair = { }
				config = line.split(":")[1].strip("\n").strip()
				lastTestConfig = config
			if "FrameCount:" in line or "States:" in line:
				statesInLine = line[line.index("States:")+len("States:"):].strip("\n").strip()
				FrameCountLine = line[line.index("FrameCount:")+len("FrameCount:"):line.index("States")-1].strip()
				lastStatesFrameCountPair[statesInLine] = eval(FrameCountLine)
				ks[lastFoundedURL][lastTestConfig] = lastStatesFrameCountPair
	return ks

def _get_cw_attack_vectors(ks_object, target_browser, target_browser_version, target_state, recursion = 100, included_logout=False):
	returnMe = {"LookupME": {}}
	target_config_start = target_browser.capitalize() + ", "+ target_browser_version
	minStates = 10000 # inital number of other states sharing same results with target state
	minStateFrameCountPair = None
	minURL = None
	targetMinStateLine = None  # contains the target state in combination with the minimum number of other states
	# Disallow multiple logout detection
	alreadyHaveLoginDetection = included_logout
	maxRecursion = recursion
	for url in ks_object:
		configs = ks_object[url]
		for config in configs:
			if not config.startswith(target_config_start): continue # discard other browser info
			state_fc_pair = configs[config]
			if target_state in state_fc_pair:  #simple case - exact key match

				if url not in returnMe["LookupME"]:
					returnMe["LookupME"][url] = {}
				for st in state_fc_pair:
					count = state_fc_pair[st]
					returnMe["LookupME"][url][count]=st

				return returnMe

			# always add Logout case
			elif (LOGOUT_STATE_LABEL in state_fc_pair):
				if alreadyHaveLoginDetection: continue # not sure here or in the above condition ??!

				if url not in returnMe["LookupME"]:
					returnMe["LookupME"][url] = {}
				for st in state_fc_pair:
					count = state_fc_pair[st]
					returnMe["LookupME"][url][count]=st
				alreadyHaveLoginDetection = True
				continue
			else:
				# find the row with min states containing that state
				for statesLine in state_fc_pair:
					if target_state in statesLine:
						countStates = len(statesLine.split(", "))
						if countStates < minStates:
							minStates = countStates
							minStateFrameCountPair= state_fc_pair
							targetMinStateLine = statesLine
							minURL = url

	other_states = [st.strip() for st in targetMinStateLine.split(", ")]
	for state in other_states:
		if state == target_state:
			url = minURL
			if url not in returnMe["LookupME"]:
				returnMe["LookupME"][url] = {}
			for st in minStateFrameCountPair:
				count = minStateFrameCountPair[st]
				returnMe["LookupME"][url][count]=st

		else:
			# if this state already distinguished by one recursion, then break
			for url in returnMe["LookupME"]:
				counts = returnMe["LookupME"][url]
				for count in counts:
					s = counts[count]
					if state == s:
						return returnMe
			if maxRecursion:
				maxRecursion = maxRecursion -1
				if maxRecursion ==0:
					return returnMe
				# check if state is not anymore distinguishable
				ks_other = _get_cw_attack_vectors(ks_object, target_browser, target_browser_version, state, maxRecursion, alreadyHaveLoginDetection)

				for key, value in ks_other["LookupME"].items():
					if key not in returnMe["LookupME"]:
						returnMe["LookupME"][key] = value
					else:
						for k, v in value.items():
							returnMe["LookupME"][key][k] = v
	return returnMe


# @stub-method for _get_ks_data_cw
def __get_ks_data_cw(input_target_site_id, input_target_browser, input_browser_version, input_target_state, input_ks_report_file=None):
	if input_ks_report_file:
		input_report_file = input_ks_report_file
	else:
		input_report_file = _get_cw_ks_report_pathname(input_target_site_id)

	lookup = {
 			"https://drive.google.com/file/d/1WISg6hJ8uvUPZ3xDNNej4WQ7GcGzCWZb": { 4: "User1-LoggedIn", 0: "Logout, Logged-with-XFO-protection"} # more URL inclusions goes here
 			} 
	
	return {"IncludeME": lookup.keys(), "LookupME": lookup}


# @TestCall _get_ks_data_cw(29, 'Chrome', '72.0.3626.109', 'User2-LoggedIn')
def _get_ks_data_cw(input_target_site_id, input_target_browser, input_browser_version, input_target_state, input_ks_report_file=None):
	if input_ks_report_file:
		input_report_file = input_ks_report_file
	else:
		input_report_file = _get_cw_ks_report_pathname(input_target_site_id)

	ks = _get_cw_parsed_content(input_report_file)

	attack_vectors = _get_cw_attack_vectors(ks, input_target_browser, input_browser_version, input_target_state)
	lookup =  attack_vectors["LookupME"]

	return {"IncludeME": lookup.keys(), "LookupME": lookup}
	


# ----------------------------------------------------------------------- #
#               			CSP
# ----------------------------------------------------------------------- #

def _get_csp_ks_report_pathname(input_site_id):

	global ROOT_DIR
	path = os.path.join(ROOT_DIR, os.path.join("automator", os.path.join("%s"%str(input_site_id), os.path.join("TestReports", "CSP"))))
	report_name = "summary-table-vulnerability.out"
	pathname = os.path.join(path, report_name)
	return pathname

def _get_csp_parsed_content(input_report_file):
	# store ks like: { URL :  { TestConfig: { States(comma-delimited): violations }}}
	ks = { }
	with open(input_report_file, "r") as fp:
		lines = fp.readlines()
		lastFoundedURL = None
		lastTestConfig = None
		lastStatesViolationsPair = { }
		for line in lines:		
			if "URL:" in line:
				url = line.split(" ")[1].strip("\n").strip("\"")
				lastFoundedURL = url
				if lastFoundedURL not in ks:
						ks[lastFoundedURL] = {}
				continue
			if "TestConfig:" in line:
				if lastTestConfig != None:
					lastStatesViolationsPair = { }
				config = line.split(":")[1].strip("\n").strip()
				lastTestConfig = config
			if "Violations:" in line or "States:" in line:
				statesInLine = line[line.index("States:")+len("States:"):].strip("\n").strip()
				violationsLine = line[line.index("["):line.index("]")+1].strip()
				lastStatesViolationsPair[statesInLine] = str(eval(violationsLine))
				ks[lastFoundedURL][lastTestConfig] = lastStatesViolationsPair
	return ks


def _get_csp_attack_vectors(ks_object, target_browser, target_browser_version, target_state, recursion = 100, included_logout=False):
	
	returnMe = {"LookupME": {}}
	target_config_start = target_browser.capitalize() + ", "+ target_browser_version
	minStates = 10000 # number of other states sharing same results with target state
	minStateEventPair = None
	minTag = None
	minURL = None
	targetMinStateLine = None  # contains the target state in combination with the minimum number of other states
	# Disallow multiple logout detection
	alreadyHaveLoginDetection = included_logout
	maxRecursion = recursion
	for url in ks_object:
		configs = ks_object[url]
		for config in configs:
			if not config.startswith(target_config_start): continue
			tag = config.split(",")[2].strip()
			state_event_pair = configs[config]
			if target_state in state_event_pair:  #simple case - exact key match

				if url not in returnMe["LookupME"]:
					returnMe["LookupME"][url] = {}
				if tag not in returnMe["LookupME"][url]:
					returnMe["LookupME"][url][tag] = {}
				for st in state_event_pair:
					evnt = state_event_pair[st]
					returnMe["LookupME"][url][tag][evnt]=st

				return returnMe
			# always add Logout case
			elif (LOGOUT_STATE_LABEL in state_event_pair):
				if alreadyHaveLoginDetection: continue # not sure here or in the above condition ??!
				if url not in returnMe["LookupME"]:
					returnMe["LookupME"][url] = {}
				if tag not in returnMe["LookupME"][url]:
					returnMe["LookupME"][url][tag] = {}
				for st in state_event_pair:
					evnt = state_event_pair[st]
					returnMe["LookupME"][url][tag][evnt]=st

				alreadyHaveLoginDetection = True
				continue
			else:
				# find the row with min states containing that state
				for statesLine in state_event_pair:
					if target_state in statesLine:
						countStates = len(statesLine.split(", "))
						if countStates < minStates:
							minStates = countStates
							minStateEventPair= state_event_pair
							targetMinStateLine = statesLine
							minTag= tag
							minURL = url

	other_states = [st.strip() for st in targetMinStateLine.split(", ")]
	for state in other_states:
		if state == target_state:
			tag = minTag 
			url = minURL
			if url not in returnMe["LookupME"]:
				returnMe["LookupME"][url] = {}
			if tag not in returnMe["LookupME"][url]:
				returnMe["LookupME"][url][tag] = {}
			for st in minStateEventPair:
				evnt = minStateEventPair[st]
				returnMe["LookupME"][url][tag][evnt]=st

		else:
			# if this state already distinguished by one recursion, then break
			for url in returnMe["LookupME"]:
				tags = returnMe["LookupME"][url]
				for tag in tags:
					events = tags[tag]
					for event in events:
						s = events[event]
						if state == s:
							return returnMe
			if maxRecursion:
				maxRecursion = maxRecursion -1
				if maxRecursion ==0:
					return returnMe
				# check if state is not anymore distinguishable
				ks_other = _get_csp_attack_vectors(ks_object, target_browser, target_browser_version, state, maxRecursion, alreadyHaveLoginDetection)
				for key, value in ks_other["LookupME"].items():
					if key not in returnMe["LookupME"]:
						# avoid overriding of keys (same url inclusion with different or same tag)
						returnMe["LookupME"][key] = value
					else:
						for k, v in value.items():
							returnMe["LookupME"][key][k] = v
	return returnMe


def _get_csp_what_to_include(ks_lookup):
	res = {}
	for url, value in ks_lookup.items():
		res[url] = []
		for tag in value:
			res[url].append(tag)
	return res

# @TestCall _get_ks_data_csp(24, 'Chrome', '71.0.3578.98', 'Free-Account-LoggedIn')
def _get_ks_data_csp(input_target_site_id, input_target_browser, input_browser_version, input_target_state, input_ks_report_file=None):
	if input_ks_report_file:
		input_report_file = input_ks_report_file
	else:
		input_report_file = _get_csp_ks_report_pathname(input_target_site_id)

	ks = _get_csp_parsed_content(input_report_file)
	attack_vectors = _get_csp_attack_vectors(ks, input_target_browser, input_browser_version, input_target_state)
	lookup =  attack_vectors["LookupME"]
	include = _get_csp_what_to_include(lookup)
	return {"IncludeME": include, "LookupME": lookup}


# ---------------------------------------------------------------------- #
#                  	Generate Attack Page Main Interface
# ----------------------------------------------------------------------- #

# @param input_site_id: the identifier of the target website
# @param input_browser: user browser name as string
# @param input_browser_version: the target browser version 
# @param input_state: desired state to be identified
# @param input_attack_type:  attack class, use ATTACK_TYPE enum to pass value
# @param input_ks_report_file: aabsolute pathname to the knowledge source report
# @param input_kwargs: an associative array with the required inputs of that attack class	
# returns: the attack page as "string"
def _get_attack_page(input_site_id, input_browser, input_browser_version, input_state, input_attack_type, input_ks_report_file=None, input_kwargs = None):

	global ATTACK_TYPE
	global REPORT_ENDPOINT_EF
	global REPORT_ENDPOINT_OP
	global _apg_instance

	if input_attack_type == ATTACK_TYPE["EF"]:
		ks_data, is_frame_tag = _get_ks_data_ef(input_site_id, input_browser, input_browser_version, input_state)
		if is_frame_tag:
			str_attack_pg = _apg_instance.getEFInstance().get_ef_attack_page_multiple_inclusion_frameset(
				ks_data["IncludeME"], ks_data["LookupME"], REPORT_ENDPOINT_EF)
		else:
			str_attack_pg = _apg_instance.getEFInstance().get_ef_attack_page_multiple_inclusion(
				ks_data["IncludeME"], ks_data["LookupME"], REPORT_ENDPOINT_EF)
		return str_attack_pg, None, None

	if input_attack_type == ATTACK_TYPE["OP"]:
		op_ks_data, op_is_frame_tag = _get_ks_data_op(input_site_id, input_browser, input_browser_version, input_state)

		inc_op = op_ks_data["IncludeME"]
		ks = {"OP": op_ks_data, "IncludeME": inc_op}
		if op_is_frame_tag:
			str_attack_pg = "" #TODO: pass for now!!
		else:
			str_attack_pg = _apg_instance.getOPInstance().get_op_attack_page_multiple_inclusion(
				ks, REPORT_ENDPOINT_OP)
		return str_attack_pg, None, None

	if input_attack_type == ATTACK_TYPE["CW"]:
		cw_ks_data= _get_ks_data_cw(input_site_id, input_browser, input_browser_version, input_state)

		inc_cw = cw_ks_data["IncludeME"]
		ks = {"CW": cw_ks_data, "IncludeME": inc_cw}
		str_attack_pg = _apg_instance.getCWInstance().get_cw_attack_page_multiple_inclusion(
				ks, REPORT_ENDPOINT_CW)
		return str_attack_pg, None, None

	if input_attack_type == ATTACK_TYPE["CSP"]:
		csp_ks_data= _get_ks_data_csp(input_site_id, input_browser, input_browser_version, input_state)

		inc_cw = csp_ks_data["IncludeME"]
		ks = {"CSP": csp_ks_data, "IncludeME": inc_cw}
		str_attack_pg, csp_headers, node_server = _apg_instance.getCSPInstance().get_csp_attack_page_multiple_inclusion_and_headers(
				ks, REPORT_ENDPOINT_CSP)
		return str_attack_pg, csp_headers, node_server

	if input_attack_type == ATTACK_TYPE["ALL"]:
		ef_ks_data, ef_is_frame_tag = _get_ks_data_ef(input_site_id, input_browser, input_browser_version, input_state)
		op_ks_data, op_is_frame_tag = _get_ks_data_op(input_site_id, input_browser, input_browser_version, input_state)

		inc_ef = ef_ks_data["IncludeME"]
		inc_op = op_ks_data["IncludeME"]
		inc_combined = _get_all_inclusions(inc_ef, inc_op)
		ks = {"OP": op_ks_data, "EF": ef_ks_data, "IncludeME": inc_combined}
		if ef_is_frame_tag or op_is_frame_tag:
			str_attack_pg = "" #TODO: pass for now!!
		else:
			str_attack_pg = _apg_instance.getOPInstance().get_ef_op_attack_page_multiple_inclusion(
				ks, REPORT_ENDPOINT_ALL)
		return str_attack_pg, None, None	
	return "", None, None


# ----------------------------------------------------------------------- #
#                  	Controllers
# ----------------------------------------------------------------------- #

# Request URLs (example)
# @Request GET http://localhost:8000/attack-page/?browser=chrome&site=hotcrp&state=Reviewer1-LoggedIn&version=71.0.3578.98&method=ef
def render_attack_page(request):
	# TODO: validate the input combination of browser name and browser version and state name IMPORTANT!!!
	# code is breakable upon bad inputs
	
	# attack-class
	global ATTACK_TYPE
	_method = request.GET.get("method", None)
	if (_method == None):
		_method = ATTACK_TYPE["ALL"]
	else:
		_method = _method.upper()
		if _method not in ATTACK_TYPE:
			_method = ATTACK_TYPE["ALL"]
		else:
			_method = ATTACK_TYPE[_method]

	# browser
	browser = request.GET.get("browser", None)
	if browser is None:
		user_agent = request.META['HTTP_USER_AGENT']
		browser = _get_browser_agent(user_agent)
	else:
		browser = browser.capitalize()


	# browser version
	browser_version = request.GET.get("version", None)
	if browser_version is None:
		return HttpResponse("[Error] browser version must be specified to generate its attack page!")


	# target site
	site_id= request.GET.get("site", None)
	if site_id is None:
		return HttpResponse("[Error] target site must be specified to generate its attack page!")
	try:
		site_id = int(site_id)
	except:
		site_id = sitemap[site_id]


	# target state
	desired_state= request.GET.get("state", None)
	if desired_state is None:
		return HttpResponse("[Error] Desired state must be specified to generate its attack page!")

	# get the attack page
	attack_pg_str, csp_headers, node_server_string = _get_attack_page(site_id, browser, browser_version, desired_state, _method)
	
	# save the attack page string
	html_filename = browser.lower()+ _method +".html"
	savepath = os.path.join(ATTACK_PAGES_DIR, str(site_id))
	if not os.path.exists(savepath):
		os.makedirs(savepath)
	pathname = os.path.join(savepath, html_filename)
	with open(pathname, "wb") as fp:
		fp.write(attack_pg_str)

	if node_server_string is not None:
		node_filename = browser.lower()+ _method +".js"
		pathname = os.path.join(savepath, node_filename)
		with open(pathname, "wb") as fp:
			fp.write(node_server_string)	


	response = HttpResponse(attack_pg_str)
	if csp_headers is not None:
		httpHeaders = " ; ".join(csp_headers)
		response["Content-Security-Policy"] = httpHeaders
	return response


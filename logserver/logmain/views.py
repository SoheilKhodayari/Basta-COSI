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
	1. Main logic to log the output of the candidate COSI attack pages
	2. Creates a single attack-vector database (SQLAlchemy) from individual django models
"""

from __future__ import unicode_literals

from django.shortcuts import render,get_list_or_404, get_object_or_404
from django.http import JsonResponse
from django.http import HttpResponse
import json
import sys
import os

from .apps import ROOT_DIR, \
_site_ids_attacked, _append_site_ids_attacked, _clear_site_ids_attacked, \
_get_last_timestamp, _get_current_timestamp, CONTENT_WINDOW, _clear_content_window_memory

local_settings_path = os.path.join(ROOT_DIR,"testserver/main")
sys.path.insert(0, local_settings_path)

from local_settings import site_dict
from .models import PostMessageRun, PostMessageData, PostMessageDataElement, EventFireCountRun, EventFireCountData, ContentWindowRun, ContentWindowData
from .models import ScriptRun, ScriptData, TimingAnalysisRun, TimingAnalysisData, CORSRun, CORSData, ObjectReadPropertiesRun, ObjectReadPropertiesData
from .apps import FRAMED_URLS, IN_MEM_DB, FRAME_COUNTS
from shutil import copyfile
from datetime import datetime

# --------------------------------------------------------------------------- #
#							Read Env Configuration
# --------------------------------------------------------------------------- #

BROWSER = 'chrome' # Default Browser
config_filepath = os.path.join(ROOT_DIR, "automator/app-config.json")
with open(config_filepath, "r") as configFile:
	configData = json.load(configFile)
	if "browser" in configData:
		BROWSER = configData["browser"]

BROWSER_REPORT_FOLDER = 'Chrome' # Default folder tag for saving test reports
if BROWSER == 'chrome':
	BROWSER_REPORT_FOLDER = 'Chrome' 
elif BROWSER == 'firefox':
	BROWSER_REPORT_FOLDER = 'Firefox' 
elif BROWSER == 'edge':
	BROWSER_REPORT_FOLDER = 'Edge'

BROWSER_VERSION = 'null' # Set when first log has been sent
BROWSER_CONFIG = {"BROWSER": BROWSER, "BROWSER_VERSION": BROWSER_VERSION} 
# --------------------------------------------------------------------------- #
#							Utility
# --------------------------------------------------------------------------- #

def decodeURL_Plus(enc):
	return enc.replace('AMPERSIGNED_REPLACE', "&")

def encodeURL_Plus(url):
	return enc.replace("&", "AMPERSIGNED_REPLACE")

# needs to be called exactly once to set the config 
def get_browser_version():
	global BROWSER_VERSION
	global BROWSER_CONFIG
	if BROWSER_VERSION == 'null':
		config_filepath = os.path.join(ROOT_DIR, "automator/auto-generated-config.json")
		with open(config_filepath, "r") as configFile:
			configData = json.load(configFile)
			BROWSER_CONFIG=configData
			if "BROWSER_VERSION" in configData:
				BROWSER_VERSION = configData["BROWSER_VERSION"]
	return BROWSER_VERSION

def auto_geneate_browser_config_log(baseDirectory):
	filepath = os.path.join(baseDirectory, "browser.json")
	if not os.path.exists(filepath):
		fp = open(filepath, "wb")
		fp.write(json.dumps(BROWSER_CONFIG))
		fp.close()

def list_of_dict_objs_contains_value(key, value, lst):
	idx=0
	for elm in lst:
		if elm[key] == value:
			return [True,idx]
		idx+=1
	return [False,0]

# --------------------------------------------------------------------------- #
#							Main Functions
# --------------------------------------------------------------------------- #

def recordPostMessage(request):

	# body_unicode = request.body.decode('utf-8') # python 3.x
	body = json.loads(request.body)

	p_url = body["url"]
	p_stateLabel = body["state_status"]
	p_siteId = body["siteId"]
	p_message = body["message"]
	p_runHashId = body["runHashId"]
	p_opentype = body["opentype"]
	global BROWSER
	p_browser = BROWSER
	p_browser_version = get_browser_version()
	
	runObject, runObjectCreated = PostMessageRun.objects.get_or_create(hashId=p_runHashId, Browser=p_browser, BrowserVersion=p_browser_version)
	if runObjectCreated:
		timestamp = str(datetime.now().strftime('%Y-%m-%d_%H-%M-%S'))
		runObject.timestamp = timestamp
		runObject.save()

	messageDataObject, messageDataObjectCreated = PostMessageData.objects.get_or_create(run = runObject, siteId= p_siteId, url= p_url, 
	stateLabel= p_stateLabel, openType = p_opentype)

	# create the new message element 
	element = PostMessageDataElement.objects.create(messageData= messageDataObject, message= p_message)
	element.save()

	response_status = 200
	return JsonResponse({'response_status':response_status})

def get_or_create_post_message_base_directory(siteId):
	global BROWSER_REPORT_FOLDER
	relative_dir = "automator/%s/TestReports/PostMessage/%s"%(siteId, BROWSER_REPORT_FOLDER)
	abs_dir = os.path.join(ROOT_DIR, relative_dir)
	if not os.path.exists(abs_dir):
		os.makedirs(abs_dir)
	return abs_dir


def postMessageExportCSVFromDB(request, siteId, opentype):
	opentype = str(opentype)
	siteId = int(siteId)
	runHashId= request.GET.get('hash', '')
	states = request.GET.get('states', '')

	if runHashId == '' or states == '':
		return HttpResponse("[Error] Invalid Invokation")

	stateLabels = states.split(",")
	sqlalchemy_export_post_message(request, siteId, runHashId, stateLabels, int(opentype))

	if int(opentype) == 0:
		openmode = "frame"
	else:
		openmode = "window"

	run= get_object_or_404(PostMessageRun, hashId = runHashId)
	msgDataObjects = run.postMessages.filter(siteId = siteId, openType = opentype)

	base_dir = get_or_create_post_message_base_directory(siteId)
	auto_geneate_browser_config_log(base_dir) #creates browser specification file 

	filename = "post-message-%s-%s.csv"%(openmode, run.timestamp)
	filepath = os.path.join(base_dir, filename)
	csvFile = open(filepath, "wb")

	stateCount = len(stateLabels)
	headerLine = "URL, "
	for stateIdx in range(stateCount):
		state = stateLabels[stateIdx]
		if stateIdx == stateCount-1:
			headerLine+="%s_pMessages\n"%(state)
		else:
			headerLine+="%s_pMessages, "%(state)

	csvFile.write(headerLine)

	pObjects_all = []
	for stateLabel in stateLabels:
		pObjects_i = msgDataObjects.filter(stateLabel=stateLabel).all()
		pObjects_all.append(pObjects_i)

	for pObj in pObjects_all[0]:
		target_url = pObj.url
		s0_pMessages = [obj.message for obj in pObj.elements.all()]
		writeLine = "\"%s\", \"%s\", "%(target_url, s0_pMessages)
		pObjects_all_length = len(pObjects_all)
		for i in range(pObjects_all_length):
			if i == 0: continue
			pObjects_i = pObjects_all[i]
			if "user_token=" in target_url:
				matchURL = target_url[:target_url.index("user_token=")]
				pObject_i = pObjects_i.get(url__startswith=matchURL).elements.all()
			else:
				pObject_i = pObjects_i.get(url=target_url).elements.all()
			
			si_pMessages = [obj.message for obj in pObject_i]
			if i == pObjects_all_length-1:
				writeLine+="\"%s\"\n"%(si_pMessages)
			else:
				writeLine+="\"%s\", "%(si_pMessages)
		csvFile.write(writeLine.encode('ascii','replace'))

	return HttpResponse("[Success] Exported CSV for siteId={0}, open-type={1} and hash={2}".format(siteId, openmode, runHashId))



# --------------------------------------------------------------------------- #
#				  Script Inclusion Attack - DATA COLLECTION
# --------------------------------------------------------------------------- #


def get_or_create_script_file_base_directory(testType, siteId):
	global BROWSER_REPORT_FOLDER
	if int(testType) == 0:
		attack_type = "ScriptInclusion"
	else:
		attack_type = "ScriptErrors"
	script_inclusion_relative_dir = "automator/{0}/TestReports/{1}/{2}".format(siteId, attack_type, BROWSER_REPORT_FOLDER)
	siv_abs = os.path.join(ROOT_DIR, script_inclusion_relative_dir)
	if not os.path.exists(siv_abs):
		os.makedirs(siv_abs)
	return siv_abs


# @Function: Django Controller - Http GET Handler
# @URL GET /record-script-message/
# testType=0 : script variables, testType=1: script inclusion
def recordScriptMessage(request, testType):

	# body_unicode = request.body.decode('utf-8') # python 3.x
	httpBody = json.loads(request.body)

	p_siteId = httpBody["siteId"]
	p_runHashId = httpBody["runHashId"]
	p_url = httpBody["url"]
	p_stateStatus = httpBody["state_status"]
	p_message = httpBody["message"]
	p_messageLength=httpBody["length"]
	p_testType = int(testType)

	global BROWSER
	p_browser = BROWSER
	p_browser_version = get_browser_version()

	runObject, runObjectCreated = ScriptRun.objects.get_or_create(hashId=p_runHashId, defaults={"attackMode": p_testType,"Browser":p_browser,"BrowserVersion":p_browser_version})
	if runObjectCreated:
		timestamp = str(datetime.now().strftime('%Y-%m-%d_%H-%M-%S'))
		runObject.timestamp = timestamp
		runObject.save()

	messageObject, messageObjectCreated = ScriptData.objects.get_or_create(run = runObject, siteId= p_siteId, targetURL= p_url, 
	stateLabel= p_stateStatus, message= p_message, messageLength=p_messageLength)

	response_status = 200
	return JsonResponse({'response_status':response_status})

# function to export csv from db for script errors and script variables attack
# @param testType 0 for script variables, 1 for script errors
def ScriptErrsExportCSVFromDB(request, siteId, testType):
	siteId= int(siteId)
	p_testType= int(testType)
	runHashId= request.GET.get('hash', '')
	states= request.GET.get('states', '')
	if runHashId == '' or states == '':
		return HttpResponse("[Error] Invalid Invokation")

	stateLabels = states.split(",")
	if p_testType == 1:
		sqlalchemy_export_js_errors(request, siteId, runHashId, stateLabels)

	run= get_object_or_404(ScriptRun, hashId = runHashId, attackMode=p_testType)
	dataObjects = run.script_datas.filter(siteId = siteId)

	base_dir = get_or_create_script_file_base_directory(testType, siteId)
	auto_geneate_browser_config_log(base_dir) #creates browser specification file 

	if p_testType == 0:
		file_second_part_name= "vars"
		report_header_suffix= "Variables"
	else:
		file_second_part_name= "errs"
		report_header_suffix= "Errors"
	filename = "script-%s-%s.csv"%(file_second_part_name, run.timestamp)
	filepath = os.path.join(base_dir, filename)
	csvFile = open(filepath, "wb")

	stateCount = len(stateLabels)
	headerLine = "URL, "
	for stateIdx in range(stateCount):
		state = stateLabels[stateIdx]
		if stateIdx == stateCount-1:
			headerLine+="%s_%s\n"%(state, report_header_suffix)
		else:
			headerLine+="%s_%s, "%(state, report_header_suffix)
	csvFile.write(headerLine)

	msgsState_all = []
	for stateLabel in stateLabels:
		msgsState_i = dataObjects.filter(stateLabel=stateLabel).all()
		msgsState_all.append(msgsState_i)

	for data_obj in msgsState_all[0]:
		target_url = data_obj.targetURL
		s0_message = data_obj.message
		writeLine = "\"%s\", \"%s\", "%(target_url, s0_message)
		msgsState_all_length = len(msgsState_all)
		for i in range(msgsState_all_length):
			if i == 0: continue
			mState_i = msgsState_all[i]
			if "user_token=" in target_url:
				matchURL = target_url[:target_url.index("user_token=")]
				stateMessage_i = mState_i.filter(targetURL__startswith=matchURL).first()
			else:
				stateMessage_i = mState_i.filter(targetURL=target_url).first()
			si_message = stateMessage_i.message
			if i == msgsState_all_length-1:
				writeLine+="\"%s\"\n"%(si_message)
			else:
				writeLine+="\"%s\", "%(si_message)
		csvFile.write(writeLine.encode('ascii','replace'))
		
	csvFile.close()
	return HttpResponse("[Success] Exported CSV for siteId={0}, hash={1} and attackMode={2}".format(siteId, runHashId, p_testType))


# function to export csv from db for script errors and script variables attack
# @param testType 0 for script variables, 1 for script errors
def ScriptVarsExportCSVFromDB(request, siteId, testType):
	siteId= int(siteId)
	p_testType= int(testType)
	runHashId= request.GET.get('hash', '')
	states= request.GET.get('states', '')
	if runHashId == '' or states == '':
		return HttpResponse("[Error] Invalid Invokation")

	stateLabels = states.split(",")

	if p_testType == 0:
		sqlalchemy_export_js_object_read(request, siteId, runHashId, stateLabels)


	run= get_object_or_404(ScriptRun, hashId = runHashId, attackMode=p_testType)
	dataObjects = run.script_datas.filter(siteId = siteId)

	base_dir = get_or_create_script_file_base_directory(testType, siteId)
	auto_geneate_browser_config_log(base_dir) #creates browser specification file 

	if p_testType == 0:
		file_second_part_name= "vars"
		report_header_suffix= "Variables"
	else:
		file_second_part_name= "errs"
		report_header_suffix= "Errors"
	filename = "script-%s-%s.csv"%(file_second_part_name, run.timestamp)
	filepath = os.path.join(base_dir, filename)
	csvFile = open(filepath, "wb")

	stateCount = len(stateLabels)
	headerLine = "URL, "
	for stateIdx in range(stateCount):
		state = stateLabels[stateIdx]
		if stateIdx == stateCount-1:
			headerLine+="%s_%s, %s_Length\n"%(state, report_header_suffix, state)
		else:
			headerLine+="%s_%s, %s_Length, "%(state, report_header_suffix, state)
	csvFile.write(headerLine)

	msgsState_all = []
	for stateLabel in stateLabels:
		msgsState_i = dataObjects.filter(stateLabel=stateLabel).all()
		msgsState_all.append(msgsState_i)

	for data_obj in msgsState_all[0]:
		target_url = data_obj.targetURL
		s0_message = data_obj.message
		s0_message_len = data_obj.messageLength
		writeLine = "\"%s\", \"%s\", \"%s\", "%(target_url, s0_message, s0_message_len)
		msgsState_all_length = len(msgsState_all)
		for i in range(msgsState_all_length):
			if i == 0: continue
			mState_i = msgsState_all[i]
			if "user_token=" in target_url:
				matchURL = target_url[:target_url.index("user_token=")]
				stateMessage_i = mState_i.filter(targetURL__startswith=matchURL).first()
			else:
				stateMessage_i = mState_i.filter(targetURL=target_url).first()
			si_message = stateMessage_i.message
			si_message_length = stateMessage_i.messageLength
			if i == msgsState_all_length-1:
				writeLine+="\"%s\", \"%s\"\n"%(si_message, si_message_length)
			else:
				writeLine+="\"%s\", \"%s\", "%(si_message, si_message_length)
		csvFile.write(writeLine.encode('ascii','replace'))
		
	csvFile.close()
	return HttpResponse("[Success] Exported CSV for siteId={0}, hash={1} and attackMode={2}".format(siteId, runHashId, p_testType))	



# --------------------------------------------------------------------------- #
#				  Content Window Attack - DATA COLLECTION
# --------------------------------------------------------------------------- #


def get_or_create_content_window_file_base_directory(siteId):
	global BROWSER_REPORT_FOLDER
	content_window_relative_dir = "automator/%s/TestReports/ContentWindow/%s"%(siteId, BROWSER_REPORT_FOLDER)
	content_window_abs_dir = os.path.join(ROOT_DIR, content_window_relative_dir)
	if not os.path.exists(content_window_abs_dir):
		os.makedirs(content_window_abs_dir)
	return content_window_abs_dir

# @Format site_url, logged_in_count, logged_out_count, fresh_count;
# @Note assumes base log directory exists
def save_log_file_content_window(siteId):
	global CONTENT_WINDOW
	timestamp = _get_current_timestamp() # update the timestamp on each save
	log_file_name = "content-window-"+ timestamp+".csv"
	log_file_base =  get_or_create_content_window_file_base_directory(siteId)
	auto_geneate_browser_config_log(log_file_base)
	abs_path =  os.path.join(log_file_base, log_file_name)
	fp = open(abs_path, "w+")
	fp.write("URL, Logged_In_Count, Logged_Out_Count, Fresh_Browser_Count\n")
	print CONTENT_WINDOW
	for url in CONTENT_WINDOW["L"]:
		LCount = CONTENT_WINDOW["L"][url]
		NCount = CONTENT_WINDOW["N"][url]
		FCount = CONTENT_WINDOW["F"][url]
		to_write = "%s, %s, %s, %s\n"%(url, LCount, NCount, FCount)
		fp.write(to_write)
	fp.close()
	save_status = 200
	return save_status

# @Function: Django Controller - Http GET Handler
# @URL GET /clear-content-window-memory/
def clear_content_window_memory(request):
	global CONTENT_WINDOW 
	CONTENT_WINDOW = {"L": {}, "N": {}, "F": {}}
	return HttpResponse("[SucesssMessage] Memory Cleared")

def ContentWindowExportCSVFromDB(request, siteId):
	siteId = int(siteId)
	runHashId= request.GET.get('hash', '')
	states = request.GET.get('states', '')
	if runHashId == '' or states == '':
		return HttpResponse("[Error] Invalid Invokation")

	stateLabels = states.split(",")
	sqlalchemy_export_op_content_window(request, siteId, runHashId, stateLabels)
	print "here"

	run= get_object_or_404(ContentWindowRun, hashId = runHashId)
	cwObjects = run.datas.filter(siteId = siteId)

	base_dir = get_or_create_content_window_file_base_directory(siteId)
	auto_geneate_browser_config_log(base_dir) #creates browser specification file 

	filename = "content-window-"+ run.timestamp+".csv"

	filepath = os.path.join(base_dir, filename)
	csvFile = open(filepath, "wb")

	stateCount = len(stateLabels)
	headerLine = "URL, "
	for stateIdx in range(stateCount):
		state = stateLabels[stateIdx]
		if stateIdx == stateCount-1:
			headerLine+="%s_cwLength\n"%(state)
		else:
			headerLine+="%s_cwLength, "%(state)

	csvFile.write(headerLine)

	cwObjects_all = []
	for stateLabel in stateLabels:
		cwObjects_i = cwObjects.filter(stateLabel=stateLabel).all()
		cwObjects_all.append(cwObjects_i)

	for cwObj in cwObjects_all[0]:
		target_url = cwObj.url
		s0_cwCount = cwObj.cwCount
		writeLine = "\"%s\", \"%s\", "%(target_url, s0_cwCount)
		cwObjects_all_length = len(cwObjects_all)
		for i in range(cwObjects_all_length):
			if i == 0: continue
			cwObjects_i = cwObjects_all[i]
			if "user_token=" in target_url:
				matchURL = target_url[:target_url.index("user_token=")]
				cwObject_i = cwObjects_i.filter(url__startswith=matchURL).first()
			else:
				cwObject_i = cwObjects_i.filter(url=target_url).first()
			si_cwCount = cwObject_i.cwCount
			if i == cwObjects_all_length-1:
				writeLine+="\"%s\"\n"%(si_cwCount)
			else:
				writeLine+="\"%s\", "%(si_cwCount)
		csvFile.write(writeLine.encode('ascii','replace'))
		
	csvFile.close()
	return HttpResponse("[Success] Exported CSV for siteId={0} and hash={1}".format(siteId, runHashId))


# @Function: Django Controller - Http GET Handler
# @URL GET /record-content-window/
def recordContentWindowFrameCount(request, siteId):

	# body_unicode = request.body.decode('utf-8') # python 3.x
	body = json.loads(request.body)

	p_siteId = siteId
	p_runHashId = body["runHashId"]
	p_url = body["framedurl"]
	p_stateStatus = body["state_status"]
	p_cwCount = body["frame_count"]

	global BROWSER
	p_browser = BROWSER
	p_browser_version = get_browser_version()

	runObject, runObjectCreated = ContentWindowRun.objects.get_or_create(hashId=p_runHashId, defaults={"Browser":p_browser,"BrowserVersion":p_browser_version})
	if runObjectCreated:
		timestamp = str(datetime.now().strftime('%Y-%m-%d_%H-%M-%S'))
		runObject.timestamp = timestamp
		runObject.save()

	cwObject, cwObjectCreated = ContentWindowData.objects.get_or_create(run = runObject, siteId= p_siteId, url= p_url, 
	stateLabel= p_stateStatus, cwCount= p_cwCount)

	response_status = 200
	return JsonResponse({'response_status':response_status})

# @DEPRECATED METHOD
# @Function: Django Controller - Http GET Handler
# @URL GET /export-content-window/
def exportContentWindowFrameCount(request, siteId):
	save_log_file_content_window(siteId)
	global CONTENT_WINDOW 
	CONTENT_WINDOW = {"L": {}, "N": {}, "F": {}}
	return HttpResponse("[SucesssMessage] Exported Content Window Frame Counts.")

# @DEPRECATED METHOD
def clearContentWindowMemory(request):
	global CONTENT_WINDOW 
	CONTENT_WINDOW = {"L": {}, "N": {}, "F": {}}
	return HttpResponse("[SucesssMessage] Memory Cleared")

# @DEPRECATED METHOD
def peekContentWindowMemory(request):
	global CONTENT_WINDOW
	return HttpResponse(CONTENT_WINDOW.items())


# --------------------------------------------------------------------------- #
#				  Event Fire Count - DATA COLLECTION
# --------------------------------------------------------------------------- #


# @Function: Django Controller - Http GET Handler
# @URL GET /record-event-count/siteId/
def recordEventFireCount(request, siteId):
	# body_unicode = request.body.decode('utf-8') # python 3.x
	body = json.loads(request.body)

	p_runHashId = body["runHashId"]
	p_url = body["target_url"]
	p_siteId = body["siteId"]
	p_stateStatus = body["state_status"]
	p_event_order = body["event_order"]
	p_event_count = body["event_count"]
	p_tag_name = body["tag"]

	global BROWSER
	p_browser = BROWSER
	p_browser_version = get_browser_version()

	# IMPORTANT: pass non-unique keys to defaults to ensure get_or_create being thread-safe
	runObject, runObjectCreated = EventFireCountRun.objects.get_or_create(hashId=p_runHashId, defaults={"Browser":p_browser,"BrowserVersion":p_browser_version})
	if runObjectCreated:
		timestamp = str(datetime.now().strftime('%Y-%m-%d_%H-%M-%S'))
		runObject.timestamp = timestamp
		runObject.save()

	eventCountObject, eventCountObjectCreated = EventFireCountData.objects.get_or_create(run = runObject, siteId= p_siteId, url= p_url, 
	stateLabel= p_stateStatus, tag_name= p_tag_name, event_order= p_event_order, event_count= p_event_count)

	response_status = 200
	return JsonResponse({'response_status':response_status})

def get_or_create_event_fire_count_base_directory(siteId, browserFolder):
	global BROWSER_REPORT_FOLDER
	if browserFolder!= None:
		relative_dir = "automator/%s/TestReports/EventFireCount/%s"%(siteId, browserFolder)
	else:
		relative_dir = "automator/%s/TestReports/EventFireCount/%s"%(siteId, BROWSER_REPORT_FOLDER)
	abs_dir = os.path.join(ROOT_DIR, relative_dir)
	if not os.path.exists(abs_dir):
		os.makedirs(abs_dir)
	return abs_dir

def eventFireCountExportCSVFromDB(request, siteId):
	siteId = int(siteId)
	runHashId= request.GET.get('hash', '')
	tag_name= request.GET.get('tag', '')
	events= request.GET.get('events', '')
	states = request.GET.get('states', '')
	forceBrowser=request.GET.get('browser', None)
	if runHashId == '' or tag_name == '' or events == '' or states == '':
		return HttpResponse("[Error] Invalid Invokation")

	stateLabels = states.split(",")
	sqlalchemy_export_events_fired_dynamic(request, siteId, runHashId, stateLabels, tag_name)

	run= get_object_or_404(EventFireCountRun, hashId = runHashId)
	eventObjects = run.events.filter(siteId = siteId, tag_name= tag_name)

	base_dir = get_or_create_event_fire_count_base_directory(siteId, forceBrowser)
	auto_geneate_browser_config_log(base_dir) #creates browser specification file 

	if len(events)>60:
		eventsSummary = events[:60]+ "-etc"
	else:
		eventsSummary = events
	filename = "%s-%s-%s.csv"%(tag_name, eventsSummary, run.timestamp)
	filepath = os.path.join(base_dir, filename)
	csvFile = open(filepath, "wb")

	stateCount = len(stateLabels)
	headerLine = "URL, "
	for stateIdx in range(stateCount):
		state = stateLabels[stateIdx]
		if stateIdx == stateCount-1:
			headerLine+="%s_EventsOrder, %s_EventsFired\n"%(state, state)
		else:
			headerLine+="%s_EventsOrder, %s_EventsFired, "%(state, state)

	csvFile.write(headerLine)

	eventsState_all = []
	for stateLabel in stateLabels:
		eventsState_i = eventObjects.filter(stateLabel=stateLabel).all()
		eventsState_all.append(eventsState_i)

	for evt in eventsState_all[0]:
		target_url = evt.url
		s0_EventOrder = evt.event_order
		s0_EventCount = evt.event_count
		writeLine = "\"%s\", \"%s\", \"%s\", "%(target_url, s0_EventOrder, s0_EventCount)
		eventsState_all_length = len(eventsState_all)
		skipLine=False
		for i in range(eventsState_all_length):
			if skipLine: break
			if i == 0: continue
			eventsState_i = eventsState_all[i]
			if "user_token=" in target_url:
				matchURL = target_url[:target_url.index("user_token=")]
				stateEvent_i = eventsState_i.filter(url__startswith=matchURL).first()
			else:
				stateEvent_i = eventsState_i.filter(url=target_url).first()
			if stateEvent_i is None:
				skipLine = True
				break
			si_EventOrder = stateEvent_i.event_order
			si_EventCount = stateEvent_i.event_count
			if i == eventsState_all_length-1:
				writeLine+="\"%s\", \"%s\"\n"%(si_EventOrder, si_EventCount)
			else:
				writeLine+="\"%s\", \"%s\", "%(si_EventOrder, si_EventCount)
		if not skipLine:
			csvFile.write(writeLine.encode('ascii','replace'))
		
	csvFile.close()
	return HttpResponse("[Success] Exported CSV for siteId={0}, tag={1}, event={2} and hash={3}".format(siteId, tag_name, eventsSummary, runHashId))


# --------------------------------------------------------------------------- #
#							CSP Attack
# --------------------------------------------------------------------------- #

from .models import CSPRun, CSPData, CSPDataViolatedURL

def get_or_create_csp_base_directory(siteId):
	global BROWSER_REPORT_FOLDER
	relative_dir = "automator/%s/TestReports/CSP/%s"%(siteId, BROWSER_REPORT_FOLDER)
	abs_dir = os.path.join(ROOT_DIR, relative_dir)
	if not os.path.exists(abs_dir):
		os.makedirs(abs_dir)
	return abs_dir

# controllerURL = record-csp-violation/site-id/state-status/tag-name/run-hash-id/target-url/
def record_csp_attack(request, site_id, state_status, tag_name, hash_id):
	target_url = request.GET.get("target", "")
	target_url = decodeURL_Plus(target_url)
	body = json.loads(request.body)
	try:
		blocked_url = body["csp-report"]["blocked-uri"]
	except:
		blocked_url = "[Warning] webpage did not posted the blocked_url correctly!"

	global BROWSER
	p_browser = BROWSER
	p_browser_version = get_browser_version()

	runObject, runObjectCreated = CSPRun.objects.get_or_create(hashId=hash_id, Browser = p_browser, BrowserVersion = p_browser_version)
	if runObjectCreated:
		timestamp = str(datetime.now().strftime('%Y-%m-%d_%H-%M-%S'))
		runObject.timestamp = timestamp
		runObject.save()

	dataObject, dataObjectedCreated = CSPData.objects.get_or_create(run=runObject, siteId=site_id, targetURL = target_url, stateLabel=state_status, tagName=tag_name)

	violatedURLObject = CSPDataViolatedURL.objects.create(CSPData=dataObject ,violatedURL=blocked_url)
	violatedURLObject.save()

	response_status = 200
	return JsonResponse({'response_status':response_status})

def record_csp_test(request):
	pass

def csp_export_csv_from_db(request, site_id):
	siteId = int(site_id)
	runHashId= request.GET.get('hash', '')
	tag_name= request.GET.get('tag', '')
	states = request.GET.get('states', '')
	if runHashId == '' or tag_name == ''  or states == '':
		return HttpResponse("[Error] Invalid Invokation")

	stateLabels = states.split(",")
	sqlalchemy_export_content_security_policy(request, siteId, runHashId, stateLabels, tag_name)

	run= get_object_or_404(CSPRun, hashId = runHashId)
	dataObjects = run.csp_datas.filter(siteId = siteId, tagName= tag_name)

	base_dir = get_or_create_csp_base_directory(siteId)
	auto_geneate_browser_config_log(base_dir) #creates browser specification file


	filename = "csp-%s-%s.csv"%(tag_name, run.timestamp)
	filepath = os.path.join(base_dir, filename)
	csvFile = open(filepath, "wb")

	stateCount = len(stateLabels)
	headerLine = "URL, "
	for stateIdx in range(stateCount):
		state = stateLabels[stateIdx]
		if stateIdx == stateCount-1:
			headerLine+="%s_violation_urls\n"%(state)
		else:
			headerLine+="%s_violation_urls, "%(state)

	csvFile.write(headerLine)

	objStates_all = []
	for stateLabel in stateLabels:
		objState_i = dataObjects.filter(stateLabel=stateLabel).all()
		objStates_all.append(objState_i)

	no_violation_string= "NO_VIOLATION"
	objStates_all_len = len(objStates_all)
	for obj in objStates_all[0]:
		s0_target_url = obj.targetURL
		s0_violated_urls = [qq.violatedURL for qq in obj.violated_urls.all()]
		if (len(s0_violated_urls) >1) and (no_violation_string in s0_violated_urls):
			s0_violated_urls.remove(no_violation_string)

		writeLine = "\"%s\", \"%s\", "%(s0_target_url, s0_violated_urls)

		for i in range(objStates_all_len):
			if i == 0: continue
			objState_i = objStates_all[i]
			if "user_token=" in s0_target_url:
				matchURL = s0_target_url[:s0_target_url.index("user_token=")]
				objState_url_i = objState_i.filter(targetURL__startswith=matchURL).first()
			else:
				print s0_target_url
				objState_url_i = objState_i.filter(targetURL=s0_target_url).first()
			if objState_url_i is not None:
				si_violated_urls = [ qq.violatedURL for qq in objState_url_i.violated_urls.all()]
				if (len(si_violated_urls) >1) and (no_violation_string in si_violated_urls):
					si_violated_urls.remove(no_violation_string)
				if i == objStates_all_len-1:
					writeLine+="\"%s\"\n"%(si_violated_urls)
				else:
					writeLine+="\"%s\", "%(si_violated_urls)
			else:
				si_violated_urls= [no_violation_string]
				if i == objStates_all_len-1:
					writeLine+="\"%s\"\n"%(si_violated_urls)
				else:
					writeLine+="\"%s\", "%(si_violated_urls)
		csvFile.write(writeLine.encode('ascii','replace'))

	csvFile.close()
	return HttpResponse("[Success] Exported CSV for siteId={0}, tag={1} and hash={2}".format(siteId, tag_name, runHashId))



# --------------------------------------------------------------------------- #
#							Timing Analysis (TA) Attack
# --------------------------------------------------------------------------- #


# @URL GET /record-event-count/siteId/
def recordTimingAnalysisLog(request, siteId):
	# body_unicode = request.body.decode('utf-8') # python 3.x
	body = json.loads(request.body)

	p_runHashId = body["runHashId"]
	p_url = body["target_url"]
	p_siteId = body["siteId"]
	p_stateStatus = body["state_status"]
	p_time = body["time"]
	p_tag_name = body["tag"]

	global BROWSER
	p_browser = BROWSER
	p_browser_version = get_browser_version()

	# IMPORTANT: pass non-unique keys to defaults to ensure get_or_create being thread-safe
	runObject, runObjectCreated = TimingAnalysisRun.objects.get_or_create(hashId=p_runHashId, defaults={"Browser":p_browser,"BrowserVersion":p_browser_version})
	if runObjectCreated:
		timestamp = str(datetime.now().strftime('%Y-%m-%d_%H-%M-%S'))
		runObject.timestamp = timestamp
		runObject.save()

	timingDataObject, timingDataObjectCreated = TimingAnalysisData.objects.get_or_create(run = runObject, siteId= p_siteId, url= p_url, 
	stateLabel= p_stateStatus, tag_name= p_tag_name, elpased_time= p_time)

	response_status = 200
	return JsonResponse({'response_status':response_status})


def get_or_create_ta_base_directory(siteId, browserFolder):
	global BROWSER_REPORT_FOLDER
	if browserFolder!= None:
		relative_dir = "automator/%s/TestReports/TimingAnalysis/%s"%(siteId, browserFolder)
	else:
		relative_dir = "automator/%s/TestReports/TimingAnalysis/%s"%(siteId, BROWSER_REPORT_FOLDER)
	abs_dir = os.path.join(ROOT_DIR, relative_dir)
	if not os.path.exists(abs_dir):
		os.makedirs(abs_dir)
	return abs_dir


def timingAnalysisExportCSVFromDB(request, siteId):
	siteId = int(siteId)
	runHashId= request.GET.get('hash', '')
	tag_name= request.GET.get('tag', '')
	states = request.GET.get('states', '')
	forceBrowser=request.GET.get('browser', None)
	if runHashId == '' or tag_name == '' or states == '':
		return HttpResponse("[Error] Invalid Invocation")

	stateLabels = states.split(",")

	run= get_object_or_404(TimingAnalysisRun, hashId = runHashId)
	TAObjects = run.ta_datas.filter(siteId = siteId, tag_name= tag_name)

	base_dir = get_or_create_ta_base_directory(siteId, forceBrowser)
	auto_geneate_browser_config_log(base_dir) # creates the browser specification file 

	filename = "%s-%s.csv"%(tag_name, run.timestamp)
	filepath = os.path.join(base_dir, filename)
	csvFile = open(filepath, "wb")

	stateCount = len(stateLabels)
	headerLine = "URL, "
	for stateIdx in range(stateCount):
		state = stateLabels[stateIdx]
		if stateIdx == stateCount-1:
			headerLine+="%s\n"%(state)
		else:
			headerLine+="%s, "%(state)

	csvFile.write(headerLine)

	datasState_all = []
	for stateLabel in stateLabels:
		dataState_i = TAObjects.filter(stateLabel=stateLabel).all()
		datasState_all.append(dataState_i)

	for dataState in datasState_all[0]:
		target_url = dataState.url
		s0_elpased_time = dataState.elpased_time
		writeLine = "\"%s\",\"%s\", "%(target_url, s0_elpased_time)
		datasState_all_length = len(datasState_all)
		skipLine=False
		for i in range(datasState_all_length):
			if skipLine: break
			if i == 0: continue
			dataState_i = datasState_all[i]
			if "user_token=" in target_url: #quick fix for open cart session dependent urls
				matchURL = target_url[:target_url.index("user_token=")]
				dState_i = dataState_i.filter(url__startswith=matchURL).first()
			else:
				dState_i = dataState_i.filter(url=target_url).first()
			if dState_i is None:
				skipLine = True
				break
			si_elpased_time = dState_i.elpased_time
			if i == datasState_all_length-1:
				writeLine+="\"%s\"\n"%(si_elpased_time)
			else:
				writeLine+="\"%s\", "%(si_elpased_time)
		if not skipLine:
			csvFile.write(writeLine.encode('ascii','replace'))
		
	csvFile.close()
	return HttpResponse("[Success] Exported CSV for siteId={0}, tag={1}, and hash={2}".format(siteId, tag_name, runHashId))


# --------------------------------------------------------------------------- #
#							CORS Attack
# --------------------------------------------------------------------------- #

def get_or_create_cors_base_directory(siteId, browserFolder):
	global BROWSER_REPORT_FOLDER
	if browserFolder!= None:
		relative_dir = "automator/%s/TestReports/CORS/%s"%(siteId, browserFolder)
	else:
		relative_dir = "automator/%s/TestReports/CORS/%s"%(siteId, BROWSER_REPORT_FOLDER)
	abs_dir = os.path.join(ROOT_DIR, relative_dir)
	if not os.path.exists(abs_dir):
		os.makedirs(abs_dir)
	return abs_dir


# GET /record-cors-data/siteId/
def recordCORSData(request, siteId):
	# body_unicode = request.body.decode('utf-8') # python 3.x
	body = json.loads(request.body)

	p_runHashId = body["runHashId"]
	p_url = body["target_url"]
	p_siteId = body["siteId"]
	p_stateStatus = body["state_status"]
	p_response = body["response"]

	global BROWSER
	p_browser = BROWSER
	p_browser_version = get_browser_version()

	# IMPORTANT: pass non-unique keys to defaults to ensure get_or_create being thread-safe
	runObject, runObjectCreated = CORSRun.objects.get_or_create(hashId=p_runHashId, defaults={"Browser":p_browser,"BrowserVersion":p_browser_version})
	if runObjectCreated:
		timestamp = str(datetime.now().strftime('%Y-%m-%d_%H-%M-%S'))
		runObject.timestamp = timestamp
		runObject.save()

	CORSDataObject, CORSDataObjectCreated = CORSData.objects.get_or_create(run = runObject, siteId= p_siteId, url= p_url, 
	stateLabel= p_stateStatus, response= p_response)

	response_status = 200
	return JsonResponse({'response_status':response_status})

def CORSExportCSVFromDB(request, siteId):
	siteId = int(siteId)
	runHashId= request.GET.get('hash', '')
	states = request.GET.get('states', '')
	forceBrowser=request.GET.get('browser', None)
	if runHashId == ''  or states == '':
		return HttpResponse("[Error] Invalid Invocation")

	stateLabels = states.split(",")

	run= get_object_or_404(CORSRun, hashId = runHashId)
	dataObjects = run.cors_datas.filter(siteId = siteId)

	base_dir = get_or_create_cors_base_directory(siteId, forceBrowser)
	auto_geneate_browser_config_log(base_dir) # creates the browser specification file 

	filename = "cors-%s.csv"%(run.timestamp)
	filepath = os.path.join(base_dir, filename)
	csvFile = open(filepath, "wb")

	stateCount = len(stateLabels)
	headerLine = "URL, "
	for stateIdx in range(stateCount):
		state = stateLabels[stateIdx]
		if stateIdx == stateCount-1:
			headerLine+="%s\n"%(state)
		else:
			headerLine+="%s, "%(state)

	csvFile.write(headerLine)

	datasState_all = []
	for stateLabel in stateLabels:
		dataState_i = dataObjects.filter(stateLabel=stateLabel).all()
		datasState_all.append(dataState_i)

	for dataState in datasState_all[0]:
		target_url = dataState.url
		s0_response = dataState.response
		writeLine = "\"%s\",\"%s\", "%(target_url, s0_response)
		datasState_all_length = len(datasState_all)
		skipLine=False
		for i in range(datasState_all_length):
			if skipLine: break
			if i == 0: continue
			dataState_i = datasState_all[i]
			if "user_token=" in target_url: #quick fix for open cart session dependent urls
				matchURL = target_url[:target_url.index("user_token=")]
				dState_i = dataState_i.filter(url__startswith=matchURL).first()
			else:
				dState_i = dataState_i.filter(url=target_url).first()
			if dState_i is None:
				skipLine = True
				break
			si_response = dState_i.response
			if i == datasState_all_length-1:
				writeLine+="\"%s\"\n"%(si_response)
			else:
				writeLine+="\"%s\", "%(si_response)
		if not skipLine:
			csvFile.write(writeLine.encode('ascii','replace'))
		
	csvFile.close()
	return HttpResponse("[Success] Exported CSV for siteId={0}, and hash={1}".format(siteId, runHashId))


# --------------------------------------------------------------------------- #
#					 Read Object Properties
# --------------------------------------------------------------------------- #

def get_or_create_object_props_base_directory(siteId, browserFolder):
	global BROWSER_REPORT_FOLDER
	if browserFolder!= None:
		relative_dir = "automator/%s/TestReports/ObjectProperties/%s"%(siteId, browserFolder)
	else:
		relative_dir = "automator/%s/TestReports/ObjectProperties/%s"%(siteId, BROWSER_REPORT_FOLDER)
	abs_dir = os.path.join(ROOT_DIR, relative_dir)
	if not os.path.exists(abs_dir):
		os.makedirs(abs_dir)
	return abs_dir

# @Function: Django Controller - Http GET Handler
# @URL GET /record-event-count/siteId/
def recordObjectProperties(request, siteId):
	# body_unicode = request.body.decode('utf-8') # python 3.x
	body = json.loads(request.body)

	p_runHashId = body["runHashId"]
	p_url = body["target_url"]
	p_siteId = body["siteId"]
	p_stateStatus = body["state_status"]
	p_props = body["props"]
	p_tag_name = body["tag"]

	global BROWSER
	p_browser = BROWSER
	p_browser_version = get_browser_version()

	# IMPORTANT: pass non-unique keys to defaults to ensure get_or_create being thread-safe
	runObject, runObjectCreated = ObjectReadPropertiesRun.objects.get_or_create(hashId=p_runHashId, defaults={"Browser":p_browser,"BrowserVersion":p_browser_version})
	if runObjectCreated:
		timestamp = str(datetime.now().strftime('%Y-%m-%d_%H-%M-%S'))
		runObject.timestamp = timestamp
		runObject.save()

	dataObject, dataObjectCreated = ObjectReadPropertiesData.objects.get_or_create(run = runObject, siteId= p_siteId, url= p_url, 
	stateLabel= p_stateStatus, tag_name= p_tag_name, props= p_props)

	response_status = 200
	return JsonResponse({'response_status':response_status})


def ObjectPropertiesExportCSVFromDB(request, siteId):
	siteId = int(siteId)
	runHashId= request.GET.get('hash', '')
	tag_name= request.GET.get('tag', '')
	states = request.GET.get('states', '')
	forceBrowser=request.GET.get('browser', None)
	if runHashId == '' or tag_name == '' or states == '':
		return HttpResponse("[Error] Invalid Invokation")

	stateLabels = states.split(",")
	sqlalchemy_export_object_properties(request, siteId, runHashId, stateLabels, tag_name)

	run= get_object_or_404(ObjectReadPropertiesRun, hashId = runHashId)
	dataObjects = run.datas.filter(siteId = siteId, tag_name= tag_name)

	base_dir = get_or_create_object_props_base_directory(siteId, forceBrowser)
	auto_geneate_browser_config_log(base_dir) #creates browser specification file 

	filename = "%s-%s.csv"%(tag_name, run.timestamp)
	filepath = os.path.join(base_dir, filename)
	csvFile = open(filepath, "wb")

	stateCount = len(stateLabels)
	headerLine = "URL, "
	for stateIdx in range(stateCount):
		state = stateLabels[stateIdx]
		if stateIdx == stateCount-1:
			headerLine+="%s\n"%(state)
		else:
			headerLine+="%s, "%(state)

	csvFile.write(headerLine)

	datasState_all = []
	for stateLabel in stateLabels:
		dataState_i = dataObjects.filter(stateLabel=stateLabel).all()
		datasState_all.append(dataState_i)

	for dataState in datasState_all[0]:
		target_url = dataState.url
		s0_props = dataState.props
		writeLine = "\"%s\",\"%s\", "%(target_url, s0_props)
		datasState_all_length = len(datasState_all)
		skipLine=False
		for i in range(datasState_all_length):
			if skipLine: break
			if i == 0: continue
			dataState_i = datasState_all[i]
			if "user_token=" in target_url: #quick fix for open cart session dependent urls
				matchURL = target_url[:target_url.index("user_token=")]
				dState_i = dataState_i.filter(url__startswith=matchURL).first()
			else:
				dState_i = dataState_i.filter(url=target_url).first()
			if dState_i is None:
				skipLine = True
				break
			si_props = dState_i.props
			if i == datasState_all_length-1:
				writeLine+="\"%s\"\n"%(si_props)
			else:
				writeLine+="\"%s\", "%(si_props)
		if not skipLine:
			csvFile.write(writeLine.encode('ascii','replace'))
		
	csvFile.close()
	return HttpResponse("[Success] Exported CSV for siteId={0}, hash={1}, and tag={2}".format(siteId, runHashId, tag_name))
		


# --------------------------------------------------------------------------- #
#					Export Logged Data to SQLAlchemy
#
#  Goal: Create a single attack-vector database from django unstructured records
# --------------------------------------------------------------------------- #

from sqlalchemy_lib import AttackVectorModel, get_or_create_sqlalchemy_session

# utils
def get_tuple_permutations(lst):
	length = len(lst)
	out = []
	for i in range(length):
		for j in range(length):
			if i == j: continue
			item = [lst[i], lst[j]]
			itemReverse = item[::-1]
			if item in out or itemReverse in out:
				continue
			out.append(item)
	return out


# export with sqlalhemy to a single attack-vector database
def sqlalchemy_export_js_object_read(request, siteId, runHashId, stateLabels):

	stateCount = len(stateLabels)	
	run= get_object_or_404(ScriptRun, hashId = runHashId, attackMode=0)
	browser = run.Browser
	browser_version = run.BrowserVersion
	dataObjects = run.script_datas.filter(siteId = siteId)

	dbSession= get_or_create_sqlalchemy_session(siteId)

	distinctURLs= dataObjects.order_by('targetURL').values('targetURL').distinct()
	for eachURL in distinctURLs:
		eachURL = eachURL['targetURL']
		dataObjectsPerURL=  dataObjects.filter(targetURL=eachURL).all()
		queryObjectsPerState= []
		for stateLabel in stateLabels:
			stateLabel = stateLabel.strip()
			qo = dataObjectsPerURL.filter(stateLabel=stateLabel).first()
			queryObjectsPerState.append(qo)

		perms = get_tuple_permutations(queryObjectsPerState)
		for pair in perms:
			p0 = pair[0]
			p1 = pair[1]
			if p0.message != p1.message:
				inclusion= "<script type=\"text/javascript\" src=\"{0}\"></script>".format(eachURL)
				method = "JSObjectRead"
				attackClassType = "dynamic"
				leakVector = str([{'state_a_data': p0.message, 'state_b_data': p1.message, 'method': method, 'inclusion': inclusion}])
				# attackVector = [pair, method, attackClassType, inclusion, browser, browser_version]

				record = AttackVectorModel(States=str([p0.stateLabel, p1.stateLabel]), LeakMethod= method, 
					AttackClassType=attackClassType, Inclusion= leakVector, 
					Browser = browser, BrowserVersion= browser_version)
				dbSession.add(record)
				dbSession.commit()


def sqlalchemy_export_js_errors(request, siteId, runHashId, stateLabels):

	stateCount = len(stateLabels)	
	run= get_object_or_404(ScriptRun, hashId = runHashId, attackMode=1)
	browser = run.Browser
	browser_version = run.BrowserVersion
	dataObjects = run.script_datas.filter(siteId = siteId)

	dbSession= get_or_create_sqlalchemy_session(siteId)

	distinctURLs= dataObjects.order_by('targetURL').values('targetURL').distinct()
	for eachURL in distinctURLs:
		eachURL = eachURL['targetURL']
		dataObjectsPerURL=  dataObjects.filter(targetURL=eachURL).all()
		queryObjectsPerState= []
		for stateLabel in stateLabels:
			stateLabel = stateLabel.strip()
			qo = dataObjectsPerURL.filter(stateLabel=stateLabel).first()
			queryObjectsPerState.append(qo)

		perms = get_tuple_permutations(queryObjectsPerState)
		for pair in perms:
			p0 = pair[0]
			p1 = pair[1]
			if p0.message != p1.message:
				inclusion= "<script type=\"text/javascript\" src=\"{0}\"></script>".format(eachURL)
				method = "JSError"
				attackClassType = "dynamic"
				leakVector = str([{'state_a_data': p0.message, 'state_b_data': p1.message, 'method': method, 'inclusion': inclusion}])
				# attackVector = [pair, method, attackClassType, inclusion, browser, browser_version]

				record = AttackVectorModel(States=str([p0.stateLabel, p1.stateLabel]), LeakMethod= method, 
					AttackClassType=attackClassType, Inclusion= leakVector, 
					Browser = browser, BrowserVersion= browser_version)
				dbSession.add(record)
				dbSession.commit()

def sqlalchemy_export_object_properties(request, siteId, runHashId, stateLabels, tag_name):

	stateCount = len(stateLabels)	
	run= get_object_or_404(ObjectReadPropertiesRun, hashId = runHashId)
	browser = run.Browser
	browser_version = run.BrowserVersion

	dataObjects = run.datas.filter(siteId = siteId, tag_name= tag_name)

	dbSession= get_or_create_sqlalchemy_session(siteId)

	distinctURLs= dataObjects.order_by('url').values('url').distinct()
	for eachURL in distinctURLs:
		eachURL = eachURL['url']
		dataObjectsPerURL=  dataObjects.filter(url=eachURL).all()
		queryObjectsPerState= []
		for stateLabel in stateLabels:
			stateLabel = stateLabel.strip()
			qo = dataObjectsPerURL.filter(stateLabel=stateLabel).first()
			queryObjectsPerState.append(qo)

		perms = get_tuple_permutations(queryObjectsPerState)
		for pair in perms:
			p0 = pair[0]
			p1 = pair[1]
			if (p0 is not None) and (p1 is not None): 
				if p0.props != p1.props:
					if tag_name == "script":
						inclusion= "<script src=\"{0}\"></script>".format(eachURL)
					elif tag_name == "input":
						inclusion= "<input type=\"image\" src=\"{0}\" />".format(eachURL)
					elif tag_name == "video":
						inclusion= "<video src=\"{0}\"></video>".format(eachURL)
					elif tag_name == "audio":
						inclusion= "<audio src=\"{0}\"></audio>".format(eachURL)
					elif tag_name == "videoPoster":
						inclusion= "<video poster=\"{0}\"></video>".format(eachURL)
					elif tag_name == "link_preload_script":
						inclusion= "<link rel=\"preload\" as=\"script\" href=\"{0}\" />".format(eachURL)
					elif tag_name == "link_preload_style":
						inclusion= "<link rel=\"preload\" as=\"style\" href=\"{0}\" />".format(eachURL)
					elif tag_name == "link_prefetch":
						inclusion= "<link rel=\"prefetch\" href=\"{0}\" />".format(eachURL)
					elif tag_name == "link_stylesheet":
						inclusion= "<link rel=\"stylesheet\" href=\"{0}\" />".format(eachURL)
					elif tag_name == "object":
						inclusion= "<object data=\"{0}\"></object>".format(eachURL)	
					elif tag_name == "source":
						inclusion= "<video autoplay=\"true\"><source src=\"{0}\"></video>".format(eachURL)
					elif tag_name == "track":
						inclusion= "<video autoplay=\"true\" src=\"https://interactive-examples.mdn.mozilla.net/media/examples/friday.mp4\"><track src=\"{0}\"></video>".format(eachURL)
					elif tag_name == "embed":
						inclusion= "<embed src=\"{0}\"></embed>".format(eachURL)
					elif tag_name == "iframe":
						inclusion= "<iframe src=\"{0}\"></iframe>".format(eachURL)
					elif tag_name == "img":
						inclusion= "<img src=\"{0}\"></img>".format(eachURL)
					elif tag_name == "applet":
						inclusion= "<applet code=\"{0}\"></applet>".format(eachURL)	
					else:
						inclusion = "<{0} src=\"{1}\"></{0}>".format(tag_name, eachURL)
					method = "ObjectProperties"
					attackClassType = "dynamic"
					leakVector = str([{'state_a_data': p0.props, 'state_b_data': p1.props, 'method': method, 'inclusion': inclusion}])
					# attackVector = [pair, method, attackClassType, inclusion, browser, browser_version]
					record = AttackVectorModel(States=str([p0.stateLabel, p1.stateLabel]), LeakMethod= method, 
						AttackClassType=attackClassType, Inclusion= leakVector, 
						Browser = browser, BrowserVersion= browser_version)
					dbSession.add(record)
					dbSession.commit()

def sqlalchemy_export_post_message(request, siteId, runHashId, stateLabels, attackMode):

	stateCount = len(stateLabels)	
	run= get_object_or_404(PostMessageRun, hashId = runHashId)
	browser = run.Browser
	browser_version = run.BrowserVersion
	dataObjects = run.postMessages.filter(siteId = siteId, openType = attackMode)

	dbSession= get_or_create_sqlalchemy_session(siteId)

	distinctURLs= dataObjects.order_by('url').values('url').distinct()
	for eachURL in distinctURLs:
		eachURL = eachURL['url']
		dataObjectsPerURL=  dataObjects.filter(url=eachURL).all()
		queryObjectsPerState= []
		for stateLabel in stateLabels:
			stateLabel = stateLabel.strip()
			qo = dataObjectsPerURL.filter(stateLabel=stateLabel).first()
			queryObjectsPerState.append(qo)

		perms = get_tuple_permutations(queryObjectsPerState)
		for pair in perms:
			p0 = pair[0]
			p1 = pair[1]
			p0_messages = [obj.message for obj in p0.elements.all()]
			p1_messages = [obj.message for obj in p0.elements.all()]
			if str(p0_messages) != str(p1_messages):
				if str(attackMode) == "0":
					inclusion= "<iframe src=\"{0}\"></iframe>".format(eachURL)
				else:
					inclusion= "window.open(\"{0}\", \"_blank\")".format(eachURL)
				method = "PostMessage"
				attackClassType = "dynamic"
				leakVector = str([{'state_a_data': str(p0_messages), 'state_b_data': str(p1_messages), 'method': method, 'inclusion': inclusion}])
				# attackVector = [pair, method, attackClassType, inclusion, browser, browser_version]
				record = AttackVectorModel(States=str([p0.stateLabel, p1.stateLabel]), LeakMethod= method, 
					AttackClassType=attackClassType, Inclusion= leakVector, 
					Browser = browser, BrowserVersion= browser_version)
				dbSession.add(record)
				dbSession.commit()


def _get_csp_header(tag_name, target_url):
    if tag_name == "iframe" or tag_name == "frame":
        return "frame-src '%s' %s ; frame-ancestors '%s' %s"%('self', target_url, 'self', target_url)
    elif tag_name == "object":
        return "object-src '%s' %s"%('self', target_url)
    elif tag_name == "img":
        return "img-src '%s' %s"%('self', target_url)
    elif tag_name == "audio" or tag_name == "video":
        return "media-src '%s' %s"%('self',target_url)
    elif tag_name == "link":
        return "style-src '%s' %s"%('self',target_url)
    elif tag_name == "embed":
        return "child-src '%s' %s ; frame-ancestors '%s' %s"%('self', target_url, 'self', target_url)
    elif tag_name == "script":
        jquery_url = "https://ajax.googleapis.com/ajax/libs/jquery/3.1.0/jquery.min.js"
        return "script-src 'unsafe-inline' '%s' %s %s"%('self', jquery_url, target_url)
    elif tag_name == "applet":
        return "frame-ancestors '%s' %s ; object-src '%s' %s"%('self', target_url, 'self', target_url)
    else:
        return ""

def sqlalchemy_export_content_security_policy(request, siteId, runHashId, stateLabels, tag_name):

	stateCount = len(stateLabels)	
	run= get_object_or_404(CSPRun, hashId = runHashId)
	browser = run.Browser
	browser_version = run.BrowserVersion

	dataObjects = run.csp_datas.filter(siteId = siteId, tagName= tag_name)

	dbSession= get_or_create_sqlalchemy_session(siteId)

	distinctURLs= dataObjects.order_by('targetURL').values('targetURL').distinct()
	for eachURL in distinctURLs:
		eachURL = eachURL['targetURL']
		dataObjectsPerURL=  dataObjects.filter(targetURL=eachURL).all()
		queryObjectsPerState= []
		for stateLabel in stateLabels:
			stateLabel = stateLabel.strip()
			qo = dataObjectsPerURL.filter(stateLabel=stateLabel).first()
			queryObjectsPerState.append(qo)

		perms = get_tuple_permutations(queryObjectsPerState)
		for pair in perms:
			p0 = pair[0]
			p1 = pair[1]
			p0_violated_urls = [qq.violatedURL for qq in p0.violated_urls.all()]
			p1_violated_urls = [qqq.violatedURL for qqq in p1.violated_urls.all()]
			csp_policy = _get_csp_header(tag_name, eachURL)
			if str(p0_violated_urls) != str(p1_violated_urls):
				if tag_name == "script":
					inclusion= "<script src=\"{0}\"></script>".format(eachURL)
				elif tag_name == "iframe":
					inclusion= "<iframe src=\"{0}\"></iframe>".format(eachURL)
				elif tag_name == "img":
					inclusion= "<img src=\"{0}\"></img>".format(eachURL)
				elif tag_name == "video":
					inclusion= "<video src=\"{0}\"></video>".format(eachURL)
				elif tag_name == "audio":
					inclusion= "<audio src=\"{0}\"></audio>".format(eachURL)
				elif tag_name == "embed":
					inclusion= "<embed src=\"{0}\"></embed>".format(eachURL)
				elif tag_name == "object":
					inclusion= "<object data=\"{0}\"></object>".format(eachURL)	
				elif tag_name == "videoPoster":
					inclusion= "<video poster=\"{0}\"></video>".format(eachURL)
				elif tag_name == "link_preload_script":
					inclusion= "<link rel=\"preload\" as=\"script\" href=\"{0}\" />".format(eachURL)
				elif tag_name == "link_preload_style":
					inclusion= "<link rel=\"preload\" as=\"style\" href=\"{0}\" />".format(eachURL)
				elif tag_name == "link_prefetch":
					inclusion= "<link rel=\"prefetch\" href=\"{0}\" />".format(eachURL)
				elif tag_name == "link_stylesheet":
					inclusion= "<link rel=\"stylesheet\" href=\"{0}\" />".format(eachURL)
				elif tag_name == "source":
					inclusion= "<video autoplay=\"true\"><source src=\"{0}\"></video>".format(eachURL)
				elif tag_name == "track":
					inclusion= "<video autoplay=\"true\" src=\"https://interactive-examples.mdn.mozilla.net/media/examples/friday.mp4\"><track src=\"{0}\"></video>".format(eachURL)				
				elif tag_name == "input":
					inclusion= "<input type=\"image\" src=\"{0}\" />".format(eachURL)
				elif tag_name == "applet":
					inclusion= "<applet code=\"{0}\"></applet>".format(eachURL)	
				else:
					inclusion = "<{0} src=\"{1}\"></{0}>".format(tag_name, eachURL)
				method = "CSP"
				attackClassType = "dynamic"
				leakVector = str([{'state_a_data': str(p0_violated_urls), 'state_b_data': str(p1_violated_urls), 'method': method, 'inclusion': inclusion, "csp_policy": csp_policy, "url": eachURL}])
				# attackVector = [pair, method, attackClassType, inclusion, browser, browser_version]
				record = AttackVectorModel(States=str([p0.stateLabel, p1.stateLabel]), LeakMethod= method, 
					AttackClassType=attackClassType, Inclusion= leakVector, 
					Browser = browser, BrowserVersion= browser_version)
				dbSession.add(record)
				dbSession.commit()



def sqlalchemy_export_op_content_window(request, siteId, runHashId, stateLabels):

	stateCount = len(stateLabels)	
	run= get_object_or_404(ContentWindowRun, hashId = runHashId)
	browser = run.Browser
	browser_version = run.BrowserVersion

	dataObjects = run.datas.filter(siteId = siteId)

	dbSession= get_or_create_sqlalchemy_session(siteId)

	distinctURLs= dataObjects.order_by('url').values('url').distinct()
	print distinctURLs
	print "distinctURLs"
	for eachURL in distinctURLs:
		eachURL = eachURL['url']
		dataObjectsPerURL=  dataObjects.filter(url=eachURL).all()
		queryObjectsPerState= []
		for stateLabel in stateLabels:
			stateLabel = stateLabel.strip()
			qo = dataObjectsPerURL.filter(stateLabel=stateLabel).first()
			queryObjectsPerState.append(qo)

		perms = get_tuple_permutations(queryObjectsPerState)
		for pair in perms:
			p0 = pair[0]
			p1 = pair[1]
			if (p0 is not None) and (p1 is not None):
				if str(p0.cwCount) != str(p1.cwCount):
					inclusion = "window.open(\"{0}\", \"_blank\")".format(eachURL)
					method = "OPFrameCount"
					attackClassType = "dynamic"
					leakVector = str([{'state_a_data': str(p0.cwCount), 'state_b_data': str(p1.cwCount), 'method': method, 'inclusion': inclusion}])
					# attackVector = [pair, method, attackClassType, inclusion, browser, browser_version]
					record = AttackVectorModel(States=str([p0.stateLabel, p1.stateLabel]), LeakMethod= method, 
						AttackClassType=attackClassType, Inclusion= leakVector, 
						Browser = browser, BrowserVersion= browser_version)
					dbSession.add(record)
					dbSession.commit()

# @Depcreated: exports the "dynamic" version of events-fired
def sqlalchemy_export_events_fired_dynamic(request, siteId, runHashId, stateLabels, tag_name):

	stateCount = len(stateLabels)	
	run= get_object_or_404(EventFireCountRun, hashId = runHashId)
	browser = run.Browser
	browser_version = run.BrowserVersion

	dataObjects = run.events.filter(siteId = siteId, tag_name= tag_name)

	dbSession= get_or_create_sqlalchemy_session(siteId)

	distinctURLs= dataObjects.order_by('url').values('url').distinct()
	for eachURL in distinctURLs:
		eachURL = eachURL['url']
		dataObjectsPerURL=  dataObjects.filter(url=eachURL).all()
		queryObjectsPerState= []
		for stateLabel in stateLabels:
			stateLabel = stateLabel.strip()
			qo = dataObjectsPerURL.filter(stateLabel=stateLabel).first()
			queryObjectsPerState.append(qo)

		perms = get_tuple_permutations(queryObjectsPerState)
		for pair in perms:
			p0 = pair[0]
			p1 = pair[1]
			if str(p0.event_count) != str(p1.event_count):
				if tag_name == "script":
					inclusion= "<script src=\"{0}\"></script>".format(eachURL)
				elif tag_name == "iframe":
					inclusion= "<iframe src=\"{0}\"></iframe>".format(eachURL)
				elif tag_name == "img":
					inclusion= "<img src=\"{0}\"></img>".format(eachURL)
				elif tag_name == "video":
					inclusion= "<video src=\"{0}\"></video>".format(eachURL)
				elif tag_name == "audio":
					inclusion= "<audio src=\"{0}\"></audio>".format(eachURL)
				elif tag_name == "embed":
					inclusion= "<embed src=\"{0}\"></embed>".format(eachURL)
				elif tag_name == "object":
					inclusion= "<object data=\"{0}\"></object>".format(eachURL)	
				elif tag_name == "videoPoster":
					inclusion= "<video poster=\"{0}\"></video>".format(eachURL)
				elif tag_name == "link_preload_script":
					inclusion= "<link rel=\"preload\" as=\"script\" href=\"{0}\" />".format(eachURL)
				elif tag_name == "link_preload_style":
					inclusion= "<link rel=\"preload\" as=\"style\" href=\"{0}\" />".format(eachURL)
				elif tag_name == "link_prefetch":
					inclusion= "<link rel=\"prefetch\" href=\"{0}\" />".format(eachURL)
				elif tag_name == "link_stylesheet":
					inclusion= "<link rel=\"stylesheet\" href=\"{0}\" />".format(eachURL)
				elif tag_name == "source":
					inclusion= "<video autoplay=\"true\"><source src=\"{0}\"></video>".format(eachURL)
				elif tag_name == "track":
					inclusion= "<video autoplay=\"true\" src=\"https://interactive-examples.mdn.mozilla.net/media/examples/friday.mp4\"><track src=\"{0}\"></video>".format(eachURL)				
				elif tag_name == "input":
					inclusion= "<input type=\"image\" src=\"{0}\" />".format(eachURL)
				elif tag_name == "applet":
					inclusion= "<applet code=\"{0}\"></applet>".format(eachURL)	
				else:
					inclusion = "<{0} src=\"{1}\"></{0}>".format(tag_name, eachURL)
				method = "events_fired"
				attackClassType = "dynamic"
				leakVector = str([{'state_a_data': str(p0.event_count), 'state_b_data': str(p1.event_count), 'method': method, 'inclusion': inclusion}])
				# attackVector = [pair, method, attackClassType, inclusion, browser, browser_version]
				record = AttackVectorModel(States=str([p0.stateLabel, p1.stateLabel]), LeakMethod= method, 
					AttackClassType=attackClassType, Inclusion= leakVector, 
					Browser = browser, BrowserVersion= browser_version)
				dbSession.add(record)
				dbSession.commit()

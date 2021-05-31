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
    A state-based attack vector identification (AVI) crawler module saving different HTTP response headers, 
    such as status code, content-Type or XFO. It is used for `static` detection of COSI attacks, i.e., 
    checking against an attack vector database.

"""


import time
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.proxy import Proxy, ProxyType
from selenium.webdriver.firefox.firefox_binary import FirefoxBinary
from selenium.webdriver.firefox.firefox_profile import FirefoxProfile
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException
from tbselenium.tbdriver import TorBrowserDriver
from zapv2 import ZAPv2
import re
import sys
import os
import json

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
local_settings_path = os.path.join(ROOT_DIR,"testserver/main")
sys.path.insert(0, local_settings_path)
cosi_attack_finder_plugin = os.path.join(ROOT_DIR,"plugins/cosi-attack-finder")
sys.path.insert(0, cosi_attack_finder_plugin)

from attack_page_getter import COSIAttackFinder
from datetime import datetime
from local_settings import site_dict
from publicsuffix import *
import uuid
import urllib
import base64
import copy
import sqlite3
from xlsxwriter.workbook import Workbook
from crawler_find_urls import get_urls
from main import get_new_browser_driver


# --------------------------------------------------------------------------- #
#			    Constants & Global Vars
# --------------------------------------------------------------------------- #


# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# maximum page timeout seconds
MAX_PAGE_TIMEOUT = 23

ZAP_API_KEY = "6g607t3sik9balv4hge6krpis7" 
TEST_SERVER_BASE = "http://127.0.0.1:8000"
BROWSER = 'chrome'
PLATFORM = 'win32' # possible values are win32 and macos
STATES_SCRIPT_FILE = "loginNlogout"
ACTIVE_EDGE_DRIVER= []


# DB_NAME = "crawlerDB.db"
DB_NAME = "crawler-storage.db"
TABLE_NAME = "Table_SD_URLs"


# --------------------------------------------------------------------------- #
#		        Read Config File and Override
# --------------------------------------------------------------------------- #

config_filepath = "app-config.json"
with open(config_filepath, "r") as configFile:
	configData = json.load(configFile)
	if "test-server-endpoint" in configData:
		TEST_SERVER_BASE = configData["test-server-endpoint"]
	if "zap-api-key" in configData:
		ZAP_API_KEY = configData["zap-api-key"]
	if "browser" in configData:
		BROWSER = configData["browser"]
	if "platform" in configData:
		PLATFORM = configData["platform"]
	if "states-script" in configData:
		STATES_SCRIPT_FILE = configData["states-script"]


# --------------------------------------------------------------------------- #
#		        ResponseCategory Class 
# --------------------------------------------------------------------------- #

class ResponseCategory(object):

	def __init__(self, res_code, res_ctype, res_ctype_ops, res_xfo, res_cd ,*args, **kwargs):
		super(ResponseCategory, self).__init__(*args, **kwargs)
		self.res_code = res_code
		self.res_ctype = res_ctype
		self.res_ctype_ops = res_ctype_ops
		self.res_xfo = res_xfo
		self.res_cd = res_cd

	def __unicode__(self):
		return "HttpCode: %s | Content-Type: %s | Content-Type-Options: %s | XFO: %s | res_cd: %s"%(
			self.res_code, self.res_ctype, self.res_ctype_ops, self.res_xfo, self.res_cd)

	def __str__(self):
		return "HttpCode: %s | Content-Type: %s | Content-Type-Options: %s | XFO: %s | res_cd: %s"%(
			self.res_code, self.res_ctype, self.res_ctype_ops, self.res_xfo, self.res_cd)

	def __repr__(self):
		return "HttpCode: %s | Content-Type: %s | Content-Type-Options: %s | XFO: %s | res_cd: %s"%(
			self.res_code, self.res_ctype, self.res_ctype_ops, self.res_xfo, self.res_cd)

	def __eq__(self, other):
		if isinstance(other, ResponseCategory):
			return self.__unicode__() == other.__unicode__()
		else:
			return False

	def __ne__(self, other):
	    """
	    :Description= Overrides the default implementation 
	    :Warning= this MUST exist in Python 2
	    """
	    return not self.__eq__(other)

# --------------------------------------------------------------------------- #
#		        Utility
# --------------------------------------------------------------------------- #

def find_nth(haystack, needle, n):
    """
	finds the nth occurance of the needle in haystack string
    """
    start = haystack.find(needle)
    while start >= 0 and n > 1:
        start = haystack.find(needle, start+len(needle))
        n -= 1
    return start


def get_main_urls_directory(siteId):
	return os.path.join(BASE_DIR, os.path.join("%s"%siteId, "urls"))

def get_crawler_save_directory(siteId):

	path_crawler = os.path.join(BASE_DIR, os.path.join("%s"%siteId, os.path.join("TestReports", "Crawler")))
	if not os.path.exists(path_crawler):
		os.makedirs(path_crawler)
	return path_crawler

def get_test_reports_directory(siteId):
	path_test_report = os.path.join(BASE_DIR, os.path.join("%s"%siteId,"TestReports"))
	if not os.path.exists(path_test_report):
		os.makedirs(path_test_report)
	return path_test_report

def get_urls_for_site(siteId):

	url_file_path = os.path.join(get_main_urls_directory(siteId), "urls.txt")
	if os.path.exists(url_file_path) and os.path.isfile(url_file_path):
		f= open(url_file_path, "r")
		list_urls = f.readlines();
		list_urls = [ item.strip().strip('\n') for item in list_urls]
		f.close()
		return list_urls
	return []

def get_chunks(list_urls, chunk_size):
    """Yield successive n-sized chunks from l."""
    out = []
    for i in xrange(0, len(list_urls), chunk_size):
        out.append(list_urls[i:i + chunk_size])
    return out


def get_other_states(target_state, list_states):
	"""
		returns a list of all states except the target_state
	"""
	out = []
	for state in list_states:
		if state != target_state:
			out.append(state)
	return out

def convert_db_to_xlsx(siteId, conn = None, out_file_name='url-table.xlsx', dbname= DB_NAME, table_name=TABLE_NAME):
	
	crawler_dir = get_crawler_save_directory(siteId)
	db_abs_path = os.path.join(crawler_dir, dbname)
	directory = get_db_save_directory(siteId)
	out_file_path_name = os.path.join(directory, out_file_name)
	workbook = Workbook(out_file_path_name)
	worksheet = workbook.add_worksheet()

	if conn is None:
		conn=sqlite3.connect(db_abs_path)
	schema = _query_db_schema_structure(conn, table_name)
	for i in range(len(schema)):
		item = schema[i]
		columnTitle = item[1]
		worksheet.write(0, i, columnTitle)

	c=conn.cursor()
	mysel = c.execute("select * from %s"%table_name)
	for i, row in enumerate(mysel):
	    for j, value in enumerate(row):
	        worksheet.write(i+1, j, row[j]) # i+1 : does not override header row 
	workbook.close()

# --------------------------------------------------------------------------- #
#		        Database 
# --------------------------------------------------------------------------- #

def get_db_save_directory(siteId):
	return get_main_urls_directory(siteId)


def generate_sql_create_table_statement(list_state_names):
	""" creates the sql table creation command
	:param list_state_names: state script names
	:return sql-create-command
	"""
	global TABLE_NAME
	template = "`in_state_%s` text, `code_state_%s` text, `ctype_state_%s` text, `ctypeops_state_%s` text, `xfo_state_%s` text, `headers_state_%s` text"
	sql_create_urls_table = """ CREATE TABLE IF NOT EXISTS %s (url text PRIMARY KEY"""%TABLE_NAME

	for state_name in list_state_names:  
		row = template%(state_name, state_name, state_name, state_name, state_name, state_name)   
		sql_create_urls_table += ", "+ row

	sql_create_urls_table_start_end = ");"
	sql_create_urls_table += sql_create_urls_table_start_end

	return sql_create_urls_table


def create_connection(db_file):
    """ create a database connection to the SQLite database
        specified by db_file
    :param db_file: database file
    :return: Connection object or None
    """
    conn = sqlite3.connect(db_file)
    return conn
    try:
        conn = sqlite3.connect(db_file)
        return conn
    except:
        return None


def create_table(conn, create_table_sql):
    """ create a table from the create_table_sql statement
    :param conn: Connection object
    :param create_table_sql: a CREATE TABLE statement
    :return: True/False
    """

    c = conn.cursor()
    c.execute(create_table_sql)
    return True
    try:
        c = conn.cursor()
        c.execute(create_table_sql)
        conn.commit()
        return True
    except:
    	return False                     



def get_or_create_db(siteId):

    global DB_NAME
    db_path_name = os.path.join(get_db_save_directory(siteId), DB_NAME)

    # create a database if not exists
    conn = create_connection(db_path_name)
    return conn

def create_tables_if_not_exists(conn, list_state_names):

    sql_create_table_command = generate_sql_create_table_statement(list_state_names)
    if conn is not None:
        return create_table(conn, sql_create_table_command)
    else:
        return False

def upsert_url_state(conn, url, state_name, other_states, in_state_value="Yes"):
	global TABLE_NAME

	template = "url, 'in_state_%s', 'code_state_%s', 'ctype_state_%s', 'ctypeops_state_%s', 'xfo_state_%s'"
	columns = template%(state_name, state_name, state_name, state_name, state_name)

	other_columns_template = "'in_state_%s', 'code_state_%s', 'ctype_state_%s', 'ctypeops_state_%s', 'xfo_state_%s'"
	other_columns = []
	for state in other_states:
		col = other_columns_template%(state, state, state, state, state)
		columns+= ", "+ col
		tmp = col.split(", ")
		other_columns.extend(tmp)
	
	insert_command = """ INSERT OR REPLACE INTO %s (%s) VALUES 
						('%s', '%s', %s, %s, %s, %s
					 """%(TABLE_NAME,
					     columns, 
					     url,
					     in_state_value,
					     "SELECT 'code_state_%s' FROM %s WHERE url = '%s'"%(state_name, TABLE_NAME, url),
					     "SELECT 'ctype_state_%s' FROM %s WHERE url = '%s'"%(state_name, TABLE_NAME, url), 
					     "SELECT 'ctypeops_state_%s' FROM %s WHERE url = '%s'"%(state_name, TABLE_NAME, url), 
					     "SELECT 'xfo_state_%s' FROM %s WHERE url = '%s'"%(state_name, TABLE_NAME, url)) 

	for column in other_columns:
		statement = ", " + "SELECT '%s' FROM %s WHERE url = '%s'"%(column, TABLE_NAME, url)
		insert_command += statement
	insert_command_end = ");"
	insert_command += insert_command_end

	try:
		c = conn.cursor()
		c.execute(insert_command)
		return True
	except:
		return False    


def upsert_url_item_into_db(conn, state_name, other_states, url, url_dictonary_info):
	global TABLE_NAME

	template = "'url', 'in_state_%s', 'code_state_%s', 'ctype_state_%s', 'ctypeops_state_%s', 'xfo_state_%s'"
	columns = template%(state_name, state_name, state_name, state_name, state_name)

	other_columns_template = "'in_state_%s', 'code_state_%s', 'ctype_state_%s', 'ctypeops_state_%s', 'xfo_state_%s'"
	other_columns = []
	for state in other_states:
		col = other_columns_template%(state, state, state, state, state)
		columns+= ", "+ col
		tmp = col.split(", ")
		other_columns.extend(tmp)
	
	insert_command = "REPLACE INTO %s (%s) VALUES ('%s', %s, '%s', '%s', '%s', '%s'"%(TABLE_NAME,
					     columns, 
					     url,
					     "(SELECT `in_state_%s` FROM %s WHERE url = '%s')"%(state_name, TABLE_NAME, url),
					     str(url_dictonary_info['codes']).replace("\'", "\'\'"), 
					     str(url_dictonary_info['c_types']).replace("\'", "\'\'"), 
					     str(url_dictonary_info['c_type_ops']).replace("\'", "\'\'"), 
					     str(url_dictonary_info['xfos']).replace("\'", "\'\'"))

	for column in other_columns:
		statement = ", " + "(SELECT `%s` FROM %s WHERE url = '%s')"%(column.strip('\''), TABLE_NAME, url)
		insert_command += statement
	insert_command_end = ");"
	insert_command += insert_command_end

	c = conn.cursor()
	c.execute(insert_command)
	conn.commit()
                 


def upsert_url_item_into_db_with_headers(conn, state_name, other_states, url, url_dictonary_info):
	global TABLE_NAME

	template = "'url', 'in_state_%s', 'code_state_%s', 'ctype_state_%s', 'ctypeops_state_%s', 'xfo_state_%s', 'headers_state_%s'"
	columns = template%(state_name, state_name, state_name, state_name, state_name, state_name)

	other_columns_template = "'in_state_%s', 'code_state_%s', 'ctype_state_%s', 'ctypeops_state_%s', 'xfo_state_%s', 'headers_state_%s'"
	other_columns = []
	for state in other_states:
		col = other_columns_template%(state, state, state, state, state, state)
		columns+= ", "+ col
		tmp = col.split(", ")
		other_columns.extend(tmp)
	
	insert_command = "REPLACE INTO %s (%s) VALUES ('%s', %s, '%s', '%s', '%s', '%s', '%s'"%(TABLE_NAME,
					     columns, 
					     url,
					     "(SELECT `in_state_%s` FROM %s WHERE url = '%s')"%(state_name, TABLE_NAME, url),
					     str(url_dictonary_info['codes']).replace("\'", "\'\'"), 
					     str(url_dictonary_info['c_types']).replace("\'", "\'\'"), 
					     str(url_dictonary_info['c_type_ops']).replace("\'", "\'\'"), 
					     str(url_dictonary_info['xfos']).replace("\'", "\'\'"),
					     str(url_dictonary_info['headers']).replace("\'", "\'\'"))

	for column in other_columns:
		statement = ", " + "(SELECT `%s` FROM %s WHERE url = '%s')"%(column.strip('\''), TABLE_NAME, url)
		insert_command += statement
	insert_command_end = ");"
	insert_command += insert_command_end

	c = conn.cursor()
	# print insert_command
	c.execute(insert_command)
	conn.commit()

def _query_db_schema_structure(conn, table_name= "Table_SD_URLs"):

	c = conn.cursor()
	command = "PRAGMA table_info(%s);"%table_name
	c.execute(command)
	result_set = c.fetchall()
	return result_set

def _get_count_states_from_db(conn, table_name= "Table_SD_URLs", schema = None):
	if schema:
		result_set = schema
	else:
		result_set = _query_db_schema_structure(conn, table_name)
	return (len(result_set)-1)/6

def _get_element_state_name(conn, elementIndex, schema=None):
	if not schema:
		result_set = _query_db_schema_structure(conn)
	else:
		result_set = schema
	state_counts = (len(result_set)-1)/6
	if elementIndex >= len(result_set):
		return None
	else:
		element = result_set[elementIndex]
		name = element[1]
		name = name[name.index("state_")+len("state_"):]
		return name

# --------------------------------------------------------------------------- #
#		        Main Utils
# --------------------------------------------------------------------------- #


def all_pair_perms_list(lst_indexes=[0,1,2,3,4]):
	"""
		:return [set([0, 1]), set([0, 2]), set([0, 3]), 
			set([0, 4]), set([1, 2]), set([1, 3]), set([1, 4]), 
			set([2, 3]), set([2, 4]), set([3, 4])]
	"""
	results = []
	for elm1 in lst_indexes:
		for elm2 in lst_indexes:
			if elm1 == elm2: continue
			set_pair = {elm1, elm2} # use sets as they do not have order
			if set_pair not in results:
				results.append(set_pair)
	return results


def _get_content_disposition(header_str):
	header_str = header_str.lower()
	find_Index = header_str.find("content-disposition:")
	if find_Index == -1:
		return ''
	else:
		rightSide = header_str[find_Index+len("content-disposition:"):]
		idx = rightSide.find(";")
		if idx == -1:
			idx = rightSide.find("\n")

		headerValue = rightSide[:idx]
		headerValue = headerValue.strip().strip("\n").strip("\r")
		return headerValue



def _get_url_crawl_page(base64token):
	return TEST_SERVER_BASE + "/crawler/index/?inc=%s"%base64token


def _get_cleaned_header(element):
	out = element.split(" ")[1].strip(";")
	if ";" in out: # the case were no space exists between two different headers
		out = out.split(";")[0].strip()
	return out

def _get_zap_message(url, zap):
	"""
		ZAP API does not have a method to get a message with exactURL;
		filter out the messages based on baseurl and then find the target message
	"""
	messages = zap.core.messages(baseurl=url)
	if not isinstance(messages, list): return None
	if len(messages) <=0: return None

	for message in messages:
		responseHeader = message["requestHeader"]
		header = responseHeader.split("\r\n")[0]
		SPACE = " "
		url_with_end_specified = url + SPACE
		if url_with_end_specified in header:
			return message
	return None

def _get_url_traffic_info(url, zap, current_info={"codes":[], "c_types":[], "c_type_ops":[], "xfos":[], "headers": []}):

	out = current_info
	# messages = zap.core.messages(baseurl=url)
	message = _get_zap_message(url, zap)
	if message is None:
		return out

	lastStatusCode = 'XXX'
	targetMessage = message
	responseHeader = targetMessage['responseHeader']
	headersList = responseHeader.split("\r\n")
	for headerItem in headersList:
		headerItem = headerItem.lower()
		if "HTTP/1." in headerItem or "http/1." in headerItem :
			code= headerItem.split(" ")[1]
			lastStatusCode = code
			out["codes"].append(code)
			continue
		elif "Content-Type:" in headerItem:
			item = headerItem[headerItem.index("Content-Type:")+len("Content-Type:")-1:]
			content_type = _get_cleaned_header(item)
			out["c_types"].append(content_type)
			continue
		elif "content-type:" in headerItem:
			item = headerItem[headerItem.index("content-type:")+len("content-type:")-1:]
			content_type = _get_cleaned_header(item)
			out["c_types"].append(content_type)
			continue
		elif "X-Content-Type-Options:" in headerItem:
			item = headerItem[headerItem.index("X-Content-Type-Options:")+len("X-Content-Type-Options:")-1:]
			content_type_option = _get_cleaned_header(item)
			out["c_type_ops"].append(content_type_option)	
			continue
		elif "x-content-type-options:" in headerItem:
			item = headerItem[headerItem.index("x-content-type-options:")+len("x-content-type-options:")-1:]
			content_type_option = _get_cleaned_header(item)
			out["c_type_ops"].append(content_type_option)	
			continue
		elif "X-Frame-Options:" in headerItem:
			item = headerItem[headerItem.index("X-Frame-Options:")+len("X-Frame-Options:")-1:]
			x_frame_option = _get_cleaned_header(item)	
			out["xfos"].append(x_frame_option)
			continue
		elif "x-frame-options:" in headerItem:
			item = headerItem[headerItem.index("x-frame-options:")+len("x-frame-options:")-1:]
			x_frame_option = _get_cleaned_header(item)	
			out["xfos"].append(x_frame_option)
			continue		
	if lastStatusCode.startswith('3'):
		locationHeaderURL = ''
		recursiveCall= False
		for headerItem in headersList:
			locationIndex = headerItem.find("Location:")
			if locationIndex == -1:
				locationIndex = headerItem.find("location:")
				if locationIndex == -1:
					# ZAP API unrespnsive!!
					continue
			else:
				locationHeader = headerItem.split(" ")
				locationHeaderURL = locationHeader[1].strip(";")
				if locationHeaderURL.startswith("/"):
					targetURL = url
					extraPartOfURLIndex = find_nth(targetURL, "/", 3)
					baseURL = targetURL[:extraPartOfURLIndex]
					locationHeaderURL= baseURL + locationHeaderURL
				recursiveCall = True
				break
		if recursiveCall:
			out = _get_url_traffic_info(locationHeaderURL, zap, out)
	else:
		out['headers'].append(responseHeader)
	return out


# --------------------------------------------------------------------------------- #
#							Data Collector (Response Headers)
# --------------------------------------------------------------------------------- #


def main_crawl_url_response_headers(siteId, chunk_size=5):
	"""
		:param chunk_size= generate and visit the same page for a chunk_size number of urls 
	"""
	zap = ZAPv2(apikey=ZAP_API_KEY)
	zap.core.new_session(apikey=ZAP_API_KEY)

	list_urls = get_urls_for_site(siteId)
	chunks = get_chunks(list_urls, chunk_size)

	stateModule = __import__("%s.Scripts.%s"%(siteId, STATES_SCRIPT_FILE), fromlist=["states"])
	states = stateModule.states
	list_state_names = [item["label"] for item in states]


	conn = get_or_create_db(siteId)
	if conn is None:
		print "Error while creating a db connection!"
		sys.exit(1)

	operation_stat = create_tables_if_not_exists(conn, list_state_names)
	if operation_stat == False:
		print "Error while creating the table schema!"
		sys.exit(1)

	stateCount = len(states)
	for stateIdx in range(stateCount):
		state = states[stateIdx]
		stateFunctionPtr = state["function"]
		stateLabel = state["label"]
		# Step 1: execute each state function
		if stateIdx == 0:
			log_browser_config = True
		else:
			log_browser_config = False
		driver = get_new_browser_driver(BROWSER, generate_config_file = log_browser_config)	
		time.sleep(1)
		print "[MainThread] Executing state function '%s' for siteID='%s'"%(stateLabel, siteId)
		try:
			driver = stateFunctionPtr(driver)
		except:
			print "[MainThread State script runtimee error!"
			# continue
		print "[MainThread] Successfully Executed state function '%s' for siteID='%s'"%(stateLabel, siteId) 
		driver.set_page_load_timeout(45)

		# Step 2: visit crawl pages (each having a chunk of urls) for every state 
		for chunk in chunks:
			zap.core.new_session(apikey=ZAP_API_KEY)
			time.sleep(2)
			base64_urls_list = str(chunk).encode('base64')
			target_url_crawl_page = _get_url_crawl_page(base64_urls_list)
			try:
				driver.get(target_url_crawl_page)
			except:
				pass
			if int(siteId) == 103:
				# fix for opencart dialog box openings
				try:
				    WebDriverWait(driver, 3).until(EC.alert_is_present(),
				                                   'Timed out waiting for PA creation ' +
				                                   'confirmation popup to appear.')

				    alert = driver.switch_to.alert
				    alert.accept()
				except:
					pass
				time.sleep(2)

			# collect the traffic we want from ZAP
			for url in chunk:
				current_info={"codes":[], "c_types":[], "c_type_ops":[], "xfos":[], 'headers': []}
				url_traffic_info_dict = _get_url_traffic_info(url, zap, current_info)
				other_states = get_other_states(stateLabel, list_state_names)
				# upsert_url_item_into_db(conn, stateLabel, other_states, url, url_traffic_info_dict)
				upsert_url_item_into_db_with_headers(conn, stateLabel, other_states, url, url_traffic_info_dict)
				time.sleep(1)
			time.sleep(1)
		driver.close()
		time.sleep(2)

	convert_db_to_xlsx(siteId, conn=conn)

# --------------------------------------------------------------------------------- #
#				Attack Vector Identification (AVI)
# --------------------------------------------------------------------------------- #


sqlalchemy_path= os.path.join(ROOT_DIR, os.path.join("logserver", "logmain"))
sys.path.insert(0, sqlalchemy_path)

from sqlalchemy_lib import AttackVectorModel, get_or_create_sqlalchemy_session


def get_cosi_attacks(siteId, browser, browser_version, out_file_slug=''):

	browser = browser.lower()

	_OUTPUT_REPORT_NAME = "report-%s-%s-%s.out"%(browser, browser_version, out_file_slug)
	_OUTPUT_REPORT_NAME_VULN = "report-%s-%s-%s-vuln.out"%(browser, browser_version, out_file_slug)
	_OUTPUT_REPORT_PATH_NAME_VULN = os.path.join(get_crawler_save_directory(siteId), _OUTPUT_REPORT_NAME_VULN)
	_OUTPUT_REPORT_PATH_NAME = os.path.join(get_crawler_save_directory(siteId), _OUTPUT_REPORT_NAME)

	_OUT_REPORT_ATTACK_VECTORS_NAME = "report-attack-vectors.xlsx"
	_OUT_REPORT_ATTACK_VECTORS_PATH_NAME = os.path.join(get_test_reports_directory(siteId), _OUT_REPORT_ATTACK_VECTORS_NAME)

	_caf_instance = COSIAttackFinder()

	conn = get_or_create_db(siteId)
	c = conn.cursor()
	command = "select * from Table_SD_URLs"
	c.execute(command)
	queryset = c.fetchall()

	sqlAlchemySession = get_or_create_sqlalchemy_session(siteId)

	schema = _query_db_schema_structure(conn)
	stateCount =  _get_count_states_from_db(conn, schema=schema)
	# gives the start index of each stateItem (+1-4 to get each other one)
	stateIndexes = [6*i+1 for i in range(stateCount)] 
	permuations =  all_pair_perms_list(stateIndexes)

	# :variable responseMemory
	# map from 
	#	the set {responseCategoryA, responseCategoryB}
	# to 
	#	get_attack_inclusion(responseCategoryA, responseCategoryB)
	responseMemory = { }

	# :variable attackMemory
	# output map from 
	#	the set {state_a_name, state_b_name}
	# to 
	#	(url, get_attack_inclusion(responseCategoryA, responseCategoryB), responseCategoryA, responseCategoryB)
	attackMemory = { }
	keyOrders = { }

	for row in queryset:
		inclusion_url = row[0]
		for pair in permuations:
			pair = list(pair)

			res_a = eval(row[pair[0]+1]) # +1 is to pass in_state_* flag
			res_b = eval(row[pair[1]+1])
			if len(res_a) == 0 or len(res_b) == 0:
				continue

			res_a = res_a[-1] # the last status code in the chain
			res_b = res_b[-1]

			# if res_a.startswith('4'):
			# 	res_a = '400'
			# if res_b.startswith('4'):
			# 	res_b = '400'

			if res_a.startswith('2'):
				res_a = '200'
			if res_b.startswith('2'):
				res_b = '200'

			# force redirect chain to end!
			if res_a.startswith('3'):
				res_a = "200"
			if res_b.startswith('3'):
				res_b = "200"	

			res_type_a = eval(row[pair[0]+2])
			res_type_b = eval(row[pair[1]+2])
			if len(res_type_a) == 0 or len(res_type_b) == 0:
				continue
			res_type_a = res_type_a[-1]
			res_type_b = res_type_b[-1]


			ctype_ops_a = row[pair[0]+3] # X-Content-Type-Ops is in 3rd Column
			ctype_ops_b = row[pair[1]+3]
			if len(ctype_ops_a) <= 2:
				ctype_ops_a_str = "disabled"
			else:
				ctype_ops_a_str = "enabled"
			if len(ctype_ops_b) <= 2:
				ctype_ops_b_str = "disabled"
			else:
				ctype_ops_b_str = "enabled"


			xfo_a = row[pair[0]+4] #XFO is in 4th column
			xfo_b = row[pair[1]+4]
			if len(xfo_a) <= 2:
				xfo_a_str = "disabled"
			else:
				xfo_a_str = "enabled"
			if len(xfo_b) <= 2:
				xfo_b_str = "disabled"
			else:
				xfo_b_str = "enabled"


			cnt_disposition_a = _get_content_disposition(row[pair[0]+5])
			cnt_disposition_a = cnt_disposition_a.lower()
			cnt_disposition_a_str = 'disabled'
			cnt_disposition_b = _get_content_disposition(row[pair[1]+5])
			cnt_disposition_b = cnt_disposition_b.lower()
			cnt_disposition_b_str = 'disabled'
			content_disposition_values = ["inline", "form-data", "attachment"]
			for cd in content_disposition_values:
				if cd in cnt_disposition_a:
					cnt_disposition_a_str = cd
				if cd in cnt_disposition_b:
					cnt_disposition_b_str = cd			


			responseCategoryA = ResponseCategory(res_a, res_type_a, ctype_ops_a_str, xfo_a_str, cnt_disposition_a_str)
			responseCategoryB = ResponseCategory(res_b, res_type_b, ctype_ops_b_str, xfo_b_str, cnt_disposition_b_str)
			if responseCategoryA == responseCategoryB:
				# not an state dependent pair
				continue

			state_a_name = _get_element_state_name(conn, pair[0]+1, schema= schema)
			state_b_name = _get_element_state_name(conn, pair[1]+1, schema= schema)
			attackMemoryKey = frozenset({state_a_name, state_b_name}) # unordered set
			keyOrders[attackMemoryKey] = [state_a_name, state_b_name]
			responseMemoryKey = frozenset({responseCategoryA, responseCategoryB})
			if responseMemoryKey in responseMemory:
				# avoid invoking get_attack_inclusion by storing the results of previous similar invocations
				inclusion = responseMemory[responseMemoryKey]
				if attackMemoryKey not in attackMemory:
					attackMemory[attackMemoryKey] = [(inclusion_url, inclusion, responseCategoryA, responseCategoryB)]
				else:
					attackMemory[attackMemoryKey].append((inclusion_url, inclusion, responseCategoryA, responseCategoryB))
			else:
				inclusion = _caf_instance.get_attack_inclusion(str(res_a), ctype_ops_a_str, res_type_a, xfo_a_str, cnt_disposition_a_str, str(res_b), ctype_ops_b_str, res_type_b, xfo_b_str, cnt_disposition_b_str, browser, browser_version)
				responseMemory[responseMemoryKey] = inclusion
				if attackMemoryKey not in attackMemory:
					attackMemory[attackMemoryKey] = [(inclusion_url, inclusion, responseCategoryA, responseCategoryB)]
				else:
					attackMemory[attackMemoryKey].append((inclusion_url, inclusion, responseCategoryA, responseCategoryB))

	fp =  open(_OUTPUT_REPORT_PATH_NAME, "wb")
	fp_vuln = open(_OUTPUT_REPORT_PATH_NAME_VULN, "wb")
	fp.write("# ====================================================================== #\n ")
	fp.write("\t\tTestConfig: %s, %s\n"%(browser, browser_version))
	fp.write("# ====================================================================== #\n\n")
	fp_vuln.write("# ====================================================================== #\n ")
	fp_vuln.write("\t\tTestConfig: %s, %s\n"%(browser, browser_version))
	fp_vuln.write("# ====================================================================== #\n\n")

	workbook = Workbook(_OUT_REPORT_ATTACK_VECTORS_PATH_NAME)
	wsInstance = workbook.add_worksheet()
	worksheetHeaders = ["States", "LeakMethod", "AttackClassType", "Inclusion", "browser", "browserVersion"]
	for j in range(len(worksheetHeaders)):
		element = worksheetHeaders[j]
		wsInstance.write(1, j+1, element)
	
	wsRow = 2
	wsColumn = 1

	for statePair in attackMemory:
		pairList = keyOrders[statePair]
		fp.write("======================================================================\n")
		fp.write("\t\tA= %s | B= %s\n"%(pairList[0], pairList[1]))
		fp.write("======================================================================\n\n")
		fp_vuln.write("======================================================================\n")
		fp_vuln.write("\t\tA= %s | B= %s\n"%(pairList[0], pairList[1]))
		fp_vuln.write("======================================================================\n\n")
		attack_vectors = attackMemory[statePair]
		for attack_vector in attack_vectors:
			inc = attack_vector[1] # list of inclusions
			if len(inc) != 0:
				for inclusion in inc:
					# change data/src="INCLUDED_URL" with the actual URl 
					inccString = str(inclusion).replace("INCLUDED_URL", attack_vector[0])
					wsColumn = 1
					wsInstance.write(wsRow, wsColumn, str(pairList))	
					wsColumn = wsColumn + 1
					wsInstance.write(wsRow, wsColumn, str(inclusion["method"]))
					wsColumn = wsColumn + 1
					wsInstance.write(wsRow, wsColumn, "static")
					wsColumn = wsColumn + 1
					wsInstance.write(wsRow, wsColumn, inccString)
					wsColumn = wsColumn + 1
					wsInstance.write(wsRow, wsColumn, browser)
					wsColumn = wsColumn + 1
					wsInstance.write(wsRow, wsColumn, browser_version)
					wsRow = wsRow + 1
					
					attackVectorInstance = AttackVectorModel(States=str(pairList), LeakMethod=str(inclusion["method"]), 
						AttackClassType="static", Inclusion=inccString,
						Browser= browser, BrowserVersion=browser_version)

					sqlAlchemySession.add(attackVectorInstance)
					sqlAlchemySession.commit()

				fp_vuln.write("Config A: %s\n"%attack_vector[2])
				fp_vuln.write("Config B: %s\n"%attack_vector[3])
				fp_vuln.write("URL: %s\n"%attack_vector[0])
				fp_vuln.write("INCLUSION: %s\n"%attack_vector[1])
				fp_vuln.write("----------------------------------------------------------------------\n\n")
			fp.write("Config A: %s\n"%attack_vector[2])
			fp.write("Config B: %s\n"%attack_vector[3])
			fp.write("URL: %s\n"%attack_vector[0])
			fp.write("INCLUSION: %s\n"%attack_vector[1])
			fp.write("----------------------------------------------------------------------\n\n")
	fp.write("\n\n")
	fp.close()
	fp_vuln.write("\n\n")
	fp_vuln.close()
	workbook.close()




if __name__ == "__main__":

	# browsers
	# versions must match those in the COSI attack vector database of the `cosi-attack-finder` plugin
	chrome = ["chrome" ,"73.0.3683.86"] 
	firefox = ["firefox" ,"60.0"]
	edge = ["edge" ,"44.17763.1.0"]
	browsers = [chrome, firefox, edge]

	# sites under test
	siteIDs = [23]

	for siteId in siteIDs:
		main_crawl_url_response_headers(siteId, chunk_size=3)
		# get_cosi_attacks(siteId, browser, browser_version, out_file_slug='static_ef') 


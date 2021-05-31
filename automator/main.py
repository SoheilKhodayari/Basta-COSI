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
    Main driver program for running Basta-COSI.
"""

import time
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.proxy import Proxy, ProxyType
from selenium.webdriver.firefox.firefox_binary import FirefoxBinary
from selenium.webdriver.firefox.firefox_profile import FirefoxProfile
from tbselenium.tbdriver import TorBrowserDriver
from zapv2 import ZAPv2
import re
import sys
import requests
import os
import json
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
local_settings_path = os.path.join(ROOT_DIR,"testserver/main")
sys.path.insert(0, local_settings_path)
from datetime import datetime
from local_settings import site_dict
from publicsuffix import *
import httplib2
import uuid
import hashlib
import urllib
import base64
import copy
import tinycss

# --------------------------------------------------------------------------- #
#			    Constants & Global Vars
# --------------------------------------------------------------------------- #

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# contains the key for every site which has some error in the error log file
LOG_ERR_KEYS = []

STATUS_LOGGED_IN = 1
STATUS_LOGGED_OUT = 0
STATUS_FRESH_BROWSER = 2

WINDOW_OPEN_TYPE = 1
FRAME_OPEN_TYPE = 0

SCRIPT_INCLUSION_NUM_OF_RUNS = 1
MODE_SCRIPT_INCLUSION_VARS = 0
MODE_SCRIPT_INCLUSION_ERRS = 1


# Default Configuration Values
ZAP_API_KEY = "6g607t3sik9balv4hge6krpis7" 

TEST_SERVER_BASE = "http://127.0.0.1:8000"

LOG_SERVER_BASE = "http://127.0.0.1:1234"

# maximum page timeout seconds
MAX_PAGE_TIMEOUT = 23

BROWSER = 'chrome'

# this value is only used to choose the installed selenium browser drivers
# example possible values are win32 and macos.
PLATFORM = 'win32'

STATES_SCRIPT_FILE = "loginNlogout"

ACTIVE_EDGE_DRIVER= []

# --------------------------------------------------------------------------- #
#		   Read Config File and Override
# --------------------------------------------------------------------------- #

config_filepath = "app-config.json"
with open(config_filepath, "r") as configFile:
	configData = json.load(configFile)
	if "log-server-endpoint" in configData:
		LOG_SERVER_BASE = configData["log-server-endpoint"]
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
#		   Browser Driver Configuration
# --------------------------------------------------------------------------- #

# TODO: adapt according to your config.

class TorBrowserDriverObject(TorBrowserDriver):
	def __init__(self, binary, *args, **kwargs):
		
		self.binary = binary
		super(TorBrowserDriverObject, self).__init__(*args, **kwargs)
		self.binary= binary

def _auto_generate_browser_config_lock_file(browser, browserVersion):
	run_config_filepath = "auto-generated-config.json"
	runConfigFp = open(run_config_filepath, "w+")
	data_f="{\"BROWSER\":\"%s\", \"BROWSER_VERSION\": \"%s\"}"%(browser, str(browserVersion))
	runConfigFp.write(data_f)
	runConfigFp.close()


def get_new_browser_driver(browser, generate_config_file = False):

	ZAP_PROXY = "127.0.0.1:8080" 

	if browser == "chrome":
		if PLATFORM == "win32":
			chromedriver = 'browser-drivers/win32/chromedriver'
		else:
			chromedriver = 'chromedriver'
		chrome_options = webdriver.ChromeOptions()
		chrome_options.add_argument('--proxy-server=%s' % ZAP_PROXY)
		driver = webdriver.Chrome(chromedriver, chrome_options=chrome_options)
		browser_version = driver.capabilities['version']

	elif browser == "firefox":
		firefox_capabilities = webdriver.DesiredCapabilities.FIREFOX
		if PLATFORM == "win32":
			firefox_capabilities['marionette'] = True #MUST set to TRUE/FALSE depending on firefox and driver version
		else:
			firefox_capabilities['marionette'] = True
		firefox_capabilities['proxy'] = {
		    "proxyType": "MANUAL",
		    "httpProxy": ZAP_PROXY,
		    "ftpProxy": ZAP_PROXY,
		    "sslProxy": ZAP_PROXY
		}
		if PLATFORM == "win32":
			firefoxdriver = "C:/Program Files/Mozilla Firefox/firefox"
			binary = FirefoxBinary(firefoxdriver) #set 
			executable_path= os.path.join(BASE_DIR,'browser-drivers\\win32\\geckodriver')
			driver = webdriver.Firefox(firefox_binary=binary, executable_path=executable_path, capabilities=firefox_capabilities)
			print driver
		else:
			driver = webdriver.Firefox(capabilities=firefox_capabilities)
		browser_version = driver.capabilities['browserVersion']

	elif browser == "edge":
		executable_path= os.path.join(BASE_DIR,'browser-drivers\\win32\\MicrosoftWebDriver')
		capabilities = webdriver.DesiredCapabilities.EDGE.copy()
		capabilities['ignoreProtectedModeSettings'] = True
		global ACTIVE_EDGE_DRIVER

		# edge only allows one instance to be opened by webDriver
		if len(ACTIVE_EDGE_DRIVER)>0:
			driver = ACTIVE_EDGE_DRIVER[0]
			try:
				driver.close()
			except:
				pass
			time.sleep(2)
			driver = webdriver.Edge(executable_path=executable_path, capabilities=capabilities)
			ACTIVE_EDGE_DRIVER[0]= driver
		else:
			driver = webdriver.Edge(executable_path=executable_path, capabilities=capabilities)
			ACTIVE_EDGE_DRIVER.append(driver)
		browser_version = driver.capabilities['browserVersion']
	if generate_config_file:
		_auto_generate_browser_config_lock_file(BROWSER, browser_version)
	return driver



# --------------------------------------------------------------------------- #
#	      Utility Functions
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

def generate_uuid():
	return str(uuid.uuid4())

def get_or_create_directory(relative_directory):
	""" 
	Note: no preceding slash for relative_directory is required 
	"""
	abs_dir = os.path.join(BASE_DIR, relative_directory)
	if not os.path.exists(abs_dir):
		os.makedirs(abs_dir)
	return abs_dir

def get_current_datetime():
	return datetime.now().strftime('%Y-%m-%d_%H-%M-%S')


def get_md5_hash_digest(text_input):
	# return hashlib.sha224(text_input).hexdigest()
	result = hashlib.md5(text_input.encode('utf-8').strip()) 
	return result.hexdigest().encode('utf-8').strip()


def encodeURL(url):
	return url.replace("&", "AMPERSIGNED_REPLACE")

# --------------------------------------------------------------------------- #
#		  Logging Utility Functions
# --------------------------------------------------------------------------- #

def _get_error_log_path(attack_type):
	err_log_dir = os.path.join(BASE_DIR,"global-application-log")
	if not os.path.exists(err_log_dir):
		os.makedirs(err_log_dir)
	err_log_path = os.path.join(err_log_dir, "application-log.log")
	return err_log_path

def create_error_log_fp(attack_type):
	log_path = _get_error_log_path(attack_type)
	fp = open(log_path, "a+")
	return fp

def close_error_log_fp(fp):

	fp.close()

def write_login_error_entry(fp, siteId, site_url):
	if fp.closed:
		fp =  open(err_log_path, "a+")
	LOG_ERR_KEYS.append(siteId)
	timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
	login_error = "[LoginError on %s] error while logging in %s:%s\n"%(timestamp, siteId, site_url)
	fp.write(login_error)

def write_logout_error_entry(fp, siteId, site_url):
	if fp.closed:
		fp =  open(err_log_path, "a+")
	LOG_ERR_KEYS.append(siteId)
	timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
	logout_error = "[LogoutError on %s] error while logging out from %s:%s\n"%(timestamp, siteId, site_url)
	fp.write(logout_error)

def write_state_error_entry(fp, siteId, site_url, state_label):
	if fp.closed:
		fp =  open(err_log_path, "a+")
	LOG_ERR_KEYS.append(siteId)
	timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
	error_message = "[StateError on %s] error while executing state function '%s' for siteId=%s , siteURL=%s\n"%(timestamp, state_label, siteId, site_url)
	fp.write(error_message)
	return error_message

def write_csv_export_error_entry(fp, siteId, site_url, attack_name, runHashId):
	if fp.closed:
		fp =  open(err_log_path, "a+")
	timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
	error_message = "[CSV-Export-Error on %s] export error on %s for siteId=%s, siteURL=%s, runHashId=%s\n"%(timestamp, attack_name, siteId, site_url, runHashId)
	fp.write(error_message)
	return error_message
# --------------------------------------------------------------------------- #
#			     URL Utility Functions
# --------------------------------------------------------------------------- #
# target = target site address
# filter_regex = main regex section for filtering urls
def get_zap_urls(zap ,target, filter_regex, exhaustive_search = False):
	if exhaustive_search:
		print '[ZAP] Accessing target %s' % target
		zap.urlopen(target)
		# Give the sites tree a chance to get updated
		time.sleep(2)

		print '[ZAP] Spidering target %s' % target
		maxChildren = 1000
		scanObject = zap.spider.scan(target, maxChildren)
		# Give the Spider a chance to start
		time.sleep(2)

		mins = 0;
		while (int(zap.spider.status(scanObject)) < 100):
		    print '[ZAP] Spider progress %: ' + zap.spider.status(scanObject)
		    mins+=2
		    time.sleep(2)
		    if mins==10: 
		    	zap.spider.stop(scanObject, ZAP_API_KEY)
		    	print '[ZAP] Spider forced to complete crawling!'

		urls = zap.spider.all_urls
		regex = re.compile(r'%s'%filter_regex)
		selected_urls = filter(regex.search, urls)

		return selected_urls
	else:
		urlObjects = zap.search.urls_by_url_regex(filter_regex)
		urls = [str(obj["url"]) for obj in urlObjects]
		urls = list(set(urls))
		return urls


def save_urls_to_file(siteId, urls_list, filename="urls.txt"):
    base_directory = os.path.join(BASE_DIR,"%s/urls/"%siteId)
    if not os.path.exists(base_directory):
    	os.makedirs(base_directory)

    with open(base_directory+filename, "wb") as fp:
	    for item in urls_list:
	    	data = item.strip()
	    	if data != "":
	    		fp.write(item+"\n")
def clean_empty_space(fileContent):
	results = []
	for line in fileContent:
		data = line.strip()
		if data != "":
			results.append(line)
	return results

def get_urls_for_site(siteId, zap, psl, site_url, site_filter_regex, domain_base, use_css_url_set=False):

	if use_css_url_set:
		file_path = os.path.join(BASE_DIR,"%s/urls/urls-css.txt"%siteId)
	else:
		file_path = os.path.join(BASE_DIR,"%s/urls/urls.txt"%siteId)
	if os.path.exists(file_path) and os.path.isfile(file_path):
		f= open(file_path, "r")
		content = f.readlines();
		content = clean_empty_space(content)
		f.close()
		return content
	else:
		# @URL CRAWLING UPDATE
		# crawled_endpoints = get_zap_urls(zap, site_url, site_filter_regex, False)
		# crawled_endpoints = psl_filter(psl, crawled_endpoints, domain_base)
		crawled_endpoints = main_new_policy_exhaustive_crawling(siteId)
		return crawled_endpoints

def urls_for_site_exists(siteId):
	file_path = os.path.join(BASE_DIR,"%s/urls/urls.txt"%siteId)
	if os.path.exists(file_path) and os.path.isfile(file_path):
		return True
	else:
		False

# considers *.domain.*
def get_regex(domain_name):
	filter_regex = r"(^http:\/\/www\.[^=\/]+\.{0}\..*)|(^https:\/\/www\.[^=\/]+\.{1}\..*)|(^http:\/\/[^=\/]+\.{2}\..*)|(^https:\/\/[^=\/]+\.{3}\..*)|(^http:\/\/www\.{4}\..*)|(^https:\/\/www\.{5}\..*)|(^http:\/\/{6}\..*)|(^https:\/\/{7}\..*)".format(domain_name, domain_name, domain_name, domain_name, domain_name, domain_name, domain_name, domain_name)
	return filter_regex

# considers domain.*
def get_regex_2(domain_name):
	filter_regex = r"(^http://www\.{0}\..*)|(^https://www\.{1}\..*)|(^http://{2}\..*)|(^https://{3}\..*)".format(domain_name, domain_name, domain_name, domain_name)
	return filter_regex

def psl_filter(psl, urls, domain_base):
	results = []
	for url in urls:
		if url.startswith('http'):
			nth = 3
		else:
			nth = 1
		idx= find_nth(url, '/', nth)

		baseURL = url[:idx]

		domain = psl.domain(baseURL)
		suffix = psl.tld(baseURL)

		domainMatch = domain_base + '.' + suffix

		if domainMatch == domain:
			results.append(url)
	return results

# --------------------------------------------------------------------------- #
#					ZAP Spider 
# --------------------------------------------------------------------------- #

# Crawling URLs with an authenticated session
# @Thanks to: 
# 1) https://github.com/zaproxy/zap-api-python/blob/master/src/examples/zap_example_api_script.py
# 2) https://stackoverflow.com/questions/31516420/adding-authentication-in-zap-tool-to-attack-a-url/37972846


# @Param authAccount: denotes which account to use for the test
# possible values are "1" and "2"
def new_policy_exhaustive_crawling(authAccount="1", spider_duration_mins=5, ajax_duration_mins=1, Local=False, IP=False, CrawlFlag=True):

	# TODO: ajax spider: does it require process Id to open in same Browser??!
	# pid = driver.service.process.pid # is a Popen instance for the chromedriver process
	# import psutil
	# p = psutil.Process(pid) #chromedriver process
	# proccesId = p.children(recursive=True)[0].pid

	# public suffix list caching
	cache_dir = os.path.join(BASE_DIR, "cache/")
	psl = public_suffix_list(http=httplib2.Http(cache_dir), headers={'cache-control': 'max-age=%d' % (90000000*60*24)})

	# zap instance
	zap = ZAPv2(apikey=ZAP_API_KEY)
	sessionName="COSISession"
	zap.core.new_session(name=sessionName, overwrite=True, apikey=ZAP_API_KEY)

	for siteId, siteSpec in site_dict.items():
		# new selenium driver
		driver = get_new_browser_driver(BROWSER)
		site_url = siteSpec[0]
		domain_base = siteSpec[1]
		site_filter_regex= get_regex(domain_base)
		if IP:
			site_filter_regex=r"%s.*"%site_url

		# target site for zap spider
		target = site_url 

		# Define the list of global exclude URL regular expressions. List can be empty.
		# The expressions must follow the java.util.regex.Pattern class syntax
		# The following excludes every single URL except targetURL.*
		# as the regex matches only targetURL.*
		globalExcludeUrl = [r"^(?:(?!(http|https):\/\/www.{0}\..+).*).$".format(domain_base)]
		if IP:
			globalExcludeUrl = [r"^(?:(?!(http|https):\/\/{0}\..+).*).$".format(domain_base)]
			print globalExcludeUrl
		if Local:
			globalExcludeUrl = [r"^(?:(?!http:\/\/localhost:80/testconf).*).$"]

		# Corresponds to the ID of the context to use
		# DO NOT CHANGE - default for zap
		contextId = 0
		contextName= "Default Context"

		# Define Context Include URL regular expressions.
		# You have to put the URL/regex you want to test in this list.
		contextIncludeURL = [get_regex(domain_base)]
		if IP:
			contextIncludeURL = ['%s.*'%target]
		if Local:
			contextIncludeURL = ['http://localhost:80.*']

		# You can specify other URL in order to help ZAP discover more site locations
		# List can be empty
		applicationURL = []

		# Authentication
		if authAccount == "1":
			first_phase_completed=False
		else:
			first_phase_completed=True

		stateModule = __import__("%s.Scripts.%s"%(siteId, STATES_SCRIPT_FILE), fromlist=["states"])
		states = stateModule.states
		state = states[int(authAccount)-1]
		stateFunctionPtr = state["function"]
		stateLabel = state["label"]
		print stateLabel
		stateFunctionPtr(driver, site_url, first_phase = first_phase_completed)
		time.sleep(3)
		if not Local:
			trafficURLs = get_zap_urls(zap ,target, site_filter_regex, False)
			if not IP:
				trafficURLs = psl_filter(psl, trafficURLs, domain_base)
		else:
			trafficURLs = get_zap_urls(zap, target, r".*localhost.*")
		save_file_name = "traffic-urls-{0}.txt".format(authAccount)
		save_urls_to_file(siteId, trafficURLs, filename=save_file_name)

		if CrawlFlag:
			# Exclude Other Domains
			for excludeURL in globalExcludeUrl:
				zap.core.exclude_from_proxy(regex=excludeURL, apikey=ZAP_API_KEY)

			# Include target website in the context to test it
			for testURL in contextIncludeURL:
				zap.context.include_in_context(contextname=contextName, regex=testURL, apikey=ZAP_API_KEY)

			try:
				# get login session and set it in the current context
				loginSessions = zap.httpsessions.sessions(target)
				LastLoginSession = loginSessions[-1]
				zap.httpsessions.set_active_session(target, LastLoginSession, apikey=ZAP_API_KEY )
				time.sleep(2)
			except:
				print "No Http Session Found"
				pass 


			# Open URL inside ZAP
			target=target+"/"
			print 'Access target URL ' + target
			zap.core.access_url(url=target, followredirects=True)
			for url in applicationURL:
			    print 'Access URL ' + url
			    zap.core.access_url(url=url, followredirects=True)
			# Give the sites tree a chance to get updated
			time.sleep(5)

			print '[ZAP] Spidering target %s' % target
			# sets the maximum number of child nodes (per node) that can be crawled, 0 means no limit.
			maxChildren = 5000 
			# sets the crawling duration
			zap.spider.set_option_max_duration(spider_duration_mins, apikey=ZAP_API_KEY)
			# The parameter 'subtreeOnly' allows to restrict the spider under a site's subtree (using the specified target 'url')
			subTreeOnly = None
			scanObject = zap.spider.scan(url=target, maxchildren=maxChildren, recurse=True, contextname=contextName, subtreeonly=subTreeOnly)
			# Give the Spider a chance to start
			time.sleep(5)

			while (int(zap.spider.status(scanObject)) < 100):
				print '[ZAP] Spider progress %: ' + zap.spider.status(scanObject)
				time.sleep(2)

			# TODO: How to FORCE ajaxSpider to crawl in the selenium authenticated browser? NO API provided
			# ajax = zap.ajaxSpider
			# ajax.set_option_max_duration(ajax_duration_mins, apikey=ZAP_API_KEY)
			# ajax.scan(url=target, inscope=None)
			# while (ajax.status != 'stopped'):
			# 	time.sleep(5)

			# get all urls
			urls = zap.spider.all_urls

			# save urls with pattern website.public-suffix-list
			ExcludeOutOfContextRegex = re.compile(r'%s'%site_filter_regex)
			IntentedURLs = filter(ExcludeOutOfContextRegex.search, urls)
			if Local:
				IntentedURLs = urls
			save_file_name = "spider-urls-{0}.txt".format(authAccount)
			save_urls_to_file(siteId, IntentedURLs, filename=save_file_name)

			# find redirection urls that redirect to website.public-suffix-list
			print '[MainThread] Finding redirection URLs ...'
			redirectionURLs = []
			messageIDs = range(1, len(urls)+1)
			for messageId in messageIDs:
				message = zap.core.message(messageId)
				if message == "Does Not Exist": continue
				requestHeader = message["requestHeader"].split(" ")
				requestedURL = requestHeader[1]

				responseHeader = message["responseHeader"] 

				responseStatusCode = responseHeader.split(" ")[1]
				if responseStatusCode[0] == "3":
					locationHeader = "Location: " 
					locationHeaderIdx = responseHeader.find(locationHeader)
					if locationHeaderIdx != -1:
						part = responseHeader[locationHeaderIdx+len(locationHeader): ]
						endIdx = part.find("\r\n")
						redirectURL = part[:endIdx]
						# check if redirectURL is of pattern website.public-suffic-list
						if ExcludeOutOfContextRegex.match(redirectURL):
							redirectionURLs.append(requestedURL)

			save_file_name = "redirection-urls-{0}.txt".format(authAccount)
			save_urls_to_file(siteId, redirectionURLs, filename=save_file_name)

			combinedURLs = list(set(redirectionURLs+ IntentedURLs + trafficURLs))
			save_file_name = "urls-{0}.txt".format(authAccount)
			save_urls_to_file(siteId, combinedURLs, filename=save_file_name)
			driver.close()
			return combinedURLs
		else: 
			driver.close()

		

# Steps:
# 1. Run the selenium script for user account 1 
# 2. Run the spider with the session of user 1
# 3. Collect URLs from 1 and 2
# 4. Run the selenium script for user account 2
# 5. Run the spider the session of user 2
# 6. Collect URLs from 4 and 5
# 7. Remove duplicates from the URLs collected in step 3 and 6
def main_new_policy_exhaustive_crawling(siteId, spider_duration_mins=5, ajax_duration_mins=1, Local=False, IP=False, CrawlFlag=True):
	firstAccountURLs = new_policy_exhaustive_crawling(authAccount="2", spider_duration_mins=spider_duration_mins, ajax_duration_mins=ajax_duration_mins, Local=Local, IP=IP, CrawlFlag=CrawlFlag)
	secondAccountURLs = new_policy_exhaustive_crawling(authAccount="1",spider_duration_mins=spider_duration_mins, ajax_duration_mins=ajax_duration_mins, Local=Local, IP=IP, CrawlFlag=CrawlFlag)
	combinedURLs = list(set(firstAccountURLs + secondAccountURLs))
	save_file_name = "urls.txt"
	save_urls_to_file(siteId, combinedURLs, filename=save_file_name)
	return combinedURLs

# --------------------------------------------------------------------------- #
#			Crawling: fetch URLs by an initial run
# --------------------------------------------------------------------------- #

def init_run(err_log_fp, refresh = False):

	zap = ZAPv2(apikey=ZAP_API_KEY)
	zap.core.new_session(apikey=ZAP_API_KEY)
	driver = get_new_browser_driver(BROWSER)

	# init psl 
	cache_dir = os.path.join(BASE_DIR, "cache/")
	psl = public_suffix_list(http=httplib2.Http(cache_dir), headers={'cache-control': 'max-age=%d' % (90000000*60*24)})


	for siteId, siteSpec in site_dict.items():

		site_url = siteSpec[0]
		domain_base = siteSpec[1]
		terminate = urls_for_site_exists(siteId)

		if terminate and (not refresh):
			print "[INIT-RUN] urls for %s:%s already exists -> Proceeding to Main Run"%(siteId, site_url)
			continue

		first_phase = terminate
		
		if siteId == "27":
			driver.set_page_load_timeout(20)	#QUICK FIX for yandex.ru un-responsive pages


		site_filter_regex= get_regex(domain_base)

		creds = __import__("%s.Scripts.loginNlogout"%siteId, fromlist=["login", "logout"])

		print "[MainThread] First-Time-Logging In: %s"%site_url
		try:
			creds.login(driver, site_url, first_phase = first_phase)
		except:
			write_login_error_entry(err_log_fp, siteId, site_url)
			continue
		print "[MainThread] First-Time-Logged In: %s"%site_url

		print "[MainThread] Fetching URLS..."
		crawled_endpoints = get_urls_for_site(siteId, zap, psl, site_url, site_filter_regex, domain_base)

		if site_url not in crawled_endpoints:
				crawled_endpoints = [site_url] + crawled_endpoints

		print "[MainThread] Fetched %s urls"%len(crawled_endpoints)
		save_urls_to_file(siteId, crawled_endpoints)
		time.sleep(5)

	driver.close()

# --------------------------------------------------------------------------- #
#			      Post Message Attack
# --------------------------------------------------------------------------- #

def get_post_message_attack_url(siteId, stateLabel,  opentype, runHashId, url):
	target = encodeURL(url)
	return TEST_SERVER_BASE + '/getAttackPage/{0}/{1}/{2}/?hash={3}&fr={4}'.format(siteId, stateLabel, opentype, runHashId, target)

def get_post_message_export_csv_url(siteId, opentype, runHashId, stateLabels):
	states = ",".join(stateLabels)
	return LOG_SERVER_BASE + "/post-message-export-csv/{0}/{1}/?hash={2}&states={3}".format(siteId, opentype, runHashId, states)

def postMessageRun(err_log_fp, opentype, runHashId):

	# attack opentype = 0 for frame, 1 for window
	# -- BEGIN PRIMARY CONFIG -- #
	zap = ZAPv2(apikey=ZAP_API_KEY)
	zap.core.new_session(apikey=ZAP_API_KEY)
	psl_cache_dir = os.path.join(BASE_DIR, "cache/")
	psl = public_suffix_list(http=httplib2.Http(psl_cache_dir), headers={'cache-control': 'max-age=%d' % (90000000*60*24)})
	# -- END PRIMARY CONFIG -- #

	# time before opening another URL for testing
	delay_seconds = 22
	for siteId, siteSpec in site_dict.items():

		if siteId in LOG_ERR_KEYS:
			continue

		# The first phase is the initial URL crawling phase
		# first_phase_completed flag is true if its not the URL crawling phase
		first_phase_completed = urls_for_site_exists(siteId) 
		site_url = siteSpec[0]
		domain_base = siteSpec[1]
		site_filter_regex= get_regex(domain_base)

		stateModule = __import__("%s.Scripts.%s"%(siteId, STATES_SCRIPT_FILE), fromlist=["states"])
		states = stateModule.states
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
			# set driver timeout for sites
			if siteId == "27":
				#QUICK FIX for yandex.ru un-responsive pages
				driver.set_page_load_timeout(20)	
			print "[MainThread] Executing state function '%s' for siteURL='%s'"%(stateLabel, site_url)
			try:
				driver = stateFunctionPtr(driver, site_url, first_phase= first_phase_completed)
			except:
				error_message = write_state_error_entry(err_log_fp, siteId, site_url, stateLabel)
				print error_message
				continue
			print "[MainThread] Successfully Executed state function '%s' for siteURL='%s'"%(stateLabel, site_url) 

			# Step 2: read previously crawled URLs
			print "[MainThread] Reading URLS..."
			crawled_endpoints = get_urls_for_site(siteId, zap, psl, site_url, site_filter_regex, domain_base)
			print "[MainThread] Found %s urls"%len(crawled_endpoints)

			# step 3: test every url at every state
			time.sleep(1)
			for aURL in crawled_endpoints:
				print "[MainThread-LoggedIn] Testing resource: %s"%aURL
				attackURL = get_post_message_attack_url(siteId, stateLabel, opentype, runHashId, aURL)
				try:
					driver.get(attackURL)
				except:
					pass
				time.sleep(delay_seconds)

			driver.close()
		# step 4: export DB as CSV file 
		time.sleep(1)
		driver = get_new_browser_driver(BROWSER)
		time.sleep(1)
		stateLabels = [state["label"] for state in states]
		exportURL = get_post_message_export_csv_url(siteId, opentype, runHashId, stateLabels)
		try:
			driver.get(exportURL)
			time.sleep(30)
			driver.close()
		except:
			write_csv_export_error_entry(err_log_fp, siteId, site_url, 'post-message', runHashId)

	print "[MainThread-Finished] PostMessage Run Finished..."

def main_post_message_attack(number_of_runs=1):
	# each_test_number_of_runs = 3
	each_test_number_of_runs = 1
	err_log_fp = create_error_log_fp('post-message')
	# init_run(err_log_fp, refresh = False)

	for r in range(number_of_runs):
		for runIdx in range(each_test_number_of_runs):
			runHashId = generate_uuid()
			postMessageRun(err_log_fp, FRAME_OPEN_TYPE, runHashId)

	for r in range(number_of_runs):
		for runIdx in range(each_test_number_of_runs):
			runHashId = generate_uuid()
			postMessageRun(err_log_fp, WINDOW_OPEN_TYPE, runHashId)


# --------------------------------------------------------------------------- #
#			   Content Window Attack
# --------------------------------------------------------------------------- #

# @DEPRECATED v.memory.1.0, no longer in use
def _get_restart_mem_content_window():
	return LOG_SERVER_BASE + "/clear-cw-memory/"

# @DEPRECATED v.memory.1.0, replaced by _get_content_window_export_csv_url in v.db.1.0
def _get_content_window_export_mem_url(siteId):
	return LOG_SERVER_BASE + "/export-content-window/%s/"%siteId

# @NEW v.db.1.0
def _get_content_window_export_csv_url(siteId, stateLabels, runHashId):
	states = ",".join(stateLabels)
	return LOG_SERVER_BASE + "/export-csv-content-window/%s/?hash=%s&states=%s"%(siteId, runHashId, states)

def _get_attack_url_content_window_length(siteId, state_status, target_url, runHashId):
	target = encodeURL(target_url)
	return TEST_SERVER_BASE + "/attack-page/content-window/%s/%s/?fr=%s&hash=%s"%(siteId, state_status, target, runHashId)


def run_content_window_attack(err_log_fp, runHashId):

	# -- BEGIN PRIMARY CONFIG -- #
	zap = ZAPv2(apikey=ZAP_API_KEY)
	zap.core.new_session(apikey=ZAP_API_KEY)
	psl_cache_dir = os.path.join(BASE_DIR, "cache/")
	psl = public_suffix_list(http=httplib2.Http(psl_cache_dir), headers={'cache-control': 'max-age=%d' % (90000000*60*24)})
	# -- END PRIMARY CONFIG -- #

	# time before opening another URL for testing
	# need a min of 12 sec for sending results (see testserver js) 
	delay_seconds = 22
	for siteId, siteSpec in site_dict.items():

		if siteId in LOG_ERR_KEYS:
			continue

		# The first phase is the initial URL crawling phase
		# first_phase_completed flag is true if its not the URL crawling phase
		first_phase_completed = urls_for_site_exists(siteId) 
		site_url = siteSpec[0]
		domain_base = siteSpec[1]
		site_filter_regex= get_regex(domain_base)

		stateModule = __import__("%s.Scripts.%s"%(siteId, STATES_SCRIPT_FILE), fromlist=["states"])
		states = stateModule.states
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
			# set driver timeout for sites
			if siteId == "27":
				#QUICK FIX for yandex.ru un-responsive pages
				driver.set_page_load_timeout(20)	
			print "[MainThread] Executing state function '%s' for siteURL='%s'"%(stateLabel, site_url)
			try:
				driver = stateFunctionPtr(driver, site_url, first_phase= first_phase_completed)
			except:
				error_message = write_state_error_entry(err_log_fp, siteId, site_url, stateLabel)
				print error_message
				continue
			print "[MainThread] Successfully Executed state function '%s' for siteURL='%s'"%(stateLabel, site_url) 

			# Step 2: read previously crawled URLs
			print "[MainThread] Reading URLS..."
			crawled_endpoints = get_urls_for_site(siteId, zap, psl, site_url, site_filter_regex, domain_base)
			print "[MainThread] Found %s urls"%len(crawled_endpoints)

			# step 3: test every url at every state
			time.sleep(1)
			for aURL in crawled_endpoints:
				print "[MainThread-LoggedIn] Testing resource: %s"%aURL
				attackURL = _get_attack_url_content_window_length(siteId, stateLabel, aURL, runHashId)
				try:
					driver.get(attackURL)
				except:
					pass
				time.sleep(delay_seconds)

			driver.close()
			time.sleep(1)
		# step 4: export DB as CSV file 
		time.sleep(1)
		driver = get_new_browser_driver(BROWSER)
		time.sleep(2)
		stateLabels = [state["label"] for state in states]
		try:
			driver.get(_get_content_window_export_csv_url(siteId, stateLabels, runHashId))
		except:
			driver = get_new_browser_driver(BROWSER)
			driver.get(_get_content_window_export_csv_url(siteId, stateLabels, runHashId))
		time.sleep(delay_seconds)


def main_content_window_attack(number_of_runs = 1):
	err_log_fp = create_error_log_fp('content-window')
	# init_run(err_log_fp, refresh = False)
	for runIdx in range(number_of_runs):
		for i in range(1):
			runHashId = generate_uuid()
			run_content_window_attack(err_log_fp, runHashId)

# --------------------------------------------------------------------------- #
#			  Script Inclusion Attack
# --------------------------------------------------------------------------- #

def _get_attack_url_script_inclusion_vars(siteId, state_status, target_url, runHashId):
	target = encodeURL(target_url)
	returnURL= TEST_SERVER_BASE + '/attack-page/script-vars/%s/%s/?hash=%s&fr=%s'%(siteId, state_status, runHashId, target)
	return returnURL

def _get_attack_url_script_inclusion_errs(siteId, state_status, target_url, runHashId):
	target = encodeURL(target_url)
	returnURL= TEST_SERVER_BASE + '/attack-page/script-errs/%s/%s/?hash=%s&fr=%s'%(siteId, state_status, runHashId, target)
	return returnURL
# @param mode_of_run 0 for script variables, 1 for script inclusion
def _get_script_attack_export_csv_url(siteId, stateLabels, mode_of_run, runHashId):
	states = ",".join(stateLabels)
	if mode_of_run == MODE_SCRIPT_INCLUSION_VARS:
		return LOG_SERVER_BASE + "/script-inclusion-export-csv/%s/%s/?hash=%s&states=%s"%(siteId, mode_of_run, runHashId, states) 
	else:
		return LOG_SERVER_BASE + "/script-errors-export-csv/%s/%s/?hash=%s&states=%s"%(siteId, mode_of_run, runHashId, states) 

# @DELETED FUNCTIONALITY
# @param login_status: 0 for logged out - 1 for loggged in
def _get_analysis_url_script_inclusion_vars(siteId):
	return TEST_SERVER_BASE + '/script-inclusion/vars/analyze/%s/'%(siteId)

# @DELETED FUNCTIONALITY
def _get_analysis_url_script_inclusion_errs(siteId):
	return TEST_SERVER_BASE + '/script-inclusion/errs/analyze/%s/'%(siteId)

# @DELETED FUNCTIONALITY
def _get_restart_mem_url_script_inclusion():
	return LOG_SERVER_BASE + '/setup-script-attack/'

# mode_of_run = 0 for variable collection, mode_of_run = 1 for err collection 
def run_script_inclusion_attack(err_log_fp, runHashId, mode_of_run):

# -- BEGIN PRIMARY CONFIG -- #
	zap = ZAPv2(apikey=ZAP_API_KEY)
	zap.core.new_session(apikey=ZAP_API_KEY)
	psl_cache_dir = os.path.join(BASE_DIR, "cache/")
	psl = public_suffix_list(http=httplib2.Http(psl_cache_dir), headers={'cache-control': 'max-age=%d' % (90000000*60*24)})
	# -- END PRIMARY CONFIG -- #

	# time before opening another URL for testing
	delay_seconds = 12
	for siteId, siteSpec in site_dict.items():

		if siteId in LOG_ERR_KEYS:
			continue

		# The first phase is the initial URL crawling phase
		# first_phase_completed flag is true if its not the URL crawling phase
		first_phase_completed = urls_for_site_exists(siteId) 
		site_url = siteSpec[0]
		domain_base = siteSpec[1]
		site_filter_regex= get_regex(domain_base)

		stateModule = __import__("%s.Scripts.%s"%(siteId, STATES_SCRIPT_FILE), fromlist=["states"])
		states = stateModule.states
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
			# set driver timeout for sites
			if siteId == "27":
				#QUICK FIX for yandex.ru un-responsive pages
				driver.set_page_load_timeout(20)	
			print "[MainThread] Executing state function '%s' for siteURL='%s'"%(stateLabel, site_url)
			try:
				driver = stateFunctionPtr(driver, site_url, first_phase= first_phase_completed)
			except:
				error_message = write_state_error_entry(err_log_fp, siteId, site_url, stateLabel)
				print error_message
				continue
			print "[MainThread] Successfully Executed state function '%s' for siteURL='%s'"%(stateLabel, site_url) 

			# Step 2: read previously crawled URLs
			print "[MainThread] Reading URLS..."
			crawled_endpoints = get_urls_for_site(siteId, zap, psl, site_url, site_filter_regex, domain_base)
			print "[MainThread] Found %s urls"%len(crawled_endpoints)

		# 	step 3: test every url at every state
			time.sleep(1)
			for aURL in crawled_endpoints:
				print "[MainThread-LoggedIn] Testing resource: %s"%aURL
				if mode_of_run == MODE_SCRIPT_INCLUSION_VARS:
					attackURL = _get_attack_url_script_inclusion_vars(siteId, stateLabel, aURL, runHashId)
				else:
					attackURL = _get_attack_url_script_inclusion_errs(siteId, stateLabel, aURL, runHashId)
				try:
					driver.get(attackURL)
				except:
					pass
				time.sleep(delay_seconds)
			driver.close()
			time.sleep(4)

		# step 4: export DB as CSV file 
		time.sleep(1)
		driver = get_new_browser_driver(BROWSER, generate_config_file = False)
		stateLabels = [state["label"] for state in states]
		try:
			driver.get(_get_script_attack_export_csv_url(siteId, stateLabels, mode_of_run, runHashId))
		except:
			driver = get_new_browser_driver(BROWSER)
			driver.get(_get_script_attack_export_csv_url(siteId, stateLabels, mode_of_run, runHashId))
		time.sleep(delay_seconds)
		driver.close()


def main_script_inclusion_attack_vars(number_of_runs = 1):
	err_log_fp = create_error_log_fp('script-vars')
	# init_run(err_log_fp, refresh = False)
	for runIdx in range(number_of_runs):
		runHashId = generate_uuid()
		run_script_inclusion_attack(err_log_fp, runHashId, MODE_SCRIPT_INCLUSION_VARS)

def main_script_inclusion_attack_errs(number_of_runs = 1):
	err_log_fp = create_error_log_fp('script-errs')
	# init_run(err_log_fp, refresh = False)
	for runIdx in range(number_of_runs):
		runHashId = generate_uuid()
		run_script_inclusion_attack(err_log_fp, runHashId, MODE_SCRIPT_INCLUSION_ERRS)



# --------------------------------------------------------------------------- #
#			  	EventFireCounting Attack + Object Properties
# --------------------------------------------------------------------------- #



def _get_attack_url_event_fire_count(siteId, state_status, target_url, events, tag_name, runHashId):
	target = encodeURL(target_url)
	return TEST_SERVER_BASE + "/attack-page/event-count/%s/%s/?fr=%s&events=%s&tag=%s&hash=%s"%(siteId, state_status, target, events, tag_name, runHashId)

def _get_event_count_export_csv_from_db(siteId, stateLabels, events, tag_name, runHashId):
	states = ",".join(stateLabels)
	return LOG_SERVER_BASE + "/event-fire-count-export-csv/%s/?events=%s&tag=%s&hash=%s&states=%s"%(siteId, events, tag_name, runHashId, states) 

def _get_read_obj_props_export_csv_from_db(siteId, stateLabels, tag_name, runHashId):
	states = ",".join(stateLabels)
	return LOG_SERVER_BASE + "/object-props-export-csv/%s/?tag=%s&hash=%s&states=%s"%(siteId, tag_name, runHashId, states) 


def run_event_fire_count_attack(err_log_fp, event_list, tag_list, runHashId):

	# -- BEGIN PRIMARY CONFIG -- #
	zap = ZAPv2(apikey=ZAP_API_KEY)
	zap.core.new_session(apikey=ZAP_API_KEY)
	psl_cache_dir = os.path.join(BASE_DIR, "cache/")
	psl = public_suffix_list(http=httplib2.Http(psl_cache_dir), headers={'cache-control': 'max-age=%d' % (90000000*60*24)})
	# -- END PRIMARY CONFIG -- #

	# time before opening another URL for testing
	delay_seconds = 11
	for siteId, siteSpec in site_dict.items():

		if siteId in LOG_ERR_KEYS:
			continue

		# The first phase is the initial URL crawling phase
		# first_phase_completed flag is true if its not the URL crawling phase
		first_phase_completed = urls_for_site_exists(siteId) 
		site_url = siteSpec[0]
		domain_base = siteSpec[1]
		site_filter_regex= get_regex(domain_base)

		stateModule = __import__("%s.Scripts.%s"%(siteId, STATES_SCRIPT_FILE), fromlist=["states"])
		states = stateModule.states
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
			# set driver timeout for sites
			if siteId == "27":
				#QUICK FIX for yandex.ru un-responsive pages
				driver.set_page_load_timeout(20)	
			print "[MainThread] Executing state function '%s' for siteURL='%s'"%(stateLabel, site_url)
			try:
				driver = stateFunctionPtr(driver, site_url, first_phase= first_phase_completed)
			except:
				error_message = write_state_error_entry(err_log_fp, siteId, site_url, stateLabel)
				print error_message
				continue
			print "[MainThread] Successfully Executed state function '%s' for siteURL='%s'"%(stateLabel, site_url) 

			# Step 2: read previously crawled URLs
			print "[MainThread] Reading URLS..."
			crawled_endpoints = get_urls_for_site(siteId, zap, psl, site_url, site_filter_regex, domain_base)
			print "[MainThread] Found %s urls"%len(crawled_endpoints)
			

			# Step 3: test each url at the current state
			events = "-".join(event_list)
			time.sleep(1)
			MAX_PAGE_TIMEOUT = 60
			driver.set_page_load_timeout(MAX_PAGE_TIMEOUT)
			for tag_name in tag_list:
				for aURL in crawled_endpoints:
					print "[MainThread-%s] Testing resource: %s"%(stateLabel, aURL)
					attackURL = _get_attack_url_event_fire_count(siteId, stateLabel, aURL, events, tag_name, runHashId)
					try:
						driver.get(attackURL)
					except:
						pass
					time.sleep(delay_seconds)

			driver.close()
			time.sleep(2)
		# step 4: export csv result from DB
		time.sleep(1)
		driver = get_new_browser_driver(BROWSER)
		time.sleep(4)
		stateLabels = [state["label"] for state in states]
		for tag_name in tag_list:
			exportURL = _get_event_count_export_csv_from_db(siteId, stateLabels, events, tag_name, runHashId)
			propsExportURL = _get_read_obj_props_export_csv_from_db(siteId, stateLabels, tag_name, runHashId)
			try:
				driver.get(exportURL)
				time.sleep(10)
				driver.get(propsExportURL)
			except:
				driver = get_new_browser_driver(BROWSER)
				driver.get(exportURL)
				time.sleep(10)
				driver.get(propsExportURL)
			time.sleep(20)
		time.sleep(1)


def main_event_fire_count_attack(number_of_runs = 1):
	err_log_fp = create_error_log_fp('event-fire-count')
	# init_run(err_log_fp, refresh = False)
	event_list = ['onload', 'onerror', 'onprogress', 'onabort', 'onchange', 'onscroll', 'onunload', 'hashchange' ,'onwaiting', 'onloadstart','onafterprint', 'onbeforeunload', 'oncanplay', 'oncanplaythrough', 'ondurationchange' , 'oncontextmenu', 'onended', 'onloadeddata', 'onloadedmetadata', 'oninvalid', 'onsuspend']
	tag_list = ["embed", "img", "link_stylesheet", "link_prefetch", "link_preload_style", "link_preload_script", "script", "iframe", "object", "track", "audio", "video", "source", "videoPoster"]
	
	for runIdx in range(number_of_runs):
			runHashId = generate_uuid()
			run_event_fire_count_attack(err_log_fp, event_list, tag_list, runHashId)


# --------------------------------------------------------------------------- #
#			  	Content Security Policy Attack
# --------------------------------------------------------------------------- #

def get_csp_attack_page(site_id, state_status, hash_id, tag_name, target_url):
	target = encodeURL(target_url.replace(",", "COMMACOMMA").replace("%2C", "COMMACOMMA"))
	attack_page_url = TEST_SERVER_BASE + "/attack-page/csp/%s/%s/?hash=%s&tag=%s&fr=%s"%(site_id, state_status, hash_id, tag_name, target )
	return attack_page_url

def _get_csp_export_csv_from_db(siteId, stateLabels, tag_name, runHashId):
	states = ",".join(stateLabels)
	return LOG_SERVER_BASE + "/csp-export-csv/%s/?tag=%s&hash=%s&states=%s"%(siteId, tag_name, runHashId, states) 

def run_csp_attack(err_log_fp, tag_list, runHashId):

	# -- BEGIN PRIMARY CONFIG -- #
	zap = ZAPv2(apikey=ZAP_API_KEY)
	zap.core.new_session(apikey=ZAP_API_KEY)
	psl_cache_dir = os.path.join(BASE_DIR, "cache/")
	psl = public_suffix_list(http=httplib2.Http(psl_cache_dir), headers={'cache-control': 'max-age=%d' % (90000000*60*24)})
	# -- END PRIMARY CONFIG -- #

	# time before opening another URL for testing
	delay_seconds = 11
	for siteId, siteSpec in site_dict.items():

		if siteId in LOG_ERR_KEYS:
			continue

		first_phase_completed = urls_for_site_exists(siteId) 
		site_url = siteSpec[0]
		domain_base = siteSpec[1]
		site_filter_regex= get_regex(domain_base)

		stateModule = __import__("%s.Scripts.%s"%(siteId, STATES_SCRIPT_FILE), fromlist=["states"])
		states = stateModule.states
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
			# set driver timeout for sites
			if siteId == "27":
				driver.set_page_load_timeout(20)	
			print "[MainThread] Executing state function '%s' for siteURL='%s'"%(stateLabel, site_url)
			try:
				driver = stateFunctionPtr(driver, site_url, first_phase= first_phase_completed)
			except:
				error_message = write_state_error_entry(err_log_fp, siteId, site_url, stateLabel)
				print error_message
				continue
			print "[MainThread] Successfully Executed state function '%s' for siteURL='%s'"%(stateLabel, site_url) 

			# Step 2: read previously crawled URLs
			print "[MainThread] Reading URLS..."
			crawled_endpoints = get_urls_for_site(siteId, zap, psl, site_url, site_filter_regex, domain_base)
			print "[MainThread] Found %s urls"%len(crawled_endpoints)
			

			# Step 3: test each url at the current state
			time.sleep(1)
			for tag_name in tag_list:
				for aURL in crawled_endpoints:
					print "[MainThread-%s] Testing resource: %s"%(stateLabel, aURL)
					attackURL = get_csp_attack_page(siteId, stateLabel, runHashId, tag_name, aURL)
					try:
						driver.get(attackURL)
					except:
						pass
					time.sleep(delay_seconds)

			driver.close()
			time.sleep(4)
		# step 4: export csv result from DB
		time.sleep(1)
		driver = get_new_browser_driver(BROWSER)
		time.sleep(2)
		stateLabels = [state["label"] for state in states]
		for tag_name in tag_list:
			exportURL = _get_csp_export_csv_from_db(siteId, stateLabels, tag_name, runHashId)
			try:
				driver.get(exportURL)
			except:
				driver = get_new_browser_driver(BROWSER)
				driver.get(exportURL)
			time.sleep(20)
		time.sleep(1)

def main_run_csp_attack(number_of_runs= 1):
	err_log_fp = create_error_log_fp('csp')
	# init_run(err_log_fp, refresh = False)

	tag_list = ['iframe', 'script', 'img', 'object', 'embed', 'link', 'audio', 'video', 'applet']
	for runIdx in range(number_of_runs):
		runHashId = generate_uuid()
		run_csp_attack(err_log_fp, tag_list, runHashId)


# --------------------------------------------------------------------------- #
#			  	Analyze Redirect Chains/ Payload Chains
# --------------------------------------------------------------------------- #

def get_traffic_messages(targetURL, zap):
	if targetURL == '':
		return [['', '', '', '', ''], ['', '', '','', '','', '']]
	msgs = zap.core.messages(baseurl=targetURL)
	if len(msgs) >0:
		targetMessage = msgs[0]
	else:
		return [[targetURL, '200','', '',''], [targetURL, '200','', '','', '']]

	responseBody = targetMessage['responseBody'] 
	responseBodyMD5 =  get_md5_hash_digest(u"%s"%responseBody)
	responseHeader = targetMessage['responseHeader']
	headersList = responseHeader.split("\r\n")

	httpStatusHeader= ''
	for httpHeader in headersList:
		if "HTTP/1." in httpHeader:
			httpStatusHeader = httpHeader
			break
	httpStatus= httpStatusHeader.split(" ")[1]
	locationHeaderURL=''
	if httpStatus.startswith('3'):
		for header in headersList:
			locationIndex = header.find("Location:")
			if locationIndex == -1:
				continue
			else:
				locationHeader = header.split(" ")
				locationHeaderURL = locationHeader[1]
				if locationHeaderURL.startswith("/"):
					extraPartOfURLIndex = find_nth(targetURL, "/", 3)
					baseURL = targetURL[:extraPartOfURLIndex]
					locationHeaderURL= baseURL + locationHeaderURL
				break
	res = [targetURL, httpStatus, locationHeaderURL, headersList[1:], responseBodyMD5, responseBody]
	return [res[:5], res]

def get_message_chain(targetURL, driver, zap):
	driver.get(targetURL)
	time.sleep(10)
	returnResults = []
	url = targetURL
	while url != '':
		messages = get_traffic_messages(url, zap)
		returnResults.append(messages)
		try:
			if isinstance(messages[0], list):
				url=messages[0][2]
				url = url.strip()
			else:
				url=''
		except:
			url = ''
	if len(returnResults) == 0:
		res = [[targetURL, '200','', '',''], [targetURL, '200','', '','', '']]
		returnResults.append(res)

	res = [item[0] for item in returnResults]
	resPayload = [item[1] for item in returnResults]
	return [res, resPayload]


def main_read_redirect_chains():

	# -- BEGIN PRIMARY CONFIG -- #
	zap = ZAPv2(apikey=ZAP_API_KEY)
	psl_cache_dir = os.path.join(BASE_DIR, "cache/")
	psl = public_suffix_list(http=httplib2.Http(psl_cache_dir), headers={'cache-control': 'max-age=%d' % (90000000*60*24)})
	# -- END PRIMARY CONFIG -- #

	for siteId, siteSpec in site_dict.items():

		if siteId in LOG_ERR_KEYS:
			continue

		# The first phase is the initial URL crawling phase
		# first_phase_completed flag is true if its not the URL crawling phase
		first_phase_completed = urls_for_site_exists(siteId) 
		site_url = siteSpec[0]
		domain_base = siteSpec[1]
		site_filter_regex= get_regex(domain_base)

		# step 0: prepare outfile for saving results
		outfiledir_name = "%s/urls/redirectChains/%s"%(siteId, STATES_SCRIPT_FILE)
		outfiledir = get_or_create_directory(outfiledir_name)

		timestamp = get_current_datetime()
		filename = "%s-%s.csv"%(STATES_SCRIPT_FILE, timestamp)
		filename_payload = "%s-%s-payload.csv"%(STATES_SCRIPT_FILE, timestamp)

		outFilePathName = os.path.join(outfiledir, filename)
		outFilePathNamePayload = os.path.join(outfiledir, filename_payload)
		outResults = {} # {'stateLabel': {'url': results }}
		outResultsPayload = {}
		stateNames = []

		stateModule = __import__("%s.Scripts.%s"%(siteId, STATES_SCRIPT_FILE), fromlist=["states"])
		states = stateModule.states
		stateCount = len(states)
		for stateIdx in range(stateCount):
			state = states[stateIdx]
			stateFunctionPtr = state["function"]
			stateLabel = state["label"]
			stateNames.append(stateLabel)

			# Step 1: execute each state function
			if stateIdx == 0:
				log_browser_config = True
			else:
				log_browser_config = False

			# obtain new zap session for each state
			zap.core.new_session(apikey=ZAP_API_KEY)
			driver = get_new_browser_driver(BROWSER, generate_config_file = log_browser_config)	
			time.sleep(1)
			print "[MainThread] Executing state function '%s' for siteURL='%s'"%(stateLabel, site_url)
			try:
				driver = stateFunctionPtr(driver, site_url, first_phase= first_phase_completed)
			except:
				error_message = write_state_error_entry(err_log_fp, siteId, site_url, stateLabel)
				print error_message
				continue
			print "[MainThread] Successfully Executed state function '%s' for siteURL='%s'"%(stateLabel, site_url) 

			# Step 2: read previously crawled URLs
			print "[MainThread] Reading URLS..."
			crawled_endpoints = get_urls_for_site(siteId, zap, psl, site_url, site_filter_regex, domain_base)
			print "[MainThread] Found %s urls"%len(crawled_endpoints)
			
			# Step 3: test each url at the current state
			time.sleep(1)
			for aURL in crawled_endpoints:
				url = aURL.strip().rstrip("\n")

				print "[MainThread-%s] Testing resource: %s"%(stateLabel, url)
				trafficResults = get_message_chain(url, driver, zap)
				if stateLabel not in outResults:
					outResults[stateLabel] = {}
				if stateLabel not in outResultsPayload:
					outResultsPayload[stateLabel]= {}
				outResults[stateLabel][url] = trafficResults[0]
				outResultsPayload[stateLabel][url] = trafficResults[1]
				time.sleep(1)

		fp= open(outFilePathName, "wb")
		fp_payload = open(outFilePathNamePayload, "wb")
		fp.write("URL, ")
		fp_payload.write("URL, ")
		for i in range(stateCount):
			stateName = stateNames[i]
			if i == stateCount-1:
				fp.write("%s\n"%stateName)
				fp_payload.write("%s\n"%stateName)
			else:
				fp.write("%s, "%stateName)
				fp_payload.write("%s, "%stateName)

		for aURL in crawled_endpoints:
			url = aURL.strip()
			fp.write("%s, "%(url))
			fp_payload.write("%s, "%(url))
			for i in range(stateCount):
				stateName = stateNames[i]
				res = outResults[stateName][url]
				resPayload = outResultsPayload[stateName][url]
				if i == stateCount-1:
					fp_payload.write("%s\n"%resPayload)
					fp.write("%s\n"%res)
				else:
					fp.write("%s, "%res)
					fp_payload.write("%s, "%resPayload)
		fp.close()
		fp_payload.close()


		#save in new summary format as well
		mfilename = "%s-%s-summary.out"%(STATES_SCRIPT_FILE, timestamp)
		moutFilePathName = os.path.join(outfiledir, mfilename)
		fp= open(moutFilePathName, "wb")
		for aURL in crawled_endpoints:
			url = aURL.strip()
			fp.write("===================================================================\n")
			fp.write("States Involved: {0}\nURL: {1}\nInformation Summary:\n---------------------------------------------\n".format(stateNames, url))
			for i in range(stateCount):
				stateName = stateNames[i]
				res = outResults[stateName][url]
				resPayload = outResultsPayload[stateName][url]

				response_code_chain_i = [listItem[1] for listItem in resPayload]
				fp.write("({0}) Response_Code_Chain: {1}\n".format(stateName, response_code_chain_i))
			fp.write("---------------------------------------------\n")
			for i in range(stateCount):
				stateName = stateNames[i]
				res = outResults[stateName][url]
				resPayload = outResultsPayload[stateName][url]

				response_url_chain_i = [listItem[0] for listItem in resPayload]
				fp.write("({0}) Response_URL_Chain: {1}\n".format(stateName, response_url_chain_i))
			fp.write("---------------------------------------------\n")
			for i in range(stateCount):
				stateName = stateNames[i]
				res = outResults[stateName][url]
				resPayload = outResultsPayload[stateName][url]

				response_header_chain_i = [listItem[3] for listItem in resPayload]
				fp.write("({0}) Response_Header_Chain: {1}\n".format(stateName, response_header_chain_i))
			fp.write("---------------------------------------------\n")
			for i in range(stateCount):
				stateName = stateNames[i]
				res = outResults[stateName][url]
				resPayload = outResultsPayload[stateName][url]

				response_body_hash_chain_i = [listItem[4] for listItem in resPayload]
				fp.write("({0}) Response_Body_Chain: {1}\n".format(stateName, response_body_hash_chain_i))
			fp.write("\n")
			fp.write("===================================================================\n")

# --------------------------------------------------------------------------- #
#				End Redirect Chain
# --------------------------------------------------------------------------- #

# --------------------------------------------------------------------------- #
#				Timing Analysis (TA)
# --------------------------------------------------------------------------- #

def _get_attack_url_ta(siteId, state_status, target_url, tag_name, runHashId):
	target = encodeURL(target_url)
	return TEST_SERVER_BASE + "/attack-page/timing-analysis/%s/%s/?fr=%s&tag=%s&hash=%s"%(siteId, state_status, target, tag_name, runHashId)

def _get_ta_export_csv_from_db(siteId, stateLabels, tag_name, runHashId):
	states = ",".join(stateLabels)
	return LOG_SERVER_BASE + "/timing-analysis-export-csv/%s/?tag=%s&hash=%s&states=%s"%(siteId, tag_name, runHashId, states) 

def run_timing_analysis_attack(err_log_fp, tag_list, runHashId):

	# -- BEGIN PRIMARY CONFIG -- #
	zap = ZAPv2(apikey=ZAP_API_KEY)
	zap.core.new_session(apikey=ZAP_API_KEY)
	psl_cache_dir = os.path.join(BASE_DIR, "cache/")
	psl = public_suffix_list(http=httplib2.Http(psl_cache_dir), headers={'cache-control': 'max-age=%d' % (90000000*60*24)})
	# -- END PRIMARY CONFIG -- #

	# time before opening another URL for testing
	delay_seconds = 11
	for siteId, siteSpec in site_dict.items():

		if siteId in LOG_ERR_KEYS:
			continue

		# The first phase is the initial URL crawling phase
		# first_phase_completed flag is true if its not the URL crawling phase
		first_phase_completed = urls_for_site_exists(siteId) 
		site_url = siteSpec[0]
		domain_base = siteSpec[1]
		site_filter_regex= get_regex(domain_base)

		stateModule = __import__("%s.Scripts.%s"%(siteId, STATES_SCRIPT_FILE), fromlist=["states"])
		states = stateModule.states
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
			# set driver timeout for sites
			if siteId == "27":
				#QUICK FIX for yandex.ru un-responsive pages
				driver.set_page_load_timeout(20)	
			print "[MainThread] Executing state function '%s' for siteURL='%s'"%(stateLabel, site_url)
			try:
				driver = stateFunctionPtr(driver, site_url, first_phase= first_phase_completed)
			except:
				error_message = write_state_error_entry(err_log_fp, siteId, site_url, stateLabel)
				print error_message
				continue
			print "[MainThread] Successfully Executed state function '%s' for siteURL='%s'"%(stateLabel, site_url) 

			# Step 2: read previously crawled URLs
			print "[MainThread] Reading URLS..."
			crawled_endpoints = get_urls_for_site(siteId, zap, psl, site_url, site_filter_regex, domain_base)
			print "[MainThread] Found %s urls"%len(crawled_endpoints)
			

			# Step 3: test each url at the current state
			time.sleep(1)
			for tag_name in tag_list:
				for aURL in crawled_endpoints:
					print "[MainThread-%s] Testing resource: %s"%(stateLabel, aURL)
					attackURL = _get_attack_url_ta(siteId, stateLabel, aURL, tag_name, runHashId)
					try:
						driver.get(attackURL)
					except:
						pass
					time.sleep(delay_seconds)

			driver.close()
			time.sleep(2)
		# step 4: export csv result from DB
		time.sleep(1)
		driver = get_new_browser_driver(BROWSER)
		time.sleep(4)
		stateLabels = [state["label"] for state in states]
		for tag_name in tag_list:
			exportURL = _get_ta_export_csv_from_db(siteId, stateLabels, tag_name, runHashId)
			try:
				driver.get(exportURL)
			except:
				driver = get_new_browser_driver(BROWSER)
				driver.get(exportURL)
			time.sleep(20)
		time.sleep(1)


def main_ta_attack(number_of_runs = 1):
	err_log_fp = create_error_log_fp('timing-analysis')
	# init_run(err_log_fp, refresh = False)
	tag_list = ["img", "video", "audio", "script", "link"]
	for runIdx in range(number_of_runs):
			runHashId = generate_uuid()
			run_timing_analysis_attack(err_log_fp, tag_list, runHashId)

# --------------------------------------------------------------------------- #
#				End Timing Analysis (TA)
# --------------------------------------------------------------------------- #

# --------------------------------------------------------------------------- #
#				Start CSS Collection (CSSC)
# --------------------------------------------------------------------------- #

def run_css_rules_collection(err_log_fp, runHashId):

	# -- BEGIN PRIMARY CONFIG -- #
	zap = ZAPv2(apikey=ZAP_API_KEY)
	zap.core.new_session(apikey=ZAP_API_KEY)
	psl_cache_dir = os.path.join(BASE_DIR, "cache/")
	psl = public_suffix_list(http=httplib2.Http(psl_cache_dir), headers={'cache-control': 'max-age=%d' % (90000000*60*24)})
	# -- END PRIMARY CONFIG -- #

	# time before opening another URL for testing
	delay_seconds = 11
	for siteId, siteSpec in site_dict.items():

		if siteId in LOG_ERR_KEYS:
			continue

		# The first phase is the initial URL crawling phase
		# first_phase_completed flag is true if its not the URL crawling phase
		first_phase_completed = urls_for_site_exists(siteId) 
		site_url = siteSpec[0]
		domain_base = siteSpec[1]
		site_filter_regex= get_regex(domain_base)
		use_css_url_set = True  # use only specific set of URLs for this test, not all the URLs

		# setup output file 
		browserCapitalize = copy.deepcopy(BROWSER)
		browserCapitalize = browserCapitalize.capitalize()
		out_file_path_relative = os.path.join(os.path.join(str(siteId), "TestReports"), os.path.join("CSSRules", BROWSER))
		out_file_path_absoulte = get_or_create_directory(out_file_path_relative)
		timestamp = get_current_datetime()
		out_file_name = "css-rules.out"
		out_file_path_name = os.path.join(out_file_path_absoulte, out_file_name)

		with open(out_file_path_name, "a+") as fd:
			fd.write('-----------------------------------------------------------------------------\n')
			fd.write('[timestamp] generated on: %s\n'%timestamp)
			fd.write('[run-Id] hash:%s\n'%timestamp)
			fd.write('-----------------------------------------------------------------------------\n\n\n')

		stateModule = __import__("%s.Scripts.%s"%(siteId, STATES_SCRIPT_FILE), fromlist=["states"])
		states = stateModule.states
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
			# set driver timeout for sites
			if siteId == "27":
				#QUICK FIX for yandex.ru un-responsive pages
				driver.set_page_load_timeout(20)	
			print "[MainThread] Executing state function '%s' for siteURL='%s'"%(stateLabel, site_url)
			try:
				driver = stateFunctionPtr(driver, site_url, first_phase= first_phase_completed)
			except:
				error_message = write_state_error_entry(err_log_fp, siteId, site_url, stateLabel)
				print error_message
				continue
			print "[MainThread] Successfully Executed state function '%s' for siteURL='%s'"%(stateLabel, site_url) 

			# Step 2: read previously crawled URLs
			print "[MainThread] Reading URLS..."
			crawled_endpoints = get_urls_for_site(siteId, zap, psl, site_url, site_filter_regex, domain_base, use_css_url_set = use_css_url_set)
			print "[MainThread] Found %s urls"%len(crawled_endpoints)
			

			# Step 3: test each url at the current state
			time.sleep(1)
			for aURL in crawled_endpoints:
				print "[MainThread-%s] Testing resource: %s"%(stateLabel, aURL)
				driver.get(aURL)
				time.sleep(4)
				pageContent = driver.page_source
				fd = open(out_file_path_name, "a+")
				fd.write("==================================================================================\n")
				if aURL.endswith("\n"):
					fd.write("URL: %s"%aURL)
				else:
					fd.write("URL: %s\n"%aURL)
				fd.write("STATE: %s\n"%stateLabel)
				fd.write("==================================================================================\n")
				pageContent = u''.join(pageContent).encode('utf-8').strip()
				fd.write(pageContent+"\n")
				fd.close()
				time.sleep(1)
			driver.close()
			time.sleep(2)

def main_css_rules_attack(number_of_runs = 1):
	err_log_fp = create_error_log_fp('css-rules')
	for runIdx in range(number_of_runs):
		runHashId = generate_uuid()
		run_css_rules_collection(err_log_fp, runHashId)


def remove_digits_from_string(in_str):
	in_str = str(in_str)
	result = ''.join([i for i in in_str if not i.isdigit()])
	return result

def remove_digits_from_list_items(lst):  # must not remove css digit values?! only the line/col number of the error
	# results = []
	# for elm in lst:
	# 	results.append(remove_digits_from_string(elm))
	# return results
	results = []
	for elm in lst:
		priority = ' !' + elm.priority if elm.priority else ''
		cssCodeLine= "{0.name}: {1}{2}".format(elm, elm.value.as_css(),priority)
		results.append(cssCodeLine)
	return results

def get_rule_declaration_list(rule_set):
	"""
		returns a list of items like: css-selector {NEWLINE_CHARdeclaration1 ;NEWLINE_CHARdeclaration2 ;NEWLINE_CHAR}
	"""
	results = []
	for rule in rule_set:
		selectorString = rule.selector.as_css()
		cssItem = "%s {"%selectorString
		declarationsStringList = remove_digits_from_list_items(rule.declarations)
		for decElement in declarationsStringList:
			cssItem+="\n{0} ;".format(decElement)
		cssItem+="\n}"
		results.append(cssItem)
	return results

def parse_css_rules(siteId, browser):
	BROWSER = browser
	# browserCapitalize = copy.deepcopy(BROWSER)
	# browserCapitalize = browserCapitalize.capitalize()
	read_file_path_relative = os.path.join(os.path.join(str(siteId), "TestReports"), os.path.join("CSSRules", browser))
	read_file_path_absoulte = get_or_create_directory(read_file_path_relative)
	read_file_name = "css-rules.out"
	read_file_path_name = os.path.join(read_file_path_absoulte, read_file_name)

	out_file_name = "report-vulnerability-test.out"
	out_file_path_name = os.path.join(read_file_path_absoulte, out_file_name)

	OUTPUT_ERRORS = False # set to true to also output css parse errors

	fileContents=None
	distinctURLs=[]
	distinctStates=[]
	with open(read_file_path_name, "r") as fp:
		separator="==================================================================================\n"
		fileContents= fp.read().split(separator) #URL & STATE would appear in the same list element
		# TO DO: REMOVE THE HTML STRING EITHER HERE OR WHEN STORING THE OUTPUT
	for line in fileContents:
		if "URL: http" in line:
			foundURL= line[line.index("URL:")+len("URL:"):].strip("\n").strip()
			print foundURL
			distinctURLs.append(foundURL)
		if "STATE:" in line:
			foundState = line[line.index("STATE:")+len("STATE:"):].strip("\n").strip()
			if foundState not in distinctStates:
				distinctStates.append(foundState)
	distinctURLs=list(set(distinctURLs))

	contentStates={} #include the contents of different states like, e.g, {url1: {loggedState: cssRules, ...}, url2: ...}
	contentStatesParsed={} #contains url1: {'statename': [[all rules], [all errors]], ...}
	for eachURL in distinctURLs:
		contentStates[eachURL] = {}
		for i in range(len(fileContents)):
			line= fileContents[i]
			if eachURL+":" in line:
				stateName= line[line.index("STATE:")+len("STATE:"):].strip("\n").strip()
				cssRules= fileContents[i+1]
				contentStates[eachURL][stateName]=cssRules

		contentStatesParsed[eachURL] = {}
		for url,value in contentStates.items():
			for state in contentStates[url]:
				parser = tinycss.make_parser('page3')
				stylesheet = parser.parse_stylesheet_bytes(b'''%s'''%contentStates[url][state])
				# print remove_digits_from_list_items(stylesheet.rules[0].declarations)
				rules = stylesheet.rules
				contentStatesParsed[eachURL][state]=[rules, stylesheet.errors, get_rule_declaration_list(rules)]

	# init output empty lists
	output = {}
	if OUTPUT_ERRORS:
		output_errors={}
	for eachURL in distinctURLs:
		output[eachURL] = {}
		if OUTPUT_ERRORS:
			output_errors[eachURL] = {}
		for eachState in distinctStates:
			output[eachURL][eachState]=[]
			if OUTPUT_ERRORS:
				output_errors[eachURL][eachState]=[]


	for eachURL in distinctURLs:
		for eachState in distinctStates:
			try:
				currentInfo= contentStatesParsed[eachURL][eachState]
			except:
				continue
			currentRuleDeclarations = currentInfo[2]
			for eachRuleDecItem in currentRuleDeclarations:
				for eachOtherState in distinctStates:
					if eachState == eachOtherState: continue
					otherInfo= contentStatesParsed[eachURL][eachOtherState]
					otherRuleDeclarations= otherInfo[2]
					if eachRuleDecItem not in otherRuleDeclarations:
						output[eachURL][eachState].append(eachRuleDecItem)
						break
		if OUTPUT_ERRORS:
			for eachState in distinctStates:
				currentInfo= contentStatesParsed[eachURL][eachState]
				currentErrors = currentInfo[1]
				for eachError in currentErrors:
					for eachOtherState in distinctStates:
						if eachState == eachOtherState: continue
						otherInfo= contentStatesParsed[eachURL][eachOtherState]
						otherErrors= otherInfo[1]
						if eachError not in otherErrors:
							output_errors[eachURL][eachState].append(eachError)
							break

	timestamp = get_current_datetime()
	with open(out_file_path_name, "wb") as fd:
		fd.write('-----------------------------------------------------------------------------\n')
		fd.write('[subject] CSS Rules Parse Results\n')
		fd.write('[timestamp] generated on: %s\n'%timestamp)
		fd.write('-----------------------------------------------------------------------------\n\n\n')
		for eachURL in distinctURLs:
			fd.write("=======================================================================\n")
			fd.write("URL: %s\n"%eachURL)
			fd.write("=======================================================================\n")
			for eachState in distinctStates:
				fd.write("STATE: %s\n"%eachState)
				fd.write("- RuleSets:")
				rules = output[eachURL][eachState]
				if len(rules) == 0:
					fd.write(" []\n");
				else:
					fd.write("\n")
				for eachRule in rules:
					fd.write('################ -- RULE -- ################\n')
					fd.write("%s\n"%eachRule)
				if OUTPUT_ERRORS:
					fd.write("- Errors:")
					errors = output_errors[eachURL][eachState]
					if len(errors) == 0:
						fd.write(" []\n");
					else:
						fd.write("\n")
					for err in errors:
						fd.write('################ -- Error -- ###############\n')
						fd.write("%s\n"%err)


# --------------------------------------------------------------------------- #
#				End CSS Collection (CSSC)
# --------------------------------------------------------------------------- #

# --------------------------------------------------------------------------- #
#							Start CORS 
# --------------------------------------------------------------------------- #

def _get_attack_url_cors(siteId, state_status, target_url, runHashId):
	target = encodeURL(target_url)
	return TEST_SERVER_BASE + "/attack-page/cors/%s/%s/?fr=%s&hash=%s"%(siteId, state_status, target, runHashId)

def _get_cors_export_csv_from_db(siteId, stateLabels, runHashId):
	states = ",".join(stateLabels)
	return LOG_SERVER_BASE + "/cors-export-csv/%s/?hash=%s&states=%s"%(siteId, runHashId, states) 

def run_cors_attack(err_log_fp, runHashId):

	# -- BEGIN PRIMARY CONFIG -- #
	zap = ZAPv2(apikey=ZAP_API_KEY)
	zap.core.new_session(apikey=ZAP_API_KEY)
	psl_cache_dir = os.path.join(BASE_DIR, "cache/")
	psl = public_suffix_list(http=httplib2.Http(psl_cache_dir), headers={'cache-control': 'max-age=%d' % (90000000*60*24)})
	# -- END PRIMARY CONFIG -- #

	# time before opening another URL for testing
	delay_seconds = 11
	for siteId, siteSpec in site_dict.items():

		if siteId in LOG_ERR_KEYS:
			continue

		# The first phase is the initial URL crawling phase
		# first_phase_completed flag is true if its not the URL crawling phase
		first_phase_completed = urls_for_site_exists(siteId) 
		site_url = siteSpec[0]
		domain_base = siteSpec[1]
		site_filter_regex= get_regex(domain_base)

		stateModule = __import__("%s.Scripts.%s"%(siteId, STATES_SCRIPT_FILE), fromlist=["states"])
		states = stateModule.states
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
			# set driver timeout for sites
			if siteId == "27":
				#QUICK FIX for yandex.ru un-responsive pages
				driver.set_page_load_timeout(20)	
			print "[MainThread] Executing state function '%s' for siteURL='%s'"%(stateLabel, site_url)
			try:
				driver = stateFunctionPtr(driver, site_url, first_phase= first_phase_completed)
			except:
				error_message = write_state_error_entry(err_log_fp, siteId, site_url, stateLabel)
				print error_message
				continue
			print "[MainThread] Successfully Executed state function '%s' for siteURL='%s'"%(stateLabel, site_url) 

			# Step 2: read previously crawled URLs
			print "[MainThread] Reading URLS..."
			crawled_endpoints = get_urls_for_site(siteId, zap, psl, site_url, site_filter_regex, domain_base)
			print "[MainThread] Found %s urls"%len(crawled_endpoints)
			

			# Step 3: test each url at the current state
			time.sleep(1)
			for aURL in crawled_endpoints:
				print "[MainThread-%s] Testing resource: %s"%(stateLabel, aURL)
				attackURL = _get_attack_url_cors(siteId, stateLabel, aURL, runHashId)
				try:
					driver.get(attackURL)
				except:
					pass
				time.sleep(delay_seconds)

			driver.close()
			time.sleep(2)
		# step 4: export csv result from DB
		time.sleep(1)
		driver = get_new_browser_driver(BROWSER)
		time.sleep(4)
		stateLabels = [state["label"] for state in states]
		exportURL = _get_cors_export_csv_from_db(siteId, stateLabels, runHashId)
		try:
			driver.get(exportURL)
		except:
			driver = get_new_browser_driver(BROWSER)
			driver.get(exportURL)
		time.sleep(20)


def main_cors_attack(number_of_runs = 1):
	err_log_fp = create_error_log_fp('cors')
	for runIdx in range(number_of_runs):
			runHashId = generate_uuid()
			run_cors_attack(err_log_fp, runHashId)


# --------------------------------------------------------------------------- #
#		Main: Call Each Individual COSI Attack Detector
# --------------------------------------------------------------------------- #

def main():

	# JSObjectRead
	main_script_inclusion_attack_vars(number_of_runs = 1)

	# Frame Count
	main_content_window_attack(number_of_runs = 1)

	# Dynamic Event Fire + Object Properties
	main_event_fire_count_attack()
	
	# Content Security Policy
	main_run_csp_attack()

	# JSErrors
	main_script_inclusion_attack_errs(number_of_runs = 1)

	# Post Messages
	main_post_message_attack(number_of_runs = 1)

	# CORS
	# main_cors_attack()

	# timing
	# main_ta_attack(number_of_runs = 2)

	# CSSRules
	# main_css_rules_attack()	
	### parse_css_rules(105, "Chrome")

	
if __name__ == "__main__":
	main()


























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
    Crawler: URL discovery
"""


from main import * 
BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def find_urls(site_id, state, spider_duration_mins=3, ajax_duration_mins=1, Local=False, IP=False, CrawlFlag=True):

	# public suffix list caching
	cache_dir = os.path.join(BASE_DIR, "cache/")
	psl = public_suffix_list(http=httplib2.Http(cache_dir), headers={'cache-control': 'max-age=%d' % (90000000*60*24)})

	# zap instance
	zap = ZAPv2(apikey=ZAP_API_KEY)
	sessionName="COSISession"
	zap.core.new_session(name=sessionName, overwrite=True, apikey=ZAP_API_KEY)

	siteSpec = site_dict[site_id]
	sites = [(site_id, siteSpec)] # = site_dict.items()
	for siteId, siteSpec in sites:
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
		first_phase_completed=False

		stateFunctionPtr = state["function"]
		stateLabel = state["label"]
		authAccount = stateLabel
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
			if not target.endswith('/'):
				target=target+"/cources"
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
# 1. for i=1 to n-states
# 	1.1. Run the selenium script for user account i 
# 	1.2. Run the spider with the session of user i
# 	1.3. Combine URLs from steps 1.1 and 1.2
# 2. Combine all collected urls and Remove duplicates

def get_urls(siteId, spider_duration_mins=3, ajax_duration_mins=1, Local=False, IP=False, CrawlFlag=True):
	stateModule = __import__("%s.Scripts.%s"%(siteId, STATES_SCRIPT_FILE), fromlist=["states"])
	states = stateModule.states
	urls = []

	for stateIndex in range(len(states)):
		state = states[stateIndex]
		currentAccountURLs = find_urls(siteId, state, spider_duration_mins=spider_duration_mins, ajax_duration_mins=ajax_duration_mins, Local=Local, IP=IP, CrawlFlag=CrawlFlag)
		urls.append(currentAccountURLs)

	combinedURLs = list(set(urls))
	save_file_name = "urls.txt"
	save_urls_to_file(siteId, combinedURLs, filename=save_file_name)
	return combinedURLs


def get_main_urls_directory(siteId):
	return os.path.join(BASE_DIR, os.path.join("%s"%siteId, "urls"))

def get_urls_for_site(siteId):

	url_file_path = os.path.join(get_main_urls_directory(siteId), "urls.txt")
	if os.path.exists(url_file_path) and os.path.isfile(url_file_path):
		f= open(url_file_path, "r")
		list_urls = f.readlines();
		list_urls = [ item.strip().strip('\n') for item in list_urls]
		f.close()
		return list_urls
	return []


if __name__ == "__main__":

	if len(sys.argv)!= 2:
		print "Script-Usage: you must provide siteId as argument, e.g.\n'python <script-name> siteId'"

	else:
		siteId = sys.argv[1]
		
		# URL collector
		URLs = get_urls_for_site(siteId)
		if len(URLs) == 0:
			print "++ URL Crawling Started!"
			URLs = get_urls(siteId)
			print "++ URL Crawling Finished!"
		else:
			print "URLs already exists..."
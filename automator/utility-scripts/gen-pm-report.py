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

import sys
import os
import glob
import hashlib
from datetime import datetime

#-----------------------------------------------------------------------#
#						Constants
#-----------------------------------------------------------------------#

# define output names
VULNERABILITY_REPORT_OUT_NAME="report-vulnerability.out"
# VULNERABILITY_REPORT_DETAILED_OUT_NAME="report-vulnerability-detailed.out"
VULNERABLE_URLS_OUT_NAME="urls-vulnerable.out"

NUM_COLS_EACH_STATE = 1
#-----------------------------------------------------------------------#
#						Utils
#-----------------------------------------------------------------------#
def _get_md5_hash_digest(text_input):
	# return hashlib.sha224(text_input).hexdigest()
	result = hashlib.md5(text_input.encode('utf-8').strip())
	return result.hexdigest().encode('utf-8').strip()

def _get_current_date():
	timestamp = datetime.now().strftime('%d/%m/%Y at %H:%M:%S')
	return timestamp

def _divide_string_in_n_parts(string, n_parts):
    parts= string.split(", ")
    results=[]
    k=n_parts
    i=0
    while k:
        z=NUM_COLS_EACH_STATE-1
        while z:
            parts[i]+=", "+parts[i+z]
            z=z-1
    	results.append(parts[i])
    	k-=1
    	i+=NUM_COLS_EACH_STATE
    return results


def _is_item_in_all_other_lists(item, listItem, skip_this_index):
	# if item.startswith("parent") or item.startswith("frame") or item.startswith("self"):
	# 	return True # DO NOT Compare parent and frame variables
	for i in range(len(listItem)):
		if i == skip_this_index: continue
		eachOtherList= listItem[i]
		if item not in eachOtherList:
			return False
	return True

def _all_same(items):
    return all(x == items[0] for x in items)

def _get_difference_list(listItem):
	copy = listItem
	lenListItem=len(copy)
	for i in range(lenListItem):
		copy[i]=eval(copy[i].strip("\""))

	results=[]
	for ListIndex in range(lenListItem):
		eachList = copy[ListIndex]
		eachResult=[]
		for item in eachList:
			if not _is_item_in_all_other_lists(item, copy, ListIndex):
				eachResult.append(item)
		results.append(eachResult)
	return results

def _hasify_values(listItem):
	results =[]
	for listElement in listItem:
		resListElement = []
		for element in listElement:
			[key, value] = element.split(":::")
			value = _get_md5_hash_digest(u"{0}".format(value))
			newElement= "%s ::: %s"%(key, value)
			resListElement.append(newElement)
		results.append(resListElement)
	return results
#-----------------------------------------------------------------------#
#						   Main
#-----------------------------------------------------------------------#
def main():
	if len(sys.argv)!= 2:
		print "Script-Usage: you must provide siteId as argument, e.g.\n'python gen-summary-csv.py siteId'"
		return 0
	siteId = sys.argv[1]
	AUTOMATOR_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
	ROOT_DIR = os.path.join(AUTOMATOR_DIR, "%s/TestReports/PostMessage/"%siteId)
	timestamp = _get_current_date()
	for subdir, dirs, files in os.walk(ROOT_DIR):
		list_files = glob.glob(subdir+"/*.csv")
		if len(list_files) != 0:
			urls_fp = open(subdir+ "/"+ VULNERABLE_URLS_OUT_NAME, "wb")
			with open(subdir+ "/" + VULNERABILITY_REPORT_OUT_NAME, "wb") as outFileFp:
				outFileFp.write("======================================================================\n")
				outFileFp.write("[Subject]: Vulnerability Report\n")
				outFileFp.write("[DateTime]: %s\n"%timestamp )
				outFileFp.write("[Notes]:\n" )
				outFileFp.write("\tThis report is produced at the completion of the PostMessage test\n\t for the websiteId=%s, and provides a summary of all potentially vulnerable URLS of this website to PostMessage attack\n"%siteId )
				outFileFp.write("\tIf multiple runs of the same test exists, the report would aggregate\n\tthe results for all runs accordingly.\n")
				outFileFp.write("======================================================================\n\n\n")
				ListOfAllFiles = [] # Shows all Files In a single Directory
				for file in list_files:
					if file.endswith(".csv") and (not file.endswith("report-summary.csv")) and (not file.endswith("results-summary.csv")):
						with open(file, "r") as fp:
							fileContent = fp.readlines()
							filename = file[:-24] #remove the datetime part
							datetime = file[-20:]
							fullname = file
							ListOfAllFiles.append([filename, fileContent, datetime, fullname])

				ListOfDistinctFileNames = list(set([obj[0] for obj in ListOfAllFiles]))
				for name in ListOfDistinctFileNames:
					ListOfFilesWithSimilarNames = []
					for obj in ListOfAllFiles:
						compareName = obj[0]
						if name == compareName:
							ListOfFilesWithSimilarNames.append(obj)

					# similar filenames may have different csv headers-> distinguish them
					ListOfDistinctHeaders = list(set([obj[1][0].strip() for obj in ListOfFilesWithSimilarNames]))
					for header in ListOfDistinctHeaders:
						states=header[header.index(',')+1:].strip().strip("\n").split(",")
						stateCount = len(states)/NUM_COLS_EACH_STATE
						ListOfFilesWithSimilarNamesAndHeader = []
						for obj in ListOfFilesWithSimilarNames:
							compareHeader = obj[1][0].strip()
							if header == compareHeader:
								ListOfFilesWithSimilarNamesAndHeader.append(obj)

						# aggregate all Contents of ListOfFilesWithSimilarNamesAndHeader in same place
						ListOfAllDistinctURLs_AtHand= []
						for fileObject in ListOfFilesWithSimilarNamesAndHeader:
							fileLines = fileObject[1]
							for lineIdx in range(len(fileLines)):
								if lineIdx == 0: continue
								line = fileLines[lineIdx]
								# url may contain comma itself, do NOT seperate with comma
								# url = line.split(",")[0].strip()
								ucc = line.split(" ")[0]
								url=ucc.strip()[:-1]
								# try:
								# 	url = eval(ucc.strip()[:-1]) #Omit the comma at the end
								# except:
									#continue
								ListOfAllDistinctURLs_AtHand.append(url)
						ListOfAllDistinctURLs_AtHand = list(set(ListOfAllDistinctURLs_AtHand))

						AttackName=ListOfFilesWithSimilarNamesAndHeader[0][0]
						SectionHeader =  AttackName[AttackName.rindex("/")+1:] + "\n"
						outFileFp.write("----------------------------------------------------------------------\n")
						outFileFp.write("Test: "+SectionHeader)
						if not header.endswith("\n"):
							outFileFp.write("Header: "+header[header.index(',')+1:].strip()+"\n")
						else:
							outFileFp.write("Header: "+header[header.index(',')+1:].strip())
						outFileFp.write("----------------------------------------------------------------------\n")

						toWriteURL = False;
						currentHeaderList=header.split(",")[1:]
						for i in range(len(currentHeaderList)):
							currentHeaderList[i]= currentHeaderList[i].strip("\n").strip() 
						for url in ListOfAllDistinctURLs_AtHand:
							toWriteURL = False
							resultDict = {} # key=URL, value=list of a dicts (each dict represent one SAME run for that url), each dict contains:
							# key: si_TM ; value = [s1_TM, s2_TM, ...]
							# key: si_TDO; value = [s1_TDO, s2_TDO, ...]
							# key: si_DMD; value = [[s1_DMD1, s1_DMD2, ...], [...]]
							# key: si_MO; value= [[s1_MO1, s1_MO2, ...], [...]] ONLY for same si_DMDi elements (two level) in between level 1 (si_DMD) lists
							for fileObject in ListOfFilesWithSimilarNamesAndHeader:
								fileLines = fileObject[1]
								datetime = fileObject[2]
								for lineIdx in range(len(fileLines)):
									if lineIdx == 0: continue
									line = fileLines[lineIdx]
									uc = line.split(" ")[0]
									try:
										urlCompare = uc.strip()[:-1] #convert to string object with comma removed
									except:
										continue
									if url == urlCompare:
										stringLineItems = line[len(uc):]
										# stringLineItems = line[line.index(","):]
										stringLineItems = stringLineItems.strip()
										#remove newline char at the end if exists
										if stringLineItems.endswith("\n"):
											stringLineItems= stringLineItems.strip("\n")
										#divide the string in two and compare
										division = _divide_string_in_n_parts(stringLineItems, stateCount)
										if not _all_same(division):				
											# analyze the "divistion" variable having the different parts
											# and store the results
											# @HACK: prevent errors in evaluation of jsons by
											# re-defining non-string variables as string
											null = "null"
											true = "true"
											false = "false" 
											parts=[]
											for element in division:
												element = eval(element)
												parts.append(element)
											toWriteURL=True

							if(toWriteURL):
								outFileFp.write("URL: "+url+"\n")
								urls_fp.write(url+"\n")
								outFileFp.write("\n")
						if not toWriteURL:
							# no url in this section is vulnerable
							outFileFp.write("--"+"\n\n")
			urls_fp.close()
if __name__ == "__main__":
	main()

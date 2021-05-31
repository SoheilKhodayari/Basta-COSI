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
VULNERABILITY_REPORT_DETAILED_OUT_NAME="report-vulnerability-detailed.out"
VULNERABLE_URLS_OUT_NAME="urls-vulnerable.out"


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
		results.append(parts[i]+", "+parts[i+1])
		k-=1
		i+=2
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
	# siteId= 101
	AUTOMATOR_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
	ROOT_DIR = os.path.join(AUTOMATOR_DIR, "%s/TestReports/ScriptInclusion/"%siteId)
	timestamp = _get_current_date()
	for subdir, dirs, files in os.walk(ROOT_DIR):
		list_files = glob.glob(subdir+"/*.csv")
		if len(list_files) != 0:
			urls_fp = open(subdir+ "/"+ VULNERABLE_URLS_OUT_NAME, "wb")
			detailed_fp=open(subdir+ "/" + VULNERABILITY_REPORT_DETAILED_OUT_NAME, "wb")
			with open(subdir+ "/" + VULNERABILITY_REPORT_OUT_NAME, "wb") as outFileFp:
				outFileFp.write("======================================================================\n")
				outFileFp.write("[Subject]: Vulnerability Report\n")
				outFileFp.write("[DateTime]: %s\n"%timestamp )
				outFileFp.write("[Notes]:\n" )
				outFileFp.write("\tThis report is produced at the completion of the ScriptInclusion test\n\t for the websiteId=%s, and provides a summary of all potentially vulnerable URLS of this website to ScriptInclusion attack\n"%siteId )
				outFileFp.write("\tIf multiple runs of the same test exists, the report would aggregate\n\tthe results for all runs accordingly.\n")
				outFileFp.write("======================================================================\n\n\n")
				detailed_fp.write("======================================================================\n")
				detailed_fp.write("[Subject]: Vulnerability Report\n")
				detailed_fp.write("[DateTime]: %s\n"%timestamp )
				detailed_fp.write("[Notes]:\n" )
				detailed_fp.write("\tThis report is produced at the completion of the ScriptInclusion test\n\t for the websiteId=%s, and provides a summary of all potentially vulnerable URLS of this website to ScriptInclusion attack\n"%siteId )
				detailed_fp.write("\tIf multiple runs of the same test exists, the report would aggregate\n\tthe results for all runs accordingly.\n")
				detailed_fp.write("======================================================================\n\n\n")
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
						stateCount = len(states)/2 #each two header value relate to one state in script inclusion(vars)
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
								try:
									url = eval(ucc.strip()[:-1])
								except:
									continue
								ListOfAllDistinctURLs_AtHand.append(url)
						ListOfAllDistinctURLs_AtHand = list(set(ListOfAllDistinctURLs_AtHand))

						AttackName=ListOfFilesWithSimilarNamesAndHeader[0][0]
						SectionHeader =  AttackName[AttackName.rindex("/")+1:] + "\n"
						outFileFp.write("----------------------------------------------------------------------\n")
						outFileFp.write("Test: "+SectionHeader)
						detailed_fp.write("----------------------------------------------------------------------\n")
						detailed_fp.write("Test: "+SectionHeader)
						if not header.endswith("\n"):
							outFileFp.write("Header: "+header[header.index(',')+1:].strip()+"\n")
							detailed_fp.write("Header: "+header[header.index(',')+1:].strip()+"\n")
						else:
							outFileFp.write("Header: "+header[header.index(',')+1:].strip())
							detailed_fp.write("Header: "+header[header.index(',')+1:].strip()+"\n")
						outFileFp.write("----------------------------------------------------------------------\n")
						detailed_fp.write("----------------------------------------------------------------------\n")
						toWriteURL = False;
						currentHeaderList=header.split(",")[1:]
						for i in range(len(currentHeaderList)):
							currentHeaderList[i]= currentHeaderList[i].strip("\n").strip()
						for url in ListOfAllDistinctURLs_AtHand:
							toWriteURL = False
							for fileObject in ListOfFilesWithSimilarNamesAndHeader:
								fileLines = fileObject[1]
								datetime = fileObject[2]
								for lineIdx in range(len(fileLines)):
									if lineIdx == 0: continue
									line = fileLines[lineIdx]
									uc = line.split(" ")[0]
									try:
										urlCompare = eval(uc.strip()[:-1]) #convert to string object with comma removed
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
										if not _all_same(division): #divide the string in n=stateCount number of parts and check if they are all same
											line_items = stringLineItems.split(" ")
											compare_this_list=[]
											for i in range(len(currentHeaderList)):
												line_items[i]=line_items[i].strip(',')
												if not i%2:
													compare_this_list.append(line_items[i])
													continue
											#create a list of i%2
											diff_list = _get_difference_list(compare_this_list)
											diff_list_hashed = _hasify_values(diff_list)
											if _all_same(diff_list_hashed):
												continue
											for i in range(len(currentHeaderList)):
												line_items[i]=line_items[i].strip(',')
												if not i%2:
													compare_this_list.append(line_items[i])
													continue
												outFileFp.write("%s: %s\n"%(currentHeaderList[i], line_items[i]))
												detailed_fp.write("%s: %s\n"%(currentHeaderList[i], line_items[i]))

											for i in range(stateCount):
												outFileFp.write("%s: %s\n"%(currentHeaderList[i+i], str(diff_list_hashed[i])))
												detailed_fp.write("%s: %s\n"%(currentHeaderList[i+i], str(diff_list[i])))
											toWriteURL=True
							if(toWriteURL):
								outFileFp.write("URL: "+url+"\n")
								urls_fp.write(url+"\n")
								outFileFp.write("\n")
						if not toWriteURL:
							# no url in this section is vulnerable
							outFileFp.write("--"+"\n\n")
							detailed_fp.write("--"+"\n\n")
			urls_fp.close()
			detailed_fp.close()
if __name__ == "__main__":
	main()

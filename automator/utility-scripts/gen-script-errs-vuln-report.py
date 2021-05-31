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
from datetime import datetime

#-----------------------------------------------------------------------#
#						Constants
#-----------------------------------------------------------------------#

# define output names
VULNERABILITY_REPORT_OUT_NAME="report-vulnerability.out"
VULNERABLE_URLS_OUT_NAME="urls-vulnerable.out"

NUM_COLS_EACH_STATE = 1
#-----------------------------------------------------------------------#
#						Utils
#-----------------------------------------------------------------------#

def _get_current_date():
	timestamp = datetime.now().strftime('%d/%m/%Y at %H:%M:%S')
	return timestamp

def _divide_string_in_half(string):
	firstpart, secondpart = string[:len(string)/2], string[len(string)/2:]
	return firstpart, secondpart

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


def _all_same(items):
    return all(x == items[0] for x in items)
#-----------------------------------------------------------------------#
#						   Main
#-----------------------------------------------------------------------#
def main():
	if len(sys.argv)!= 2:
		print "Script-Usage: you must provide siteId as argument, e.g.\n'python gen-summary-csv.py siteId'"
		return 0
	siteId = sys.argv[1]
	AUTOMATOR_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
	ROOT_DIR = os.path.join(AUTOMATOR_DIR, "%s/TestReports/ScriptErrors/"%siteId)
	from datetime import datetime
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
				outFileFp.write("\tThis report is produced at the completion of the ScriptErrors test\n\t for the websiteId=%s, and provides a summary of all potentially vulnerable URLS of this website to ScriptErrors attack\n"%siteId )
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
						if not header.endswith("\n"):
							outFileFp.write("Header: "+header[header.index(',')+1:].strip()+"\n")
						else:
							outFileFp.write("Header: "+header[header.index(',')+1:].strip())
						outFileFp.write("----------------------------------------------------------------------\n")
						toWriteURL = False;
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
											outFileFp.write(stringLineItems+"\n")
											# print stringLineItems
											# print division
											# print states
											# print stateCount
											# print file
											# print division
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

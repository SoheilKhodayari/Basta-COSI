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
import json
from datetime import datetime
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
	string=string+","
	size=len(string)/n_parts
	parts = []
	for i in range(0, len(string), size):
		part = string[i:i+size]
		part = part.replace("\"","")
		part = part.strip() #remove the start whitespace if any
		if part.endswith(","):
			part=part[:-1] #remove middle commas
		if part.startswith(","):
			part=part[1:]
		part = part.strip() #remove the start whitespace if any after removing commas
		if part!="" and part != ',' and part!="\"" and part!="'": 
			parts.append(part)
	# parts = [string[i:i+size].strip() for i in range(0, len(string), size)]
	return parts

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

	timestamp = _get_current_date()

	#-------------------------------------------------------------------#
	#						Constants
	#-------------------------------------------------------------------#

	# directories
	AUTOMATOR_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

	ROOT_DIR = os.path.join(AUTOMATOR_DIR, os.path.join("%s"%siteId, os.path.join("TestReports", "EventFireCount")))
	OUTPUT_DIR = ROOT_DIR

	# define inputs file names
	INPUTS_FILE_NAME="report-summary.out"

	BROWSER_INPUT_FILE="browser.json"

	# define output file name
	OUTPUT_FILE_NAME = "summary-table.out"
	OUTPUT_FILE_PATH_NAME = os.path.join(OUTPUT_DIR, OUTPUT_FILE_NAME)

	# define a TEMP file
	TEMP_FILE_NAME = "temp.out"
	TEMP_FILE_PATH_NAME= os.path.join(OUTPUT_DIR, TEMP_FILE_NAME)



	#-------------------------------------------------------------------#
	#					End Constants
	#-------------------------------------------------------------------#
	
	# Contains the contents of all INPUTS_FILE_NAME files as fp.read()
	summaryFileContents=[]

	# results dict ,  key=url, value=[[browser, tag, state,value], [[browser, tag, state,value],..]]
	resultsDict={}

	# { chrome: chrome-version, firefox: firefox-version,...}
	browserDict={}

	for subdir, dirs, files in os.walk(ROOT_DIR):
		browserSpecFile=os.path.join(subdir, BROWSER_INPUT_FILE)
		if not os.path.exists(browserSpecFile):
			continue #the main directory does not contain a browser json file
		with open(browserSpecFile, "r") as browserSpecFile:
			specData = json.load(browserSpecFile)
			browserDict[specData["BROWSER"].lower()]=specData["BROWSER_VERSION"].lower()

		reportPathName= os.path.join(subdir, INPUTS_FILE_NAME)
		if not os.path.exists(reportPathName):
			continue #the main directory does not contain a report
		with open(reportPathName, "r") as fp:
			content= fp.read()
			summaryFileContents.append(content)

	# Number of different Browsers
	nBrowsers= len(summaryFileContents)
	# store all date  in temp file 
	with open(TEMP_FILE_PATH_NAME, "wb") as fp:
		for idx in range(nBrowsers):
			content = summaryFileContents[idx]
			fp.write(content)
			fp.write("\n\n")

	with open(TEMP_FILE_PATH_NAME, "r") as tempFP:
		tempFileLines = tempFP.readlines()
		distinctURLs=[]
		for i in range(len(tempFileLines)):
			line=tempFileLines[i]
			if line.startswith("URL:"):
				url=line.split(" ")[1].strip("\n")
				distinctURLs.append(url)
		distinctURLs=list(set(distinctURLs))

		for eachURL in distinctURLs:
			for i in range(len(tempFileLines)):
				line=tempFileLines[i]
				if eachURL in line:
					try:
						valueStates=tempFileLines[i+1]
					except:
						print "NO-VALUE"
						continue
					# go back to top to find the header
					for j in range(i, 0, -1):
						lineHeading= tempFileLines[j]
						if not lineHeading.startswith("Test:"):
							continue
						lineStates=tempFileLines[j+1]
						if not lineStates.startswith("Header:"):
							print "FILE_FORMAT_WRONG"
							sys.exit()

						lineHeadingSeparator="\\"
						if "/" in lineHeading:
							lineHeadingSeparator="/"

						lineHeadingSplitted= lineHeading.split(lineHeadingSeparator)
						# browser (for writing to out)
						currentBrowser=lineHeadingSplitted[1]

						currentBrowserVersion=browserDict[currentBrowser.lower()]

						# html tag (for writing to out)
						currentTag = lineHeadingSplitted[2].split("-")[0]

						lineStates= lineStates[len("Header:"):].strip().strip("\n")
						lineStatesSeperator=","
						# list of states
						lineStatesSplitted= lineStates.split(lineStatesSeperator)
						stateCount= len(lineStatesSplitted)/2
						
						valueStates= valueStates.strip().strip("\n")
						valueStatesSeperator= ", \"" #previously " " #changed because of linkedin only
						valueStatesSpliteed= valueStates.split(valueStatesSeperator)
						
						# create a dict of state:value
						states=[]
						for idx in range(0, len(lineStatesSplitted), 2):
							state=lineStatesSplitted[idx].strip()+", "+lineStatesSplitted[idx+1].strip()
							states.append(state)

						try:
							values=[]
							for idx in range(0, len(valueStatesSpliteed), 2):
									val=valueStatesSpliteed[idx].strip()+" "+valueStatesSpliteed[idx+1].strip().strip(",").strip()
									values.append(val)
						except:
							valueStatesSpliteed = valueStatesSpliteed[1:] #fix for linkedin errr
							values=[]
							for idx in range(0, len(valueStatesSpliteed), 2):
									val=valueStatesSpliteed[idx].strip()+" "+valueStatesSpliteed[idx+1].strip().strip(",").strip()
									values.append(val)		
						
						stateValueDict={}
						for k in range(stateCount):
							stateValueDict[states[k]]=values[k]

						for stateAsKey in stateValueDict:
							vector=[currentBrowser, currentBrowserVersion, currentTag, stateAsKey, stateValueDict[stateAsKey]]
							if eachURL in resultsDict:
								resultsDict[eachURL].append(vector)
							else:
								resultsDict[eachURL]=[vector]
						# the heading for this url is found
						break
							
	with open(OUTPUT_FILE_PATH_NAME, "wb") as outFileFp:
		outFileFp.write("======================================================================\n")
		outFileFp.write("[Subject]: Summary of Results For EventFireCount Attack\n")
		outFileFp.write("[Generated]: %s\n"%timestamp )
		outFileFp.write("======================================================================\n\n\n")

		for eachKeyURL in resultsDict:
			vectors=resultsDict[eachKeyURL]
			outFileFp.write("----------------------------------------------------------------------\n")
			outFileFp.write("URL: %s\n"%eachKeyURL)
			outFileFp.write("----------------------------------------------------------------------\n")
			lastTag=''
			lastBrowser='chrome'
			for vector in vectors:
				if vector[2]!= lastTag:
					outFileFp.write("\n")
				lastTag=vector[2]
				if vector[1]!= lastBrowser:
					outFileFp.write("\n")
				lastBrowser=vector[1]
				
				outFileFp.write("{0}".format(vector))
				outFileFp.write("\n")
			outFileFp.write("\n\n")

if __name__ == "__main__":
	main()
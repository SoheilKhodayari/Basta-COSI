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
   generates both the summary table and the summary table vulnerability CSVs

"""


import sys
import os
import glob
import json
import copy
from datetime import datetime
#-----------------------------------------------------------------------#
#                                               Utils
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
                part = part.strip("\"")
                if part!="" and part != ',' and part!="\"" and part!="'":
                        parts.append(part)
        # parts = [string[i:i+size].strip() for i in range(0, len(string), size)]
        return parts

def _all_same(items):
    return all(x == items[0] for x in items)


def _is_item_in_all_other_lists(item, listItem, skip_this_index):
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
    results=[]
    for ListIndex in range(lenListItem):
        eachList = copy[ListIndex]
        eachResult=[]
        for item in eachList:
            if not _is_item_in_all_other_lists(item, copy, ListIndex):
                eachResult.append(item)
        results.append(eachResult)
    return results


#-----------------------------------------------------------------------#
#          Main
#-----------------------------------------------------------------------#

def main():
    if len(sys.argv)!= 2:
      print "Script-Usage: you must provide siteId as argument, e.g.\n'python <filename> siteId'"
      return 0
    siteId = sys.argv[1]
    timestamp = _get_current_date()

    #-------------------------------------------------------------------#
    #            Constants
    #-------------------------------------------------------------------#

    # directories
    AUTOMATOR_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    ROOT_DIR = os.path.join(AUTOMATOR_DIR, os.path.join("%s"%siteId, os.path.join("TestReports", "ObjectProperties")))
    OUTPUT_DIR = ROOT_DIR

    # define inputs file names
    INPUTS_FILE_NAME="report-summary.out"

    BROWSER_INPUT_FILE="browser.json"

    # define output file name
    OUTPUT_FILE_NAME = "summary-table.out"
    OUTPUT_FILE_VULN_NAME = "summary-table-vulnerability.out"
    OUTPUT_FILE_PATH_NAME = os.path.join(OUTPUT_DIR, OUTPUT_FILE_NAME)
    OUTPUT_FILE_PATH_VULN_NAME = os.path.join(OUTPUT_DIR, OUTPUT_FILE_VULN_NAME)
    # define a TEMP file
    TEMP_FILE_NAME = "temp.out"
    TEMP_FILE_PATH_NAME= os.path.join(OUTPUT_DIR, TEMP_FILE_NAME)



    #-------------------------------------------------------------------#
    #            End Constants
    #-------------------------------------------------------------------#

    # Contains the contents of all INPUTS_FILE_NAME files as fp.read()
    summaryFileContents=[]

    # results dict, key=url, value=[[browser, tag, state,value], [[browser, tag, state,value],..]]
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
                                        stateCount= len(lineStatesSplitted)
                                        
                                        valueStates= valueStates.strip().strip("\n")
                                        
                                        valueStatesSeperator=", \""
                                        valueStatesSpliteed= valueStates.split(valueStatesSeperator)
                                        
                                        # create a dict of state:value
                                        states=[]
                                        for idx in range(0, len(lineStatesSplitted)):
                                            state=lineStatesSplitted[idx].strip()
                                            states.append(state)

                                        values=[]
                                        for idx in range(0, len(valueStatesSpliteed)):
                                            val=valueStatesSpliteed[idx].strip().strip(",").strip()
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
        outFileFp.write("[Subject]: Summary of Results For ObjectProperties Attack\n")
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
                        outFileFp.write("\n\n")
                outFileFp.write("\n\n")

    with open(OUTPUT_FILE_PATH_VULN_NAME, "wb") as outFileFp:
        outFileFp.write("======================================================================\n")
        outFileFp.write("[Subject]: Summary of Vulnerable Results For ObjectProperties Attack\n")
        outFileFp.write("[Generated]: %s\n"%timestamp )
        outFileFp.write("======================================================================\n\n\n")

        for eachKeyURL in resultsDict:
                vectors=resultsDict[eachKeyURL]
                WriteURLHeader=True
                cats = {}
                for vector in vectors:
                        currentCategory= vector[0]+ ", " + vector[1] + ", " + vector[2]
                        if currentCategory not in cats:
                            cats[currentCategory] = [vector]
                        else:
                            cats[currentCategory].append(vector)

                SortedCats=[]
                for eachCategory in cats:
                    SortedCats.append(eachCategory)
                SortedCats.sort()
                for eachCategory in SortedCats:
                        vectors = cats[eachCategory]
                        # find diffs of each eachCategory
                        diff_cats = {}
                        for vector in vectors:
                                vector[4] = vector[4].replace("\\", "")  #added this to fix github qutoation error creating multiple same categories
                                currentValue = vector[4].split(", ")[0].strip().strip("\"") #added strip("\"")  to fix github qutoation error creating multiple same categories
                                if currentValue not in diff_cats:
                                        diff_cats[currentValue]=[vector]
                                else:
                                        diff_cats[currentValue].append(vector)
                        lenEventKeys = len(diff_cats.keys())
                        if lenEventKeys <=1:
                            continue # if one type of event, no vulnerability can be infered, so skip printing
                        if WriteURLHeader:
                            WriteURLHeader=False
                            outFileFp.write("----------------------------------------------------------------------\n")
                            outFileFp.write("URL: %s\n"%eachKeyURL)
                            outFileFp.write("----------------------------------------------------------------------\n")
                        outFileFp.write("- TestConfig: %s\n"%eachCategory)

                        # compare the keys in diff_cats
                        distinctValues= diff_cats.keys()
                        nCountDifferentiation = len(distinctValues)
                        lst = []
                        for eachValue in distinctValues:
                            z = eachValue.split(",")
                            lst.append(z)
              
                        difference={}
                        d = _get_difference_list(lst)
                        assert len(d) == nCountDifferentiation
                
                        for i in range(len(d)):
                            elm = d[i]
                            difference[distinctValues[i]] = elm
                            

                        for valueAsKey in diff_cats:
                                vectors=diff_cats[valueAsKey]
                                outFileFp.write("\t\tProps: {0}\t\tStates: ".format(difference[valueAsKey]))
                                for idx in range(len(vectors)):
                                        vector=vectors[idx]
                                        stateLabel=vector[3].strip() 
                                        if idx == len(vectors)-1:
                                            outFileFp.write("%s\n"%stateLabel)
                                        else:
                                            outFileFp.write("%s, "%stateLabel)
                                outFileFp.write("\n")
                        outFileFp.write("\n")
if __name__ == "__main__":
        main()


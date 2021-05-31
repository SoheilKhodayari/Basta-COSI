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
import tinycss
from datetime import datetime
#-----------------------------------------------------------------------#
#                                               Utils
#-----------------------------------------------------------------------#

def get_current_datetime():
    return datetime.now().strftime('%Y-%m-%d_%H-%M-%S')

def remove_digits_from_string(in_str):
    in_str = str(in_str)
    result = ''.join([i for i in in_str if not i.isdigit()])
    return result

def remove_digits_from_list_items(lst):  # must not remove css digit values?! only the line/col number of the error

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

def get_or_create_directory(relative_directory):
    """ 
    Note: no preceding slash for relative_directory is required 
    """
    abs_dir = os.path.join(BASE_DIR, relative_directory)
    if not os.path.exists(abs_dir):
        os.makedirs(abs_dir)
    return abs_dir
#-----------------------------------------------------------------------#
#           Main
#-----------------------------------------------------------------------#

def main():
    if len(sys.argv)!= 2:
    	print "Script-Usage: you must provide siteId as argument, e.g.\n'python gen-summary-csv.py siteId'"
    	return 0
    siteId = sys.argv[1]

    timestamp = get_current_datetime()

    #-------------------------------------------------------------------#
    #      Constants
    #-------------------------------------------------------------------#

    # directories
    AUTOMATOR_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    ROOT_DIR = os.path.join(AUTOMATOR_DIR, os.path.join("%s"%siteId, os.path.join("TestReports", "CSSRules")))
    OUTPUT_DIR = ROOT_DIR
    BROWSER_INPUT_FILE="browser.json"

    OUTPUT_ERRORS = False # set to true to also output css parse errors     

    # filenames
    READ_FILE_NAME = "css-rules.out"
    OUT_FILE_NAME = "report-vulnerability.out"
    #-------------------------------------------------------------------#
    #                   End Constants
    #-------------------------------------------------------------------#
    
    # { chrome: chrome-version, firefox: firefox-version,...}
    browserDict={}

    for subdir, dirs, files in os.walk(ROOT_DIR):
        browserSpecFile=os.path.join(subdir, BROWSER_INPUT_FILE)
        if not os.path.exists(browserSpecFile):
            continue #the main directory does not contain a browser json file
        with open(browserSpecFile, "r") as browserSpecFile:
            specData = json.load(browserSpecFile)
            browserDict[specData["BROWSER"].lower()]=specData["BROWSER_VERSION"].lower()


    for eachBrowser in browserDict:
        BROWSER = eachBrowser

        CURRENT_BASE_DIR =  os.path.join(OUTPUT_DIR, BROWSER)
        read_file_path_name = os.path.join(CURRENT_BASE_DIR, READ_FILE_NAME)
        out_file_path_name = os.path.join(CURRENT_BASE_DIR, OUT_FILE_NAME)

        fileContents=None
        distinctURLs=[]
        distinctStates=[]
        with open(read_file_path_name, "r") as fp:
            separator="==================================================================================\n"
            fileContents= fp.read().split(separator)
        for line in fileContents:
            if "URL" in line:
                foundURL= line[line.index("URL:")+len("URL:"):line.index('\n')].strip("\n").strip()
                distinctURLs.append(foundURL)
            if "STATE" in line:
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
                if eachURL in line:
                    stateName= line[line.index("STATE:")+len("STATE:"):].strip("\n").strip()
                    cssRules= fileContents[i+1]
                    contentStates[eachURL][stateName]=cssRules

            contentStatesParsed[eachURL] = {}
            for url,value in contentStates.items():
                for state in contentStates[url]:
                    parser = tinycss.make_parser('page3')
                    stylesheet = parser.parse_stylesheet_bytes(b'''%s'''%contentStates[url][state])
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
                currentInfo= contentStatesParsed[eachURL][eachState]
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


if __name__ == "__main__":
        main()

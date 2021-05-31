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
import xlsxwriter
from datetime import datetime


def get_state_label(old_name):
    ret = old_name
    if 'User1' in old_name:
        ret = 'User1Login'
    elif 'User2' in old_name:
        ret = 'User2Login'
    elif ('log' in old_name or 'Log' in old_name) and ('out' in old_name or 'Out' in old_name):
        ret = 'Logout'
    elif 'Free' in old_name:
        ret = 'FreeAccount'
    elif 'Prem' in old_name:
        ret = 'PremiumAccount'
    elif 'Fresh' in old_name:
        ret = 'FreshBrowser'
    else:
        ret = old_name
    return ret


if len(sys.argv)!= 2:
	print "Script-Usage: you must provide siteId as argument, e.g.\n'python gen-summary-csv.py siteId'"
	return 0
siteId = sys.argv[1]

site = "SITE_NAME"

AUTOMATOR_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

ROOT_DIR = os.path.join(AUTOMATOR_DIR, os.path.join("%s"%siteId, os.path.join("TestReports", "ContentWindow")))
OUTPUT_DIR = ROOT_DIR

# define inputs file names
INPUTS_FILE_NAME="summary-table-limited.out"
INPUT_FILE_PATH_NAME = os.path.join(ROOT_DIR, INPUTS_FILE_NAME)

BROWSER_INPUT_FILE="browser.json"

# define output file name
OUTPUT_FILE_NAME = "summ-pairs.xlsx"
OUTPUT_FILE_PATH_NAME = os.path.join(OUTPUT_DIR, OUTPUT_FILE_NAME)


workbook = xlsxwriter.Workbook(OUTPUT_FILE_PATH_NAME)
sheet = workbook.add_worksheet()
row = 0
browsers = ['chrome', 'firefox', 'edge']
with open(INPUT_FILE_PATH_NAME, "r") as fp:
	contents = fp.readlines()
	states = []
	lastURL = ''
	for line in contents:
		if line.startswith('----'): continue
		if line.startswith('Header:'):
			l = line[line.index("Header:")+len("Header:"):]
			s = l.split(', ')
			for st in s:
				states.append(get_state_label(st.strip().strip('\n')))
			continue
		if 'URL:' in line:
			lastURL = line.split(" ")[1].strip()
			continue

		values = line.split(', ')
		for i in range(len(values)):
			for j in range(len(values)):
				if i == j: continue
				vi = values[i].strip().strip('\n').strip()
				vj = values[j].strip().strip('\n').strip()
				if vi != vj:
					for browser in browsers:
						sheet.write(row, 0, site)
						sheet.write(row, 1, "[u'%s', u'%s']"%(states[i], states[j]))
						sheet.write(row, 2, "OPFrameCount")
						sheet.write(row, 3, "dynamic")
						sheet.write(row, 4, "[data_a: %s, data_b: %s]"%(vi, vj))
						sheet.write(row, 5, browser) 
						sheet.write(row, 6, lastURL) 
						row = row + 1
workbook.close()



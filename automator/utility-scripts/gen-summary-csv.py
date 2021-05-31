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

def main():
	if len(sys.argv)!= 2:
		print "Script-Usage: you must provide siteId as argument, e.g.\n'python gen-summary-csv.py siteId'"
		return 0
	siteId = sys.argv[1] 
	AUTOMATOR_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
	ROOT_DIR = os.path.join(AUTOMATOR_DIR, "%s/TestReports"%siteId)

	for subdir, dirs, files in os.walk(ROOT_DIR):
		list_files = glob.glob(subdir+"/*.csv")
		if len(list_files) != 0:
			with open(subdir+"/results-summary.csv", "wb") as outFileFp:
				for file in list_files:
					if file.endswith(".csv") and (not file.endswith("results-summary.csv")):
						with open(file, "r") as fp:
							outFileFp.write("%s\n"%(file[file.rindex("/")+1:]))
							outFileFp.write(fp.read())
							outFileFp.write("\n\n")
					

if __name__ == "__main__":
	main()
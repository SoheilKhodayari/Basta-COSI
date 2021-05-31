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
    Generate all CSV test reports for each of the tested COSI attack classes.
"""


from subprocess import call
import os
import sys
import time
BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def main():
	if len(sys.argv)!= 2:
		print "Script-Usage: you must provide siteId as argument, e.g.\n'python gen-summary-csv.py siteId'"
		return 0
	site_id = sys.argv[1]

	sites= [site_id]
	os.chdir(BASE_DIR) #change dir to current dir
	for siteId in sites:
		Commands = [
		"python gen-summary-csv.py %s"%siteId,
		"python gen-summary-report.py %s"%siteId,
		"python gen-efc-summary-table.py %s"%siteId,
		"python gen-efc-summary-table-vuln.py %s"%siteId,
		"python gen-efc-vuln-report.py %s"%siteId,
		"python gen-csp-summary-table.py %s"%siteId,
		"python gen-csp-summary-table-vuln.py %s"%siteId,
		"python gen-csp-vuln-report.py %s"%siteId,
		"python gen-cw-summary-table.py %s"%siteId,
		"python gen-cw-summary-table-vulnerability.py %s"%siteId,
		"python gen-script-errs-vuln-report.py %s"%siteId,
		"python gen-script-vars-vuln-report.py %s"%siteId,
		"python gen-cw-summary-table.py %s"%siteId,
		"python gen-cw-summary-table-vulnerability.py %s"%siteId,
		"python gen-op-summary-report.py %s"%siteId,
		"python gen-op-summary-table.py %s"%siteId,
		"python gen-op-summary-table-vuln.py %s"%siteId,
		#"python gen-pm-report.py %s"%siteId
		]
		for cmd in Commands:
			try:
				os.system(cmd)
				time.sleep(1)
			except:
				continue


if __name__ == "__main__":
	main()
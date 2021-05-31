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

def main():
	if len(sys.argv)!= 2:
		print "Script-Usage: you must provide siteId as argument, e.g.\n'python gen-summary-csv.py siteId'"
		return 0
	siteId = sys.argv[1]


	AUTOMATOR_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
	ROOT_DIR = os.path.join(AUTOMATOR_DIR, "%s/urls/redirectChains/"%siteId)
	from datetime import datetime
	timestamp = datetime.now().strftime('%d/%m/%Y at %H:%M:%S')
	for subdir, dirs, files in os.walk(ROOT_DIR):
		list_files = glob.glob(subdir+"/*summary.out")
		if len(list_files) != 0:
			file = list_files[0] # get the first file matching the naming requirement
			with open(subdir+"/report-comparison.out", "wb") as outFileFp:
				outFileFp.write("======================================================================\n")
				outFileFp.write("[Subject]: Comparsion Report\n")
				outFileFp.write("[DateTime]: %s\n"%timestamp )
				outFileFp.write("======================================================================\n\n\n")
				fileContent= ''
				with open(file, "r") as fp:
					fileContent = fp.read()
					fileContentList = fileContent.split("===================================================================\n===================================================================")
					for item in fileContentList:
						itemAsList = item.split("---------------------------------------------\n")
						response_codes = itemAsList[1]
						response_urls = itemAsList[2]
						response_headers = itemAsList[3]
						response_bodies = itemAsList[4]

						response_codes_as_list = response_codes.split("\n")
						stateLineItem1 = response_codes_as_list[0]
						stateLineItem2 = response_codes_as_list[0+1]
						if len(stateLineItem1)>5:  #make sure no empty string
							respononse_chain_i1 = stateLineItem1.split(":")[1].strip();
							respononse_chain_i2 = stateLineItem2.split(":")[1].strip()
							if respononse_chain_i1 != respononse_chain_i2:
								outFileFp.write(item)
								continue
								#print item

						response_urls_as_list = response_urls.split("\n")
						stateLineItem1 = response_urls_as_list[0]
						stateLineItem2 = response_urls_as_list[0+1]
						if len(stateLineItem1)>5:  #make sure no empty string
							respononse_chain_i1 = stateLineItem1.split(":")[1].strip();
							respononse_chain_i2 = stateLineItem2.split(":")[1].strip()
							if respononse_chain_i1 != respononse_chain_i2:
								outFileFp.write(item)
								continue
								#print item			

						response_bodies_as_list = response_bodies.split("\n")
						stateLineItem1 = response_bodies_as_list[0]
						stateLineItem2 = response_bodies_as_list[0+1]
						if len(stateLineItem1)>5:  #make sure no empty string
							respononse_chain_i1 = stateLineItem1.split(":")[1].strip();
							respononse_chain_i2 = stateLineItem2.split(":")[1].strip()
							if respononse_chain_i1 != respononse_chain_i2:
								outFileFp.write(item)
								continue
								#print item		

						response_headers_as_list = response_headers.split("\n")
						stateLineItem1 = response_headers_as_list[0]
						stateLineItem2 = response_headers_as_list[0+1]

						idx1 = stateLineItem1.index("Response_Header_Chain")
						sItem1 = stateLineItem1[idx1+len("Response_Header_Chain")+1:].strip() #plus 1 to remove semicolon
						sItem1 = eval(sItem1) # eval to list
						# get the hedaer for last response 
						sItem1Last = sItem1[-1]

						idx2 = stateLineItem2.index("Response_Header_Chain")
						sItem2 = stateLineItem2[idx2+len("Response_Header_Chain")+1:].strip() #plus 1 to remove semicolon
						sItem2 = eval(sItem2) # eval to list
						# get the hedaer for last response 
						sItem2Last = sItem2[-1]

						haveDiffInHeader= False
						for header1Item in sItem1Last:
							for header2Item in sItem2Last:
								if ('Date' in header1Item) or ('Date' in header2Item) or \
									('Expires' in header1Item) or ('Expires' in header2Item) or \
									('Last-Modified' in header1Item) or ('Last-Modified' in header2Item):
									continue
								if ('Content-Type' in header1Item) and ('Content-Type' in header2Item) and \
								  ("X-Content-Type-Options"not in header1Item) and ("X-Content-Type-Options" not in header2Item):
									if str(header1Item) != str(header2Item):
										haveDiffInHeader = True
								if ('Content-Length' in header1Item) and ('Content-Length' in header2Item):
									if str(header1Item) != str(header2Item):
										haveDiffInHeader = True
								if ('Content-Security-Policy' in header1Item) and ('Content-Security-Policy' in header2Item):
									if str(header1Item) != str(header2Item):
										haveDiffInHeader = True	
								if ('X-Frame-Options' in header1Item) and ('X-Frame-Options' in header2Item):
									if str(header1Item) != str(header2Item):
										haveDiffInHeader = True	
								if ('X-XSS-Protection' in header1Item) and ('X-XSS-Protection' in header2Item):
									if str(header1Item) != str(header2Item):
										haveDiffInHeader = True

						if haveDiffInHeader:
							outFileFp.write(item)
							continue


if __name__ == "__main__":
	main()
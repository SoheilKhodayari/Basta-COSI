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
	ROOT_DIR = os.path.join(AUTOMATOR_DIR, "%s/TestReports/"%siteId)

	for subdir, dirs, files in os.walk(ROOT_DIR):
		list_files = glob.glob(subdir+"/*.csv")
		if len(list_files) != 0:
			with open(subdir+"/report-summary.out", "wb") as outFileFp:
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
								url = line.split(", ")[0].strip()
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
						for url in ListOfAllDistinctURLs_AtHand:
							outFileFp.write("URL: "+url+"\n")
							for fileObject in ListOfFilesWithSimilarNamesAndHeader:
								fileLines = fileObject[1]
								datetime = fileObject[2]
								for lineIdx in range(len(fileLines)):
									if lineIdx == 0: continue
									line = fileLines[lineIdx]
									urlCompare = line.split(", ")[0].strip()	
									if url == urlCompare and url!= "":
										results = line[line.index(", ")+1:]
										if not results.endswith("\n"):
											results = results+ "\n"
										outFileFp.write(results)
							outFileFp.write("\n")

if __name__ == "__main__":
	main()


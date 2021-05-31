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
    In memory storage for logging.
	@DEPRECATED This script belongs to an older version of Basta-COSI.

"""

from __future__ import unicode_literals

from django.apps import AppConfig
import os
from datetime import datetime

# --------------------------------------------------------------------------- #
#								General
# --------------------------------------------------------------------------- #

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# --------------------------------------------------------------------------- #
#						Post Message & Content Window
# --------------------------------------------------------------------------- #

FRAMED_URLS = {} #in memory storage to save framed urls
IN_MEM_DB = {} # in memory storage to save messages
FRAME_COUNTS = {"L": {"Fr":{}, "Wd": {}}, "N": {"Fr":{}, "Wd": {}}}

# --------------------------------------------------------------------------- #
#                       Content Window
# --------------------------------------------------------------------------- #

CONTENT_WINDOW = {"L": {}, "N": {}, "F": {}}

def _clear_content_window_memory():
    global CONTENT_WINDOW
    CONTENT_WINDOW = {"L": {}, "N": {}, "F": {}}


# USES _get_last_timestamp()
# USES _get_current_timestamp()

# --------------------------------------------------------------------------- #
#						Script Inclusion Attack
# --------------------------------------------------------------------------- #

LAST_TIME_STAMP = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
SITE_IDS_ATTACKED = [] 

def _get_last_timestamp():
	global LAST_TIME_STAMP
	return LAST_TIME_STAMP

def _get_current_timestamp():
	global LAST_TIME_STAMP
	LAST_TIME_STAMP = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
	return LAST_TIME_STAMP

def _site_ids_attacked():
	global SITE_IDS_ATTACKED
	return SITE_IDS_ATTACKED

def _clear_site_ids_attacked():
    global SITE_IDS_ATTACKED
    SITE_IDS_ATTACKED = []
    
def _append_site_ids_attacked(siteId):
	global SITE_IDS_ATTACKED
	SITE_IDS_ATTACKED.append(siteId)
# --------------------------------------------------------------------------- #
#							Startup Config Class
# --------------------------------------------------------------------------- #
class LogmainConfig(AppConfig):
    name = 'logmain'

    def ready(self):

    	# -- begin post message ------------------------- #

    	global FRAMED_URLS 
    	FRAMED_URLS = {}
    	global IN_MEM_DB
    	IN_MEM_DB = {}
    	global FRAME_COUNTS
    	FRAME_COUNTS = {"L": {"Fr":{}, "Wd": {}}, "N": {"Fr":{}, "Wd": {}}}

    	# -- end post message --------------------------- #

        global LAST_TIME_STAMP
    	LAST_TIME_STAMP = _get_current_timestamp()
        global SITE_IDS_ATTACKED
    	SITE_IDS_ATTACKED = []

        global CONTENT_WINDOW
        CONTENT_WINDOW = {"L": {}, "N": {}, "F": {}}




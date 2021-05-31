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
	------------------
	Test for Attack Page Generator (Version 1)

"""


import os
import sys
import uuid

# import the lib
PLUGINS_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LIB_DIR = os.path.join(PLUGINS_DIR, "apg_module")
sys.path.insert(0, LIB_DIR)
from attack_page_generator import AttackPageGenerator


def _generate_uuid():
	return str(uuid.uuid4())


def main():
	_uuid = _generate_uuid()
	kwargs = {"name": "test-attack-page"}
	apg_instance = AttackPageGenerator(_uuid, **kwargs)

	# interface 1
	inclusion_url = "https://www.myinclusionurl.com"
	tag_event_dictionary = {"script": ["onload", "onerror"], "object": ["onload", "onerror"] }
	report_uri = "https://www.myreporturi.com"

	attack_page = apg_instance.get_ef_attack_page(inclusion_url, tag_event_dictionary, report_uri)
	
	with open("test-page-1.html", "wb") as fp:
		fp.write(attack_page)


	# interface 2
	inclusion_url_1 = "https://www.myinclusionurl1.com"
	inclusion_url_2 = "https://www.myinclusionurl2.com"
	tag_event_and_target_dict = {"script": {"events": ["onload", "onerror"],"inclusion_url": inclusion_url_1},
							"object": {"events": ["onerror"], "inclusion_url": inclusion_url_2}}
	report_uri = "https://www.myreporturi.com"
	attack_page_mult = apg_instance.get_ef_attack_page_multiple_inclusion(tag_event_and_target_dict, report_uri)

	with open("test-page-2.html", "wb") as fp:
		fp.write(attack_page_mult)

if __name__ == "__main__":
	main()
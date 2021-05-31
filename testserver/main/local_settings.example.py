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
	
	Usage:
	---------------
	- Add a site entry in the `site_dict` dictionary for testing, with the integer id `XYZ`
	- Copy and rename the `automator/site-template` folder to `automator/XYZ`
	- Rename this file from `local_setttings.example.py` to `local_settings.py`

"""



# TODO: place your input sites here for testing
# Each entry contains:
# 	key: site id which specifies the site rank (e.g., Alexa ranking)
# 	value [0]: site seed URL
# 	value [1]: site name
# See example below.

site_dict= {
	'1': ('https://www.google.com', 'google'), 	
}










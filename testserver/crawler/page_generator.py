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
	-------------
	COSI test attack page generator utility functions

"""

def _get_base_dom_document(document_title):
	document = '''
		<!DOCTYPE html>
		<html>
		<head>
		    <title>%s</title>
		    <meta charset="utf-8">
		</head>
		<body>
		<script src="https://ajax.googleapis.com/ajax/libs/jquery/3.1.0/jquery.min.js"></script>
		</body>
		</html>
	  '''%(document_title)

	return document

# Note: Frame and FrameSet are not supported in HTML5
def _get_base_dom_document_with_frameset(document_title):
	document = '''
		<!DOCTYPE html>
		<html>
		<head>
		    <title>%s</title>
		    <meta charset="utf-8">
		    <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.1.0/jquery.min.js"></script>
		</head>
		<frameset id='frameset-container'>
		</frameset>
		</html>
	  '''%(document_title)

	return document

def _include_tag_in_head(html, tag_as_string):

	head_idx = html.find("</head>")
	html_low_part = html[:head_idx]
	html_high_part = html[head_idx:]

	return html_low_part + tag_as_string + html_high_part

def _include_tag_in_body(html, tag_as_string):

	body_idx = html.rfind("</body>")
	html_low_part = html[:body_idx]
	html_high_part = html[body_idx:]

	return html_low_part + tag_as_string + html_high_part


def _get_corresponding_attribute(tag_name):
	if tag_name == "img" or tag_name == "video" or tag_name == "audio" \
		or tag_name == "script" or tag_name == "track" or tag_name == "embed" \
		or tag_name == "iframe" or tag_name == "source" or tag_name == "input" \
		or tag_name == "frame":
		attribute = "src"
	elif tag_name == "applet":
		attribute = "code"
	elif tag_name == "link" or tag_name == "link_stylesheet" or tag_name == "link_prefetch" \
	 	or tag_name == "link_preload_style" or tag_name == "link_preload_script":
		attribute = "href"
	elif tag_name == "object":
		attribute = "data"
	elif tag_name == "videoPoster":
		attribute= "poster"
	return attribute

def _attach_element(html, tag, inclusion_url):
	attribute = _get_corresponding_attribute(tag)
	js = '''
		<script type="text/javascript">
			var tag = document.createElement("%s")
			tag.setAttribute("%s", "%s");
			document.body.appendChild(tag);
		</script>
	'''%(tag, attribute, inclusion_url)
	if tag == "frame":
		html = _include_tag_in_head(html, js)
	else:
		html = _include_tag_in_body(html, js)
	return html

def get_str_crawler_request_page(inclusion_list):
	"""
		create the page that sends a cross-origin request (through browser) to the inclusion resources
	"""
	_document_title = "COSICrawler" 
	_default_tag = "object"
	html = _get_base_dom_document(_document_title)
	for inclusion_url in inclusion_list:
		html = _attach_element(html, _default_tag, inclusion_url)

	return html
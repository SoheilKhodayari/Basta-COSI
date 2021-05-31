"""
Author: Avinash Sudhodanan
Contact: firstname.lastname@imdea.org
Project: ElasTest, COSI
Description: This code can be included as a library
             to identify the ways to differentiate between
             two different HTTP responses
"""
from pprint import pprint
import xlrd # Reading an excel file using Python
import os
import re


# --------------------------------------------------------------------- #
#               Constants
# --------------------------------------------------------------------- #
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# --------------------------------------------------------------------- #



class COSIAttackFinder(object):
    """
        COSIAttackFinder Class
    """
    def __init__(self, *args, **kwargs):
        super(COSIAttackFinder, self).__init__(*args, **kwargs)

        _DEFAULT_DEBUG= False
        if "debug" in kwargs:
            self._debug= kwargs["debug"]
        else:
            self._debug = _DEFAULT_DEBUG

    @staticmethod
    def strlist_to_list(strlist):
        """Converts a string representation of list to a list
        Args:
        strlist: string representation of the list
        Returns:
        The list representation of the input string
        """
        lst = []
        for event in strlist.lstrip('[').rstrip(']').split(','):
            lst.append(event.lstrip().rstrip().lstrip('\'').rstrip('\''))
        return lst

    @staticmethod
    def open_workbook(location):
        """Returns the 0th sheet of a .xslx workbook
        Args:
        location: the location of the .xslx workbook
        Returns:
        The pointer to the sheet of the .xslx workbook
        """
        workbook = xlrd.open_workbook(location)
        sheet = workbook.sheet_by_index(0)
        return sheet

    def _clean_event_props(self, inclusion_str):
        """
            cleans all the event listeners on the inclusion string
        """
        pattern = r"on[A-Za-z]+=\".*\""
        out = re.sub(pattern, "", inclusion_str)
        return out

    def get_attack_inclusion(self,
                             state_a_res_code, state_a_cto, state_a_ctype, state_a_xfo, state_a_cd,
                             state_b_res_code, state_b_cto, state_b_ctype, state_b_xfo, state_b_cd,
                             browser, browser_version):
        """Returns the inclusions that can be performed for
           differentiating between the two input states
        Args:
        state_a_res_code: the HTTP response code of State A
        state_a_cto: the HTTP response's X-Content-Type-Options settings of State A
        state_a_ctype: the HTTP response content type of State A
        state_a_xfo: the HTTP response's X-Frame-Options settings of State A
        state_a_cd: the HTTP response's Content-Disposition header's value for State A
        state_b_res_code: the HTTP response code of State B
        state_b_cto: the HTTP response's X-Content-Type-Options settings of State B
        state_b_ctype: the HTTP response content type of State B
        state_b_xfo: the HTTP response's X-Frame-Options settings of State B
        state_b_cd: the HTTP response's Content-Disposition header's value for State B
        browser: The browser for which the attack needs to be performed
        browser_version: The browser version for which the attack needs to be performed
        Returns:
        A list of dictionaries where each item represents an inclusion strategy.
        Each dictionary item has the following keys
        inclusion: the exact inclusion that needs to be used in the attack page.
                   the value INCLUDED_URL shuld be replaced with the URL of the response
        method:
        state_a_events:
        state_b_events:
        """
        attack_vectors=["events_fired","appcache"]
        efc_tags = ["script","img","iframe","object","link"]
        cosi_attacks = []
        for attack_vector in attack_vectors:
            if attack_vector == "events_fired" and browser in ["firefox"]:
                for efc_tag in efc_tags:
                    workbook_name = efc_tag + "_tag_test_log_"+ browser + ".xlsx"
                    workbook_path = os.path.join(BASE_DIR, "reports")
                    workbook_path_name = os.path.join(workbook_path, workbook_name)
                    sheet = self.open_workbook(workbook_path_name)
                    # For row 0 and column 0
                    previous_inclusion = sheet.cell_value(1, 2)
                    events_a = None
                    events_b = None
                    for row in range(1, sheet.nrows):
                        if sheet.cell_value(row, 2) != previous_inclusion:
                            if self._debug: print("")
                            if (events_a is not None and events_b is not None and events_a != events_b):
                                inc = self._clean_event_props(previous_inclusion)
                                cosi_attacks.append({"inclusion" : inc,
                                                     "method" : "events_fired",
                                                     "state_a_events" : events_a,
                                                     "state_b_events" : events_b})
                            events_triggered_a = None
                            events_triggered_b = None
                            previous_inclusion = sheet.cell_value(row, 2)
                        state_b_res_code, state_b_cto, state_b_ctype, state_b_xfo, state_b_cd,
                        if(state_a_res_code == sheet.cell_value(row, 3) and
                           state_a_cto == sheet.cell_value(row, 4) and
                           state_a_ctype == sheet.cell_value(row, 5) and
                           state_a_xfo == sheet.cell_value(row, 6) and
                           sheet.cell_value(row, 7) in state_a_cd and
                           browser == sheet.cell_value(row, 9) and
                           browser_version == sheet.cell_value(row, 10)):
                            events_triggered_a = sheet.cell_value(row, 8)
                            events_a = self.strlist_to_list(events_triggered_a)
                            events_a.sort()
                            if self._debug: print(events_a)
                        if(state_b_res_code == sheet.cell_value(row, 3) and
                           state_b_cto == sheet.cell_value(row, 4) and
                           state_b_ctype == sheet.cell_value(row, 5) and
                           state_b_xfo == sheet.cell_value(row, 6) and
                           sheet.cell_value(row, 7) in state_b_cd and
                           browser == sheet.cell_value(row, 9) and
                           browser_version == sheet.cell_value(row, 10)):
                            events_triggered_b = sheet.cell_value(row, 8)
                            events_b = self.strlist_to_list(events_triggered_b)
                            events_b.sort()
                            if self._debug: print(events_b)
                    if(events_a is not None and events_b is not None and events_a != events_b):
                        if self._debug: print (events_a is not events_b)
                        if self._debug: print(type(events_a),type(events_b))
                        inc = self._clean_event_props(previous_inclusion)
                        cosi_attacks.append({"inclusion" : inc,
                                             "method" : "events_fired",
                                             "state_a_events" : events_a,
                                             "state_b_events" : events_b})
                
            elif attack_vector == "appcache" and browser in ["chrome", "opera"]:
                if state_a_res_code.startswith("2") and (state_b_res_code.startswith("3") or state_b_res_code.startswith("4") or state_b_res_code.startswith("5")):
                    cosi_attacks.append({"inclusion" : "<link rel=\"prefetch\" href=\"INCLUDED_URL\">",
                                                "method" : "appcache",
                                                "state_a_events" : [],
                                                "state_b_events" : ["error"]})
                elif state_b_res_code.startswith("2") and (state_a_res_code.startswith("3") or state_a_res_code.startswith("4") or state_a_res_code.startswith("5")):
                    cosi_attacks.append({"inclusion" : "<link rel=\"prefetch\" href=\"INCLUDED_URL\">",
                                                "method" : "appcache",
                                                "state_a_events" : ["error"],
                                                "state_b_events" : []})
        if self._debug: print("\nThe following are the matches:")
        if self._debug: pprint(cosi_attacks)
        return cosi_attacks

if __name__ == "__main__":
    OBJECT_CAF = COSIAttackFinder()
    OBJECT_CAF.get_attack_inclusion("200", "enabled", "application/pdf", "disabled", "inline",
                                          "302", "enabled", "text/html", "disabled", "disabled",
                                          "chrome", "60.0")

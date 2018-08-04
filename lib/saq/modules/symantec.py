# vim: sw=4:ts=4:et

import logging
import re

import saq

from saq.analysis import Analysis, DetectionPoint, Observable
from saq.constants import *
from saq.modules import SplunkAnalysisModule, splunktime_to_saqtime
from saq.modules.asset import NetworkIdentifierAnalysis

PATH_REGEX = re.compile(r'^[a-zA-Z]:')

class SymantecAnalysis(Analysis):
    """Did Symantec detect anything on this asset?"""

    def initialize_details(self):
        self.details = None # free form

    @property
    def jinja_template_path(self):
        return "analysis/symantec_analysis.html"

    def generate_summary(self):
        if isinstance(self.details, list) and len(self.details) > 0:
            return "Symantec Identified Risks ({0} events)".format(len(self.details))
        return None

class SymantecAnalyzer(SplunkAnalysisModule):
    @property
    def generated_analysis_type(self):
        return SymantecAnalysis

    @property
    def valid_observable_types(self):
        return ( F_IPV4, F_HOSTNAME )

    def execute_analysis(self, observable):

        # get all the symantec alerts for this ipv4 address
        if observable.type == F_IPV4:
            query = 'index=symantec ( sourcetype=sep12:risk OR sourcetype=sep12:ids ) {0} | search dest_ip = {0} | fields _time, dest_ip, dest_nt_host, dest_nt_domain, event_time, requested_action, actual_action, hash_value, user, downloaded_by, process, signature'.format(observable.value, observable.value)
        elif observable.type == F_HOSTNAME:
            query = 'index=symantec ( sourcetype=sep12:risk OR sourcetype=sep12:ids ) {0} | search src = {0} | fields _time, dest_ip, dest_nt_host, dest_nt_domain, event_time, requested_action, actual_action, hash_value, user, downloaded_by, process, signature'.format(observable.value, observable.value)

        self.splunk_query(query, self.root.event_time_datetime if observable.time_datetime is None else observable.time_datetime)

        if self.search_results is None:
            logging.debug("missing search results after splunk query")
            return False

        analysis = self.create_analysis(observable)
        analysis.details = self.json()

        if isinstance(analysis.details, list) and len(analysis.details) > 0:
            for event in analysis.details:
                observable.add_tag('av:{}'.format(event['signature']))

                # pull the file path out
                if 'process' in event and event['process'] and len(event['process']) > 0:
                    file_path = analysis.add_observable(F_FILE_PATH, event['process'])

                    # is this a USB drive?
                    if PATH_REGEX.search(event['process']) and not event['process'].lower().startswith('c:'):
                        file_path.add_tag('usb')

                #if 'username' in event and event['username'] is not None:
                    #temp = event['username']
                    #if not isinstance(event['username'], list):
                        #temp = [event['username']]

                    #for username_entry in temp:
                        #if username_entry == '-':
                            #pass

                    #analysis.add_observable(F_USER, username_entry)

                #if 'src_ip' in event and event['src_ip'] is not None and event['src_ip'] != '-':
                    #analysis.add_observable(F_IPV4, event['src_ip'], splunktime_to_saqtime(event['_time']))
                    #analysis.add_observable(F_IPV4, event['src_ip'])

        return True

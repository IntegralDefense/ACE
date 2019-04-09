# vim: sw=4:ts=4:et

import logging

import saq
from saq.analysis import Analysis, Observable
from saq.modules import SplunkAnalysisModule, splunktime_to_datetime
from saq.constants import *

class PanThreatsAnalysis(Analysis):
    """What are the PaloAlto alerts for this ip address?"""

    def initialize_details(self):
        self.details = None # free form from results

    @property
    def jinja_template_path(self):
        return "analysis/pan_threats.html"

    def generate_summary(self):
        if isinstance(self.details, list) and len(self.details) > 0:
            return "Palo Alto Threats ({0} alerts)".format(len(self.details))
        return None

class PanThreatsAnalyzer(SplunkAnalysisModule):
    @property
    def generated_analysis_type(self):
        return PanThreatsAnalysis

    @property
    def valid_observable_types(self):
        return F_IPV4

    def execute_analysis(self, ipv4):

        self.splunk_query('index=pan_logs sourcetype=pan_threat log_subtype != file {0} | sort _time | fields _time action src_ip src_port dst_ip dst_port transport filename threat_name threat_id'.format(ipv4.value), 
            self.root.event_time_datetime if ipv4.time_datetime is None else ipv4.time_datetime)

        if self.search_results is None:
            logging.debug("missing search results after splunk query")
            return False

        analysis = self.create_analysis(ipv4)
        analysis.details = self.json()
        return True

class PanSnortCorrelationAnalysis(Analysis):
    """Given a snort alert and dest+src+src_port, what PAN blocks did we see around the same time?"""
    def initialize_details(self):
        self.details = [ ]

    @property
    def jinja_template_path(self):
        return 'analysis/pan_snort_correlation.html'

    def generate_summary(self):
        if not self.details:
            return None

        action_counts = {}
        for result_group in self.details:
            for row in result_group:
                if 'action' in row:
                    if row['action'] not in action_counts:
                        action_counts[row['action']] = 0
                    action_counts[row['action']] += 1
            
        return "Pan - Snort Correlation Analysis ({})".format(' '.join(['{} {}'.format(action_counts[action], action) for action in action_counts.keys()]))
    
class PanSnortCorrelationAnalyzer(SplunkAnalysisModule):
    @property
    def generated_analysis_type(self):
        return PanSnortCorrelationAnalysis

    @property
    def valid_observable_types(self):
        return F_IPV4_CONVERSATION

    def execute_analysis(self, ipv4_conversation):

        if self.root.alert_type != 'splunk - snort':
            logging.info("MARKER: invalid alert_type")
            return False

        analysis = self.create_analysis(ipv4_conversation)

        # we also need the source port so we'll pull what we need out of the alert details
        ipv4s = parse_ipv4_conversation(ipv4_conversation.value)
        for row in self.root.details:
            if row['src_ip'] in ipv4s and row['dest_ip'] in ipv4s:
                ipv4_source = row['src_ip']
                ipv4_dest = row['dest_ip']
                ipv4_source_port = row['src_port']
                target_time = splunktime_to_datetime(row['_time'])

                self.splunk_query(f'index=pan_logs sourcetype=pan:threat {ipv4_source} AND {ipv4_dest} AND src_port={ipv4_source_port} | fields *', target_time)

                if self.search_results is None:
                    return False

                analysis.details.append(self.json())

        return True

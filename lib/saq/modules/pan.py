# vim: sw=4:ts=4:et

import logging

import saq
from saq.analysis import Analysis, Observable
from saq.modules import SplunkAnalysisModule
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


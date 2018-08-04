# vim: sw=4:ts=4:et

import logging
import os.path

from subprocess import Popen, PIPE

from saq.analysis import Analysis, Observable
from saq.modules import SplunkAnalysisModule, AnalysisModule
from saq.constants import *

class SnortAlertsAnalysis(Analysis):
    """What are all the snort alerts for this ip address?"""

    def initialize_details(self):
        self.details = None # free form from results

    @property
    def jinja_template_path(self):
        return "analysis/snort.html"

    def generate_summary(self):
        if isinstance(self.details, list) and len(self.details) > 0:
            return "Snort Alerts ({0} alerts)".format(len(self.details))

        return None

class SnortAlertsAnalyzer(SplunkAnalysisModule):
    @property
    def generated_analysis_type(self):
        return SnortAlertsAnalysis

    @property
    def valid_observable_types(self):
        return F_IPV4

    def execute_analysis(self, ipv4):

        self.splunk_query("""
index=snort {0}
    | sort _time 
    | fields 
        _time 
        Ack 
        Seq 
        category 
        dest_ip 
        dest_port 
        name 
        signature 
        eventtype 
        priority 
        proto 
        severity 
        signature 
        signature_rev 
        src_ip 
        src_port 
        tag""".format(ipv4.value), 
            self.root.event_time_datetime if ipv4.time_datetime is None else ipv4.time_datetime)

        if self.search_results is None:
            logging.debug("missing search results after splunk query")
            return False

        analysis = self.create_analysis(ipv4)
        analysis.details = self.json()
        return True

KEY_SIGNATURE_ID = 'signature_id'
KEY_SIGNATURE = 'signature'

class SnortSignatureAnalysis_v1(Analysis):
    """What is the actual signature used by snort to fire this detection?"""

    def initialize_details(self):
        self.details = {
            KEY_SIGNATURE_ID: None,
            KEY_SIGNATURE: 'unknown signature (rules not updating?)' }

    @property
    def signature_id(self):
        return self.details[KEY_SIGNATURE_ID]

    @signature_id.setter
    def signature_id(self, value):
        self.details[KEY_SIGNATURE_ID] = value

    @property
    def signature(self):
        return self.details[KEY_SIGNATURE]

    @signature.setter
    def signature(self, value):
        self.details[KEY_SIGNATURE] = value

    def generate_summary(self):
        if self.signature_id is not None and self.signature is not None:
            return "Snort Signature Analysis - ({0}) {1}".format(self.signature_id, self.signature)

        return None

    @property
    def jinja_is_drillable(self):
        return False

class SnortSignatureAnalyzer_v1(AnalysisModule):
    def verify_environment(self):
        self.verify_config_exists('rules_dir')
        self.verify_path_exists(self.config['rules_dir'])

    @property
    def rules_dir(self):
        return self.config['rules_dir']

    @property
    def generated_analysis_type(self):
        return SnortSignatureAnalysis_v1

    @property
    def valid_observable_types(self):
        return F_SNORT_SIGNATURE

    def execute_analysis(self, snort_sig):

        analysis = self.create_analysis(snort_sig)
        logging.debug("searching snort rules for {0}".format(snort_sig.value))
        p = Popen(['grep', '-h', '-r', 'sid:{0};'.format(snort_sig.value), self.rules_dir], stdout=PIPE, universal_newlines=True)
        analysis.signature_id = snort_sig.value
        analysis.signature, _ = p.communicate()
        p.wait() # needed?

        return True

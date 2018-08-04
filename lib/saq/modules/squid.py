# vim: sw=4:ts=4:et

import csv
import logging
import os.path

from urllib.parse import urlparse

import saq

from saq.analysis import Analysis, Observable
from saq.constants import *
from saq.modules import SplunkAnalysisModule, splunktime_to_saqtime

KEY_RESULTS = 'results'

class SquidProxyAnalysisByDestination(Analysis):
    """Were there any requests for this destination made by the squid proxy?"""
    
    def initialize_details(self):
        self.details = { KEY_RESULTS: None }

    @property
    def results(self):
        if not self.details:
            return None

        if KEY_RESULTS not in self.details:
            return None

        return self.details[KEY_RESULTS]

    def generate_summary(self):
        if not self.results:
            return None

        return "Squid Proxy Analysis ({} requests)".format(len(self.results))

class SquidProxyAnalyzerByDestination(SplunkAnalysisModule):
    def verify_environment(self):
        self.verify_config_exists('max_request_count')

    @property
    def max_request_count(self):
        return self.config.getint('max_request_count')

    @property
    def generated_analysis_type(self):
        return SquidProxyAnalysisByDestination

    @property
    def valid_observable_types(self):
        return F_IPV4, F_FQDN, F_URL

    def execute_analysis(self, observable):


        query_broad_filter = None
        query_fine_filter = None
        if observable.type == F_IPV4:
            query_broad_filter = observable.value
            query_fine_filter = 'dest_ip={}'.format(observable.value)
        elif observable.type == F_FQDN:
            query_broad_filter = observable.value
            query_fine_filter = 'dest="*{}*"'.format(observable.value)
        else:
            try:
                parsed_url = urlparse(observable.value)
                # if the URL does not have a schema then we assume http and re-parse
                if parsed_url.scheme == '':
                    parsed_url = urlparse('http://{0}'.format(observable.value))

                query_broad_filter = '"{}" AND "{}"'.format(parsed_url.netloc, parsed_url.path)
                query_fine_filter = 'uri_host="*{}*" AND uri_path="*{}*"'.format(parsed_url.netloc, parsed_url.path)
            except Exception as e:
                logging.warning("unable to parse url {}: {}".format(observable.value, e))
                return False

        self.relative_duration_before = self.config['relative_duration_before']
        self.relative_duration_after = self.config['relative_duration_after']

        self.splunk_query("""index=squid {} | search {} | head limit={} | fields *""".format(query_broad_filter, query_fine_filter, self.max_request_count))
        results = self.json()

        if not results:
            return False

        analysis = self.create_analysis(observable)
        analysis.details[KEY_RESULTS] = results

        # add any source IP addresses as observables
        # these will most likely get flagged as infosec
        for entry in analysis.results:
            if 'src_ip' in entry:
                analysis.add_observable(F_IPV4, entry['src_ip'])

        return True

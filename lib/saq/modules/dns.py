# vim: sw=4:ts=4:et

import csv
import logging
import os.path

from urllib.parse import urlparse

import saq

from saq.analysis import Analysis, Observable
from saq.constants import *
from saq.modules import SplunkAnalysisModule, splunktime_to_saqtime

KEY_SOURCE_COUNT = 'src_count'
KEY_REQUEST_BREAKDOWN = 'request_breakdown'
KEY_REQUEST_BREAKDOWN_DOMAIN = 'domain'
KEY_REQUEST_BREAKDOWN_COUNT = 'src_count'
KEY_REQUEST_BREAKDOWN_DOMAIN_COUNT = 'domain_count'
KEY_REQUEST_BREAKDOWN_TOTAL_COUNT = 'total_count'
KEY_DNS_REQUESTS = 'dns_requests'

#
# Module:   DNS Request Analysis
# Question: Who requested DNS resolution for this FQDN?
# Question: How common is it to request this domain or something from this domain?
#

class DNSRequestAnalysis_v1(Analysis):
    """Who requested DNS resolution for this FQDN?  How common is it to request this domain or something from this domain?"""

    def initialize_details(self):
        self.details = {
            # how many distinct SRC_IP in the X minutes surrounding the alert
            KEY_SOURCE_COUNT: None,
            KEY_REQUEST_BREAKDOWN: None,
            KEY_DNS_REQUESTS: None }

    @property
    def source_count(self):
        """Returns the number of distinct SRC_IP in the X minutes surrounding the event"""
        return self.details[KEY_SOURCE_COUNT]

    @source_count.setter
    def source_count(self, value):
        if isinstance(value, str):
            value = int(value)

        self.details[KEY_SOURCE_COUNT] = value

    @property
    def request_breakdown(self):
        """Returns a breakdown of frequency of each component of the domain."""
        return self.details[KEY_REQUEST_BREAKDOWN]

    @request_breakdown.setter
    def request_breakdown(self, value):
        self.details[KEY_REQUEST_BREAKDOWN] = value

    @property
    def dns_requests(self):
        """Returns all the DNS reqeuests made for the FQDN in the X minutes surround the event."""
        return self.details[KEY_DNS_REQUESTS]
        
    @dns_requests.setter
    def dns_requests(self, value):
        self.details[KEY_DNS_REQUESTS] = value

    @property
    def jinja_template_path(self):
        return "analysis/dns_request_analysis_v1.html"

    def generate_summary(self):
        if self.source_count is None:
            return None

        breakdown = ''
        if self.request_breakdown is not None:
            buf = []
            for part in self.request_breakdown:
                buf.append('({0} {1} hosts {2} subdomains {3} requests)'.format(
                    part[KEY_REQUEST_BREAKDOWN_DOMAIN],
                    part[KEY_REQUEST_BREAKDOWN_COUNT],
                    part[KEY_REQUEST_BREAKDOWN_DOMAIN_COUNT],
                    part[KEY_REQUEST_BREAKDOWN_TOTAL_COUNT]))

            breakdown = 'breakdown: {0}'.format(' '.join(buf))

        return "DNS Requests Analysis ({0} hosts) {1}".format(self.source_count, breakdown)

class DNSRequestAnalyzer_v1(SplunkAnalysisModule):

    @property
    def generated_analysis_type(self):
        return DNSRequestAnalysis_v1

    @property
    def valid_observable_types(self):
        return F_FQDN

    def execute_analysis(self, observable):

        # we only run this analysis for observables that came in with the alert
        if observable not in self.root.observables:
            return False

        logging.debug("performing DNS analysis on {}".format(observable.value))

        # first we look at our Windows DNS systems
        query_broad_filter = observable.value
        query_fine_filter = 'domain = {} AND snd_rcv = Snd'.format(observable.value)

        # who made these requests?
        self.relative_duration_before = self.config['relative_duration_before']
        self.relative_duration_after = self.config['relative_duration_after']

        self.splunk_query("""index=dns_logs {} | search {} | stats dc(src_ip) as source_count""".format(
            query_broad_filter, query_fine_filter),
            self.root.event_time_datetime if observable.time_datetime is None else observable.time_datetime)
        
        source_count_results = self.json()

        if source_count_results is None or len(source_count_results) == 0:
            logging.error("got 0 results from a stats command (should not happen)")
            return False

        analysis = self.create_analysis(observable)
        analysis.source_count = source_count_results[0]['source_count']

        # now perform a detailed query for the individual dns requests
        self.splunk_query("""index=dns_logs {} | search {} | head limit={} | fields *""".format(
            query_broad_filter, query_fine_filter, self.config['max_request_count']),
            self.root.event_time_datetime if observable.time_datetime is None else observable.time_datetime)

        if self.search_results is None:
            logging.debug("missing search results after splunk query")
            return True

        analysis.dns_requests = self.json()

        if analysis.source_count > self.config.getint('max_source_count'):
            return True

        requesting_ips = set()
        for event in analysis.dns_requests:
            if 'src_ip' in event:
                requesting_ips.add(event['src_ip'])

        for ipv4 in requesting_ips:
            # decided to not add by time here
            analysis.add_observable(F_IPV4, ipv4)

        # now we do the breakdown analysis
        # but don't try it on PTR lookups
        if observable.value.lower().endswith('.in-addr.arpa'):
            logging.debug("skipping breakdown analysis on in-addr.arpa address {}".format(observable.value))
            return True

        analysis.request_breakdown = []
        parts = observable.value.split('.')
        for index in range(1, len(parts) - 1): # we don't want to analyze the root tld
            fqdn = '.'.join(parts[index:])
            logging.debug("analyzing dns breakdown for {}".format(fqdn))
            
            self.relative_duration_before = self.config['baseline_relative_duration_before']
            self.relative_duration_after = self.config['baseline_relative_duration_after']

            query_broad_filter = fqdn
            query_fine_filter = 'domain = "*.{}" AND snd_rcv = Snd'.format(fqdn)

            self.splunk_query("""index=dns_logs .{} | search {} | stats count as total_count, dc(src_ip) as source_count, dc(domain) as domain_count""".format(
                query_broad_filter, query_fine_filter),
                self.root.event_time_datetime if observable.time_datetime is None else observable.time_datetime)

            search_results = self.json()

            if len(search_results) == 0:
                logging.error("got 0 results from a stats command (should not happen)")
                continue

            analysis.request_breakdown.append({
                KEY_REQUEST_BREAKDOWN_DOMAIN: fqdn,
                KEY_REQUEST_BREAKDOWN_COUNT: search_results[0]['source_count'],
                KEY_REQUEST_BREAKDOWN_DOMAIN_COUNT: search_results[0]['domain_count'],
                KEY_REQUEST_BREAKDOWN_TOTAL_COUNT: search_results[0]['total_count']})

        return True

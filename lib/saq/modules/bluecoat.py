# vim: sw=4:ts=4:et

import csv
import logging
import os.path

from urllib.parse import urlparse

import saq

from saq.analysis import Analysis, Observable
from saq.constants import *
from saq.modules import SplunkAnalysisModule, splunktime_to_saqtime

KEY_USER_COUNT = 'user_count'
KEY_TOTAL_COUNT = 'total_count'
KEY_PROXY_REQUESTS = 'proxy_requests'

#
# Module:   Proxy Request Analysis By Destination
# Question: How many people have requested this resource, and if only a few, what are the details?
#

class BluecoatProxyAnalysisByDestination_v1(Analysis):
    """How many people have requested this resource, and if only a few, what are the details?"""

    def initialize_details(self):
        self.details = {
            KEY_USER_COUNT: None,
            KEY_TOTAL_COUNT: None,
            KEY_PROXY_REQUESTS: None }

    @property
    def user_count(self):
        """Returns the number of distinct users that requested the resource in the 24 hour period prior."""
        return self.details[KEY_USER_COUNT]

    @user_count.setter
    def user_count(self, value):
        if isinstance(value, str):
            value = int(value)

        self.details[KEY_USER_COUNT] = value

    @property
    def total_count(self):
        """Returns the total number of requests for the resource in the 24 hour period prior."""
        return self.details[KEY_TOTAL_COUNT]

    @total_count.setter
    def total_count(self, value):
        if isinstance(value, str):
            value = int(value)

        self.details[KEY_TOTAL_COUNT] = value

    @property
    def proxy_requests(self):
        """Returns the first N proxy requests to this resource."""
        return self.details[KEY_PROXY_REQUESTS]
        
    @proxy_requests.setter
    def proxy_requests(self, value):
        self.details[KEY_PROXY_REQUESTS] = value

    @property
    def jinja_template_path(self):
        return "analysis/bluecoat_proxy_analysis_by_destination_v1.html"

    def generate_summary(self):
        if self.user_count is None:
            return None

        if self.user_count == 0 and self.total_count == 0:
            return None

        return "Proxy Requests By Destination ({0} users {1} total requests)".format(self.user_count, self.total_count)

class BluecoatProxyAnalyzerByDestination_v1(SplunkAnalysisModule):

    def verify_environment(self):
        self.verify_config_exists('max_request_count')
        self.verify_config_exists('max_user_count')
        self.verify_config_exists('category_tag_csv_path')
        self.verify_path_exists(self.config['category_tag_csv_path'])

    @property
    def generated_analysis_type(self):
        return BluecoatProxyAnalysisByDestination_v1

    @property
    def valid_observable_types(self):
        return F_IPV4, F_FQDN, F_URL

    @property
    def category_tag_csv_path(self):
        path = self.config['category_tag_csv_path']
        if os.path.isabs(path):
            return path

        return os.path.join(saq.SAQ_HOME, path)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # load tag settings for bluecoat categories
        self.category_tags = { } # key = category (lowercase), value = tag
        self.watch_file(self.category_tag_csv_path, self.load_category_file)

    def load_category_file(self):
        with open(self.category_tag_csv_path, 'r') as fp:
            for row in csv.reader(fp):
                self.category_tags[row[0]] = row[1]
        
    def execute_analysis(self, observable):

        # we only run this analysis for observables that came in with the alert
        if observable not in self.root.observables:
            return False

        query_broad_filter = None
        query_fine_filter = None
        if observable.type == F_IPV4:
            query_broad_filter = observable.value
            query_fine_filter = 'dst_ip={}'.format(observable.value)
        elif observable.type == F_FQDN:
            query_broad_filter = observable.value
            query_fine_filter = 'uri_host="*{}*"'.format(observable.value)
        else:
            try:
                parsed_url = urlparse(observable.value)
                # if the URL does not have a schema then we assume http and re-parse
                if parsed_url.scheme == '':
                    parsed_url = urlparse('http://{0}'.format(observable.value))

                query_broad_filter = '"{0}" AND "{1}"'.format(parsed_url.netloc, parsed_url.path)
                query_fine_filter = 'uri_host="*{0}*" AND uri_path="*{1}*"'.format(parsed_url.netloc, parsed_url.path)
            except Exception as e:
                logging.warning("unable to parse url {0}: {1}".format(observable.value, str(e)))
                return False

        # now get a baseline to answer the question "how many people requested this in the 24 hour period preceeding the alert?
        # XXX to be replaced by a better baseline system later
        self.relative_duration_before = self.config['baseline_relative_duration_before']
        self.relative_duration_after = self.config['baseline_relative_duration_after']

        self.splunk_query("""index=bluecoat exception_id != "authentication_failed" {0} | search {1} 
    | stats dc(username) as user_count, count as total_count""".format(
            query_broad_filter, query_fine_filter))
        
        baseline = self.json()

        if baseline is None or len(baseline) == 0:
            logging.error("got 0 results from a stats command (should not happen)")
            return False

        if 'user_count' not in baseline[0]:
            logging.error("missing user_count")
            return False

        if 'total_count' not in baseline[0]:
            logging.error("missing total_count")
            return False

        analysis = self.create_analysis(observable)
        analysis.user_count = baseline[0]['user_count']
        analysis.total_count = baseline[0]['total_count'] 

        # now perform a detailed query for the individual proxy requests
        self.relative_duration_before = self.config['relative_duration_before']
        self.relative_duration_after = self.config['relative_duration_after']
        self.splunk_query("""
index=bluecoat {0} 
    | search exception_id != "authentication_failed"  {1}
    | sort _time 
    | head limit={2}
    | fields 
        _time
        src_ip
        username
        uri
        http_method
        http_content_type
        http_status
        http_referrer
        categories
        filter_result""".format(query_broad_filter, query_fine_filter, self.config.getint('max_request_count')),
            self.root.event_time_datetime if observable.time_datetime is None else observable.time_datetime)

        if self.search_results is None:
            logging.debug("missing search results after splunk query")
            return True

        analysis.proxy_requests = self.json()

        if analysis.user_count > self.config.getint('max_user_count'):
            return True

        for event in analysis.proxy_requests:
            # tag the observable based on some bluecoat categories
            for category in self.category_tags.keys():
                if 'categories' in event and category.lower() in event['categories'].lower():
                    observable.add_tag(self.category_tags[category])
            
            if 'username' in event and event['username'] is not None:
                temp = event['username']
                if not isinstance(event['username'], list):
                    temp = [event['username']]

                for username_entry in temp:
                    if username_entry == '-':
                        continue

                    analysis.add_observable(F_USER, username_entry)

            if 'src_ip' in event and event['src_ip'] is not None and event['src_ip'] != '-':
                # note that we want to look at the proxy traffic of the source ip around the time of the request we're looking at here
                analysis.add_observable(F_IPV4, event['src_ip'], observable.time) # <-- see? :-)

        return True
#
# Module:   Proxy Request Analysis By Source
# Question: What all kinds of requests did this source make during the time of the event?
#

class BluecoatProxyAnalysisBySource_v1(Analysis):
    """What all kinds of requests did this source make during the time of the event?"""

    def initialize_details(self):
        self.details = {
            KEY_PROXY_REQUESTS: None }

    @property
    def proxy_requests(self):
        """Returns the first N proxy requests to this resource."""
        return self.details[KEY_PROXY_REQUESTS]
        
    @proxy_requests.setter
    def proxy_requests(self, value):
        self.details[KEY_PROXY_REQUESTS] = value

    @property
    def jinja_template_path(self):
        return "analysis/bluecoat_proxy_analysis_by_source_v1.html"

    def generate_summary(self):
        if self.proxy_requests is None:
            return None

        if len(self.proxy_requests) == 0:
            return None

        return "Proxy Requests By Source ({0} requests)".format(len(self.proxy_requests))

class BluecoatProxyAnalyzerBySource_v1(SplunkAnalysisModule):
    def verify_environment(self):
        self.verify_config_exists('max_request_count')

    @property
    def generated_analysis_type(self):
        return BluecoatProxyAnalysisBySource_v1

    @property
    def valid_observable_types(self):
        return F_ASSET

    def execute_analysis(self, observable):

        query_broad_filter = observable.value
        query_fine_filter = 'src_ip={0}'.format(observable.value)

        # perform a detailed query for the individual proxy requests
        self.relative_duration_before = self.config['relative_duration_before']
        self.relative_duration_after = self.config['relative_duration_after']
        self.splunk_query("""
index=bluecoat {0} 
    | search exception_id != "authentication_failed"  {1}
    | sort _time 
    | head limit={2}
    | fields *""".format(query_broad_filter, query_fine_filter, self.config.getint('max_request_count')),
            self.root.event_time_datetime if observable.time_datetime is None else observable.time_datetime)

        if self.search_results is None:
            logging.debug("missing search results after splunk query")
            return False

        analysis = self.create_analysis(observable)
        analysis.proxy_requests = self.json()

        for event in analysis.proxy_requests:
            if 'username' in event and event['username'] is not None:
                temp = event['username']
                if not isinstance(event['username'], list):
                    temp = [event['username']]

                for username_entry in temp:
                    if username_entry == '-':
                        continue

                    analysis.add_observable(F_USER, username_entry)

        return True

class ExploitKitProxyAnalysis(Analysis):
    """Did an HTTP request to this site result in a redirect to another site categorized as malicious by the proxy?"""

    def initialize_details(self):
        self.details = {
            'username': None,
            'dst_ip': None,
            'dst_hostname': None,
            'dst_filter_result': None,
            'dst_categories': None,
            'redirection_ip': None,
            'redirection_hostname': None,
            'redirection_filter_result': None,
            'redirection_categories': None,
            'query_1': [],
            'query_2': []
        }

    def generate_summary(self):
        if not self.details:
            return None

        if not self.username:
            return None

        result = 'Exploit Kit Proxy Analysis {} ({})'.format(self.dst_ip, self.dst_hostname)

        if not self.redirection_ip:
            return '{} - {} by proxy ({})'.format(result, self.dst_filter_result, self.dst_categories)

        return '{} redirects to {} ({}) - {} by proxy ({})'.format(
            result, self.redirection_ip, self.redirection_hostname, 
            self.redirection_filter_result, self.redirection_categories)

    @property
    def username(self):
        return self.details['username']

    @username.setter
    def username(self, value):
        self.details['username'] = value

    @property
    def dst_ip(self):
        return self.details['dst_ip']

    @dst_ip.setter
    def dst_ip(self, value):
        self.details['dst_ip'] = value

    @property
    def dst_hostname(self):
        return self.details['dst_hostname']

    @dst_hostname.setter
    def dst_hostname(self, value):
        self.details['dst_hostname'] = value

    @property
    def dst_filter_result(self):
        return self.details['dst_filter_result']

    @dst_filter_result.setter
    def dst_filter_result(self, value):
        self.details['dst_filter_result'] = value

    @property
    def dst_categories(self):
        return self.details['dst_categories']

    @dst_categories.setter
    def dst_categories(self, value):
        self.details['dst_categories'] = value

    @property
    def redirection_ip(self):
        return self.details['redirection_ip']

    @redirection_ip.setter
    def redirection_ip(self, value):
        self.details['redirection_ip'] = value

    @property
    def redirection_hostname(self):
        return self.details['redirection_hostname']

    @redirection_hostname.setter
    def redirection_hostname(self, value):
        self.details['redirection_hostname'] = value

    @property
    def redirection_filter_result(self):
        return self.details['redirection_filter_result']

    @redirection_filter_result.setter
    def redirection_filter_result(self, value):
        self.details['redirection_filter_result'] = value

    @property
    def redirection_categories(self):
        return self.details['redirection_categories']

    @redirection_categories.setter
    def redirection_categories(self, value):
        self.details['redirection_categories'] = value

class ExploitKitProxyAnalyzer(SplunkAnalysisModule):
    def verify_environment(self):
        self.verify_config_exists('max_request_count')

    @property
    def generated_analysis_type(self):
        return ExploitKitProxyAnalysis

    @property
    def valid_observable_types(self):
        return F_IPV4

    def execute_analysis(self, ipv4):

        # we need the proxy analysis by destination to see who made the requests
        dest_analysis = self.wait_for_analysis(ipv4, BluecoatProxyAnalysisByDestination_v1)
        if not dest_analysis:
            return False

        # who did it?
        users = [o for o in dest_analysis.observables if o.type == F_USER]
        if len(users) == 0:
            return False

        analysis = self.create_analysis(ipv4)
        analysis.dst_ip = ipv4.value

        for user in users:
            analysis.username = user.value
            self.relative_duration_before = self.config['relative_duration_before']
            self.relative_duration_after = self.config['relative_duration_after']
            self.splunk_query("""
index=bluecoat {username} {dst_ip} 
    | search username={username} dst_ip={dst_ip} exception_id != authentication_failed 
    | dedup uri_host filter_result exception_id categories
    | fields uri_host filter_result exception_id categories""".format(username=user.value, dst_ip=ipv4.value), 
                self.root.event_time_datetime if ipv4.time_datetime is None else ipv4.time_datetime)

            if self.search_results is None:
                logging.debug("missing search results after splunk query")
                continue

            results = self.json()

            for event in results:
                logging.debug(' + '.join(event))
                uri_host = event['uri_host']
                filter_result = event['filter_result']
                exception_id = event['exception_id']
                categories = event['categories']

                analysis.dst_hostname = uri_host
                analysis.dst_filter_result = filter_result
                analysis.dst_categories = categories

                # was this first request denied?
                if filter_result != 'OBSERVED':
                    # as far as we need to go
                    return True

                # now look to see what that might have redirected to
                self.splunk_query("""
index=bluecoat {uri_host} 
    | search exception_id != authentication_failed http_referrer = "*{uri_host}*" uri_host != {uri_host} filter_result != OBSERVED 
    | fields uri_host dst_ip filter_result categories""".format(uri_host=event['uri_host']),
                    self.root.event_time_datetime if ipv4.time_datetime is None else ipv4.time_datetime)

                if self.search_results is None:
                    logging.debug("missing search results after splunk query")
                    continue

                # did we find something?
                sub_results = self.json()

                for sub_event in sub_results:
                    uri_host = sub_event['uri_host']
                    dst_ip = sub_event['dst_ip']
                    filter_result = sub_event['filter_result']
                    categories = sub_event['categories']
            
                    # looking for something that was not allowed
                    if filter_result == 'OBSERVED':
                        continue

                    analysis.redirection_ip = dst_ip
                    analysis.redirection_hostname = uri_host
                    analysis.redirection_filter_result = filter_result
                    analysis.redirection_categories = categories

                    return True

        return True

# XXX DEPRECATED
class BluecoatProxyRequestAnalysis(Analysis):
    @property
    def jinja_template_path(self):
        return "analysis/bluecoat_proxy_requests.html"

    def generate_summary(self):
        if isinstance(self.details, list) and len(self.details) > 0:
            return "Proxy Requests To ({0} events)".format(len(self.details))

        return None

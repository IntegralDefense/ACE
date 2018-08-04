# vim: sw=4:ts=4:et

import logging

import saq

from saq.analysis import Analysis, Observable
from saq.constants import *
from saq.error import report_exception
from saq.modules import AnalysisModule

from cbapi_legacy import CbApi

import requests

KEY_TOTAL_RESULTS = 'total_results'

class CarbonBlackProcessAnalysis_v1(Analysis):
    """How many times have we seen this anywhere in our environment?"""
    def initialize_details(self):
        self.details = {
        }

    @property
    def jinja_template_path(self):
        return "analysis/carbon_black.html"

    def generate_summary(self):
        if self.details is None:
            return None

        if KEY_TOTAL_RESULTS not in self.details:
            return None

        return 'Carbon Black Process Analysis ({} matches)'.format(self.details[KEY_TOTAL_RESULTS])

class CarbonBlackProcessAnalyzer_v1(AnalysisModule):
    def verify_environment(self):

        if not 'carbon_black' in saq.CONFIG:
            raise ValueError("missing config section carbon_black")

        for key in [ 'url', 'token' ]:
            if not key in saq.CONFIG['carbon_black']:
                raise ValueError("missing config item {} in section carbon_black".format(key))

    @property
    def url(self):
        return saq.CONFIG['carbon_black']['url']

    @property
    def token(self):
        return saq.CONFIG['carbon_black']['token']

    @property
    def generated_analysis_type(self):
        return CarbonBlackProcessAnalysis_v1

    @property
    def valid_observable_types(self):
        return ( F_IPV4, F_FQDN, F_FILE_PATH, F_FILE_NAME, F_MD5, F_SHA1, F_SHA256 )

    def execute_analysis(self, observable):

        # we only analyze observables that came with the alert and ones with detection points
        if observable not in self.root.observables and not observable.is_suspect:
            return False

        # generate the query based on the indicator type
        query = None
        if observable.type == F_IPV4:
            # we don't analyze our own IP address space
            if observable.is_managed():
                logging.debug("skipping analysis for managed ipv4 {}".format(observable))
                return False

            query = 'ipaddr:{}/32'.format(observable.value)
        elif observable.type == F_FQDN:
            query = 'domain:{}'.format(observable.value)
        elif observable.type == F_FILE_PATH or observable.type == F_FILE_NAME:
            query = '"{}"'.format(observable.value.replace('"', '\\"'))
        elif observable.type == F_MD5:
            query = observable.value
        elif observable.type == F_SHA1:
            query = observable.value
        elif observable.type == F_SHA256:
            query = observable.value
        else:
            # this should not happen
            logging.error("invalid observable type {}".format(observable.type))
            return False

        analysis = self.create_analysis(observable)

        api = CbApi(self.url, ssl_verify=False, token=self.token)

        # when love makes a sound babe
        # a heart needs a second chance
        attempt = 0
        while True:
            try:
                analysis.details = api.process_search(query)
                break
            except requests.exceptions.HTTPError as e:
                if attempt > 2:
                    raise e

                # requests.exceptions.HTTPError: 502 Server Error: Bad Gateway for url: https://cmas.ashland.com:8443/api/v1/process
                # requests.exceptions.HTTPError: 504 Server Error: Gateway Time-out for url: https://cmas.ashland.com:8443/api/v1/process
                if e.response.status_code in [ 502, 504 ]:
                    attempt += 1
                    logging.warning("{} - retrying attempt #{}".format(e, attempt))
                    # XXX use delayed analysis instead
                    self.sleep(5) # wait a few seconds and try again
                    if self.shutdown or self.cancel_analysis_flag:
                        return False

                    continue

                raise e

        # look for people using skype
        for result in analysis.details['results']:
            if 'process_name' in result and result['process_name'] == 'skype.exe':
                observable.add_tag('p2p:skype')
            if 'process_name' in result and result['process_name'] == 'thunder.exe':
                observable.add_tag('p2p:thunder')
            #if 'process_name' in result and 'sogou' in result['process_name']:
                #observable.add_tag('p2p:sogou')
            

        # I'm going to refactor to allow users to do this manually we needed
        #for result in analysis.details['results']:
            #if 'hostname' in result and result['hostname'] != '':
                #analysis.add_observable(F_HOSTNAME, result['hostname'])
            #if 'path' in result and result['path'] != '':
                #analysis.add_observable(F_FILE_PATH, result['path'])
            #if 'process_md5' in result and result['process_md5'] != '':
                #analysis.add_observable(F_MD5, result['process_md5'])
            #if 'username' in result and result['username'] != '':
                #if '\\' in result['username']:
                    #analysis.add_observable(F_USER, result['username'].split('\\')[1])
                #else:
                    #analysis.add_observable(F_USER, result['username'])

        return True

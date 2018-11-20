# vim: sw=4:ts=4:et

import logging

import saq

from saq.analysis import Analysis, Observable
from saq.constants import *
from saq.error import report_exception
from saq.modules import AnalysisModule

from cbapi.response import *

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

    def print_facet_histogram(self, facets):
        total_results = sum([entry['value'] for entry in facets])
        return_string = "\n\t\t\tTotal Process Segments: {}\n".format(total_results)
        return_string += "\t\t\t--------------------------\n"
        for entry in facets:
            return_string += "%50s: %5s %5s%% %s\n" % (entry["name"][:45], entry['value'], entry["ratio"],
                  u"\u25A0"*(int(entry['percent']/2)))
        return return_string

    def generate_summary(self):
        if self.details is None:
            return None

        if KEY_TOTAL_RESULTS not in self.details:
            return None

        return 'Carbon Black Process Analysis ({} process matches - Sample of {} processes)'.format(self.details[KEY_TOTAL_RESULTS],
                                                                                                    len(self.details['results']))

class CarbonBlackProcessAnalyzer_v1(AnalysisModule):
    def verify_environment(self):

        if not 'carbon_black' in saq.CONFIG:
            raise ValueError("missing config section carbon_black")

        for key in [ 'url', 'token' ]:
            if not key in saq.CONFIG['carbon_black']:
                raise ValueError("missing config item {} in section carbon_black".format(key))

    @property
    def max_results(self):
        return self.config.getint('max_results')

    @property
    def credentials(self):
        return saq.CONFIG['carbon_black']['credential_file']

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
            query = 'md5:"{}"'.format(observable.value)
        elif observable.type == F_SHA1:
            query = observable.value
        elif observable.type == F_SHA256:
            query = observable.value
        else:
            # this should not happen
            logging.error("invalid observable type {}".format(observable.type))
            return False

        analysis = self.create_analysis(observable)

        # the default is to use the 'default' profile
        cb = CbResponseAPI(credential_file=self.credentials)

        # when love makes a sound babe
        # a heart needs a second chance
        attempt = 0
        while True:
            try:
                processes = cb.select(Process).where(query).group_by('id')
                break
            except Exception as e:
                if attempt > 2:
                    raise e
                attempt += 1
                logging.warning("{} - retrying attempt #{}".format(e, attempt))
                # XXX use delayed analysis instead
                self.sleep(5) # wait a few seconds and try again
                if self.shutdown or self.cancel_analysis_flag:
                    return False

        analysis.details['results'] = []
        analysis.details['total_results'] = len(processes)
        # generate some facet data
        analysis.details['process_name_facet'] = processes.facets('process_name')['process_name']
        for process in processes:
            if len(analysis.details['results']) >= self.max_results:
                break
            analysis.details['results'].append({'id': process.id,
                    'start': process.start,
                    'username': process.username,
                    'hostname': process.hostname,
                    'cmdline': process.cmdline,
                    'process_md5': process.process_md5,
                    'path': process.path,
                    'webui_link': process.webui_link
                    })
            analysis.add_observable(F_PROCESS_GUID, process.id)


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

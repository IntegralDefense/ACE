# vim: sw=4:ts=4:et

import datetime
import hashlib
import io
import json
import logging
import os
import os.path
import re
import shutil

# for Falcon download
import gzip
import tempfile
from subprocess import Popen, PIPE

import saq

from saq.analysis import Analysis, Observable
from saq.constants import *
from saq.error import report_exception
from saq.modules import AnalysisModule
from saq.modules.file_analysis import FileHashAnalysis
from saq.modules.sandbox import SandboxAnalysisModule

import requests

from vxstreamlib import VxStreamServer, VxStreamSubmission, \
    VXSTREAM_STATUS_SUCCESS, \
    VXSTREAM_STATUS_ERROR, \
    VXSTREAM_STATUS_UNKNOWN, \
    VXSTREAM_STATUS_IN_PROGRESS, \
    VXSTREAM_STATUS_IN_QUEUE, \
    VXSTREAM_DOWNLOAD_JSON, \
    VXSTREAM_DOWNLOAD_PCAP, \
    VXSTREAM_DOWNLOAD_SAMPLE, \
    VXSTREAM_DOWNLOAD_MEMORY

KEY_JSON_PATH = 'json_path'
KEY_SHA256 = 'sha256'
KEY_MD5 = 'md5'
KEY_SHA1 = 'sha1'
KEY_JOB_ID = 'job_id'
KEY_SANDBOX_LINK = 'sandbox_link'
KEY_ENV = 'environment_id'
KEY_STATUS = 'status'
KEY_SUBMIT_DATE = 'submit_date'
KEY_COMPLETE_DATE = 'complete_date'
KEY_FAIL_DATE = 'fail_date'
KEY_VXSTREAM_THREAT_SCORE = 'vxstream_threat_score'
KEY_VXSTREAM_THREAT_LEVEL = 'vxstream_threat_level'

class VxStreamAnalysis_v1_0(Analysis):
    """What does this file do when it is executed or opened?"""

    def generate_summary(self):
        if self.vxstream_threat_score is not None:
            return 'VxStream Analysis : {}'.format(self.vxstream_threat_score)

        return None

    @property
    def sha256(self):
        if self.details is None:
            return None

        if KEY_SHA256 not in self.details:
            return None

        return self.details[KEY_SHA256]

    @sha256.setter
    def sha256(self, value):
        self.details[KEY_SHA256] = value

    @property
    def environment_id(self):
        if self.details is None:
            return None

        if KEY_ENV not in self.details:
            return None
        
        return self.details[KEY_ENV]

    @environment_id.setter
    def environment_id(self, value):
        self.details[KEY_ENV] = value

    @property
    def status(self):
        if self.details is None:
            return None

        if KEY_STATUS not in self.details:
            return None

        return self.details[KEY_STATUS]

    @status.setter
    def status(self, value):
        self.details[KEY_STATUS] = value

    @property
    def submit_date(self):
        if self.details is None:
            return None

        if KEY_SUBMIT_DATE not in self.details:
            return None

        return self.details[KEY_SUBMIT_DATE]

    @submit_date.setter
    def submit_date(self, value):
        self.details[KEY_SUBMIT_DATE] = value

    @property
    def complete_date(self):
        if self.details is None:
            return None

        if KEY_COMPLETE_DATE not in self.details:
            return None

        return self.details[KEY_COMPLETE_DATE]

    @complete_date.setter
    def complete_date(self, value):
        self.details[KEY_COMPLETE_DATE] = value

    @property
    def fail_date(self):
        if self.details is None:
            return None

        if KEY_FAIL_DATE not in self.details:
            return None

        return self.details[KEY_FAIL_DATE]

    @fail_date.setter
    def fail_date(self, value):
        self.details[KEY_FAIL_DATE] = value

    @property
    def vxstream_threat_score(self):
        if self.details is None:
            return None

        if KEY_VXSTREAM_THREAT_SCORE not in self.details:
            return None

        return self.details[KEY_VXSTREAM_THREAT_SCORE]
        
    @vxstream_threat_score.setter
    def vxstream_threat_score(self, value):
        self.details[KEY_VXSTREAM_THREAT_SCORE] = value

    @property
    def vxstream_threat_level(self):
        if self.details is None:
            return None

        if KEY_VXSTREAM_THREAT_LEVEL not in self.details:
            return None

        return self.details[KEY_VXSTREAM_THREAT_LEVEL]

    @vxstream_threat_level.setter
    def vxstream_threat_level(self, value):
        self.details[KEY_VXSTREAM_THREAT_LEVEL] = value

# abstract class for both vxstream analysis types
class VxStreamAnalysis(Analysis):
    """What is the VxStream analysis for this hash or file?"""

    def initialize_details(self):
        self.details = {
            KEY_JSON_PATH: None,
            KEY_SHA256: None,
            KEY_ENV: None,
            KEY_STATUS: None,
            KEY_SUBMIT_DATE: None,
            KEY_COMPLETE_DATE: None, 
            KEY_FAIL_DATE: None,
            KEY_VXSTREAM_THREAT_SCORE: None,
            KEY_VXSTREAM_THREAT_LEVEL: None,
        }

    def generate_summary(self):
        if self.vxstream_threat_score is not None:
            return 'VxStream Analysis : {}'.format(self.vxstream_threat_score)

        return None

    @property
    def json_path(self):
        """Returns the path to the JSON file returned by VxStream."""
        return self.details_property(KEY_JSON_PATH)

    @json_path.setter
    def json_path(self, value):
        self.details[KEY_JSON_PATH] = value
        self.set_modified()

    @property
    def sha256(self):
        """Return the sha256 value of the file (or the hash.)"""
        return self.details_property(KEY_SHA256)

    @sha256.setter
    def sha256(self, value):
        self.details[KEY_SHA256] = value
        self.set_modified()

    @property
    def environment_id(self):
        return self.details_property(KEY_ENV)

    @environment_id.setter
    def environment_id(self, value):
        self.details[KEY_ENV] = value
        self.set_modified()

    @property
    def status(self):
        return self.details_property(KEY_STATUS)

    @status.setter
    def status(self, value):
        self.details[KEY_STATUS] = value
        self.set_modified()

    @property
    def submit_date(self):
        result = self.details_property(KEY_SUBMIT_DATE)
        if isinstance(result, str):
            return datetime.datetime.strptime(result, '%Y-%m-%dT%H:%M:%S.%f')
            
        return result

    @submit_date.setter
    def submit_date(self, value):
        self.details[KEY_SUBMIT_DATE] = value
        self.set_modified()

    @property
    def complete_date(self):
        return self.details_property(KEY_COMPLETE_DATE)

    @complete_date.setter
    def complete_date(self, value):
        self.details[KEY_COMPLETE_DATE] = value
        self.set_modified()

    @property
    def fail_date(self):
        return self.details_property(KEY_FAIL_DATE)

    @fail_date.setter
    def fail_date(self, value):
        self.details[KEY_FAIL_DATE] = value
        self.set_modified()

    @property
    def vxstream_threat_score(self):
        return self.details_property(KEY_VXSTREAM_THREAT_SCORE)
        
    @vxstream_threat_score.setter
    def vxstream_threat_score(self, value):
        self.details[KEY_VXSTREAM_THREAT_SCORE] = value
        self.set_modified()

    @property
    def vxstream_threat_level(self):
        return self.details_property(KEY_VXSTREAM_THREAT_LEVEL)

    @vxstream_threat_level.setter
    def vxstream_threat_level(self, value):
        self.details[KEY_VXSTREAM_THREAT_LEVEL] = value
        self.set_modified()

# abstract class for both vxstream analyzers
class VxStreamAnalyzer(SandboxAnalysisModule):
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # main vxstreamlib object
        self._vx = None

        # the list of regular expressions of file paths to avoid when processing dropped files from vxstream
        self.dropped_files_regex = [] # list of re objects
        self.dropped_files_regex_loaded = False

    @property
    def vx(self):
        if self._vx is None:
            self._vx = VxStreamServer(self.url, self.api_key, self.secret, proxies=self.proxies)

        return self._vx

    @property
    def url(self):
        return saq.CONFIG['vxstream']['baseuri']

    @property
    def api_key(self):
        return saq.CONFIG['vxstream']['apikey']

    @property
    def secret(self):
        return saq.CONFIG['vxstream']['secret']

    @property
    def environment_id(self):
        return saq.CONFIG['vxstream']['environmentid']

    @property
    def threat_score_threshold(self):
        return self.config.getint('threat_score_threshold')

    @property
    def threat_level_threshold(self):
        return self.config.getint('threat_level_threshold')

    @property
    def timeout(self):
        return self.config.getint('timeout')

    @property
    def frequency(self):
        return self.config.getint('frequency')

    @property
    def download_memory_dumps(self):
        return self.config.getboolean('download_memory_dumps')

    @property
    def dropped_files_regex_config(self):
        return self.config['dropped_files_regex_config']

    def load_dropped_files_regex(self):
        with open(self.dropped_files_regex_config, 'r') as fp:
            for line in fp:
                if line.startswith('#'):
                    continue

                if not line.strip():
                    continue

                try:
                    self.dropped_files_regex.append(re.compile(line.strip()))
                except Exception as e:
                    logging.warning("unable to load dropped file regex {}: {}".format(line.strip(), e))

        logging.debug("loaded {} regex for dropped files".format(len(self.dropped_files_regex)))

    def check_dropped_file(self, path):
        """Returns True if a given "dropped file" should be added to analysis."""
        # have we loaded the regular expressions yet?
        if not self.dropped_files_regex_loaded:
            self.dropped_files_regex_loaded = True
            self.watch_file(self.dropped_files_regex_config, self.load_dropped_files_regex)

        for r in self.dropped_files_regex:
            if r.search(os.path.basename(path)):
                logging.debug("dropped file path {} matches {}".format(path, r))
                return False

        return True

    def execute_vxstream_analysis(self, target, analysis):

        # at this point we should definitely have a sha256 value
        if analysis.sha256 is None:
            logging.error("missing sha256 hash for {}".format(target))
            return False

        status = self.vx.get_status(analysis.sha256, analysis.environment_id)
        if status != analysis.status:
            logging.debug("status of {} changed from {} to {}".format(target.value, analysis.status, status))
            analysis.status = status

        if analysis.status == VXSTREAM_STATUS_IN_PROGRESS or analysis.status == VXSTREAM_STATUS_IN_QUEUE:
            logging.debug("waiting for completion of {}".format(target))
            return self.delay_analysis(target, analysis, seconds=self.frequency, timeout_minutes=self.timeout)

        # something go wrong?
        if analysis.status == VXSTREAM_STATUS_ERROR or analysis.status == VXSTREAM_STATUS_UNKNOWN:
            logging.debug("detected error status {} for {} sha256 {} env {}".format(
                analysis.status, target, analysis.sha256, analysis.environment_id))
            analysis.fail_date = datetime.datetime.now()
            return True

        if analysis.status != VXSTREAM_STATUS_SUCCESS:
            logging.error("unknown vxstream status {} for sample {}".format(analysis.status, target))
            return False

        # the analysis is assumed to be complete here
        analysis.complete_date = datetime.datetime.now()

        # attempt to download the results
        vxstream_dir = os.path.join(self.root.storage_dir, '{}.vxstream'.format(target.value))
        if not os.path.isdir(vxstream_dir):
            try:
                os.mkdir(vxstream_dir)
            except Exception as e:
                logging.error("unable to create directory {}: {}".format(vxstream_dir, e))
                return False

        analysis.json_path = os.path.join(vxstream_dir, 'vxstream.json')
        if self.vx.download(analysis.sha256, self.environment_id, VXSTREAM_DOWNLOAD_JSON, analysis.json_path) is None:
            logging.warning("download_results failed for {} {}".format(target, self.environment_id))
            analysis.status = VXSTREAM_STATUS_ERROR
            return False

        results = None

        try:
            with open(analysis.json_path, 'r') as fp:
                results = json.load(fp)

                # get the overall "score"
                # and get the overall "thread level"
                # believe that the following values are used
                # 2 = malicious
                # 1 = suspect
                # 0 = no verdict or no specific threat??
                if results['analysis']['final']['verdict']['isreliable'] == 'false': # not sure why this is a string instead of a boolean
                    analysis.vxstream_threat_score = 0
                    analysis.vxstream_threat_level = 0
                else:
                    analysis.vxstream_threat_score = results['analysis']['final']['verdict']['threatscore']
                    analysis.vxstream_threat_level = results['analysis']['final']['verdict']['threatlevel']
                    if ((analysis.vxstream_threat_score and int(analysis.vxstream_threat_score) >= self.threat_score_threshold)
                        and (analysis.vxstream_threat_level and int(analysis.vxstream_threat_level) >= self.threat_level_threshold)):
                        target.add_tag('malicious')
                        analysis.add_detection_point("sample has vxstream threat score of {} and threat level of {}".format(
                                                     analysis.vxstream_threat_score, analysis.vxstream_threat_level))

                # NOTE for these results if there is only one result then vxstream uses a single dict
                # for more than one result it uses a list of dict, so you have to check for that

                # collect observables
                # ipv4
                if results['analysis']['runtime']['network']['hosts'] != "":
                    host_list = results['analysis']['runtime']['network']['hosts']['host']
                    if isinstance(host_list, dict):
                        host_list = [ host_list ]

                    for host in host_list:
                        analysis.add_observable(F_IPV4, host['address'])

                # url
                if 'httprequests' in results['analysis']['runtime']['network'] and results['analysis']['runtime']['network']['httprequests'] != "":
                    http_list = results['analysis']['runtime']['network']['httprequests']['request']
                    if isinstance(http_list, dict):
                        http_list = [ http_list ]

                    for http_request in http_list:
                        analysis.add_observable(F_URL, http_request['request_url'])

        except KeyError as e:
            logging.warning("vxstream report for {} missing or incomplete: {}".format(analysis.sha256, e))
        except Exception as e:
            logging.error("unable to load json from {}: {}".format(analysis.json_path, e))

        # download dropped files
        try:
            output_dir = os.path.join(vxstream_dir, 'dropped')
            if not os.path.isdir(output_dir):
                os.mkdir(output_dir)

            for dropped_file in self.vx.download_dropped_files(analysis.sha256, analysis.environment_id, output_dir):
                # we've got a list of things we ignore here
                if not self.check_dropped_file(dropped_file):
                    continue

                f = analysis.add_observable(F_FILE, os.path.relpath(dropped_file, start=self.root.storage_dir))
                # we don't want to automatically sandbox the files we get from the sandbox
                f.exclude_analysis(self)
                
        except Exception as e:
            logging.error("unable to download dropped files for {}: {}".format(target, e))


        # download process memory
        #try:
            #output_dir = os.path.join(vxstream_dir, 'memory')
            #os.mkdir(output_dir)
            #mem_result = self.vx.download_memory_dump(analysis.sha256, analysis.environment_id, output_dir)
            #if mem_result is None:
                #logging.debug("unable to download memory dump for {}".format(target))
            #else:
                #file_list, combined_memory_dump = mem_result
                #for file_path in file_list:
                    #analysis.add_observable(F_FILE, os.path.relpath(file_path, start=self.root.storage_dir))

                #analysis.add_observable(F_FILE, os.path.relpath(combined_memory_dump, start=self.root.storage_dir))
        #except Exception as e:
            #logging.error("unable to download memory dump for {}: {}".format(target, e))

        # if this is a hash get the original file
        if target.type == F_SHA256:
            # do we already have this file?
            for _file in self.root.get_observables_by_type(F_FILE):
                if not _file.sha256_hash:
                    _file.compute_hashes()
                if _file.sha256_hash.lower() == target.value.lower():
                    logging.debug("already have file {} with sha256 {}".format(_file, target.value))
                    return True

            try:
                target_path = os.path.join(vxstream_dir, results['analysis']['general']['sample'])
                if self.vx.download(analysis.sha256, self.environment_id, VXSTREAM_DOWNLOAD_SAMPLE, target_path) is None:
                    logging.warning("unable to download sample for {}".format(analysis.sha256))
                else:
                    analysis.add_observable(F_FILE, os.path.relpath(target_path, start=self.root.storage_dir))
            except Exception as e:
                logging.error("unable to download sample for {}: {}".format(analysis.sha256, e))

        return True

class VxStreamHashAnalysis(VxStreamAnalysis):
    pass

class VxStreamHashAnalyzer(VxStreamAnalyzer):

    @property
    def required_directives(self):
        return [ ]

    @property
    def generated_analysis_type(self):
        return VxStreamHashAnalysis

    @property
    def valid_observable_types(self):
        return F_SHA256

    def execute_analysis(self, target):
        analysis = target.get_analysis(VxStreamHashAnalysis)
        if analysis is None:
            analysis = self.create_analysis(target)
            analysis.sha256 = target.value
            analysis.environment_id = self.environment_id
            analysis.submit_date = datetime.datetime.now()

        return self.execute_vxstream_analysis(target, analysis)

class VxStreamFileAnalysis(VxStreamAnalysis):
    pass

class VxStreamFileAnalyzer(VxStreamAnalyzer):

    @property
    def generated_analysis_type(self):
        return VxStreamFileAnalysis

    @property
    def required_directives(self):
        return [ DIRECTIVE_SANDBOX ]

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, target):
        analysis = target.get_analysis(VxStreamFileAnalysis)
        if analysis is None:
            # let vxstream analyze the hash of the file before we decide to submit it
            hash_analysis = self.wait_for_analysis(target, FileHashAnalysis)

            # hash analysis is excluded for some things
            # if that's the case then we just upload the file
            # otherwise we wait to see if how the vxstream anaysis of the hash goes
            while hash_analysis:
                sha256_observable = hash_analysis.get_observables_by_type(F_SHA256)
                if len(sha256_observable) == 1:
                    sha256_observable = sha256_observable[0]
                else:
                    raise RuntimeError("got {} sha256 observables from {}".format(len(sha256_observable), hash_analysis))

                hash_vx_analysis = self.wait_for_analysis(sha256_observable, VxStreamHashAnalysis)
                if hash_vx_analysis is None:
                    logging.warning("vxstream analysis for {} returned nothing".format(sha256_observable))
                    break

                # if we've already analyzed the hash then we're done (the analysis will be listed under the hash)
                if hash_vx_analysis.status in [ VXSTREAM_STATUS_ERROR, VXSTREAM_STATUS_SUCCESS ]:
                    return False

                # we're expecting the state to be UNKNOWN at this point
                if hash_vx_analysis.status != VXSTREAM_STATUS_UNKNOWN:
                    logging.error("unexpected state {}".format(hash_vx_analysis.status))
                    return False
                
                break

            # does this file even exist?
            local_path = os.path.join(self.root.storage_dir, target.value)
            if not os.path.exists(local_path):
                logging.warning("{} does not exist".format(local_path))
                return False

            # should we be sandboxing this type of file?
            if not self.is_sandboxable_file(local_path):
                logging.debug("{} is not a supported file type for vx analysis".format(local_path))
                return False

            analysis = self.create_analysis(target)

            # this sample needs to be submitted
            submission = self.vx.submit(local_path, self.environment_id)
            if submission is None:
                logging.error("submission of {} failed".format(local_path))
                return False

            if not submission.sha256:
                logging.error("submission of {} failed to return sha256".format(target))
                return False

            analysis.sha256 = submission.sha256
            analysis.environment_id = submission.environment_id
            analysis.submit_date = datetime.datetime.now()

        # at this point we have analysis for a file that has been submitted
        return self.execute_vxstream_analysis(target, analysis)


## Experimenting sandboxapi wrapper because VxAPI
## Wasn't written to be a good library
from sandboxapi.falcon import FalconAPI

class FalconAnalysis(Analysis):
    """What is the Falcon/VxStream analysis for this hash or file?"""

    def initialize_details(self):
        self.details = {
            KEY_JSON_PATH: None,
            KEY_SHA256: None,
            KEY_ENV: None,
            KEY_STATUS: None,
            KEY_SUBMIT_DATE: None,
            KEY_COMPLETE_DATE: None,
            KEY_FAIL_DATE: None,
            KEY_VXSTREAM_THREAT_SCORE: None,
            KEY_VXSTREAM_THREAT_LEVEL: None,
            KEY_MD5: None,
            KEY_SHA1: None,
            KEY_SANDBOX_LINK: None,
            KEY_JOB_ID: None
        }

    def generate_summary(self):
        if self.vxstream_threat_score is not None:
            return 'Falcon Sandbox Analysis : {}'.format(self.vxstream_threat_score)

        return None

    @property
    def json_path(self):
        """Returns the path to the JSON file returned by VxStream."""
        return self.details_property(KEY_JSON_PATH)

    @json_path.setter
    def json_path(self, value):
        self.details[KEY_JSON_PATH] = value
        self.set_modified()

    @property
    def job_id(self):
        """Return the Falcon sandbox job id."""
        return self.details_property(KEY_JOB_ID)

    @job_id.setter
    def job_id(self, value):
        self.details[KEY_JOB_ID] = value

    @property
    def sha256(self):
        """Return the sha256 value of the file (or the hash.)"""
        return self.details_property(KEY_SHA256)

    @sha256.setter
    def sha256(self, value):
        self.details[KEY_SHA256] = value
        self.set_modified()

    @property
    def md5(self):
        return self.details_property(KEY_MD5)

    @md5.setter
    def md5(self, value):
        self.details[KEY_MD5] = value
        self.set_modified()

    @property
    def sha1(self):
        return self.details_property(KEY_SHA1)

    @sha1.setter
    def sha1(self, value):
        self.details[KEY_SHA1] = value
        self.set_modified()

    @property
    def sandbox_link(self):
        return self.details_property(KEY_SANDBOX_LINK)

    @sandbox_link.setter
    def sandbox_link(self, value):
        self.details[KEY_SANDBOX_LINK] = value
        self.set_modified()

    @property
    def environment_id(self):
        return self.details_property(KEY_ENV)

    @environment_id.setter
    def environment_id(self, value):
        self.details[KEY_ENV] = value
        self.set_modified()

    @property
    def status(self):
        return self.details_property(KEY_STATUS)

    @status.setter
    def status(self, value):
        self.details[KEY_STATUS] = value
        self.set_modified()

    @property
    def submit_date(self):
        result = self.details_property(KEY_SUBMIT_DATE)
        if isinstance(result, str):
            return datetime.datetime.strptime(result, '%Y-%m-%dT%H:%M:%S.%f')

        return result

    @submit_date.setter
    def submit_date(self, value):
        self.details[KEY_SUBMIT_DATE] = value
        self.set_modified()

    @property
    def complete_date(self):
        return self.details_property(KEY_COMPLETE_DATE)

    @complete_date.setter
    def complete_date(self, value):
        self.details[KEY_COMPLETE_DATE] = value
        self.set_modified()

    @property
    def fail_date(self):
        return self.details_property(KEY_FAIL_DATE)

    @fail_date.setter
    def fail_date(self, value):
        self.details[KEY_FAIL_DATE] = value
        self.set_modified()

    @property
    def vxstream_threat_score(self):
        return self.details_property(KEY_VXSTREAM_THREAT_SCORE)

    @vxstream_threat_score.setter
    def vxstream_threat_score(self, value):
        self.details[KEY_VXSTREAM_THREAT_SCORE] = value
        self.set_modified()

    @property
    def vxstream_threat_level(self):
        return self.details_property(KEY_VXSTREAM_THREAT_LEVEL)

    @vxstream_threat_level.setter
    def vxstream_threat_level(self, value):
        self.details[KEY_VXSTREAM_THREAT_LEVEL] = value
        self.set_modified()

    @property
    def targets(self):
        if self.details is None:
            return

        if self.json_path is None:
            return

        try:
            results = None
            with open(self.json_path, 'r') as fp:
                results = json.load(fp)

            try:
                yield ProfilePointTarget(TARGET_VX_IPDOMAINSTREAMS,
                      json.dumps(results['analysis']['hybridanalysis']['ipdomainstreams']['stream'],
                      indent=2, sort_keys=True))
            except KeyError as e:
                logging.debug("{} missing key: {}".format(self, e))

        except Exception as e:
            logging.error("unable to parse vxstream json at {}: {}".format(self.json_path, e))
            #report_exception()


class FalconAnalyzer(SandboxAnalysisModule):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # FalconAPI object
        self._vx = None

        # the list of regular expressions of file paths to avoid when processing dropped files from vxstream
        self.dropped_files_regex = [] # list of re objects
        self.dropped_files_regex_loaded = False


    @property
    def vx(self):
        if self._vx is None:
            self._vx = FalconAPI(self.api_key, self.url) # proxies=self.proxies)
            if self.proxies:
                self._vx.proxies = self.proxies
            self._vx.verify_ssl = self.ssl_verification
            self._vx.env_id = saq.CONFIG['vxstream']['environmentid']
        return self._vx

    @property
    def url(self):
        return saq.CONFIG['vxstream']['baseuri_v2']

    @property
    def base_gui_uri(self):
        return saq.CONFIG['vxstream']['gui_baseuri'].strip('/')

    @property
    def api_key(self):
        return saq.CONFIG['vxstream']['apikey']

    @property
    def secret(self):
        return saq.CONFIG['vxstream']['secret']

    @property
    def environment_id(self):
        return self.vx.env_id

    @environment_id.setter
    def environment_id(self, value):
        self.vx.env_id = value

    @property
    def ssl_verification(self):
        """Set ssl verification. In the config, this should be set to the path to CA cert, True (default), 
        or False to turn off ssl_verification.
        """
        if 'ssl_verification' in saq.CONFIG['vxstream']:
            ssl_verify = saq.CONFIG['vxstream']['ssl_verification']
            if os.path.exists(ssl_verify):
                # assume it's a path to the CA cert
                return ssl_verify
            else:
                # it should be interpreted as a bool
                return saq.CONFIG['vxstream'].getboolean('ssl_verification')
        # Default OS cert store
        return True

    @property
    def threat_score_threshold(self):
        return self.config.getint('threat_score_threshold')

    @property
    def threat_level_threshold(self):
        return self.config.getint('threat_level_threshold')

    @property
    def timeout(self):
        return self.config.getint('timeout')

    @property
    def frequency(self):
        return self.config.getint('frequency')

    @property
    def download_memory_dumps(self):
        return self.config.getboolean('download_memory_dumps')

    @property
    def dropped_files_regex_config(self):
        return self.config['dropped_files_regex_config']

    @property
    def is_restricted(self):
        if self.access_level == 'restricted':
            return True
        return False

    @property
    def is_default(self):
        if self.access_level == 'default':
            return True
        return False

    @property
    def is_intelligence(self):
        if self.access_level == 'intelligence':
            return True
        return False

    @property
    def limited_report(self):
        if self.is_restricted or self.is_default or self.is_intelligence:
            return True
        return False

    @property
    def access_level(self):
        """Get the access level of our API key.
        This module is not concerned with elevated or super access.
        """
        result = self.vx._request('/key/current')
        if result.status_code == 200:
            key_data = result.json()
            return key_data['auth_level_name']
        return False

    def download_file(self, job_id, _type, path):
        result = self.vx._request('/report/{}/file/{}'.format(job_id, _type))

        if result.status_code != 200:
            logging.error("got result {} from Falcon sandbox: {}".format(result.status_code, result.reason))
            return None

        write_path = path + '.gz'
        with open(write_path, 'wb') as fp:
            for block in result.iter_content(io.DEFAULT_BUFFER_SIZE):
                fp.write(block)

        with gzip.open(write_path) as fp:
            logging.debug("decompressing {}".format(write_path))
            with open(path, 'wb') as dest_fp:
                while True:
                    data = fp.read(io.DEFAULT_BUFFER_SIZE)
                    if data == b'':
                        break

                    dest_fp.write(data)

        os.remove(write_path)
        return path

    def download_dropped_files(self, job_id, target_dir):
        result = self.vx._request('/report/{}/dropped-files'.format(job_id))
        # put what we download into a temporary directory
        temp_dir = tempfile.mkdtemp()
        logging.debug("Created tempdir: {}".format(os.path.abspath(temp_dir)))
        try:
            # all dropped files come in a zip file
            compressed_path = os.path.join(temp_dir, 'download.zip')

            # write zip file to disk
            with open(compressed_path, 'wb') as fp:
                for block in result.iter_content(io.DEFAULT_BUFFER_SIZE):
                    fp.write(block)

            # unzip without paths
            p = Popen(['7z', 'e', '-y', '-o{}'.format(target_dir), compressed_path], stdout=PIPE, stderr=PIPE)
            stdout, stderr = p.communicate()

            try:
                os.remove(compressed_path)
            except Exception as e:
                logging.error("unable to delete {}: {}".format(compressed_path, e))

            # list gz files in drop_path
            file_list = [os.path.join(target_dir, f) for f in os.listdir(target_dir) if f.endswith('.gz')]

            result = []
            for compressed_path in file_list:
                # there are some other files in here sometimes that we'll ignore
                # we just want the dropped file
                if '.DROPPED.' not in compressed_path:
                    continue

                DROPPED_FILE_REGEX = re.compile(r'^(.+?)\.[0-9]+\.DROPPED\.gz')

                # the file paths look like this
                # dropped/78QC7UOHAWCI47906LWH.temp.4212842214.DROPPED.gZ
                m = DROPPED_FILE_REGEX.match(os.path.basename(compressed_path))
                if not m:
                    logging.error("could not extract file name from {}".format(compressed_path))
                    continue

                target_path = os.path.join(target_dir, m.group(1))
                result.append(target_path)

                with gzip.open(compressed_path) as fp:
                    logging.debug("decompressing {}".format(compressed_path))
                    with open(target_path, 'wb') as dest_fp:
                        while True:
                            data = fp.read(io.DEFAULT_BUFFER_SIZE)
                            if data == b'':
                                break

                            dest_fp.write(data)

                os.remove(compressed_path)

            return result

        finally:
            try:
                if temp_dir:
                    shutil.rmtree(temp_dir)
            except Exception as e:
                logging.error("unable to delete temporary directory {}: {}".format(temp_dir, e))


    def load_dropped_files_regex(self):
        with open(self.dropped_files_regex_config, 'r') as fp:
            for line in fp:
                if line.startswith('#'):
                    continue

                if not line.strip():
                    continue

                try:
                    self.dropped_files_regex.append(re.compile(line.strip()))
                except Exception as e:
                    logging.warning("unable to load dropped file regex {}: {}".format(line.strip(), e))

        logging.debug("loaded {} regex for dropped files".format(len(self.dropped_files_regex)))

    def check_dropped_file(self, path):
        """Returns True if a given "dropped file" should be added to analysis."""
        # have we loaded the regular expressions yet?
        if not self.dropped_files_regex_loaded:
            self.dropped_files_regex_loaded = True
            self.watch_file(self.dropped_files_regex_config, self.load_dropped_files_regex)

        for r in self.dropped_files_regex:
            if r.search(os.path.basename(path)):
                logging.debug("dropped file path {} matches {}".format(path, r))
                return False

        return True

    def search(self, target_hash):
        """Search the Falcon environment for the target hash (md5, sha1, sha256)"""
        self.vx.verify_ssl = False
        result = self.vx._request('/search/hash', method='POST', params={'hash':target_hash})
        if result.status_code == 200 and result.json() != []:
            # just going to take whatever is the first result
            result = result.json()[0]
            return result
        return False

    def execute_vxstream_analysis(self, target, analysis):

        if target.type == F_SHA1 or target.type == F_MD5:
            for _o in self.root.observables:
                if _o.type == F_MD5 or _o.type == F_SHA1:
                    if _o.value.lower() == target.value.lower():
                        logging.debug("found hash in root - {}".format(target))
                        break
            else:
                logging.debug("Skipping target '{}' not in root analysis.".format(target))
                return False

        logging.debug("Working on '{}'".format(target))
        if analysis.job_id is None:
            target_hash = target.value
            if target.type == F_FILE:
                # if it's a F_FILE type we *should* have the sha256 already
                if isinstance(analysis, bool):
                    logging.error("Target type is F_FILE but analysis does not contain sha256 for {}".format(target))
                    return False
                target_hash = analysis.sha256
                logging.debug("Got file sha256 of {}".format(target_hash))
            result = self.search(target_hash)
            if not result:
                logging.info("Result not found in Falcon sandbox for {}".format(target))
                return False
            try:
                analysis.job_id = result['job_id']
                analysis.sha1 = result['sha1']
                analysis.md5 = result['md5']
                analysis.sha256 = result['sha256']
            except KeyError as e:
                logging.warning("Problem with Falcon Search results: {}".format(e))
                return False
            analysis.sandbox_link = '{}/sample/{}?environmentId={}'.format(self.base_gui_uri,
                                                                           analysis.sha256,
                                                                           self.environment_id)

        logging.debug("Using job_id {} for target hash {}".format(analysis.job_id, target.value))
        status = self.vx._request("/report/{}/state".format(analysis.job_id)).json()
        if 'state' in status:
            status = status['state']
        else:
            logging.info("Unknown report state: {}".format(status))
            return False

        if status != analysis.status:
            logging.debug("status of {} changed from {} to {}".format(target.value, analysis.status, status))
            analysis.status = status

        if analysis.status == VXSTREAM_STATUS_IN_PROGRESS or analysis.status == VXSTREAM_STATUS_IN_QUEUE:
            logging.debug("waiting for completion of {}".format(target))
            return self.delay_analysis(target, analysis, seconds=self.frequency, timeout_minutes=self.timeout)

        # something go wrong?
        if analysis.status == VXSTREAM_STATUS_ERROR or analysis.status == VXSTREAM_STATUS_UNKNOWN:
            logging.debug("detected error status {} for {} sha256 {} env {}".format(
                analysis.status, target, analysis.sha256, analysis.environment_id))
            analysis.fail_date = datetime.datetime.now()
            return True

        if analysis.status != VXSTREAM_STATUS_SUCCESS:
            logging.error("unknown vxstream status {} for sample {}".format(analysis.status, target))
            return False

        # the analysis is assumed to be complete here
        analysis.complete_date = datetime.datetime.now()

        # attempt to download the results
        vxstream_dir = os.path.join(self.root.storage_dir, '{}.vxstream'.format(target.value))
        if not os.path.isdir(vxstream_dir):
            try:
                os.mkdir(vxstream_dir)
            except Exception as e:
                logging.error("unable to create directory {}: {}".format(vxstream_dir, e))
                return False

        analysis.json_path = os.path.join(vxstream_dir, 'vxstream.json')
        if self.limited_report:
            # our access levels is limited to report summaries
            logging.info("Getting limited report from Falcon Sandbox for {}".format(target))
            try:
                report = self.vx.report("{}".format(analysis.job_id))#analysis.sha256, self.environment_id))
            except sandboxapi.SandboxError as e:
                logging.info('{}'.format(e))
                return self.delay_analysis(target, analysis, seconds=self.frequency, timeout_minutes=self.timeout)
            if 'job_id' not in report:
                # there should be a job_id
                message = 'Missing expected job_id field'
                if 'message' in report:
                    message = report['message']
                logging.error("Getting report for {} {} failed: {}".format(target, self.environment_id, message))
                analysis.status = VXSTREAM_STATUS_ERROR
                return False
        else:
            # we have access to the full report
            logging.info("Getting full report from Falcon Sandbox for {}".format(target))
            try:
                report = self.vx.full_report("{}".format(analysis.job_id))#analysis.sha256, self.environment_id))
            except sandboxapi.SandboxError as e:
                logging.info('{}'.format(e))
                return self.delay_analysis(target, analysis, seconds=self.frequency, timeout_minutes=self.timeout)
            if 'analysis' not in report:
                message = 'Missing expected analysis field'
                logging.error("Getting report for {} {} failed: {}".format(target, self.environment_id, message))
                analysis.status = VXSTREAM_STATUS_ERROR
                return False

        with open(analysis.json_path, 'w') as fp:
            fp.write(json.dumps(report))

        results = None

        try:
            with open(analysis.json_path, 'r') as fp:
                results = json.load(fp)

                if self.limited_report:
                    analysis.overall_verdict = results['verdict']
                    analysis.vxstream_threat_score = results['threat_score']
                    analysis.vxstream_threat_level = results['threat_level']
                    # threatlevel is the verdict field with values: 0 = no threat, 1 = suspicious, 2 = malicious
                    if ((analysis.vxstream_threat_score and int(analysis.vxstream_threat_score) >= self.threat_score_threshold)
                        and (analysis.vxstream_threat_level and int(analysis.vxstream_threat_level) >= self.threat_level_threshold)):
                        target.add_tag('malicious')
                        analysis.add_detection_point("sample has vxstream threat score of {} and threat level of {}".format(
                                                     analysis.vxstream_threat_score, analysis.vxstream_threat_level))

                    for host in results['hosts']:
                        analysis.add_observable(F_IPV4, host)

                else:
                    if results['analysis']['final']['verdict']['isreliable'] == 'false': # not sure why this is a string instead of a boolean
                        analysis.vxstream_threat_score = 0
                        analysis.vxstream_threat_level = 0
                    else:
                        analysis.vxstream_threat_score = results['analysis']['final']['verdict']['threatscore']
                        analysis.vxstream_threat_level = results['analysis']['final']['verdict']['threatlevel']
                        if ((analysis.vxstream_threat_score and int(analysis.vxstream_threat_score) >= self.threat_score_threshold)
                            and (analysis.vxstream_threat_level and int(analysis.vxstream_threat_level) >= self.threat_level_threshold)):
                            target.add_tag('malicious')
                            analysis.add_detection_point("sample has vxstream threat score of {} and threat level of {}".format(
                                                         analysis.vxstream_threat_score, analysis.vxstream_threat_level))

                    # NOTE for these results if there is only one result then vxstream uses a single dict
                    # for more than one result it uses a list of dict, so you have to check for that

                    # collect observables
                    # ipv4
                    if results['analysis']['runtime']['network']['hosts'] != "":
                        host_list = results['analysis']['runtime']['network']['hosts']['host']
                        if isinstance(host_list, dict):
                            host_list = [ host_list ]

                        for host in host_list:
                            analysis.add_observable(F_IPV4, host['address'])

                    # url
                    if 'httprequests' in results['analysis']['runtime']['network'] and results['analysis']['runtime']['network']['httprequests'] != "":
                        http_list = results['analysis']['runtime']['network']['httprequests']['request']
                        if isinstance(http_list, dict):
                            http_list = [ http_list ]

                        for http_request in http_list:
                            analysis.add_observable(F_URL, http_request['request_url'])

        except KeyError as e:
            logging.warning("vxstream report for {} missing or incomplete: {}".format(analysis.sha256, e))
        except Exception as e:
            logging.error("unable to load json from {}: {}".format(analysis.json_path, e))

        if not self.limited_report:
            # download dropped files
            try:
                output_dir = os.path.join(vxstream_dir, 'dropped')
                if not os.path.isdir(output_dir):
                    os.mkdir(output_dir)

                for dropped_file in self.download_dropped_files(analysis.job_id, output_dir):
                    # we've got a list of things we ignore here
                    if not self.check_dropped_file(dropped_file):
                        continue

                    f = analysis.add_observable(F_FILE, os.path.relpath(dropped_file, start=self.root.storage_dir))
                    # we don't want to automatically sandbox the files we get from the sandbox
                    f.exclude_analysis(self)

            except Exception as e:
                logging.error("unable to download dropped files for {}: {}".format(target, e))

            # if this is a hash get the original file
            if target.type != F_FILE:
                # do we already have this file?
                for _file in self.root.get_observables_by_type(F_FILE):
                    if not _file.sha256_hash:
                        _file.compute_hashes()
                    if _file.sha256_hash.lower() == target.value.lower():
                        logging.debug("already have file {} with sha256 {}".format(_file, target.value))
                        return True

                try:
                    target_path = os.path.join(vxstream_dir, results['analysis']['general']['sample'])
                    if self.download_file(analysis.job_id, VXSTREAM_DOWNLOAD_SAMPLE, target_path) is None:
                        logging.warning("unable to download sample for {}".format(analysis.sha256))
                    else:
                        analysis.add_observable(F_FILE, os.path.relpath(target_path, start=self.root.storage_dir))
                except Exception as e:
                    logging.error("unable to download sample for {}: {}".format(analysis.sha256, e))

        return True

class FalconHashAnalysis(FalconAnalysis):
    pass

class FalconHashAnalyzer(FalconAnalyzer):

    @property
    def required_directives(self):
        return [ ]

    @property
    def generated_analysis_type(self):
        return FalconHashAnalysis

    @property
    def valid_observable_types(self):
        return F_MD5, F_SHA1, F_SHA256

    def execute_analysis(self, target):
        analysis = target.get_analysis(FalconHashAnalysis)
        if analysis is None:
            analysis = self.create_analysis(target)
            if target.type == F_SHA256:
                analysis.sha256 = target.value
            analysis.environment_id = self.environment_id
            analysis.submit_date = datetime.datetime.now()

        return self.execute_vxstream_analysis(target, analysis)


class FalconFileAnalysis(FalconAnalysis):
    pass

class FalconFileAnalyzer(FalconAnalyzer):

    @property
    def generated_analysis_type(self):
        return FalconFileAnalysis

    @property
    def required_directives(self):
        return [ DIRECTIVE_SANDBOX ]

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, target):
        # we want to sandbox the root file which this file originated from
        while target.redirection:
            logging.debug("Performing target redirection to origional file")
            target = target.redirection

        analysis = target.get_analysis(FalconFileAnalysis)
        if analysis is None:
            # let vxstream analyze the hash of the file before we decide to submit it
            hash_analysis = self.wait_for_analysis(target, FileHashAnalysis)

            # hash analysis is excluded for some things
            # if that's the case then we just upload the file
            # otherwise we wait to see if how the vxstream anaysis of the hash goes
            while hash_analysis:
                sha256_observable = hash_analysis.get_observables_by_type(F_SHA256)
                if len(sha256_observable) == 1:
                    sha256_observable = sha256_observable[0]
                else:
                    raise RuntimeError("got {} sha256 observables from {}".format(len(sha256_observable), hash_analysis))

                hash_vx_analysis = self.wait_for_analysis(sha256_observable, FalconHashAnalysis)
                if hash_vx_analysis is None:
                    logging.warning("Falcon analysis for {} returned nothing".format(sha256_observable))
                    break

                # if we've already analyzed the hash then we're done (the analysis will be listed under the hash)
                if hash_vx_analysis.status in [ VXSTREAM_STATUS_ERROR, VXSTREAM_STATUS_SUCCESS ]:
                    return False

                # we're expecting the state to be UNKNOWN at this point
                if hash_vx_analysis.status not in [VXSTREAM_STATUS_UNKNOWN, None]:
                    logging.error("unexpected state {}".format(hash_vx_analysis.status))
                    return False

                break

            # does this file even exist?
            local_path = os.path.join(self.root.storage_dir, target.value)
            if not os.path.exists(local_path):
                logging.warning("{} does not exist".format(local_path))
                return False

            # should we be sandboxing this type of file?
            if not self.is_sandboxable_file(local_path):
                logging.debug("{} is not a supported file type for Falcon vx analysis".format(local_path))
                return False

            analysis = self.create_analysis(target)

            # this sample needs to be submitted
            job_id = None
            with open(local_path, 'rb') as fp:
                job_id = self.vx.analyze(fp, target.value)
            if job_id is None:
                logging.error("submission of {} failed".format(local_path))
                return False
            # should be a string 
            assert isinstance(job_id, str)

            analysis.job_id = job_id 
            analysis.submit_date = datetime.datetime.now()

        else:
            logging.debug("FalconFileAnalysis exists with status {} for target: {}".format(analysis.status, target))

        # at this point we have analysis for a file that has been submitted
        return self.execute_vxstream_analysis(target, analysis)

# vim: sw=4:ts=4:et:cc=120
import base64
import datetime
import json
import logging
import os
import requests
import xml.etree.ElementTree as xml

from hashlib import sha256
from os import mkdir, listdir, remove, rename
from os.path import isfile, join, basename, relpath, isdir

import saq

from saq.analysis import Analysis
from saq.constants import *
from saq.modules.sandbox import SandboxAnalysisModule
from saq.modules.file_analysis import FileHashAnalysis
from wildfirelib import parse

class WildfireAnalysis(Analysis):

    def initialize_details(self):
        self.details = {
            'sha256': sha256(open(path, 'rb').read()).hexdigest(),
            'verdict': None,
            'submit_date': None }

    def init(self, path):
        self.report = None

    def fail(self, message, error):
        self.verdict = '-101'
        try:
            error = error.split('<error-message>')[1].split('</error-message>')[0].strip().strip("'")
        except:
            error.replace('\n','').replace('\r','')

        self.report = "{}: {}".format(message, error)
        logging.debug("{}: {}".format(message, error))

    @property
    def sha256(self):
        return self.details['sha256']

    @sha256.setter
    def sha256(self, value):
        self.details['sha256'] = value
        self.set_modified()

    @property
    def verdict(self):
        return self.details['verdict']

    @verdict.setter
    def verdict(self, value):
        self.details['verdict'] = value
        self.set_modified()

    @property
    def submit_date(self):
        return self.details['submit_date']

    @submit_date.setter
    def submit_date(self, value):
        self.details['submit_date'] = value
        self.set_modified()

    def generate_summary(self):
        if self.verdict is None:
            return None
        elif self.verdict == '-100':
            return "Wildfire Analysis - Incomplete"
        elif self.verdict == '-101':
            if not hasattr(self, 'report') or self.report is None:
                return "Wildfire Analysis - Missing Report"
            if self.report.endswith('Unsupport File type'):
                return "Wildfire Analysis - Unsupported File Type"
            return "Wildfire Analysis - Failed"
        elif self.verdict == '-102':
            return "Wildfire Analysis - Not Submitted"
        elif self.verdict == '0':
            return "Wildfire Analysis - Benign"
        elif self.verdict == '1':
            return "Wildfire Analysis - Malware"
        elif self.verdict == '2':
            return "Wildfire Analysis - Grayware"
        else:
            return "Wildfire Analysis - Verdict Not Recognized {}".format(self.verdict)

class WildfireAnalyzer(SandboxAnalysisModule):

    @property
    def api_key(self):
        return self.config['api_key']

    @property
    def timeout(self):
        return self.config.getint('timeout')

    @property
    def frequency(self):
        return self.config.getint('frequency')

    @property
    def use_proxy(self):
        return self.config.getboolean('use_proxy')

    @property
    def proxies(self):
        if not self.use_proxy:
            return {}

        return {'http': saq.CONFIG['proxy']['http'], 'https': saq.CONFIG['proxy']['https'] }

    @property
    def generated_analysis_type(self):
        return WildfireAnalysis

    def verify_environment(self):
        self.verify_config_exists('frequency')
        self.verify_config_exists('api_key')
        self.verify_config_exists('use_proxy')
        self.verify_config_exists('timeout')
        self.verify_config_exists('supported_extensions')
    
    def execute_analysis(self, _file):
        # we want to sandbox the root file which this file originated from
        while _file.redirection:
            _file = _file.redirection
        path = os.path.join(self.root.storage_dir, _file.value)

        # create new wildfire analysis if none exists
        analysis = _file.get_analysis(WildfireAnalysis)
        if analysis is None:
            analysis = self.create_analysis(_file)
            analysis.init(path)

            # does this file even exist?
            if not os.path.exists(os.path.join(self.root.storage_dir, _file.value)):
                logging.debug("{} does not exist".format(_file))
                return

            # does this file have a supported file extension?
            is_supported = False
            file_extension = None
            try:
                file_extension = _file.value.rsplit('.', 1)[-1]
            except IndexError:
                pass

            if not self.is_sandboxable_file(os.path.join(self.root.storage_dir, _file.value)):
                logging.debug("{} is not a supported file type for vx analysis".format(_file))
                return

        # request verdict from wildfire
        job = { "apikey": self.api_key, "hash": analysis.sha256 }
        url = "https://wildfire.paloaltonetworks.com/publicapi/get/verdict"
        r = requests.post(url, data=job, verify=False, proxies=self.proxies)
        if r.status_code != 200:
            analysis.fail("failed to get verdict {}".format(r.status_code), r.text)
            return

        try:
            analysis.verdict = r.text.split('<verdict>')[1].split('</verdict>')[0].strip()
        except:
            analysis.fail("failed to get verdict 200", "format not recognized")
            return

        # if wildfire failed to analyze file
        if analysis.verdict == '-101':
            analysis.fail(r.text)
            return

        # if wildfire has never analyzed this file before then submit it and check back later
        elif analysis.verdict == '-102':
            logging.debug("submitting {} to wildfire for analysis".format(path))
            file = { "file" : (os.path.basename(path), open(path, 'rb').read()) }
            url = "https://wildfire.paloaltonetworks.com/publicapi/submit/file"
            r = requests.post(url, data=job, files=file, verify=False, proxies=self.proxies)
            if r.status_code != 200:
                analysis.fail("failed to submit file {}".format(r.status_code), r.text)
                return

            self.delay_analysis(_file, analysis, seconds=self.frequency)
            analysis.submit_date = datetime.datetime.now()
            return

        # if wildfire is currently analyzing the file then check back later
        elif analysis.verdict == '-100':
            # XXX refactor this out -- should already be a datetime object to begin with
            # I think that in some cases wildfire may already be processing a given file
            # in that case we may not receive a -102 message and thus not have a submit_date
            if not analysis.submit_date:
                logging.warning("{} got -100 result from wildfire without a "
                                "submit date set (already processing?)".format(path))
                analysis.submit_date = datetime.datetime.now()
            else:
                submit_date = analysis.submit_date
                if isinstance(submit_date, str):
                    submit_date = datetime.datetime.strptime(submit_date, '%Y-%m-%dT%H:%M:%S.%f')
                if datetime.datetime.now() > (submit_date + datetime.timedelta(minutes=self.timeout)):
                    logging.error("submission for {} sha256 {} has timed out".format(
                        _file.value, analysis.sha256))
                    return

            logging.debug("waiting on wildfire analysis...")
            self.delay_analysis(_file, analysis, seconds=self.frequency)
            return

        # tag appropriately if verdict is malware or grayware
        if analysis.verdict == '1':
            _file.add_tag('malicious')
        elif analysis.verdict == '2':
            _file.add_tag('grayware')

        # download the report
        logging.debug("downloading wildfire report")
        url = "https://wildfire.paloaltonetworks.com/publicapi/get/report"
        r = requests.post(url, data=job, verify=False, proxies=self.proxies)
        if r.status_code != 200:
            analysis.fail("failed to get report {}".format(r.status_code), r.text)
            return
        report_json = parse(r.text);

        # store the report
        wildfire_dir = "{}.wildfire".format(path)
        if not isdir(wildfire_dir):
            mkdir(wildfire_dir)

        # we also create this subdirectory to support the event2wiki.py script
        #wildfire_symlink_dir = os.path.join(self.root.storage_dir, 'wildfire.out')
        #if not os.path.isdir(wildfire_symlink_dir):
            #os.mkdir(wildfire_symlink_dir)
        #wildfire_symlink = os.path.join(wildfire_symlink_dir, os.path.basename(wildfire_dir))
        #if not os.path.islink(wildfire_symlink):
            #os.symlink(os.path.relpath(wildfire_dir, start=wildfire_symlink_dir), wildfire_symlink)

        report_path = join(wildfire_dir, "report.json")
        with open(report_path, "w") as report:
            json.dump(report_json, report)
        analysis.add_observable(F_FILE, relpath(report_path, start=self.root.storage_dir))

        # parse report for observables
        taskinfo = xml.fromstring(r.text).find('task_info')
        if taskinfo is None:
            return
        for report in taskinfo.findall('report'):
            # parse network section of report for observables
            network = report.find('network')
            if network is None:
                continue
            for tcp in network.findall('TCP'):
                ip = tcp.get('ip')
                if ip is not None:
                    analysis.add_observable(F_IPV4, ip)
            for udp in network.findall('UDP'):
                ip = udp.get('ip')
                if ip is not None:
                    analysis.add_observable(F_IPV4, ip)
            for dns in network.findall('dns'):
                type = dns.get('type')
                query = dns.get('query')
                response = dns.get('response')
                if query is not None:
                    analysis.add_observable(F_FQDN, query)
                if type is not None and response is not None:
                    if type == 'A':
                        analysis.add_observable(F_IPV4, response)
                    else:
                        analysis.add_observable(F_FQDN, response)
            for url in network.findall('url'):
                host = url.get('host')
                uri = url.get('uri')
                if host is None:
                    continue
                if uri is None:
                    analysis.add_observable(F_URL, host)
                else:
                    analysis.add_observable(F_URL, "{}{}".format(host, uri))
            
            # parse process reports
            process_list = report.find('process_list')
            if process_list is None:
                continue
            for process in process_list.findall('process'):
                files = process.find('file')
                if files is not None:
                    file_file_path = join(wildfire_dir, "report.windows_filepath")
                    with open(file_file_path, "a") as file_file:
                        for file in files:
                            name = file.get('name')
                            if name is not None:
                                file_file.write("{}\n".format(name))
                                if name.endswith(".exe") and file.get('md5') != "N/A":
                                    # download sample
                                    job = { "apikey": self.api_key, "hash": file.get('md5') }
                                    url = "https://wildfire.paloaltonetworks.com/publicapi/get/sample"
                                    r = requests.post(url, data=job, verify=False, proxies=self.proxies)
                                    if (r.status_code == 200):
                                        outpath = join(wildfire_dir, "{}.exe".format(file.get('md5')))
                                        with open(outpath, "wb") as fp:
                                            fp.write(r.content)
                                        analysis.add_observable(F_FILE, os.path.relpath(outpath, start=self.root.storage_dir))
                    analysis.add_observable(F_FILE, os.path.relpath(file_file_path, start=self.root.storage_dir))

                # parse registry events
                regs = process.find('registry')
                if regs is not None:
                    reg_file_path = join(wildfire_dir, "report.windows_registry")
                    with open(reg_file_path, "a") as reg_file:
                        for reg in regs:
                            key = "{}\\{}".format(reg.get('key'), reg.get('subkey'))
                            reg_file.write("{}\n".format(key))
                    analysis.add_observable(F_FILE, os.path.relpath(reg_file_path, start=self.root.storage_dir))

                # parse mutex events
                mutexs = process.find('mutex')
                if mutexs is not None:
                    mutex_file_path = join(wildfire_dir, "report.windows_mutex")
                    with open(mutex_file_path, "a") as mutex_file:
                        for mutex in mutexs:
                            mutex_file.write("{}\n".format(mutex.get('name')))
                    analysis.add_observable(F_FILE, os.path.relpath(mutex_file_path, start=self.root.storage_dir))

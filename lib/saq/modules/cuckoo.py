# vim: sw=4:ts=4:et:cc=120
import datetime
import io
import json
import logging
import re
import tarfile

from hashlib import md5
from multiprocessing import Value
from os import mkdir, listdir, remove, rename
from os.path import exists, isfile, join, basename, relpath, isdir
from zipfile import ZipFile, BadZipFile

import saq
from saq.analysis import Analysis
from saq.constants import *
from saq.error import report_exception
from saq.modules.sandbox import SandboxAnalysisModule

import requests

class CuckooAnalysis(Analysis):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def init(self, path):
        self.details = {
            'complete': False,
            'md5': md5(open(path, 'rb').read()).hexdigest(),
            'tasks': {},
            'malscore': 0,
            'start_date': datetime.datetime.now(),
            'server': None
            }

    def fail(self, message):
        message.replace('\n','').replace('\r','')
        logging.error(message)
        self.complete = True

    @property
    def server(self):
        return self.details['server']

    @server.setter
    def server(self, value):
        self.details['server'] = value

    @property
    def complete(self):
        return self.details['complete']

    @complete.setter
    def complete(self, value):
        self.details['complete'] = value

    @property
    def tasks(self):
        return self.details['tasks']

    @tasks.setter
    def tasks(self, value):
        self.details['tasks'] = value

    @property
    def malscore(self):
        return self.details['malscore']

    @malscore.setter
    def malscore(self, value):
        self.details['malscore'] = value

    @property
    def start_date(self):
        return self.details['start_date']

    @start_date.setter
    def start_date(self, value):
        self.details['start_date'] = value

    @property
    def md5(self):
        return self.details['md5']

    @md5.setter
    def md5(self, value):
        self.details['md5'] = value

    def generate_summary(self):
        return "Cuckoo Analysis ({}/10.0)".format(self.malscore)

class CuckooAnalyzer(SandboxAnalysisModule):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        requests.packages.urllib3.disable_warnings() # XXX take care of this properly
        self.server_index = Value('i', 0)

    @property
    def frequency(self):
        return self.config.getint('frequency')

    @property
    def servers(self):
        return self.config['hosts'].split(',')

    @property
    def timeout(self):
        return self.config.getint('timeout')

    @property
    def threat_score_threshold(self):
        return self.config.getfloat('threat_score_threshold')

    @property
    def protocol(self):
        if 'protocol' in self.config:
            return self.config['protocol']

        return 'http'

    def execute_analysis(self, sample):
        # we want to sandbox the root file which this file originated from
        while sample.redirection:
            sample = sample.redirection
        path = join(self.root.storage_dir, sample.value)

        # create new cuckoo analysis if none exists
        analysis = sample.get_analysis(CuckooAnalysis)
        if analysis is None:
            analysis = CuckooAnalysis()
            sample.add_analysis(analysis)
            analysis.init(path)

            # make sure the file exists
            if not exists(join(self.root.storage_dir, sample.value)):
                logging.debug("{} does not exist".format(sample))
                analysis.fail("{} does not exist".format(sample.value))
                return

            if not self.is_sandboxable_file(join(self.root.storage_dir, sample.value)):
                logging.debug("{} is not a supported file type for vx analysis".format(sample))
                analysis.complete = True
                return

        # stop if cuckoo analysis has already been completed for this file
        if analysis.complete:
            logging.debug("cuckoo analysis already complete for {}".format(sample.value))
            return

        # check if cuckoo has exceeded allotted time
        start_date = analysis.start_date # XXX refactor this out (should already be datetime)
        if isinstance(start_date, str):
            start_date = datetime.datetime.strptime(analysis.start_date, '%Y-%m-%dT%H:%M:%S.%f')
        if datetime.datetime.now() > (start_date + datetime.timedelta(minutes=self.timeout)):
            logging.error("cuckoo analysis timed out for {}".format(sample.value))
            analysis.complete = True
            return

        tasks = []
        for server in self.servers:
            try:
                # get existing tasks
                tasks = self.get_tasks(server, analysis)

                # use this server if it has tasks for our sample
                if len(tasks) > 0:
                    logging.debug("found existing task for {} on {}".format(sample.value, server))
                    analysis.server = server;
                    break

            except Exception as e:
                logging.error("unable to query for existing tasks: {}".format(e))
                report_exception()
                analysis.fail(str(e))
                return

        # if no server had existing tasks then pick one to submit to
        if analysis.server is None:
            analysis.server = self.servers[self.server_index.value]
            logging.debug("selected cuckoo server {}".format(analysis.server))
            with self.server_index.get_lock():
                self.server_index.value += 1
                if self.server_index.value >= len(self.servers):
                    self.server_index.value = 0

        # submit the sample if there are no existing tasks
        if len(tasks) == 0:
            try:
                self.submit_sample(server, path)
            except Exception as e:
                logging.error("unable to submit {} to {}: {}".format(path, server, e))
                report_exception()
                analysis.fail(str(e))
                return

            self.delay_analysis(sample, analysis, seconds=self.frequency)
            return

        # fetch report for all completed tasks
        analysis.complete = True
        for task in tasks:
            # ignore if we have already processed this task
            if task['id'] in analysis.tasks:
                continue

            if task['status'] == "failed_analysis":
                analysis.tasks[task['id']] = True
                continue

            if task['status'] != "reported":
                analysis.complete = False
                continue

            # mark task as complete
            analysis.tasks[task['id']] = True

            # get report
            self.download_report(server, task['id'], analysis, path)

            # get memory dumps
            self.download_procmem(server, task['id'], analysis, path)

            # get dropped files
            self.download_dropped(server, task['id'], analysis, path)

        # if we have not received a report for every task then check back later
        if not analysis.complete:
            self.delay_analysis(sample, analysis, seconds=self.frequency)

        # mark samples as malicious that exceed the threshold defined in the configuration file
        if analysis.malscore >= self.threat_score_threshold:
            sample.add_tag('malicious')

    # gets list of tasks linked to this sample
    def get_tasks(self, server, analysis):
        logging.debug("looking for existing tasks")
        r = requests.get("{}://{}/api/tasks/search/md5/{}".format(self.protocol, server, analysis.md5), 
                         proxies=self.proxies, verify=False) # XXX
        if r.status_code != 200:
            raise Exception("failed to get tasks: status code {}".format(r.status_code))
        response = json.loads(r.text)
        if response['error'] == True:
            raise Exception("failed to get tasks: {}".format(response['error_value']))
        if response['data'] == "Sample not found in database":
            return []
        if isinstance(response['data'], str):
            raise Exception("failed to get tasks: {}".format(response['data']))
        return response['data']

    # submits sample to cuckoo for processing
    def submit_sample(self, server, path):
        parts = basename(path).split('.')
        ext = "default"
        if len(parts) > 1:
            ext = parts[-1]
        tags = []
        if ext in self.config:
            tags = self.config[ext].split(',')
        else:
            tags = self.config["default"].split(',')

        for tag in tags:
            with open(path, 'rb') as fp:
                sample = { "file" : (basename(path), fp) }
                url = "{}://{}/api/tasks/create/file/".format(self.protocol, server)
                options = { 'options':'procmemdump=yes', 'custom':'ace', 'tags':tag }
                logging.info("submitting sample {} to cuckoo server {} with tag {}".format(path, server, tag))
                r = requests.post(url, files = sample, data = options, proxies=self.proxies, verify=False) # XXX
                if r.status_code != 200:
                    raise Exception("failed to submit: status code {}".format(r.status_code))
                response = json.loads(r.text)
                if response['error'] == True:
                    raise Exception("failed to submit: {}".format(response['error_value']))

    # fetch report for task
    def download_report(self, server, id, analysis, path):
        # download report
        logging.debug("fetching report for task_id {}".format(id))
        r = requests.get("{}://{}/api/tasks/get/report/{}".format(self.protocol, server, id), 
                         proxies=self.proxies, verify=False) # XXX
        if r.status_code != 200:
            logging.error("failed to get report")
            return

        # append report to reports file
        cuckoo_dir = "{}.cuckoo".format(path)
        if not isdir(cuckoo_dir):
            mkdir(cuckoo_dir)
        reports = join(cuckoo_dir, "report{}.json".format(id))
        with open(reports, "w") as fp:
            fp.write(r.text)
            fp.write("\n")
        #analysis.add_observable(F_FILE, relpath(reports, start=self.root.storage_dir))

        # we also create this subdirectory to support the event2wiki.py script
        #cuckoo_symlink_dir = os.path.join(self.root.storage_dir, 'cuckoo.out')
        #if not os.path.isdir(cuckoo_symlink_dir):
            #os.mkdir(cuckoo_symlink_dir)
        #cuckoo_symlink = os.path.join(cuckoo_symlink_dir, os.path.basename(cuckoo_dir))
        #if not os.path.islink(cuckoo_symlink):
            #os.symlink(os.path.relpath(cuckoo_dir, start=cuckoo_symlink_dir), cuckoo_symlink)

        # load report as json object
        report = json.loads(r.text)

        # increase malscore if this reports malscore is higher
        if report['malscore'] > analysis.malscore:
            analysis.malscore = report['malscore']

        # record file paths for scanning
        file_paths = join(cuckoo_dir, "report.windows_filepath")
        with open(file_paths, "a") as fp:
            for file_path in report['behavior']['summary']['files']:
                fp.write("{}\n".format(file_path))
        analysis.add_observable(F_FILE, relpath(file_paths, start=self.root.storage_dir))

        # record reg keys for scanning
        reg_keys = join(cuckoo_dir, "report.windows_registry")
        with open(reg_keys, "a") as fp:
            for reg_key in report['behavior']['summary']['keys']:
                fp.write("{}\n".format(reg_key))
        analysis.add_observable(F_FILE, relpath(reg_keys, start=self.root.storage_dir))

        # record mutexes for scanning
        mutexes = join(cuckoo_dir, "report.windows_mutex")
        with open(mutexes, "a") as fp:
            for mutex in report['behavior']['summary']['mutexes']:
                fp.write("{}\n".format(mutex))
        analysis.add_observable(F_FILE, relpath(mutexes, start=self.root.storage_dir))

        # add network observables
        if 'udp' in report['network']:
            for udp in report['network']['udp']:
                if not udp['src'].startswith("192."):
                    analysis.add_observable(F_IPV4, udp['src'])
                if not udp['dst'].startswith("192."):
                    analysis.add_observable(F_IPV4, udp['dst'])
        if 'http' in report['network']:
            for http in report['network']['http']:
                analysis.add_observable(F_URL, http['uri'])
        if 'tcp' in report['network']:
            for tcp in report['network']['tcp']:
                if not tcp['src'].startswith("192."):
                    analysis.add_observable(F_IPV4, tcp['src'])
                if not tcp['dst'].startswith("192."):
                    analysis.add_observable(F_IPV4, tcp['dst'])
        if 'domains' in report['network']:
            for domain in report['network']['domains']:
                analysis.add_observable(F_FQDN, domain['domain'])
        if 'icmp' in report['network']:
            for icmp in report['network']['icmp']:
                if not icmp['src'].startswith("192."):
                    analysis.add_observable(F_IPV4, icmp['src'])
                if not icmp['dst'].startswith("192."):
                    analysis.add_observable(F_IPV4, icmp['dst'])
        if 'host' in report['network']:
            for host in report['network']['hosts']:
                if not host['ip'].startswith("192."):
                    analysis.add_observable(F_IPV4, host['ip'])
                if host['hostname'] != "":
                    analysis.add_observable(F_FQDN, host['hostname'])
        if 'dns' in report['network']:
            for dns in report['network']['dns']:
                analysis.add_observable(F_FQDN, dns['request'])
                for answer in dns['answers']:
                    if answer['data'] != "":
                        if answer['type'] == "A":
                            analysis.add_observable(F_IPV4, answer['data'])
                        else:
                            analysis.add_observable(F_FQDN, answer['data'])

    # fetch memory dump
    def download_procmem(self, server, id, analysis, path):
        # XXX this is too big 2/7/2017
        return

        logging.debug("downloading process memory dumps")
        r = requests.get("{}://{}/api/tasks/get/procmemory/{}/".format(self.protocol, server, id), 
                         proxies=self.proxies, verify=False) # XXX
        logging.debug("status code = {}".format(r.status_code))
        if r.status_code != 200:
            logging.warning("failed to get procmemory: status code {}".format(r.status_code))
            return
        try:
            if r.content[0] == 123:
                response = json.loads(r.text)
                if response['error'] == True:
                    logging.warning("failed to get procmemory: {}".format(response['error_value']))
                    return
        except Exception:
            pass

        # extract all memory dumps
        cuckoo_dir = "{}.cuckoo".format(path)
        if not isdir(cuckoo_dir):
            mkdir(cuckoo_dir)
        with tarfile.open(fileobj=io.BytesIO(r.content)) as tar_archive:
            for member in tar_archive.getmembers():
                tar_archive.extract(member, path=cuckoo_dir)
                member_path = join(cuckoo_dir, member.name)
                try:
                    with ZipFile(member_path, 'r') as zip_ref:
                        for name in zip_ref.namelist():
                            content = zip_ref.read(name)
                            if '.strings' in name:
                                strings_file = join(cuckoo_dir, "memory_strings.dat")
                                with open(strings_file, 'ab') as strings:
                                    strings.write(content)
                                    strings.write(b"\n")
                                analysis.add_observable(F_FILE, relpath(strings_file, start=self.root.storage_dir))
                            else:
                                binary_file = join(cuckoo_dir, "memory_binary.dat")
                                with open(binary_file, 'ab') as binary:
                                    binary.write(content)
                                analysis.add_observable(F_FILE, relpath(binary_file, start=self.root.storage_dir))
                        remove(member_path)
                except BadZipFile:
                    # file is not a zip file so just add it as a normal file
                    file_observable = analysis.add_observable(F_FILE, relpath(member_path, start=self.root.storage_dir))
                    file_observable.add_tag("memory_dump")

    # fetch dropped files
    def download_dropped(self, server, id, analysis, path):
        logging.debug("downloading dropped files")
        r = requests.get("{}://{}/api/tasks/get/dropped/{}/".format(self.protocol, server, id), 
                         proxies=self.proxies, verify=False) # XXX
        if r.status_code != 200:
            logging.warning("failed to get dropped files: status code {}".format(r.status_code))
            return
        try:
            if r.content[0] == 123:
                response = json.loads(r.text)
                if response['error'] == True:
                    logging.warning("failed to get dropped files: {}".format(response['error_value']))
                    return
        except Exception:
            pass

        # extract all dropped files
        cuckoo_dir = "{}.cuckoo".format(path)
        if not isdir(cuckoo_dir):
            mkdir(cuckoo_dir)
        with tarfile.open(fileobj=io.BytesIO(r.content)) as tar_archive:
            members = tar_archive.getmembers()
            for member in members:
                logging.debug("member name = {}".format(member.name))
                if '.' not in member.name:
                    tar_archive.extract(member, path=cuckoo_dir)
                    dropped_file = join(cuckoo_dir, member.name)
                    magic_sig = open(dropped_file, 'rb').read(2)
                    logging.debug("magic_sig = {}".format(magic_sig))
                    if magic_sig == b"MZ":
                        new_path = "{}.exe".format(dropped_file)
                        logging.debug("renaming {} to {}".format(dropped_file, new_path))
                        rename(dropped_file, new_path)
                        analysis.add_observable(F_FILE, relpath(new_path, start=self.root.storage_dir))
                    else:
                        remove(dropped_file)

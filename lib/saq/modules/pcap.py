# vi: sw=4:ts=4:et

import logging
import os
import os.path
import saq
import shutil
import sys
import tempfile

from subprocess import Popen, PIPE, DEVNULL

from saq.analysis import Analysis, Observable
from saq.constants import *
from saq.modules import ExternalProcessAnalysisModule, AnalysisModule
from saq.observables import IPv4Observable

class PcapExtractionAnalysis(Analysis):
    """What was the network traffic for this IP address or conversation?"""

    def initialize_details(self):
        self.details = None

    def generate_summary(self):
        if len(self.observables) == 0:
            return None

        return 'PCAP Extraction ({} files)'.format(len(self.observables))

class PcapConversationExtraction(ExternalProcessAnalysisModule):
    """Automatically pulls pcap for any FIPV4_CONVERSATION that comes in with an Alert."""

    def verify_environment(self):
        self.verify_config_exists('relative_duration')
        self.verify_config_exists('executable_path')
        self.verify_config_exists('config_path')
        self.verify_config_exists('max_pcap_count')
        self.verify_path_exists(self.config['executable_path'])
        self.verify_path_exists(self.config['config_path'])
    
    @property
    def relative_duration(self):
        return self.config['relative_duration']

    @property
    def executable_path(self):
        path = self.config['executable_path']
        if os.path.isabs(path):
            return path
        return os.path.join(saq.SAQ_HOME, path)

    @property
    def config_path(self):
        path = self.config['config_path']
        if os.path.isabs(path):
            return path
        return os.path.join(saq.SAQ_HOME, path)

    @property
    def max_pcap_count(self):
        return self.config.getint('max_pcap_count')

    @property
    def generated_analysis_type(self):
        return PcapExtractionAnalysis

    @property
    def valid_observable_types(self):
        return F_IPV4_CONVERSATION

    def execute_analysis(self, conversation):

        # we only pull pcap for IP addresseses that 
        # 1) came with the alert
        # 2) is suspect (see https://wiki.local/w/index.php/ACE_Development_Guide#Detection_Points)
        if not conversation in self.root.observables and not conversation.is_suspect:
            logging.debug("{} does not meet criteria for extraction".format(conversation))
            return False

        # are we at our limit?
        if self.root.get_action_counter('pcap_conversation') >= self.max_pcap_count:
            logging.debug("exceeded pcap_conversation count skipping pcap extract for {}".format(conversation))
            return False

        # if BOTH addresses are excluded then we do not collect PCAP
        # XXX do we still need this?  we have built-in exclusions support now
        src_ipv4, dst_ipv4 = parse_ipv4_conversation(conversation.value)
        if self.is_excluded(IPv4Observable(src_ipv4)) and self.is_excluded(IPv4Observable(dst_ipv4)):
            logging.debug("excluding conversation {}".format(conversation.value))
            return False

        analysis = self.create_analysis(conversation)

        pcap_dir = os.path.join(self.root.storage_dir, 'pcap', '{0}_pcap'.format(conversation))
        extraction_time = conversation.time if conversation.time is not None else self.root.event_time
        logging.debug("collecting pcap from {0} into {1} at time {2}".format(conversation, pcap_dir, extraction_time))

        if self.extract_pcap(
            conversation=conversation.value,
            event_time=extraction_time,
            output_dir=pcap_dir):

            self.root.increment_action_counter('pcap_conversation')

            # look inside the newly created directory for .pcap files
            pcap_file_count = 0
            for pcap_file in os.listdir(pcap_dir):
                if not pcap_file.endswith('.pcap'):
                    continue

                # skip ones that have a size of 24 bytes (which is an empty pcap file)
                pcap_path = os.path.join(pcap_dir, pcap_file)
                if os.path.getsize(pcap_path) < 25:
                    logging.debug("removing empty pcap file {0}".format(pcap_path))
                    try:
                        os.remove(pcap_path)
                    except Exception as e:
                        logging.error("unable to delete file {0}: {1}".format(pcap_path, str(e)))
                    continue

                logging.debug("found pcap file {0}".format(pcap_path))
                pcap_file_count += 1

                # add it as an observable to the analysis
                analysis.add_observable(F_FILE, os.path.relpath(pcap_path, start=self.root.storage_dir))

            return True

        else:
            logging.error("unable to get pcap for conversation {0}".format(conversation))
            return False

    def extract_pcap(self, *args, **kwargs):
        try:
            if not self.acquire_semaphore():
                logging.warning("unable to acquire semaphore")
                return False

            return self.extract_pcap_exec(*args, **kwargs)
        finally:
            self.release_semaphore()

    def extract_pcap_exec(self, conversation, event_time, output_dir):
        assert conversation is not None
        assert output_dir is not None

        src, dst = parse_ipv4_conversation(conversation)

        event_time = event_time.strftime('%Y-%m-%d %H:%M:%S %z')

        bpf = '(host {} and host {})'.format(src, dst)
        logging.info("extracting pcap using BPF {} @ {} duration {} to {}".format(bpf, event_time, self.relative_duration, output_dir))

        # also collect stdout and stderr for troubleshooting
        # collect the pcap
        self.external_process = Popen([
            self.executable_path,
            '-c', self.config_path,
            '-D', output_dir,
            '-t', event_time,
            '-d', self.relative_duration,
            '-r',
            bpf], preexec_fn=os.setsid,
            stdout = DEVNULL,
            stderr = DEVNULL)
        self.external_process.wait()
    
        logging.debug("got return code {} for pcap_extract".format(self.external_process.returncode))

        if self.external_process.returncode != 0:
            logging.error("pcap extraction returned {}".format(str(self.external_process.returncode)))
            return False

        return True

class TsharkAnalysis(Analysis):
    def generate_summary(self):
        return 'Tshark PCAP Analysis'

class TsharkPcapAnalyzer(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return TsharkAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, pcap):
        from saq.modules.file_analysis import FileTypeAnalysis

        # we need file type analysis first
        file_type_analysis = self.wait_for_analysis(pcap, FileTypeAnalysis)
        if file_type_analysis is None:
            return

        # make sure the file exists
        if not os.path.exists(os.path.join(self.root.storage_dir, pcap.value)):
            logging.error("pcap path {0} does not exist".format(pcap.value))
            return
    
        # make sure this is a pcap file
        if file_type_analysis.mime_type != 'application/vnd.tcpdump.pcap':
            logging.debug("invalid mime type: {0}".format(file_type_analysis.mime_type))
            return

        tshark_output_path = os.path.join(self.root.storage_dir, '{0}.tshark'.format(pcap.value))
        tshark_stderr_path = os.path.join(self.root.storage_dir, '{0}.tshark.stderr'.format(pcap.value))

        with open(tshark_output_path, 'wb') as stdout_fp:
            with open(tshark_stderr_path, 'wb') as stderr_fp:
                #logging.debug("analyzing {0} with tshark".format(pcap.value))
                p = Popen(['tshark', '-t', 'a', '-V', '-r', os.path.join(self.root.storage_dir, pcap.value)], 
                    stdout=stdout_fp, stderr=stderr_fp)
                p.wait()
                #logging.debug("finished analyzing {0} with tshark".format(pcap.value))

        # XXX it will become important to pass this information on to the GUI somehow
        if os.path.getsize(tshark_stderr_path) > 0:
            logging.error("tshark reported messages on stderr: {0}".format(tshark_stderr_path))
        else:
            try:
                os.remove(tshark_stderr_path)
            except Exception as e:
                logging.error("unable to delete {0}: {1}".format(tshark_stderr_path, str(e)))

        analysis = TsharkAnalysis()
        pcap.add_analysis(analysis)

        if os.path.getsize(tshark_output_path) > 0:
            analysis.add_observable(F_FILE, os.path.relpath(tshark_output_path, start=self.root.storage_dir))


class BroAnalysis(Analysis):
    pass

class BroAnalyzer(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return BroAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, pcap):
        from saq.modules.file_analysis import FileTypeAnalysis

        # we need file type analysis first
        file_type_analysis = self.wait_for_analysis(pcap, FileTypeAnalysis)
        if file_type_analysis is None:
            return

        # make sure the file exists
        if not os.path.exists(os.path.join(self.root.storage_dir, pcap.value)):
            logging.error("pcap path {0} does not exist".format(pcap.value))
            return

        # make sure this is a pcap file
        if file_type_analysis.mime_type != 'application/vnd.tcpdump.pcap':
            return
        
        # we need a directory to put all these things into
        output_dir = '{0}.bro_analysis'.format(os.path.join(self.storage_dir, pcap.value))
        if not os.path.isdir(output_dir):
            try:
                os.mkdir(output_dir)
            except Exception as e:
                logging.error("unable to create directory {0}: {1}".format(output_dir, str(e)))
                return

        # and a place to put all the extracted files into
        extraction_dir = os.path.join(output_dir, 'extraction')
        if not os.path.isdir(extraction_dir):
            try:
                os.mkdir(extraction_dir)
            except Exception as e:
                logging.error("unable to create directory {0}: {1}".format(extraction_dir, str(e)))
                return

        bro_stdout_path = os.path.join(output_dir, 'bro.stdout')
        bro_stderr_path = os.path.join(output_dir, 'bro.stdout')

        with open(bro_stdout_path, 'wb') as stdout_fp:
            with open(bro_stderr_path, 'wb') as stderr_fp:
                logging.debug("executing bro against {0}".format(pcap.value))
                p = Popen([
                    saq.CONFIG.get(self.config_section, 'bro_bin_path'),
                    '-r', os.path.join(saq.SAQ_HOME, pcap.value),
                    '-e', 'redef FileExtract::prefix = "{0}/";'.format(extraction_dir),
                    os.path.join(saq.SAQ_HOME, 'etc', 'bro', 'ace.bro')],
                    stdout=stdout_fp,
                    stderr=stderr_fp,
                    cwd=output_dir)
                p.wait()

        # parse bro log files
        # TODO



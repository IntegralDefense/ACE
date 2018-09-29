import datetime
import collections
import logging
import os
import os.path
import re
import shutil
import uuid

import saq

from saq.analysis import RootAnalysis
from saq.anp import *
from saq.constants import *
from saq.engine import Engine, MySQLCollectionEngine, ANPNodeEngine
from saq.error import report_exception

REGEX_CONNECTION_ID = re.compile(r'^(C[^\.]+\.\d)\.ready$')

#
# In local mode the http engine is collecting files directly from bro as it dumps them
# and then submitting them as work items to the engine.
#
# In client mode the engine is collection them and submitting them to the configured
# anp remote nodes. Once it sends the ANP_COMMAND_PROCESS command it then deletes the local
# files.
#
# In server mode the engine is expecting files to be delivered by an anp client. Once the
# engine receives the ANP_COMMAND_PROCESS command, it adds the work to the sql workload table
# (using the MySQLCollectionEngine to accomplish this) which keeps track of the files.
#

class HTTPScanningEngine(ANPNodeEngine, MySQLCollectionEngine, Engine): # XXX do I need to specify Engine here?

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # if set to True then we don't delete the work directories
        self.keep_work_dir = False

        # the location of the incoming http streams
        self.bro_http_dir = os.path.join(saq.SAQ_HOME, self.config['bro_http_dir'])

        # the list of streams (connection ids) that we need to process
        self.stream_list = collections.deque()

    @property
    def name(self):
        return 'http_scanner'

    def initialize_collection(self, *args, **kwargs):
        # before we start collecting, make sure that everything in our local directory
        # has a matching entry in the workload database
        # TODO
        pass

        super().initialize_collection(*args, **kwargs)

    def anp_command_handler(self, anp, command):
        """Handle inbound ANP commands from remote http engines."""

        if command.command == ANP_COMMAND_COPY_FILE:
            anp.send_message(ANPCommandOK())
        elif command.command == ANP_COMMAND_PROCESS:
            self.add_sql_work_item(command.target)
        else:
            self.default_command_handler(anp, command)

    def get_next_stream(self):
        """Returns the next HTTP stream to be processed or None if nothing is available to be processed."""
        # do we have a list yet?
        if len(self.stream_list) == 0:
            for file_name in os.listdir(self.bro_http_dir):
                m = REGEX_CONNECTION_ID.match(file_name)
                if m:
                    self.stream_list.append(m.group(1))

        if len(self.stream_list) == 0:
            return None

        return self.stream_list.popleft()

    def submit_stream(self, stream_prefix, node_id):
        # submit http request files
        logging.info("sending stream {}".format(stream_prefix))
        source_files = [ os.path.join(self.bro_http_dir, '{}.request'.format(stream_prefix)),
                         os.path.join(self.bro_http_dir, '{}.request.entity'.format(stream_prefix)),
                         os.path.join(self.bro_http_dir, '{}.reply'.format(stream_prefix)),
                         os.path.join(self.bro_http_dir, '{}.reply.entity'.format(stream_prefix)),
                         os.path.join(self.bro_http_dir, '{}.ready'.format(stream_prefix)) ]

        sent_files = []
        for source_file in source_files:
            if not os.path.exists(source_file):
                continue
            
            result = self.submit_command(ANPCommandCOPY_FILE(source_file, source_file), node_id)
            if result is None:
                # no servers available at the moment
                return False
            elif result.command == ANP_COMMAND_OK:
                continue
            elif result.command == ANP_COMMAND_ERROR:
                raise RuntimeError("remote server returned error message: {}".fomrat(result.error_message))
            else:
                raise ValueError("got unexpected command {}".format(result))

        # tell the remote system to process the files
        result = self.submit_command(ANPCommandPROCESS(stream_prefix), node_id)
        if result is None:
            logging.warning("did not receive a response for PROCESS command on {}".format(stream_prefix))
            return False
        elif result.command == ANP_COMMAND_OK:
            # if we get this far then all the files have been sent
            for sent_file in sent_files:
                try:
                    os.remove(sent_file)
                except Exception as e:
                    logging.error("unable to delete {}: {}".format(sent_file, e))
        elif result.command == ANP_COMMAND_ERROR:
            logging.warning("remote server returned error message: {}".format(result.error_message))
            return False
        else:
            logging.error("got unexpected command {}".format(result))
            return False

    def collect_client_mode(self):
        # gather extracted http files and submit them to the server node
        stream_prefix = self.get_next_stream()

        if stream_prefix is None:
            # nothing to do right now...
            logging.debug("no streams available to send")
            return False

        # do we have an anp node to send data to?
        node_id = self.get_available_node()
        if node_id is None:
            logging.info("waiting for available ANP node...")
            return False

        try:
            self.submit_stream(stream_prefix, node_id)
        except Exception as e:
            logging.error("unable to submit stream {}: {}".format(stream_prefix, e))
            report_exception() 

        return True

    def collect_local_mode(self):
        # gather extracted files and just process them
        stream_prefix = self.get_next_stream()
        if stream_prefix:
            self.add_work_item(stream_prefix)
            return True

        return False

    def collect_server_mode(self):
        # in server mode we just process our local workload
        return MySQLCollectionEngine.collect(self)

    def process(self, stream_prefix):

        # process the .ready file
        # file format is as follows
        #
        # C7kebl1wNwKQ1qOPck.1.ready
        # time = 1537467014.49546
        # interrupted = F
        # finish_msg = message ends normally
        # body_length = 433994
        # content_gap_length = 0
        # header_length = 494
        #

        base_path = os.path.join(self.bro_http_dir, stream_prefix)
        # the ready file contains stream summary info
        ready_path = '{}.ready'.format(base_path)
        # http request headers
        request_path = '{}.request'.format(base_path)
        # http request content (POST content for example)
        request_entity_path = '{}.request.entity'.format(base_path)
        # http response headers
        reply_path = '{}.reply'.format(base_path)
        # http response content
        reply_entity_path = '{}.reply.entity'.format(base_path)

        # make sure we have at least the files we expect (summary, and request headers)
        for path in [ ready_path, request_path ]:
            if not os.path.exists(path):
                logging.error("missing expected file {}".format(path))
                return False

        # parse the ready file
        stream_time = None
        interrupted = False
        content_gap_length = 0

        with open(ready_path, 'r') as fp:
            for line in fp:
                key, value = [_.strip() for _ in line.split(' = ')]
                
                if key == 'time':
                    stream_time = datetime.datetime.fromtimestamp(float(value))
                elif key == 'interrupted':
                    interrupted = value == 'T'
                elif key == 'content_gap_length':
                    content_gap_length = int(value)

        # parse the request
        request_headers = [] # of tuples of key, value
        request_headers_lookup = {} # key = key.lower()

        with open(request_path, 'r') as fp:
            request_ipv4 = fp.readline().strip()
            request_method = fp.readline().strip()
            request_original_uri = fp.readline().strip()
            request_unescaped_uri = fp.readline().strip()
            request_version = fp.readline().strip()

            for line in fp:
                key, value = [_.strip() for _ in line.split('\t')]
                request_headers.append((key, value))
                request_headers_lookup[key.lower()] = value

        # parse the response if it exists
        reply_headers = [] # of tuples of key, value
        reply_headers_lookup = {} # key = key.lower()
        reply_version = None
        reply_code = None
        reply_reason = None
        reply_ipv4 = None
        reply_port = None

        if os.path.exists(reply_path):
            with open(reply_path, 'r') as fp:
                reply_ipv4, reply_port = [_.strip() for _ in fp.readline().split('\t')]
                reply_port = int(reply_port)
                reply_version = fp.readline().strip()
                reply_code = fp.readline().strip()
                reply_reason = fp.readline().strip()

                for line in fp:
                    key, value = [_.strip() for _ in line.split('\t')]
                    reply_headers.append((key, value))
                    reply_headers_lookup[key.lower()] = value

        root = RootAnalysis()
        root.uuid = str(uuid.uuid4())
        root.storage_dir = os.path.join(self.collection_dir, root.uuid[0:3], root.uuid)
        root.initialize_storage()

        root.tool = 'ACE - Bro HTTP Scanner'
        root.tool_instance = self.hostname
        root.alert_type = 'http'
        root.description = 'BRO HTTP Scanner Detection - '
        root.event_time = datetime.datetime.now() if stream_time is None else stream_time
        root.details = { }

        root.add_observable(F_IPV4, request_ipv4)
        if reply_ipv4:
            root.add_observable(F_IPV4, reply_ipv4)

        if 'host' in request_headers_lookup:
            root.add_observable(F_FQDN, request_headers_lookup['host'])

        uri = request_original_uri[:]
        if 'host' in request_headers_lookup:
            # I don't think we'll ever see https here as that gets parsed as a different protocol in bro
            # we should only be seeing HTTP traffic
            uri = '{}://{}{}{}'.format('https' if reply_port == 443 else 'http', 
                                       request_headers_lookup['host'], 
                                       # if the default port is used then leave it out, otherwise include it in the url
                                       '' if reply_port == 80 else ':{}'.format(reply_port), 
                                       uri)
            root.add_observable(F_URL, uri)

        if request_original_uri != request_unescaped_uri:
            uri = request_unescaped_uri[:]
            if 'host' in request_headers_lookup:
                uri = '{}:{}'.format(request_headers_lookup['host'], uri)
                root.add_observable(F_URL, uri)

        # move all the files into the work directory and add them as file observables
        shutil.move(ready_path, root.storage_dir)
        root.add_observable(F_FILE, os.path.basename(ready_path))
        shutil.move(request_path, root.storage_dir)
        root.add_observable(F_FILE, os.path.basename(request_path))
        if os.path.exists(request_entity_path):
            shutil.move(request_entity_path, root.storage_dir)
            root.add_observable(F_FILE, os.path.basename(request_entity_path))
        if os.path.exists(reply_path):
            shutil.move(reply_path, root.storage_dir)
            root.add_observable(F_FILE, os.path.basename(reply_path))
        if os.path.exists(reply_entity_path):
            shutil.move(reply_entity_path, root.storage_dir)
            root.add_observable(F_FILE, os.path.basename(reply_entity_path))

        try:
            root.save()
        except Exception as e:
            logging.error("unable to save {}: {}".format(root, e))
            report_exception()
            return False

        # now analyze the file
        try:
            self.analyze(root)
        except Exception as e:
            logging.error("analysis failed for {}: {}".format(path, e))
            report_exception()

    def post_analysis(self, root):
        if self.should_alert(root):
            root.submit()
            self.cancel_analysis()
        else:
            # any outstanding analysis left?
            if root.delayed:
                logging.debug("{} has delayed analysis -- waiting for cleanup...".format(root))
                return

    def root_analysis_completed(self, root):
        if root.delayed:
            return

        if not self.keep_work_dir:
            root.delete()

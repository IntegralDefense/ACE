import collections
import logging
import os
import os.path
import re
import shutil
import uuid

import saq

from saq.analysis import RootAnalysis
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

class HTTPScanningEngine(MySQLCollectionEngine, ANPNodeEngine, Engine): # XXX do I need to specify Engine here?

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

    def submit_stream(self, stream_prefix):
        # submit http request files
        source_files = [ os.path.join(self.bro_http_dir, '{}.request'.format(stream_prefix)),
                         os.path.join(self.bro_http_dir, '{}.request.entity'.format(stream_prefix)),
                         os.path.join(self.bro_http_dir, '{}.reply'.format(stream_prefix)),
                         os.path.join(self.bro_http_dir, '{}.reply.entity'.format(stream_prefix)),
                         os.path.join(self.bro_http_dir, '{}.ready'.format(stream_prefix)) ]

        sent_files = []
        for source_file in source_files:
            if not os.path.exists(source_file):
                continue
            
            # note that the relative paths here are the same both locally and remotely
            result = self.submit_command(ANPCommandCOPY_FILE(source_file, source_file))
            if result.command == ANP_COMMAND_OK:
                continue
            elif result.command == ANP_COMMAND_ERROR:
                raise RuntimeError("remote server returned error message: {}".fomrat(result.error_message))
            else:
                raise ValueError("got unexpected command {}".format(result))

        # tell the remote system to process the files
        result = self.submit_command(ANPCommandPROCESS(stream_prefix))
        if result.command == ANP_COMMAND_OK:
            # if we get this far then all the files have been sent
            for sent_file in sent_files:
                try:
                    os.remove(sent_file)
                except Exception as e:
                    logging.error("unable to delete {}: {}".format(sent_file, e))
        elif result.command == ANP_COMMAND_ERROR:
            raise RuntimeError("remote server returned error message: {}".fomrat(result.error_message))
        else:
            raise ValueError("got unexpected command {}".format(result))

    def collect_client_mode(self):
        # gather extracted http files and submit them to the server node
        stream_prefix = self.get_next_stream()

        if stream_prefix is None:
            # nothing to do right now...
            return False

        try:
            self.submit_stream(stream_prefix)
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

    def process(self, path):

        root = RootAnalysis()
        root.storage_dir = path

        try:
            root.load()
        except Exception as e:
            logging.error("unable to load {}: {}".format(root, e))
            report_exception()

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

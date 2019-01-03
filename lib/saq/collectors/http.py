# vim: sw=4:ts=4:et:cc=120

import collections
import datetime
import os, os.path
import re
import socket
import logging

import saq
from saq.constants import *
from saq.collectors import Collector, Submission

REGEX_CONNECTION_ID = re.compile(r'^(C[^\.]+\.\d+)\.ready$')
HTTP_DETAILS_REQUEST = 'request'
HTTP_DETAILS_REPLY = 'reply'
HTTP_DETAILS_READY = 'ready'

class BroHTTPStreamCollector(Collector):
    def __init__(self, *args, **kwargs):
        super().__init__(workload_type='http', delete_files=True, *args, **kwargs)

        # the location of the incoming http streams
        self.bro_http_dir = os.path.join(saq.DATA_DIR, saq.CONFIG['bro']['http_dir'])

        # the list of streams (connection ids) that we need to process
        self.stream_list = collections.deque()

        # for tool_instance
        self.hostname = socket.getfqdn()

    def get_next_submission(self):
        """Returns the next HTTP stream to be processed or None if nothing is available to be processed."""
        # we collect a list of stuff to send so that we don't have to query the
        # directory listing every time we submit 
        if len(self.stream_list) == 0:
            for file_name in os.listdir(self.bro_http_dir):
                m = REGEX_CONNECTION_ID.match(file_name)
                if m:
                    # found a "ready" file indicating the stream is ready for processing
                    stream_prefix = m.group(1)
                    logging.info("found http stream {}".format(stream_prefix))

                    # these are all the possible files that can exist for a single stream request/response
                    source_files = [ os.path.join(self.bro_http_dir, '{}.request'.format(stream_prefix)),
                                     os.path.join(self.bro_http_dir, '{}.request.entity'.format(stream_prefix)),
                                     os.path.join(self.bro_http_dir, '{}.reply'.format(stream_prefix)),
                                     os.path.join(self.bro_http_dir, '{}.reply.entity'.format(stream_prefix)),
                                     os.path.join(self.bro_http_dir, '{}.ready'.format(stream_prefix)) ]

                    # filter this list down to what is actually available for this one
                    source_files = [f for f in source_files if os.path.exists(f)]

                    # create a new submission request for this
                    self.stream_list.append(Submission(
                        description = 'BRO HTTP Scanner Detection - {}'.format(stream_prefix),
                        analysis_mode = ANALYSIS_MODE_HTTP,
                        tool = 'ACE - Bro HTTP Scanner',
                        tool_instance = self.hostname,
                        type = ANALYSIS_TYPE_BRO_HTTP,
                        event_time = datetime.datetime.fromtimestamp(os.path.getmtime(os.path.join(
                                                                                      self.bro_http_dir, file_name))),
                        details = {},
                        observables = [],
                        tags = [],
                        files=source_files))

        if len(self.stream_list) == 0:
            return None

        return self.stream_list.popleft()

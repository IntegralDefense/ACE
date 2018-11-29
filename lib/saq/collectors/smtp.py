# vim: sw=4:ts=4:et:cc=120

import collections
import datetime
import os, os.path
import socket
import logging

import saq
from saq.constants import *
from saq.collectors import Collector, Submission

class BroSMTPStreamCollector(Collector):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # the location of the incoming smtp streams
        self.bro_smtp_dir = os.path.join(saq.SAQ_HOME, saq.CONFIG['bro']['smtp_dir'])

        # the list of streams (connection ids) that we need to process
        self.stream_list = collections.deque()

        # for tool_instance
        self.hostname = socket.getfqdn()

    def get_next_submission(self):
        """Returns the next SMTP stream to be processed or None if nothing is available to be processed."""
        # we collect a list of stuff to send so that we don't have to query the
        # directory listing every time we submit 
        if len(self.stream_list) == 0:
            for file_name in os.listdir(self.bro_smtp_dir):
                # each completed SMTP capture has a corresponding .ready file
                # to let us know it's ready to be picked up
                if not file_name.endswith('.ready'):
                    continue

                ready_file_path = os.path.join(self.bro_smtp_dir, file_name)
                stream_file_name = file_name[:len(file_name) - len('.ready')]
                stream_file_path = os.path.join(self.bro_smtp_dir, stream_file_name)
                if not os.path.exists(stream_file_path):
                    logging.warning("smtp stream file {} does not exist but ready file did".format(stream_file_path))
                    try:
                        os.remove(ready_file_path)
                    except Exception as e:
                        logging.error("unable to remove {}: {}".format(ready_file_path, e))

                    continue

                logging.info("found smtp stream {}".format(stream_file_name))

                # create a new submission request for this
                self.stream_list.append(Submission(
                    description = 'BRO SMTP Scanner Detection - {}'.format(stream_file_name),
                    analysis_mode = ANALYSIS_MODE_EMAIL,
                    tool = 'ACE - Bro SMTP Scanner',
                    tool_instance = self.hostname,
                    type = 'mailbox',
                    event_time = datetime.datetime.fromtimestamp(os.path.getmtime(stream_file_path)),
                    details = {},
                    observables = [],
                    tags = [],
                    files=[os.path.join(self.bro_smtp_dir, stream_file_name)]))

        if len(self.stream_list) == 0:
            return None

        result = self.stream_list.popleft()

        # also clear the ready file
        ready_file = '{}.ready'.format(result.files[0])

        try:
            os.remove(ready_file)
        except Exception as e:
            logging.error("unable to remove file {}: {}".format(ready_file, e))

        return result

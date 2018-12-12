# vim: sw=4:ts=4:et:cc=120

import datetime
import collections
import os, os.path
import socket
import logging

import saq
from saq.constants import *
from saq.collectors import Collector, Submission

class EmailCollector(Collector):
    """Collects emails received by local email system."""
    def __init__(self, *args, **kwargs):
        super().__init__(delete_files=True, *args, **kwargs)

        # the location of the incoming emails
        self.email_dir = os.path.join(saq.DATA_DIR, saq.CONFIG['email']['email_dir'])

        # the list of emails that we need to process
        self.stream_list = collections.deque()

        # for tool_instance
        self.hostname = socket.getfqdn()

        # the datetime format string used to create the subdirectories that contain the emails
        self.subdir_format = saq.CONFIG['email']['subdir_format']

        # a list (set) of subdirs that we tried to delete but couldn't
        # we keep this list so we don't keep trying to delete them
        self.invalid_subdirs = set()

    def get_next_submission(self):
        """Returns the next HTTP stream to be processed or None if nothing is available to be processed."""
        # we collect a list of stuff to send so that we don't have to query the
        # directory listing every time we submit 
        if len(self.stream_list) == 0:
            # first get a list of the sub-directories in this directory
            # each directory has the format YYYYMMDDHH
            # these should be sorted from oldest to newest
            subdirs = sorted(filter(os.path.isdir, [os.path.join(self.email_dir, _) for _ in os.listdir(self.email_dir)]), key=os.path.getmtime)

            for subdir_name in subdirs:
                target_dir = os.path.join(self.email_dir, subdir_name)
                # skip the ones we couldn't delete
                if target_dir in self.invalid_subdirs:
                    continue

                logging.debug("checking for emails in {}".format(target_dir))
                email_count = 0

                for email_file in os.listdir(target_dir):
                    email_count += 1
                    # emails are written to a file with a .new extension while being written
                    # then renamed without with .new when completed
                    if email_file.endswith(".new"):
                        continue

                    email_path = os.path.join(target_dir, email_file)
                    logging.info("found email {}".format(email_file))

                    # create a new submission request for this
                    self.stream_list.append(Submission(
                        description = 'ACE Mailbox Scanner Detection - {}'.format(email_file),
                        analysis_mode = ANALYSIS_MODE_EMAIL,
                        tool = 'ACE - Mailbox Scanner',
                        tool_instance = self.hostname,
                        type = ANALYSIS_TYPE_MAILBOX,
                        event_time = datetime.datetime.fromtimestamp(os.path.getmtime(email_path)),
                        details = {},
                        observables = [],
                        tags = [],
                        files=[email_path]))

                # was this directory empty?
                if email_count == 0:
                    # does the current directory name not equal the current YYYYMMDDHH?
                    if subdir_name != datetime.datetime.now().strftime(self.subdir_format):
                        logging.info("deleting empty email directory {}".format(target_dir))
                        try:
                            os.rmdir(target_dir)
                        except Exception as e:
                            logging.error("unable to delete {}: {}".format(target_dir, e))
                            self.invalid_subdirs.add(target_dir)

        if len(self.stream_list) == 0:
            return None

        return self.stream_list.popleft()

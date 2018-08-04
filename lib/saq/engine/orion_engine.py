# vim: sw=4:ts=4:et

import datetime
import importlib
import json
import logging
import ntpath
import os
import shutil
import socket
import sys
import time
import uuid
import shelve

from collections import deque
from multiprocessing import Process
from queue import Queue, Empty, Full
from zipfile import ZipFile

import saq

from saq.analysis import RootAnalysis
from saq.constants import *
from saq.engine import Engine
from saq.error import report_exception

import cbapi_legacy as cbapi
import pytz # pip install pytz
import requests.exceptions

class OrionCollectionEngine(Engine):
    def __init__(self, *args, **kwargs):
        super(OrionCollectionEngine, self).__init__(*args, **kwargs)

        # state information
        # current collection index
        self.index = 0

        # collection increment (how many to download at one time)
        self.increment = self.config.getint('download_batch_size')

        # the current time_range we are using
        # this will get cleared when the full list of available results is completely downloaded
        self.time_range = None

        # the last time we executed the search
        self.last_search_time = None

        # when starting up, how far back do we go to start (in hours)?
        self.initial_search_offset = self.config.getint('initial_search_offset')

        # path to tracking db
        self.tracking_db = os.path.join(self.var_dir, self.config['tracking_db'])

    @property
    def name(self):
        return 'orion'

    def collect(self):
        cb = cbapi.CbApi(self.config['url'], ssl_verify=False, token=self.config['token'])
        total_results = None

        # how far back do we look?
        # normally we look back over some period of time for any new binaries that were uploaded
        if self.last_search_time is not None: # have we already searched at least one time?
            # NOTE remember to use UTC time here
            self.time_range = 'server_added_timestamp:[{0} TO *]'.format(
                (datetime.datetime.utcnow() - datetime.timedelta(minutes=self.config.getint('search_offset'))).strftime('%Y-%m-%dT%H:%M:%S'))
        elif self.config.getint('initial_search_offset') == 0:
            self.time_range = '' # get EVERYTHING available (useful when running this entire system for the first time or to get caught up)
        else: # first time running, go back N hours
            self.time_range = 'server_added_timestamp:[{0} TO *]'.format(
                (datetime.datetime.utcnow() - datetime.timedelta(hours=self.config.getint('initial_search_offset'))).strftime('%Y-%m-%dT%H:%M:%S'))

        # remember the last time we searched
        # this was used to determine the next time range
        # now it's just a marker that at least one search was performed
        self.last_search_time = datetime.datetime.utcnow()

        while not self.shutdown:

            query = 'path:microsoft\\ office* '
            query += '-process_name:Moc.exe '
            query += '-process_name:xlview.exe '
            query += '-hostname:PC* '
            query += '-hostname:NAKYLEXRDA* '
            query += 'username:ASHLAND username:i50* '
            query += 'cmdline:AppData\\Local\\Microsoft\\Windows\\Temporary\ Internet\ Files\\Content.IE5 '
            query += self.time_range

            try:
                logging.info("searching {} for {} starting at {}".format(self.config['url'], query, self.index))
                json_result = cb.process_search(query, start=self.index, rows=self.increment)
            except requests.exceptions.HTTPError as e:
                logging.error("carbon black server returned an error: {}".format(e))
                return
            except Exception as e:
                logging.error("communication error with carbon black server: {}".format(e))
                #report_exception()
                return

            self.index += self.increment

            if len(json_result['results']) < 1:
                logging.debug("got no more results from search")
                # then we reset and use a new time range next time
                self.index = 0
                self.time_range = None
                return

            for process in json_result['results']:
                if self.shutdown:
                    return

                # have we already downloaded this file?
                logging.debug("checking for {}".format(process['id']))
                with shelve.open(self.tracking_db) as db:
                    if process['id'] in db:
                        logging.debug("already downloaded {}".format(process['id']))
                        continue
                    
                # add this process json to the work queue
                while not self.shutdown:
                    try:
                        self.work_queue.put(process, block=True, timeout=1)
                        break
                    except Full:
                        logging.debug("work queue is full...")

            # in SINGLE_THREADED mode we only loop through once
            if saq.SINGLE_THREADED:
                return

    def process(self, process):
        logging.debug("processing json")
        analysis_start_time = datetime.datetime.now()

        try:
            file_path = process['cmdline'].split('"')[-2]
        except:
            logging.error("cannot determine file path for {}".format(process['cmdline']))
            file_path = 'unknown'

        try:
            file_name = file_path.split('\\')[-1]
        except:
            logging.error("cannot determine file name for {}".format(file_path))
            file_name = 'unknown'

        # figure out when this binary arrived to the carbon black server
        # some times the time does not have the .%fZ at the end for some reason
        time_stamp_format = "%Y-%m-%dT%H:%M:%SZ"
        if '.' in process['start']:
            time_stamp_format = "%Y-%m-%dT%H:%M:%S.%fZ"
        event_time = datetime.datetime.strptime(process['start'], time_stamp_format).replace(tzinfo=pytz.utc)
        event_time = pytz.timezone('US/Eastern').normalize(event_time)

        # create the root analysis object
        root = RootAnalysis()
        # set all of the properties individually
        # XXX fix me
        # it looks like the construction logic doesn't quite work here
        # when loading from the arguments to the constructor, the internal
        # variables with leading underscores get set rather than the properties
        # representing the database columns it was designed that way to allow the
        # JSON stuff to work correctly, so I'll need to revisit that later
        root.tool='ACE - Carbon Black Internet Office File Analysis'
        root.tool_instance=socket.gethostname()
        root.alert_type='carbon_black_internet_office_file'
        root.description='Carbon Black Internet Office File {0}'.format(file_name)
        root.event_time=event_time
        root.details=process

        # XXX database.Alert does not automatically create this
        root.uuid = str(uuid.uuid4())

        # we use a temporary directory while we process the file
        root.storage_dir = os.path.join(self.work_dir, root.uuid[0:3], root.uuid)
        root.initialize_storage()

        # note that the path is relative to the storage directory
        fl_observable = root.add_observable(F_FILE_LOCATION, create_file_location(process['hostname'], file_path))
        if fl_observable: fl_observable.add_directive(DIRECTIVE_COLLECT_FILE)
        root.add_observable(F_FILE_PATH, file_path)
        root.add_observable(F_FILE_NAME, file_name)
        root.add_observable(F_HOSTNAME, process['hostname'])

        # now analyze the file
        try:
            self.analyze(root)
        except Exception as e:
            logging.error("analysis failed for {}: {}".format(process['id'], e))
            report_exception()

        logging.info("completed {} analysis time {}".format(process['id'], datetime.datetime.now() - analysis_start_time))

    def post_analysis(self, root):
        """Determine if we should alert.  Delete if no further analysis is pending."""
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

        root.delete()

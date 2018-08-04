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

class CarbonBlackCollectionEngine(Engine):
    """Collects binaries and files from Carbon Black and runs them through ACE."""

    def __init__(self, *args, **kwargs):
        super(CarbonBlackCollectionEngine, self).__init__(*args, **kwargs)

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

    @property
    def name(self):
        return 'carbon_black'

    def collect(self):
        # get the list of hashes available to download in the past X minutes    
        # TODO past X minutes
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

            query = 'is_executable_image:true -digsig_result:Signed {}'.format(self.time_range)

            try:
                json_result = cb.binary_search(query, start=self.index, rows=self.increment)
            except requests.exceptions.HTTPError as e:
                logging.error("carbon black server returned an error: {}".format(e))
                return
            except Exception as e:
                logging.error("communication error with carbon black server: {}".format(e))
                #report_exception()
                return

            logging.info("requested binary data from {0} index {1} of {2} with query {3}".format(
                self.config['url'], self.index, json_result['total_results'], query))
            self.index += self.increment

            if len(json_result['results']) < 1:
                logging.debug("got no more results from search")
                # then we reset and use a new time range next time
                self.index = 0
                self.time_range = None
                return

            for binary in json_result['results']:
                if self.shutdown:
                    return

                binary_dir = os.path.join(os.path.join(self.config['storage_dir'], binary['md5'][0:2]))
                binary_path = os.path.join(self.config['storage_dir'], binary['md5'][0:2], binary['md5'])
                binary_zip_path = os.path.join(self.config['storage_dir'], binary['md5'][0:2], '{0}.zip'.format(binary['md5']))
                binary_json_path = '{0}.json'.format(binary_path)

                # have we already downloaded this md5?
                if os.path.exists(binary_path):
                    logging.debug("already have binary {0} at {1}".format(binary['md5'], binary_path))
                else:
                    # go get it from Carbon Black
                    if not os.path.isdir(binary_dir):
                        os.makedirs(binary_dir)

                    logging.info("downloading {0}".format(binary['md5']))
                    with open(binary_zip_path, 'wb') as fp:
                        try:
                            fp.write(cb.binary(binary['md5']))
                        except Exception as e:
                            logging.warning("unable to download {0}: {1}".format(binary['md5'], str(e)))
                            continue

                    # also save the json that came with the file
                    with open(binary_json_path, 'w') as fp:
                        json.dump(binary, fp, indent=4)

                    # extract the file
                    with ZipFile(binary_zip_path) as zip_fp:
                        with zip_fp.open('filedata') as unzipped_fp:
                            with open(binary_path, 'wb') as fp:
                                fp.write(unzipped_fp.read())

                    # delete the zip file
                    os.remove(binary_zip_path)

                    logging.debug("downloaded {0}".format(binary_path))

                    # add this file to the work queue
                    while not self.shutdown:
                        try:
                            self.work_queue.put(binary_path, block=True, timeout=1)
                            break
                        except Full:
                            logging.debug("work queue is full...")

            # in SINGLE_THREADED mode we only loop through once
            if saq.SINGLE_THREADED:
                return

    def process(self, binary_path):
        logging.debug("processing {0}".format(binary_path))
        analysis_start_time = datetime.datetime.now()

        # load the JSON acquired from Carbon Black
        try:
            with open('{0}.json'.format(binary_path), 'r') as fp:
                binary_json = json.load(fp)
        except Exception as e:
            logging.error("unable to parse JSON from Carbon Black for {}: {}".format(binary_path, str(e)))
            return

        # we have to copy the file into the new storage directory for it to be analyzed
        # we use the file name that Carbon Black saw on the endpoint
        try:
            file_name = binary_json['observed_filename'][-1]
        except Exception as e:
            logging.error("cannot determine file name for {}".format(binary_path))
            file_name = 'unknown'

        # we need to figure out if this is a path from a Windows machine or a Unix machine
        # so we count the number of backslashes and forward slashes
        # it's a hack but it should work 99.9% of the time
        if file_name.count('\\') > file_name.count('/'):
            logging.debug("{0} appears to be a windows path".format(file_name))
            file_name = ntpath.basename(file_name)
        else:
            logging.debug("{0} appears to be a unix path".format(file_name))
            file_name = os.path.basename(file_name)

        # figure out when this binary arrived to the carbon black server
        # some times the time does not have the .%fZ at the end for some reason
        time_stamp_format = "%Y-%m-%dT%H:%M:%SZ"
        if '.' in binary_json['server_added_timestamp']:
            time_stamp_format = "%Y-%m-%dT%H:%M:%S.%fZ"
        event_time = datetime.datetime.strptime(binary_json['server_added_timestamp'], time_stamp_format).replace(tzinfo=pytz.utc)
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
        root.tool='ACE - Carbon Black Binary Analysis'
        root.tool_instance=socket.gethostname()
        root.alert_type='carbon_black_binary'
        root.description='Carbon Black binary {0}'.format(file_name)
        root.event_time=event_time
        root.details=binary_json

        # XXX database.Alert does not automatically create this
        root.uuid = str(uuid.uuid4())

        # we use a temporary directory while we process the file
        root.storage_dir = os.path.join(
            self.work_dir,
            root.uuid[0:3],
            root.uuid)

        root.initialize_storage()

        logging.debug("using storage directory {0} for {1}".format(root.storage_dir, binary_path))
        dest_path = os.path.join(root.storage_dir, file_name)

        try:
            shutil.copy(binary_path, dest_path)
        except Exception as e:
            logging.error("unable to copy {0} to {1}: {2}".format(binary_path, dest_path, str(e)))
            report_exception()
            return

        # note that the path is relative to the storage directory
        root.add_observable(F_FILE, file_name)

        # the endpoints are stored as an array of host names optionally appended with a pipe and count
        # I assume the number of times that executable has executed on that host?
        for endpoint in binary_json['endpoint']:
            if '|' in endpoint:
                endpoint = endpoint[:endpoint.index('|')]
                root.add_observable(F_HOSTNAME, endpoint)

        for file_path in binary_json['observed_filename']:
            root.add_observable(F_FILE_PATH, file_path)

        # now analyze the file
        try:
            self.analyze(root)
        except Exception as e:
            logging.error("analysis failed for {0}: {1}".format(binary_path, str(e)))
            report_exception()

        logging.info("completed {0} analysis time {1}".format(binary_path, datetime.datetime.now() - analysis_start_time))

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

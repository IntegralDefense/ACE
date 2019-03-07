# vim: sw=4:ts=4:et:cc=120

import collections
import datetime
import json
import logging
import ntpath
import os, os.path
import pickle
import zipfile

import saq
from saq.constants import *
from saq.collectors import Submission, Collector

import cbapi_legacy as cbapi
import requests.exceptions
import pytz

class CarbonBlackBinarySubmission(Submission):
    def success(self, group, result):
        # we save the results of the submission to indicate we've submitted it for analysis
        # NOTE that this can get called multiple times if there is more than one remote group node defined
        binary_path = self.files[0]
        submit_path = '{}.submit'.format(binary_path)

        with open(submit_path, 'w') as fp:
            json.dump(result, fp)

        logging.debug("saved submission for {} to {}".format(binary_path, submit_path))

class CarbonBlackBinaryCollector(Collector):
    def __init__(self, 
                 download_batch_size=10, 
                 initial_search_offset=24, 
                 search_offset=60, # <-- DEPRECATED
                 storage_dir='storage', 
                 *args, **kwargs):

        super().__init__(workload_type='cb', *args, **kwargs)

        # carbon black config data
        self.cb_url = saq.CONFIG['carbon_black']['url']
        self.cb_token = saq.CONFIG['carbon_black']['token']

        # collection increment (how many to download at one time)
        self.download_batch_size = download_batch_size

        # when starting up, how far back do we go to start (in hours)?
        self.initial_search_offset = initial_search_offset

        # path to the persistent locations
        self.last_search_time_path = os.path.join(self.persistence_dir, 'cb_last_search_time')
        self.current_query_path = os.path.join(self.persistence_dir, 'cb_query')
        self.current_index_path = os.path.join(self.persistence_dir, 'cb_index')
        self.current_result_count_path = os.path.join(self.persistence_dir, 'cb_result_count')

        # the last time we executed the search
        self._last_search_time = None
        # current query tracking
        self._current_query = None
        self._current_index = None
        self._current_result_count = None

        # TODO eventually this moves into a generic file storage system
        # where we store the archive of carbon black binaries
        self.storage_dir = os.path.join(saq.DATA_DIR, storage_dir)
        if not os.path.isdir(self.storage_dir):
            try:
                os.makedirs(self.storage_dir)
            except Exception as e:
                logging.error("unable to create directory {}: {}".format(self.storage_dir, e))

        # temporary list of things to submit
        self.work_list = collections.deque()

        self.load_persistence()

    def load_persistence(self):
        # load stuff
        try:
            if os.path.exists(self.last_search_time_path):
                with open(self.last_search_time_path, 'rb') as fp:
                    self._last_search_time = pickle.load(fp)

            if os.path.exists(self.current_query_path):
                with open(self.current_query_path, 'rb') as fp:
                    self._current_query = pickle.load(fp)

            if os.path.exists(self.current_index_path):
                with open(self.current_index_path, 'rb') as fp:
                    self._current_index = pickle.load(fp)

            if os.path.exists(self.current_result_count_path):
                with open(self.current_result_count_path, 'rb') as fp:
                    self._current_result_count = pickle.load(fp)

        except Exception as e:
            logging.error("unable to load from persistence: {}".format(e))
            report_exception()

            # if we can't load one of the things we need then we default to not loading anything at all
            self._last_search_time = None
            self._current_query = None
            self._current_index = None
            self._current_result_count = None

    @property
    def last_search_time(self):
        return self._last_search_time

    @last_search_time.setter
    def last_search_time(self, value):
        self._last_search_time = value
        with open(self.last_search_time_path, 'wb') as fp:
            pickle.dump(self._last_search_time, fp)

        logging.debug("updated last_search_time to {}".format(value))

    @property
    def current_query(self):
        return self._current_query

    @current_query.setter
    def current_query(self, value):
        self._current_query = value
        with open(self.current_query_path, 'wb') as fp:
            pickle.dump(self._current_query, fp)

        logging.debug("updated current_query to {}".format(value))

    @property
    def current_index(self):
        return self._current_index

    @current_index.setter
    def current_index(self, value):
        self._current_index = value
        with open(self.current_index_path, 'wb') as fp:
            pickle.dump(self._current_index, fp)

        logging.debug("updated current_index to {}".format(value))

    @property
    def current_result_count(self):
        return self._current_result_count

    @current_result_count.setter
    def current_result_count(self, value):
        self._current_result_count = value
        with open(self.current_result_count_path, 'wb') as fp:
            pickle.dump(self._current_result_count, fp)

        logging.debug("updated current_result_count to {}".format(value))

    def get_next_submission(self):
        if len(self.work_list) == 0:
            self.collect_binaries()

        if len(self.work_list) == 0:
            return None

        return self.work_list.popleft()

    def collect_binaries(self):

        # get the list of hashes available to download in the past X minutes    
        cb = cbapi.CbApi(self.cb_url, token=self.cb_token, ssl_verify=False) # XXX <-- get rid of that

        # do we need a new query to execute?
        if self.current_query is None:

            # build the time range for the carbon black query
            if self.last_search_time is not None: # have we already searched at least one time?
                time_range = 'server_added_timestamp:[{} TO *]'.format(self.last_search_time.strftime('%Y-%m-%dT%H:%M:%S'))
                    #(datetime.datetime.utcnow() - datetime.timedelta(minutes=self.search_offset)).strftime('%Y-%m-%dT%H:%M:%S'))
            elif self.initial_search_offset == 0:
                time_range = '' # get EVERYTHING available (useful when running this entire system for the first time or to get caught up)
            else: # first time running, go back N hours
                time_range = 'server_added_timestamp:[{} TO *]'.format(
                    (datetime.datetime.utcnow() - datetime.timedelta(hours=self.initial_search_offset)).strftime('%Y-%m-%dT%H:%M:%S'))

            self.current_query = 'is_executable_image:true -digsig_result:Signed {}'.format(time_range)
            self.current_index = 0

        try:
            json_result = cb.binary_search(self.current_query, 
                                           start=self.current_index,
                                           rows=self.download_batch_size, 
                                           sort='server_added_timestamp asc')

            # if we're executing a new query for the first time
            # then remember how many binaries we need to get
            if self.current_result_count is None:
                self.current_result_count = json_result['total_results']

        except requests.exceptions.HTTPError as e:
            logging.error("carbon black server returned an error: {}".format(e))
            return
        except Exception as e:
            logging.error("communication error with carbon black server: {}".format(e))
            return

        logging.info("requested binary data from {} at index {} result count {} with query {}".format(
            self.cb_url, self.current_index, self.current_result_count, self.current_query))

        if len(json_result['results']) < 1:
            logging.debug("got no more results from search")
            self.current_query = None
            self.current_index = None
            self.current_result_count = None
            return

        for binary in json_result['results']:

            if self.shutdown_event.is_set():
                return

            # move to the next set of items after processing these
            self.current_index += 1 

            # figure out when this binary arrived to the carbon black server
            # some times the time does not have the .%fZ at the end for some reason
            time_stamp_format = "%Y-%m-%dT%H:%M:%SZ"
            if '.' in binary['server_added_timestamp']:
                time_stamp_format = "%Y-%m-%dT%H:%M:%S.%fZ"

            event_time = datetime.datetime.strptime(binary['server_added_timestamp'], 
                                                    time_stamp_format).replace(tzinfo=pytz.utc)

            # this also becomes our new starting point next time we search
            if self.last_search_time is None or event_time > self.last_search_time:
                # we move one second past the last time we saw something added
                self.last_search_time = event_time + datetime.timedelta(seconds=1)

            binary_dir = os.path.join(self.storage_dir, binary['md5'][0:2])
            binary_path = os.path.join(binary_dir, binary['md5'])
            binary_zip_path  = '{}.zip'.format(binary_path)
            binary_json_path = '{}.json'.format(binary_path)
            submit_path = '{}.submit'.format(binary_path)

            # have we already submitted this one for analysis?
            if os.path.exists(submit_path):
                logging.debug("already submitted {}".format(binary['md5']))
                continue

            # have we already downloaded this md5?
            if os.path.exists(binary_path):
                logging.debug("already have binary {} at {}".format(binary['md5'], binary_path))
                continue

            else:
                # go get it from Carbon Black
                if not os.path.isdir(binary_dir):
                    try:
                        os.makedirs(binary_dir)
                    except Exception as e:
                        logging.error("unable to create directory {}: {}".format(binary_dir, e))
                        continue

                logging.info("downloading {}".format(binary['md5']))
                try:
                    # XXX see if you can do this without pulling the entire binary into memory
                    binary_content = cb.binary(binary['md5'])
                except Exception as e:
                    logging.info("unable to download {}: {}".format(binary['md5'], e))
                    continue

                if len(binary_content) == 0:
                    logging.warning("got 0 bytes for {}".format(binary_zip_path))
                    continue
                    
                with open(binary_zip_path, 'wb') as fp:
                    try:
                        fp.write(binary_content)
                    except Exception as e:
                        logging.error("unable to write to {}: {}".format(binary_zip_path, e))

                # also save the json that came with the file
                with open(binary_json_path, 'w') as fp:
                    json.dump(binary, fp, indent=4)

                # extract the file
                with zipfile.ZipFile(binary_zip_path) as zip_fp:
                    with zip_fp.open('filedata') as unzipped_fp:
                        with open(binary_path, 'wb') as fp:
                            fp.write(unzipped_fp.read())

                # delete the zip file
                os.remove(binary_zip_path)

                logging.debug("downloaded {}".format(binary_path))

            # we have to copy the file into the new storage directory for it to be analyzed
            # we use the file name that Carbon Black saw on the endpoint
            try:
                file_name = binary['observed_filename'][-1]
            except Exception as e:
                logging.error("cannot determine file name for {}".format(binary_path))
                file_name = 'unknown'

            # we need to figure out if this is a path from a Windows machine or a Unix machine
            # so we count the number of backslashes and forward slashes # it's a hack but it should work 99.9% of the time
            if file_name.count('\\') > file_name.count('/'):
                logging.debug("{} appears to be a windows path".format(file_name))
                file_name = ntpath.basename(file_name)
            else:
                logging.debug("{} appears to be a unix path".format(file_name))
                file_name = os.path.basename(file_name)


            observables = []
            for endpoint in binary['endpoint']:
                if '|' in endpoint:
                    endpoint = endpoint[:endpoint.index('|')]
                    observables.append({'type': F_HOSTNAME, 'value': endpoint})

            for file_path in binary['observed_filename']:
                observables.append({'type': F_FILE_PATH, 'value': file_path})

            # create a new submission request for this
            self.work_list.append(CarbonBlackBinarySubmission(
                description = 'Carbon Black binary {}'.format(file_name),
                analysis_mode = ANALYSIS_MODE_BINARY,
                tool = 'ACE - Carbon Black Binary Analysis',
                tool_instance = self.fqdn,
                type = 'carbon_black_binary',
                event_time = event_time,
                details = binary,
                observables = [],
                tags = [],
                files=[binary_path]))

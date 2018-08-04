import datetime
import hashlib
import logging
import os
import os.path
import pickle
import shutil
import socket
import stat
import time
import uuid

from subprocess import Popen, PIPE

import saq

from saq.analysis import RootAnalysis
from saq.cloudphish import *
from saq.constants import *
from saq.database import get_db_connection
from saq.engine import Engine, SSLNetworkServer, enable_cached_db_connections
from saq.error import report_exception

_alert_type_mailbox = 'cloudphish'

KEY_DETAILS_URL = 'url'
KEY_DETAILS_SHA256_URL = 'sha256_url'
KEY_DETAILS_ALERTABLE = 'alertable'
KEY_DETAILS_CONTEXT = 'context'

class CloudPhishEngine(Engine):
    """Processes URLS submitted by other engines."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # if set to True then we don't delete the work directories
        self.keep_work_dir = False

    @property
    def name(self):
        return 'cloudphish'

    @property
    def cache_dir(self):
        return saq.CONFIG['cloudphish']['cache_dir']

    @property
    def location(self):
        return self.config['location']

    def initialize_engine(self):
        # make sure our cache directory exists
        if not os.path.exists(self.cache_dir):
            try:
                os.makedirs(self.cache_dir)
            except Exception as e:
                logging.error("unable to create directory {}: {}".format(self.cache_dir, e))
                report_exception()
                sys.exit(1) # critial error

        # we go ahead and clear out ownership of anything we previously owned
        with get_db_connection('cloudphish') as db:
            c = db.cursor()
            c.execute("""UPDATE workload SET node = NULL WHERE node LIKE %s""", ('{}%'.format(self.location),))
            db.commit()

    def initialize_collection(self):
        enable_cached_db_connections()
        self.node = '{}:{}'.format(self.location, os.getpid())
        logging.debug("current node is {}".format(self.node))

    def collect(self):
        # grab the next urls to process
        results = None
        with get_db_connection('cloudphish') as db: 
            c = db.cursor()
            # go ahead and allocate a batch of URLs to process
            c.execute("""UPDATE workload SET node = %s WHERE sha256_url IN ( SELECT sha256_url FROM ( 
                       SELECT sha256_url FROM workload 
                       WHERE node IS NULL OR node = %s ORDER BY node, insert_date ASC LIMIT {}) as t)""".format(self.analysis_pool_size), 
                       ( self.node, self.node ))
            db.commit()

            c.execute("SELECT HEX(sha256_url), url, alertable, details FROM workload WHERE node = %s ORDER BY insert_date DESC", (self.node, ))
            results = c.fetchall()

            #logging.debug("got {} urls from database".format(len(results)))

        if not results:
            # XXX temp hack
            try:
                time.sleep(1)
            except Exception as e:
                pass

            #logging.debug("no work available")
            return

        # process each url
        url_hash_list = []
        for sha256_url, url, alertable, details in results:
            logging.info("adding url {} (alertable {}) to workload".format(url, alertable))
            self.add_work_item((url, alertable, pickle.loads(details) if details else {}))
            url_hash_list.append(sha256_url)

        with get_db_connection('cloudphish') as db:
            c = db.cursor()
            logging.debug("deleting {} entries from workload table".format(len(url_hash_list)))
            for sha256_url in url_hash_list:
                c.execute("DELETE FROM workload WHERE sha256_url = UNHEX(%s)", (sha256_url,))
            db.commit()

    def process(self, work_item):
        url, alertable, details = work_item
        # any other result means we should process it
        logging.info("processing url {} (alertable {})".format(url, alertable))
        #logging.debug("details = {}".format(details))

        sha256_url = hash_url(url)

        # create or update our analysis entry
        with get_db_connection('cloudphish') as db:
            c = db.cursor()
            c.execute("""UPDATE analysis_results SET status = %s WHERE sha256_url = UNHEX(%s)""", 
                     (STATUS_ANALYZING, sha256_url))
            db.commit()

        root = RootAnalysis()
        # create a temporary storage directory for this work
        root.tool = 'ACE - Cloudphish'
        root.tool_instance = self.location
        root.alert_type = 'cloudphish'
        root.description = 'ACE Cloudphish Detection - {}'.format(url)
        root.event_time = datetime.datetime.now()
        root.uuid = str(uuid.uuid4())
        root.storage_dir = os.path.join(self.work_dir, root.uuid[0:2], root.uuid)
        root.initialize_storage()

        if 'i' in details:
            root.company_name = details['i']

        if 'd' in details:
            root.company_id = details['d']

        root.details = {
            KEY_DETAILS_URL: url,
            KEY_DETAILS_SHA256_URL: sha256_url,
            KEY_DETAILS_ALERTABLE: alertable,
            KEY_DETAILS_CONTEXT: details,
        }

        url_observable = root.add_observable(F_URL, url)
        if url_observable is None:
            logging.error("request for invalid url received: {}".format(url))
            return

        url_observable.add_directive(DIRECTIVE_CRAWL)

        # the "details context" can also contain observables
        for key in root.details[KEY_DETAILS_CONTEXT].keys():
            if key in VALID_OBSERVABLE_TYPES:
                root.add_observable(key, root.details[KEY_DETAILS_CONTEXT][key])

        try:
            self.analyze(root)
        except Exception as e:
            logging.error("analysis failed for {}: {}".format(url, e))
            report_exception()

            with get_db_connection('cloudphish') as db:
                c = db.cursor()
                c.execute("""UPDATE analysis_results SET 
                                 result = %s,
                                 status = %s,
                                 http_result_code = NULL,
                                 http_message = NULL,
                                 sha256_content = NULL
                             WHERE sha256_url = UNHEX(%s)""", (SCAN_RESULT_ERROR, STATUS_ANALYZED, sha256_url))
                db.commit()
                return
    
    def post_analysis(self, root):
        from saq.modules.url import CrawlphishAnalysisV2

        # get the original url
        url_observable = None
        for o in root.observables:
            if o.type == F_URL and root.details[KEY_DETAILS_URL] == o.value:
                url_observable = o
                break

        if not url_observable:
            logging.error("unable to find original url observable")
            return

        url_hash = root.details[KEY_DETAILS_SHA256_URL]

        # get the crawlphish analysis for this url
        analysis = url_observable.get_analysis(CrawlphishAnalysisV2)
        if not analysis:
            logging.error("missing crawlphish analysis for {}".format(url_observable))
            return

        if not analysis.details:
            # this will happen if crawlphish does not crawl the link
            logging.debug("missing crawlphish analysis details for {}".format(url_observable))
            return

        # update the database with the results
        if analysis.filtered_status:
            scan_result = SCAN_RESULT_PASS
        elif not analysis.downloaded:
            scan_result = SCAN_RESULT_ERROR
        else:
            scan_result = SCAN_RESULT_ALERT if self.should_alert(root) else SCAN_RESULT_CLEAR

        http_result_code = analysis.status_code
        http_message = analysis.status_code_reason

        if scan_result == SCAN_RESULT_ERROR:
            http_message = analysis.error_reason

        logging.info("updating url {} with has {} http_result_code {} http_message {} scan_result {}".format(
                     url_observable.value, url_hash, http_result_code, http_message, scan_result))

        with get_db_connection('cloudphish') as db:
            c = db.cursor()
            c.execute("""UPDATE analysis_results SET 
                             http_result_code = %s, 
                             http_message = %s, 
                             result = %s 
                         WHERE sha256_url = UNHEX(%s)""", (
                http_result_code, http_message[:256] if http_message is not None else None, scan_result, url_hash ))
            db.commit()

        # did crawlphish download a file?
        if analysis.file_name:
            # find the file observable added to this analysis
            file_observable = None
            for o in analysis.observables:
                if o.type == F_FILE:
                    file_observable = o
                    break

            if not file_observable:
                logging.info("nothing downloaded from {}".format(url_observable.value))
            else:
                logging.debug("found downloaded file {} for {}".format(file_observable, url_observable))
                file_observable.compute_hashes()
                if not file_observable.sha256_hash:
                    logging.error("missing sha256 hash for {}".format(file_observable))
                    return

                cache_dir = os.path.join(self.cache_dir, file_observable.sha256_hash.lower()[0:2])
                if not os.path.isdir(cache_dir):
                    try:
                        os.makedirs(cache_dir)
                    except Exception as e:
                        logging.error("unable to create directory {}: {}".format(cache_dir, e))
                        report_exception()
                        return

                cache_path = os.path.join(cache_dir, file_observable.sha256_hash.lower())

                if not os.path.exists(cache_path):
                    src = os.path.join(root.storage_dir, file_observable.value)
                    logging.debug("copying {} to {}".format(src, cache_path))

                    try:
                        shutil.copy(src, cache_path)
                    except Exception as e:
                        logging.error("unable to copy {} to {}: {}".format(src, cache_path, e))

                # if this was an alert then we copy the analysis to a subdirectory
                if saq.FORCED_ALERTS or scan_result == SCAN_RESULT_ALERT:
                    logging.info("alert detected for {}".format(url_observable.value))
                    target_path = '{}.ace.tar.gz'.format(cache_path)
                    if os.path.exists(target_path):
                        logging.warning("target alert path {} already exists".format(target_path))
                    else:
                        try:
                            # go ahead and save the analysis out to disk
                            root.save()

                            # then copy it to cache
                            logging.debug("copying {} to {}".format(root.storage_dir, target_path))
                            p = Popen(['tar', 'zcf', target_path, '-C', root.storage_dir, '.'], 
                                      stdout=PIPE, stderr=PIPE)

                            stdout, stderr = p.communicate()

                            if p.returncode != 0:
                                logging.error("tar returned non-zero result: {}".format(p.returncode))

                            if stderr:
                                logging.error("tar emitted output on standard error: {}".format(stderr))

                        except Exception as e:
                            logging.error("unable to copy {} to {}: {}".format(root.storage_dir, target_path, e))
                            report_exception()

                    if root.details[KEY_DETAILS_ALERTABLE]:
                        try:
                            # if the submission came with source company information then send it to the right spot
                            root.submit(target_company=root.company_name if root.company_name else None)
                        except Exception as e:
                            logging.error("unable to submit alert for {}: {}".format(root.details[KEY_DETAILS_URL], e))
                            report_exception()

                # update the database with the results
                with get_db_connection('cloudphish') as db:
                    c = db.cursor()
                    c.execute("UPDATE analysis_results SET sha256_content = UNHEX(%s) WHERE sha256_url = UNHEX(%s)",
                              (file_observable.sha256_hash, url_hash))
                    db.commit()

                # update meta data content
                with get_db_connection('cloudphish') as db:
                    c = db.cursor()
                    try:
                        logging.debug("updating content metadata {} {} {}".format(
                                      file_observable.sha256_hash, self.location, analysis.file_name))
                        c.execute("""INSERT INTO content_metadata ( sha256_content, location, name )
                                     VALUES ( UNHEX(%s), %s, %s ) ON DUPLICATE KEY UPDATE location = %s, name = %s""", 
                                 (file_observable.sha256_hash, self.location, analysis.file_name,
                                 self.location, analysis.file_name))
                        db.commit()
                    except Exception as e:
                        logging.error("unable to record meta data for {}: {}".format(url_observable.value, e))
                        report_exception()

    def root_analysis_completed(self, root):
        if root.delayed:
            return

        # mark the analysis as completed
        try:
            with get_db_connection('cloudphish') as db:
                c = db.cursor()
                c.execute("UPDATE analysis_results SET status = %s WHERE sha256_url = UNHEX(%s)", 
                         (STATUS_ANALYZED, root.details[KEY_DETAILS_SHA256_URL],))
                db.commit()
        except Exception as e:
            logging.error("unable to update database: {}".format(e))
            report_exception()

        # delete the work directory
        if not self.keep_work_dir:
            try:
                shutil.rmtree(root.storage_dir)
            except Exception as e:
                logging.error("unable to delete work directory {}: {}".format(root.storage_dir, e))
                report_exception()

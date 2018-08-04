# vim: sw=4:ts=4:et

import datetime
import logging
import os.path
import pickle
import shutil
import tempfile
import threading
import time

from subprocess import Popen, PIPE
from threading import Thread
from queue import Empty, Full

import saq
import saq.database

from saq.constants import *
from saq.database import ACEAlertLock, Alert, EngineWorkload, get_db_connection, \
                         enable_cached_db_connections, disable_cached_db_connections, \
                         release_cached_db_connection, execute_with_retry
from saq.engine import SSLNetworkServer, DelayedAnalysisRequest
from saq.error import report_exception
from saq.lock import LockableObject, lock_expired
from saq.performance import record_metric

from sqlalchemy.sql.expression import and_
from sqlalchemy.orm.exc import NoResultFound

class AnalysisRequest(ACEAlertLock):
    def __init__(self, uuid, storage_dir, alert_id, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.id = alert_id
        self.uuid = uuid
        self.storage_dir = storage_dir

    def __str__(self):
        return "AnalysisRequest(uuid({}),storage_dir({}),alert_id({}),lock_id({})".format(
            self.uuid, self.storage_dir, self.id, self.acquired_lock_id)

class ACE(SSLNetworkServer):
    """Analysis Correlation Engine"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # this is for a bit of backwards compatibility
        # the ACE engine storage directory is elsewhere
        self.storge_dir = saq.CONFIG['global']['data_dir']

        # a daemon thread to watch for the disposition of the alert to change
        self.disposition_watch_thread = None
        # a flag to indicator that we're done processing
        # XXX really this should be available
        self.analysis_ended_flag = False

        # used to track new observables and tags we find as we analyze
        self._indexed_tags = [] # of saq.analysis.Tag
        self._indexed_observables = [] # of saq.analysis.Observable

        # contains a list of storage_dir that were incompleted after last shutdown
        self.incomplete_analysis_path = os.path.join(self.var_dir, 'incomplete_analysis')

        # the list of AnalysisRequest objects loaded from incomplete_analysis_path at startup
        self.incomplete_analysis = []

    @property
    def name(self):
        return 'ace'

    def handle_network_item(self, analysis_path):
        logging.info("got network item {}".format(analysis_path))

        # create a temporary directory to extract the tar file
        temp_dir = tempfile.mkdtemp(suffix='.ace_submission')

        try:
            # extract the tar file inside this temporary directory
            p = Popen(['tar', 'xf', analysis_path, '-C', temp_dir], stdout=PIPE, stderr=PIPE)
            _stdout, _stderr = p.communicate()
            p.wait()

            if p.returncode != 0:
                logging.warning("tar returned non-zero status for {}".format(analysis_path))
        
            if _stderr:
                logging.warning("tar command printed text to stderr for {}: {}".format(analysis_path, _stderr))

            # load the analysis
            root = Alert()
            root.storage_dir = temp_dir
            try:
                root.load()
            except Exception as e:
                logging.error("unable to load from {}: {}".format(analysis_path, e))
                report_exception()
                return

            # move the storage_dir into ACE
            try:
                dest_dir = os.path.join(saq.CONFIG['global']['data_dir'], saq.SAQ_NODE, root.uuid[0:3], root.uuid)
                shutil.move(root.storage_dir, dest_dir)
            except Exception as e:
                logging.error("unable to move {} to {}: {}".format(root.storage_dir, dest_dir, e))
                report_exception()
                return

            # change the location of the alert to this receiving system
            root.location = saq.SAQ_NODE

            # insert the alert into the database
            root.storage_dir = dest_dir
            if root.id:
                logging.debug("removed previous id {} from forwarded alert {}".format(root.id, root))
                root.id = None
        
            try:
                root.sync()
                root.request_correlation()
            except Exception as e:
                logging.error("unable to save alert from {}: {}".format(analysis_path, e))
                report_exception()
                return

            # if we got to this point then we're done with this input file
            try:
                os.remove(analysis_path)
            except Exception as e:
                logging.error("unable to remove {}: {}".format(analysis_path, e))
                report_exception()

        except Exception as e:
            logging.error("unable to process {}: {}".format(analysis_path, e))
            report_exception()
            raise e

        finally:
            try:
                if os.path.exists(temp_dir):
                    shutil.rmtree(temp_dir)
            except Exception as e:
                logging.error("unable to delete temporary directory {}: {}".format(temp_dir, e))
                report_exception()

    def collect(self):
        # allow persistence to load
        while not self.shutdown and not self.collection_shutdown and self.incomplete_analysis:
            try:
                logging.debug("adding persisted workload item {}".format(self.incomplete_analysis[0]))
                self.work_queue.put(self.incomplete_analysis[0], block=not saq.SINGLE_THREADED, timeout=1)
                self.incomplete_analysis.pop(0)
            except Full:
                if not saq.SINGLE_THREADED:
                    continue

        if self.shutdown or self.collection_shutdown:
            return

        # grab the workload from the database
        with get_db_connection() as db: 
            c = db.cursor()

            # how many items on the workload stack have already been acquired by this node?
            c.execute("SELECT COUNT(*) FROM workload WHERE node = %s", ( saq.SAQ_NODE, ))
            row = c.fetchone()
            assigned_count = row[0]

            if assigned_count:
                logging.debug("{} work items are currently assigned to {}".format(assigned_count, saq.SAQ_NODE))
            
            # if there is nothing currently assigned then go ahead and assign some
            # (there is some sql trickery in here to do subselect magic in MySQL)

            if assigned_count < self.analysis_pool_size:

                sql = """
                UPDATE 
                    workload 
                SET 
                    node = %s 
                WHERE id IN ( 
                    SELECT id FROM (
                        SELECT 
                            w.id 
                        FROM 
                            workload w JOIN alerts a ON a.id = w.alert_id
                        WHERE 
                            w.node IS NULL 
                            AND a.location = %s
                        ORDER BY
                            w.id DESC
                        LIMIT %s ) as t)"""

                # the number of assigned work should equal the our analysis_pool_size
                execute_with_retry(c, sql, ( saq.SAQ_NODE, saq.SAQ_NODE, self.analysis_pool_size - assigned_count ), attempts=10)
                db.commit()

                if c.rowcount != -1 and c.rowcount is not None:
                    if c.rowcount:
                        logging.debug("assigned {} work items to {}".format(c.rowcount, saq.SAQ_NODE))

            # what we've done so far is marked specific alerts as acquired by this node
            # no we'll actually go *get* them, add them to the workload, and remove from the database
            # we go ahead and remove the item from the database *before* we're able to execute the analysis

            sql = "SELECT w.id, a.id, a.uuid, a.storage_dir FROM workload w JOIN alerts a ON w.alert_id = a.id WHERE w.node = %s"
            c.execute(sql, (saq.SAQ_NODE,))

            # we'll keep a list of these so we can remove them later
            assigned_workload_ids = [] # of workload_id

            for workload_id, alert_id, uuid, storage_dir in c:
                logging.debug("got workload {} alert {} uuid {} storage_dir {}".format(
                              workload_id, alert_id, uuid, storage_dir))

                # make sure this alert is still around
                if not os.path.exists(storage_dir):
                    logging.warning("invalid or missing storage_dir {}".format(storage_dir))
                    continue

                # add this alert to the workload
                self.add_work_item(AnalysisRequest(uuid, storage_dir, alert_id))
                assigned_workload_ids.append(workload_id)

            for workload_id in assigned_workload_ids:
                logging.debug("deleting workload_id {}".format(workload_id))
                c.execute("DELETE FROM workload WHERE id = %s", (workload_id,))

            db.commit()

    def process(self, request):
        assert isinstance(request, AnalysisRequest)

        # load the alert from the databasee and detach from the session
        session = saq.database.DatabaseSession()
        try:
            logging.debug("loading alert id {}".format(request.id))
            self.root = session.query(Alert).filter(Alert.id == request.id).one()
            session.expunge(self.root)
        except Exception as e:
            logging.error("unable to load and expunge alert id {}: {}".format(request.id, e))
            report_exception()
            return
        finally:
            session.close()

        # set this properties manually from the request
        #self.root.id = request.id
        #self.root.uuid = request.uuid
        #self.root.storage_dir = request.storage_dir

        # the alert will already be locked by the queue manager
        # so we need to transfer the acquired locks
        request.transfer_locks_to(self.root)

        try:
            # have we already set a disposition for this alert?
            self.root.load()

            if self.root.disposition:
                logging.debug("alert {} already has a disposition - skipping analysis".format(self.root))
                self.cancel_analysis()
            else:
                self.start_disposition_watch(request.id)

            # note that we still make this call to analyze
            # it gives the post analysis of modules a chance to react to a different disposition
            self.analyze(self.root)

        finally:
            # make sure we unlock the alert
            if self.root.is_locked():
                self.root.unlock()

            # make sure the disposition watcher also stops
            self.analysis_ended_flag = True
            if self.disposition_watch_thread:
                self.disposition_watch_thread.join()

    def post_analysis(self, root):
        try:
            root.sync_profile_points()
        except Exception as e:
            logging.error("unable to sync profile points for {}: {}".format(root, e))
            report_exception()

    def start_disposition_watch(self, alert_id):
        # reset the state flag
        self.analysis_ended_flag = False

        self.disposition_watch_thread = Thread(target=self.disposition_watch_loop, args=(alert_id,), 
                                               name='Disposition Watch {}'.format(alert_id))
        self.disposition_watch_thread.daemon = True
        self.disposition_watch_thread.start()
        #record_metric(METRIC_THREAD_COUNT, threading.active_count())

    def disposition_watch_loop(self, alert_id):

        enable_cached_db_connections()

        while not self.shutdown and not self.cancel_analysis_flag and not self.analysis_ended_flag:
            try:
                self.disposition_watch_execute(alert_id)
                time.sleep(5)

            except Exception as e:
                logging.error("unable to check disposition of {}: {}".format(alert_id, e))
                report_exception()
                return

        disable_cached_db_connections()

        logging.debug("exiting disposition watch")

    def disposition_watch_execute(self, alert_id):
        with get_db_connection() as db:
            c = db.cursor()
            c.execute("SELECT disposition FROM alerts WHERE id = %s", (alert_id,))
            (disposition,) = c.fetchone()
            if disposition:
                self.cancel_analysis()

    def save_delayed_analysis(self):
        """Called as the engine shuts down to save outstanding delayed analysis requests."""

        # we pickle out the current contents of the queue as a list of tuples(next_time, request)
        output_data = []
        while True:
            try:
                next_time, request = self.delayed_analysis_queue.get(block=False)
                output_data.append((next_time, request))
            except Empty:
                # exit and return to loop to check shutdown status
                break

        # also take a look at the ready queue, might be one there too
        try:
            request = self.ready_queue.get(block=False)
            if isinstance(request, DelayedAnalysisRequest):
                output_data.append((datetime.datetime.now().timestamp(), request))
        except Empty:
            pass

        if not len(output_data):
            return

        logging.info("saving {} delayed analysis requests".format(len(output_data)))
        try:
            with open(self.delayed_analysis_path, 'wb') as fp:
                pickle.dump(output_data, fp)
        except Exception as e:
            logging.error("unable to save delayed analysis requests: {}".format(e))
            report_exception()
            try:
                os.remove(self.delayed_analysis_path)
            except:
                pass

    def load_delayed_analysis(self):
        """Called as the engine starts up to load saved delayed analysis requests."""

        if not os.path.exists(self.delayed_analysis_path):
            return

        with open(self.delayed_analysis_path, 'rb') as fp:
            input_data = pickle.load(fp)

        for next_time, request in input_data:
            # make sure these are unlocked as they go into the queues
            if request.is_locked():
                request.unlock()

            self.delayed_analysis_queue.put((next_time, request), block=False)

        logging.info("loaded {} outstanding delayed analysis requests".format(self.delayed_analysis_queue.qsize()))

        try:
            os.remove(self.delayed_analysis_path)
        except:
            pass

    def initialize_delayed_analysis(self):
        super().initialize_delayed_analysis()
        self.load_delayed_analysis()

    def cleanup_delayed_analysis(self):
        super().cleanup_delayed_analysis()
        self.save_delayed_analysis()

    def initialize_collection(self):
        super().initialize_collection()

        enable_cached_db_connections()

        if not os.path.exists(self.incomplete_analysis_path):
            return

        logging.info("reading incomplete analysis from {}".format(self.incomplete_analysis_path))
        with open(self.incomplete_analysis_path, 'r') as fp:
            for line in fp:
                uuid, storage_dir, _id = line.strip().split('\t')
                self.incomplete_analysis.append(AnalysisRequest(uuid, storage_dir, _id))

        logging.info("loaded {} incomplete analysis requests".format(len(self.incomplete_analysis)))
        os.remove(self.incomplete_analysis_path)

    def work_incomplete(self, alert):
        """Called when analysis finished prematurely."""

        if not isinstance(alert, Alert):
            logging.warning("not saving incomplete work on {}".format(alert))
            return

        # just write the current storage_dir out to file and we'll pick it back up when we start back up
        with open(self.incomplete_analysis_path, 'a') as fp:
            fp.write('{}\t{}\t{}\n'.format(alert.uuid, alert.storage_dir, alert.id))

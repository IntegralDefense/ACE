# vim: ts=4:sw=4:et:cc=120

import collections
import datetime
import gc
import importlib
import inspect
import io
import logging
import os, os.path
import queue
import shutil
import signal
import socket
import ssl
import stat
import sys
import tarfile
import tempfile
import threading
import time
import uuid

from multiprocessing import Process, Queue, Semaphore, Event, Pipe, cpu_count
from queue import PriorityQueue, Empty, Full
from subprocess import Popen, PIPE

import saq
import saq.analysis
import saq.database

from saq.analysis import Observable, Analysis, RootAnalysis, ProfilePoint, ProfilePointAnalyzer
from saq.constants import *
from saq.database import Alert, use_db, release_cached_db_connection, enable_cached_db_connections, \
                         get_db_connection, add_workload, acquire_lock, release_lock, execute_with_retry, \
                         add_delayed_analysis_request, clear_expired_locks, clear_expired_local_nodes, \
                         initialize_node
from saq.error import report_exception
from saq.modules import AnalysisModule
from saq.performance import record_metric
from saq.util import human_readable_size, storage_dir_from_uuid

import iptools
import psutil
import requests

# the workload database configuration section name
# corresponds to the database_workload config in etc/saq.ini
DB_CONFIG = 'workload'

# global pointer to the engine that is currently running
# only one engine runs per process
CURRENT_ENGINE = None

# state flag that indicates pre-analysis has been executed on a RootAnalysis
STATE_PRE_ANALYSIS_EXECUTED = 'pre_analysis_executed'

class AnalysisTimeoutError(RuntimeError):
    pass

class WaitForAnalysisException(Exception):
    """Thrown when we need to wait for analysis to occur on something.
       An AnalysisModule can call self.wait_for_analysis(observable, analysis) if it needs analysis performed by a 
       given module on a given observable. That function will throw this exception if analysis has not 
       occured yet, then the Engine will catch that and reorder things to perform that analysis next."""
    def __init__(self, observable, analysis, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.observable = observable
        self.analysis = analysis

class Worker(object):
    def __init__(self, mode=None):
        self.mode = mode # the primary analysis mode for the worker
        self.process = None

        # when this is set the worker will exit
        self.worker_shutdown_event = None

        # set this Event once you're started up and are running
        self.worker_startup_event = None

    def start(self):
        self.worker_shutdown_event = Event()
        self.worker_startup_event = Event()
        self.process = Process(target=self.worker_loop, name='Worker [{}]'.format(self.mode if self.mode else 'any'))
        self.process.start()
  
    def single_threaded_start(self):
        self.worker_shutdown_event = Event()
        self.worker_startup_event = Event()
        self.worker_loop()

    def wait_for_start(self):
        while not self.worker_startup_event.wait(5):
            logging.warning("worker for {} not starting".format(self.mode))

    def stop(self):
        self.worker_shutdown_event.set()
        self.wait()

    def wait(self):
        while True:
            logging.info("waiting for {}...".format(self.process))
            self.process.join(5)
            if not self.process.is_alive():
                return

            # if we are in a controlled shutdown then the wait could take a while
            if not CURRENT_ENGINE.controlled_shutdown:
                logging.warning("process {} not stopping".format(self.process))

    def check(self):
        """Makes sure the process is running and restarts it if it is not."""
        # if the system is shutting down then we don't need to worry about it
        if self.worker_shutdown_event is not None and self.worker_shutdown_event.is_set():
            logging.debug("engine under worker shutdown -- not restarting processes")
            return

        if CURRENT_ENGINE.shutdown:
            logging.debug("engine under shutdown -- not restarting processes")
            return

        if CURRENT_ENGINE.controlled_shutdown:
            logging.debug("engine under controlled shutdown -- not restarting processes")
            return

        # is the process running?
        if self.process is not None and self.process.is_alive():
            return

        # if not then start it back up
        logging.warning("detected death of process {} pid {}".format(self.process, self.process.pid))
        self.start()
        self.wait_for_start()

    def worker_loop(self):
        logging.info("started worker loop on process {} with priority {}".format(os.getpid(), self.mode))
        CURRENT_ENGINE.setup(self.mode)

        # let the main process know we started
        if self.worker_startup_event is not None:
            self.worker_startup_event.set()
        
        while True:
            # is the engine shutting down?
            if CURRENT_ENGINE.shutdown:
                break

            # have we requested this single worker to shut down?
            if self.worker_shutdown_event is not None and self.worker_shutdown_event.is_set():
                break

            try:
                # if the control event is set then it means we're looking to exit when everything is done
                if CURRENT_ENGINE.control_event.is_set():
                    if CURRENT_ENGINE.delayed_analysis_queue_is_empty and CURRENT_ENGINE.workload_queue_is_empty:
                        logging.debug("both queues are empty - broke out of engine loop")
                        break # break out of the main loop

                    logging.debug("queue sizes workload {} delayed {}".format(
                                   CURRENT_ENGINE.workload_queue_size,
                                   CURRENT_ENGINE.delayed_analysis_queue_size))

                # if execute returns True it means it discovered and processed a work_item
                # in that case we assume there is more work to do and we check again immediately
                if CURRENT_ENGINE.execute():  
                    continue

                # otherwise we wait a second until we go again
                if self.worker_shutdown_event is not None:
                    if self.worker_shutdown_event.wait(1):
                        break
                else:
                    time.sleep(1)
                    
            except KeyboardInterrupt:
                logging.warning("caught user interrupt in worker_loop")
                if CURRENT_ENGINE.control_event.is_set():
                    logging.warning("alreadying in controlled shutdown -- stopping now...")
                    CURRENT_ENGINE.stop()
                else:
                    CURRENT_ENGINE.control_event.set()
            except Exception as e:
                logging.error("uncaught exception in worker_loop: {}".format(e))
                report_exception()
                time.sleep(1)

        logging.debug("worker {} exiting".format(os.getpid()))
        release_cached_db_connection()

    def __str__(self):
        return '{}{}'.format(str(self.process), ' (PID {})'.format(self.process.pid) if self.process else '')

class WorkerManager(object):
    def __init__(self):
        self.workers = [] # of Worker objects
        self.process = None

        # set this Event once you've started up and are running
        self.startup_event = None

        # set this Event when you want to restart all the workers
        self.restart_workers_event = None

    def add_worker(self, mode=None):
        """Adds a worker for the given mode. This must be called before calling start()."""
        self.workers.append(Worker(mode))

    def start(self):
        self.restart_workers_event = Event()
        self.startup_event = Event()

        self.process = Process(target=self.manager_loop, name="Worker Manager")
        self.process.start()

        # wait for the manager to say it has started
        while not self.startup_event.wait(5):
            logging.warning("worker manager not starting...")

    # NOTE there's no stop() function for the WorkerManager
    # instead it relies on the engine to stop

    def wait(self):
        while True:
            logging.info("waiting for {}".format(self.process))
            self.process.join(10)
            if not self.process.is_alive():
                break
            
            logging.warning("worker manager not stopping")

    def restart_workers(self):
        self.restart_workers_event.set()
            
    def manager_loop(self):
        logging.info("worker manager started on pid {}".format(os.getpid()))

        # load the workers
        for mode in CURRENT_ENGINE.analysis_pools.keys():
            for i in range(CURRENT_ENGINE.analysis_pools[mode]):
                self.add_worker(mode)

        # do we NOT have any defined analysis pools?
        if len(self.workers) == 0:
            pool_count = cpu_count()
            if CURRENT_ENGINE.pool_size_limit is not None and pool_count > CURRENT_ENGINE.pool_size_limit:
                pool_count = CURRENT_ENGINE.pool_size_limit
                
            logging.info("no analysis pools defined -- defaulting to {} workers assigned to any pool".format(
                        pool_count))

            for core in range(pool_count):
                self.add_worker()

        # go ahead and start the workers for the first time
        for worker in self.workers:
            worker.start()

        for worker in self.workers:
            worker.wait_for_start()

        # everything seems to be up and running
        self.startup_event.set()

        # execute the check every second
        while not CURRENT_ENGINE.controlled_shutdown \
                  and not CURRENT_ENGINE.shutdown:

            # start any workers that need to be started
            for worker in self.workers:
                worker.check()

            # do we need to restart the workers?
            if self.restart_workers_event.is_set():
                logging.info("got command to restart workers")
                self.restart_workers_event.clear()
                for worker in self.workers:
                    worker.stop()

                # make sure we're up to date on the config
                saq.load_configuration()

                for worker in self.workers:
                    worker.start()

                for worker in self.workers:
                    worker.wait_for_start()

            # don't spin the cpu
            time.sleep(1)

        # make sure all the processes exit with you
        for worker in self.workers:
            worker.wait()

        logging.info("worker manager on pid {} exiting".format(os.getpid()))

# syntactic suger for if self.is_local: return None
def exclude_if_local(target_function):
    """A member function of Engine wrapped with this function will not execute if the Engine is in "local" mode."""
    def _wrapper(self, *args, **kwargs):
        if self.is_local:
            return None

        return target_function(self, *args, **kwargs)

    return _wrapper

class Engine(object):
    """Analysis Correlation Engine"""

    # 
    # INITIALIZATION
    # ------------------------------------------------------------------------

    def __init__(self, name='ace', local_analysis_modes=None, 
                                   analysis_pools=None, 
                                   pool_size_limit=None, 
                                   default_analysis_mode=None):

        assert local_analysis_modes is None or isinstance(local_analysis_modes, list)
        assert analysis_pools is None or isinstance(analysis_pools, dict)
        assert pool_size_limit is None or (isinstance(pool_size_limit, int) and pool_size_limit > 0)
        assert default_analysis_mode is None or (isinstance(default_analysis_mode, str) and default_analysis_mode)

        global CURRENT_ENGINE
        CURRENT_ENGINE = self

        # the name of the engine, usually you want the default unless you're doing something different
        # like unit testing
        self.name = name

        # the engine configuration
        self.config = saq.CONFIG['engine']

        # we just cache the current hostname of this engine here
        self.hostname = socket.gethostname()

        # directory to store statistical runtime information
        self.stats_dir = os.path.join(saq.MODULE_STATS_DIR, self.name)

        # controlled shutdown event - shut down ACE by allowing all existing jobs to complete
        self.control_event = Event()

        # immediate shutdown event - shut down ACE now
        self.immediate_event = Event()

        # process to manage the analysis processes
        self.engine_process = None

        # an event that gets set when the engine has started
        self.engine_startup_event = Event()

        # the worker manager is responsible for starting the actual workers (on a separate process)
        # and restarting them if they die
        self.worker_manager = None

        # used to start and stop the workers
        self.worker_control_event = Event()

        # a list of analysis modules to enable specified by configuration section names
        # this is typically used in unit testing
        # if this list is not empty then ONLY these modules will be loaded regardless of configuration settings
        self.locally_enabled_modules = []
        self.locally_mapped_analysis_modes = {} # key = analysis_mode, value = set(config section names)

        # the modules that will perform the analysis
        self.analysis_modules = []

        # the mapping of analysis mode to the list of analysis modules that should run for that mode
        self.analysis_mode_mapping = {}

        # a mapping of analysis module configuration section headers to the load analysis modules
        self.analysis_module_mapping = {} # key = analysis_module_blah, value = AnalysisModule

        # the list of analysis modes this engine supports
        # if this list is empty then it will work on any analysis mode
        # if the analysis_modes parameter is passed to the constructor then we use that instead
        if local_analysis_modes is not None:
            self.local_analysis_modes = local_analysis_modes
        else:
            self.local_analysis_modes = [_.strip() for _ in self.config['local_analysis_modes'].split(',') if _]

        # load the analysis pool settings
        # if we specified analysis_pools on the constructor then we use that instead
        self.analysis_pools = {} # key = analysis_mode, value = int (count)
        if analysis_pools is not None:
            for analysis_mode in analysis_pools.keys():
                self.add_analysis_pool(analysis_mode, analysis_pools[analysis_mode])
        else:
            self.analysis_pools = {}
            for key in self.config.keys():
                if not key.startswith('analysis_pool_size_'):
                    continue

                analysis_mode = key[len('analysis_pool_size_'):]
                self.add_analysis_pool(analysis_mode, self.config.getint(key))

        # the maximum size of the analysis pool if no analysis pools are defined
        # default is None which means to use the cpu_count 
        self.pool_size_limit = pool_size_limit

        # the default analysis mode for RootAnalysis objects assigned to invalid (unknown) analysis modes
        self._default_analysis_mode = None
        # if we pass this in on the constructor we use that instead of what is in the configuration file
        if default_analysis_mode is not None:
            self.default_analysis_mode = default_analysis_mode
        else:
            self.default_analysis_mode = self.config['default_analysis_mode']

        # make sure this analysis mode is valid
        if 'analysis_mode_{}'.format(self.default_analysis_mode) not in saq.CONFIG:
            logging.critical("engine.default_analysis_mode value {} invalid (no such analysis mode defined)".format(
                              self.default_analysis_mode))

        # things we do *not* want to analyze
        self.observable_exclusions = {} # key = o_type, value = [] of values

        # this is set to True to cancel the analysis going on in the process() function
        self._cancel_analysis_flag = False

        # we keep track of the total amount of time (in seconds) that each module takes
        self.total_analysis_time = {} # key = module.config_section, value = total_seconds

        # this gets set to true when we receive a unix signal
        self.sigterm_received = False
        self.sighup_received = False

        # how often do we automatically reload the workers?
        self.auto_refresh_frequency = self.config.getint('auto_refresh_frequency')

        # every N minutes we act as though we received a SIGHUP
        self.next_auto_refresh_time = None

        # the RootAnalysis object the current process is analyzing
        self.root = None

        # the DelayedAnalysisRequest the Alert came from (or None if it's normal processing)
        self.delayed_analysis_request = None

        # the analysis mode this worker is primary for
        self.analysis_mode_priority = None

        # threading to manage keep alives for global locks from chronos
        self.lock_manager_control_event = None
        self.lock_keepalive_thread = None

        # each worker assigns this to some random uuid to use as a lock
        self.lock_uuid = None

        # a description of who owns a given lock
        self.lock_owner = None

        # set to True after engine is started
        self.started = False

        # amount of time (in seconds) until we think analysis might be tied up
        self.maximum_cumulative_analysis_warning_time = \
                saq.CONFIG['global'].getint('maximum_cumulative_analysis_warning_time') * 60

        # amount of time (in seconds until we give up entirely
        self.maximum_cumulative_analysis_fail_time = \
                saq.CONFIG['global'].getint('maximum_cumulative_analysis_fail_time') * 60

        # maximum amount of time (in seconds) that an individual analysis module should take
        self.maximum_analysis_time = saq.CONFIG['global'].getint('maximum_analysis_time')

        # the threads that manages the execution of the maintenance routines of analysis modules
        # there is one thread per analysis module that has a maintenance_frequency > 0
        self.maintenance_threads = []
        # an event to control the management threads
        self.maintenance_control = None # threading.Event()

        # how often do we update the nodes database table for this engine (in seconds)
        self.node_status_update_frequency = self.config.getint('node_status_update_frequency')
        # and then when will be the next time we make this update?
        self.next_status_update_time = None

        # if this is set then this engine will ONLY work on work that has the given exclusive_uuid
        # by default is is None which means the engine will process anything that does NOT have an exclusive_uuid
        self.exclusive_uuid = None

        # we keep track of the invalid analysis modes we've seen so we don't warn about them a lot
        self.invalid_analysis_modes_detected = set()

        # when analysis fails (entirely) we record the details in the error_reports directory
        # if this flag is True then we also save a copy of the RootAnalysis data structure as well
        # NOTE this can take a lot of disk space
        self.copy_analysis_on_error = False

    def __str__(self):
        return "Engine ({} - {})".format(saq.SAQ_NODE, self.name)

    def set_local(self):
        """Sets the Engine into "local" mode."""
        self.exclusive_uuid = str(uuid.uuid4())
        saq.set_node(str(uuid.uuid4()))
        logging.info("set node {} to local exclusive uuid {}".format(saq.SAQ_NODE, self.exclusive_uuid))

    @property
    def is_local(self):
        """An Engine is "local" if it is using an exclusive uuid. This means
        the engine is running only once and any work it generates should be kept
        local."""

        return self.exclusive_uuid is not None

    def enable_module(self, config_section, analysis_mode=None):
        """Enables the module specified by the configuration section name.
           Modules that are enabled this way are the ONLY modules that are loaded for the Engine.
           If analysis_mode is not None then the module is also added to the given analysis mode.
           Analysis mode can either be a single mode name, or a tuple of mode names.
           This is typically only used by unit tests."""

        if config_section in saq.CONFIG['disabled_modules'] and saq.CONFIG['disabled_modules'].getboolean(config_section):
            logging.info("skipping disabled module {}".format(config_section))
            return

        self.locally_enabled_modules.append(config_section)
        if analysis_mode is not None:
            if isinstance(analysis_mode, str):
                analysis_modes = (analysis_mode,)
            else:
                analysis_modes = analysis_mode

            for analysis_mode in analysis_modes:
                if analysis_mode not in self.locally_mapped_analysis_modes:
                    self.locally_mapped_analysis_modes[analysis_mode] = set()
                self.locally_mapped_analysis_modes[analysis_mode].add(config_section)

    def add_analysis_pool(self, analysis_mode, count):
        """Adds the given analysis pool to the engine with the given prioriy
           mode and number of processes for the pool."""

        # if a pool is specified for a mode that is not supported by this engine
        # then we warn and ignore it
        if self.local_analysis_modes and analysis_mode not in self.local_analysis_modes:
            logging.critical("attempted to add analysis pool for mode {} " \
                            "which is not supported by this engine ({})".format(
                            analysis_mode, self.local_analysis_modes))
            return

        self.analysis_pools[analysis_mode] = count
        logging.debug("added analysis pool mode {} count {}".format(analysis_mode, count))

    @property
    def default_analysis_mode(self):
        return self._default_analysis_mode

    @default_analysis_mode.setter
    def default_analysis_mode(self, value):
        # if we're controlling which analysis modes we support then we need to make sure we support the default
        if self.local_analysis_modes:
            if value not in self.local_analysis_modes:
                logging.debug("added default analysis mode {} to list of supported modes".format(value))
                self.local_analysis_modes.append(value)

        self._default_analysis_mode = value
        logging.debug("set default analysis mode to {}".format(value))

    @property
    @use_db
    def delayed_analysis_queue_size(self, db, c):
        """Returns the size of the delayed analysis queue (for this engine.)"""
        where_clause = [ 'node_id = %s' ]
        params = [ saq.SAQ_NODE_ID ]

        if self.is_local:
            where_clause.append('exclusive_uuid = %s')
            params.append(self.exclusive_uuid)
        else:
            where_clause.append('exclusive_uuid IS NULL')

        where_clause = ' AND '.join(where_clause)
        params = tuple(params)

        c.execute("SELECT COUNT(*) FROM delayed_analysis WHERE {}".format(where_clause), params)
        row = c.fetchone()
        return row[0]

    @property
    @use_db
    def workload_queue_size(self, db, c):
        """Returns the size of the workload queue (for this node.)"""
        where_clause = [ 'node_id = %s', 'company_id = %s' ]
        params = [ saq.SAQ_NODE_ID, saq.COMPANY_ID ]

        if self.is_local:
            where_clause.append('exclusive_uuid = %s')
            params.append(self.exclusive_uuid)
        else:
            where_clause.append('exclusive_uuid IS NULL')

        if self.local_analysis_modes:
            where_clause.append('workload.analysis_mode IN ( {} )'.format(','.join(['%s' for _ in self.local_analysis_modes])))
            params.extend(self.local_analysis_modes)

        where_clause = ' AND '.join(where_clause)
        params = tuple(params)

        c.execute("SELECT COUNT(*) FROM workload WHERE {}".format(where_clause), params)
        row = c.fetchone()
        return row[0]

    @property
    def delayed_analysis_queue_is_empty(self):
        """Returns True if the delayed analysis queue is empty, False otherwise."""
        return self.delayed_analysis_queue_size == 0

    @property
    def workload_queue_is_empty(self):
        """Returns True if the work queue is empty, False otherwise."""
        return self.workload_queue_size == 0

    def _get_analysis_module_by_generated_analysis(self, analysis):
        """Internal function to return the loaded AnalysisModule by type or string of generated Analysis."""
        for m in self.analysis_modules:
            if isinstance(analysis, str):
                if str(m.generated_analysis_type) == analysis:
                    return m
            elif isinstance(analysis, type):
                if m.generated_analysis_type == analysis:
                    return m

        logging.error("request for analysis module that generates {} failed".format(analysis))
        return None

    @use_db
    def initialize(self, db, c):
        """Initialization routines executed once at startup."""
        # make sure these exist
        for d in [ self.stats_dir ]:
            try:
                if not os.path.isdir(d):
                    os.makedirs(d)
            except Exception as e:
                logging.error("unable to create directory {}: {}".format(d, e))

        # insert this engine as a node (if it isn't already)
        initialize_node()

        # update the database with the list of analysis modes we accept
        sql = [ "DELETE FROM node_modes WHERE node_id = %s" ]
        params = [ (saq.SAQ_NODE_ID,) ]
        
        # if we do NOT specify local_analysis_modes then we default to ANY mode
        # by setting the any_mode column of the node database row
        sql.append("UPDATE nodes SET any_mode = %s WHERE id = %s")
        params.append((0 if self.local_analysis_modes else 1, saq.SAQ_NODE_ID))

        for mode in self.local_analysis_modes:
            sql.append("INSERT INTO node_modes ( node_id, analysis_mode ) VALUES ( %s, %s )")
            params.append((saq.SAQ_NODE_ID, mode))
            logging.info("node {} supports mode {}".format(saq.SAQ_NODE, mode))

        execute_with_retry(db, c, sql, params, commit=True)

    def initialize_signal_handlers(self):
        def handle_sighup(signum, frame):
            self.sighup_received = True

        def handle_sigterm(signal, frame):
            self.sigterm_received = True

        signal.signal(signal.SIGTERM, handle_sigterm)
        signal.signal(signal.SIGHUP, handle_sighup)

    def initialize_modules(self):
        """Loads all configured analysis modules and prepares the analysis mode mapping."""

        # the entire list of enabled analysis modules
        self.analysis_modules = []

        # the mapping of analysis mode to the list of analysis modules that should run for that mode
        self.analysis_mode_mapping = {} # key = analysis_mode, value = list(analysis modules)
        # NOTE inititally set() is used to prevent duplicates, later that is turned into a list

        # quick mapping of analysis module section name to the loaded AnalysisModule
        self.analysis_module_mapping = {} # key = config_section_name, value = AnalysisModule

        # assign the analysis_modes to the analysis modules that should run in them
        for section in saq.CONFIG.sections():
            if section.startswith('analysis_mode_'):
                mode = section[len('analysis_mode_'):]
                # make sure every analysis mode defines cleanup
                if 'cleanup' not in saq.CONFIG[section]:
                    logging.critical("{} missing cleanup key in configuration file".format(section))

                # is this mode supported by this engine?
                if self.local_analysis_modes and mode not in self.local_analysis_modes:
                    logging.info("analysis mode {} is not supported by the engine (only supports {})".format(
                                 mode, self.local_analysis_modes))
                    continue

                self.analysis_mode_mapping[mode] = set()

                # iterate each module group this mode uses
                for group_name in [_.strip() for _ in saq.CONFIG[section]['module_groups'].split(',') if _.strip()]:
                    group_section = 'module_group_{}'.format(group_name)
                    if group_section not in saq.CONFIG:
                        logging.critical("{} defines invalid module group {}".format(section, group_name))
                        continue

                    # add each analysis module this group specifies to this mode
                    for module_section in saq.CONFIG[group_section].keys():
                        # make sure this is in the configuration
                        if module_section not in saq.CONFIG:
                            logging.critical("{} references invalid analysis module {}".format(
                                             group_section, module_section))
                            continue
                            
                        #if module_section not in self.analysis_module_mapping:
                            #logging.debug("{} specified for {} but is disabled globally".format(
                                          #module_section, group_section))
                            #continue

                        self.analysis_mode_mapping[mode].add(module_section)
                        #logging.info("added {} to {}".format(module_section, section))

                # and then add any other modules specified for this mode (besides the groups)
                # NOTE this can also disable individual modules specified in
                # groups by setting the value to "no" instead of "yes"
                for key_name in saq.CONFIG[section].keys():
                    if not key_name.startswith('analysis_module_'):
                        continue

                    analysis_module_name = key_name[len('analysis_module_'):]
                    # make sure this is in the configuration
                    if key_name not in saq.CONFIG:
                        logging.critical("{} references invalid analysis module {}".format(section, analysis_module_name))
                        continue

                    # are we adding or removing?
                    if saq.CONFIG[section].getboolean(key_name):
                        self.analysis_mode_mapping[mode].add(key_name)
                        #logging.info("added {} to {}".format(analysis_module_name, section))
                    else:
                        if key_name in self.analysis_mode_mapping[mode]:
                            self.analysis_mode_mapping[mode].discard(key_name)
                            #logging.debug("removed {} from analysis mode {}".format(analysis_module_name, mode))

                # same for locally (manually) mapped ones
                if mode in self.locally_mapped_analysis_modes:
                    for analysis_module_section in self.locally_mapped_analysis_modes[mode]:
                        logging.debug("manual map for mode {} to {}".format(mode, analysis_module_section))
                        self.analysis_mode_mapping[mode].add(analysis_module_section)

        # at this point self.analysis_mode_mapping[mode] each contain a list of
        # analysis module config sections names to load

        # get a list of all the analysis modules that should be loaded for the
        # modes specified in the configuration file
        analysis_module_sections = set()
        for mode in self.analysis_mode_mapping.keys():
            for section in self.analysis_mode_mapping[mode]:
                analysis_module_sections.add(section)

        # this is overridden by locally enabled modules
        for section in self.locally_enabled_modules:
            analysis_module_sections.add(section)

        logging.debug("loading {} analysis modules...".format(len(analysis_module_sections)))

        for section in analysis_module_sections:
            # if there no locally enabled modules then check configuration
            # settings for which modules are enabled/disabled
            if not self.locally_enabled_modules:

                # is this module in the list of disabled modules?
                # these are always disabled regardless of any other setting
                if section in saq.CONFIG['disabled_modules'] and saq.CONFIG['disabled_modules'].getboolean(section):
                    logging.debug("{} is disabled".format(section))
                    continue

                # is this module disabled globally?
                # modules that are disable globally are not used anywhere
                if not saq.CONFIG.getboolean(section, 'enabled'):
                    logging.debug("analysis module {} disabled (globally)".format(section))
                    continue

            else:
                # otherwise check to see if this module is enabled locally
                if section not in self.locally_enabled_modules:
                    continue

            module_name = saq.CONFIG[section]['module']
            try:
                _module = importlib.import_module(module_name)
            except Exception as e:
                logging.error("unable to import module {}".format(module_name, e))
                report_exception()
                continue

            class_name = saq.CONFIG[section]['class']
            try:
                module_class = getattr(_module, class_name)
            except AttributeError as e:
                logging.error("class {} does not exist in module {} in analysis module {}".format(
                              class_name, module_name, section))
                report_exception()
                continue

            try:
                logging.info("loading module {}".format(section))
                analysis_module = module_class(section)
            except Exception as e:
                logging.error("unable to load analysis module {}: {}".format(section, e))
                report_exception()
                continue

            # make sure the module has everything it needs
            try:
                analysis_module.verify_environment()
            except Exception as e:
                logging.error("analysis module {} failed environment verification: {}".format(analysis_module, e))
                report_exception()
                continue

            # if this module genereated analysis then make sure the generated analysis can initialize itself
            try:
                if analysis_module.generated_analysis_type is not None:
                    check_analysis = analysis_module.generated_analysis_type()
                    check_analysis.initialize_details()
            except NotImplementedError:
                if check_analysis.details is None:
                    logging.critical("analysis module {} generated analysis {} fails to initialize -- did you forget "
                                     "to override the initialize_details method of the Analysis object that is "
                                     "generated by this AnalysisModule?".format(
                                     analysis_module, type(check_analysis)))
                continue

            # we keep a reference to the engine here
            analysis_module.engine = self
            self.analysis_modules.append(analysis_module)
            self.analysis_module_mapping[section] = analysis_module

            logging.info("loaded analysis module from {}".format(section))

        # for each analysis mode mapping, remap the list of analysis module configuration sections names
        # to the actual loaded modules
        for mode in self.analysis_mode_mapping.keys():
            self.analysis_mode_mapping[mode] = [self.analysis_module_mapping[s] 
                                                for s in self.analysis_mode_mapping[mode]
                                                if s in self.analysis_module_mapping]

            # TODO check for unit testing first
            func = logging.debug
            #if not self.analysis_mode_mapping[mode]:
                #func = logging.warning

            func("analysis mode {} has {} modules loaded".format(mode, len(self.analysis_mode_mapping[mode])))

        logging.debug("finished loading {} modules".format(len(self.analysis_modules)))

        for mode in self.analysis_mode_mapping.keys():
            for _module in self.analysis_mode_mapping[mode]:
                logging.info("mode {} activated module {}".format(mode, _module))

    #
    # MAINTENANCE
    # ------------------------------------------------------------------------

    @exclude_if_local
    def start_maintenance_threads(self):
        self.maintenance_control = threading.Event()

        for _module in self.analysis_modules:
            if _module.maintenance_frequency is None or _module.maintenance_frequency <= 0:
                continue

            t = threading.Thread(target=self.maintenance_loop, 
                                 name="Maintenance - {}".format(_module.name), 
                                 args=(_module,))
            t.start()
            self.maintenance_threads.append(t)

    @exclude_if_local
    def stop_maintenance_threads(self):
        self.maintenance_control.set()
        for t in self.maintenance_threads:
            logging.info("waiting for {} to stop".format(t.name))
            t.join()

        self.maintenance_threads = []

    @property
    def maintenance_shutdown(self):
        """Returns True if the maintenance loop should end or if the engine is shutting down."""
        return self.shutdown or self.maintenance_control.is_set()

    def maintenance_sleep(self, seconds):
        """Utility function to sleep for N seconds without blocking shutdown."""
        seconds = float(seconds)
        while not self.maintenance_shutdown and seconds > 0:
            # we also want to support sleeping for less than a second
            time.sleep(1.0 if seconds > 0 else seconds)
            seconds -= 1.0

    def maintenance_loop(self, _module):
        logging.info("maintenance loop started for {}".format(_module.name))
        while not self.maintenance_shutdown:
            try:
                logging.info("executing maintenance for {}".format(_module.name))
                _module.execute_maintenance()
            except Exception as e:
                logging.error("error executing main maintenance loop for {}: {}".format(_module.name, e))
                report_exception()

            self.maintenance_sleep(_module.maintenance_frequency)

        logging.info("maintenance loop ended")

    #
    # STATUS AND PERFORMANCE
    # ------------------------------------------------------------------------

    @property
    def controlled_shutdown(self):
        """Returns True if the engine should stop when all work has completed."""
        return self.control_event.is_set()

    @property
    def shutdown(self):
        """Returns True if the engine is to be shut down NOW."""
        return self.immediate_event.is_set()

    #
    # CONTROL FUNCTIONS
    # ------------------------------------------------------------------------

    def start(self):
        """Starts the engine."""

        # make sure engine isn't already started
        if self.started:
            logging.error("engine {} already started".format(self))
            return

        self.initialize()
        if not self.start_engine():
            sys.exit(1)

        logging.debug("control PID {}".format(os.getpid()))
        self.started = True

    def single_threaded_start(self, mode=None):
        """Typically used for debugging. Runs the entire thing under a single process/thread."""
        logging.warning("executing in single threaded mode")
        self.controlled_stop()
        worker = Worker(mode)
        worker.single_threaded_start()

    def stop(self):
        """Immediately stop the engine."""
        logging.info("stopping {} NOW".format(self))
        self.immediate_event.set()

    def controlled_stop(self):
        """Shutdown the engine in a controlled manner allowing existing jobs to complete."""
        logging.info("controlled stop started for {}".format(self))
        if self.controlled_shutdown:
            raise RuntimeError("already requested control_event")
        self.control_event.set()

    def wait(self):
        """Waits for the engine to stop."""

        self.initialize_signal_handlers()
        logging.debug("waiting for engine process {} to complete".format(self.engine_process.pid))

        while True:
            try:
                self.engine_process.join(0.1)
                if not self.engine_process.is_alive():
                    logging.debug("detected end of process {}".format(self.engine_process.pid))
                    break

                if self.sigterm_received:
                    try:
                        logging.info("sending SIGTERM to {}".format(self.engine_process.pid))
                        os.kill(self.engine_process.pid, signal.SIGTERM)
                    except Exception as e:
                        logging.error("unable to send SIGTERM to {}: {}".format(self.engine_process.pid, e))
                    finally:
                        sigterm_received = False

                if self.sighup_received:
                    try:
                        logging.info("sending SIGHUP to {}".format(self.engine_process.pid))
                        os.kill(self.engine_process.pid, signal.SIGHUP)
                    except Exception as e:
                        logging.error("unable to send SIGHUP to {}: {}".format(self.engine_process.pid, e))
                    finally:
                        sighup_received = False

            except Exception as e:
                logging.error("unable to join engine process {}".format(e))

    def cancel_analysis(self):
        """Sends a single to all the analysis modules to shut down, stops the analysis loop."""
        # force the analysis loop to break
        self._cancel_analysis_flag = True

        # try to get currently executing analysis modules to bail
        for analysis_module in self.analysis_modules:
            analysis_module.cancel_analysis()

        # TODO send a signal to the delayed analysis manager to discontinue processing 
        # right now it relies on the fact that the storage directory is gone

    @property
    def cancel_analysis_flag(self):
        """Returns True if analysis has been cancelled."""
        return self.shutdown or self._cancel_analysis_flag

    #
    # LOCK MANAGEMENT
    # ------------------------------------------------------------------------

    def start_root_lock_manager(self, uuid):
        """Starts a thread that keeps a lock open."""
        logging.debug("starting lock manager for {}".format(uuid))

        # we use this event for a controlled shutdown
        self.lock_manager_control_event = threading.Event()

        # start a thread that sends keep alives every N seconds
        self.lock_keepalive_thread = threading.Thread(target=self.root_lock_manager_loop,
                                                           name="Lock Manager ({})".format(uuid),
                                                           args=(uuid,))
        self.lock_keepalive_thread.daemon = True # we want this thread to die if the process dies
        self.lock_keepalive_thread.start()

    def stop_root_lock_manager(self):
        """Stops the root lock manager thread."""
        if self.lock_manager_control_event is None:
            logging.warning("called stop_root_lock_manager() when no lock manager was running")
            return

        logging.debug("stopping {}".format(self.lock_keepalive_thread))
        self.lock_manager_control_event.set()
        self.lock_keepalive_thread.join()

    def root_lock_manager_loop(self, uuid):
        try:
            while not self.lock_manager_control_event.is_set():
                if self.lock_manager_control_event.wait(float(saq.CONFIG['global']['lock_keepalive_frequency'])):
                    break

                if not acquire_lock(uuid, self.lock_uuid, lock_owner=self.lock_owner):
                    logging.warning("failed to maintain lock")
                    break

        except Exception as e:
            logging.error("caught unknown error in {}: {}".format(self.lock_keepalive_thread, e))
            report_exception()
    #
    # DELAYED ANALYSIS
    # ------------------------------------------------------------------------

    @use_db
    def delay_analysis(self, root, observable, analysis, analysis_module, db, c,
                       hours=None, minutes=None, seconds=None,
                       timeout_hours=None, timeout_minutes=None, timeout_seconds=None):
        assert hours or minutes or seconds
        assert isinstance(root, RootAnalysis)
        assert isinstance(observable, Observable)
        assert isinstance(analysis, Analysis)
        assert isinstance(analysis_module, AnalysisModule)

        if analysis.delayed:
            logging.warning("analysis for {} by {} seems to already be scheduled".format(observable, analysis_module))

        # are we set to time out?
        if timeout_hours or timeout_minutes or timeout_seconds:
            # have we timed out?
            start_time = root.get_delayed_analysis_start_time(observable, analysis_module)
            if start_time is None:
                root.set_delayed_analysis_start_time(observable, analysis_module)
            else:
                timeout = start_time + datetime.timedelta(hours=0 if timeout_hours is None else timeout_hours, 
                                                          minutes=0 if timeout_minutes is None else timeout_minutes,
                                                          seconds=0 if timeout_seconds is None else timeout_seconds)
                if datetime.datetime.now() > timeout:
                    logging.warning("delayed analysis for {} in {} has timed out".format(observable, analysis_module))
                    return False

                logging.info("delayed analysis for {} in {} has been waiting for {} seconds".format(
                             observable, analysis_module, (datetime.datetime.now() - start_time).total_seconds()))

        # when do we resume analysis?
        next_analysis = datetime.datetime.now() + datetime.timedelta(hours=hours, minutes=minutes, seconds=seconds)

        # add the request to the workload
        try:
            if add_delayed_analysis_request(root, observable, analysis_module, next_analysis, 
                                            exclusive_uuid=self.exclusive_uuid):
                analysis.delayed = True
        except Exception as e:
            logging.error("unable to insert delayed analysis on {} by {} for {}: {}".format(
                             root, analysis_module.config_section, observable, e))
            report_exception()
            return False

        return True

    #
    # ANALYSIS ENGINE
    # ------------------------------------------------------------------------

    @exclude_if_local
    @use_db
    def update_node_status(self, db, c):
        """Updates the last_update field of the node table for this node."""
        try:
            execute_with_retry(db, c, """UPDATE nodes SET last_update = NOW(), is_local = %s, location = %s 
                                         WHERE id = %s""", 
                              (self.is_local, saq.API_PREFIX, saq.SAQ_NODE_ID), commit=True)

            logging.debug("updated node {} ({}) (is_local = {})".format(saq.SAQ_NODE, saq.SAQ_NODE_ID, self.is_local))

        except Exception as e:
            logging.error("unable to update node {} status: {}".format(saq.SAQ_NODE, e))
            report_exception()

    @exclude_if_local
    @use_db
    def execute_primary_node_routines(self, db, c):
        """Executes primary node routines and may become the primary node if no other node has done so."""
        try:
            # is there a primary node that has updated node status in the past N seconds
            # where N is 30 + node update status frequency
            c.execute("""
                SELECT name FROM nodes 
                WHERE 
                    is_primary = 1 
                    AND TIMESTAMPDIFF(SECOND, last_update, NOW()) < %s
                """, (self.node_status_update_frequency + 30,))

            primary_node = c.fetchone()

            # is there no primary node at this point?
            if primary_node is None:
                execute_with_retry(db, c, [ 
                    "UPDATE nodes SET is_primary = 0",
                    "UPDATE nodes SET is_primary = 1, last_update = NOW() WHERE id = %s" ],
                [ tuple(), (saq.SAQ_NODE_ID,) ], commit=True)
                primary_node = saq.SAQ_NODE
                logging.info("this node {} has become the primary node".format(saq.SAQ_NODE))
            else:
                primary_node = primary_node[0]

            # are we the primary node?
            if primary_node != saq.SAQ_NODE:
                logging.debug("node {} is not primary - skipping primary node routines".format(saq.SAQ_NODE))
                return

            # do primary node stuff
            # clear any outstanding locks
            clear_expired_locks()
            clear_expired_local_nodes()

        except Exception as e:
            logging.error("error executing primary node routines: {}".format(e))
            report_exception()

    def start_engine(self):

        self.engine_process = Process(target=self.engine_loop, name='ACE Engine')
        self.engine_process.start()
        
        # wait for the message from the child that it started up
        try:
            logging.debug("waiting for engine to start...")
            self.engine_startup_event.wait()
            logging.info("engine started")

        except Exception as e:
            logging.error("engine failed to start: {}".format(e))
            return False

        return True

    def engine_loop(self):
        logging.info("started engine on process {}".format(os.getpid()))

        self.worker_manager = WorkerManager()
        self.worker_manager.start()

        if self.auto_refresh_frequency:
            self.next_auto_refresh_time = datetime.datetime.now() + datetime.timedelta(
                                          seconds=self.auto_refresh_frequency)

        self.start_maintenance_threads()
        self.engine_startup_event.set()
        self.initialize_signal_handlers()

        try:
            while True:
                if self.sigterm_received:
                    logging.info("recevied SIGTERM -- shutting down")
                    self.stop()
                    break

                # is it time to update our node status?
                if self.next_status_update_time is None or \
                datetime.datetime.now() >= self.next_status_update_time:

                    self.update_node_status()
                    self.execute_primary_node_routines()

                    # when will we do this again?
                    self.next_status_update_time = datetime.datetime.now() + \
                    datetime.timedelta(seconds=self.node_status_update_frequency)

                reload_flag = False
                if self.auto_refresh_frequency and datetime.datetime.now() > self.next_auto_refresh_time:
                    logging.info("auto refresh frequency {} triggered reload of worker modules".format(
                                 self.auto_refresh_frequency))

                    reload_flag = True

                    self.next_auto_refresh_time = datetime.datetime.now() + \
                    datetime.timedelta(seconds=self.auto_refresh_frequency)
                    logging.debug("next auto refresh scheduled for {}".format(self.next_auto_refresh_time))

                if self.sighup_received:
                    # we re-load the config when we receive SIGHUP
                    logging.info("reloading engine configuration")
                    reload_flag = True
                    self.sighup_received = False

                if reload_flag:
                    # tell the manager to reload the workers
                    self.worker_manager.restart_workers()
                    # and then reload the configuration
                    saq.load_configuration()
                
                # if this event is set then we need to exit now
                if self.immediate_event.wait(0.5):
                    break
        
                if self.control_event.wait(0.5):
                    break

            # if we're shutting down then go ahead and tell the workers to shut down
            self.worker_manager.wait()
            self.stop_maintenance_threads()

        except KeyboardInterrupt:
            logging.warning("caught user interrupt in engine_loop")

        logging.debug("ended engine loop")

    #
    # PROCESS MANAGEMENT
    # ------------------------------------------------------------------------


    #
    # ANALYSIS
    # ------------------------------------------------------------------------

    def add_workload(self, root):
        """See saq.database.add_workload."""
        assert isinstance(root, RootAnalysis)
        return saq.database.add_workload(root, exclusive_uuid=self.exclusive_uuid)
    
    @use_db
    def transfer_work_target(self, uuid, node_id, db, c):
        """Moves the given work target from the given remote node to the local node.
           Returns the (unloaded) RootAnalysis for the object transfered."""
        from ace_api import download, clear
        logging.info("downloading work target {} from {}".format(uuid, node_id))

        # get a lock on the target we want to transfer
        if not acquire_lock(uuid, self.lock_uuid):
            logging.info("unable to acquire lock on {} for transfer".format(uuid))
            return False

        target_dir = storage_dir_from_uuid(uuid)
        if os.path.isdir(target_dir):
            logging.warning("target_dir {} for transfer exists! deleting".format(target_dir))

            try:
                shutil.rmtree(target_dir)
            except Exception as e:
                logging.error("unable to delete {}: {}".format(target_dir, e))
                report_exception()
                return False

        try:
            logging.debug("creating transfer target_dir {}".format(target_dir))
            os.makedirs(target_dir)
        except Exception as e:
            logging.error("unable to create transfer target_dir {}: {}".format(target_dir, e))
            report_exception()
            return False

        tar_path = None

        try:
            # now make the transfer
            # look up the url for this target node
            c.execute("SELECT location FROM nodes WHERE id = %s", (node_id,))
            row = c.fetchone()
            if row is None:
                logging.error("cannot find node_id {} in nodes table".format(node_id))
                return False

            remote_host = row[0]
            download(uuid, target_dir, remote_host=remote_host)

            # update the node (location) of this workitem to the local node
            execute_with_retry(db, c, "UPDATE workload SET node_id = %s, storage_dir = %s WHERE uuid = %s", (
                               saq.SAQ_NODE_ID, target_dir, uuid))
            execute_with_retry(db, c, "UPDATE delayed_analysis SET node_id = %s, storage_dir = %s WHERE uuid = %s", (
                               saq.SAQ_NODE_ID, target_dir, uuid))
            db.commit()

            # then finally tell the remote system to clear this work item
            # we use our lock uuid as kind of password for clearing the work item
            clear(uuid, self.lock_uuid, remote_host=remote_host)

            return RootAnalysis(uuid=uuid, storage_dir=target_dir)
            
        except Exception as e:
            logging.error("unable to transfer {}: {}".format(uuid, e))
            try:
                shutil.rmtree(target_dir)
            except Exception as e:
                logging.error("unable to clear transfer target_dir {}: {}".format(target_dir, e))
                report_exception()
            
            return None

        finally:
            try:
                if tar_path:
                    os.remove(tar_path)
            except Exception as e:
                logging.error("unable to delete temporary tar file {}: {}".format(tar_path, e))
                report_exception()

    @use_db
    def get_delayed_analysis_work_target(self, db, c):
        """Returns the next DelayedAnalysisRequest that is ready, or None if none are ready."""
        # get the next thing to do
        # first we look for any delayed analysis that needs to complete

        # if the engine that is currently running has the exclusive_uuid set
        # then we ONLY pull work with that exclusive_uuid
        exclusive_clause = 'AND exclusive_uuid IS NULL'
        if self.exclusive_uuid is not None:
            exclusive_clause = 'AND exclusive_uuid = %s'

        sql = """
SELECT 
    delayed_analysis.id, 
    delayed_analysis.uuid, 
    delayed_analysis.observable_uuid, 
    delayed_analysis.analysis_module, 
    delayed_analysis.delayed_until,
    delayed_analysis.storage_dir
FROM
    delayed_analysis LEFT JOIN locks ON delayed_analysis.uuid = locks.uuid
WHERE
    delayed_analysis.node_id = %s
    AND locks.uuid IS NULL
    AND NOW() > delayed_until
    {}
ORDER BY
    delayed_until ASC
""".format(exclusive_clause)

        params = [ saq.SAQ_NODE_ID ]
        if self.exclusive_uuid is not None:
            params.append(self.exclusive_uuid)

        c.execute(sql, tuple(params))

        for _id, uuid, observable_uuid, analysis_module, delayed_until, storage_dir in c:
            if not acquire_lock(uuid, self.lock_uuid, lock_owner=self.lock_owner):
                continue

            return DelayedAnalysisRequest(uuid,
                                          observable_uuid,
                                          analysis_module,
                                          delayed_until,
                                          storage_dir,
                                          database_id=_id)

        return None

    @use_db
    def get_work_target(self, db, c, priority=True, local=True):
        """Returns the next work item available. 
           If priority is True then only work items with analysis_modes that match the analysis_mode_priority
           of this worker are selected.
           If local is True then only work items on the local node are selected.
           Remote work items are moved to become local.
           Returns a valid work item, or None if none are available."""
    
        where_clause = [ 'locks.uuid IS NULL' ]
        params = []

        if self.analysis_mode_priority and priority:
            where_clause.append('workload.analysis_mode = %s')
            params.append(self.analysis_mode_priority)

        if local:
            where_clause.append('workload.node_id = %s')
            params.append(saq.SAQ_NODE_ID)
        else:
            # if we're looking remotely then we need to make sure we only select work for whatever company
            # this node belongs to
            # this is true for instances where you're sharing an ACE resource between multiple companies
            where_clause.append('workload.company_id = %s')
            params.append(saq.COMPANY_ID)

        if self.local_analysis_modes:
            # limit our scope to locally support analysis modes
            where_clause.append('workload.analysis_mode IN ( {} )'.format(','.join(['%s' for _ in self.local_analysis_modes])))
            params.extend(self.local_analysis_modes)

        if self.exclusive_uuid is not None:
            where_clause.append('workload.exclusive_uuid = %s')
            params.append(self.exclusive_uuid)
        else:
            where_clause.append('workload.exclusive_uuid IS NULL')

        where_clause = ' AND '.join(['({})'.format(clause) for clause in where_clause])

        logging.debug("looking for work with {} ({})".format(where_clause, ','.join([str(_) for _ in params])))

        c.execute("""
SELECT
    workload.id,
    workload.uuid,
    workload.analysis_mode,
    workload.insert_date,
    workload.node_id,
    workload.storage_dir
FROM
    workload LEFT JOIN locks ON workload.uuid = locks.uuid
WHERE
    {where_clause}
ORDER BY
    id ASC
LIMIT 16""".format(where_clause=where_clause), tuple(params))

        for _id, uuid, analysis_mode, insert_date, node_id, storage_dir in c:
            if not acquire_lock(uuid, self.lock_uuid, lock_owner=self.lock_owner):
                continue

            # is this work item on a different node?
            if node_id != saq.SAQ_NODE_ID:
                # go grab it
                return self.transfer_work_target(uuid, node_id)

            return RootAnalysis(uuid=uuid, storage_dir=storage_dir)

        return None

    def get_next_work_target(self):
        try:
            # get any delayed analysis work that is ready to be processed
            target = self.get_delayed_analysis_work_target()
            if target:
                return target

            if self.analysis_mode_priority:
                # get any local work with high priority
                target = self.get_work_target(priority=True, local=True)
                if target:
                    return target

                # get any work with high priority
                target = self.get_work_target(priority=True, local=False)
                if target:
                    return target

            # get any available local work
            target = self.get_work_target(priority=False, local=True)
            if target:
                return target

            # get any available work
            target = self.get_work_target(priority=False, local=False)
            if target:
                return target

        except Exception as e:
            logging.error("unable to get work target: {}".format(e))
            report_exception()

        # no work available anywhere
        return None

    @use_db
    def clear_work_target(self, target, db, c):
        if isinstance(target, DelayedAnalysisRequest):
            execute_with_retry(db, c, "DELETE FROM delayed_analysis WHERE id = %s", (target.database_id,))
        else:
            execute_with_retry(db, c, "DELETE FROM workload WHERE uuid = %s", (target.uuid,))

        execute_with_retry(db, c, "DELETE FROM locks where uuid = %s", (target.uuid,))
        db.commit()
        logging.debug("cleared work target {}".format(target))

    def setup(self, mode):
        """Called to setup the engine for execution. Typically this is called on the worker
           process just before the execution loop begins."""

        enable_cached_db_connections()

        # this determines what kind of work we look for first
        self.analysis_mode_priority = mode

        # set up our lock
        self.lock_uuid = str(uuid.uuid4())
        self.lock_owner = '{}-{}-{}'.format(saq.SAQ_NODE, mode, os.getpid())

        try:
            self.initialize_modules()
        except Exception as e:
            logging.error("unable to initialize modules: {} (worker exiting)".format(e))
            report_exception()
            return

        self.initialize_signal_handlers()
        
    def execute(self):

        # get the next thing to work on
        work_item = self.get_next_work_target()
        if work_item is None:
            return False

        logging.debug("got work item {}".format(work_item))

        # at this point the thing to work on is locked (using the locks database table)
        # start a secondary thread that just keeps the lock open
        self.start_root_lock_manager(work_item.uuid)

        try:
            self.process_work_item(work_item)
        except Exception as e:
            logging.error("error processing work item {}: {}".format(work_item, e))
            report_exception()

        # at this point self.root is set and loaded
        # remember what the analysis mode was before we started analysis
        current_analysis_mode = self.root.analysis_mode
        logging.debug("analyzing {} in analysis_mode {}".format(self.root, self.root.analysis_mode))

        try:
            self.analyze(work_item)
        except Exception as e:
            logging.error("error analyzing {}: {}".format(work_item, e))
            report_exception()

        self.stop_root_lock_manager()

        try:
            self.clear_work_target(work_item)
        except Exception as e:
            logging.error("unable to clear work item {}: {}".format(work_item, e))
            report_exception()

        # did the analysis mode change?
        # NOTE that we do this AFTER locks are released
        if self.root.analysis_mode != current_analysis_mode:
            logging.info("analysis mode for {} changed from {} to {}".format(
                          self.root, current_analysis_mode, self.root.analysis_mode))

            try:
                add_workload(self.root, exclusive_uuid=self.exclusive_uuid)
            except Exception as e:
                logging.error("unable to add {} to workload: {}".format(self.root, e))
                report_exception()

        # if the analysis mode did NOT change
        # then we look to see if we should clean this up
        else:
            # is this analysis_mode one that we want to clean up?
            if self.root.analysis_mode is not None \
            and 'analysis_mode_{}'.format(self.root.analysis_mode) in saq.CONFIG \
            and saq.CONFIG['analysis_mode_{}'.format(self.root.analysis_mode)].getboolean('cleanup'):
                # OK then is there any outstanding work assigned to this uuid?
                try:
                    with get_db_connection() as db:
                        c = db.cursor()
                        c.execute("""SELECT uuid FROM workload WHERE uuid = %s
                                     UNION SELECT uuid FROM delayed_analysis WHERE uuid = %s
                                     UNION SELECT uuid FROM locks WHERE uuid = %s
                                     LIMIT 1
                                     """, (self.root.uuid, self.root.uuid, self.root.uuid))

                        row = c.fetchone()
                        db.commit()

                        if row is None:
                            # OK then it's time to clean this one up
                            logging.debug("clearing {}".format(self.root.storage_dir))
                            try:
                                shutil.rmtree(self.root.storage_dir)
                            except Exception as e:
                                logging.error("unable to clear {}: {}".format(self.root.storage_dir))
                        else:
                            logging.debug("not cleaning up {} (found outstanding work))".format(self.root))

                except Exception as e:
                    logging.error("trouble checking finished status of {}: {}".format(self.root, e))
                    report_exception()
    
    def process_work_item(self, work_item):
        """Processes the work item."""
        assert isinstance(work_item, DelayedAnalysisRequest) or isinstance(work_item, RootAnalysis)

        self.delayed_analysis_request = None
        self.root = None

        # both RootAnalysis and DelayedAnalysisRequest define storage_dir
        if not os.path.isdir(work_item.storage_dir):
            logging.warning("storage directory {} missing - already processed?".format(work_item.storage_dir))
            return

        if isinstance(work_item, DelayedAnalysisRequest):
            self.delayed_analysis_request = work_item
            self.delayed_analysis_request.load()
            self.root = self.delayed_analysis_request.root

            # reset the delay flag for this analysis
            self.delayed_analysis_request.analysis.delayed = False

        elif isinstance(work_item, RootAnalysis):
            self.root = work_item
            self.root.load()

        logging.info("processing {}".format(self.root.description))

    def analyze(self, target):
        assert isinstance(target, saq.analysis.RootAnalysis) or isinstance(target, DelayedAnalysisRequest)

        # reset state flags
        self._cancel_analysis_flag = False
    
        # reset total analysis measurements
        self.total_analysis_time.clear()

        # reset each module to it's default state
        for analysis_module in self.analysis_modules:
            analysis_module.reset()

        # tell all the analysis modules what alert they'll be processing
        for analysis_module in self.analysis_modules:
            analysis_module.root = self.root

        # track module pre-analysis execution
        if STATE_PRE_ANALYSIS_EXECUTED not in self.root.state:
            self.root.state[STATE_PRE_ANALYSIS_EXECUTED] = {} # key = analysis_module.config_section
                                                              # value = boolean result of function call

        # when something goes wrong it helps to have the logs specific to this analysis
        logging_handler = logging.FileHandler(os.path.join(self.root.storage_dir, 'saq.log'))
        logging_handler.setLevel(logging.getLogger().level)
        logging_handler.setFormatter(logging.getLogger().handlers[0].formatter)
        logging.getLogger().addHandler(logging_handler)

        # remember what mode we were in when we started
        initial_mode = self.root.analysis_mode

        elapsed_time = None
        error_report_path = None
        try:
            start_time = time.time()

            # don't even start if we're already cancelled
            if not self.cancel_analysis_flag:
                self.execute_module_analysis()

            # do we NOT have any outstanding delayed analysis requests?
            if not self.root.delayed:
                for analysis_module in self.get_analysis_modules_by_mode(initial_mode):
                    try:
                        # give the modules an opportunity to do something after all analysis has completed
                        # NOTE that this does NOT allow adding any new observables or analysis
                        analysis_module.execute_post_analysis()
                    except Exception as e:
                        logging.error("post analysis module {} failed".format(analysis_module))
                        report_exception()

            elapsed_time = time.time() - start_time
            logging.info("completed analysis {} in {:.2f} seconds".format(target, elapsed_time))

            # save all the changes we've made
            self.root.save() 

        except Exception as e:
            elapsed_time = time.time() - start_time
            logging.error("anaysis failed on {}: {}".format(self.root, e))
            error_report_path = report_exception()

            try:
                # just try to save what we've got thus far
                self.root.save()
            except Exception as e:
                logging.error("unable to save failed analysis {}: {}".format(self.root, e))

        finally:
            # make sure we remove the logging handler that we added
            logging.getLogger().removeHandler(logging_handler)

            # turn off the root lock manager
            self.stop_root_lock_manager()

            # stop any outstanding threaded modules
            for analysis_module in self.get_analysis_modules_by_mode(initial_mode):
                analysis_module.stop_threaded_execution()

            for t in threading.enumerate():
                logging.debug("ACTIVE THREAD: {}".format(t))

        # give the modules a chance to cleanup
        for analysis_module in self.analysis_modules:
            try:
                analysis_module.cleanup()
            except Exception as e:
                logging.error("unable to clean up analysis module {}: {}".format(analysis_module, e))
                report_exception()

        # if analysis failed, copy all the details to error_reports for review
        if self.copy_analysis_on_error:
            error_report_stats_dir = None
            if error_report_path and os.path.isdir(self.root.storage_dir):
                analysis_dir = '{}.ace'.format(error_report_path)
                try:
                    shutil.copytree(self.root.storage_dir, analysis_dir)
                    logging.info("copied analysis from {} to {} for review".format(self.root.storage_dir, analysis_dir))
                except Exception as e:
                    logging.error("unable to copy from {} to {}: {}".format(self.root.storage_dir, analysis_dir, e))

                try:
                    error_report_stats_dir = os.path.join(analysis_dir, 'stats')
                    os.mkdir(error_report_stats_dir)
                except Exception as e:
                    logging.error("unable to create error reporting stats dir {}: {}".format(error_report_stats_dir, e))

        # save module execution time metrics
        try:
            # how long did all the analysis take combined?
            _total = 0.0
            for key in self.total_analysis_time.keys():
                _total += self.total_analysis_time[key]

            for key in self.total_analysis_time.keys():
                subdir_name = os.path.join(self.stats_dir, datetime.datetime.now().strftime('%Y%m%d'))
                if not os.path.isdir(subdir_name):
                    try:
                        os.mkdir(subdir_name)
                    except Exception as e:
                        logging.error("unable to create new stats subdir {}: {}".format(subdir_name, e))
                        continue

                percentage = '?'
                if elapsed_time:
                    percentage = '{0:.2f}%'.format((self.total_analysis_time[key] / elapsed_time) * 100.0)
                if not elapsed_time:
                    elapsed_time = 0

                output_line = '{} ({}) [{:.2f}:{:.2f}] - {}\n'.format(
                              datetime.timedelta(seconds=self.total_analysis_time[key]),
                              percentage,
                              _total,
                              elapsed_time,
                              self.root.uuid)

                with open(os.path.join(subdir_name, '{}.stats'.format(key)), 'a') as fp:
                    fp.write(output_line)

                #if error_report_stats_dir:
                    #with open(os.path.join(error_report_stats_dir, '{}.stats'.format(key)), 'a') as fp:
                        #fp.write(output_line)

        except Exception as e:
            logging.error("unable to record statistics: {}".format(e))


        return

    def get_analysis_modules_by_mode(self, analysis_mode):
        """Returns the list of analysis modules configured for the given mode sorted alphabetically by configuration section name."""
        if analysis_mode is None:
            result = self.analysis_mode_mapping[self.default_analysis_mode]
        else:
            try:
                result = self.analysis_mode_mapping[analysis_mode]
            except KeyError:
                if analysis_mode not in self.invalid_analysis_modes_detected:
                    logging.warning("invalid analysis mode {} - defaulting to {}".format(
                                    analysis_mode, self.default_analysis_mode))
                    self.invalid_analysis_modes_detected.add(analysis_mode)
                result = self.analysis_mode_mapping[self.default_analysis_mode]

        return sorted(result, key=lambda x: x.config_section)

    # ------------------------------------------------------------------------
    # This is the main processing loop of analysis in ACE.
    #

    def execute_module_analysis(self):
        """Implements the recursive analysis logic of ACE."""

        # first we execute any pre-analysis routines that are loaded for the current analysis mode
        # this may end up introducing more observables so we do this before we initialize our work stack
        if self.delayed_analysis_request is None: # don't need to bother if we're working on a delayed analysis req
            target_analysis_mode = self.root.analysis_mode 
            if target_analysis_mode is None or target_analysis_mode not in self.analysis_mode_mapping:
                target_analysis_mode = self.default_analysis_mode

            state = self.root.state[STATE_PRE_ANALYSIS_EXECUTED]
            for analysis_module in self.analysis_mode_mapping[target_analysis_mode]:
                if analysis_module.config_section not in state:
                    try:
                        state[analysis_module.config_section] = bool(analysis_module.execute_pre_analysis())
                    except Exception as e:
                        logging.error("pre analysis module {} failed".format(analysis_module))
                        report_exception()
                        state[analysis_module.config_section] = False

                if self.cancel_analysis_flag:
                    logging.debug("analysis for {} cancelled during pre-analysis".format(self.root))
                    return

        # next we start threads for any configured threaded analysis modules available for the analysis
        # mode of the current target
        for analysis_module in self.get_analysis_modules_by_mode(self.root.analysis_mode):
            analysis_module.start_threaded_execution()

        class WorkTarget(object):
            """Utility class the defines what exactly we're working on at the moment."""
            def __init__(self, observable=None, analysis=None, analysis_module=None, dependency=None):
                self.observable = observable            # the observable to analyze
                self.analysis = analysis                # the analysis to analyze (not actually supported)
                self.analysis_module = analysis_module  # the analysis module to use (or all of them if not set)
                self.dependency = dependency            # the dependency we're trying to resolve

            def __str__(self):
                return "WorkTarget(obs:{},analyis:{},module:{},dep:{})".format(self.observable, self.analysis, self.analysis_module, self.dependency)

            def __repr__(self):
                return self.__str__()

        class WorkStack(object):
            def __init__(self):
                self.tracker = set() # observable uuids
                self.work = collections.deque() # of WorkTarget objects

            def appendleft(self, item):
                assert isinstance(item, WorkTarget)
                self.work.appendleft(item)

            def append(self, item):
                # are we already tracking this in the work stack?
                if isinstance(item, Observable):
                    if item.id in self.tracker:
                        return

                logging.debug("adding work stack item {}".format(item))
                if isinstance(item, WorkTarget):
                    self.work.append(item)
                elif isinstance(item, Observable):
                    self.work.append(WorkTarget(observable=item))
                    self.tracker.add(item.id)
                elif isinstance(item, Analysis):
                    pass
                else:
                    raise RuntimeError("invalid work item type {} ({})".format(type(item), item))

            def popleft(self):
                result = self.work.popleft()
                if result.observable:
                    try:
                        self.tracker.remove(result.observable.id)
                    except KeyError:
                        pass # will throw this when analyzing delayed analysis

                return result

            def __len__(self):
                return len(self.work)

        # our list of things to analyze (of type WorkTarget)
        work_stack = WorkStack()

        # temporary work stack buffer
        work_stack_buffer = []

        # initialize the work stack

        # if this was a delayed analysis request then we want to start with a specific observable and analysis module
        if self.delayed_analysis_request is not None:
            logging.debug("processing delayed analysis request {}".format(self.delayed_analysis_request))
            work_stack.append(WorkTarget(observable=self.delayed_analysis_request.observable,
                                         analysis_module=self.delayed_analysis_request.analysis_module))

            # find the analysis module that needs to analyze this observable
            #for analysis_module in self.analysis_modules:
                #if analysis_module.config_section == self.delayed_analysis_request.analysis_module:
                    #work_stack.append(WorkTarget(
                                      #observable=self.root.get_observable(self.delayed_analysis_request.observable_uuid), 
                                      #analysis_module=analysis_module))
                    #break

            # we should have found 1 exactly
            if len(work_stack) != 1:
                raise RuntimeError("delayed analysis request {} references missing analysis module".format(
                                    self.delayed_analysis_request))
        else:
            # otherwise we analyze everything
            for analysis in self.root.all_analysis:
                work_stack.append(analysis)

            for observable in self.root.all_observables:
                work_stack.append(observable)

            #work_stack.extend([WorkTarget(analysis=a) for a in self.root.all_analysis])
            #work_stack.extend([WorkTarget(observable=o) for o in self.root.all_observables])

        def _workflow_callback(target, event, *args, **kwargs):
            if isinstance(target, Analysis) or isinstance(target, Observable):
                logging.debug("WORKFLOW: detected change to {} with event {}".format(target, event))
                work_stack_buffer.append(target)

        def _register_analysis_event_listeners(analysis):
            analysis.add_event_listener(EVENT_OBSERVABLE_ADDED, _observable_added_callback)
            analysis.add_event_listener(EVENT_OBSERVABLE_ADDED, _workflow_callback)
            analysis.add_event_listener(EVENT_TAG_ADDED, _workflow_callback)
            analysis.add_event_listener(EVENT_DETAILS_UPDATED, _workflow_callback)
            analysis.add_event_listener(EVENT_ANALYSIS_MARKED_COMPLETED, _workflow_callback)

        def _register_observable_event_listeners(observable):
            observable.add_event_listener(EVENT_ANALYSIS_ADDED, _analysis_added_callback)
            observable.add_event_listener(EVENT_ANALYSIS_ADDED, _workflow_callback)
            observable.add_event_listener(EVENT_TAG_ADDED, _workflow_callback)
            observable.add_event_listener(EVENT_DIRECTIVE_ADDED, _workflow_callback)
            observable.add_event_listener(EVENT_RELATIONSHIP_ADDED, _workflow_callback)

        # when we add new Observable and Analysis objects we need to track those as well
        def _observable_added_callback(analysis, event, observable):
            #logging.debug("WORKFLOW: detected new observable {} added to {}".format(observable, analysis))
            _register_observable_event_listeners(observable)
            work_stack_buffer.append(observable)

        def _analysis_added_callback(observable, event, analysis):
            #logging.debug("WORKFLOW: detected new analysis {} for observable {}".format(analysis, observable))
            _register_analysis_event_listeners(analysis)
            work_stack_buffer.append(analysis)

        # initialize event listeners for the objects we already have
        #self.root.clear_event_listeners()
        _register_analysis_event_listeners(self.root)

        for analysis in self.root.all_analysis:
            #analysis.clear_event_listeners()
            _register_analysis_event_listeners(analysis)

        for observable in self.root.all_observables:
            #observable.clear_event_listeners()
            _register_observable_event_listeners(observable)

        # we use this when we're dealing with delayed analysis
        first_pass = True

        # we use this when we're executing in final analysis mode
        # in this mode we've executed all analysis until there's no more work left
        # then we iterate through all the analysis modules executing the execute_final_analysis function
        # this gives modules the ability to delay their analysis until everything else is done
        final_analysis_mode = False

        # when we started analyzing this
        start_time = datetime.datetime.now()
        # the last time we logged a warning about analysis taking too long
        last_analyze_time_warning = None
    
        # MAIN LOOP
        # keep going until there is nothing to analyze
        while not self.cancel_analysis_flag:
            # the current WorkTarget
            work_item = None

            # how long have we been analyzing?
            elapsed_time = (datetime.datetime.now() - start_time).total_seconds()
            if elapsed_time >= self.maximum_cumulative_analysis_warning_time:
                if ( last_analyze_time_warning is None or 
                     (datetime.datetime.now() - last_analyze_time_warning).total_seconds() > 60 ):
                    last_analyze_time_warning = datetime.datetime.now()
                    logging.warning("ACE has been analyzing {} for {} seconds".format(self.root, elapsed_time))

            if elapsed_time >= self.maximum_cumulative_analysis_fail_time:
                raise AnalysisTimeoutError("ACE took too long to analyze {}".format(self.root))

            # are we done?
            logging.debug("work stack size {} active dependencies {}".format(len(work_stack), len(self.root.active_dependencies)))
            if len(work_stack) == 0 and len(self.root.active_dependencies) == 0:
            #if len(work_stack) == 0:
                # are we in final analysis mode?
                if final_analysis_mode:
                    # then we are truly done
                    break

                # should we enter into final analysis mode?
                # we only do this if A) all analysis is complete and B) there is no outstanding delayed analysis
                if not self.root.delayed:
                    logging.info("entering final analysis for {}".format(self.root))
                    final_analysis_mode = True
                    # place everything back on the stack
                    for obj in self.root.all:
                        work_stack.append(obj)

                    continue

                else:
                    logging.info("not entering final analysis mode for {} (delayed analysis waiting)".format(self.root))
                    break

            # get the next thing to analyze
            # if we have delayed analysis then that is the thing to analyze at this moment
            if self.delayed_analysis_request and first_pass:
                logging.debug("processing delayed analysis request {}".format(self.delayed_analysis_request))
                work_item = work_stack.popleft() # should be the only thing on the stack
                assert len(work_stack) == 0
                first_pass = False # XXX don't think I need this flag anymore
                
            # otherwise check to see if we have any dependencies waiting
            elif self.root.active_dependencies:
                logging.debug("{} active dependencies to process".format(len(self.root.active_dependencies)))
                for index, dep in enumerate(self.root.active_dependencies):
                    logging.debug("LIST: ({}) {}".format(index, dep))
                # get the next dependency that is not waiting on an analysis module that is delayed
                for dep in self.root.active_dependencies: # these are returned in the correct order
                    # do we need to execute the dependency anaylysis?
                    if dep.ready:
                        logging.debug("analyzing ready dependency {}".format(dep))
                        # has this already been completed?
                        # this could happen if the target analysis was performed after the request to wait in the
                        # loop that iterates over the analysis modules
                        existing_analysis = dep.target_observable.get_analysis(dep.target_analysis_type)
                        if existing_analysis is False or existing_analysis is not None:
                            logging.debug("already analyzed obs {} target {}".format(dep.target_observable, dep.target_analysis_type))
                            dep.increment_status()
                        else:
                            target_analysis_module = self._get_analysis_module_by_generated_analysis(dep.target_analysis_type)
                            if target_analysis_module is None:
                                raise RuntimeError("cannot find target analysis for {}".format(dep))

                            work_item = WorkTarget(observable=dep.target_observable, 
                                                   analysis_module=target_analysis_module,
                                                   dependency=dep)
                            break

                    logging.debug("detected completed active dependency {}".format(dep))
                    # re-analyze the original source observable that requested the dependency
                    source_analysis_module = self._get_analysis_module_by_generated_analysis(dep.source_analysis_type)
                    if source_analysis_module is None:
                        raise RuntimeError("cannot find source analysis module for {}".format(dep))

                    work_item = WorkTarget(observable=dep.source_observable, 
                                           analysis_module=source_analysis_module,
                                           dependency=dep)

                    break

            # otherwise just get the next item off the stack
            if work_item is None:
                work_item = work_stack.popleft()

                # is this work item waiting on a dependency?
                if work_item.observable:
                    # get the list of all non-resolved deps
                    # deps that are new or completed will already be executed at this point
                    # so what we're really looking for here are deps that are waiting for delayed analysis
                    if [d for d in work_item.observable.dependencies if not d.resolved and not d.failed]:
                        logging.debug("{} has outstanding dependencies: {}".format(
                                      work_item, ','.join(map(str, [d for d in work_item.observable.dependencies if not d.resolved]))))
                        continue

            # check for global observable exclusions
            if work_item.observable:
                # has this thing been whitelisted?
                if work_item.observable.whitelisted:
                    logging.debug("{} was whitelisted -- not analyzing".format(work_item.observable))
                    if work_item.dependency:
                        work_item.dependency.set_status_failed('whitelisted')
                        work_item.dependency.increment_status()

                    continue

                # is this observable excluded?
                excluded = False
                if work_item.observable.type in self.observable_exclusions:

                    # XXX this is where you'd want specific types for observables with overloaded ==
                    # so special case for ipv4 so you can allow cidr
                    exclusions = self.observable_exclusions[work_item.observable.type]
                    if work_item.observable.type == F_IPV4:
                        exclusions = [iptools.IpRange(x) for x in exclusions]
                    for exclusion in exclusions:
                        try:
                            if work_item.observable.value in exclusion:
                                excluded = True
                                break
                        except Exception as e:
                            logging.debug("{} probably is not an IP address".format(work_item.observable.value))
                            #report_exception()

                if excluded:
                    logging.debug("ignoring globally excluded observable {}".format(work_item.observable))
                    if work_item.dependency:
                        work_item.dependency.set_status_failed('globally excluded observable')
                        work_item.dependency.increment_status()

                    continue

                # check for the DIRECTIVE_EXCLUDE_ALL directive
                if work_item.observable.has_directive(DIRECTIVE_EXCLUDE_ALL):
                    logging.debug("ignoring observable {} with directive {}".format(work_item.observable, DIRECTIVE_EXCLUDE_ALL))
                    if work_item.dependency:
                        work_item.dependency.set_status_failed('directive {}'.format(DIRECTIVE_EXCLUDE_ALL))
                        work_item.dependency.increment_status()
                    continue

            # select the analysis modules we want to use
            # first we limit ourselves to whatever analysis modules are available for the current analysis mode
            #logging.debug("analyzing {} in mode {}".format(self.root, self.root.analysis_mode))
            # if we didn't specify an analysis mode then we just use the default
            analysis_modules = self.get_analysis_modules_by_mode(self.root.analysis_mode)
                
            # an Observable can specify a limited set of analysis modules to run
            # by using the limit_analysis() function
            # (this is ignored if there is a dependency - we'll use that instead)
            if work_item.dependency is None and work_item.observable and work_item.observable.limited_analysis:
                analysis_modules = []
                for target_module in work_item.observable.limited_analysis:
                    target_module_section = 'analysis_module_{}'.format(target_module)
                    if target_module_section not in self.analysis_module_mapping:
                        logging.error("{} specified unknown limited analysis {}".format(work_item, target_module))
                    else:
                        analysis_modules.append(self.analysis_module_mapping[target_module_section])

                logging.debug("analysis for {} limited to {} modules ({})".format(
                              work_item.observable, len(analysis_modules), ','.join(work_item.observable.limited_analysis)))

            # if the work_item includes a dependency then the analysis_module property will already be set
            elif work_item.analysis_module:
                logging.debug("analysis for {} limited to {}".format(work_item, work_item.analysis_module))
                analysis_modules = [work_item.analysis_module]

            # analyze this thing with the analysis modules we've selected
            for analysis_module in analysis_modules:

                if self.cancel_analysis_flag:
                    break

                # if this module does not generate analysis then we skip this part
                # (it may execute pre and post analysis though)
                if analysis_module.generated_analysis_type is None:
                    continue

                if work_item.observable:
                    # does this module accept this observable type?
                    if not analysis_module.accepts(work_item.observable):
                        if work_item.dependency:
                            work_item.dependency.set_status_failed('unaccepted for analysis')
                            work_item.dependency.increment_status()
                        continue

                    # XXX not sure we need to make this check here
                    # XXX previous logic should have filtered these out
                    # are we NOT working on a delayed analysis request?
                    # have we delayed analysis here?
                    if analysis_module.generated_analysis_type is not None:
                        target_analysis = work_item.observable.get_analysis(analysis_module.generated_analysis_type)
                        if target_analysis and target_analysis.delayed:
                            logging.debug("analysis for {} by {} has been delayed".format(work_item, analysis_module))
                            continue

                #logging.debug("analyzing {} with {}".format(work_item, analysis_module))
                last_work_stack_size = len(work_stack)

                try:
                    # final_analysis_mode will be True if this is the last pass of analysis
                    if work_item.observable:
                        logging.debug("analyzing {} with {} (final analysis={})".format(
                                       work_item.observable, analysis_module, final_analysis_mode))

                        def _monitor(monitor_event, monitor_module, monitor_target):
                            monitor_start_time = datetime.datetime.now()
                            monitor_event.wait(timeout=self.maximum_analysis_time)
                            monitor_elapsed_time = (datetime.datetime.now() - monitor_start_time).total_seconds()
                            if monitor_elapsed_time > self.maximum_analysis_time:
                                while True:
                                    logging.warning("excessive time - analysis module {} has been analyzing {} for {} seconds".format(
                                                     monitor_module, monitor_target, monitor_elapsed_time))

                                    # repeat warning every 10 seconds until we bail
                                    # TODO possibly kill the analysis somehow
                                    if monitor_event.wait(timeout=10):
                                        break

                        # start a side thread that watches how long a single analysis request can take
                        monitor_event = threading.Event()
                        monitor_thread = threading.Thread(target=_monitor, args=(monitor_event, 
                                                                                 analysis_module, 
                                                                                 work_item.observable))
                        monitor_thread.daemon = True
                        monitor_thread.start()

                        # we indicate that the analysis module refused to generate analysis (for whatever reason)
                        # by returning False here
                        try:
                            module_start_time = datetime.datetime.now()
                            current_analysis_mode = self.root.analysis_mode
                            analysis_result = analysis_module.analyze(work_item.observable, final_analysis_mode)
                        finally:
                            # make sure we stop the monitor thread
                            monitor_event.set()
                            monitor_thread.join()

                        # this should always return a boolean
                        # but just warn if it doesn't
                        if not isinstance(analysis_result, bool):
                            logging.warning("analysis module {} is not returning a boolean value".format(analysis_module))

                        # did we not generate analysis?
                        if isinstance(analysis_result, bool) and not analysis_result:
                            work_item.observable.add_no_analysis(analysis_module.generated_analysis_type())

                        # analysis that was added (if it was) to the observable is considered complete
                        output_analysis = work_item.observable.get_analysis(analysis_module.generated_analysis_type)
                        if output_analysis:
                            # if it hasn't been delayed
                            if not output_analysis.delayed:
                                logging.debug("analysis {} is completed".format(output_analysis))
                                output_analysis.completed = True

                        # did we just analyze a dependency?
                        if work_item.dependency:
                            # did we analyze the target analysis of a dependency?
                            if work_item.dependency.ready:
                                # if we did not generate any analysis then the dependency has failed 
                                # (which might be OK) -- move on to analyze source target again
                                if not output_analysis:
                                    logging.info("analysis module {} did not generate analysis to resolve dep {}".format(
                                                  analysis_module, work_item.dependency))

                                    work_item.dependency.set_status_failed('analysis not generated')
                                    work_item.dependency.increment_status()
                                    work_stack.appendleft(WorkTarget(observable=self.root.get_observable(work_item.dependency.source_observable_id),
                                                                     analysis_module=self._get_analysis_module_by_generated_analysis(work_item.dependency.source_analysis_type)))

                                # if we do have output analysis and it's not delayed then we move on to analyze
                                # the source target again
                                elif not output_analysis.delayed:
                                    work_item.dependency.increment_status()
                                    logging.debug("dependency status updated {}".format(work_item.dependency))
                                    work_stack.appendleft(WorkTarget(observable=self.root.get_observable(work_item.dependency.source_observable_id),
                                                                     analysis_module=self._get_analysis_module_by_generated_analysis(work_item.dependency.source_analysis_type)))

                                # otherwise (if it's delayed) then we need to wait
                                else:
                                    logging.debug("{} {} waiting on delayed analysis".format(analysis_module, work_item.observable))

                            # if we completed the source analysis of a dependency then we are done
                            elif work_item.dependency.completed:
                                work_item.dependency.increment_status()

                except WaitForAnalysisException as wait_exception:
                    # first off, if we completed the source analysis of a dependency then we are done with that
                    if work_item.dependency and work_item.dependency.completed:
                        work_item.dependency.increment_status()
                    
                    # this analysis depends on the analysis of this other thing first
                    # find that thing in the queue and move it to the top
                    # then perform this analysis (again) right after that
                    logging.debug("analysis of {} by {} depends on obs {} analyzed by {}".format(
                                   work_item, analysis_module, wait_exception.observable, wait_exception.analysis))

                    # make sure the requested analysis module is available
                    if not self._get_analysis_module_by_generated_analysis(wait_exception.analysis):
                        raise RuntimeError("{} requested to wait for disabled (or missing) module {}".format(
                                      analysis_module, wait_exception.analysis))

                    # create the dependency between the two analysis modules
                    work_item.observable.add_dependency(analysis_module.generated_analysis_type,
                                                        wait_exception.observable, wait_exception.analysis)
                    
                except Exception as e:
                    logging.error("analysis module {} failed on {} for {}".format(
                        analysis_module, work_item, self.root))
                    report_exception()

                    if work_item.dependency:
                        work_item.dependency.set_status_failed('error: {}'.format(e))
                        work_item.dependency.increment_status()

                module_end_time = datetime.datetime.now()
            
                # keep track of some module execution time metrics
                if analysis_module.config_section not in self.total_analysis_time:
                    self.total_analysis_time[analysis_module.config_section] = 0

                self.total_analysis_time[analysis_module.config_section] += (module_end_time - module_start_time).total_seconds()

                # when analyze() executes it populates the work_stack_buffer with things that need to be analyzed
                # if the thing that was just analyzed turned out to be whitelisted (tagged with 'whitelisted')
                # then we don't analyze anything that was just added
                if work_item.observable and work_item.observable.whitelisted:
                    logging.debug("{} was whitelisted - ignoring {} items on work stack buffer".format(
                                  work_item, len(work_stack_buffer)))
                    work_stack_buffer.clear()
                else:
                    if work_stack_buffer:
                        #logging.debug("adding {} to the work queue".format(len(work_stack_buffer)))
                        # if an Analysis object was added to the work stack let's go ahead and flush it
                        flushed = set()
                        for item in work_stack_buffer:
                            if isinstance(item, Analysis):
                                if item in flushed:
                                    continue

                                logging.debug("flushing {}".format(item))
                                item.flush()
                                flushed.add(item)

                        for buffer_item in work_stack_buffer:
                            work_stack.append(buffer_item)

                        work_stack_buffer.clear()

                        # if we were in final analysis mode and we added something to the work stack
                        # then we exit final analysis mode so that everything can get a chance to execute again
                        final_analysis_mode = False

        # did analysis complete when there was work left to do?
        if len(work_stack):
            logging.info("work on {} was incomplete".format(self.root))
            self.work_incomplete(self.root)

    def is_module_enabled(self, _type_or_string):
        """Returns True if the given module is enabled. 
           _type_or_string can be an instance of the class type, the string representation of that,
           or the section name of the module in the configuration file.
           The class to query can be either the analysis module itself or the generated analysis.
           Note that this also returns False if you typo the name."""
        
        for module in self.analysis_modules:
            if isinstance(_type_or_string, type):
                if isinstance(module, _type_or_string):
                    return True
                if module.generated_analysis_type == _type_or_string:
                    return True
            elif isinstance(_type_or_string, str):
                if _type_or_string == str(type(module)):
                    return True
                elif _type_or_string == module.config_section:
                    return True
                elif _type_or_string == str(module.generated_analysis_type):
                    return True

        return False

    def sleep(self, seconds):
        """Utility function to sleep for N seconds without blocking shutdown."""
        seconds = float(seconds)
        while not self.shutdown and seconds > 0:
            # we also want to support sleeping for less than a second
            time.sleep(1.0 if seconds > 0 else seconds)
            seconds -= 1.0

class DelayedAnalysisRequest(object):
    """Encapsulates a request for delayed analysis."""
    def __init__(self, uuid, observable_uuid, analysis_module, next_analysis, storage_dir, database_id=None):

        assert isinstance(uuid, str) and uuid
        assert isinstance(observable_uuid, str) and observable_uuid
        assert isinstance(analysis_module, str) and analysis_module
        assert isinstance(storage_dir, str) and storage_dir
        
        self.uuid = uuid
        self.observable_uuid = observable_uuid
        self.analysis_module = analysis_module
        self.next_analysis = next_analysis
        self.database_id = database_id
        self.storage_dir = storage_dir

        self.root = None

    def load(self):
        self.root = RootAnalysis(uuid=self.uuid, storage_dir=self.storage_dir)
        self.root.load()
        
        self.observable = self.root.get_observable(self.observable_uuid)
        self.analysis_module = CURRENT_ENGINE.analysis_module_mapping[self.analysis_module]
        self.analysis = self.observable.get_analysis(self.analysis_module.generated_analysis_type)
    
    def __str__(self):
        return "DelayedAnalysisRequest for {} by {} @ {}".format(
                self.uuid, self.analysis_module, self.next_analysis)

    def __repr__(self):
        return self.__str__()

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
import threading
import time
import uuid

from multiprocessing import Process, Queue, Semaphore, Event, Pipe
from queue import PriorityQueue, Empty, Full
from subprocess import Popen, PIPE

import saq
import saq.analysis
import saq.database

from saq.analysis import Observable, Analysis, RootAnalysis, ProfilePoint, ProfilePointAnalyzer
from saq.constants import *
from saq.database import Alert, get_db_connection, release_cached_db_connection, enable_cached_db_connections
from saq.error import report_exception
from saq.lock import LockableObject, LocalLockableObject, initialize_locking
from saq.modules import AnalysisModule, PostAnalysisModule
from saq.performance import record_metric
from saq.util import human_readable_size

import iptools
import psutil

# the workload database configuration section name
# corresponds to the database_workload config in etc/saq.ini
DB_CONFIG = 'workload'

# global pointer to the engine that is currently running
# only one engine runs per process
CURRENT_ENGINE = None

class AnalysisTimeoutError(RuntimeError):
    pass

def initialize_sql_collection(collection_dir, workload_name):
    if not os.path.isdir(collection_dir):
        try:
            logging.info("creating collection directory {}".format(collection_dir))
            os.makedirs(collection_dir)
        except Exception as e:
            logging.error("unable to create collection dir {}: {}".format(collection_dir, e))
            report_exception()
            raise e

def reset_sql_collection(collection_dir, workload_name):
    if os.path.isdir(collection_dir):
        try:
            logging.info("deleting {}".format(collection_dir))
            shutil.rmtree(collection_dir)
        except Exception as e:
            logging.error("unable to delete {}: {}".format(collection_dir, e))
            report_exception()
            raise e

    with get_db_connection(DB_CONFIG) as db:
        c = db.cursor()
        logging.info("deleting database entries for {}".format(workload_name))
        c.execute("DELETE FROM workload WHERE name = %s", (workload_name,))
        db.commit()

    initialize_sql_collection(collection_dir, workload_name)

def submit_sql_work_item(workload_name, path):
    """Submits the given path to the given sql database."""
    logging.debug("adding {} to sql workload {}".format(path, workload_name))
    try:
        with get_db_connection(DB_CONFIG) as db:
            c = db.cursor()
            c.execute("""INSERT INTO workload ( name, path ) VALUES ( %s, %s )""", (workload_name, path))
            db.commit()
    except Exception as e:
        logging.error("unable to add {} to sql workload {}: {}".format(path, workload_name, e))
        report_exception()
        raise e

def signal_process(p, sig):
    """Sends a single to the specified multiprocessing.Process object logging any errors.  Returns True on success."""
    log_message = "sending signal {} to {}".format(sig, p.pid)
    if sig == signal.SIGKILL:
        logging.warning(log_message)
    else:
        logging.debug(log_message)

    try:
        os.kill(p.pid, sig)
        return True
    except Exception as e:
        logging.error("unable to send signal {} to {}: {}".format(sig, p.pid, e))
        report_exception()

    return False

class WaitForAnalysisException(Exception):
    """Thrown when we need to wait for analysis to occur on something.
       An AnalysisModule can call self.wait_for_analysis(observable, analysis) if it needs analysis performed by a 
       given module on a given observable. That function will throw this exception if analysis has not 
       occured yet, then the Engine will catch that and reorder things to perform that analysis next."""
    def __init__(self, observable, analysis, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.observable = observable
        self.analysis = analysis

class Engine(object):
    """Base engine functionality."""

    #
    # REQUIRED OVERRIDES
    # ------------------------------------------------------------------------

    def collect(self):
        """Used to fill the self.work_queue with things to do."""
        raise NotImplementedError()

    def process(self, work_item):
        """Used to analyze the work items collected by the collect() routine."""
        raise NotImplementedError()

    def post_analysis(self, analysis):
        """Called after analysis has been performed."""
        raise NotImplementedError()

    @property
    def name(self):
        """This must be overridden and have a matching engine_ENGINE_NAME section in the configuration file."""
        raise NotImplementedError()

    #
    # OPTIONAL OVERRIDES
    # ------------------------------------------------------------------------
    def initialize_collection(self):
        """Override this routine to provide custom initialization for collection."""
        pass

    def initialize_engine(self):
        """Override this routine to provide custom initialization for engine."""
        pass

    def initialize_delayed_analysis(self):
        """Override this routine to provide custom initialization for engine."""
        pass

    def cleanup_delayed_analysis(self):
        """Override thsi routine to provide custom shutdown for delayed analysis."""
        pass

    def work_incomplete(self, analysis):
        """Called when analysis finished prematurely."""
        pass

    def root_analysis_completed(self, root):
        """Called when the given RootAnalysis object has fully completed analysis."""
        pass

    def get_tracking_information(self, root):
        """Called by an analysis module to obtain tracking information for this analysis.
           This is typically used to track the original source of a request. For example, the
           cloudphish analysis uses this to track what email a given url was seen in.
           Returns a valid JSON dict. Defaults to an empty dict."""
        return {}

    # 
    # INITIALIZATION
    # ------------------------------------------------------------------------

    def __init__(self):

        global CURRENT_ENGINE
        CURRENT_ENGINE = self

        # the engine configuration
        # this will be the engine_ENGINE_NAME section in the configuration file
        section_name = 'engine_{}'.format(self.name)

        if section_name not in saq.CONFIG:
            logging.critical("missing engine configuration {}".format(section_name))
            # cannot proceed beyond this point
            sys.exit(1)

        self.config = saq.CONFIG[section_name]

        # a work directory where we can find the files to work on
        self.work_dir = os.path.join(saq.SAQ_HOME, 'work', self.name)

        # directory for temporary files
        self.var_dir = os.path.join(saq.SAQ_HOME, 'var', self.name)

        # directory to store incoming work (if neeeded)
        self.collection_dir = os.path.join(saq.SAQ_HOME, 'var', 'incoming', self.name)

        # directory to store statistical runtime information
        self.stats_dir = os.path.join(saq.MODULE_STATS_DIR, self.name)

        # controlled shutdown event - shut down ACE by allowing all existing jobs to complete
        self.control_event = Event()

        # immediate shutdown event - shut down ACE now
        self.immediate_event = Event()

        # the amount of time in between collection attempts
        self.collection_frequency = self.config.getint('collection_frequency')

        # process to collect the things we're going to be analyzing
        self.collection_process = None

        # used to signal that the collection has completed
        self.collection_event = Event()

        # process to manage the analysis processes
        self.engine_process = None

        # communication pipes to sync startup
        self.engine_startup_pipe_p = None
        self.engine_startup_pipe_c = None
        self.collection_startup_pipe_p = None
        self.collection_startup_pipe_c = None

        # maximum number of simultaneous analysis processes
        self.analysis_pool_size = self.config.getint('analysis_pool_size')

        # a single process is started to manage each child process executed to analyze
        self.process_managers = [] # of Process objects

        # used to start and stop the process managers
        self.process_manager_event = Event()

        # every N minutes we act as though we received a SIGHUP
        self.next_auto_refresh_time = None

        # the process spawned by the process manager to actually do the work
        self.child_process = None

        # the time the child process started
        self.child_process_start_time = None

        # zero or more module groups configured for this engine
        self.module_groups = []

        # the modules that will perform the analysis
        self.analysis_modules = []

        # things we do *not* want to analyze
        self.observable_exclusions = {} # key = o_type, value = [] of values

        # this is the queue that is shared between the processes
        # NOTE the size limit of the queue
        # this forces the collector to block until resources are available to process existing work
        self.work_queue = Queue(maxsize=1)

        # holds a list of LockableObject waiting for locks to become available
        self.lock_queue = []

        # shared queue that contains the next job to process
        self.ready_queue = Queue(maxsize=1)
        self.current_ready = None # the current object we want to place on the ready_queue
        self.current_active = None # the current object that is ON the ready_queue (ready to be sent out)
        
        # the last time we sent keep alives for chronos locks
        self.last_lock_update_time = datetime.datetime.now()

        # this thread manages the work, lock and ready queues
        self.queue_manager_thread = None
        self.queue_manager_event = threading.Event()

        # the last time we dump the statistical information
        self.last_statistic_dump = None

        # the frequency (in seconds) that we dump statistics to the log
        self.statistic_dump_frequency = self.config.getint('statistic_dump_frequency')

        # this is set to True to cancel the analysis going on in the process() function
        self._cancel_analysis_flag = False

        # this is set to True after engine process receives the EOQ marker on the work queue
        self.work_queue_ended_flag = False

        # we keep track of the total amount of time (in seconds) that each module takes
        self.total_analysis_time = {} # key = module.config_section, value = total_seconds

        # this gets set to true when we receive a unix signal
        self.sighup_received = False
        self.sigusr1_received = False
        self.sigusr2_received = False

        # auto reload frequency (in seconds)
        # every so often we give the analysis modules a chance to "reload"
        self.auto_reload_frequency = self.config.getint('auto_reload_frequency')
        
        # the last time we checked for module auto-reload
        self.last_auto_reload_check = datetime.datetime.now()

        # delayed analysis processing threads
        self.delayed_analysis_thread = None
        self.delayed_analysis_xfer_thread = None
        self.delayed_analysis_monitor_thread = None

        # queues for submitting delayed analysis requests
        self.delayed_analysis_queue = PriorityQueue()
        self.delayed_analysis_xfer_queue = Queue() # for cross-process transfer

        # this is used to 
        self.delayed_analysis_shutdown_event = threading.Event()
        
        # used to sleep when waiting to process the next delayed analysis request
        self.delayed_analysis_sync_event = threading.Event()

        # used to know when delayed analysis has started running
        self.delayed_analysis_xfer_startup_event = threading.Event()
        self.delayed_analysis_startup_event = threading.Event()

        # the file path used for saving outstanding delayed analysis requests on shutdown
        self.delayed_analysis_path = os.path.join(self.var_dir, 'delayed_analysis')

        # the current delayed analysis request being waited on
        self.current_delayed_analysis_request = None

        # the RootAnalysis object the current process is analyzing
        self.root = None

        # the DelayedAnalysisRequest the Alert came from (or None if it's normal processing)
        self.delayed_analysis_request = None

        # a temporary buffer of all the delayed analysis requests that have been added during the call to analyze
        # after all analysis has completed these will be sent to the delayed analysis manager
        # we do this because we do not want the delayed analysis manager to start analyzing an object
        # we're not finished analyzing yet
        # we do this so that we're not actually required to lock the root object the first time we analyze it
        # this is the case in most detection-based engines
        self.delayed_analysis_buffer = [] # of tuples of (next_analysis_time, DelayedAnalysisRequest)

        # threading to manage keep alives for global locks from chronos
        self.root_lock_manager_event = None
        self.root_lock_keepalive_thread = None

        # the list of ProfilePointAnalyzer objects to run against each analysis
        self.profile_point_analyzers = []

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

    @property
    def auto_refresh_frequency(self):
        """How often do we refresh the process managers (in seconds.)"""
        try:
            return self.config.getint('auto_refresh_frequency')
        except:
            # defaults to 30 minutes if we didnt' specify
            return 60 * 30

    @property
    def enabled(self):
        return self.config.getboolean('enabled')

    @property
    def profile_points_enabled(self):
        """Returns True if profile points are enabled for this engine."""
        return self.config.getboolean('profile_points_enabled')

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

    def initialize(self):
        """Initialization routines executed once as startup."""
        # clear out these directories
        for d in [ self.work_dir ]:
            if os.path.exists(d):
                try:
                    logging.debug("clearing out directory {0}".format(d))
                    shutil.rmtree(d)
                except Exception as e:
                    logging.error("unable to clear out directory {0}: {1}".format(d, str(e)))
                    sys.exit(1)

        # make sure these exist
        for d in [ self.work_dir, self.var_dir, self.collection_dir, self.stats_dir ]:
            try:
                if not os.path.isdir(d):
                    os.makedirs(d)
            except Exception as e:
                logging.error("unable to create directory {}: {}".format(d, e))

        # initialize locking
        initialize_locking()

    def initialize_sighup_handler(self):
        # capture SIGHUP for engines that want to dynamically re-initialize
        def handle_sighup(signum, frame):
            self.sighup_received = True

        def handle_sigusr1(signum, frame):
            self.sigusr1_received = True

        def handle_sigusr2(signum, frame):
            self.sigusr2_received = True

        signal.signal(signal.SIGHUP, handle_sighup)
        signal.signal(signal.SIGUSR1, handle_sigusr1)
        signal.signal(signal.SIGUSR2, handle_sigusr2)

    def initialize_modules(self):
        # load the analysis modules

        # get every section that starts with analysis_module_
        self.analysis_modules = []

        # a module_group define a list of modules to load for a given engine
        # the module_groups config option defines a comma separated list of groups to load
        # each group defines one or more modules to load
        if 'module_groups' in self.config:
            self.module_groups = [x for x in self.config['module_groups'].split(',') if x]

        group_configured_modules = {}
        for group_name in self.module_groups:
            group_section = 'module_group_{}'.format(group_name)
            if group_section not in saq.CONFIG:
                logging.error("invalid module group {} specified for {}".format(group_name, self))
                continue

            for module_name in saq.CONFIG[group_section].keys():
                if module_name in group_configured_modules:
                    logging.debug("replacing config for module {} by module_group {}".format(
                                  module_name, group_section))

                group_configured_modules[module_name] = saq.CONFIG[group_section].getboolean(module_name)
                if group_configured_modules[module_name]:
                    logging.debug("module {} enabled by group config {}".format(module_name, group_name))

        for section in saq.CONFIG.sections():
            if not section.startswith('analysis_module_'):
                continue

            # is this module in the list of disabled modules?
            # these are always disabled regardless
            if section in saq.CONFIG['disabled_modules'] and saq.CONFIG['disabled_modules'].getboolean(section):
                logging.info("{} is disabled".format(section))
                continue

            # is this module disabled globally?
            # modules that are disable globally are not used anywhere
            if not saq.CONFIG.getboolean(section, 'enabled'):
                logging.debug("analysis module {} disabled (globally)".format(section))
                continue

            #logging.info("{} enabled globally".format(section))

            # the module has to be specified in the engine configuration to be used
            if section not in self.config and section not in group_configured_modules:
                logging.debug("analysis module {} is not specified for {}".format(section, self.name))
                continue

            # and it must be enabled
            if ( section in self.config and not self.config.getboolean(section) ) or (
                 section in group_configured_modules and not group_configured_modules[section] ):
                logging.debug("analysis module {} is disabled for {}".format(section, self.name))
                continue

            # we keep track of how much memory this module uses when it starts up
            current_process = psutil.Process()
            starting_rss = current_process.memory_info().rss

            logging.info("loading analysis module from {}".format(section))
            module_name = saq.CONFIG.get(section, 'module')
            try:
                _module = importlib.import_module(module_name)
            except Exception as e:
                logging.error("unable to import module {}".format(module_name, e))
                report_exception()
                continue

            class_name = saq.CONFIG.get(section, 'class')
            try:
                module_class = getattr(_module, class_name)
            except AttributeError as e:
                logging.error("class {} does not exist in module {} in analysis module {}".format(
                              class_name, module_name, section))
                report_exception()
                continue

            try:
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

            # make sure the module generates analysis
            if analysis_module.generated_analysis_type is None:
                logging.critical("analysis module {} returns None for generated_analysis_type".format(analysis_module))
                continue

            # make sure the generated analysis can initialize itself
            check_analysis = analysis_module.generated_analysis_type()
            try:
                check_analysis.initialize_details()
            except NotImplementedError:
                if check_analysis.details is None:
                    logging.critical("analysis module {} generated analysis {} fails to initialize".format(
                                     analysis_module, type(check_analysis)))
                continue


            # we keep a reference to the engine here
            analysis_module.engine = self
            self.analysis_modules.append(analysis_module)

            # how much memory did we end up using here?
            ending_rss = current_process.memory_info().rss

            # we want to warn if the memory usage is very large ( > 10MB)
            if ending_rss - starting_rss > 1024 * 1024 * 10:
                logging.warning("memory usage grew by {} bytes for loading analysis module {}".format(
                                human_readable_size(ending_rss - starting_rss),
                                analysis_module))

        logging.debug("finished loading {} modules".format(len(self.analysis_modules)))

    def initialize_profile_points(self):
        """Initializes all the enabled profile points for this engine if profile points are enabled."""
        if not self.profile_points_enabled:
            return

        self.profile_point_analyzers.clear()

        disabled_profile_points = saq.CONFIG['profile_points']['disabled_profile_points'].split(',')

        for module_name in saq.CONFIG['profile_points']['modules'].split(','):
            logging.debug("loading profile points from module {}".format(module_name))

            module = importlib.import_module(module_name)
            
            for name, obj in inspect.getmembers(module):
                if inspect.isclass(obj):
                    if obj.__module__ == module.__name__:
                        if name in disabled_profile_points:
                            logging.warning("profile point module {} is disabled".format(name))
                            continue

                        logging.info("loading profile point module {} from {}".format(name, module.__name__))

                        try:
                            pp_module = obj()
                            if not isinstance(pp_module, ProfilePointAnalyzer):
                                raise RuntimeError("{} does not extend ProfilePointAnalyzer".format(type(pp_module).__name__))

                            self.profile_point_analyzers.append(pp_module)
                        except Exception as e:
                            logging.error("unable to load profile point module {} from {}: {}".format(
                                          name, module.__name__, e))
                            report_exception()

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

    @property
    def process_manager_shutdown(self):
        """Returns True if the process managers are shutting down."""
        return self.shutdown or self.process_manager_event.is_set()

    @property
    def collection_shutdown(self):
        """Returns True if collection has ended."""
        return self.shutdown or self.collection_event.is_set()

    @property
    def delayed_analysis_shutdown(self):
        """Returns True if delayed analysis has ended."""
        return self.shutdown or self.delayed_analysis_shutdown_event.is_set()

    @property
    def queue_manager_shutdown(self):
        """Used to control queue manager."""
        return self.shutdown or self.queue_manager_event.is_set()

    #
    # CONTROL FUNCTIONS
    # ------------------------------------------------------------------------

    def start(self):
        """Starts the engine.

        In SINGLE_THREADED mode the entire systems runs under a single thread and process and only one job is processed.
        Otherwise various processes will start for the various subsystems."""

        # make sure engine isn't already startef
        if self.started:
            logging.error("engine {} already started".format(self))
            return

        # make sure this engine is actually enabled 
        if not self.enabled:
            logging.error("engine {} is disabled in configuration".format(self))
            sys.exit(1)

        if saq.SINGLE_THREADED:
            self._single_threaded_start()
            return

        self.initialize()
        self.start_collection()
        if not self.start_engine():
            self.stop_collection()
            sys.exit(1)

        # the parent process will re-send SIGHUP and SIGTERM to collector and engine
        def signal_handler(signum, frame):
            if self.collection_process is not None:
                if self.collection_process.is_alive():
                    signal_process(self.collection_process, signum)

            if self.engine_process is not None:
                if self.engine_process.is_alive:
                    signal_process(self.engine_process, signum)

        signal.signal(signal.SIGHUP, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        logging.debug("control PID {}".format(os.getpid()))

        self.started = True

    def _single_threaded_start(self):
        logging.warning("executing in SINGLE_THREADED mode")

        self.initialize()
        self.initialize_modules()
        self.initialize_profile_points()
        self.initialize_engine()
        self._initialize_collection()

        # collect once
        self.collect()

        while True:
            # run queue management and analysis until queues are empty
            while self.work_queue.qsize() or self.ready_queue.qsize() or len(self.lock_queue):
                self.queue_manager_execute()
                self.execute()

            # any delayed analysis required?
            self._debug_delayed_analysis()
            if not self.work_queue.qsize():
                break

    def stop(self):
        """Immediately stop the engine."""
        logging.warning("stopping {} NOW".format(self))
        self.immediate_event.set()

    def controlled_stop(self):
        """Shutdown the engine in a controlled manner allowing existing jobs to complete."""
        logging.info("shutting down {}".format(self))
        if self.control_event.is_set():
            raise RuntimeError("already requested control_event")
        self.control_event.set()

    def wait(self):
        """Assumes no more work will be generated by the collection process.  Waits for the engine to stop."""
        # if we're running in SINGLE_THREADED mode then we didn't use processes at all
        if saq.SINGLE_THREADED:
            return

        try:
            logging.debug("waiting for collection process {0} to complete".format(self.collection_process.pid))
            self.collection_process.join()
        except Exception as e:
            logging.error("unable to join collection process: {0}".format(str(e)))

        try:
            logging.debug("waiting for engine process {0} to complete".format(self.engine_process.pid))
            self.engine_process.join()
        except Exception as e:
            logging.error("unable to join engine process {0}".format(str(e)))

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
    # COLLECTION
    # ------------------------------------------------------------------------

    def start_collection(self):
        self.collection_startup_pipe_p, self.collection_startup_pipe_c = Pipe()
        self.collection_event.clear()
        self.collection_process = Process(target=self.collection_loop, name='{0} Collection'.format(self.name))
        self.collection_process.start()

        # wait for the message from the child that it started up
        try:
            if not self.collection_startup_pipe_p.poll(30):
                raise RuntimeError("collection start timed out")

            started = self.collection_startup_pipe_p.recv()
            assert isinstance(started, bool)

            if not started:
                raise RuntimeError("collection start failed (returned False)")

            logging.info("collection started")
            self.collection_startup_pipe_p.close()
            self.collection_startup_pipe_p = None

        except Exception as e:
            logging.error("collection engine failed to start: {}".format(e))
            return False

        return True

    def stop_collection(self):
        logging.debug("called stop_collection")
        self.collection_event.set()

    def _initialize_collection(self):
        """Called when collection is started and when SIGHUP is received."""
        # custom initialization
        self.initialize_collection()

    def collection_loop(self):

        self.initialize_sighup_handler()

        try:
            self._initialize_collection()
        except Exception as e:
            logging.error("unable to initialize collection: {0}".format(str(e)))
            report_exception()

        # let the parent process know that we've started
        self.collection_startup_pipe_c.send(True)
        self.collection_startup_pipe_c.close()
        self.collection_startup_pipe_c = None

        logging.info("started collection loop on process {0}".format(os.getpid()))
        while not self.collection_shutdown:
            try:
                if self.sighup_received:
                    self.sighup_received = False
                    logging.info("reloading collection configuration")

                    saq.load_configuration()

                    try:
                        self._initialize_collection()
                    except Exception as e:
                        logging.error("unable to initialize collection: {0}".format(str(e)))
                        report_exception()
                    
                try:
                    self.collect()
                except Exception as e:
                    logging.error("uncaught exception: {0}".format(str(e)))
                    report_exception()

                # are we done collecting? (see stop_collection())
                if self.collection_shutdown:
                    logging.debug("detected collection ended flag")
                    break

                self.sleep(self.collection_frequency)

            except KeyboardInterrupt:
                logging.warning("caught user interrupt in collection_loop")
                break

        logging.info("collection loop ended")

    # m:lock
    # ROOT LOCK MANAGER
    # ------------------------------------------------------------------------
    def start_root_lock_manager(self):
        """Starts a thread that executes keep alives messages if the root object is a LockableObject."""
        if not isinstance(self.root, LockableObject):
            logging.debug("{} is not a LockObject (not starting root lock manager)".format(self.root))
            return

        logging.debug("starting lock manager for {}".format(self.root.lock_identifier))

        # we use this event for a controlled shutdown
        self.root_lock_manager_event = threading.Event()

        # start a thread that sends keep alives every N seconds
        self.root_lock_keepalive_thread = threading.Thread(target=self.root_lock_manager_loop,
                                                           name="Lock Manager ({})".format(self.root))
        self.root_lock_keepalive_thread.daemon = True # we want this thread to die if the process dies
        self.root_lock_keepalive_thread.start()
        #record_metric(METRIC_THREAD_COUNT, threading.active_count())

    def stop_root_lock_manager(self):
        """Stops the root lock manager thread."""
        if not isinstance(self.root, LockableObject):
            return

        if self.root_lock_manager_event is None:
            logging.warning("called stop_root_lock_manager() when no lock manager was running")
            return

        logging.debug("stopping {}".format(self.root_lock_keepalive_thread))
        self.root_lock_manager_event.set()
        self.root_lock_keepalive_thread.join()

    def root_lock_manager_loop(self):
        try:
            while not self.root_lock_manager_event.is_set():

                self.root_lock_manager_execute()

                if self.root_lock_manager_event.wait(float(saq.CONFIG['global']['lock_keepalive_frequency'])):
                    break

        except Exception as e:
            logging.error("caught unknown error in {}: {}".format(self.root_lock_keepalive_thread, e))
            report_exception()

    def root_lock_manager_execute(self):
        self.root.refresh_lock()

    # m:delayed
    # DELAYED ANALYSIS 
    # ------------------------------------------------------------------------
    # this gives us a way to keep track of what delayed analysis is outstanding
    # the reason this exists is because the actual delayed analysis processing is multi-threaded multi-process
    # so super difficult to share state without race conditions
    def track_delayed_analysis_start(self, target, observable, analysis_module):
        delayed_dir = os.path.join(target.storage_dir, '.delayed')
        if not os.path.isdir(delayed_dir):
            os.mkdir(delayed_dir)
        
        target_file = os.path.join(delayed_dir, '{}-{}'.format(analysis_module.config_section, observable.id))
        if os.path.exists(target_file):
            logging.warning("delayed analysis tracking file {} already exists".format(target_file))
        else:
            with open(target_file, 'w') as fp:
                pass

            logging.debug("delayed analysis tracking start {}".format(target_file))

    def track_delayed_analysis_stop(self, target, observable, analysis_module):
        delayed_dir = os.path.join(target.storage_dir, '.delayed')
        if not os.path.isdir(delayed_dir):
            logging.warning("missing tracking directory {}".format(delayed_dir))
            return
        
        target_file = os.path.join(delayed_dir, '{}-{}'.format(analysis_module.config_section, observable.id))
        if not os.path.exists(target_file):
            logging.warning("missing delayed analysis tracking file {}".format(target_file))
            return

        os.remove(target_file)
        logging.debug("delayed analysis tracking stop {}".format(target_file))

    def delay_analysis(self, root, observable, analysis, analysis_module, 
                       hours=None, minutes=None, seconds=None,
                       timeout_hours=None, timeout_minutes=None, timeout_seconds=None):
        assert hours or minutes or seconds
        assert isinstance(root, RootAnalysis)
        assert isinstance(observable, Observable)
        assert isinstance(analysis, Analysis)
        assert isinstance(analysis_module, AnalysisModule)

        # have we already delayed analysis?
        if analysis.delayed:
            logging.warning("already delayed analysis for {} by {} in {}".format(
                            observable, analysis_module, root))
            return False

        start_time = None

        # we keep track of when delayed analysis starts for a given observable + analysis module
        # the first request to delay creates an entry in the delayed_analysis_tracking table of the RootAnalysis
        # subsequent requests reference this time to see if it has timed out

        # are we set to time out?
        if timeout_hours or timeout_minutes or timeout_seconds:
            # have we timed out?
            start_time = root.get_delayed_analysis_start_time(observable, analysis_module)
            if start_time is None:
                start_time = datetime.datetime.now()

            timeout = start_time + datetime.timedelta(hours=0 if timeout_hours is None else timeout_hours, 
                                                      minutes=0 if timeout_minutes is None else timeout_minutes,
                                                      seconds=0 if timeout_seconds is None else timeout_seconds)
            if datetime.datetime.now() > timeout:
                logging.error("delayed analysis for {} in {} has timed out".format(observable, analysis_module))
                return False

        if start_time is not None:
            logging.info("delayed analysis for {} in {} has been waiting for {} seconds".format(
                         observable, analysis_module, (datetime.datetime.now() - start_time).total_seconds()))

        # when do we resume analysis?
        next_analysis = datetime.datetime.now() + datetime.timedelta(hours=hours, minutes=minutes, seconds=seconds)

        analysis.delayed = True

        try:
            root.track_delayed_analysis_start(observable, analysis_module)
        except Exception as e:
            logging.error("unable to start tracking delayed analysis: {}".format(e))
            report_exception()

        # add it to the priority queue for processing
        # note that it's a tuple: (timestamp, request)
        self.delayed_analysis_buffer.append((next_analysis.timestamp(), 
                                             DelayedAnalysisRequest(root, 
                                                                    observable.id,
                                                                    analysis_module.config_section,
                                                                    next_analysis)))
        return True

    def _initialize_delayed_analysis(self):
        self.initialize_delayed_analysis()
        self.load_delayed_analysis()

    def _cleanup_delayed_analysis(self):
        self.cleanup_delayed_analysis()

    def start_delayed_analysis(self):
        assert not self.delayed_analysis_thread
        assert not self.delayed_analysis_xfer_thread

        logging.debug("starting delayed analysis")
        
        try:
            self.initialize_delayed_analysis()
        except Exception as e:
            logging.error("failed to initialize delayed analysis: {}".format(e))
            report_exception()

        self.delayed_analysis_shutdown_event.clear()
        self.delayed_analysis_xfer_startup_event.clear()
        self.delayed_analysis_startup_event.clear()

        # we have a separete thread that pulls things out of the xfer queue and puts then into the priority queue
        # since there is no multiprocess priority queue we have to do this
        self.delayed_analysis_xfer_thread = threading.Thread(target=self.delayed_analysis_xfer_loop,
                                                             name="delayed analysis xfer {}".format(self.name))
        self.delayed_analysis_xfer_thread.start()
        #record_metric(METRIC_THREAD_COUNT, threading.active_count())
        logging.debug("waiting for delayed analysis xfer to start...")
        self.delayed_analysis_xfer_startup_event.wait()
        logging.debug("delayed analysis xfer started")

        self.delayed_analysis_thread = threading.Thread(target=self.delayed_analysis_loop, 
                                                        name="delayed analysis {}".format(self.name))
        self.delayed_analysis_thread.start()
        #record_metric(METRIC_THREAD_COUNT, threading.active_count())
        logging.debug("waiting for delayed analysis to start...")
        self.delayed_analysis_startup_event.wait()
        logging.debug("delayed analysis started")


        # this thread only starts once and continues to run for the life of the process
        # we don't to control stop this thread because it's waiting on I/O from a FIFO
        # and I can't figure out how to tell it to stop without doing non-blocking stuff which I don't want to do
        if not self.delayed_analysis_monitor_thread:
            self.delayed_analysis_monitor_thread = threading.Thread(target=self.delayed_analysis_monitor_loop,
                                                                    name="delayed analysis monitor {}".format(self.name))
            self.delayed_analysis_monitor_thread.daemon = True
            self.delayed_analysis_monitor_thread.start()

    def stop_delayed_analysis(self):
        self.delayed_analysis_shutdown_event.set()
        self.delayed_analysis_sync_event.set() # wakes up the sleeping thread
        self.delayed_analysis_xfer_startup_event.set() # ^
        self.delayed_analysis_startup_event.set() # ^
        for t in [self.delayed_analysis_thread, self.delayed_analysis_xfer_thread]:
            if t and t.is_alive():
                logging.debug("waiting for delayed analysis thread {} to stop...".format(t))
                t.join()
                logging.debug("{} stopped".format(t))

        self.delayed_analysis_thread = None
        self.delayed_analysis_xfer_thread = None

        try:
            self._cleanup_delayed_analysis()
        except Exception as e:
            logging.error("delayed analysis cleanup failed: {}".format(e))
            report_exception()

    def delayed_analysis_monitor_loop(self):
        while not self.delayed_analysis_shutdown:
            try:
                self.delayed_analysis_monitor_execute()
            except Exception as e:
                logging.error("unable to monitor {}: {}".format(self.name, e))
                report_exception()
                time.sleep(1)

    def delayed_analysis_monitor_execute(self):
        metrics_fifo_path = os.path.join(saq.SAQ_HOME, 'stats', 'metrics', 'delayed_analysis_queue_{}'.format(self.name))
        if not ( os.path.exists(metrics_fifo_path) and stat.S_ISFIFO(os.stat(metrics_fifo_path).st_mode) ):
            os.mkfifo(metrics_fifo_path)

        try:
            with open(metrics_fifo_path, 'w') as fp:
                fp.write("delayed analysis queue size = {}\n".format(self.delayed_analysis_queue.qsize()))
        # safe to ignore these, just means the reader bailed
        except BrokenPipeError:
            pass

    def delayed_analysis_xfer_loop(self):
        while not self.delayed_analysis_shutdown:
            try:
                self.delayed_analysis_xfer_execute()
                # indicate that we've started if we haven't already
                if not self.delayed_analysis_xfer_startup_event.is_set():
                    self.delayed_analysis_xfer_startup_event.set()
            except Exception as e:
                logging.error("uncaught exception: {}".format(e))
                report_exception()
                time.sleep(1)

        logging.debug("delayed analysis xfer exiting")

    def delayed_analysis_xfer_execute(self):
        try:
            timestamp, request = self.delayed_analysis_xfer_queue.get(block=not saq.SINGLE_THREADED, timeout=0.05)
        except Empty:
            return

        self.delayed_analysis_queue.put_nowait((timestamp, request))
        logging.debug("moved {} with timeout {}".format(request, timestamp))
        self.delayed_analysis_sync_event.set()

    def delayed_analysis_loop(self):
        while not self.delayed_analysis_shutdown:
            try:
                self.delayed_analysis_execute()
                # we're no longer currently working on a request
                self.current_delayed_analysis_request = None 
            except Exception as e:
                logging.error("uncaught exception: {}".format(e))
                report_exception()
                time.sleep(1)

        # make sure this was fired
        self.delayed_analysis_startup_event.set()
        logging.debug("delayed analysis exiting")

    def _process_delayed_analysis_request(self, request):
        # add it to the work queue
        # NOTE that we don't try to lock() here -- the queue manager does that for us
        assert isinstance(request, DelayedAnalysisRequest)
        self.add_work_item(request)

    def delayed_analysis_execute(self):

        # read the next item from the priority queue
        # the priority queue returns the items with the lowest value first
        # we place a tuple of (epoch, DelayedAnalysisRequest) on the queue
        # thus the analysis to run in the future has a higher value than that runs runs now
        try:
            next_time, self.current_delayed_analysis_request = \
            self.delayed_analysis_queue.get(block=not saq.SINGLE_THREADED, timeout=0.05)

            if not self.delayed_analysis_startup_event.is_set():
                self.delayed_analysis_startup_event.set()

            if self.delayed_analysis_queue.qsize():
                logging.debug("delayed analysis queue size {}".format(self.delayed_analysis_queue.qsize()))

        except Empty:
            # exit and return to loop to check shutdown status
            if not self.delayed_analysis_startup_event.is_set():
                self.delayed_analysis_startup_event.set()

            return

        # note that at any time past this queue.get() a new item might have been added
        # so the event object might be set at this point

        logging.debug("processing {} {}".format(next_time, self.current_delayed_analysis_request))

        # is this ready to run now?
        if datetime.datetime.now() >= self.current_delayed_analysis_request.next_analysis:
            logging.debug("{} is ready to process".format(self.current_delayed_analysis_request))
            self._process_delayed_analysis_request(self.current_delayed_analysis_request)
            return

        # if not then we need to sleep until it's ready
        # we use the event to sync
        # when we add something we need to check to see if the new thing is the next thing to run
        # that changes how long we're sleeping for
        timeout = (self.current_delayed_analysis_request.next_analysis - datetime.datetime.now()).total_seconds()
        logging.debug("waiting for {} seconds for next delayed analysis processing".format(timeout))

        # NOTE the first time a delayed analysis request is added, this event will already be set
        # NOTE since we're setting the event each time we add
        # NOTE so we cycle through this twice the first time

        self.delayed_analysis_sync_event.wait(timeout=timeout) 
        self.delayed_analysis_sync_event.clear()

        # we could be shutting down at this point
        if self.delayed_analysis_shutdown:
            # put this back to so we can (possibly) persist it
            self.delayed_analysis_queue.put_nowait((self.current_delayed_analysis_request.next_analysis.timestamp(), 
                                                    self.current_delayed_analysis_request))
            return

        # when we exit this wait, we have either exited due to timeout or event sync
        # so we check (again) to see if we need to run this analysis
        now = datetime.datetime.now()
        if now >= self.current_delayed_analysis_request.next_analysis:
            logging.info("{} is ready to process".format(self.current_delayed_analysis_request))
            self._process_delayed_analysis_request(self.current_delayed_analysis_request)
            #self.add_work_item(request)
            return

        # if this is not true then something was added while we were waiting
        # and it's possible that that new thing needs to run sooner than this
        # so we put this item back on the work queue and try again
        logging.debug("{} is not ready current time {} run time {} - returning to queue".format(
                     self.current_delayed_analysis_request, now, self.current_delayed_analysis_request.next_analysis))
        self.delayed_analysis_queue.put_nowait((self.current_delayed_analysis_request.next_analysis.timestamp(), 
                                                self.current_delayed_analysis_request))

    def _debug_delayed_analysis(self):
        self.initialize_delayed_analysis()
        self.delayed_analysis_xfer_execute()
        self.delayed_analysis_execute()
    #
    # ANALYSIS ENGINE
    # ------------------------------------------------------------------------

    # queue managments
    def start_queue_manager(self):
        logging.debug("starting queue manager")
        self.queue_manager_event.clear()
        self.queue_manager_thread = threading.Thread(target=self.queue_manager_loop, name="{} queue manager".format(
                                                                                          self.name))
        self.queue_manager_thread.start()
        #record_metric(METRIC_THREAD_COUNT, threading.active_count())
        logging.debug("started queue manager")

    def stop_queue_manager(self):
        self.queue_manager_event.set()
        if self.queue_manager_thread:
            if self.queue_manager_thread.is_alive():
                logging.debug("waiting for queue mananger to stop...")
                self.queue_manager_thread.join()
                logging.debug("queue mananger stopped")

        # make sure that the current_ready is unlocked
        if self.current_ready:
            try:
                if isinstance(self.current_ready, LockableObject):
                    self.current_ready.unlock()
            except Exception as e:
                logging.error("unable to unlock {}: {}".format(self.current_ready, e))
                report_exception()

            self.current_ready = None

    def queue_manager_loop(self):

        enable_cached_db_connections()

        while not self.queue_manager_shutdown:
            try:
                self.queue_manager_execute()
            except Exception as e:
                logging.error("uncaught exception: {}".format(e))
                report_exception()
                time.sleep(1)

        release_cached_db_connection()

    def queue_manager_execute(self):
        while True:
            # do we need to send keep alives messages for LockableObjects?
            send_keepalives = False
            if (datetime.datetime.now() - self.last_lock_update_time).total_seconds() > saq.CONFIG['global'].getint('lock_keepalive_frequency'):
                send_keepalives = True
                self.last_lock_update_time = datetime.datetime.now()
            
            if send_keepalives:
                # first we need to manage the keep alive for object that is currently waiting to get picked up
                if self.current_active and isinstance(self.current_active, LockableObject):
                    # is it still there?
                    # this kind of sucks since the documentation says this is unreliable
                    # worst case scenario, we ask for a keep alive on a lock that is released
                    if self.ready_queue.qsize():
                        self.current_active.refresh_lock()
                    
            # are we already trying to add something to the ready queue?
            # if so, that is our only task in this routine
            if self.current_ready is not None:

                if send_keepalives and isinstance(self.current_ready, LockableObject):
                    self.current_ready.refresh_lock()
                
                try:
                    logging.debug("placing {} on ready queue".format(self.current_ready))
                    self.ready_queue.put(self.current_ready, block=not saq.SINGLE_THREADED, timeout=0.05)
                    self.current_active = self.current_ready # keep track of what is currently on the queue
                    self.current_ready = None # clear this up for the next loop iteration
                except Full:
                    # if we are unable to place the item on the queue then it times out after 1 second
                    # and we exit and try again
                    return

            # get the next work item to pass to the ready queue
            # first we look at all the items in the locked queue
            # these are LockableObject that were locked when we wanted to process them
            for lockable in self.lock_queue:
                # does this storage directory still exist?
                #if not os.path.isdir(lockable.storage_dir): # XXX <-- this looks like an assumption (.storage_dir)
                    #logging.debug("storage directory {} no longer exists - removing from queue".format(
                                  #lockable.storage_dir))
                    #self.lock_queue.remove(lockable)
                    #return

                # can we lock it?
                if not lockable.lock():
                    logging.debug("still unable to lock {}".format(lockable))
                    continue

                self.current_ready = lockable
                self.lock_queue.remove(lockable)
                return

            if len(self.lock_queue):
                logging.debug("lock queue size = {}".format(len(self.lock_queue)))

            # nothing is available or ready in the lock queue
            # so look for new stuff on the incoming work_queue
            try:
                self.current_ready = self.work_queue.get(block=not saq.SINGLE_THREADED, timeout=0.05)
                logging.debug("got {} from work queue".format(self.current_ready))
            except Empty:
                return

            # is this object lockable?
            # some engines (brotex, carbon black) create work items that are specific to the engine
            # and don't require locks 
            if isinstance(self.current_ready, LockableObject):
                if not self.current_ready.lock():
                    logging.debug("unable to lock {}: moving to lock queue".format(self.current_ready))
                    if self.current_ready in self.lock_queue:
                        logging.error("{} already in lock queue".format(self.current_ready))
                    else:
                        self.lock_queue.append(self.current_ready)
                        self.current_ready = None

            # at this point we have somthing to do
            # so we continue the loop

    def add_work_item(self, item):
        """Adds the given item to the work queue.  Blocks until the item can be added, or the engine has shut down."""
        start_time = datetime.datetime.now()
        while not self.shutdown:
            try:
                self.work_queue.put(item, block=not saq.SINGLE_THREADED, timeout=1)
                logging.debug("added work item {} in {} seconds".format(item, 
                              (datetime.datetime.now() - start_time).total_seconds()))
                return
            except Full:
                #logging.debug("work queue is full...")
                pass

    def start_engine(self):
        self.engine_startup_pipe_p, self.engine_startup_pipe_c = Pipe()
        self.engine_process = Process(target=self.engine_loop, name='{0} Engine'.format(self.name))
        self.engine_process.start()
        
        # wait for the message from the child that it started up
        try:
            if not self.engine_startup_pipe_p.poll(30):
                raise RuntimeError("start timed out")

            started = self.engine_startup_pipe_p.recv()
            assert isinstance(started, bool)

            if not started:
                raise RuntimeError("start failed (returned False)")

            logging.info("engine started")
            self.engine_startup_pipe_p.close()
            self.engine_startup_pipe_p = None

        except Exception as e:
            logging.error("engine failed to start: {}".format(e))
            return False

        return True

    def engine_loop(self):
        logging.info("started engine {} on process {}".format(self.name, os.getpid()))

        self.initialize_sighup_handler()

        # add the capability for a graceful shutdown
        def handle_sigterm(signum, frame):
            logging.warning("received SIGTERM in engine")
            self.stop()

        signal.signal(signal.SIGTERM, handle_sigterm)

        self.initialize_modules()
        self.initialize_profile_points()
        self.initialize_engine()

        if not saq.SINGLE_THREADED:
            self.start_process_managers() # this needs to come first here
            self.start_queue_manager()
            self.start_delayed_analysis()

            if self.auto_refresh_frequency:
                self.next_auto_refresh_time = datetime.datetime.now() + datetime.timedelta(
                                              seconds=self.auto_refresh_frequency)

        # let the parent process know that we've started
        self.engine_startup_pipe_c.send(True)
        self.engine_startup_pipe_c.close()
        self.engine_startup_pipe_c = None

        try:
            # wait for collection to shutdown
            while not self.shutdown and not self.collection_event.wait(timeout=1):
                # every second we break out and look to see if we got a SIGHUP
                # if or if reached a time limit that automatically reloads everything
                if not saq.SINGLE_THREADED and (self.sighup_received or (self.auto_refresh_frequency and 
                                            datetime.datetime.now() > self.next_auto_refresh_time)):

                    self.sighup_received = False
                    if self.auto_refresh_frequency:
                        self.next_auto_refresh_time = datetime.datetime.now() + datetime.timedelta(
                                                      seconds=self.auto_refresh_frequency)

                    logging.info("reloading modules")
                    self.stop_delayed_analysis()
                    self.stop_queue_manager()

                    if self.sighup_received:
                        # we re-load the config when we receive SIGHUP
                        logging.info("reloading engine configuration")
                        saq.load_configuration()

                    self.initialize_modules()
                    self.initialize_profile_points()
                    self.initialize_engine()
                    self.restart_process_managers() # this needs to come first here
                    self.start_queue_manager()
                    self.start_delayed_analysis()

                if self.sigusr1_received:
                    try:
                        for p in self.process_managers:
                            logging.info("sending SIGUSR1 to process manager {}".format(p.pid))
                            os.kill(p.pid, signal.SIGUSR1)
                    except Exception as e:
                        logging.error(str(e))
                    
                    self.sigusr1_received = False

                if self.sigusr2_received:
                    try:
                        for p in self.process_managers:
                            logging.info("sending SIGUSR2 to process manager {}".format(p.pid))
                            os.kill(p.pid, signal.SIGUSR2)
                    except Exception as e:
                        logging.error(str(e))
                    self.sigusr2_received = False

            # at this point collection is done 
            # so we're just waiting for things to finish

            # wait for the request to shutdown
            # this will come from the engine_loop
            logging.debug("detected collection shutdown -- waiting for shutdown message...")
            while not self.shutdown and not self.controlled_shutdown:
                time.sleep(0.1)

            logging.debug("detected shutdown message -- waiting for queues to empty...")

            # we have the request to shut down
            # wait for the queues to empty out

            while not self.shutdown and \
                  ( self.delayed_analysis_xfer_queue.qsize() or 
                  self.delayed_analysis_queue.qsize() or 
                  self.current_delayed_analysis_request or 
                  self.work_queue.qsize() or 
                  self.lock_queue or 
                  self.ready_queue.qsize() ):

                if self.delayed_analysis_xfer_queue.qsize():
                    logging.debug("queue status: delayed_analysis_xfer_queue = {}".format(self.delayed_analysis_xfer_queue.qsize()))
                if self.delayed_analysis_queue.qsize():
                    logging.debug("queue status: delayed_analysis_queue = {}".format(self.delayed_analysis_queue.qsize()))
                if self.current_delayed_analysis_request:
                    logging.debug("queue status: current_delayed_analysis_request = {}".format(self.current_delayed_analysis_request))
                if self.work_queue.qsize():
                    logging.debug("queue status: work_queue = {}".format(self.work_queue.qsize()))
                if self.lock_queue:
                    logging.debug("queue status: lock_queue = {}".format(self.lock_queue))
                if self.ready_queue.qsize():
                    logging.debug("queue status: ready_queue = {}".format(self.ready_queue.qsize()))

                time.sleep(1.0)

            self.stop_delayed_analysis()
            self.stop_queue_manager()
            self.stop_process_managers()

            # these should all be zero
            #if self.delayed_analysis_xfer_queue.qsize():
                #logging.error("delayed_analysis_xfer_queue = {}".format(self.delayed_analysis_xfer_queue.qsize()))
            #if self.delayed_analysis_queue.qsize():
                #logging.error("delayed_analysis_queue = {}".format(self.delayed_analysis_queue.qsize()))
            #if self.current_delayed_analysis_request:
                #logging.error("current_delayed_analysis_request = {}".format(self.current_delayed_analysis_request))
            #if self.work_queue.qsize():
                #logging.error("work_queue = {}".format(self.work_queue.qsize()))
            #if self.lock_queue:
                #logging.error("lock_queue = {}".format(self.lock_queue))
            #if self.ready_queue.qsize():
                #logging.error("ready_queue = {}".format(self.ready_queue.qsize()))

        except KeyboardInterrupt:
            logging.warning("caught user interrupt in engine_loop")

        logging.debug("ended engine loop")

    def start_process_managers(self):
        logging.debug("starting process managers")
        self.process_manager_event.clear()
        self.process_managers = []

        for i in range(self.analysis_pool_size):
            p = Process(target=self.process_manager_loop, name='{} Process Manager'.format(self.name))
            p.start()
            logging.debug("started process manager {}".format(p.pid))
            self.process_managers.append(p)

    def stop_process_managers(self):
        logging.debug("stopping process managers")
        self.process_manager_event.set()
        
        for pm in self.process_managers:
            logging.debug("waiting for process manager {}".format(pm.pid))
            pm.join()
            logging.debug("process manager {} stopped".format(pm.pid))

    def restart_process_managers(self):
        logging.info("restarting process managers for {}".format(self.name))
        #
        # NOTE before you call this make sure you don't have any threads running
        # because new processes will inherit running threads
        #
        # keep track of which ones we've restarted
        restarted = [False for p in self.process_managers]
        
        # the new list of process managers
        new_process_managers = []

        # tell them all to stop
        self.stop_process_managers()

        # create a new event to use to control the new process managers
        # the existing process managers will still have references to the old event that is now set
        self.process_manager_event = Event()

        while not self.shutdown:
            # as each of them stop, start up a new one
            for index, p in enumerate(self.process_managers):
                if restarted[index]:
                    continue

                p.join(0.1)
                if p.is_alive():
                    continue

                logging.debug("process manager {} stopped".format(p.pid))
                new_process = Process(target=self.process_manager_loop, 
                                      name='{} Process Manager'.format(self.name))
                new_process.start()
                new_process_managers.append(new_process)
                restarted[index] = True
                continue

            if all(restarted):
                break

        # we now have a new list of process managers
        old_process_managers = self.process_managers
        self.process_managers = new_process_managers

        # if we broke out while we are shutting down then it's possible that there are
        # child processes still running that haven't stop yet
        if self.shutdown:
            for p in old_process_managers:
                logging.warning("sending SIGTERM to remaining child process {}".format(p.pid))
                signal_process(p, signal.SIGTERM)
                p.join(10)
                if p.is_alive():
                    logging.warning("sending SIGKILL to remaining child process {}".format(p.pid))
                    signal_process(p, signal.SIGKILL)

        logging.info("finished restarting process managers for {}".format(self.name))

    def process_manager_loop(self):
        logging.info("started process manager loop on process {}".format(os.getpid()))
        enable_cached_db_connections()

        def handle_sigusr1(signum, frame):
            self.sigusr1_received = True

        def handle_sigusr2(signum, frame):
            self.sigusr2_received = True

        signal.signal(signal.SIGUSR1, handle_sigusr1)
        signal.signal(signal.SIGUSR2, handle_sigusr2)
        
        while not self.process_manager_shutdown:
            if self.sigusr1_received:
                try:
                    from pympler import tracker
                    if not hasattr(self, '_memory_tracker'):
                        logging.info("creating initial summary - send another SIGUSR1 to compare")
                        self._memory_tracker = tracker.SummaryTracker()
                        logging.info("finished creating initial summary")
                    else:
                        logging.info("calculating object diff...")
                        self._memory_tracker.print_diff()
                except Exception as e:
                    logging.error(str(e))

                self.sigusr1_received = False

            if self.sigusr2_received:
                try:
                    pass
                except Exception as e:
                    logging.error(str(e))

                self.sigusr2_received = False

            try:
                self.execute()
            except KeyboardInterrupt:
                logging.warning("caught user interrupt in process_manager_loop")
                self.process_manager_event.set()
            except Exception as e:
                logging.error("uncaught exception in process management: {}".format(str(e)))
                report_exception()
                time.sleep(1)

        logging.debug("process manager {} exiting".format(os.getpid()))
        release_cached_db_connection()

    def log_process_statistics(self):
        if self.statistic_dump_frequency == 0:
            return

        if ( self.last_statistic_dump is None or datetime.datetime.now() > 
                self.last_statistic_dump + datetime.timedelta(seconds=self.statistic_dump_frequency) ):

            logging.debug("process {} pid {} run time {}".format(
                          self.child_process.name, 
                          self.child_process.pid, 
                          datetime.datetime.now() - self.child_process_start_time))

            self.last_statistic_dump = datetime.datetime.now()

    def execute(self):
        try:
            # get the next thing to do
            # I'm using this blocking get() call to throttle the use of the CPU (FYI)
            work_item = self.ready_queue.get(block=not saq.SINGLE_THREADED, timeout=0.05)
        except Empty:
            return

        logging.info("got work item {}".format(work_item))

        # give the modules a chance to update their configurations
        if self.auto_reload_frequency:
            if (datetime.datetime.now() - self.last_auto_reload_check).total_seconds() > self.auto_reload_frequency:
                logging.info("running autoreload for modules...")
                self.last_auto_reload_check = datetime.datetime.now()
                for analysis_module in self.analysis_modules:
                    try:
                        analysis_module.check_watched_files()
                        analysis_module.auto_reload()
                    except Exception as e:
                        logging.error("unable to auto-reload {}: {}".format(analysis_module, e))
                        report_exception()

        target_function = None

        # reset state flags
        self._cancel_analysis_flag = False

        # if the work item is a delayed analysis request then it goes straight to processing
        if isinstance(work_item, DelayedAnalysisRequest):
            target_function = self.analyze
        # did this come from processing?
        else:
            # otherwise the work_item is abstract and given to the process function for processing
            target_function = self.process

        # TODO start a thread to the side that logs the process statistics
        target_function(work_item)

    def child_process_wrapper(self, target_function, *args, **kwargs):
        try:
            target_function(*args, **kwargs)
        except KeyboardInterrupt:
            logging.warning("caught user interrupt in child_process_wrapper")

    def analyze(self, target):
        assert isinstance(target, saq.analysis.RootAnalysis) or isinstance(target, DelayedAnalysisRequest)
    
        # make sure root analysis has it's storage directory available
        if isinstance(target, saq.analysis.RootAnalysis):
            if not os.path.exists(target.storage_dir):
                logging.error("missing storage directory for {}".format(target))
                return

        # reset total analysis measurements
        self.total_analysis_time.clear()

        # when we receive SIGTERM we want to cancel the current analysis efforts
        #def handle_sigterm(signum, frame):
            #logging.info("analysis processing for {} received SIGTERM pid {}".format(target, os.getpid()))
            #self.cancel_analysis_flag = True

        #signal.signal(signal.SIGTERM, handle_sigterm)

        self.root = target # usually this is the RootAnalysis
        self.delayed_analysis_request = None

        # are we completing an analysis request?
        if isinstance(target, DelayedAnalysisRequest):
            self.delayed_analysis_request = target

            # when we create the DelayedAnalysisRequest we also record what the type of the target was
            # so that we can instaniate it here with the correct type
            self.root = self.delayed_analysis_request.target_type(
                        storage_dir=self.delayed_analysis_request.storage_dir)

            # sanity check, we can remove this later
            assert isinstance(self.root, RootAnalysis)

            if not os.path.isdir(self.root.storage_dir):
                logging.warning("storage directory {} missing - already processed?".format(self.root.storage_dir))
                # don't leave locks behind
                self.delayed_analysis_request.unlock()
                return

            # load from JSON
            self.root.load()

            # transfer locks from the DelayedAnalysisRequest
            self.delayed_analysis_request.transfer_locks_to(self.root)

            # at this point the delayed analysis *request* is done (even though we are currently analyzing)
            # so we delete the tracking we're doing
            try:
                observable = self.root.get_observable(self.delayed_analysis_request.observable_uuid)
                analysis_module = None
                for _analysis_module in self.analysis_modules:
                    if _analysis_module.config_section == self.delayed_analysis_request.analysis_module:
                        analysis_module = _analysis_module
                        break

                if observable and analysis_module:
                    self.root.track_delayed_analysis_stop(observable, analysis_module)

                # we also need to reset the delay flag for this analysis
                target_analysis = observable.get_analysis(analysis_module.generated_analysis_type)
                if target_analysis:
                    target_analysis.delayed = False

            except Exception as e:
                logging.error("unable to stop tracking delayed analysis: {}".format(e))
                report_exception()

        # if we ARE in SINGLE_THREADED mode then we need to initialize the modules (each time)
        if saq.SINGLE_THREADED:
            logging.warning("re-initializing modules in SINGLE_THREADED mode")
            self.initialize_modules()
        else:
            # reset each module to it's default state
            for analysis_module in self.analysis_modules:
                analysis_module.reset()

        # tell all the analysis modules what alert they'll be processing
        for analysis_module in self.analysis_modules:
            analysis_module.root = self.root

        # when something goes wrong it helps to have the logs specific to this analysis
        logging_handler = logging.FileHandler(os.path.join(self.root.storage_dir, 'saq.log'))
        logging_handler.setLevel(logging.getLogger().level)
        logging_handler.setFormatter(logging.getLogger().handlers[0].formatter)
        logging.getLogger().addHandler(logging_handler)

        # if self.root is a LockableObject then we need to manage "keep alives" for the object
        # this is done on the side in a thread
        self.start_root_lock_manager()

        elapsed_time = None
        error_report_path = None

        try:
            start_time = time.time()
            # don't even start if we're already cancelled
            if not self.cancel_analysis_flag:
                self.execute_module_analysis()

            elapsed_time = time.time() - start_time
            logging.info("completed analysis {} in {:.2f} seconds".format(target, elapsed_time))

            if self.root.delayed:
                self.root.save()
            else:
                self.execute_module_post_analysis()
                self.execute_profile_point_analysis()

                # give the engine a chance to review the analysis
                # it may want to do something with it like create an alert to notify someone
                self.post_analysis(self.root)

                # save all the changes we've made
                self.root.save() # XXX this is saving even before we may be about to delete

                # notify that we've fully completed analysis for this
                self.root_analysis_completed(self.root)

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

        # unlock the root if it isn't already
        if isinstance(self.root, LockableObject):
            self.root.unlock()

        # cleanup
        for analysis_module in self.analysis_modules:
            try:
                analysis_module.cleanup()
            except Exception as e:
                logging.error("unable to clean up analysis module {}: {}".format(analysis_module, e))
                report_exception()

        # transfer any delayed analysis requests over to the delayed analysis manager
        logging.debug("transfering {} delayed analysis requests".format(len(self.delayed_analysis_buffer)))
        for next_analysis, request in self.delayed_analysis_buffer:
            self.delayed_analysis_xfer_queue.put_nowait((next_analysis, request))
    
        self.delayed_analysis_buffer.clear()

        # if analysis failed, copy all the details to error_reports for review
        error_report_stats_dir = None
        if error_report_path and os.path.isdir(self.root.storage_dir):
            analysis_dir = '{}.ace'.format(error_report_path)
            try:
                shutil.copytree(self.root.storage_dir, analysis_dir)
                logging.warning("copied analysis from {} to {} for review".format(self.root.storage_dir, analysis_dir))
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

                if error_report_stats_dir:
                    with open(os.path.join(error_report_stats_dir, '{}.stats'.format(key)), 'a') as fp:
                        fp.write(output_line)

        except Exception as e:
            logging.error("unable to record statistics: {}".format(e))

        return

    # ------------------------------------------------------------------------
    # This is the main processing loop of analysis in ACE.
    #

    def execute_module_analysis(self):
        """Implements the recursive analysis logic of ACE."""

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
            # find the analysis module that needs to analyze this observable
            for analysis_module in self.analysis_modules:
                if analysis_module.config_section == self.delayed_analysis_request.analysis_module:
                    work_stack.append(WorkTarget(
                                      observable=self.root.get_observable(self.delayed_analysis_request.observable_uuid), 
                                      analysis_module=analysis_module))
                    break

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
                if work_item.observable.has_tag('whitelisted'):
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
            # normally we want to analyze with all the enabled modules
            analysis_modules = self.analysis_modules
                
            # an Observable can specify a limited set of analysis modules to run
            # by using the limit_analysis() function
            # (this is ignored if there is a dependency - we'll use that instead)
            if work_item.dependency is None and work_item.observable and work_item.observable.limited_analysis:
                analysis_modules = [x for x in self.analysis_modules 
                                    if type(x).__name__ in work_item.observable.limited_analysis]
                logging.debug("analysis for {} limited to {} modules ({})".format(
                              work_item.observable, len(analysis_modules), ','.join(work_item.observable.limited_analysis)))

            # if the work_item includes a dependency then the analysis_module property will already be set
            elif work_item.analysis_module:
                logging.debug("analysis for {} limited to {}".format(work_item, work_item.analysis_module))
                analysis_modules = [work_item.analysis_module]
            
            else:
                logging.debug("analysis for {} not limited".format(work_item))

            # analyze this thing with the analysis modules we've selected
            for analysis_module in analysis_modules:

                if self.cancel_analysis_flag:
                    break

                # is this module only supposed to execute in post analysis?
                if isinstance(analysis_module, PostAnalysisModule):
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
                                    #logging.info("MARKER: first")

                                # if we do have output analysis and it's not delayed then we move on to analyze
                                # the source target again
                                elif not output_analysis.delayed:
                                    work_item.dependency.increment_status()
                                    logging.debug("dependency status updated {}".format(work_item.dependency))
                                    work_stack.appendleft(WorkTarget(observable=self.root.get_observable(work_item.dependency.source_observable_id),
                                                                     analysis_module=self._get_analysis_module_by_generated_analysis(work_item.dependency.source_analysis_type)))
                                    #logging.info("MARKER: second")

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
                if work_item.observable and work_item.observable.has_tag('whitelisted'):
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

    def execute_module_post_analysis(self):
        logging.debug("executing post analysis on {}".format(self.root))
        for analysis_module in self.analysis_modules:
            try:
                analysis_module.execute_post_analysis()
            except Exception as e:
                logging.error("post analysis module {} failed".format(analysis_module))
                report_exception()

    def execute_profile_point_analysis(self):
        self.root.clear_profile_points()
        for pp_module in self.profile_point_analyzers:
            logging.debug("executing {} on {}".format(pp_module, self.root))
            try:
                result = pp_module.analyze(self.root)
                if not result:
                    continue
                elif isinstance(result, ProfilePoint):
                    self.root.add_profile_point(result)
                elif isinstance(result, list):
                    for profile_point in result:
                        assert isinstance(profile_point, ProfilePoint)
                        self.root.add_profile_point(profile_point)
                else:
                    raise ValueError("expected either False (or None), ProfilePoint or list of ProfilePoint")
            except Exception as e:
                logging.error("profile point module {} failed: {}".format(pp_module, e))
                report_exception()

    def should_alert(self, root):
        """Returns True if we should fire an alert for this analysis.

        Analysis and Observable objects implement a function called has_detection_points which
        returns True if the object has anything that would result in a detection.

        """

        if root.alerted:
            return False

        has_detection = False
        for analysis in root.all_analysis:
            has_detection |= analysis.has_detection_points()
        for observable in root.all_observables:
            has_detection |= observable.has_detection_points()

        # there's a flag that tells ACE to always signal something as an alert
        return has_detection or saq.FORCED_ALERTS

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

class DelayedAnalysisRequest(LocalLockableObject):
    """Encapsulates a request for delayed analysis."""
    def __init__(self, target, observable_uuid, analysis_module, next_analysis, *args, **kwargs):
        super().__init__(*args, **kwargs)

        assert isinstance(target, RootAnalysis)
        assert isinstance(observable_uuid, str) and observable_uuid
        assert isinstance(analysis_module, str) and analysis_module
        
        self.storage_dir = target.storage_dir
        self.target_type = type(target) # we end up using this in the analyze() call
        self.observable_uuid = observable_uuid
        self.analysis_module = analysis_module
        self.uuid = target.uuid
        self.next_analysis = next_analysis

        # if the target is lockable then we use a "lock proxy" to managing that locking
        # see lib/saq/lock.py for details
        self.lock_proxy = None
        if isinstance(target, LockableObject):
            self.lock_proxy = target.create_lock_proxy()

    def lock(self):
        if self.lock_proxy:
            return self.lock_proxy.lock()

        return super().lock()

    def unlock(self):
        if self.lock_proxy:
            return self.lock_proxy.unlock()

        return super().unlock()

    def is_locked(self):
        if self.lock_proxy:
            return self.lock_proxy.is_locked()

        return super().is_locked()

    def refresh_lock(self):
        if self.lock_proxy:
            return self.lock_proxy.refresh_lock()

        return super().refresh_lock()

    def transfer_locks_to(self, lockable):
        if self.lock_proxy:
            self.lock_proxy.transfer_locks_to(lockable)
            return

        super().transfer_locks_to(lockable)
    
    def __str__(self):
        return "DelayedAnalysisRequest for {} type {} by {} @ {}".format(
                self.storage_dir, str(self.target_type), self.analysis_module, self.next_analysis)

    def __repr__(self):
        return self.__str__()

    # we need to override this for when next_analysis is equal
    def __lt__(self, other):
        return False

class SSLNetworkServer(Engine):
    """An Engine that implements an SSL socket to receive work."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # the listening SSL socket
        self.server_socket = None
        self.ssl_context = None

        # main thread for network looping
        self.network_server_management_thread = None
        # queue.Queue of tuple(client_socket, client_stream, client_address)
        self.network_server_work_queue = queue.Queue(maxsize=1) # maxsize = 1 to limit the connections
        # worker threads
        self.network_server_workers = [] # of threading.Thread

        # make sure we have the configuration options we need
        for option in [ 'max_connections', 
                        'server_host',
                        'server_port',
                        'ssl_ca_path',
                        'ssl_cert_path',
                        'ssl_key_path',
                        'network_timeout' ]:
            if option not in self.config:
                logging.critical("missing configuration option {} for engine {}".format(option, self.name))
        
    def handle_network_item(self, item):
        """Override this function to handle incoming files sent over the network."""
        raise NotImplementedError()

    def initialize_collection(self, *args, **kwargs):
        super().initialize_collection(*args, **kwargs)
        self.start_network_server()

    def stop(self, *args, **kwargs):
        super().stop(*args, **kwargs)
        self.stop_network_server()

    def start_network_server(self):
        self.network_server_management_thread = threading.Thread(target=self.network_server_management_loop, 
                                                                 name="Network Server Management")
        self.network_server_management_thread.start()
        #record_metric(METRIC_THREAD_COUNT, threading.active_count())

        # the queue the contains the work to be done by the workers
        # this will be tuple of (client_socket, client_stream, client_address)
        self.network_server_work_queue = queue.Queue(maxsize=1)

        for i in range(self.config.getint('max_connections')):
            t = threading.Thread(target=self.network_worker_loop, 
                                 name="Network Server Worker Loop #{}".format(i))
            t.start()
            #record_metric(METRIC_THREAD_COUNT, threading.active_count())
            self.network_server_workers.append(t)
            logging.debug("started network worker thread {}".format(t))

    def stop_network_server(self):
        if self.network_server_management_thread:
            logging.debug("waiting for network server management to stop...")
            self.network_server_management_thread.join()

        for t in self.network_server_workers:
            logging.debug("waiting for {} to stop...".format(t))
            t.join()

    def network_server_management_loop(self):
        logging.debug("started network server management")
        while not self.collection_shutdown:
            try:
                self.network_server_management_execute()
            except Exception as e:
                logging.error("network error: {}".format(e))
                report_exception()
                time.sleep(1)

    def network_server_management_execute(self):
        # initialize the connection if we need to
        if not self.server_socket:
            try:
                logging.info("initializing server socket on {}:{}".format(
                              self.config['server_host'], self.config.getint('server_port')))
                self.ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                #logging.debug("loading certificate chain certfile {} keyfile {}".format(
                             #os.path.join(saq.SAQ_HOME, self.config['ssl_cert_path']),
                             #os.path.join(saq.SAQ_HOME, self.config['ssl_key_path'])))

                if 'ssl_ca_path' in self.config:
                    self.ssl_context.load_verify_locations(self.config['ssl_ca_path'])
                self.ssl_context.load_cert_chain(certfile=os.path.join(saq.SAQ_HOME, self.config['ssl_cert_path']), 
                                                 keyfile=os.path.join(saq.SAQ_HOME, self.config['ssl_key_path']))
                self.server_socket = socket.socket()
                self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.server_socket.bind((self.config['server_host'], self.config.getint('server_port')))
                conn = self.ssl_context.wrap_socket(socket.socket(socket.AF_INET))
                self.server_socket.listen(5)

                # setting a timeout allows us to gracefully shutdown
                self.server_socket.settimeout(1)

            except Exception as e:
                logging.error("unable to create server socket on host {} port {}: {}".format(
                              self.config['server_host'], self.config['server_port'], e))

                if self.server_socket is not None:
                    try:
                        self.server_socket.close()
                    except:
                        pass

                self.server_socket = None
                time.sleep(1) # throttle
                return

        # get the next connection to handle
        try:
            logging.debug("waiting for network connection")
            client_socket, client_address = self.server_socket.accept()
            client_stream = self.ssl_context.wrap_socket(client_socket, server_side=True)
            logging.debug("received connection from {}".format(client_address))

        except ssl.SSLEOFError:
            logging.warning("caught ssl EOF error for {}".format(client_address))
            return

        except socket.timeout:
            return

        except Exception as e:
            logging.error("unable to accept new connection: {}".format(e))
            report_exception()

            if self.server_socket is not None:
                try:
                    self.server_socket.close()
                except:
                    pass

            # this will signal to re-establish the connection on the next loop
            self.server_socket = None
            return

        while not self.collection_shutdown:
            try:
                self.network_server_work_queue.put((client_socket, client_stream, client_address), timeout=1)
                break
            except Full:
                logging.debug("ssl service queue is full, waiting...")
                continue

        # start a thread to handle the connection
        ##t = threading.Thread(target=self.network_loop, args=(client_socket, client_stream, client_address), 
                             #name="SSL Network Handler({})".format(client_address))
        #t.daemon = True
        #t.start()

    def network_worker_loop(self):

        enable_cached_db_connections()
        
        while not self.collection_shutdown:
            client_socket = None
            client_stream = None
            client_address = None

            try:
                # get the next thing to do
                #logging.info("waiting for work...")
                work = self.network_server_work_queue.get(timeout=1)
                client_socket, client_stream, client_address = work
                logging.debug("processing connection from {}".format(client_address))
                self.network_execute(client_stream, client_address)
            except Empty:
                #logging.info("work queue is empty...")
                continue
            except Exception as e:
                logging.error("uncaught exception in network worker loop: {}".format(e))
                report_exception()
            finally:

                if client_stream:
                    try:
                        client_stream.shutdown(socket.SHUT_RDWR)
                    except:
                        pass

                    try:
                        client_stream.shutdown(socket.SHUT_RDWR)
                    except:
                        pass

        release_cached_db_connection()
        
    def network_execute(self, client_stream, client_address):

        p = None # our tar process (see below)
        _stdout = None
        _stderr = None

        try:
            # make sure that dead sockets timeout
            if 'network_timeout' in self.config:
                logging.debug("setting network timeout to {}".format(str(self.config.getint('network_timeout'))))
                client_stream.settimeout(self.config.getint('network_timeout'))

            # I wanted to avoid reading the whole thing into memory
            # but was having trouble with ascyn non-blocking Popen pipes

            # TODO
            # keep track of how many bytes we've read
            # if we've read more than X bytes then we write it all to disk
            # and continue to write to disk, then use that in our Popen call
            #

            logging.debug("reading network data from {}".format(client_address))
            bytes_read = 0
            data_buffer = io.BytesIO()
            while not self.collection_shutdown:
                data = client_stream.recv(4096)
                if data == b'':
                    break

                data_buffer.write(data)
                bytes_read += len(data)

            # close the sockets here
            client_stream.shutdown(socket.SHUT_RDWR)
            client_stream.close()
            
            logging.debug("read {} bytes from {}".format(bytes_read, client_address))

            # this is all just basically tar | nc --> nc -l | tar
            p = Popen(['tar', 'zxvf', '-', '-C', self.collection_dir], 
                      stdin=PIPE, stdout=PIPE, stderr=PIPE)
            logging.debug("opened tar process {}".format(p.pid))

            _stdout, _stderr = p.communicate(input=data_buffer.getbuffer())
            p.wait()

            # did tar fail?
            if p.returncode:
                logging.error("tar failed for data from connection {}: {}".format(client_address, p.returncode))
                if _stderr:
                    logging.error("tar stderr: {}".format(_stderr))
                return

            p = None

        except Exception as e:
            logging.error("I/O error handling connection {}: {}".format(client_address, e))
            report_exception()

        finally:
            if p is not None:
                try:
                    logging.debug("attempting to terminate process {}".format(p.pid))
                    p.terminate()
                    try:
                        p.wait(timeout=60)
                        logging.debug("terminated process {}".format(p.pid))
                    except TimeoutExpired:
                        logging.warning("process {} did not terminate -- killing".format(p.pid))
                        p.kill()
                        logging.debug("killed process {}".format(p.pid))
                        try:
                            p.wait(timeout=5)
                        except TimeoutExpired:
                            logging.error("process {} did not terminate at all".format(p.pid))
                except ProcessLookupError:
                    pass
                except Exception as e:
                    logging.error("uncaught exception {}".format(e))
                    report_exception()

        # at this point we should have one or more files extracted
        # these files are printed out on the stdout of tar
        if _stdout:
            for file_path in _stdout.split(b'\n'):
                file_path = file_path.decode().strip()
                if file_path == '':
                    continue

                file_path = os.path.join(self.collection_dir, file_path)
                if not os.path.exists(file_path):
                    logging.error("extracted file path {} does not exist".format(file_path))
                    continue

                self.handle_network_item(file_path)

class MySQLCollectionEngine(Engine):
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if 'workload_name' not in self.config:
            logging.critical("missing workload_name in engine config {}".format(self.name))

        self.workload_name = self.config['workload_name']

        # any mysql engine needs at least a 1 second delay between checks
        # since we're querying a database
        if self.collection_frequency < 1:
            logging.warning("invalid collection frequency {} for mysql-based collection (setting to 1 second)".format(
                            self.collection_frequency))
            self.collection_frequency = 1

    def initialize_collection(self, *args, **kwargs):
        super().initialize_collection(*args, **kwargs)

        enable_cached_db_connections()

        try:
            # this needs to be OK for this to work
            initialize_sql_collection(self.collection_dir, self.workload_name)
        except Exception as e:
            logging.critical("unable to initialize sql collection: {}".format(e))
        
    def collect(self):
        # get the next thing to do from the local sql database
        while not self.collection_shutdown:
            logging.debug("checking for new work from sql database...")
            with get_db_connection(DB_CONFIG) as db:
                c = db.cursor()
                c.execute("""SELECT id, path FROM workload WHERE name = %s ORDER BY id ASC LIMIT 1""", 
                          (self.workload_name,))

                try:
                    _id, path = c.fetchone()
                except Exception as e:
                    if saq.SINGLE_THREADED:
                        time.sleep(1)
                        continue
                    
                    return

                logging.debug("got path {} id {}".format(path, _id))

                if not os.path.exists(path):
                    logging.error("file {} does not exist".format(path))
                else:
                    # submit the file for processing
                    self.add_work_item(path)

                # remove it from the database workload
                c.execute("""DELETE FROM workload WHERE id = %s""", (_id,))
                if c.rowcount != 1:
                    logging.error("no rows were deleted when trying to delete rowid {}".format(_id))

                db.commit()
        
            # if we're executing in single threaded mode then we only need to submit one thing
            if saq.SINGLE_THREADED:
                return

        release_cached_db_connection()

    def add_sql_work_item(self, path):
        """Adds the given path to the sql database for collection later."""
        submit_sql_work_item(self.workload_name, path)

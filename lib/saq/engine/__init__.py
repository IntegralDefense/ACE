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

from multiprocessing import Process, Queue, Semaphore, Event, Pipe, cpu_count
from queue import PriorityQueue, Empty, Full
from subprocess import Popen, PIPE

import saq
import saq.analysis
import saq.database

from saq.analysis import Observable, Analysis, RootAnalysis, ProfilePoint, ProfilePointAnalyzer
from saq.anp import *
from saq.constants import *
from saq.database import Alert, use_db, release_cached_db_connection, enable_cached_db_connections, \
                         get_db_connection, add_workload, acquire_lock, release_lock, execute_with_retry, \
                         add_delayed_analysis_request
from saq.error import report_exception
from saq.modules import AnalysisModule
from saq.performance import record_metric
from saq.util import human_readable_size, storage_dir_from_uuid

import iptools
import psutil

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

class Engine(object):
    """Analysis Correlation Engine"""

    @property
    def workload_count(self):
        """Returns the current size of the workload."""
        raise NotImplementedError()

    # 
    # INITIALIZATION
    # ------------------------------------------------------------------------

    def __init__(self, name='ace'):

        global CURRENT_ENGINE
        CURRENT_ENGINE = self

        # the name of the engine, usually you want the default unless you're doing something different
        # like unit testing
        self.name = name

        # the engine configuration
        self.config = saq.CONFIG['engine']

        # we just cache the current hostname of this engine here
        self.hostname = socket.gethostname()

        # a work directory where we can find the files to work on
        self.work_dir = os.path.join(saq.SAQ_HOME, 'work', self.name)

        # directory for temporary files
        self.var_dir = os.path.join(saq.SAQ_HOME, 'var', self.name)

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

        # the worker processes that do the actual analysis
        self.workers = [] # of Process objects

        # used to start and stop the workers
        self.worker_control_event = Event()

        # the modules that will perform the analysis
        self.analysis_modules = []

        # the mapping of analysis mode to the list of analysis modules that should run for that mode
        self.analysis_mode_mapping = {}

        # a mapping of analysis module configuration section headers to the load analysis modules
        self.analysis_module_mapping = {} # key = analysis_module_blah, value = AnalysisModule

        # the default analysis mode for RootAnalysis objects assigned to invalid analysis modes
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
        self.sigusr1_received = False
        self.sigusr2_received = False

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

    def __str__(self):
        return "Engine ({})".format(saq.SAQ_NODE)

    @property
    @use_db
    def delayed_analysis_queue_size(self, db, c):
        """Returns the size of the delayed analysis queue (for this node.)"""
        c.execute("SELECT COUNT(*) FROM delayed_analysis WHERE node = %s", (saq.SAQ_NODE,))
        row = c.fetchone()
        return row[0]

    @property
    @use_db
    def workload_queue_size(self, db, c):
        """Returns the size of the workload queue (for this node.)"""
        c.execute("SELECT COUNT(*) FROM workload WHERE node = %s", (saq.SAQ_NODE,))
        row = c.fetchone()
        return row[0]

    # if you just want to check to see if the queues are empty
    # then these queries are probably faster than counting all of them

    @property
    @use_db
    def delayed_analysis_queue_is_empty(self, db, c):
        """Returns True if the delayed analysis queue is empty, False otherwise."""
        c.execute("SELECT id FROM delayed_analysis WHERE node = %s LIMIT 1", (saq.SAQ_NODE,))
        row = c.fetchone()
        return row is None

    @property
    @use_db
    def workload_queue_is_empty(self, db, c):
        """Returns True if the work queue is empty, False otherwise."""
        c.execute("SELECT id FROM workload WHERE node = %s LIMIT 1", (saq.SAQ_NODE,))
        row = c.fetchone()
        return row is None

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
        # make sure these exist
        for d in [ self.work_dir, self.var_dir, self.stats_dir ]:
            try:
                if not os.path.isdir(d):
                    os.makedirs(d)
            except Exception as e:
                logging.error("unable to create directory {}: {}".format(d, e))

    def initialize_signal_handlers(self):
        def handle_sighup(signum, frame):
            self.sighup_received = True

        def handle_sigusr1(signum, frame):
            self.sigusr1_received = True

        def handle_sigusr2(signum, frame):
            self.sigusr2_received = True
    
        def handle_sigterm(signal, frame):
            self.sigterm_received = True

        signal.signal(signal.SIGTERM, handle_sigterm)
        signal.signal(signal.SIGHUP, handle_sighup)
        signal.signal(signal.SIGUSR1, handle_sigusr1)
        signal.signal(signal.SIGUSR2, handle_sigusr2)

    def initialize_modules(self):
        """Loads all configured analysis modules and prepares the analysis mode mapping."""

        # the entire list of enabled analysis modules
        self.analysis_modules = []

        # the mapping of analysis mode to the list of analysis modules that should run for that mode
        self.analysis_mode_mapping = {}

        # quick mapping of analysis module section name to the loaded AnalysisModule
        self.analysis_module_mapping = {} # key = analysis_module_name, value = AnalysisModule

        # a module_group define a list of modules to load for a given engine
        # the module_groups config option defines a comma separated list of groups to load
        # each group defines one or more modules to load
        #if 'module_groups' in self.config:
            #self.module_groups = [x for x in self.config['module_groups'].split(',') if x]

        #group_configured_modules = {}
        #for group_name in self.module_groups:
            #group_section = 'module_group_{}'.format(group_name)
            #if group_section not in saq.CONFIG:
                #logging.error("invalid module group {} specified for {}".format(group_name, self))
                #continue

            #for module_name in saq.CONFIG[group_section].keys():
                #if module_name in group_configured_modules:
                    #logging.debug("replacing config for module {} by module_group {}".format(
                                  #module_name, group_section))

                #group_configured_modules[module_name] = saq.CONFIG[group_section].getboolean(module_name)
                #if group_configured_modules[module_name]:
                    #logging.debug("module {} enabled by group config {}".format(module_name, group_name))

        for section in saq.CONFIG.sections():
            if not section.startswith('analysis_module_'):
                continue

            # is this module in the list of disabled modules?
            # these are always disabled regardless of any other setting
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
            #if section not in self.config and section not in group_configured_modules:
                #logging.debug("analysis module {} is not specified for {}".format(section, self.name))
                #continue

            # and it must be enabled
            #if ( section in self.config and not self.config.getboolean(section) ) or (
                 #section in group_configured_modules and not group_configured_modules[section] ):
                #logging.debug("analysis module {} is disabled for {}".format(section, self.name))
                #continue

            # we keep track of how much memory this module uses when it starts up
            #current_process = psutil.Process()
            #starting_rss = current_process.memory_info().rss

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

        # now assign the analysis_modes to the analysis modules that should run in them
        for section in saq.CONFIG.sections():
            if section.startswith('analysis_mode_'):
                mode = section[len('analysis_mode_'):]
                # make sure every analysis mode defines cleanup
                if 'cleanup' not in saq.CONFIG[section]:
                    logging.critical("{} missing cleanup key".format(section))

                self.analysis_mode_mapping[mode] = []

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
                            
                        if module_section not in self.analysis_module_mapping:
                            logging.debug("{} specified for {} but is disabled globally".format(
                                          module_section, group_section))
                            continue

                        self.analysis_mode_mapping[mode].append(self.analysis_module_mapping[module_section])
                        logging.info("added {} to {}".format(module_section, section))

                # and then add any other modules specified for this mode (besides the groups)
                # NOTE this can also disable individual modules specified in
                # groups by setting the value to "no" instead of "yes"
                for key_name in saq.CONFIG[section].keys():
                    if key_name.startswith('analysis_module_'):
                        analysis_module_name = key_name[len('analysis_module_'):]
                        # make sure this is in the configuration
                        if key_name not in saq.CONFIG:
                            logging.critical("{} references invalid analysis module {}".format(section, analysis_module_name))
                            continue

                        # make sure the module was loaded
                        if key_name not in self.analysis_module_mapping:
                            logging.info("{} specified for {} but is disabled globally".format(
                                         analysis_module_name, section))
                            continue

                        # are we adding or removing?
                        if saq.CONFIG[section].getboolean(key_name):
                            self.analysis_mode_mapping[mode].append(self.analysis_module_mapping[key_name])
                            logging.info("added {} to {}".format(analysis_module_name, section))
                        else:
                            if self.analysis_module_mapping[key_name] in self.analysis_mode_mapping[mode]:
                                self.analysis_mode_mapping[mode].remove(self.analysis_module_mapping[key_name])
                                logging.debug("removed {} from analysis mode {}".format(analysis_module_name, mode))

            # how much memory did we end up using here?
            #ending_rss = current_process.memory_info().rss

            # we want to warn if the memory usage is very large ( > 10MB)
            #if ending_rss - starting_rss > 1024 * 1024 * 10:
                #logging.warning("memory usage grew by {} bytes for loading analysis module {}".format(
                                #human_readable_size(ending_rss - starting_rss),
                                #analysis_module))

        logging.debug("finished loading {} modules".format(len(self.analysis_modules)))

    #
    # MAINTENANCE
    # ------------------------------------------------------------------------

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

    @property
    def worker_shutdown(self):
        """Returns True if the workers should be shutting down."""
        return self.shutdown or self.worker_control_event.is_set()

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

    def single_threaded_start(self, analysis_mode_priority=None, started_event=None):
        """Typically used for debugging. Runs the entire process under a single thread."""
        logging.warning("executing in single threaded mode")
        self.initialize()
        self.worker_loop(analysis_mode_priority, started_event)

    def stop(self):
        """Immediately stop the engine."""
        logging.warning("stopping {} NOW".format(self))
        self.immediate_event.set()

    def controlled_stop(self):
        """Shutdown the engine in a controlled manner allowing existing jobs to complete."""
        logging.info("shutting down {}".format(self))
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
                if not acquire_lock(uuid, self.lock_uuid, lock_owner=self.lock_owner):
                    logging.warning("failed to maintain lock")
                    break

                if self.lock_manager_control_event.wait(float(saq.CONFIG['global']['lock_keepalive_frequency'])):
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
                    logging.error("delayed analysis for {} in {} has timed out".format(observable, analysis_module))
                    return False

                logging.info("delayed analysis for {} in {} has been waiting for {} seconds".format(
                             observable, analysis_module, (datetime.datetime.now() - start_time).total_seconds()))

        # when do we resume analysis?
        next_analysis = datetime.datetime.now() + datetime.timedelta(hours=hours, minutes=minutes, seconds=seconds)

        # add the request to the workload
        try:
            if add_delayed_analysis_request(root, observable, analysis_module, next_analysis):
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

        self.start_workers()
        if self.auto_refresh_frequency:
            self.next_auto_refresh_time = datetime.datetime.now() + datetime.timedelta(
                                          seconds=self.auto_refresh_frequency)

        self.start_maintenance_threads()
        self.engine_startup_event.set()
        self.initialize_signal_handlers()

        try:
            while True:
                if self.sigterm_received:
                    logging.warning("recevied SIGTERM -- shutting down")
                    self.stop()
                    break

                if self.auto_refresh_frequency and datetime.datetime.now() > self.next_auto_refresh_time:
                    logging.info("auto refresh frequency {} triggered reload of worker modules".format(
                                 self.auto_refresh_frequency))

                    self.stop_workers()
                    saq.load_configuration()
                    self.start_workers()

                    self.next_auto_refresh_time = datetime.datetime.now() + \
                    datetime.timedelta(seconds=self.auto_refresh_frequency)
                    logging.debug("next auto refresh scheduled for {}".format(self.next_auto_refresh_time))

                if self.sighup_received:
                    # we re-load the config when we receive SIGHUP
                    logging.info("reloading engine configuration")

                    # reload the workers
                    self.stop_workers()
                    saq.load_configuration()
                    self.start_workers()

                    self.sighup_received = False

                if self.sigusr1_received:
                    for worker in self.workers:
                        try:
                            logging.info("sending SIGUSR1 to worker {}".format(worker))
                            os.kill(worker.pid, signal.SIGUSR1)
                        except Exception as e:
                            logging.error("unable to send SIGUSR1 to worker {}".format(worker))
                            report_exception()
                    
                    self.sigusr1_received = False

                if self.sigusr2_received:
                    for worker in self.workers:
                        try:
                            logging.info("sending SIGUSR2 to worker {}".format(worker))
                            os.kill(worker.pid, signal.SIGUSR2)
                        except Exception as e:
                            logging.error("unable to send SIGUSR2 to worker {}".format(worker))
                            report_exception()

                    self.sigusr2_received = False
                
                # if this event is set then we need to exit now
                if self.immediate_event.wait(0.1):
                    break
        
                if self.control_event.wait(0.1):
                    break

            # if we're shutting down then go ahead and tell the workers to shut down
            if self.shutdown:
                self.stop_workers()
            else:
                # otherwise just wait for the workers to finish working the queue
                self.wait_workers()

            self.stop_maintenance_threads()

        except KeyboardInterrupt:
            logging.warning("caught user interrupt in engine_loop")

        logging.debug("ended engine loop")

    #
    # PROCESS MANAGEMENT
    # ------------------------------------------------------------------------

    def start_workers(self):
        logging.debug("starting workers")
        self.worker_control_event.clear()
        self.workers = []
        tracking = [] # of (process, event)

        for key in self.config.keys():
            if key.startswith('analysis_pool_size_'):
                mode = key[len('analysis_pool_size_'):]
                for i in range(self.config.getint(key)):
                    event = Event()
                    p = Process(target=self.worker_loop, 
                                name='Worker {} [{}]'.format(i, mode), args=(mode, event))
                    self.workers.append(p)
                    tracking.append((p, event))
                    p.start()

        # do we NOT have any defined analysis pools?
        if len(self.workers) == 0:
            logging.info("no analysis pools defined -- defaulting to {} workers assigned to any pool".format(
                         cpu_count()))
            for core in range(cpu_count()):
                event = Event()
                p = Process(target=self.worker_loop, name='Worker {} [{}]'.format(core, 'equal priority'), 
                            args=(None, event))
                self.workers.append(p)
                tracking.append((p, event))
                p.start()

        logging.info("waiting for workers to start...")
        for p, event in tracking:
            if not event.wait(5):
                logging.critical("detected {} failed to start".format(p.name))
                return False

        logging.info("workers started")
        return True

    def stop_workers(self):
        logging.info("stopping workers")
        self.worker_control_event.set()
        self.wait_workers()

    def wait_workers(self):
        """Waits for all the workers to shutdown."""
        for worker in self.workers:
            logging.info("waiting for worker {}".format(worker.pid))
            worker.join()
            logging.info("worker {} stopped".format(worker.pid))

    def restart_workers(self):
        logging.info("restarting workers")
        self.stop_workers()
        self.start_workers()

    def worker_loop(self, analysis_mode_priority, started_event):
        logging.info("started worker loop on process {}".format(os.getpid()))
        enable_cached_db_connections()

        # this determines what kind of work we look for first
        self.analysis_mode_priority = analysis_mode_priority

        # set up our lock
        self.lock_uuid = str(uuid.uuid4())
        self.lock_owner = '{}-{}-{}'.format(saq.SAQ_NODE, analysis_mode_priority, os.getpid())

        try:
            self.initialize_modules()
        except Exception as e:
            logging.error("unable to initialize modules: {} (worker exiting)".format(e))
            report_exception()
            return

        self.initialize_signal_handlers()

        # let the main process know we started
        if started_event is not None:
            started_event.set()
        
        while not self.shutdown and not self.worker_shutdown:
            # we're not doing anything with these signals atm
            if self.sigusr1_received:
                self.sigusr1_received = False

            if self.sigusr2_received:
                self.sigusr2_received = False

            try:
                # if the control event is set then it means we're looking to exit when everything is done
                if self.control_event.is_set():
                    if self.delayed_analysis_queue_is_empty and self.workload_queue_is_empty:
                        self.stop() # XXX not sure we actually need this
                        return

                    logging.debug("queue sizes workload {} delayed {}".format(
                                   self.workload_queue_size,
                                   self.delayed_analysis_queue_size))

                # if execute returns True it means it discovered and processed a work_item
                # in that case we assume there is more work to do and we check again immediately
                if self.execute():  
                    continue

                # otherwise we wait a second until we go again
                self.sleep(1)
                    
            except KeyboardInterrupt:
                logging.warning("caught user interrupt in worker_loop")
                self.worker_control_event.set()
            except Exception as e:
                logging.error("uncaught exception in worker_loop: {}".format(str(e)))
                report_exception()
                self.sleep(1)

        logging.debug("worker {} exiting".format(os.getpid()))
        release_cached_db_connection()

    #
    # ANALYSIS
    # ------------------------------------------------------------------------
    
    @use_db
    def transfer_work_target(self, uuid, node, db, c):
        """Moves the given work target from the given remote node to the local node."""
        logging.info("moving work target {} from {}".format(uuid, node))

        # get the main data.json
        # get all the analysis objects
        # get all the files
        
        # change the node entry
        return True

    @use_db
    def get_delayed_analysis_work_target(self, db, c):
        """Returns the next DelayedAnalysisRequest that is ready, or None if none are ready."""
        # get the next thing to do
        # first we look for any delayed analysis that needs to complete
        c.execute("""
SELECT 
    delayed_analysis.id, 
    delayed_analysis.uuid, 
    delayed_analysis.observable_uuid, 
    delayed_analysis.analysis_module, 
    delayed_analysis.delayed_until
FROM
    delayed_analysis LEFT JOIN locks ON delayed_analysis.uuid = locks.uuid
WHERE
    delayed_analysis.node = %s
    AND locks.uuid IS NULL
    AND NOW() > delayed_until
ORDER BY
    delayed_until ASC
""", (saq.SAQ_NODE,))

        for _id, uuid, observable_uuid, analysis_module, delayed_until in c:
            if not acquire_lock(uuid, self.lock_uuid, lock_owner=self.lock_owner):
                continue

            return DelayedAnalysisRequest(uuid,
                                          observable_uuid,
                                          analysis_module,
                                          delayed_until,
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
            where_clause.append('workload.node = %s')
            params.append(saq.SAQ_NODE)

        where_clause = ' AND '.join(['({})'.format(clause) for clause in where_clause])

        logging.debug("looking for work with {} ({})".format(where_clause, ','.join(params)))

        c.execute("""
SELECT
    workload.id,
    workload.uuid,
    workload.analysis_mode,
    workload.insert_date,
    workload.node
FROM
    workload LEFT JOIN locks ON workload.uuid = locks.uuid
WHERE
    {where_clause}
ORDER BY
    id ASC
LIMIT 16""".format(where_clause=where_clause), tuple(params))

        for _id, uuid, analysis_mode, insert_date, node in c:
            if not acquire_lock(uuid, self.lock_uuid, lock_owner=self.lock_owner):
                continue

            # is this work item on a different node?
            if node != saq.SAQ_NODE:
                if not self.transfer_work_target(uuid, node):
                    return None

            return RootAnalysis(uuid=uuid, storage_dir=storage_dir_from_uuid(uuid))

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
            execute_with_retry(db, c, "DELETE FROM workload WHERE uuid = %s", (target.uuid))

        execute_with_retry(db, c, "DELETE FROM locks where uuid = %s", (target.uuid))
        db.commit()
        logging.debug("cleared work target {}".format(target))
        
    def execute(self):

        # get the next thing to work on
        work_item = self.get_next_work_target()
        if work_item is None:
            return False

        logging.info("got work item {}".format(work_item))

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

        # did the analysis mode change?
        # NOTE that we do this AFTER locks are released
        if self.root.analysis_mode != current_analysis_mode:
            logging.info("analysis mode for {} changed from {} to {}".format(
                          self.root, current_analysis_mode, self.root.analysis_mode))

            try:
                add_workload(self.root.uuid, self.root.analysis_mode)
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
                        c.execute("""SELECT uuid FROM workload
                                     UNION SELECT uuid FROM delayed_analysis
                                     UNION SELECT uuid FROM locks 
                                     WHERE uuid = %s
                                     LIMIT 1
                                     """, (self.root.uuid,))

                        row = c.fetchone()
                        db.commit() # XXX I assume this releases whatever lock the SELECT statement holds

                        if row is None:
                            # OK then it's time to clean this one up
                            logging.debug("clearing {}".format(self.root.storage_dir))
                            try:
                                shutil.rmtree(self.root.storage_dir)
                            except Exception as e:
                                logging.error("unable to clear {}: {}".format(self.root.storage_dir))
                        else:
                            logging.debug("not cleaning up {} (found outstanding work)".format(self.root))

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

        elapsed_time = None
        error_report_path = None
        try:
            start_time = time.time()
            
            # don't even start if we're already cancelled
            if not self.cancel_analysis_flag:
                self.execute_module_analysis()

            # do we NOT have any outstanding delayed analysis requests?
            if not self.root.delayed:
                for analysis_module in self.analysis_modules:
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

        # give the modules a chance to cleanup
        for analysis_module in self.analysis_modules:
            try:
                analysis_module.cleanup()
            except Exception as e:
                logging.error("unable to clean up analysis module {}: {}".format(analysis_module, e))
                report_exception()

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
                    return

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
            if self.root.analysis_mode is None:
                analysis_modules = self.analysis_mode_mapping[self.default_analysis_mode]
            else:
                try:
                    analysis_modules = self.analysis_mode_mapping[self.root.analysis_mode]
                except KeyError:
                    logging.warning("{} specifies invalid analysis mode {} - defaulting to {}".format(
                                    self.root, self.root.analysis_mode, self.default_analysis_mode))
                    analysis_modules = self.analysis_mode_mapping[self.default_analysis_mode]
                
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
    def __init__(self, uuid, observable_uuid, analysis_module, next_analysis, database_id=None):

        assert isinstance(uuid, str) and uuid
        assert isinstance(observable_uuid, str) and observable_uuid
        assert isinstance(analysis_module, str) and analysis_module
        
        self.uuid = uuid
        self.observable_uuid = observable_uuid
        self.analysis_module = analysis_module
        self.next_analysis = next_analysis
        self.database_id = database_id

        self.root = None

    @property
    def storage_dir(self):
        return storage_dir_from_uuid(self.uuid)

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

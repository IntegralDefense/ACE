# vim: sw=4:ts=4:et

__all__ = [
    'EV_TEST_DATE',
    'EV_ROOT_ANALYSIS_TOOL',
    'EV_ROOT_ANALYSIS_TOOL_INSTANCE',
    'EV_ROOT_ANALYSIS_ALERT_TYPE',
    'EV_ROOT_ANALYSIS_DESCRIPTION',
    'EV_ROOT_ANALYSIS_EVENT_TIME',
    'EV_ROOT_ANALYSIS_NAME',
    'EV_ROOT_ANALYSIS_UUID',
    'create_root_analysis',
    'ACEBasicTestCase',
    'ACEEngineTestCase',
    'ACEModuleTestCase',
    'reset_alerts',
    'log_count',
    'wait_for_log_count',
    'WaitTimedOutError',
    'wait_for_log_entry',
    'track_io',
    'send_test_message',
    'recv_test_message',
    'splunk_query',
    'wait_for',
    'enable_module',
    'force_alerts',
    'GUIServer',
    'search_log',
    'search_log_regex',
    'search_log_condition',
    'TestEngine',
    'UNITTEST_USER_NAME',
    'UNITTEST_USER_ID',
]

import atexit
import datetime
import logging
import os, os.path
import secrets
import shutil
import sys
import threading
import time

from multiprocessing import Manager, RLock, Pipe, Process
from unittest import TestCase
from subprocess import Popen, PIPE

import saq
import saq.engine
from saq.analysis import RootAnalysis, _enable_io_tracker, _disable_io_tracker
from saq.database import initialize_database, get_db_connection, use_db
from saq.engine import Engine
from saq.error import report_exception
from saq.util import storage_dir_from_uuid, workload_storage_dir

from splunklib import SplunkQueryObject

test_dir = None
UNITTEST_USER_NAME = 'unittest'
UNITTEST_USER_ID = None

# decorators
#

def track_io(target_function):
    def wrapper(*args, **kwargs):
        try:
            _enable_io_tracker()
            return target_function(*args, **kwargs)
        finally:
            _disable_io_tracker()
    return wrapper

def force_alerts(target_function):
    """Alerts will be forced ON for the duration of this function."""
    def wrapper(*args, **kwargs):
        try:
            saq.FORCED_ALERTS = True
            return target_function(*args, **kwargs)
        finally:
            saq.FORCED_ALERTS = False
    return wrapper

def reset_alerts(target_function):
    """Deletes all alerts in the database."""
    def wrapper(*args, **kwargs):
        with get_db_connection() as db:
            c = db.cursor()
            c.execute("""DELETE FROM alerts""")
            db.commit()

        return target_function(*args, **kwargs)
    return wrapper

# 
# utility functions

def enable_module(engine_name, module_name):
    """Adds a module to be enabled."""
    saq.CONFIG[module_name]['enabled'] = 'yes'
    saq.CONFIG[engine_name][module_name] = 'yes'

def wait_for(condition, interval=1, timeout=8):
    """Wait for condition to return True, checking every interval seconds until timeout seconds have elapsed.
       Return True if condition returned True before timeout was exceeded, False otherwise."""
    timeout = datetime.datetime.now() + datetime.timedelta(seconds=timeout)
    while datetime.datetime.now() < timeout:
        if condition():
            return True

        time.sleep(interval)

    return False

# test comms pipe is used to communicate between test process and child processes
test_comms_p = None
test_comms_pid = None
test_comms_c = None

def open_test_comms():
    global test_comms_p
    global test_comms_pid
    global test_comms_c

    test_comms_p, test_comms_c = Pipe()
    test_comms_pid = os.getpid()
    
def close_test_comms():
    test_comms_p.close()
    test_comms_c.close()

def get_test_comm_pipe():
    # if we are the original process then we use the "parent" pipe
    # otherwise we use the "child" pipe
    if os.getpid() == test_comms_pid:
        return test_comms_p

    return test_comms_c

def send_test_message(message):
    get_test_comm_pipe().send(message)

def recv_test_message():
    return get_test_comm_pipe().recv()

test_log_manager = None
test_log_sync = None
test_log_messages = None
memory_log_handler = None

class WaitTimedOutError(Exception):
    pass

#
# custom logging

class MemoryLogHandler(logging.Handler):
    def acquire(self):
        test_log_sync.acquire()

    def release(self):
        test_log_sync.release()

    def createLock(self):
        pass

    def emit(self, record):
        try:
            test_log_messages.append(record)
        except:
            sys.stderr.write(str(record) + "\n")

    def clear(self):
        with test_log_sync:
            del test_log_messages[:]

    def search(self, condition):
        """Searches and returns all log records for which condition(record) was True. Returns the list of LogRecord that matched."""

        result = []
        with test_log_sync:
            for message in test_log_messages:
                if condition(message):
                    result.append(message)

        return result

    def wait_for_log_entry(self, callback, timeout=5, count=1):
        """Waits for callback to return True count times before timeout seconds expire.
           callback takes a single LogRecord object as the parameter and returns a boolean."""
        time_limit = datetime.datetime.now() + datetime.timedelta(seconds=timeout)

        current_index = 0
        current_count = 0

        while True:
            with test_log_sync:
                while current_index < len(test_log_messages):
                    if callback(test_log_messages[current_index]):
                        current_count += 1

                        if current_count == count:
                            return True

                    current_index += 1

            if datetime.datetime.now() >= time_limit:
                raise WaitTimedOutError()

            time.sleep(0.1)

def _atexit_callback():
    global test_log_manager

    if test_log_manager:
        try:
            test_log_manager.shutdown()
        except Exception as e:
            print("ERROR: unable to shutdown test log manager: {}".format(e))
            
def initialize_unittest_logging():
    # ACE is multi-process multi-threaded
    # so we use this special logging mechanism to keep a central repository of the log events generated
    # that the original process can access

    global test_log_manager
    global test_log_sync
    global test_log_messages
    global memory_log_handler

    test_log_manager = Manager()
    atexit.register(_atexit_callback)
    test_log_sync = RLock()
    test_log_messages = test_log_manager.list()

    log_format = logging.Formatter(datefmt='%(asctime)s')

    memory_log_handler = MemoryLogHandler()
    memory_log_handler.setLevel(logging.DEBUG)
    memory_log_handler.setFormatter(log_format)
    logging.getLogger().addHandler(memory_log_handler)

def wait_for_log_entry(*args, **kwargs):
    return memory_log_handler.wait_for_log_entry(*args, **kwargs)

def log_count(text):
    """Returns the number of times the given text is seen in the logs."""
    with test_log_sync:
        return len([x for x in test_log_messages if text in x.getMessage()])

def wait_for_log_count(text, count, timeout=5):
    """Waits for text to occur count times in the logs before timeout seconds elapse."""
    def condition(e):
        return text in e.getMessage()

    return memory_log_handler.wait_for_log_entry(condition, timeout, count)

def search_log(text):
    return memory_log_handler.search(lambda log_record: text in log_record.getMessage())

def search_log_regex(regex):
    return memory_log_handler.search(lambda log_record: regex.search(log_record.getMessage()))

def search_log_condition(func):
    return memory_log_handler.search(func)

def splunk_query(search_string, *args, **kwargs):
    config = saq.CONFIG['splunk']
    q = SplunkQueryObject(
        uri=config['uri'],
        username=config['username'],
        password=config['password'],
        *args, **kwargs)

    result = q.query(search_string)
    return q, result

def initialize_test_environment():
    global test_dir

    # there is no reason to run anything as root
    if os.geteuid() == 0:
        print("do not run ace as root please")
        sys.exit(1)

    # where is ACE?
    saq_home = '/opt/saq'
    if 'SAQ_HOME' in os.environ:
        saq_home = os.environ['SAQ_HOME']

    # adjust search path
    sys.path.append(os.path.join(saq_home, 'lib'))

    # initialize saq
    import saq
    saq.initialize(saq_home=saq_home, config_paths=[], 
                   logging_config_path=os.path.join(saq_home, 'etc', 'unittest_logging.ini'), 
                   args=None, relative_dir=None, unittest=True)

    if saq.CONFIG['global']['instance_type'] not in [ 'PRODUCTION', 'QA', 'DEV' ]:
        sys.stderr.write('\n\n *** CRITICAL ERROR *** \n\ninvalid instance_type setting in configuration\n')
        sys.exit(1)

    if saq.CONFIG['global']['instance_type'] == 'PRODUCTION':
        sys.stderr.write('\n\n *** PROTECT PRODUCTION *** \ndo not execute this in production, idiot\n')
        sys.exit(1)

    # additional logging required for testing
    initialize_unittest_logging()

    # create a temporary storage directory
    test_dir = os.path.join(saq.SAQ_HOME, 'var', 'test')
    if os.path.exists(test_dir):
        try:
            shutil.rmtree(test_dir)
        except Exception as e:
            logging.error("unable to delete {}: {}".format(test_dir, e))
            sys.exit(1)

    try:
        os.makedirs(test_dir)
    except Exception as e:
        logging.error("unable to create temp dir {}: {}".format(test_dir, e))

    # in all our testing we use the password "password" for encryption/decryption
    from saq.crypto import get_aes_key
    saq.ENCRYPTION_PASSWORD = get_aes_key('password')

    #initialize_database()
    initialized = True

# expected values
EV_TEST_DATE = datetime.datetime(2017, 11, 11, hour=7, minute=36, second=1, microsecond=1)

EV_ROOT_ANALYSIS_TOOL = 'test_tool'
EV_ROOT_ANALYSIS_TOOL_INSTANCE = 'test_tool_instance'
EV_ROOT_ANALYSIS_ALERT_TYPE = 'test_alert'
EV_ROOT_ANALYSIS_DESCRIPTION = 'This is only a test.'
EV_ROOT_ANALYSIS_EVENT_TIME = EV_TEST_DATE
EV_ROOT_ANALYSIS_NAME = 'test'
EV_ROOT_ANALYSIS_UUID = '14ca0ff2-ff7e-4fa1-a375-160dc072ab02'

def create_root_analysis(tool=None, tool_instance=None, alert_type=None, desc=None, event_time=None,
                         action_counts=None, details=None, name=None, remediation=None, state=None,
                         uuid=None, location=None, storage_dir=None, company_name=None, company_id=None,
                         analysis_mode=None):
    """Returns a default RootAnalysis object with expected values for testing."""
    return RootAnalysis(tool=tool if tool else EV_ROOT_ANALYSIS_TOOL,
                        tool_instance=tool_instance if tool_instance else EV_ROOT_ANALYSIS_TOOL_INSTANCE,
                        alert_type=alert_type if alert_type else EV_ROOT_ANALYSIS_ALERT_TYPE,
                        desc=desc if desc else EV_ROOT_ANALYSIS_DESCRIPTION,
                        event_time=event_time if event_time else EV_TEST_DATE,
                        action_counters=action_counts if action_counts else None,
                        details=details if details else None, 
                        name=name if name else EV_ROOT_ANALYSIS_NAME,
                        remediation=remediation if remediation else None,
                        state=state if state else None,
                        uuid=uuid if uuid else EV_ROOT_ANALYSIS_UUID,
                        location=location if location else None,
                        storage_dir=storage_dir if storage_dir else os.path.relpath(
                            workload_storage_dir(uuid if uuid else EV_ROOT_ANALYSIS_UUID),
                            start=saq.SAQ_HOME),
                        company_name=company_name if company_name else None,
                        company_id=company_id if company_id else None,
                        analysis_mode=analysis_mode if analysis_mode else 'test_groups')

class ServerProcess(object):
    def __init__(self, args):
        self.args = args
        self.process = None
        self.stdout_reader = None
        self.stderr_reader = None

    def start(self):
        self.process = Popen(self.args, stdout=PIPE, stderr=PIPE, universal_newlines=True)
        logging.debug("started process for {} with pid {} args {}".format(
                      type(self), self.process.pid, ','.join(self.args)))

        self.stdout_reader = threading.Thread(target=self.pipe_reader, args=(self.process.stderr, self.handle_stdout))
        self.stdout_reader.daemon = True
        self.stdout_reader.start()

        self.stderr_reader = threading.Thread(target=self.pipe_reader, args=(self.process.stdout, self.handle_stderr))
        self.stderr_reader.daemon = True
        self.stderr_reader.start()

        logging.debug("waiting for {} to start...".format(type(self)))
        wait_for(self.startup_condition)
        logging.debug("{} started".format(type(self)))

    def stop(self):
        if self.process is None:
            return

        logging.debug("stopping process {} with pid {}".format(type(self), self.process.pid))
        self.process.terminate()
        self.process.wait()
        self.process = None

        logging.debug("stopping process output readers...")
        self.stdout_reader.join()
        self.stdout_reader = None
        self.stderr_reader.join()
        self.stderr_reader = None

    def handle_stdout(self, line):
        #print("STDOUT {}\t{}".format(type(self), line.strip()))
         pass

    def handle_stderr(self, line):
        if '[ERROR]' in line:
            print("detected error in subprocess: {}".format(line.strip()))

        #print("STDERR {}\t{}".format(type(self), line.strip()))

    def pipe_reader(self, pipe, callback):
        for line in pipe:
            callback(line.strip())

    def started(self):
        """Returns True if this process has actually started."""
        return True

class EngineProcess(ServerProcess):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.engine_started = False

    def startup_condition(self):
        return self.engine_started

    def handle_stderr(self, line):
        if 'engine started' in line:
            self.engine_started = True

        ServerProcess.handle_stderr(self, line)

class GUIServer(ServerProcess):
    def __init__(self):
        super().__init__(['python3', 'saq', '-L', 'etc/console_debug_logging.ini', 'start-gui'])
        self.saq_init = 0

    def handle_stderr(self, line):
        if 'SAQ initialized' in line:
            self.saq_init += 1
        
        ServerProcess.handle_stderr(self, line)

    def startup_condition(self):
        return self.saq_init > 1

class ACEBasicTestCase(TestCase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.api_server_process = None

        # a list of temporary test files we've created using self.create_test_file
        self.tracked_test_files = []

    def setUp(self):
        #saq.DUMP_TRACEBACKS = True
        logging.info("TEST: {}".format(self.id()))
        initialize_test_environment()
        self.reset()
        open_test_comms()
        memory_log_handler.clear()
        self.initialize_test_client()

    def initialize_test_client(self):
        from api import create_app
        self.app = create_app(testing=True)
        self.app_context = self.app.test_request_context()                      
        self.app_context.push()                           
        self.client = self.app.test_client()

    def tearDown(self):
        close_test_comms()

        # anything logged at CRITICAL log level will cause the test the fail
        #self.assertFalse(memory_log_handler.search(lambda e: e.levelno == logging.CRITICAL))

        saq.DUMP_TRACEBACKS = False

        self.stop_api_server()

        if saq.engine.CURRENT_ENGINE is not None:
            try:
                saq.engine.CURRENT_ENGINE.stop()
            except:
                pass

        for file_path in self.tracked_test_files:
            if os.path.exists(file_path):
                os.remove(file_path)

        # clear the database session this test used
        saq.db.remove()

    def create_test_file(self, file_path='test', file_content=None, root_analysis=None):
        """Creates a test file and returns the path to the newly created file.
           Any file created this way is automatically deleted after the test runs.
           If file_path is relative then the file is created relative to SAQ_HOME.
           If root_analysis is a RootAnalysis object then file_path is crated relative to the storage_dir of this analysis.
           If file_content is not None then it is used as the content of the file.
           Otherwise, 1024 random bytes are used."""
        
        if not os.path.isabs(file_path):
            if root_analysis:
                target_file_path = os.path.join(root_analysis.storage_dir, file_path)
            else:
                target_file_path = abs_path(file_path)

        mode = 'wb'
        if isinstance(file_content, str):
            mode = 'w'

        with open(target_file_path, mode) as fp:
            if file_content:
                fp.write(file_content)
            else:
                fp.write(secrets.token_bytes(1024))

        self.tracked_test_files.append(target_file_path)
        return file_path

    def clear_error_reports(self):
        """Clears out any error reports generated by the test."""
        try:
            shutil.rmtree(os.path.join(saq.DATA_DIR, 'error_reports'))
            os.makedirs(os.path.join(saq.DATA_DIR, 'error_reports'))
        except Exception as e:
            sys.stderr.write("unable to clear error_reports: {}\n".format(e))

    def wait_for_log_entry(self, *args, **kwargs):
        try:
            return wait_for_log_entry(*args, **kwargs)
        except WaitTimedOutError:
            return False

    def wait_for_condition(self, condition, timeout=5, delay=1):
        """Waits for condition to return True. 
           condition is checked every delay seconds until it return True or timeout seconds have elapsed."""
        time_limit = datetime.datetime.now() + datetime.timedelta(seconds=timeout)
        while True:
            if condition():
                return True

            if datetime.datetime.now() > time_limit:
                raise WaitTimedOutError()

            time.sleep(delay)

    def reset(self):
        """Resets everything back to the default state."""
        self.reset_config()
        self.reset_hal9000()
        self.reset_brocess()
        self.reset_cloudphish()
        self.reset_correlation()
        self.reset_email_archive()
        self.reset_crawlphish()
        self.reset_log_exports()

    def reset_log_exports(self):
        # reset splunk export logs
        splunk_log_dir = os.path.join(saq.DATA_DIR, saq.CONFIG['splunk_logging']['splunk_log_dir'])
        if os.path.isdir(splunk_log_dir):
            shutil.rmtree(splunk_log_dir)
            os.mkdir(splunk_log_dir)

        # reset es export logs
        es_log_dir = os.path.join(saq.DATA_DIR, saq.CONFIG['elk_logging']['elk_log_dir'])
        if os.path.isdir(es_log_dir):
            shutil.rmtree(es_log_dir)
            os.mkdir(es_log_dir)

    def reset_crawlphish(self):
        self.whitelist_path = saq.CONFIG['analysis_module_crawlphish']['whitelist_path'] \
                            = os.path.join('etc', 'crawlphish.unittest.whitelist')

        self.regex_path = saq.CONFIG['analysis_module_crawlphish']['regex_path'] \
                        = os.path.join('etc', 'crawlphish.unittest.regex')

        self.blacklist_path = saq.CONFIG['analysis_module_crawlphish']['blacklist_path'] \
                        = os.path.join('etc', 'crawlphish.unittest.blacklist')

        if os.path.exists(self.whitelist_path):
            os.remove(self.whitelist_path)

        if os.path.exists(self.regex_path):
            os.remove(self.regex_path)

        if os.path.exists(self.blacklist_path):
            os.remove(self.blacklist_path)

        with open(self.blacklist_path, 'w') as fp:
            fp.write('10.0.0.0/8\n')
            fp.write('127.0.0.1\n')
            fp.write('localhost.local\n')

        with open(self.regex_path, 'w') as fp:
            fp.write('\.(pdf|zip|scr|js|cmd|bat|ps1|doc|docx|xls|xlsx|ppt|pptx|exe|vbs|vbe|jse|wsh|cpl|rar|ace|hta)$\n')

        with open(self.whitelist_path, 'w') as fp:
            fp.write('anonfile.xyz\n')

    def reset_config(self):
        """Resets saq.CONFIG."""
        saq.load_configuration()

    @use_db(name='hal9000')
    def reset_hal9000(self, db, c):
        c.execute("DELETE FROM observables")
        db.commit()

    @use_db(name='brocess')
    def reset_brocess(self, db, c):
        # clear the brocess db
        c.execute("""DELETE FROM httplog""")
        c.execute("""DELETE FROM smtplog""")
        db.commit()
        # TODO instead of using harded values pull the limits from the config
        c.execute("""INSERT INTO httplog ( host, numconnections, firstconnectdate ) 
                     VALUES ( 'local', 1000, UNIX_TIMESTAMP(NOW()) ),
                            ( 'xyz', 1000, UNIX_TIMESTAMP(NOW()) ),
                            ( 'test1.local', 70, UNIX_TIMESTAMP(NOW()) ),
                            ( 'test2.local', 69, UNIX_TIMESTAMP(NOW()) )""")
        db.commit()

    @use_db
    def reset_cloudphish(self, db, c):
        # clear cloudphish db
        c.execute("""DELETE FROM cloudphish_analysis_results""")
        c.execute("""DELETE FROM cloudphish_content_metadata""")
        db.commit()

        # clear cloudphish engine and module cache
        for cache_dir in [ saq.CONFIG['cloudphish']['cache_dir'] ]:
            if os.path.isdir(cache_dir):
                shutil.rmtree(cache_dir)
                os.makedirs(cache_dir)

    @use_db
    def reset_correlation(self, db, c):
        global UNITTEST_USER_ID

        data_subdir = os.path.join(saq.CONFIG['global']['data_dir'], saq.SAQ_NODE)
        failed_alert_subdir = os.path.join(saq.SAQ_HOME, '.saq_alerts')

        subdirs = [ data_subdir, failed_alert_subdir ]
        if saq.CONFIG['engine']['work_dir']:
            subdirs.append(saq.CONFIG['engine']['work_dir'])

        for subdir in subdirs:
            if os.path.isdir(subdir):
                try:
                    shutil.rmtree(subdir)
                    os.mkdir(subdir)
                except Exception as e:
                    logging.error(f"unable to clear {subdir}: {e}")

        c.execute("DELETE FROM alerts")
        c.execute("DELETE FROM workload")
        c.execute("DELETE FROM observables")
        c.execute("DELETE FROM tags")
        c.execute("DELETE FROM profile_points")
        c.execute("DELETE FROM events")
        c.execute("DELETE FROM remediation")
        c.execute("DELETE FROM company WHERE name != 'default'")
        c.execute("DELETE FROM nodes WHERE is_local = 1")
        c.execute("UPDATE nodes SET is_primary = 0")
        c.execute("DELETE FROM locks")
        c.execute("DELETE FROM delayed_analysis")
        c.execute("DELETE FROM users")

        from app.models import User
        u = User()
        u.username = 'unittest'
        u.email = 'unittest@localhost'
        u.password = 'unittest'
        c.execute("""
            INSERT INTO users ( username, email, password_hash ) VALUES ( %s, %s, %s )""", 
            (u.username, u.email, u.password_hash))

        UNITTEST_USER_ID = c.lastrowid
        logging.debug(f"got user id {UNITTEST_USER_ID} for unittest user")
        db.commit()

    def reset_email_archive(self):
        import socket
        archive_subdir = os.path.join(saq.DATA_DIR, saq.CONFIG['analysis_module_email_archiver']['archive_dir'], 
                                      socket.gethostname().lower())

        if os.path.exists(archive_subdir):
            try:
                shutil.rmtree(archive_subdir)
                os.mkdir(archive_subdir)
            except Exception as e:
                logging.error("unable to clear {}: {}".format(archive_subdir, e))

        with get_db_connection('email_archive') as db:
            c = db.cursor()
            c.execute("DELETE FROM archive")
            db.commit()

    def start_api_server(self, remote_host=None, ssl_verification=None, listen_address=None, listen_port=None, ssl_cert=None, ssl_key=None):
        """Starts the API server as a separate process."""
        self.api_server_process = Process(target=self.execute_api_server, args=(listen_address, listen_port, ssl_cert, ssl_key))
        self.api_server_process.start()

        if remote_host is None:
            remote_host = saq.API_PREFIX
        if ssl_verification is None:
            ssl_verification = saq.CONFIG['SSL']['ca_chain_path']

        import ace_api

        result = None
        errors = []
        for x in range(5):
            try:
                result = ace_api.ping(remote_host=remote_host, ssl_verification=ssl_verification)
                break
            except Exception as e:
                errors.append(str(e))
                time.sleep(1)

        if result is None:
            for error in errors:
                logging.error(error)

            self.fail("unable to start api server")

    def execute_api_server(self, listen_address=None, listen_port=None, ssl_cert=None, ssl_key=None):

        # https://gist.github.com/rduplain/1705072
        # this is a bit weird because I want the urls to be the same as they
        # are configured for apache, where they are all starting with /api
        
        from api import create_app
        from saq.database import initialize_database

        app = create_app(testing=True)
        from werkzeug.serving import run_simple
        from werkzeug.wsgi import DispatcherMiddleware
        from flask import Flask
        app.config['DEBUG'] = True
        app.config['APPLICATION_ROOT'] = '/api'
        application = DispatcherMiddleware(Flask('dummy_app'), {
            app.config['APPLICATION_ROOT']: app,
        })

        if listen_address is None:
            listen_address = saq.CONFIG.get('api', 'listen_address')
        if listen_port is None:
            listen_port = saq.CONFIG.getint('api', 'listen_port')
        ssl_context = (
            saq.CONFIG.get('api', 'ssl_cert') if ssl_cert is None else ssl_cert,
            saq.CONFIG.get('api', 'ssl_key') if ssl_key is None else ssl_key )

        initialize_database(use_flask=True)

        logging.info(f"starting api server on {listen_address} port {listen_port}")
        run_simple(listen_address, listen_port, application, ssl_context=ssl_context, use_reloader=False)

    def stop_api_server(self):
        """Stops the API server if it's running."""
        if self.api_server_process is None:
            return

        import signal
        os.kill(self.api_server_process.pid, signal.SIGKILL)

        self.api_server_process.join()
        self.api_server_process = None

class ACEEngineTestCase(ACEBasicTestCase):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # if we create an engine using self.create_engine() then we track it here
        self.tracked_engine = None
        self.server_processes = {} # key = name, value ServerProcess

    def start_gui_server(self):
        self.server_processes['gui'] = GUIServer()
        self.server_processes['gui'].start()

    def start_cloudphish_server(self):
        self.server_processes['cloudphish'] = CloudphishServer()
        self.server_processes['cloudphish'].start()

    def stop_tracked_engine(self):
        if self.tracked_engine:
            try:
                self.tracked_engine.stop()
                self.wait_engine(self.tracked_engine)
            except Exception as e:
                logging.error("unable to stop tracked engine {}: {}".format(self.tracked_engine, e))
                report_exception()
            finally:
                self.tracked_engine = None

    def setUp(self, *args, **kwargs):
        super().setUp(*args, **kwargs)
        self.disable_all_modules()

    def tearDown(self):
        ACEBasicTestCase.tearDown(self)
        self.stop_tracked_engine()

        for key in self.server_processes.keys():
            self.server_processes[key].stop()

        #if saq.engine.CURRENT_ENGINE:
            #try:
                #saq.engine.CURRENT_ENGINE.stop()
            #except:
                #pass

    def execute_engine_test(self, engine):
        try:
            engine.start()
            engine.wait()
        except KeyboardInterrupt:
            engine.stop()
            engine.wait()

    def create_engine(self, cls, *args, **kwargs):
        try:
            self.tracked_engine = cls(*args, **kwargs)
            return self.tracked_engine
        except Exception as e:
            logging.error("unable to create engine {}: {}".format(cls, e))
            report_exception()
            self.fail("unable to create engine {}: {}".format(cls, e))
    
    def start_engine(self, engine):
        try:
            engine.start()
        except Exception as e:
            engine.stop()
            engine.wait()
            self.fail("engine failure: {}".format(e))

    def wait_engine(self, engine):
        try:
            engine.wait()
        except Exception as e:
            engine.controlled_stop()
            engine.wait()
            self.fail("engine failure: {}".format(e))

    def kill_engine(self, engine):
        try:
            engine.stop()
            engine.wait()
        except Exception as e:
            self.fail("engine failure: {}".format(e))

    def disable_all_modules(self):
        """Disables all the modules specified in the configuration file. Requires a @reset_config."""
        for key in saq.CONFIG.keys():
            if key.startswith('analysis_module_'):
                saq.CONFIG[key]['enabled'] = 'no'

        logging.debug("disabled all modules")

class CloudphishServer(EngineProcess):
    def __init__(self):
        super().__init__(['python3', 'saq', '-L', 'etc/console_debug_logging.ini', '--start', 'cloudphish'])

class ACEModuleTestCase(ACEEngineTestCase):
    pass

class TestEngine(Engine):
    def set_cleanup(self, mode, value):
        saq.CONFIG[f'analysis_mode_{mode}']['cleanup'] = 'yes' if value else 'no'
        logging.debug(f"set cleanup to {value} for analysis mode {mode}")

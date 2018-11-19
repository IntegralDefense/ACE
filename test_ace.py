# vim: sw=4:ts=4:et

import logging
import os.path
import threading

from subprocess import Popen, PIPE, TimeoutExpired

from saq.constants import *
from saq.test import ACEBasicTestCase

import psutil

class CLITestCase(ACEBasicTestCase):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.cli_process = None
        self.stderr_reader_thread = None
        self.stdout_reader_thread = None

    def tearDown(self, *args, **kwargs):
        if self.cli_process is not None:
            try:
                self.cli_process.terminate()
                self.cli_process.wait(5)
            except TimeoutExpired:
                try:
                    self.cli_process.kill()
                    self.cli_process.wait(5)
                except Exception as e:
                    logging.critical("cannot stop subprocess {}: {}".format(self.cli_process, e))

            if self.cli_process.returncode != 0:
                self.fail("subprocess {} returned exit code {}".format(' '.join(self.cli_args), self.cli_process.returncode))

        if self.stdout_reader_thread is not None:
            self.stdout_reader_thread.join(5)
            if self.stdout_reader_thread.is_alive():
                logging.error("reader thread not stopping...")

        if self.stderr_reader_thread is not None:
            self.stderr_reader_thread.join(5)
            if self.stderr_reader_thread.is_alive():
                logging.error("reader thread not stopping...")

    def stdout_reader(self):
        for line in self.cli_process.stdout:
            self.stdout_buffer.append(line)
            logging.debug("STDOUT: {}".format(line.strip()))

    def search_stdout(self, func):
        for line in self.stdout_buffer:
            if func(line):
                return line

    def stderr_reader(self):
        for line in self.cli_process.stderr:
            self.stderr_buffer.append(line)
            logging.debug("STDERR: {}".format(line.strip()))

    def search_stderr(self, func):
        for line in self.stderr_buffer:
            if func(line):
                return line

    def cli(self, *args, **kwargs):
        """Executes the ACE CLI with the given command line arguments. Sets up result monitoring."""
        self.cli_args = [ 'ace', '-L', 'etc/console_debug_logging.ini' ]
        self.cli_args.extend(args)

        logging.debug("executing {}".format(' '.join(self.cli_args)))
        self.cli_process = Popen(self.cli_args, stdout=PIPE, stderr=PIPE, universal_newlines=True)

        self.stdout_buffer = []
        self.stdout_reader_thread = threading.Thread(target=self.stdout_reader)
        self.stdout_reader_thread.daemon = True
        self.stdout_reader_thread.start() 

        self.stderr_buffer = []
        self.stderr_reader_thread = threading.Thread(target=self.stderr_reader)
        self.stderr_reader_thread.daemon = True
        self.stderr_reader_thread.start() 

    def cli_wait(self, seconds):
        """Waits for the CLI subprocess execute to exit for the given number of seconds."""
        try:
            self.cli_process.wait(seconds)
        except TimeoutExpired as e:
            self.fail("subprocess {} failed to exit in {} seconds".format(' '.join(self.cli_args), seconds))

    def verify_daemon(self, name):
        pid_path = os.path.join('var', 'daemon', name)
        self.assertTrue(os.path.exists(pid_path))
        with open(pid_path, 'r') as fp:
            daemon_pid = int(fp.read())

        self.assertTrue(psutil.pid_exists(daemon_pid))

    def verify_daemon_stopped(self, name):
        pid_path = os.path.join('var', 'daemon', name)
        self.assertFalse(os.path.exists(pid_path))

    def test_list_observables(self):
        self.cli('list-observables')
        self.cli_wait(5)

        for observable in VALID_OBSERVABLE_TYPES:
            self.assertTrue(self.search_stdout(lambda x: observable in x))

    def test_network_semaphore(self):
        self.cli('--start', '--daemon', 'network-semaphore')
        self.cli_wait(5)

        self.verify_daemon('network-semaphore')

        self.cli('--stop', 'network-semaphore')
        self.cli_wait(5)

        self.verify_daemon_stopped('network-semaphore')

# vim: sw=4:ts=4:et:cc=120

#
# this class exists because the main process is so large that clone() calls take too long to complete
# when we start we create a small process that just listens for commands to execute
# the multiprocessing python module has a similar approach available
#
# protocol
# client --> server : send tuple(*args, **kwargs) for Popen command
# client --> server : send bytes for stdin (if stdin is PIPE)
# client --> server : send tuple(*args, **kwargs) for communicate or wait
# server --> client : send stdout, stderr, returncode and exception
#

#
# NOTE this can only be used to execute single commands
# you cannot use this library if you want to chain commands together
#


import atexit
import datetime
import io
import logging
import os
import pickle
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

from multiprocessing import Process, Event

import saq
from saq.error import report_exception

# the global server all processes and threads share
SP_SERVER = None

# operating modes
MODE_CLIENT = 'client'
MODE_SERVER = 'server'

# available for import
PIPE = subprocess.PIPE
DEVNULL = subprocess.DEVNULL
STDOUT = subprocess.STDOUT
TimeoutExpired = subprocess.TimeoutExpired

MODE_TEXT = 1
MODE_BINARY = 2

# stdin reader thread timeout (in seconds)
STDIN_READER_TIMEOUT = 5

# default data block size (64K)
BLOCK_SIZE = 64 * 1024

# number of bytes we'll store in memory reading from stderr before we start storing in file
STDERR_BYTE_LIMIT = 1024 * 1024 # 1MB

class RemoteConnection(object):
    """Utility class the bundles everything a connection handles. Includes cleanup."""
    def __init__(self, sock):
        # flags for when stdin, stdout and stderr are pipes
        self.stdin_is_pipe = False
        self.stdout_is_pipe = False
        self.stderr_is_pipe = False

        # the mode of the pipes (binary or text)
        self.pipe_mode = MODE_BINARY

        # communcation socket to client
        self.sock = sock

        # reference to the Process object
        self.p = None

        # stderr buffer
        self.stderr_buffer = [] # of bytearray

        # tempfile.TemporaryFile object for stderr overflow data
        self.stderr_fp = None

        # reader threads for stdout and stderr
        self.stdout_reader_thread = None
        self.stderr_reader_thread = None

    def handle_request_execute(self):
        args, kwargs = pickle.loads(read_data_block(self.sock))
        logging.debug("got job args({}) kwargs({})".format(args, kwargs))

        # we always want to be able to kill the entire process tree it creates
        kwargs['start_new_session'] = True

        self.stdin_is_pipe = 'stdin' in kwargs and kwargs['stdin'] == PIPE
        self.stdout_is_pipe = 'stdout' in kwargs and kwargs['stdout'] == PIPE
        self.stderr_is_pipe = 'stderr' in kwargs and kwargs['stderr'] == PIPE

        self.p = subprocess.Popen(*args, **kwargs)

        self.pipe_mode = MODE_BINARY
        if 'universal_newlines' in kwargs and kwargs['universal_newlines']:
            self.pipe_mode = MODE_TEXT

        # are we feeding stdin?
        if self.stdin_is_pipe:
            for data in iterate_data_blocks(self.sock):
                if self.pipe_mode == MODE_TEXT:
                    data = data.decode()

                try:
                    self.p.stdin.write(data)
                except OSError as e:
                    # copy-pasta from python's communicate() call
                    if e.errno == errno.EPIPE:
                        # communicate() should ignore pipe full error
                        break
                    # skipping this for now... XXX
                    #elif (e.errno == errno.EINVAL
                          #and self.poll() is not None):
                        # Issue #19612: stdin.write() fails with EINVAL
                        # if the process already exited before the write
                        #pass
                    else:
                        raise

            # we're done with stdin at this point
            try:
                self.p.stdin.close()
            except Exception as e:
                logging.error("unable to close process stdin: {}".format(e))

        # read parameters for communicate (or wait)
        c_args, c_kwargs = pickle.loads(read_data_block(self.sock))

        logging.debug("waiting for args {} kwargs {} to complete".format(args, kwargs))
        timeout_exception = None

        # what we do here is pretty similar to what communicate() does
        # except that we don't want to keep storing stuff into memory
        # if stdout (or stderr) get too big
        # but if it stays small then we want to just use memory

        def _stdout_reader_routine():
            # since stdout is the first thing to get sent to the client
            # we can just directly send it right away
            logging.debug("sending stdout")
            while True:
                if self.p is None:
                   break

                #logging.debug("MARKER: read stdout")
                data = self.p.stdout.read(BLOCK_SIZE)
                if len(data) == 0:
                    break

                if self.pipe_mode == MODE_TEXT:
                    data = data.encode()

                send_data_block(self.sock, data)

            send_block0(self.sock)
            logging.debug("finished sending stdout")

        def _stderr_reader_routine():
            # so for stderr we go ahead and start reading into memory
            # if we get too big we start writing it to file instead
            bytes_read = 0

            while True:
                if self.p is None:
                    break

                #logging.debug("MARKER: read stderr")
                data = self.p.stderr.read(BLOCK_SIZE)
                if len(data) == 0:
                    break

                if self.pipe_mode == MODE_TEXT:
                    data = data.encode()

                bytes_read += len(data)

                # have we read enough bytes to start writing to file?
                if self.stderr_fp is None and bytes_read > STDERR_BYTE_LIMIT:
                    logging.debug("switch to file storage for stderr")
                    self.stderr_fp = tempfile.TemporaryFile(suffix='stderr_', dir=saq.TEMP_DIR)

                # we are writing to file at this point?
                if self.stderr_fp:
                    self.stderr_fp.write(data)
                    continue

                # otherwise we store it in memory
                self.stderr_buffer.append(data)

        if self.stdout_is_pipe:
            self.stdout_reader_thread = threading.Thread(target=_stdout_reader_routine)
            self.stdout_reader_thread.start()
        if self.stderr_is_pipe:
            self.stderr_reader_thread = threading.Thread(target=_stderr_reader_routine)
            self.stderr_reader_thread.start()

        # wait for both threads to join
        # handle the timeout here if specified
        timeout = None
        if 'timeout' in c_kwargs:
            timeout = c_kwargs['timeout']

        # keep track of when we start waiting
        start = datetime.datetime.now()

        if self.stdout_is_pipe:
            self.stdout_reader_thread.join(timeout=timeout)
            if self.stdout_reader_thread.is_alive():
                timeout_exception = TimeoutExpired(args, timeout) # timeout is passed onto client

        if timeout_exception is None and self.stderr_is_pipe:
            # the amount of time we wait here is the timeout minus how long we've already waited
            stderr_timeout = timeout
            if stderr_timeout:
                stderr_timeout = timeout - (datetime.datetime.now() - start).total_seconds()
                if stderr_timeout < 0:
                    stderr_timeout = 0

            self.stderr_reader_thread.join(timeout=stderr_timeout)
            if self.stderr_reader_thread.is_alive():
                timeout_exception = TimeoutExpired(args, timeout)

        # did we timeout?
        if timeout_exception:
            # kill the running process
            if self.p:
                try:
                    logging.warning("process {} timed out after {} seconds".format(self.p, timeout))
                    os.killpg(os.getpgid(self.p.pid), signal.SIGKILL)
                    #self.p.kill()
                    self.p.wait()
                except Exception as e:
                    logging.error("unable to kill args {} kwargs {} pid {}: {}".format(
                                  args, kwargs, self.p.pid, e))

            # the KILL should kill the pipes the threads are reading
            # wait for the threads to expire again
            if self.stdout_is_pipe:
                self.stdout_reader_thread.join(timeout=5)
                if self.stdout_reader_thread.is_alive():
                    logging.error("stdout reader failed to expire after kill")

            if self.stderr_is_pipe:
                self.stderr_reader_thread.join(timeout=5)
                if self.stderr_reader_thread.is_alive():
                    logging.error("stderr reader failed to expire after kill")

            if self.p:
                return_code = self.p.returncode
                self.p = None
        else:

            # otherwise we just reap the child process that finished
            return_code = None
            try:
                self.p.wait(timeout=timeout)
                return_code = self.p.returncode
                self.p = None
            except TimeoutExpired as e:
                timeout_exception = e

        # at this point stderr is already sent so send stderr next
        if self.stderr_is_pipe:
            logging.debug("sending {} data blocks for stderr".format(len(self.stderr_buffer)))
            for _buffer in self.stderr_buffer:
                send_data_block(self.sock, _buffer)

            self.stderr_buffer = [] # for gc

            # did we write any of stderr to file?
            if self.stderr_fp:
                # go back to the start of it and send it in chunks
                self.stderr_fp.seek(0)
                while True:
                    data = self.stderr_fp.read(BLOCK_SIZE)
                    if len(data) == 0:
                        break

                    send_data_block(self.sock, data)

            # finish stderr
            send_block0(self.sock)
            logging.debug("finished sending stderr")

        # finally send a pickle of a tuple of the return code and timeout exception
        logging.debug("sending last data block for return code {} timeout exception {}".format(
                     return_code, timeout_exception))
        _buffer = pickle.dumps((return_code, timeout_exception))
        send_data_block(self.sock, _buffer)
        logging.debug("finished communication")

    def cleanup(self):
        try:
            # make sure the socket is closed
            self.sock.close()
        except Exception as e:
            logging.error("unable to close socket connection: {}".format(e))
            report_exception()

        # make sure the process is dead and reaped
        try:
            if self.p:
                logging.warning("killing leftover child process pid {}".format(self.p.pid))
                os.killpg(os.getpgid(self.p.pid), signal.SIGKILL)
                #self.p.kill()
                self.p.wait()
        except Exception as e:
            logging.error("unable to kill leftover process: {}".format(e))
            report_exception()

        # make sure the reader threads are dead
        # not much we can do except report it
        if self.stdout_reader_thread and self.stdout_reader_thread.is_alive():
            logging.error("stdout reader thread is still alive (not good)")

        if self.stderr_reader_thread and self.stderr_reader_thread.is_alive():
            logging.error("stderr reader thread is still alive (not good)")

        # delete the stderr tempfile if it exists
        try:
            if self.stderr_fp:
                self.stderr_fp.close()
        except Exception as e:
            logging.error("unable to delete stderr tempfile: {}".format(e))
            report_exception()

def initialize_process_server(unix_socket=None):
    global SP_SERVER

    # if nothing is given then just use some randomly named file
    if unix_socket is None:
        import uuid
        unix_socket = os.path.join(saq.SAQ_HOME, 'var', '{}.socket'.format(str(uuid.uuid4())))

    SP_SERVER = SubprocessServer(unix_socket)
    SP_SERVER.start()

    atexit.register(stop_process_server)

def stop_process_server():
    if SP_SERVER is None:
        logging.warning("global subprocess server is not running")
        return

    SP_SERVER.stop()

def Popen(*args, **kwargs):
    if SP_SERVER is None:
        logging.debug("global subprocess server not used")

        # default to previous behavior
        return subprocess.Popen(*args, **kwargs)

    return SP_SERVER.Popen(*args, **kwargs)

#
# protocol routines
#

def read_n_bytes(s, n):
    """Reads n bytes from socket s.  Returns the bytearray of the data read."""
    bytes_read = 0
    _buffer = []
    while bytes_read < n:
        data = s.recv(n - bytes_read)
        if data == b'':
            break

        bytes_read += len(data)
        _buffer.append(data)

    result = b''.join(_buffer)
    if len(result) != n:
        logging.warning("expected {} bytes but read {}".format(n, len(result)))

    return b''.join(_buffer)

def read_data_block_size(s):
    """Reads the size of the next data block from the given socket."""
    size = struct.unpack('!I', read_n_bytes(s, 4))
    size = size[0]
    logging.debug("read command block size {}".format(size))
    return size

def read_data_block(s):
    """Reads the next data block from socket s. Returns the bytearray of the data portion of the block."""
    # read the size of the data block (4 byte network order integer)
    size = struct.unpack('!I', read_n_bytes(s, 4))
    size = size[0]
    #logging.debug("read command block size {}".format(size))
    # read the data portion of the data block
    return read_n_bytes(s, size)

def iterate_data_blocks(s):
    """Reads the next data block until a block0 is read."""
    while True:
        block = read_data_block(s)
        if len(block) == 0:
            raise StopIteration()
    
        yield block

def send_data_block(s, data):
    """Writes the given data to the given socket as a data block."""
    message = b''.join([struct.pack("!I", len(data)), data])
    #logging.debug("sending data block length {} ({})".format(len(message), message[:64]))
    s.sendall(message)

def send_block0(s):
    """Writes an empty data block to the given socket."""
    send_data_block(s, b'')

class SubprocessServerJob(object):
    """Client side object that acts like Popen but executes the commands from a different process."""
    def __init__(self, *args, **kwargs):
        # we only support kwargs constructor because we do some logic based on what is passed in
        if len(args) > 1:
            raise ValueError("process server only works with keyword arguments for Popen contructor")

        # becomes True after we've downloaded the results from the connection
        self.results_available = False

        # the cached results of the command
        self._stdin = None
        self._stdout = None
        self._stdout_fd = None # if a file descriptor was passed in
        self._stderr = None
        self._stderr_fd = None
        self._returncode = None

        self.exception = None # the exception that was thrown on the server side (if any)
        # this should be a TimeoutExpired exception

        # connection to the process server (unix socket)
        self.connection = None

        # command arguments
        self.command_args = args
        self.command_kwargs = kwargs

        # the Popen object we use if networking fails
        self.p = None

        # when we are passing stdin data we need a reader thread that passes it through
        self.stdin_reader_pipe = None
        self.stdin_reader_thread = None
        # a timestamp of stdin reader thread activity
        self.stdin_timestamp = None
        # set to true once we've finished stdin
        self.stdin_completed = False

        # what mode are the pipes in?
        self.pipe_mode = MODE_BINARY
        if 'universal_newlines' in kwargs and kwargs['universal_newlines']:
            self.pipe_mode = MODE_TEXT

    def __getattr__(self, name):
        """If we fell back to just using Popen then we pass requests for properties we don't know
           on to that object instead."""
        if self.p:
            return getattr(p, name)

        raise AttributeError()

    @property
    def returncode(self):
        if self.p:
            return self.p.returncode

        return self._returncode

    @property
    def stdout(self):
        if self.p:
            return self.p.stdout

        return self._stdout

    @property
    def stderr(self):
        if self.p:
            return self.p.stderr

        return self._stderr

    @property
    def stdin(self):
        if self.p:
            return self.p.stdin

        return self._stdin

    def execute(self):
        try:
            socket_path = SP_SERVER.unix_socket
            logging.debug("connecting to {}".format(socket_path))
            self.connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.connection.connect(socket_path)

            # make a copy because we're going to modify it before we send it
            kwargs = self.command_kwargs.copy()

            # if stdout or stderr are file descriptors then we need to do PIPE on the other side
            # and then automatically write to these file descriptors
            if 'stdout' in kwargs and isinstance(kwargs['stdout'], io.IOBase):
                logging.debug("detection stdout is file stream")
                self._stdout_fd = kwargs['stdout']
                kwargs['stdout'] = PIPE

            if 'stderr' in kwargs and isinstance(kwargs['stderr'], io.IOBase):
                logging.debug("detection stderr is file stream")
                self._stderr_fd = kwargs['stderr']
                kwargs['stderr'] = PIPE

            # send the parameters for Popen
            send_data_block(self.connection, pickle.dumps((self.command_args, kwargs)))

            if 'stdin' in kwargs and kwargs['stdin'] == PIPE:
                self.stdin_reader_pipe, self._stdin = os.pipe()

                # is stdin in text mode?
                if self.pipe_mode == MODE_TEXT:
                    read_mode = 'r'
                    write_mode = 'w'
                else:
                    read_mode = 'rb'
                    write_mode = 'wb'

                self.stdin_reader_pipe = os.fdopen(self.stdin_reader_pipe, read_mode)
                self._stdin = os.fdopen(self._stdin, write_mode)

                self.stdin_reader_thread = threading.Thread(target=self.stdin_reader_loop)
                self.stdin_reader_thread.daemon = True
                self.stdin_reader_thread.start()

        except Exception as e:
            logging.error("unable to send request for args {} kwargs {}: {}".format(
                          self.command_args, self.command_kwargs, e))
            report_exception()

            # if this fails then we just run it ourselves
            self.p = subprocess.Popen(*self.command_args, **self.command_kwargs)

    def stdin_reader_loop(self):
        try:
            while True:
                data = self.stdin_reader_pipe.read(BLOCK_SIZE)
                if len(data) == 0:
                    break

                logging.debug("read {} bytes from stdin".format(len(data)))
                self.stdin_timestamp = int(time.time()) # not used?

                # in text mode we translate to binary to send it over
                if self.pipe_mode == MODE_TEXT:
                    data = data.encode()

                # we send the data in chunks
                send_data_block(self.connection, data)

            # tell the server we're done sending by sending a block size of 0
            logging.debug("finished sending stdin data blocks (sending zero block)")
            send_block0(self.connection)

        except Exception as e:
            logging.error("unable to read from pipe: {}".format(e))
            report_exception()

        logging.debug("thread exited")

    def communicate(self, *args, **kwargs):
        if self.p:
            return self.p.communicate()

        self.complete_stdin()

        # download the results if they are not available yet
        if not self.results_available:
            self.download_results(*args, **kwargs)

        if self.exception:
            # we only raise this once then we're done with it
            # this is to suppose cases where another call to communicate *after* a Timeout exception is caught
            e = self.exception
            self.exception = None
            raise e

        # did we end up running it ourselves?
        if self.p:
            return self.p.communicate()

        # return the results we downloaded
        return self.stdout, self.stderr

    def wait(self, *args, **kwargs):
        if self.p:
            return self.p.wait()

        self.complete_stdin()

        if not self.results_available:
            self.download_results(*args, **kwargs)

        # did we end up running it ourselves?
        if self.p:
            return self.p.wait()

    def complete_stdin(self):
        if self.stdin is not None:
            if self.stdin_completed:
                return

            self.stdin_completed = True

            try:
                # we're done writing to stdin at this point
                # closing it will cause the reader thread to finish
                self.stdin.close()
            except Exception as e:
                logging.error("unable to call close in stdin: {}".format(e))
                report_exception()

            # wait for the stdin reader thread to exit
            self.stdin_reader_thread.join(STDIN_READER_TIMEOUT)
            if self.stdin_reader_thread.is_alive():
                logging.error("stdin reader thread (server side) is still alive (not good)")

    def download_results(self, *args, **kwargs):
        try:
            # send the parameters for communicate or wait
            send_data_block(self.connection, pickle.dumps((args, kwargs)))

            # if stdout is a PIPE (or a file descriptor) then we expect a stream of data blocks next
            if self._stdout_fd is not None or ( 'stdout' in self.command_kwargs 
                                                and self.command_kwargs['stdout'] == PIPE):

                _buffer = []
                logging.debug("reading stdout stream")
                for data in iterate_data_blocks(self.connection):
                    # are we in text mode?
                    if self.pipe_mode == MODE_TEXT:
                        data = data.decode()

                    # are we writing these to a file?
                    if self._stdout_fd:
                        self._stdout_fd.write(data)
                    else:
                        _buffer.append(data)

                logging.debug("finished reading stdout stream")

                if _buffer:
                    if self.pipe_mode == MODE_TEXT:
                        self._stdout = ''.join(_buffer)
                    else:
                        self._stdout = b''.join(_buffer)

                    _buffer = []
                else:
                    if self.pipe_mode == MODE_TEXT:
                        self._stdout = ''
                    else:
                        self._stdout = b''

                if self._stdout_fd:
                    self._stdout_fd = None
                    self._stdout = None

            # same goes for stderr
            if self._stderr_fd is not None or ( 'stderr' in self.command_kwargs 
                                                and self.command_kwargs['stderr'] == PIPE):

                _buffer = []
                logging.debug("reading stderr stream")
                for data in iterate_data_blocks(self.connection):
                    # are we in text mode?
                    if self.pipe_mode == MODE_TEXT:
                        data = data.decode()

                    # are we writing these to a file?
                    if self._stderr_fd:
                        self._stderr_fd.write(data)
                    else:
                        _buffer.append(data)

                logging.debug("finished reading stderr stream")

                if _buffer:
                    if self.pipe_mode == MODE_TEXT:
                        self._stderr = ''.join(_buffer)
                    else:
                        self._stderr = b''.join(_buffer)

                    _buffer = []
                else:
                    if self.pipe_mode == MODE_TEXT:
                        self._stderr = ''
                    else:
                        self._stderr = b''

                if self._stderr_fd:
                    self._stderr_fd = None
                    self._stderr = None
            
            # get the last data block
            logging.debug("reading last data block")
            (self._returncode, self.exception ) = pickle.loads(read_data_block(self.connection))
            self.results_available = True
            logging.debug("finished data transfer")

        except Exception as e:
            logging.error("unable to download results for args {} kwargs {}: {}".format(
                          self.command_args, self.command_kwargs, e))
            report_exception()

            # if this fails then we just run it ourselves
            self.p = subprocess.Popen(*self.command_args, **self.command_kwargs)
            
        finally:
            try:
                self.connection.close()
            except Exception as e:
                logging.error("unable to close connection: {}".format(e))
                report_exception()

    def __str__(self):
        return "SubprocessServerJob({})".format(self.job_id)

class SubprocessServer(object):
    def __init__(self, unix_socket):
        # communication point for this subprocess server
        self.unix_socket = unix_socket
        # multiprocessing.Process object of child (server) process
        self.child_process = None
        # control shutdown flag (set by SIGTERM)
        self.shutdown = False
        # server socket for communication with clients
        self.server_socket = None
        # set when we are initialized and ready
        self.ready_event = None

    @property
    def mode(self):
        return MODE_CLIENT if self.child_process is None else MODE_SERVER

    def start(self):
        self.ready_event = Event()
        self.child_process = Process(target=self.server_loop)
        self.child_process.start()
        self.ready_event.wait()
        logging.info("started subprocess server pid {}".format(self.child_process.pid))

    def stop(self):
        if self.child_process is None:
            logging.error("child process does not exist")
            return

        logging.info("shutting down process server pid {}...".format(self.child_process.pid))

        try:
            self.child_process.terminate()

            # connect to move it past the connect call
            # TODO do we need a sleep here ? (is the signal async?)
            try:
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.connect(self.unix_socket)
            except:
                logging.error("unable to connect to {} to close connection: {}".format(self.socket_path, e))
            finally:
                try:
                    s.close()
                except:
                    pass

            self.child_process.join(5)
            if self.child_process.is_alive():
                raise RuntimeError("unable to stop child process {}".format(self.child_process.pid))
        except Exception as e:
            logging.error("unable to terminate child process pid {}: {}".format(self.child_process.pid, e))
            try:
                logging.warning("sending SIGKILL to {}".format(self.child_process.pid))
                os.kill(self.child_process.pid, signal.SIGKILL)
            except Exception as e:
                logging.error("unable to kill process {}: {}".format(self.child_process.pid, e))

        try:
            os.remove(self.unix_socket)
        except Exception as e:
            logging.error("unable to delete unix socket {}: {}".format(self.unix_socket, e))
            report_exception()

        logging.info("process server stopped")

    def initialize_signals(self):
        # catch SIGTERM for controlled shutdown
        def _handler(signum, frame):
            self.shutdown = True

        signal.signal(signal.SIGTERM, _handler)

    def initialize_socket(self):
        # start server socket for receiving connections
        self.server_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        #socket_path = os.path.join(saq.SAQ_HOME, saq.CONFIG['process_server']['unix_socket'])
        if os.path.exists(self.unix_socket):
            try:
                os.remove(self.unix_socket)
            except Exception as e:
                logging.error("unable to remove {}".format(socket_path))
        self.server_socket.bind(self.unix_socket)
        # TODO change perms on socket
        self.server_socket.listen(50)

    def server_loop(self):
        self.initialize_signals()

        while not self.shutdown:
            self.initialize_socket()

            # this will let the parent process continue starting up
            if not self.ready_event.is_set():
                self.ready_event.set()

            while not self.shutdown:
                try:
                    self.execute_loop()
                except Exception as e:
                    if not self.shutdown:
                        logging.error("uncaught exception: {}".format(e))
                        report_exception()
                        time.sleep(1)

    def execute_loop(self):
        # get the next connection
        connection, client_address = self.server_socket.accept()
        logging.debug("got new connection")

        connection = RemoteConnection(connection)

        # handle this connection on a new thread
        t = threading.Thread(target=self.handle_request, args=(connection,), name="SubprocessServer Client Handler")
        t.start()

    def handle_request(self, connection):
        try:
            connection.handle_request_execute()
        except Exception as e:
            logging.error("unable to handle request: {}".format(e))
            report_exception()
        finally:
            connection.cleanup()

    def Popen(self, *args, **kwargs):
        """Passes *args and **kwargs off to subprocess.Popen via multiprocess communication."""
        result = SubprocessServerJob(*args, **kwargs)
        result.execute()
        return result

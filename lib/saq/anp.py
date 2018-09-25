# vim: ts=4:sw=4:et:cc=120

#
# ACE Network Protocol
#
# routines and functions implementing the custom network protocol between ACE nodes
#

__all__ = [
    'ANPException',
    'ANPSocket',
    'ANPCommandEXIT',
    'ANPCommandREGISTER',
    'ANPCommandOK',
    'ANPCommandERROR',
    'ANPCommandPING',
    'ANPCommandPONG',
    'ANPCommandAVAILABLE',
    'ANPCommandCOPY_FILE',
    'ANPCommandPROCESS',
    'ANP_COMMAND_EXIT',
    'ANP_COMMAND_REGISTER',
    'ANP_COMMAND_OK',
    'ANP_COMMAND_ERROR',
    'ANP_COMMAND_PING',
    'ANP_COMMAND_PONG',
    'ANP_COMMAND_AVAILABLE',
    'ANP_COMMAND_COPY_FILE',
    'ANP_COMMAND_PROCESS',
    'ANP_COMMAND_STRING',
    'ANP_CLASS_LOOKUP',
    'ACENetworkProtocolServer',
    'anp_connect',
]

import logging
import os.path
import socket
import threading
import time
import struct
import io

import saq
from saq.error import report_exception

DEFAULT_PORT = 41433 # AC3

# struct data formats
UINT_FORMAT = '!I'
ULONG_FORMAT = '!Q'

class ANPException(Exception):
    pass

# base network I/O routines

class ANPSocket(object):

    def __init__(self, s):
        # the socket speaking ANP
        self.s = s

    def close_socket(self):
        try:
            self.s.shutdown(socket.SHUT_RDWR)
        except Exception as e:
            pass

        try:
            self.s.close()
        except Exception as e:
            pass

    def read_n_bytes(self, count, fp=None):
        """Read N bytes. If fp is None then return the result, otherwise write the results to fp."""
        assert count

        logging.debug("reading {} bytes".format(count))

        bytes_read = 0
        byte_buffer = []
        while bytes_read < count:
            # get the right chunk size - we're trying to avoid reading the whole thing into memory
            bytes_left = count - bytes_read
            chunk_size = io.DEFAULT_BUFFER_SIZE if io.DEFAULT_BUFFER_SIZE < count else count
            data = self.s.recv(chunk_size)

            if len(data) == 0 and bytes_read == 0:
                logging.debug("socket closed normally")
                return None # socket closed normally
                    
            if len(data) == 0:
                raise ANPException("expected {} more bytes but got end of stream".format(bytes_left))

            if fp is not None:
                fp.write(data)
            else:
                byte_buffer.append(data)

            bytes_read += len(data)

        if fp is None:
            return b''.join(byte_buffer)

    def write_n_bytes(self, count, data=None, fp=None):
        """Writes N bytes. If fp is None then the data parameter is expected to contain the data to write. Otherwise,
           the data is read from the file descriptor fp. The count parameter is expected to contain the total number
           of bytes to write."""

        if data is not None:
            # make sure we're not making a bunch of copies as we write
            data = memoryview(data)

        bytes_written = 0
        while bytes_written < count:
            bytes_left = count - bytes_written
            chunk_size = io.DEFAULT_BUFFER_SIZE if io.DEFAULT_BUFFER_SIZE < count else count

            if data is not None:
                chunk = data[bytes_written:bytes_written + chunk_size]
            else:
                chunk = fp.read(chunk_size)
                if chunk == b'':
                    raise ANPException("reached EOF when reading file")

            if len(chunk) != chunk_size:
                raise ANPException("expected {} bytes but got {} bytes".format(chunk_size, len(chunk)))

            # XXX this should not happen    
            if len(chunk) == 0:
                raise ANPException("have 0 bytes to send!?")

            bytes_sent = self.s.send(chunk)
            bytes_written += len(chunk)

    def read_uint(self):
        """Reads a UINT from the socket. Returns None if the socket closed."""
        data = self.read_n_bytes(4)
        if data is None:
            return None

        return struct.unpack(UINT_FORMAT, data)[0]

    def read_ulong(self):
        """Reads a ULONG from the socket. Returns None if the socket closed."""
        data = self.read_n_bytes(8)
        if data is None:
            return None

        return struct.unpack(ULONG_FORMAT, data)[0]

    def read_data(self):
        data_length = self.read_ulong()
        if data_length is None:
            return None

        return self.read_n_bytes(data_length)

    def read_string(self):
        string_length = self.read_uint()
        if string_length is None:
            return None

        return self.read_n_bytes(string_length).decode('utf16')

    def write_uint(self, value):
        self.write_n_bytes(4, struct.pack(UINT_FORMAT, value))

    def write_ulong(self, value):
        self.write_n_bytes(8, struct.pack(ULONG_FORMAT, value))

    def write_data(self, value):
        self.write_uint(len(value))
        self.write_n_bytes(len(value), value)

    def write_string(self, value):
        self.write_data(value.encode('utf16'))

    #
    # OO command abstraction
    #

    def recv_message(self):

        # read the 4 byte command
        command = self.read_uint()

        if command is None:
            # connetion was closed
            return None
        
        # return the ANPMessage object corresponding to this command
        try:
            result = ANP_CLASS_LOOKUP[command](self)
        except KeyError:
            raise ANPException("unknown command {}".format(command))

        result.recv_parameters(self)
        return result

    def send_message(self, message):

        # send the 4 byte command
        self.write_uint(message.command)

        # send any required parameters for the command
        message.send_parameters(self)

# utility class for clients
def anp_connect(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    return ANPSocket(s)

# abstract class
class ANPMessage(object):
        
    def __init__(self, command, *args, **kwargs):
        # the ANP_COMMAND_* command id for this command
        self.command = command

    def __str__(self):
        return ANP_COMMAND_STRING[self.command]

    def recv_parameters(self, anp):
        """Reads the rest of the data for the command. By default this does nothing, which would be the default 
           behavior for commands with no parameters."""
        pass

    def send_parameters(self, anp):
        """Send any parameters required for this command. By default this does nothing, which be be the default
           behavior for commands with no parameters."""
        pass

class ANPCommandEXIT(ANPMessage):
    def __init__(self, *args, **kwargs):
        super().__init__(ANP_COMMAND_EXIT, *args, **kwargs)

class ANPCommandREGISTER(ANPMessage):
    def __init__(self, *args, **kwargs):
        super().__init__(ANP_COMMAND_REGISTER, *args, **kwargs)

class ANPCommandOK(ANPMessage):
    def __init__(self, *args, **kwargs):
        super().__init__(ANP_COMMAND_OK, *args, **kwargs)

class ANPCommandERROR(ANPMessage):
    def __init__(self, error_message, *args, **kwargs):
        super().__init__(ANP_COMMAND_ERROR, *args, **kwargs)
        self.error_message = error_message

    def recv_parameters(self, anp):
        self.error_message = anp.read_string()

    def send_parameters(self, anp):
        anp.write_string(self.error_message)

class ANPCommandPING(ANPMessage):
    def __init__(self, message, *args, **kwargs):
        super().__init__(ANP_COMMAND_PING, *args, **kwargs)
        self.message = message

    def recv_parameters(self, anp):
        self.message = anp.read_string()

    def send_parameters(self, anp):
        anp.write_string(self.message)

class ANPCommandPONG(ANPMessage):
    def __init__(self, message, *args, **kwargs):
        super().__init__(ANP_COMMAND_PONG, *args, **kwargs)
        self.message = message

    def recv_parameters(self, anp):
        self.message = anp.read_string()

    def send_parameters(self, anp):
        anp.write_string(self.message)

class ANPCommandAVAILABLE(ANPMessage):
    def __init__(self, *args, **kwargs):
        super().__init__(ANP_COMMAND_AVAILABLE, *args, **kwargs)

class ANPCommandCOPY_FILE(ANPMessage):
    def __init__(self, path, source_path=None, *args, **kwargs):
        super().__init__(ANP_COMMAND_COPY_FILE, *args, **kwargs)
        self.path = path
        self.source_path = source_path

    def recv_parameters(self, anp):
        self.path = anp.read_string()

        # TODO make sure this relative path is valid
        # like make sure the target directory is valid for COPY_FILE command destinations

        full_path = os.path.join(saq.SAQ_HOME, self.path)
        logging.debug("target file is {}".format(full_path))
        dir_path = os.path.dirname(full_path)
        if not os.path.isdir(dir_path):
            logging.debug("creating directory {}".format(dir_path))
            os.makedirs(dir_path)

        if os.path.exists(full_path):
            logging.warning("target file {} already exists".format(full_path))

        byte_count = anp.read_ulong()
        logging.debug("reading {} bytes into {}".format(byte_count, full_path))
        with open(full_path, 'wb') as fp:
            anp.read_n_bytes(byte_count, fp=fp)

    def send_parameters(self, anp):
        anp.write_string(self.path)
        byte_count = os.path.getsize(self.source_path)
        anp.write_ulong(byte_count)
        with open(self.source_path, 'rb') as fp:
            anp.write_n_bytes(byte_count, fp=fp)

class ANPCommandPROCESS(ANPMessage):
    def __init__(self, target, *args, **kwargs):
        super().__init__(ANP_COMMAND_PROCESS, *args, **kwargs)
        self.target = target

    def recv_parameters(self, anp):
        self.target = anp.read_string()

    def send_parameters(self, anp):
        anp.write_string(self.target)

# the list of commands available
ANP_COMMAND_EXIT = 1
ANP_COMMAND_REGISTER = 2
ANP_COMMAND_OK = 3
ANP_COMMAND_ERROR = 4
ANP_COMMAND_PING = 5
ANP_COMMAND_PONG = 6
ANP_COMMAND_AVAILABLE = 7
ANP_COMMAND_COPY_FILE = 8
ANP_COMMAND_PROCESS = 9

ANP_COMMAND_STRING = {
    ANP_COMMAND_EXIT: 'exit',
    ANP_COMMAND_REGISTER: 'register',
    ANP_COMMAND_OK: 'ok',
    ANP_COMMAND_ERROR: 'error',
    ANP_COMMAND_PING: 'ping',
    ANP_COMMAND_PONG: 'pong',
    ANP_COMMAND_AVAILABLE: 'available',
    ANP_COMMAND_COPY_FILE: 'copy_file',
    ANP_COMMAND_PROCESS: 'process',
}

ANP_CLASS_LOOKUP = {
    ANP_COMMAND_EXIT: ANPCommandEXIT,
    ANP_COMMAND_REGISTER: ANPCommandREGISTER,
    ANP_COMMAND_OK: ANPCommandOK,
    ANP_COMMAND_ERROR: ANPCommandERROR,
    ANP_COMMAND_PING: ANPCommandPING,
    ANP_COMMAND_PONG: ANPCommandPONG,
    ANP_COMMAND_AVAILABLE: ANPCommandAVAILABLE,
    ANP_COMMAND_COPY_FILE: ANPCommandCOPY_FILE,
    ANP_COMMAND_PROCESS: ANPCommandPROCESS,
}

#
# more abstract utility network I/O routiens
#

class ACENetworkProtocolServer(object):
    def __init__(self, command_handler):

        # the function that gets called when a command is received
        self.command_handler = command_handler

        # server socket objects for TCP communication
        self.tcp_server_thread = None
        self.tcp_server_socket = None
        self.tcp_server_socket_host = saq.CONFIG['anp_server']['listen_address']
        self.tcp_server_socket_port = saq.CONFIG['anp_server'].getint('listen_port')

        # list of all the threads processing tcp client requests
        self.tcp_client_threads = []

        # global event for shutdown
        self.control_event = None

    def start(self):
        self.control_event = threading.Event()
        self.tcp_server_thread = threading.Thread(target=self.tcp_server_loop, name="TCP Server")
        self.tcp_server_thread.start()

    def stop(self):
        self.control_event.set()
        logging.info("waiting for tcp server to stop...")
        self.tcp_server_thread.join()

    def tcp_server_loop(self):
        while not self.control_event.is_set():
            try:
                self.tcp_server_execute()
                if self.tcp_client_threads:
                    logging.debug("{} tcp connections active".format(len(self.tcp_client_threads)))
            except Exception as e:
                logging.error("unable to execute tcp server: {}".format(e))
                report_exception()

                self.close_tcp_server_socket()

            time.sleep(1)

        self.close_tcp_server_socket()

    def tcp_server_execute(self):
        # do we need to start listening for new connections?
        # if something goes wrong we just shut down the socket and try again
        if not self.tcp_server_socket:
            self.tcp_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.tcp_server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.tcp_server_socket.settimeout(1)
            self.tcp_server_socket.bind((self.tcp_server_socket_host, self.tcp_server_socket_port))
            self.tcp_server_socket.listen(5)

        # get the next client connection
        try:
            logging.debug("listening for connections on {} port {}".format(self.tcp_server_socket_host,
                                                                           self.tcp_server_socket_port))
            client_socket, client_address = self.tcp_server_socket.accept()
            logging.info("got connection from {}".format(client_address[0]))
        except socket.timeout:
            return

        # handle the client connection on another thread
        client_thread = threading.Thread(target=self.tcp_client_loop, 
                                         name="TCP Client ({})".format(client_address[0]), 
                                         args=(client_socket, client_address))
        self.tcp_client_threads.append(client_thread)
        client_thread.start()

    def tcp_client_loop(self, client_socket, client_address):
        socket_closed = False
        anp = ANPSocket(client_socket)
        while not socket_closed and not self.control_event.is_set():
            try:
                self.tcp_client_execute(anp, client_address)
            except Exception as e:
                logging.warning("error when handling client request: {}".format(e))
                #report_exception() # TODO remove this
                break

        try:
            client_socket.shutdown()
        except:
            pass

        self.tcp_client_threads.remove(threading.current_thread())

    def tcp_client_execute(self, anp, client_address):
        command = anp.recv_message()
        if command is None:
            return False

        logging.info("received command {} from {}".format(command, client_address))

        if command.command == ANP_COMMAND_EXIT:
            return False

        try:
            self.command_handler(anp, command)
        except Exception as e:
            logging.error("error processing command {}: {}".format(command, e))
            report_exception()

    def close_tcp_server_socket(self):
        if self.tcp_server_socket:
            try:
                self.tcp_server_socket.close()
            except Exception as e:
                logging.error("unable to close tcp server socket: {}".format(e))
            finally:
                self.tcp_server_socket = None

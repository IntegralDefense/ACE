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
    'ANPCommandBUSY',
    'ANP_COMMAND_EXIT',
    'ANP_COMMAND_REGISTER',
    'ANP_COMMAND_OK',
    'ANP_COMMAND_ERROR',
    'ANP_COMMAND_PING',
    'ANP_COMMAND_PONG',
    'ANP_COMMAND_AVAILABLE',
    'ANP_COMMAND_COPY_FILE',
    'ANP_COMMAND_PROCESS',
    'ANP_COMMAND_BUSY',
    'ANP_COMMAND_STRING',
    'ANP_CLASS_LOOKUP',
    'ACENetworkProtocolServer',
    'anp_connect',
    'DEFAULT_CHUNK_SIZE',
]

import io
import logging
import os.path
import socket
import ssl
import struct
import threading
import time

import saq
from saq.crypto import encrypt_chunk, decrypt_chunk
from saq.error import report_exception

DEFAULT_PORT = 41433 # AC3

# the size of the memory buffer when reading/writing in chunks of data
DEFAULT_CHUNK_SIZE = 256 * 1024 # 256K

# a chunk of size 0 indicates it is the last chunk
LAST_CHUNK = b''

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

    def read_n_bytes(self, count):
        """Read N bytes from the socket."""
        #logging.debug("MARKER: reading {} bytes".format(count))

        bytes_read = 0
        byte_buffer = bytearray(count)

        while bytes_read < count:
            bytes_left = count - bytes_read
            chunk_size = io.DEFAULT_BUFFER_SIZE if io.DEFAULT_BUFFER_SIZE < count else count
            data = self.s.recv(chunk_size)

            if len(data) == 0 and bytes_read == 0:
                return None # socket closed normally
                    
            if len(data) == 0:
                raise ANPException("expected {} more bytes but got end of stream".format(bytes_left))

            byte_buffer[bytes_read:bytes_read + count] = data
            bytes_read += len(data)

        return bytes(byte_buffer)

    def write_n_bytes(self, data):
        #logging.debug("MARKER: writing {} bytes".format(len(data)))
        # make sure we're not making a bunch of copies as we write
        data = memoryview(data)
        bytes_written = 0

        while bytes_written < len(data):
            bytes_left = len(data) - bytes_written
            chunk_size = io.DEFAULT_BUFFER_SIZE if io.DEFAULT_BUFFER_SIZE < len(data) else len(data)
            bytes_sent = self.s.send(data[bytes_written:bytes_written + chunk_size])
            bytes_written += bytes_sent

    def read_uint(self):
        """Reads a UINT from the socket. Returns None if the socket closed."""
        data = self.read_n_bytes(struct.calcsize(UINT_FORMAT))
        if data is None:
            return None

        return struct.unpack(UINT_FORMAT, data)[0]

    def read_ulong(self):
        """Reads a ULONG from the socket. Returns None if the socket closed."""
        data = self.read_n_bytes(struct.calcsize(ULONG_FORMAT))
        if data is None:
            return None

        return struct.unpack(ULONG_FORMAT, data)[0]

    def read_data(self):
        data_length = self.read_uint()
        if data_length is None:
            return None

        #logging.debug("MARKER: reading data block of {} bytes".format(data_length))
        return self.read_n_bytes(data_length)

    def read_string(self):
        _bytes = self.read_data()
        if _bytes is None:
            return None

        return _bytes.decode('utf16')

    def read_chunked_data(self, fp):
        """Reads a stream of chunked data into a file."""

        result = []
        while True:
            next_chunk = self.read_data()
            if next_chunk == LAST_CHUNK:
                break

            fp.write(next_chunk)

    def write_uint(self, value):
        self.write_n_bytes(struct.pack(UINT_FORMAT, value))

    def write_ulong(self, value):
        self.write_n_bytes(struct.pack(ULONG_FORMAT, value))

    def write_data(self, value):
        self.write_uint(len(value))
        if len(value) > 0:
            #logging.debug("MARKER: writing data block of {} bytes".format(len(value)))
            self.write_n_bytes(value)

    def write_string(self, value):
        #logging.debug("MARKER: writing string {}".format(value))
        self.write_data(value.encode('utf16'))

    def write_chunked_data(self, fp):
        """Writes the given file descriptor to the socket in chunks."""
        
        while True:
            chunk = fp.read(DEFAULT_CHUNK_SIZE)
            self.write_data(chunk)

            if chunk == b'':
                break

    #
    # OO command abstraction
    #

    def recv_message(self):

        # read the 4 byte command
        command = self.read_uint()

        if command is None:
            # connetion was closed
            return None

        #logging.debug("MARKER: read command byte {}".format(ANP_COMMAND_STRING[command]))
        
        # return the ANPMessage object corresponding to this command
        try:
            result = ANP_CLASS_LOOKUP[command]()
        except KeyError:
            raise ANPException("unknown command {}".format(command))

        result.recv_parameters(self)
        return result

    def send_message(self, message):

        # send the 4 byte command
        self.write_uint(message.command)

        #logging.debug("MARKER: sent command byte {}".format(ANP_COMMAND_STRING[message.command]))

        # send any required parameters for the command
        message.send_parameters(self)

        #logging.debug("MARKER: finished command {}".format(ANP_COMMAND_STRING[message.command]))

# utility class for clients
def anp_connect(host, port, ssl_ca_path=None, ssl_cert_path=None, ssl_key_path=None, ssl_hostname=None):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    if ssl_ca_path is None:
        ssl_ca_path = saq.CONFIG['anp_defaults']['ssl_ca_path']
    if ssl_cert_path is None:
        ssl_cert_path = saq.CONFIG['anp_defaults']['ssl_cert_path']
    if ssl_key_path is None:
        ssl_key_path = saq.CONFIG['anp_defaults']['ssl_key_path']
    if ssl_hostname is None:
        ssl_hostname = saq.CONFIG['anp_defaults']['ssl_hostname']

    ssl_ca_path = os.path.join(saq.SAQ_HOME, ssl_ca_path)
    ssl_cert_path = os.path.join(saq.SAQ_HOME, ssl_cert_path)
    ssl_key_path = os.path.join(saq.SAQ_HOME, ssl_key_path)

    context = ssl.create_default_context()

    if not os.path.exists(ssl_ca_path):
        logging.warning("missing ssl_ca_path {}".format(ssl_ca_path))
    if not os.path.exists(ssl_cert_path):
        logging.warning("missing ssl_cert_path {}".format(ssl_cert_path))
    if not os.path.exists(ssl_key_path):
        logging.warning("missing ssl_key_path {}".format(ssl_key_path))

    context.load_verify_locations(ssl_ca_path)
    context.load_cert_chain(ssl_cert_path, keyfile=ssl_key_path)

    s = context.wrap_socket(s, server_hostname=ssl_hostname)
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

class ANPCommandBUSY(ANPMessage):
    def __init__(self, *args, **kwargs):
        super().__init__(ANP_COMMAND_BUSY, *args, **kwargs)

class ANPCommandERROR(ANPMessage):
    def __init__(self, error_message=None, *args, **kwargs):
        super().__init__(ANP_COMMAND_ERROR, *args, **kwargs)
        self.error_message = error_message

    def recv_parameters(self, anp):
        self.error_message = anp.read_string()

    def send_parameters(self, anp):
        anp.write_string(self.error_message)

    def __str__(self):
        return '{} {}'.format(ANPMessage.__str__(self), self.error_message)

class ANPCommandPING(ANPMessage):
    def __init__(self, message=None, *args, **kwargs):
        super().__init__(ANP_COMMAND_PING, *args, **kwargs)
        self.message = message

    def recv_parameters(self, anp):
        self.message = anp.read_string()

    def send_parameters(self, anp):
        anp.write_string(self.message)

    def __str__(self):
        return '{} {}'.format(ANPMessage.__str__(self), self.message)

class ANPCommandPONG(ANPMessage):
    def __init__(self, message=None, *args, **kwargs):
        super().__init__(ANP_COMMAND_PONG, *args, **kwargs)
        self.message = message

    def recv_parameters(self, anp):
        self.message = anp.read_string()

    def send_parameters(self, anp):
        anp.write_string(self.message)

    def __str__(self):
        return '{} {}'.format(ANPMessage.__str__(self), self.message)

class ANPCommandAVAILABLE(ANPMessage):
    def __init__(self, *args, **kwargs):
        super().__init__(ANP_COMMAND_AVAILABLE, *args, **kwargs)

class ANPCommandCOPY_FILE(ANPMessage):
    def __init__(self, path=None, source_path=None, *args, **kwargs):
        super().__init__(ANP_COMMAND_COPY_FILE, *args, **kwargs)

        # the path to the file to be copied to the remote system
        self.source_path = source_path

        # target path the file will be copied to remotely
        self.path = path

    @property
    def path(self):
        return self._path
    
    @path.setter
    def path(self, value):
        # this must be relative to SAQ_HOME, if it's not then it will be made relative to SAQ_HOME
        if value is not None and os.path.isabs(value):
            if value.startswith(saq.SAQ_HOME):
                self._path = os.path.relpath(value, start=saq.SAQ_HOME)
        else:
            self._path = value

    def recv_parameters(self, anp):
        self.path = anp.read_string()

        # TODO make sure this relative path is valid
        # like make sure the target directory is valid for COPY_FILE command destinations

        #logging.info("MARKER: home {} path {}".format(saq.SAQ_HOME, self.path))
        full_path = os.path.join(saq.SAQ_HOME, self.path)
        logging.debug("target file is {}".format(full_path))
        dir_path = os.path.dirname(full_path)
        if not os.path.isdir(dir_path):
            logging.debug("creating directory {}".format(dir_path))
            os.makedirs(dir_path)

        if os.path.exists(full_path):
            logging.warning("target file {} already exists".format(full_path))

        with open(full_path, 'wb') as fp:
            anp.read_chunked_data(fp)

    def send_parameters(self, anp):
        anp.write_string(self.path)
        with open(self.source_path, 'rb') as fp:
            anp.write_chunked_data(fp)

    def __str__(self):
        return '{} {}'.format(ANPMessage.__str__(self), self.path)

class ANPCommandPROCESS(ANPMessage):
    def __init__(self, target=None, *args, **kwargs):
        super().__init__(ANP_COMMAND_PROCESS, *args, **kwargs)
        self.target = target

    def recv_parameters(self, anp):
        self.target = anp.read_string()

    def send_parameters(self, anp):
        anp.write_string(self.target)

    def __str__(self):
        return '{} {}'.format(ANPMessage.__str__(self), self.target)

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
ANP_COMMAND_BUSY = 10

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
    ANP_COMMAND_BUSY: 'busy',
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
    ANP_COMMAND_BUSY: ANPCommandBUSY,
}

#
# more abstract utility network I/O routiens
#

class ACENetworkProtocolServer(object):
    def __init__(self, listening_host, listening_port, command_handler, 
                 ssl_ca_path=None, ssl_key_path=None, ssl_cert_path=None):

        # the interface to listen on for client connections
        self.listening_host = listening_host
        self.listening_port = listening_port

        # the function that gets called when a command is received
        self.command_handler = command_handler

        if ssl_ca_path is None:
            ssl_ca_path = saq.CONFIG['anp_defaults']['ssl_ca_path']
        if ssl_key_path is None:
            ssl_key_path = saq.CONFIG['anp_defaults']['ssl_key_path']
        if ssl_cert_path is None:
            ssl_cert_path = saq.CONFIG['anp_defaults']['ssl_cert_path']

        # SSL certificate locations
        self.ssl_ca_path = os.path.join(saq.SAQ_HOME, ssl_ca_path)
        self.ssl_key_path = os.path.join(saq.SAQ_HOME, ssl_key_path)
        self.ssl_cert_path = os.path.join(saq.SAQ_HOME, ssl_cert_path)

        # and then the ssl context we're using for the server
        self.ssl_context = None

        # server socket objects for TCP communication
        self.tcp_server_thread = None
        self.tcp_server_socket = None
        self.tcp_server_socket_host = listening_host
        self.tcp_server_socket_port = listening_port

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

            #self.ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            self.ssl_context = ssl.create_default_context()
            self.ssl_context.check_hostname = False
            self.ssl_context.verify_mode = ssl.CERT_NONE

            #logging.debug("loading certificate chain certfile {} keyfile {}".format(
                         #os.path.join(saq.SAQ_HOME, self.config['ssl_cert_path']),
                         #os.path.join(saq.SAQ_HOME, self.config['ssl_key_path'])))

            if not os.path.exists(self.ssl_ca_path):
                logging.warning("missing ssl_ca_path file {}".format(self.ssl_ca_path))

            self.ssl_context.load_verify_locations(self.ssl_ca_path)

            if not os.path.exists(self.ssl_cert_path):
                logging.warning("missing ssl_cert_path file {}".format(self.ssl_cert_path))

            if not os.path.exists(self.ssl_key_path):
                logging.warning("missing key file {}".format(self.ssl_key_path))

            self.ssl_context.load_cert_chain(certfile=self.ssl_cert_path, keyfile=self.ssl_key_path)

            self.tcp_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.tcp_server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.tcp_server_socket.settimeout(1)
            self.tcp_server_socket.bind((self.tcp_server_socket_host, self.tcp_server_socket_port))
            self.tcp_server_socket = self.ssl_context.wrap_socket(self.tcp_server_socket, server_side=True)
            self.tcp_server_socket.listen(5)

            logging.debug("listening for connections on {} port {}".format(self.tcp_server_socket_host,
                                                                           self.tcp_server_socket_port))

        # get the next client connection
        try:
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
                if not self.tcp_client_execute(anp, client_address):
                    break
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
        # read the command issued by the client
        command = anp.recv_message()
        # did the connection die?
        if command is None:
            return False

        logging.info("received command {} from {}".format(command, client_address))

        # if we received the EXIT command then the server is NOT expected to send anything in response
        # and the socket should close
        if command.command == ANP_COMMAND_EXIT:
            return False # returning False causes the tcp client thread to close the socket and exit

        try:
            self.command_handler(anp, command)
            return True
        except Exception as e:
            logging.error("error processing command {}: {}".format(command, e))
            report_exception()
            return False

    def close_tcp_server_socket(self):
        if self.tcp_server_socket:
            try:
                self.tcp_server_socket.close()
            except Exception as e:
                logging.error("unable to close tcp server socket: {}".format(e))
            finally:
                self.tcp_server_socket = None

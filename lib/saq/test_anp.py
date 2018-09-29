# vim: sw=4:ts=4:et

import filecmp
import io
import logging
import os
import os.path
import random
import saq
import socket
import string
import threading
import time

from saq.anp import *
from saq.crypto import get_aes_key
from saq.test import *

ANP_SERVER_HOST = '127.0.0.1'
ANP_SERVER_PORT = 41433

class ANPTestCase(ACEBasicTestCase):

    def setUp(self, *args, **kwargs):
        super().setUp(*args, **kwargs)

        self.source_file = os.path.join('var', 'anp_sample_data.input')
        self.target_file = os.path.join('var', 'anp_sample_data.output')

        if os.path.exists(self.source_file):
            os.unlink(self.source_file)

        if os.path.exists(self.target_file):
            os.unlink(self.target_file)

        with open(self.source_file, 'wb') as fp:
            fp.write(os.urandom((DEFAULT_CHUNK_SIZE * 2) + 1))

        self.old_password = saq.ENCRYPTION_PASSWORD
        saq.ENCRYPTION_PASSWORD = None
    
    def tearDown(self, *args, **kwargs):
        super().setUp(*args, **kwargs)

        #if os.path.exists(self.source_file):
            #os.unlink(self.source_file)

        #if os.path.exists(self.target_file):
            #os.unlink(self.target_file)


        saq.ENCRYPTION_PASSWORD = self.old_password
    
    def test_anp_000_basic_io(self):

        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((ANP_SERVER_HOST, ANP_SERVER_PORT))
        server_socket.listen(1)

        def client():
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((ANP_SERVER_HOST, ANP_SERVER_PORT))

            anp_client = ANPSocket(client_socket)
            anp_client.write_uint(0)
            anp_client.write_uint(1)
            anp_client.write_ulong(0)
            anp_client.write_ulong(1)
            anp_client.write_string('')
            anp_client.write_string('Hello, world!')
            anp_client.write_data(b'')
            anp_client.write_data(b'Hello, world!')
            with open(self.source_file, 'rb') as fp:
                anp_client.write_chunked_data(fp)

            anp_client.s.shutdown(socket.SHUT_RDWR)
            anp_client.s.close()
            
        client_t = threading.Thread(target=client)
        client_t.start()

        client_connection, _ = server_socket.accept()
        anp_server = ANPSocket(client_connection)
        
        self.assertEquals(anp_server.read_uint(), 0)
        self.assertEquals(anp_server.read_uint(), 1)
        self.assertEquals(anp_server.read_ulong(), 0)
        self.assertEquals(anp_server.read_ulong(), 1)
        self.assertEquals(anp_server.read_string(), '')
        self.assertEquals(anp_server.read_string(), 'Hello, world!')
        self.assertEquals(anp_server.read_data(), b'')
        self.assertEquals(anp_server.read_data(), b'Hello, world!')
        with open(self.target_file, 'wb') as fp:
            anp_server.read_chunked_data(fp)

        self.assertTrue(filecmp.cmp(self.source_file, self.target_file))

        client_connection.shutdown(socket.SHUT_RDWR)
        client_connection.close()
        server_socket.close()

    def test_anp_001_message_io(self):

        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((ANP_SERVER_HOST, ANP_SERVER_PORT))
        server_socket.listen(1)

        def client():
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((ANP_SERVER_HOST, ANP_SERVER_PORT))
            anp_client = ANPSocket(client_socket)

            anp_client.send_message(ANPCommandOK())
            anp_client.send_message(ANPCommandERROR('test'))
            anp_client.send_message(ANPCommandPING('test'))
            anp_client.send_message(ANPCommandPONG('test'))
            anp_client.send_message(ANPCommandAVAILABLE())
            anp_client.send_message(ANPCommandCOPY_FILE(self.target_file, source_path=self.source_file))
            anp_client.send_message(ANPCommandPROCESS('test'))

            anp_client.s.shutdown(socket.SHUT_RDWR)
            anp_client.s.close()
            
        client_t = threading.Thread(target=client)
        client_t.start()

        client_connection, _ = server_socket.accept()
        anp_server = ANPSocket(client_connection)
        
        message = anp_server.recv_message()
        self.assertTrue(isinstance(message, ANPCommandOK))
        self.assertEquals(message.command, ANP_COMMAND_OK)

        message = anp_server.recv_message()
        self.assertTrue(isinstance(message, ANPCommandERROR))
        self.assertEquals(message.command, ANP_COMMAND_ERROR)
        self.assertEquals(message.error_message, 'test')

        message = anp_server.recv_message()
        self.assertTrue(isinstance(message, ANPCommandPING))
        self.assertEquals(message.command, ANP_COMMAND_PING)

        message = anp_server.recv_message()
        self.assertTrue(isinstance(message, ANPCommandPONG))
        self.assertEquals(message.command, ANP_COMMAND_PONG)

        message = anp_server.recv_message()
        self.assertTrue(isinstance(message, ANPCommandAVAILABLE))
        self.assertEquals(message.command, ANP_COMMAND_AVAILABLE)

        message = anp_server.recv_message()
        self.assertTrue(isinstance(message, ANPCommandCOPY_FILE))
        self.assertEquals(message.command, ANP_COMMAND_COPY_FILE)
        self.assertTrue(filecmp.cmp(self.source_file, self.target_file))

        message = anp_server.recv_message()
        self.assertTrue(isinstance(message, ANPCommandPROCESS))
        self.assertEquals(message.command, ANP_COMMAND_PROCESS)
        self.assertEquals(message.target, 'test')

        client_connection.shutdown(socket.SHUT_RDWR)
        client_connection.close()
        server_socket.close()
        client_t.join()

        #os.unlink(source_file)
        #os.unlink(target_file)

    def test_anp_002_server(self):

        sent_messages = [
            ANPCommandAVAILABLE(),
            ANPCommandPING('test'),
            ANPCommandCOPY_FILE(self.target_file, source_path=self.source_file),
            ANPCommandPROCESS(self.target_file),
        ]

        received_messages = []

        def command_handler(anp, command):
            received_messages.append(command)
            anp.send_message(ANPCommandOK())

        server = ACENetworkProtocolServer(ANP_SERVER_HOST, ANP_SERVER_PORT, command_handler)
        server.start()

        wait_for_log_count('listening for connections', 1, 5)

        # make our connection to the server
        client = anp_connect(ANP_SERVER_HOST, ANP_SERVER_PORT)
        
        # send one of each of the types of messages
        for message in sent_messages:
            client.send_message(message)
            result = client.recv_message()
            self.assertEquals(result.command, ANP_COMMAND_OK)

        self.assertEquals(len(sent_messages), len(received_messages))
        for index in range(len(received_messages)):
            self.assertEquals(sent_messages[index].command, received_messages[index].command)

        self.assertTrue(filecmp.cmp(self.source_file, self.target_file))

        client.send_message(ANPCommandEXIT())
        client.close_socket()

        server.stop()

    def test_anp_003_invalid_data(self):

        def command_handler(anp, command):
            if command.command == ANP_COMMAND_PING:
                anp.send_message(ANPCommandPONG(command.message))
            else:
                anp.send_message(ANPCommandERROR("invalid command bro"))

        server = ACENetworkProtocolServer(ANP_SERVER_HOST, ANP_SERVER_PORT, command_handler)
        server.start()

        wait_for_log_count('listening for connections', 1, 5)

        # make our connection to the server
        client = anp_connect(ANP_SERVER_HOST, ANP_SERVER_PORT)

        # this should eventually fail
        with self.assertRaises(Exception) as cm:
            while True:
                client.s.sendall(os.urandom(io.DEFAULT_BUFFER_SIZE))

        client.close_socket()

        # make our connection to the server
        client = anp_connect(ANP_SERVER_HOST, ANP_SERVER_PORT)
        client.send_message(ANPCommandPING('test'))
        response = client.recv_message()
        client.close_socket()
        server.stop()

    def test_anp_004_multiple_connections(self):
        def command_handler(anp, command):
            if command.command == ANP_COMMAND_PING:
                anp.send_message(ANPCommandPONG(command.message))
            else:
                self.fail("invalid command received")

        server = ACENetworkProtocolServer(ANP_SERVER_HOST, ANP_SERVER_PORT, command_handler)
        server.start()

        wait_for_log_count('listening for connections', 1, 5)

        # run 3 clients at the same time for 3 seconds, each sending PING as often as they can
        control = threading.Event()

        def run():
            client = anp_connect(ANP_SERVER_HOST, ANP_SERVER_PORT)
            while not control.is_set():
                message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=12))
                client.send_message(ANPCommandPING(message))
                response = client.recv_message()
                self.assertEquals(message, response.message)

            client.send_message(ANPCommandEXIT())
            client.close_socket()

        client_threads = []
        for _ in range(3):
            t = threading.Thread(target=run, name="Multiple Connections Test {}".format(_))
            t.start()
            client_threads.append(t)

        time.sleep(3)
        control.set()
        server.stop()
        for t in client_threads:
            t.join()

    def test_anp_005_encrypted_basic_io(self):
        saq.ENCRYPTION_PASSWORD = get_aes_key('testing')
        self.test_anp_000_basic_io()

    def test_anp_006_encrypted_message_io(self):
        saq.ENCRYPTION_PASSWORD = get_aes_key('testing')
        self.test_anp_001_message_io()
        
    def test_anp_007_encrypted_server(self):
        saq.ENCRYPTION_PASSWORD = get_aes_key('testing')
        self.test_anp_002_server()
    
    def test_anp_008_encrypted_multiple_connections(self):
        saq.ENCRYPTION_PASSWORD = get_aes_key('testing')
        self.test_anp_004_multiple_connections()

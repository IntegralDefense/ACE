# vim: sw=4:ts=4:et

import threading
import logging

import saq
import saq.test

from saq.constants import *
from saq.database import Message
from saq.messaging import MessageDispatchSystem, initialize_message_system, send_message, \
                          start_message_system, stop_message_system
from saq.test import *

class TestMessageDispatchSystem(MessageDispatchSystem):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.messages_received = []
        self.message_dispatched = threading.Event()

    def dispatch(self, message, destination):
        self.messages_received.append((message, destination))
        self.message_dispatched.set()

class TestCase(ACEBasicTestCase):

    def test_mds_load(self):
        initialize_message_system()
        self.assertIsNotNone(saq.MESSAGE_SYSTEM)
        self.assertEquals(len(saq.MESSAGE_SYSTEM.systems), 1)
        self.assertTrue('test' in saq.MESSAGE_SYSTEM.systems)
        self.assertTrue(isinstance(saq.MESSAGE_SYSTEM.systems['test'], TestMessageDispatchSystem))

    def test_mds_load_disabled(self):
        # make sure systems that are disabled are NOT loaded
        saq.CONFIG['messaging_system_test']['enabled'] = 'no'
        initialize_message_system()
        self.assertIsNotNone(saq.MESSAGE_SYSTEM)
        self.assertEquals(len(saq.MESSAGE_SYSTEM.systems), 0)

    def test_mds_start_stop(self):
        initialize_message_system()
        start_message_system()
        wait_for_log_count('started TestMessageDispatchSystem', 1)
        stop_message_system()

    def test_basic_submit(self):
        initialize_message_system()
        send_message('hello world', 'test')
        self.assertEquals(len(saq.MESSAGE_SYSTEM.systems), 1)
        start_message_system()
        system = saq.MESSAGE_SYSTEM.systems['test']
        self.assertTrue(system.message_dispatched.wait(5))
        self.assertEquals(len(system.messages_received), 1)
        stop_message_system()
        self.assertIsNone(saq.db.query(Message).first())

    def test_multi_route_submit(self):
        # a single message type is routed to two different destinations on the same system
        saq.CONFIG['message_routing']['test'] = 'test:test_destination,test:test_destination_2'
        initialize_message_system()
        send_message('hello world', 'test')
        start_message_system()
        system = saq.MESSAGE_SYSTEM.systems['test']
        wait_for(lambda: len(system.messages_received) == 2, 1, 3)
        self.assertEquals(len(system.messages_received), 2)
        stop_message_system()
        self.assertIsNone(saq.db.query(Message).first())

    def test_multi_route_submit_multi_system(self):
        # a single message type is routed to two different destinations on two different systems
        saq.CONFIG['messaging_system_test_2'] = {}
        saq.CONFIG['messaging_system_test_2']['enabled'] = 'yes'
        saq.CONFIG['messaging_system_test_2']['module'] = 'saq.messaging.test'
        saq.CONFIG['messaging_system_test_2']['class'] = 'TestMessageDispatchSystem'
        saq.CONFIG['messaging_system_test_2']['route'] = 'test_2'
        saq.CONFIG['message_routing']['test'] = 'test:test_destination,test_2:test_destination_2'
        initialize_message_system()
        send_message('hello world', 'test')
        start_message_system()
        self.assertTrue(saq.MESSAGE_SYSTEM.systems['test'].message_dispatched.wait(5))
        self.assertTrue(saq.MESSAGE_SYSTEM.systems['test_2'].message_dispatched.wait(5))
        stop_message_system()
        self.assertIsNone(saq.db.query(Message).first())

    def test_multi_route_default_type(self):
        # a single message is routed to all available routes
        saq.CONFIG['messaging_system_test_2'] = {}
        saq.CONFIG['messaging_system_test_2']['enabled'] = 'yes'
        saq.CONFIG['messaging_system_test_2']['module'] = 'saq.messaging.test'
        saq.CONFIG['messaging_system_test_2']['class'] = 'TestMessageDispatchSystem'
        saq.CONFIG['messaging_system_test_2']['route'] = 'test_2'
        saq.CONFIG['message_routing']['test'] = 'test:test_destination,test_2:test_destination_2'
        initialize_message_system()
        send_message('hello world')
        start_message_system()
        self.assertTrue(saq.MESSAGE_SYSTEM.systems['test'].message_dispatched.wait(5))
        self.assertTrue(saq.MESSAGE_SYSTEM.systems['test_2'].message_dispatched.wait(5))
        stop_message_system()
        self.assertIsNone(saq.db.query(Message).first())

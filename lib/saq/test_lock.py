# vim: sw=4:ts=4:et

import logging
import uuid
import time

from multiprocessing import Event, Process, Pipe

import saq, saq.test
from saq.test import *
from saq.lock import LocalLockableObject, initialize_locking

class TestLock(LocalLockableObject):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.uuid = str(uuid.uuid4())

class LockTestCase(ACEBasicTestCase):

    def setUp(self):
        super().setUp()
        initialize_locking()

    @modify_logging_level(logging.WARNING)
    def test_lock_000_local_lock(self):
        lock = TestLock()
        self.assertTrue(lock.lock())
        # something that was locked is locked
        self.assertTrue(lock.is_locked())
        # and cannot be locked again
        self.assertFalse(lock.lock())
        # can be unlocked
        self.assertTrue(lock.unlock())
        # truely is unlocked
        self.assertFalse(lock.is_locked())
        # cannot be unlocked again  
        self.assertFalse(lock.unlock())
        # and can be locked again
        self.assertTrue(lock.lock())
        self.assertTrue(lock.is_locked())

    def test_lock_001_multiprocess(self):
        lock = TestLock()
        sync0 = Event()
        sync1 = Event()
        sync2 = Event()

        def p1():
            lock.lock()
            # tell parent to get the lock
            sync0.set()
            # wait for parent to signal
            sync1.wait()
            lock.unlock()
            sync2.set()

        p = Process(target=p1)
        p.start()

        try:
            sync0.wait()
            
            # lock should already be locked
            self.assertTrue(lock.is_locked())
            # should not be able to lock the lock
            self.assertFalse(lock.lock())
            # and should not be able to unlock the lock
            self.assertFalse(lock.unlock())
            self.assertTrue(lock.is_locked())

            sync1.set()
            sync2.wait()
            # lock should be unlocked
            self.assertFalse(lock.is_locked())
            # and we should be able to lock it
            self.assertTrue(lock.lock())
            self.assertTrue(lock.is_locked())
            self.assertTrue(lock.unlock())
            self.assertFalse(lock.is_locked())
            
            p.join()
            p = None
        finally:
            if p:
                p.terminate()
                p.join()

    @reset_config
    @modify_logging_level(logging.ERROR)
    def test_lock_002_expired(self):
        # set locks to expire immediately
        saq.CONFIG['global']['lock_timeout'] = '00:00'
        lock = TestLock()
        self.assertTrue(lock.lock())
        # should expire right away
        self.assertFalse(lock.is_locked())
        self.assertTrue(lock.has_current_lock())
        # and we are able to lock it again
        self.assertTrue(lock.lock())

    @reset_config
    @modify_logging_level(logging.ERROR)
    def test_lock_003_refresh(self):
        # set locks to expire in 2 seconds
        saq.CONFIG['global']['lock_timeout'] = '00:02'
        lock = TestLock()
        self.assertTrue(lock.lock())
        # wait for one second
        time.sleep(1)
        # refresh the lock
        self.assertTrue(lock.refresh_lock())
        # wait for one second
        time.sleep(1)
        # we should still have the lock
        self.assertTrue(lock.is_locked())
        # wait for 1 second
        time.sleep(1.5)
        # should be expired now
        self.assertFalse(lock.is_locked())

    @modify_logging_level(logging.ERROR)
    def test_lock_004_lock_proxy(self):
        lock = TestLock()
        pipe_p, pipe_c = Pipe()

        def p1(pipe_c):
            # get the lock proxy from the queue
            proxy = pipe_c.recv()
            # unlock the lock and send the result through the pipe
            pipe_c.send(proxy.unlock())
            pipe_c.close()
        
        p = Process(target=p1, args=(pipe_c,))
        p.start()

        try:
            self.assertTrue(lock.lock())
            proxy = lock.create_lock_proxy()
            lock.transfer_locks_to(proxy)
            pipe_p.send(proxy)
            self.assertTrue(pipe_p.recv())
            pipe_p.close()
            p.join()
            p = None

            self.assertFalse(lock.is_locked())

        finally:
            if p:
                p.terminate()
                p.join()

        # do it again but this time don't transfer the locks
        # it should fail to unlock

        lock = TestLock()
        pipe_p, pipe_c = Pipe()

        p = Process(target=p1, args=(pipe_c,))
        p.start()

        try:
            self.assertTrue(lock.lock())
            proxy = lock.create_lock_proxy()
            #lock.transfer_locks_to(proxy)
            pipe_p.send(proxy)
            self.assertFalse(pipe_p.recv())
            pipe_p.close()
            p.join()
            p = None

            self.assertTrue(lock.is_locked())

        finally:
            if p:
                p.terminate()
                p.join()

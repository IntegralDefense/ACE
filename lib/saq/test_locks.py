# vim: sw=4:ts=4:et

import uuid

import saq
from saq.database import acquire_lock, release_lock, clear_expired_locks, use_db
from saq.test import *

class LockTestCase(ACEEngineTestCase):

    def test_lock(self):
        first_lock_uuid = str(uuid.uuid4())
        second_lock_uuid = str(uuid.uuid4())
        target_lock = str(uuid.uuid4())
        self.assertTrue(acquire_lock(target_lock, first_lock_uuid))
        self.assertFalse(acquire_lock(target_lock, second_lock_uuid))
        self.assertTrue(acquire_lock(target_lock, first_lock_uuid))
        release_lock(target_lock, first_lock_uuid)
        self.assertTrue(acquire_lock(target_lock, second_lock_uuid))
        self.assertFalse(acquire_lock(target_lock, first_lock_uuid))
        release_lock(target_lock, second_lock_uuid)

    def test_lock_timeout(self):
        saq.LOCK_TIMEOUT_SECONDS = 0
        first_lock_uuid = str(uuid.uuid4())
        second_lock_uuid = str(uuid.uuid4())
        target_lock = str(uuid.uuid4())
        self.assertTrue(acquire_lock(target_lock, first_lock_uuid))
        self.assertTrue(acquire_lock(target_lock, second_lock_uuid))

    @use_db
    def test_clear_expired_locks(self, db, c):
        # insert a lock that is already expired
        saq.LOCK_TIMEOUT_SECONDS = 0
        target = str(uuid.uuid4())
        lock_uuid = str(uuid.uuid4())
        self.assertTrue(acquire_lock(target, lock_uuid))
        # this should clear out the lock
        clear_expired_locks()
        # make sure it's gone
        c.execute("SELECT uuid FROM locks WHERE uuid = %s", (target,))
        self.assertIsNone(c.fetchone())

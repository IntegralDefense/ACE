# vim: sw=4:ts=4:et
#

import datetime
import threading
import logging

import saq
from saq.database import Remediation

from saq.remediation import EmailRemediationSystem, request_remediation, request_restoration, \
                            initialize_remediation_system_manager, start_remediation_system_manager, stop_remediation_system_manager, \
                            REMEDIATION_STATUS_COMPLETED
from saq.remediation.constants import *
from saq.test import *

from sqlalchemy import func, and_

class TestRemediationSystem(EmailRemediationSystem):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.remediation_executed = threading.Event()

    @property
    def remediation_type(self):
        return REMEDIATION_TYPE_TEST

    def execute_request(self, remediation):
        if '<fail>' in remediation.key:
            raise RuntimeError("forced failure")

        self.remediation_executed.set()
        remediation.status = REMEDIATION_STATUS_COMPLETED
        remediation.successful = True
        remediation.result = 'completed'
        return remediation

class TestCase(ACEBasicTestCase):

    def test_automation_start_stop(self):
        initialize_remediation_system_manager()
        start_remediation_system_manager()
        stop_remediation_system_manager()

    def test_requests(self):
        initialize_remediation_system_manager()
        remediation_id = request_remediation(REMEDIATION_TYPE_TEST, '<message_id>', '<recipient@localhost>',
                                             user_id=saq.test.UNITTEST_USER_ID, company_id=saq.COMPANY_ID)

        self.assertTrue(isinstance(remediation_id, int))
        r = saq.db.query(Remediation).filter(Remediation.id == remediation_id).one()
        self.assertIsNotNone(r)

        self.assertEquals(r.id, remediation_id)
        self.assertEquals(r.type, REMEDIATION_TYPE_TEST)
        self.assertEquals(r.action, REMEDIATION_ACTION_REMOVE)
        self.assertTrue(isinstance(r.insert_date, datetime.datetime))
        self.assertEquals(r.user_id, saq.test.UNITTEST_USER_ID)
        self.assertEquals(r.key, '<message_id>:<recipient@localhost>')
        self.assertIsNone(r.result)
        self.assertIsNone(r.comment)
        self.assertIsNone(r.successful)
        self.assertEquals(r.company_id, saq.COMPANY_ID)
        self.assertIsNone(r.lock)
        self.assertIsNone(r.lock_time)
        self.assertEquals(r.status, REMEDIATION_STATUS_NEW)

        remediation_id = request_restoration(REMEDIATION_TYPE_TEST, '<message_id>', '<recipient@localhost>',
                                             user_id=saq.test.UNITTEST_USER_ID, company_id=saq.COMPANY_ID)

        self.assertTrue(isinstance(remediation_id, int))
        r = saq.db.query(Remediation).filter(Remediation.id == remediation_id).one()
        self.assertIsNotNone(r)

        self.assertEquals(r.id, remediation_id)
        self.assertEquals(r.type, REMEDIATION_TYPE_TEST)
        self.assertEquals(r.action, REMEDIATION_ACTION_RESTORE)
        self.assertTrue(isinstance(r.insert_date, datetime.datetime))
        self.assertEquals(r.user_id, saq.test.UNITTEST_USER_ID)
        self.assertEquals(r.key, '<message_id>:<recipient@localhost>')
        self.assertIsNone(r.result)
        self.assertIsNone(r.comment)
        self.assertIsNone(r.successful)
        self.assertEquals(r.company_id, saq.COMPANY_ID)
        self.assertIsNone(r.lock)
        self.assertIsNone(r.lock_time)
        self.assertEquals(r.status, REMEDIATION_STATUS_NEW)

    def test_automation_queue(self):
        manager = initialize_remediation_system_manager()
        start_remediation_system_manager()

        remediation_id = request_remediation(REMEDIATION_TYPE_TEST, '<message_id>', '<recipient@localhost>', 
                                             user_id=saq.test.UNITTEST_USER_ID, company_id=saq.COMPANY_ID)
        wait_for(
            lambda: len(saq.db.query(Remediation).filter(
                Remediation.id == remediation_id, 
                Remediation.status == REMEDIATION_STATUS_COMPLETED).all()) > 0,
            1, 5)

        stop_remediation_system_manager()
        saq.db.commit()

        self.assertTrue(manager.systems['test'].remediation_executed.is_set())
        self.assertEquals(len(saq.db.query(Remediation).filter(Remediation.id == remediation_id, Remediation.status == REMEDIATION_STATUS_COMPLETED).all()), 1)

    def test_automation_failure(self):
        manager = initialize_remediation_system_manager()
        start_remediation_system_manager()

        remediation_id = request_remediation(REMEDIATION_TYPE_TEST, '<fail>', '<recipient@localhost>', 
                                             user_id=saq.test.UNITTEST_USER_ID, company_id=saq.COMPANY_ID)

        wait_for(
            lambda: len(saq.db.query(Remediation).filter(
                Remediation.id == remediation_id, 
                Remediation.status == REMEDIATION_STATUS_COMPLETED).all()) > 0,
            1, 5)

        stop_remediation_system_manager()
        saq.db.commit()

        self.assertFalse(manager.systems['test'].remediation_executed.is_set())
        self.assertEquals(len(saq.db.query(Remediation).filter(Remediation.id == remediation_id, Remediation.status == REMEDIATION_STATUS_COMPLETED).all()), 1)
        self.assertEquals(log_count('unable to execute remediation item'), 1)

        saq.db.commit()
        r = saq.db.query(Remediation).filter(Remediation.id == remediation_id).one()
        self.assertFalse(r.successful)
        self.assertTrue('forced failure' in r.result)

    def test_automation_cleanup(self):

        from saq.database import Remediation
        
        # make sure a lock uuid is created
        manager = initialize_remediation_system_manager()
        system = manager.systems['test']
        start_remediation_system_manager()
        stop_remediation_system_manager()

        # insert a new work request
        remediation_id = system.request_remediation('<message_id>', '<recipient@localhost>', 
                                                    user_id=saq.test.UNITTEST_USER_ID, company_id=saq.COMPANY_ID)

        # pretend it started processing
        saq.db.execute(Remediation.__table__.update().values(
            lock=system.lock,
            lock_time=func.now(),
            status=REMEDIATION_STATUS_IN_PROGRESS).where(and_(
            Remediation.company_id == saq.COMPANY_ID,
            Remediation.lock == None,
            Remediation.status == REMEDIATION_STATUS_NEW)))
        saq.db.commit()

        # start up the system again
        manager = initialize_remediation_system_manager()
        start_remediation_system_manager()

        # and it should process that job
        wait_for(
            lambda: len(saq.db.query(Remediation).filter(
                Remediation.id == remediation_id, 
                Remediation.status == REMEDIATION_STATUS_COMPLETED).all()) > 0,
            1, 5)

        stop_remediation_system_manager()

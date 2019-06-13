# vim: sw=4:ts=4:et

import time

import saq
import saq.test

from saq.constants import *
from saq.database import Remediation
from saq.remediation import initialize_remediation_system_manager, \
                            start_remediation_system_manager, \
                            stop_remediation_system_manager, \
                            request_remediation
from saq.remediation.constants import *
from saq.test import *

from sqlalchemy import func, and_

class TestCase(ACEBasicTestCase):
    def setUp(self, *args, **kwargs):
        super().setUp(*args, **kwargs)

        saq.CONFIG['remediation_system_phishfry'] = {
            'enabled': 'yes',
            'module': 'saq.remediation.phishfry',
            'class': 'PhishfryRemediationSystem' }

        del saq.CONFIG['remediation_system_test']

        self.manager = initialize_remediation_system_manager()
        self.system = self.manager.systems['email']
        self.system.enable_testing_mode()

    def test_automation_start_stop(self):
        start_remediation_system_manager()
        stop_remediation_system_manager()

    def test_account_load(self):
        self.assertEquals(len(self.system.accounts), 1)
        self.assertEquals(self.system.accounts[0].user, 'test_user')
        #self.assertEquals(self.system.accounts[0].password, 'test_password')

    def test_remediation_request(self):
        remediation_id = request_remediation(REMEDIATION_TYPE_EMAIL, '<message_id>', '<recipient@localhost>', 
                                             user_id=saq.test.UNITTEST_USER_ID, company_id=saq.COMPANY_ID)
        self.assertTrue(isinstance(remediation_id, int))
        remediation = saq.db.query(Remediation).filter(Remediation.id == remediation_id).one()
        self.assertIsNotNone(remediation)
        self.assertEquals(remediation.type, REMEDIATION_TYPE_EMAIL)
        self.assertEquals(remediation.action, REMEDIATION_ACTION_REMOVE)
        self.assertIsNotNone(remediation.insert_date)
        self.assertEquals(remediation.user_id, saq.test.UNITTEST_USER_ID)
        self.assertEquals(remediation.key, '<message_id>:<recipient@localhost>')
        self.assertIsNone(remediation.result)
        self.assertIsNone(remediation.comment)
        self.assertIsNone(remediation.successful)
        self.assertEquals(remediation.company_id, saq.COMPANY_ID)
        self.assertIsNone(remediation.lock)
        self.assertIsNone(remediation.lock_time)
        self.assertEquals(remediation.status, REMEDIATION_STATUS_NEW)

        remediation_id = self.system.request_restoration('<message_id>', '<recipient@localhost>', 
                                                   user_id=saq.test.UNITTEST_USER_ID, company_id=saq.COMPANY_ID)
        self.assertTrue(isinstance(remediation_id, int))
        remediation = saq.db.query(Remediation).filter(Remediation.id == remediation_id).one()
        self.assertIsNotNone(remediation)
        self.assertEquals(remediation.action, REMEDIATION_ACTION_RESTORE)

    def test_remediation_execution(self):
        remediation_id = request_remediation(REMEDIATION_TYPE_EMAIL, '<message_id>', '<recipient@localhost>', 
                                             user_id=saq.test.UNITTEST_USER_ID, company_id=saq.COMPANY_ID)
        self.assertTrue(isinstance(remediation_id, int))
        remediation = saq.db.query(Remediation).filter(Remediation.id == remediation_id).one()
        self.assertIsNotNone(remediation)
        self.system.execute_request(remediation)

        remediation = saq.db.query(Remediation).filter(Remediation.id == remediation_id).one()
        self.assertIsNotNone(remediation)
        self.assertEquals(remediation.type, REMEDIATION_TYPE_EMAIL)
        self.assertEquals(remediation.action, REMEDIATION_ACTION_REMOVE)
        self.assertIsNotNone(remediation.insert_date)
        self.assertEquals(remediation.user_id, saq.test.UNITTEST_USER_ID)
        self.assertEquals(remediation.key, '<message_id>:<recipient@localhost>')
        self.assertIsNotNone(remediation.result)
        self.assertIsNone(remediation.comment)
        self.assertTrue(remediation.successful)
        self.assertEquals(remediation.company_id, saq.COMPANY_ID)
        self.assertIsNone(remediation.lock)
        self.assertIsNone(remediation.lock_time)
        self.assertEquals(remediation.status, REMEDIATION_STATUS_COMPLETED)

    def test_automation_queue(self):
        start_remediation_system_manager()
        remediation_id = request_remediation(REMEDIATION_TYPE_EMAIL, '<message_id>', '<recipient@localhost>', 
                                             user_id=saq.test.UNITTEST_USER_ID, company_id=saq.COMPANY_ID)
        wait_for(
            lambda: len(saq.db.query(Remediation).filter(
                Remediation.id == remediation_id, 
                Remediation.status == REMEDIATION_STATUS_COMPLETED).all()) > 0,
            1, 5)

        stop_remediation_system_manager()

    def test_automation_cleanup(self):
        
        # make sure a lock uuid is created
        start_remediation_system_manager()
        stop_remediation_system_manager()

        # insert a new work request
        remediation_id = request_remediation(REMEDIATION_TYPE_EMAIL, '<message_id>', '<recipient@localhost>', 
                                             user_id=saq.test.UNITTEST_USER_ID, company_id=saq.COMPANY_ID)

        # pretend it started processing
        saq.db.execute(Remediation.__table__.update().values(
            lock=self.system.lock,
            lock_time=func.now(),
            status=REMEDIATION_STATUS_IN_PROGRESS).where(and_(
            Remediation.company_id == saq.COMPANY_ID,
            Remediation.lock == None,
            Remediation.status == REMEDIATION_STATUS_NEW)))
        saq.db.commit()

        # start up the system again
        start_remediation_system_manager()

        # and it should process that job
        wait_for(
            lambda: len(saq.db.query(Remediation).filter(
                Remediation.id == remediation_id, 
                Remediation.status == REMEDIATION_STATUS_COMPLETED).all()) > 0,
            1, 5)

        stop_remediation_system_manager()

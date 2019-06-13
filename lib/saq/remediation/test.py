# vim: sw=4:ts=4:et
#

import threading
import logging

import saq
from saq.database import Remediation

from saq.remediation import EmailRemediationSystem, request_remediation, \
                            initialize_remediation_system_manager, start_remediation_system_manager, stop_remediation_system_manager
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
        self.remediation_executed.set()

class TestCase(ACEBasicTestCase):

    def test_automation_start_stop(self):
        initialize_remediation_system_manager()
        start_remediation_system_manager()
        stop_remediation_system_manager()

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

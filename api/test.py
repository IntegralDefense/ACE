# vim: sw=4:ts=4:et

from saq.test import *
from saq.database import get_db_connection

class APIBasicTestCase(ACEBasicTestCase):
    def setUp(self, *args, **kwargs):
        super().setUp(*args, **kwargs)

        from api import create_app
        self.app = create_app(testing=True)
        self.app_context = self.app.test_request_context()                      
        self.app_context.push()                           
        self.client = self.app.test_client()

        # clear the workloads and alerts
        with get_db_connection() as db:
            c = db.cursor()
            c.execute("DELETE FROM alerts")
            c.execute("DELETE FROM workload")
            c.execute("DELETE FROM locks")
            c.execute("DELETE FROM delayed_analysis")
            db.commit()

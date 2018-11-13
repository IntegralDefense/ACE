# vim: sw=4:ts=4:et

from saq.test import *
from saq.database import get_db_connection

class APIBasicTestCase(ACEBasicTestCase):
    def test_external_api_server(self):
        self.start_api_server()
        self.stop_api_server()

# vim: sw=4:ts=4:et

from saq.test import *

class APIBasicTestCase(ACEBasicTestCase):
    def setUp(self, *args, **kwargs):
        super().setUp(*args, **kwargs)

        from api import create_app
        self.app = create_app(testing=True)
        self.app_context = self.app.test_request_context()                      
        self.app_context.push()                           
        self.client = self.app.test_client()

# vim: sw=4:ts=4:et

import logging
import datetime
import unittest

import saq, saq.test
from saq.constants import *
from saq.test import *

from splunklib import SplunkQueryObject

class AssetAnalysisModuleTestCase(ACEModuleTestCase):
    @unittest.skip("skipping this one for now...")
    def test_carbon_black_asset_ident_000(self):
        from saq.modules.asset import CarbonBlackAssetIdentAnalysis

        # find an IP address in the past 24 hours to use 
        q, result = splunk_query("""index=carbonblack | dedup local_ip | head limit=1 | fields local_ip""")
        self.assertTrue(result)
        self.assertTrue(isinstance(q.json(), list))
        self.assertEquals(len(q.json()), 1)

        ipv4 = q.json()[0]['local_ip']
        logging.info("using ipv4 {} for test".format(ipv4))

        engine = AnalysisEngine()
        engine.enable_module('analysis_module_carbon_black_asset_ident')
        self.start_engine(engine)

        root = create_root_analysis(event_time=datetime.datetime.now())
        root.initialize_storage()
        o_uuid = root.add_observable(F_IPV4, ipv4).id
        root.save()

        engine.queue_work_item(root.storage_dir)
        engine.queue_work_item(TerminatingMarker())
        engine.wait()

        root.load()
        ipv4 = root.get_observable(o_uuid)
        self.assertIsNotNone(ipv4)
        analysis = ipv4.get_analysis(CarbonBlackAssetIdentAnalysis)
        self.assertIsNotNone(analysis)
        self.assertIsNotNone(analysis.details)
        self.assertEquals(len(analysis.discovered_hostnames), 1)

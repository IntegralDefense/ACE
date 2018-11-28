# vim: sw=4:ts=4:et

import logging
import os, os.path
import shutil
import uuid

from saq.analysis import RootAnalysis
from saq.constants import *
from saq.test import *

SAMPLE_DETECTIONS = 'sample_detections'
OFFICE_SAMPLES = os.path.join(SAMPLE_DETECTIONS, 'office')

class DetectionTestCase(ACEModuleTestCase):
    def test_detections_000_ole(self):

        submissions = {} # key = storage_dir, value = path to file

        for file_name in os.listdir(OFFICE_SAMPLES):
            source_path = os.path.join(OFFICE_SAMPLES, file_name)
            root = create_root_analysis(uuid=str(uuid.uuid4()))
            root.initialize_storage()
            shutil.copy(source_path, root.storage_dir)
            root.add_observable(F_FILE, file_name)
            root.save()
            root.schedule()
            submissions[root.storage_dir] = source_path

        engine = TestEngine()
        engine.enable_module('analysis_module_archive')
        engine.enable_module('analysis_module_file_type')
        engine.enable_module('analysis_module_olevba_v1_1')
        engine.enable_module('analysis_module_officeparser_v1_0')
        engine.enable_module('analysis_module_yara_scanner_v3_4')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        for storage_dir in submissions:
            with self.subTest(storage_dir=storage_dir, source_path=submissions[storage_dir]):
                root = RootAnalysis()
                root.storage_dir = storage_dir
                root.load()
                detections = root.all_detection_points
                self.assertGreater(len(detections), 0)

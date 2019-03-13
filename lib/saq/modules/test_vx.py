# vim: sw=4:ts=4:et

import datetime
import shutil

import saq, saq.test
from saq.constants import *
from saq.test import *
from saq.engine.test import AnalysisEngine, TerminatingMarker

from vxstreamlib import *
from sandboxapi.falcon import FalconAPI

SAMPLE_HASH = '15e01d01a60c54207ba4beaaa694f8bde67f9418b1cd05b8f6316839fc3f65e6'
SAMPLE_PATH = 'test_data/sample.jar'

class FalconAnalysisModuleTestCase(ACEModuleTestCase):
    def setUp(self):
        ACEModuleTestCase.setUp(self)

        client = FalconAPI(saq.CONFIG['vxstream']['apikey'], saq.CONFIG['vxstream']['baseuri_v2'])
        client.verify_ssl = self.ssl_verification 
        env_id = saq.CONFIG['vxstream']['environmentid']

        # make sure the following binaries are analyzed on the system
        result = client._request('/search/hash', method='POST', params={'hash': SAMPLE_HASH})
        job_id = None
        if result.status_code != 200 or result.json() == []:
            # this sample needs to be submitted
            with open(SAMPLE_PATH, 'rb') as fp:
                job_id = client.analyze(fp, 'sample.jar')
            if job_id is None:
                print("submission of {} failed".format(local_path))
                return False
            # should be a string 
            assert isinstance(job_id, str)

        # Wait for analysis to complete
        status = client._request("/report/{}/state".format(client.job_id)).json()
        if 'state' in status:
            status = status['state']
        else:
            print("Unknown report state: {}".format(status))
            return False

        import time
        while status == VXSTREAM_STATUS_IN_PROGRESS or status == VXSTREAM_STATUS_IN_QUEUE:
            time.sleep(1)
            status = client._request("/report/{}/state".format(client.job_id)).json()['state']
                

    @property
    def ssl_verification(self):
        """Set ssl verification. In the config, this should be set to the path to CA cert, True (default), 
        or False to turn off ssl_verification.
        """
        if 'ssl_verification' in saq.CONFIG['vxstream']:
            ssl_verify = saq.CONFIG['vxstream']['ssl_verification']
            if os.path.exists(ssl_verify):
                # assume it's a path to the CA cert
                return ssl_verify
            else:
                # it should be interpreted as a bool
                return saq.CONFIG['vxstream'].getboolean('ssl_verification')
        # Default OS cert store
        return True

    def test_falcon_000_hash_lookup(self):
        engine = AnalysisEngine()
        engine.enable_module('analysis_module_falcon_hash_analyzer')
        self.start_engine(engine)

        root = create_root_analysis(event_time=datetime.datetime.now())
        root.initialize_storage()
        sha2 = root.add_observable(F_SHA256, SAMPLE_HASH)
        root.save()

        engine.queue_work_item(root.storage_dir)
        engine.queue_work_item(TerminatingMarker())
        engine.wait()

        root.load()
        sha2 = root.get_observable(sha2.id)
        from saq.modules.vx import FalconHashAnalysis
        analysis = sha2.get_analysis(FalconHashAnalysis)
        self.assertIsNotNone(analysis)
        self.assertEquals(analysis.sha256, sha2.value)
        self.assertEquals(analysis.environment_id, saq.CONFIG['vxstream']['environmentid'])
        self.assertEquals(analysis.status, VXSTREAM_STATUS_SUCCESS)
        self.assertIsNotNone(analysis.submit_date)
        self.assertIsNotNone(analysis.complete_date)
        self.assertIsNone(analysis.fail_date)
        self.assertIsNotNone(analysis.vxstream_threat_level)
        self.assertIsNotNone(analysis.vxstream_threat_score)

class VxAnalysisModuleTestCase(ACEModuleTestCase):
    def setUp(self):
        ACEModuleTestCase.setUp(self)
    
        client = VxStreamServer(saq.CONFIG['vxstream']['baseuri'],
                                saq.CONFIG['vxstream']['apikey'],
                                saq.CONFIG['vxstream']['secret'])

        env_id = saq.CONFIG['vxstream']['environmentid']
        
        # make sure the following binaries are analyzed on the system
        result = client.get_status(SAMPLE_HASH, env_id) 
        if result == VXSTREAM_STATUS_UNKNOWN:
            print("missing analysis for {} -- submitting and waiting for completion...".format(SAMPLE_PATH))
            result = client.submit(SAMPLE_PATH, env_id)
            client.wait(result.sha256, env_id)

    def test_vx_000_hash_lookup(self):
        engine = AnalysisEngine()
        engine.enable_module('analysis_module_vxstream_hash_analyzer')
        self.start_engine(engine)

        root = create_root_analysis(event_time=datetime.datetime.now())
        root.initialize_storage()
        sha2 = root.add_observable(F_SHA256, SAMPLE_HASH)
        root.save()

        engine.queue_work_item(root.storage_dir)
        engine.queue_work_item(TerminatingMarker())
        engine.wait()

        root.load()
        sha2 = root.get_observable(sha2.id)
        from saq.modules.vx import VxStreamHashAnalysis
        analysis = sha2.get_analysis(VxStreamHashAnalysis)
        self.assertIsNotNone(analysis)
        self.assertEquals(analysis.sha256, sha2.value)
        self.assertEquals(analysis.environment_id, saq.CONFIG['vxstream']['environmentid'])
        self.assertEquals(analysis.status, VXSTREAM_STATUS_SUCCESS)
        self.assertIsNotNone(analysis.submit_date)
        self.assertIsNotNone(analysis.complete_date)
        self.assertIsNone(analysis.fail_date)
        self.assertIsNotNone(analysis.vxstream_threat_level)
        self.assertIsNotNone(analysis.vxstream_threat_score)

    def test_vx_001_file_lookup(self):
        engine = AnalysisEngine()
        engine.enable_module('analysis_module_vxstream_file_analyzer')
        engine.enable_module('analysis_module_vxstream_hash_analyzer')
        engine.enable_module('analysis_module_file_hash_analyzer')
        engine.enable_module('analysis_module_file_type')
        self.start_engine(engine)

        root = create_root_analysis(event_time=datetime.datetime.now())
        root.initialize_storage()
        shutil.copy2('test_data/sample.jar', root.storage_dir)
        _file = root.add_observable(F_FILE, 'sample.jar')
        _file.add_directive(DIRECTIVE_SANDBOX)
        root.save()

        engine.queue_work_item(root.storage_dir)
        engine.queue_work_item(TerminatingMarker())
        engine.wait()

        root.load()
        _file = root.get_observable(_file.id)
        from saq.modules.file_analysis import FileHashAnalysis
        from saq.modules.vx import VxStreamHashAnalysis
        hash_analysis = _file.get_analysis(FileHashAnalysis)
        self.assertIsNotNone(hash_analysis)
        sha2 = hash_analysis.get_observables_by_type(F_SHA256)
        self.assertIsInstance(sha2, list)
        self.assertEquals(len(sha2), 1)
        sha2 = sha2[0]
        analysis = sha2.get_analysis(VxStreamHashAnalysis)
        self.assertIsNotNone(analysis)
        self.assertEquals(analysis.sha256, sha2.value)
        self.assertEquals(analysis.environment_id, saq.CONFIG['vxstream']['environmentid'])
        self.assertEquals(analysis.status, VXSTREAM_STATUS_SUCCESS)
        self.assertIsNotNone(analysis.submit_date)
        self.assertIsNotNone(analysis.complete_date)
        self.assertIsNone(analysis.fail_date)
        self.assertIsNotNone(analysis.vxstream_threat_level)
        self.assertIsNotNone(analysis.vxstream_threat_score)

    def test_vx_002_invalid_file_upload(self):
        engine = AnalysisEngine()
        engine.enable_module('analysis_module_vxstream_file_analyzer')
        engine.enable_module('analysis_module_vxstream_hash_analyzer')
        engine.enable_module('analysis_module_file_hash_analyzer')
        engine.enable_module('analysis_module_file_type')
        self.start_engine(engine)

        root = create_root_analysis(event_time=datetime.datetime.now())
        root.initialize_storage()
        with open('/dev/urandom', 'rb') as fp_in:
            with open('test_data/invalid.exe', 'wb') as fp_out:
                fp_out.write(fp_in.read(4096))

        shutil.copy('test_data/invalid.exe', root.storage_dir)
        _file = root.add_observable(F_FILE, 'invalid.exe')
        _file.add_directive(DIRECTIVE_SANDBOX)
        root.save()

        engine.queue_work_item(root.storage_dir)
        engine.queue_work_item(TerminatingMarker())
        engine.wait()

        root.load()
        _file = root.get_observable(_file.id)
        from saq.modules.vx import VxStreamFileAnalysis
        analysis = _file.get_analysis(VxStreamFileAnalysis)
        self.assertIsNotNone(analysis)
        #self.assertEquals(analysis.sha256, sha2.value)
        self.assertEquals(analysis.environment_id, saq.CONFIG['vxstream']['environmentid'])
        self.assertEquals(analysis.status, VXSTREAM_STATUS_ERROR)
        self.assertIsNotNone(analysis.submit_date)
        self.assertIsNone(analysis.complete_date)
        self.assertIsNotNone(analysis.fail_date)
        self.assertIsNone(analysis.vxstream_threat_level)
        self.assertIsNone(analysis.vxstream_threat_score)

    def test_vx_003_file_with_hash_analysis(self):
        engine = AnalysisEngine()
        engine.enable_module('analysis_module_vxstream_hash_analyzer')
        engine.enable_module('analysis_module_vxstream_file_analyzer')
        engine.enable_module('analysis_module_file_hash_analyzer')
        engine.enable_module('analysis_module_file_type')
        self.start_engine(engine)

        root = create_root_analysis(event_time=datetime.datetime.now())
        root.initialize_storage()
        with open('/dev/urandom', 'rb') as fp_in:
            # using an extension here that doesn't get hash anlaysis
            with open('test_data/invalid.pcap', 'wb') as fp_out:
                fp_out.write(fp_in.read(4096))

        shutil.copy('test_data/invalid.pcap', root.storage_dir)
        _file = root.add_observable(F_FILE, 'invalid.pcap')
        _file.add_directive(DIRECTIVE_SANDBOX)
        root.save()

        engine.queue_work_item(root.storage_dir)
        engine.queue_work_item(TerminatingMarker())
        engine.wait()

        root.load()
        _file = root.get_observable(_file.id)
        from saq.modules.vx import VxStreamFileAnalysis
        analysis = _file.get_analysis(VxStreamFileAnalysis)
        self.assertFalse(analysis)

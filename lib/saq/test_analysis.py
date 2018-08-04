# vim: sw=4:ts=4:et

import datetime
import json
import logging
import os, os.path
import time
import unittest

import saq

from saq.analysis import _JSONEncoder, RootAnalysis, _get_io_write_count, _get_io_read_count
from saq.modules import AnalysisModule
from saq.constants import *
from saq.observables import create_observable
from saq.test import *

class JSONSeralizerTestCase(ACEBasicTestCase):
    def test_encoding(self):

        test_data = {}
        class _test(object):
            json = 'hello world'

        test_data = {
            'datetime': datetime.datetime(2017, 11, 11, hour=7, minute=36, second=1, microsecond=1),
            'binary_string': '你好，世界'.encode('utf-8'),
            'custom_object': _test(), 
            'dict': {}, 
            'list': [], 
            'str': 'test', 
            'int': 1, 
            'float': 1.0, 
            'null': None, 
            'bool': True }

        json_output = json.dumps(test_data, sort_keys=True, cls=_JSONEncoder)
        self.assertEqual(json_output, r'{"binary_string": "\u00e4\u00bd\u00a0\u00e5\u00a5\u00bd\u00ef\u00bc\u008c\u00e4\u00b8\u0096\u00e7\u0095\u008c", "bool": true, "custom_object": "hello world", "datetime": "2017-11-11T07:36:01.000001", "dict": {}, "float": 1.0, "int": 1, "list": [], "null": null, "str": "test"}')


class RootAnalysisTestCase(ACEBasicTestCase):
    def test_analysis_000_create(self):
        root = create_root_analysis()
        # make sure the defaults are what we expect them to be
        self.assertIsInstance(root.action_counters, dict)
        self.assertIsNone(root.details)
        self.assertIsInstance(root.state, dict)
        #self.assertIsNone(root.storage_dir)
        self.assertEquals(root.location, saq.CONFIG['global']['node'])
        self.assertEquals(root.company_id, saq.CONFIG['global'].getint('company_id'))
        self.assertEquals(root.company_name, saq.CONFIG['global']['company_name'])

    def test_analysis_001_save(self):
        root = create_root_analysis()
        root.save()

    def test_analysis_002_load(self):
        root = create_root_analysis()
        root.load()

    @track_io
    def test_analysis_003_io_count(self):
        root = create_root_analysis()
        root.save()
        # we should have one write at this point
        self.assertEquals(_get_io_write_count(), 1)
        root = create_root_analysis()
        root.load()
        # and then one read
        self.assertEquals(_get_io_read_count(), 1)

    def test_analysis_004_has_observable(self):
        root = create_root_analysis()
        root.initialize_storage()
        o_uuid = root.add_observable(F_TEST, 'test').id
        self.assertTrue(root.has_observable(F_TEST, 'test'))
        self.assertFalse(root.has_observable(F_TEST, 't3st'))
        self.assertTrue(root.has_observable(create_observable(F_TEST, 'test')))
        self.assertFalse(root.has_observable(create_observable(F_TEST, 't3st')))


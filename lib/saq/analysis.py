# vim: sw=4:ts=4:et

import atexit
import collections
import copy
import datetime
import gc
import importlib
import json
import logging
import numbers
import os
import os.path
import re
import sys
import shutil
import time
import uuid

import dateutil.parser
import requests

import saq
from saq.constants import *
from saq.error import report_exception
from saq.lock import LocalLockableObject

##############################################################################
#
# I/O tracking
# this is used with unit testing
#

# if this is True then bytes_written and write_count get updated
_track_io = False

_io_tracker_manager = None
_io_tracker_sync = None

# total number of write counts
_write_count = None
# total number fo reads
_read_count = None

def _enable_io_tracker():
    if _track_io:
        return

    _start_io_tracker()

def _disable_io_tracker():
    if not _track_io:
        return

    _stop_io_tracker()

def _start_io_tracker():
    import multiprocessing

    global _track_io
    global _io_tracker_manager
    global _io_tracker_sync
    global _write_count
    global _read_count

    _io_tracker_manager = multiprocessing.Manager()
    _io_tracker_sync = multiprocessing.RLock()
    _write_count = _io_tracker_manager.Value('I', 0, lock=False)
    _read_count = _io_tracker_manager.Value('I', 0, lock=False)
    _track_io = True

def _stop_io_tracker():
    global _track_io
    global _io_tracker_manager
    global _io_tracker_sync
    global _write_count
    global _read_count

    if _track_io:
        try:
            _io_tracker_manager.shutdown()
        except Exception as e:
            sys.stderr.write("\n\nunable to shut down io tracker manager: {}\n\n".format(e))

        _io_tracker_manager = None
        _io_tracker_sync = None
        _write_count = None
        _read_count = None
        _track_io = False

atexit.register(_stop_io_tracker)

def _track_writes():
    if not _track_io:
        return

    with _io_tracker_sync:
        _write_count.value += 1

    #sys.stderr.write('\n')
    #sys.stderr.write('#' * 79 + '\n')
    #import traceback
    #traceback.print_stack()
    #sys.stderr.write('\n')

def _get_io_write_count():
    with _io_tracker_sync:
        return _write_count.value

def _track_reads():
    if not _track_io:
        return

    with _io_tracker_sync:
        _read_count.value += 1

def _get_io_read_count():
    with _io_tracker_sync:
        return _read_count.value

#
# end I/O tracking
# 
##############################################################################

class EventSource(object):
    """Supports callbacks for events by keyword."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.clear_event_listeners()

    def clear_event_listeners(self):
        self.event_listeners = {} # key = string, value = [] of callback functions

    def add_event_listener(self, event, callback):
        assert isinstance(event, str)
        assert callback

        if event not in self.event_listeners:
            self.event_listeners[event] = []

        if callback not in self.event_listeners[event]:
            self.event_listeners[event].append(callback)

    def fire_event(self, source, event, *args, **kwargs):
        assert isinstance(source, Analysis) or isinstance(source, Observable)
        assert event in VALID_EVENTS

        if event in self.event_listeners:
            for callback in self.event_listeners[event]:
                callback(source, event, *args, **kwargs)

class DetectionPoint(object):
    """Represents an observation that would result in a detection."""

    KEY_DESCRIPTION = 'description'
    KEY_DETAILS = 'details'

    def __init__(self, description=None, details=None):
        self.description = description
        self.details = details

    @property
    def json(self):
        return {
            DetectionPoint.KEY_DESCRIPTION: self.description,
            DetectionPoint.KEY_DETAILS: self.details }

    @json.setter
    def json(self, value):
        assert isinstance(value, dict)
        if DetectionPoint.KEY_DESCRIPTION in value:
            self.description = value[DetectionPoint.KEY_DESCRIPTION]
        if DetectionPoint.KEY_DETAILS in value:
            self.details = value[DetectionPoint.KEY_DETAILS]

    @staticmethod
    def from_json(dp_json):
        """Loads a DetectionPoint from a JSON dict. Used by _materalize."""
        dp = DetectionPoint()
        dp.json = dp_json
        return dp

    @property
    def display_description(self):
        if isinstance(self.description, str):
            return self.description.encode('unicode_escape').decode()
        else:
            return self.description

    def __str__(self):
        return "DetectionPoint({})".format(self.description)

    def __eq__(self, other):
        if not isinstance(other, DetectionPoint):
            return False

        return self.description == other.description and self.details == other.details

class ProfilePoint(object):

    KEY_DESCRIPTION = 'desc'
    KEY_ID = 'id'
    KEY_NOTES = 'notes'
    
    def __init__(self, description=None, notes=None, _id=None):
        self._details = {
            ProfilePoint.KEY_DESCRIPTION: description,
            ProfilePoint.KEY_ID: _id,
            ProfilePoint.KEY_NOTES: notes,
        }

    @property
    def description(self):
        return self._details[ProfilePoint.KEY_DESCRIPTION]

    @description.setter
    def description(self, value):
        self._details[ProfilePoint.KEY_DESCRIPTION] = value

    @property
    def notes(self):
        if ProfilePoint.KEY_NOTES in self._details:
            return self._details[ProfilePoint.KEY_NOTES]
        
        return None
        
    @notes.setter
    def notes(self, value):
        self._details[ProfilePoint.KEY_NOTES] = value

    @property
    def id(self):
        return self._details[ProfilePoint.KEY_ID]

    @id.setter
    def id(self, value):
        self._details[ProfilePoint.KEY_ID] = value

    @property
    def json(self):
        return self._details

    @json.setter
    def json(self, value):
        assert isinstance(value, dict)
        self._details = value

    def __eq__(self, o):
        if not isinstance(o, ProfilePoint):
            return False

        return self.description == o.description

    def __str__(self):
        return self.description

class ProfileObject(object):
    
    KEY_PROFILE_POINTS = 'profile_points'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._profile_points = []

    @property
    def json(self):
        return { ProfileObject.KEY_PROFILE_POINTS: self._profile_points }

    @json.setter
    def json(self, value):
        assert isinstance(value, dict)
        if ProfileObject.KEY_PROFILE_POINTS in value:
            self._profile_points = []
            for p in value[ProfileObject.KEY_PROFILE_POINTS]:
                profile_point = ProfilePoint()
                profile_point.json = p
                self._profile_points.append(profile_point)

    @property
    def profile_points(self):
        return self._profile_points

    @profile_points.setter
    def profile_points(self, value):
        assert isinstance(value, list)
        assert all([isinstance(x, ProfilePoint) for x in value])
        self._profile_points = value

    def add_profile_point(self, value):
        if isinstance(value, str):
            value = ProfilePoint(value)

        if value not in self._profile_points:
            self._profile_points.append(value)
            logging.info("added {} to {}".format(value, self))

    def clear_profile_points(self):
        self._profile_points.clear()

class ProfilePointAnalyzer(object):
    def analyze(self, root):
        """Returns a single ProfilePoint or list of ProfilePoint objects, or None (or False) if no profile point is found."""
        raise NotImplementedError()

    def __str__(self):
        return "Profile Point Analyzer {}".format(type(self).__name__)

class ProfilePointTarget(object):
    """Defines an object (some data) that can be the target of analysis."""
    def __init__(self, name, data):
        assert name in VALID_TARGETS
        self.name = name
        self.data = data

    def __str__(self):
        return "Profile Point Target {} ".format(self.name)

    @property
    def children(self):
        """Always returns an empty list."""
        return []

    @property
    def value(self):
        """Just an alias for the data property."""
        return self.data

class DetectableObject(EventSource):
    """Mixin for objects that can have detection points."""

    KEY_DETECTIONS = 'detections'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._detections = []

    @property
    def json(self):
        return { DetectableObject.KEY_DETECTIONS: self._detections }

    @json.setter
    def json(self, value):
        assert isinstance(value, dict)
        if DetectableObject.KEY_DETECTIONS in value:
            self._detections = value[DetectableObject.KEY_DETECTIONS]

    @property
    def detections(self):
        return self._detections

    @detections.setter
    def detections(self, value):
        assert isinstance(value, list)
        assert all([isinstance(x, DetectionPoint) for x in value]) or all([isinstance(x, dict) for x in value])
        self._detections = value

    def has_detection_points(self):
        """Returns True if this object has at least one detection point, False otherwise."""
        return len(self._detections) != 0

    @property
    def is_suspect(self):
        """Returns True if this object has one or more detection points."""
        return self.has_detection_points()

    def add_detection_point(self, description, details=None):
        """Adds the given detection point to this object."""
        assert isinstance(description, str)
        assert description

        detection = DetectionPoint(description, details)

        if detection in self._detections:
            return

        self._detections.append(detection)
        logging.debug("added detection point {} to {}".format(detection, self))
        self.fire_event(self, EVENT_DETECTION_ADDED, detection)

    def clear_detection_points(self):
        self._detections.clear()

class AlertSubmitException(Exception):
    pass

# utility class to translate custom objects into JSON
class _JSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime.datetime):
            return obj.isoformat()
        elif isinstance(obj, bytes):
            return obj.decode('unicode_escape', 'replace')
        elif hasattr(obj, 'json'):
            return obj.json
        else:
            logging.debug('json type {0}'.format(type(obj)))
            return super(_JSONEncoder, self).default(obj)

class Tag(object):
    """Gives a bit of metadata to an observable or analysis.  Tags defined in the configuration file are also signals for detection."""

    def __init__(self, name=None, json=None):
        if json is not None:
            self.name = json
        elif name is not None:
            self.name = name

        # all tags default to these values
        self.level = 'info'
        self.score = 0
        self.css_class = 'label-default' # white

        if self.name is None:
            logging.error("tag has no name")
            return

        # note that a tag can have the form of tag_name:random_stuff
        tag_name_lookup = self.name
        if ':' in tag_name_lookup:
            tag_name_lookup = tag_name_lookup.split(':', 1)[0]

        # does this tag exist in the configuration file?
        try:
            self.level = saq.CONFIG['tags'][tag_name_lookup]
        except KeyError:
            self.level = TAG_LEVEL_INFO

        if self.level == TAG_LEVEL_FALSE_POSITIVE:
            self.score = 0
        elif self.level == TAG_LEVEL_INFO:
            self.score = 0
        elif self.level == TAG_LEVEL_WARNING:
            self.score = 1
        elif self.level == TAG_LEVEL_ALERT:
            self.score = 3
        elif self.level == TAG_LEVEL_CRITICAL:
            self.score = 10

        try:
            self.css_class = saq.CONFIG['tag_css_class'][self.level]
        except KeyError:
            logging.error("invalid tag level {}".format(self.level))
    
    @property
    def json(self):
        return self.name

    @json.setter
    def json(self, value):
        self.name = value

    def __str__(self):
        return self.name

    def __hash__(self):
        return self.name.__hash__()

    def __eq__(self, other):
        if not isinstance(other, Tag):
            return False

        return self.name == other.name

class TaggableObject(EventSource):
    """A mixin class that adds a tags property that is a list of tags assigned to this object."""

    KEY_TAGS = 'tags'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # list of strings 
        self._tags = []

    @property
    def json(self):
        return {
            TaggableObject.KEY_TAGS: self.tags
        }

    @json.setter
    def json(self, value):
        assert isinstance(value, dict)
        if TaggableObject.KEY_TAGS in value:
            self.tags = value[TaggableObject.KEY_TAGS]

    @property
    def tags(self):
        return self._tags

    @tags.setter
    def tags(self, value):
        assert isinstance(value, list)
        assert all([isinstance(i, str) or isinstance(i, Tag) for i in value])
        self._tags = value

    def add_tag(self, tag):
        assert isinstance(tag, str)
        if tag in [t.name for t in self.tags]:
            return

        t = Tag(name=tag)
        self.tags.append(t)
        logging.debug("added {} to {}".format(t, self))
        self.fire_event(self, EVENT_TAG_ADDED, t)

    def clear_tags(self):
        self._tags = []

    def has_tag(self, tag_value):
        """Returns True if this object has this tag."""
        return tag_value in [x.name for x in self.tags]

    def mark_as_whitelisted(self):
        """Utility function to mark this Observable as whietlisted by adding the tag 'whitelisted'."""
        self.add_tag('whitelisted')

    @property
    def is_whitelisted(self):
        return self.has_tag('whitelisted')

class Analysis(TaggableObject, DetectableObject, ProfileObject):
    """Represents an output of analysis work."""

    # dictionary keys used by the Analysis class
    KEY_OBSERVABLES = 'observables'
    KEY_DETAILS = 'details' # NOTE (see the NOTE above)
    KEY_SUMMARY = 'summary'

    KEY_UUID = 'uuid'
    KEY_FILE_FORMAT = 'file_format'
    KEY_FILE_PATH = 'file_path'

    KEY_COMPLETED = 'completed' # boolean to indicate that the analysis has completed
    KEY_ALERTED = 'alerted' # boolean to indicate that this analysis has been submitted as an alert
    KEY_DELAYED = 'delayed' # boolean to indicate that the analysis has been delayed

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # a reference to the RootAnalysis object this analysis belongs to 
        self.root = None

        # list of Observables generated by this Analysis
        self._observables = []

        # by default Analysis instances will not save any changes made
        # if you set this to false then the save() function will actually do something
        # NOTE that changing the value of the properties that are backed by the JSON data 
        # NOTE will automatically set this to False
        self._is_modified = True

        # free form details of the analysis
        # this is run-time-only (never saved to disk)
        # the external_details property is what loads and saves the value of this field
        self._details = None
        # the path to the storage of the details
        self.external_details_path = None
        # gets set to True when the external details has been loaded from disk
        self.external_details_loaded = False

        self.defined_details_properties = {}

        # the observable this Analysis is for
        self._observable = None

        # a brief (or brief-ish summary of what the Analysis produced)
        # the idea here is that the analyst can read this summary and get
        # a pretty good idea of what was discovered without needing to
        # load all the details of the alert
        self._summary = None

        # this flag indicates that the analysis has been fully completed
        # this defaults to True (this is important that it defaults to True)
        # in most cases analysis happens once and that's it
        # but in the case of delayed analysis this would be set to False
        # if this is set to True when the engine will not consider it done
        # (see lib/saq/modules/__init__.py accepts())
        self._completed = True

        # this is set to True when we submit this as an alert
        # currently this is really only supported by the Alert class itself
        # but eventually I would like to be able to alert from any Analysis object
        self._alerted = False

        # when we add a tag we automatically add a detection if the tag's score is > 0
        self.add_event_listener(EVENT_TAG_ADDED, self.tag_detection)

        # certain observables also generate detections
        self.add_event_listener(EVENT_OBSERVABLE_ADDED, self.observable_detection)

        # set to True when delayed analysis is requested
        self._delayed = False

    def define_dict_property(self, name, _type, docstring=None):
        def _getter(self):
            if self.details is None:
                return None

            if name not in self.details:
                return None

            return self.details[name]

        def _setter(self, value):
            if _type:
                assert value is None or isinstance(value, _type)

            if self.details is None:
                self.details = {}

            self.details[name] = value

        setattr(type(self), name, property(_getter, _setter, None, docstring))

    def set_modified(self):
        """Calling this function indicates that the details will become modified and thus need to be saved."""
        # this is called automatically when you add an Analysis object to an Observable
        self._is_modified = True # tells ACE to save the details

    def save(self):
        """Saves the current results of the Analysis to disk."""

        if not self._is_modified:
            return

        # the only thing we actually save is the self.details object
        # which much be serializable to JSON

        # do we not have anything to save?
        if not self.external_details_loaded and self._details is None:
            #logging.debug("called save() on analysis {} but nothing to save".format(self))
            return

        if self.storage_dir is None:
            raise RuntimeError("storage_dir is None for {} in {}".format(self, self.root))

        # generate a summary before we go to disk
        # this gets stored in the main json data structure
        self._summary = self.generate_summary()

        # try to catch a case where we set the data but forgot to load first
        overwrite_warning = False
        if self._details is not None and not self.external_details_loaded and self.external_details_path is not None:
            full_path = os.path.join(saq.SAQ_RELATIVE_DIR, self.root.storage_dir, '.ace', self.external_details_path)
            if os.path.exists(full_path):
                logging.warning("saving new data over existing data without loading existing data in {} from {}".format(self, self.external_details_path))
                logging.warning("previous file size was {} bytes".format(os.path.getsize(full_path)))
                logging.warning("new details is type {} value {}".format(type(self._details), self._details))
                overwrite_warning = True

        # have we figured out where we are saving the data to?
        if self.external_details_path is None:
            self.external_details_path = '{}_{}.json'.format(type(self).__name__, str(uuid.uuid4()))

        # make sure the containing directory exists
        if not os.path.exists(os.path.join(saq.SAQ_RELATIVE_DIR, self.storage_dir)):
            os.makedirs(os.path.join(saq.SAQ_RELATIVE_DIR, self.storage_dir))

        # analysis details go into a hidden directory
        if not os.path.exists(os.path.join(saq.SAQ_RELATIVE_DIR, self.storage_dir, '.ace')):
            os.makedirs(os.path.join(saq.SAQ_RELATIVE_DIR, self.storage_dir, '.ace'))
        
        # save the details
        logging.debug("SAVE: saving external details for {} to {}".format(self, self.external_details_path))
        with open(os.path.join(saq.SAQ_RELATIVE_DIR, self.storage_dir, '.ace', self.external_details_path), 'w') as fp:
            json.dump(self._details, fp, cls=_JSONEncoder)
            _track_writes()

        if overwrite_warning:
            full_path = os.path.join(saq.SAQ_RELATIVE_DIR, self.root.storage_dir, '.ace', self.external_details_path)
            logging.warning("new file size is {} bytes".format(os.path.getsize(full_path)))

        # at this point we consider the data "loaded"
        self.external_details_loaded = True

    def flush(self):
        """Calls save() and then clears the details property.  It must be load()ed again."""
        #logging.debug("called Analysis.flush() on {}".format(self))
        self.save()
        self._details = None
        self.external_details_loaded = False

    def reset(self):
        """Deletes the current analysis output if it exists."""
        logging.debug("called reset() on {}".format(self))
        if self.external_details_path is not None:
            full_path = os.path.join(saq.SAQ_RELATIVE_DIR, self.root.storage_dir, '.ace', self.external_details_path)
            if os.path.exists(full_path):
                logging.debug("removing external details file {}".format(full_path))
                os.remove(full_path)
            else:
                logging.warning("external details path {} does not exist".format(full_path))

        self._details = None
        self.external_details_path = None
        self.external_details = None
        self.external_details_loaded = False
        
    @property
    def details(self):
        # do we already have the details loaded or set?
        if self._details is not None:
            return self._details

        # are there any external details?
        if self.external_details_path is None:
            return None

        # did we already load them and then set it to None?
        if self.external_details_loaded:
            return None

        # load the external details and return those results
        self._load_details()
        return self._details

    @details.setter
    def details(self, value):
        self._details = value
        self.fire_event(self, EVENT_DETAILS_UPDATED)

    def discard_details(self):
        """Simply discards the details of this analysis, not saving any changes."""
        self._details = None
        self.external_details_loaded = False

    def details_property(self, key):
        """Returns None if self.details is None or if key does not exist in the dict. Otherwise self.details[key] is returned."""
        if self.details is None:
            return None

        if not isinstance(self.details, dict):
            raise TypeError("_return_details_property called on a non-dict self.details analysis")

        if key not in self.details:
            logging.warning("asked for missing key {} in {}".format(key, self))
            return None

        return self.details[key]

    def _load_details(self):
        """Returns the details referenced by this object as a dict or None if the operation failed."""
        # NOTE you should never call this directly
        # this is called whenever .details is requested and it hasn't been loaded yet

        if self._details is not None:
            logging.warning("called load_external_details when self._details was not None")

        if self.external_details_path is None:
            logging.error("external_details_path is None for {}".format(self))
            return None

        self._details = None
        details_file_path = os.path.join(saq.SAQ_RELATIVE_DIR, self.storage_dir, '.ace', self.external_details_path)

        if not os.path.exists(details_file_path):
            logging.warning("missing file {0}".format(details_file_path))
            return None

        if os.path.getsize(details_file_path) > 1024 * 1024:
            logging.debug("JSON file {0} is very large: {1} bytes".format(details_file_path, os.path.getsize(details_file_path)))

        try:
            with open(details_file_path, 'r') as fp:
                self._details = json.load(fp)

            _track_reads()

            self.external_details_loaded = True
            logging.debug("LOAD: loaded external details from {0} (value type {1})".format(details_file_path, type(self._details)))
            return self._details

        except Exception as e:
            logging.error("unable to load json from {0}: {1}".format(details_file_path, str(e)))
            report_exception()

    @property
    def json(self):
        result = TaggableObject.json.fget(self)
        result.update(DetectableObject.json.fget(self))
        result.update(ProfileObject.json.fget(self))
        result.update({
            Analysis.KEY_OBSERVABLES: [o.id for o in self.observables],
            TaggableObject.KEY_TAGS: self.tags,
            Analysis.KEY_DETAILS: {
                #KEY_FILE_FORMAT: 'json',
                Analysis.KEY_FILE_PATH: self.external_details_path },
            Analysis.KEY_SUMMARY: self.summary,
            Analysis.KEY_COMPLETED: self.completed,
            Analysis.KEY_ALERTED: self.alerted,
            Analysis.KEY_DELAYED: self.delayed,
        })
        return result

    @json.setter
    def json(self, value):
        assert isinstance(value, dict)
        TaggableObject.json.fset(self, value)
        DetectableObject.json.fset(self, value)
        ProfileObject.json.fset(self, value)

        if Analysis.KEY_OBSERVABLES in value:
            # and then we un-serialize them back when we load from JSON
            self.observables = value[Analysis.KEY_OBSERVABLES]

        if Analysis.KEY_DETAILS in value:
            if Analysis.KEY_FILE_PATH in value[Analysis.KEY_DETAILS]:
                self.external_details_path = value[Analysis.KEY_DETAILS][Analysis.KEY_FILE_PATH]

        if Analysis.KEY_SUMMARY in value:
            self.summary = value[Analysis.KEY_SUMMARY]

        if Analysis.KEY_COMPLETED in value:
            # NOTE that we use the underscore value here so as to not trigger an event
            self._completed = value[Analysis.KEY_COMPLETED]

        if Analysis.KEY_ALERTED in value:
            self.alerted = value[Analysis.KEY_ALERTED]

        if Analysis.KEY_DELAYED in value:
            self.delayed = value[Analysis.KEY_DELAYED]

    @property
    def delayed(self):
        return self._delayed

    @delayed.setter
    def delayed(self, value):
        assert isinstance(value, bool)
        if value != self._delayed:
            self.set_modified()

        self._delayed = value

    @property
    def storage_dir(self):
        """Local storage directory for this Analysis."""
        return self.root.storage_dir

    @property
    def observables(self):
        """A list of Observables that was generated by this Analysis.  These are references to the Observables to Alert.observables."""
        # at run time this is a list of Observable objects which are references to what it stored in the Alert.observable_store
        # when serialized to JSON this becomes a list of uuids (keys to the Alert.observable_store dict)
        return self._observables

    @observables.setter
    def observables(self, value):
        assert isinstance(value, list)
        assert all(isinstance(o, str) or isinstance(o, Observable) for o in self._observables)
        self._observables = value

    def has_observable(self, o_or_o_type=None, o_value=None):
        """Returns True if this Analysis has this Observable.  Accepts a single Observable or o_type, o_value."""
        from saq.observables import create_observable

        if isinstance(o_or_o_type, Observable):
            return o_or_o_type in self.observables
        else:
            return create_observable(o_or_o_type, o_value) in self.observables

    def clear_observables(self):
        """Clears any existing Observables. This is typically only used in special cases such as merging."""
        self._observables = []

    @property
    def children(self):
        """Returns what is considered all of the "children" of this object (in this case is the the Observables.)"""
        return self.observables

    def _load_observable_references(self):
        """Utility function to replace uuid strings in Analysis.observables with references to Observable objects in Alert.observable_store."""
        if self.root is None:
            logging.fatal("the alert property of {0} is not set when _load_observable_references was called".format(self))
            return

        _buffer = []
        for uuid in self._observables:
            if uuid not in self.root.observable_store:
                logging.warning("missing observable with uuid {} in {}".format(uuid, self.root))
            else:
                _buffer.append(self.root.observable_store[uuid])

        self._observables = _buffer
        #self._observables = [self.root.observable_store[uuid] for uuid in self._observables]

    @property
    def observable_types(self):
        """Returns the list of unique observable types for all Observables generated by this Analysis."""
        return list(set([o.type for o in self.observables]))

    def get_observables_by_type(self, o_type):
        """Returns the list of Observables that match the given type."""
        return [o for o in self.observables if o.type == o_type]

    def get_observable_by_type(self, o_type):
        """Returns the first Observable of type o_type, or None if no Observable of that type exists."""
        result = self.get_observables_by_type(o_type)
        if len(result) == 0:
            return None

        return result[0]

    @property
    def files(self):
        """Returns the list of observables of type F_FILE that actually exists with the Alert."""
        result = []
        for observable in self.observables:
            if observable.type == F_FILE:
                if os.path.exists(os.path.join(saq.SAQ_RELATIVE_DIR, self.storage_dir, observable.value)):
                    result.append(observable)

        return result

    @property
    def observable(self):
        """The Observable this Analysis is for (or None if this is an Alert.)"""
        return self._observable

    @observable.setter
    def observable(self, value):
        assert value is None or isinstance(value, Observable)
        self._observable = value

    @property
    def summary(self):
        return self._summary

    @summary.setter
    def summary(self, value):
        self._summary = value

    @property
    def completed(self):
        return self._completed

    @completed.setter
    def completed(self, value):
        assert isinstance(value, bool)

        if self._completed != value:
            self.set_modified()

        # if this state is changing from False to True then we want to fire an event
        # so that the engine can pick this up and continue analysis
        # this is because most analysis triggers off of adding Analysis objects to Observables
        # but in the case of delayed analysis the Analysis has already been added and we're just waiting for results
        # once that delayed analysis is completed we want to allow other modules a chance to look at it
        _trigger_event = False
        if self._completed == False and value == True:
            _trigger_event = True

        self._completed = value

        if _trigger_event:
            logging.debug("{} has marked as completed manually (fire event)".format(self))
            self.fire_event(self, EVENT_ANALYSIS_MARKED_COMPLETED)

    @property
    def alerted(self):
        return self._alerted

    @alerted.setter
    def alerted(self, value):
        assert isinstance(value, bool)
        if self._alerted != value:
            self.set_modified()

        self._alerted = value

    @property
    def module_path(self):
        """Returns module.path:class_name."""
        return '{}:{}'.format(self.__module__, type(self).__name__)

    def search_tree(self, tags=()):
        """Searches this object and every object in it's analysis tree for the given items.  Returns the list of items that matched."""

        if not isinstance(tags, tuple):
            tags = (tags,)

        result = []
        def _search(target):
            for tag in tags:
                if target.has_tag(tag):
                    if target not in result:
                        result.append(target)

        recurse_tree(self, _search)
        return result

    ##########################################################################
    # GUI PROPERTIES

    @property
    def jinja_should_render(self):
        """An Analysis should be rendered if the summary is not None or if it has 1 or more observables."""
        if self.summary is not None:
            return True

        if len(self.observables) > 0:
            return True

        return False

    @property
    def jinja_display_name(self):
        """Returns a visual name to display in the GUI."""
        if self.summary is not None:
            return self.summary
        
        # if we don't have a summary then just return the name of the class
        return type(self).__name__

    @property
    def jinja_is_drillable(self):
        """Returns True if the user is intended to click on the Analysis for more details, False otherwise."""
        return True

    @property
    def jinja_template_path(self):
        """Returns the jinja template to use to view the details of the analysis."""
        return "analysis/default_template.html"

    @property
    def jinja_details(self):
        """Return an alternative object to be used when displaying to the GUI.  Defaults to just returning the details propery as is."""
        return self.details

    ##########################################################################

    def add_observable(self, *args, **kwargs):
        """Adds the Observable to this Analysis.  Returns the Observable object, or the one that already existed."""
        # you can either specify an already created Observable object, or type, value and optionally time
        if len(args) > 1:
            # if more than one argument was passed here then we are using the other style
            return self._add_observable_by_spec(*args, **kwargs)
        
        # otherwise we are using the new style
        return self._add_observable(*args, **kwargs)

    def _add_observable(self, observable):
        """Adds the Observable to this Analysis.  Returns the Observable object, or the one that already existed."""
        assert isinstance(observable, Observable)
        
        # this may return an existing observable if we already have it
        observable = self.root.record_observable(observable)
        if observable not in self.observables:
            self.observables.append(observable)
            self.fire_event(self, EVENT_OBSERVABLE_ADDED, observable)

        return observable

    def _add_observable_by_spec(self, o_type, o_value, o_time=None):
        """Adds this observable specified by type, value and time to this Analysis.  
           Returns the new Observable object, or the one that already existed."""
        assert isinstance(self.root, RootAnalysis)
        assert isinstance(o_type, str)

        observable = self.root.record_observable_by_spec(o_type, o_value, o_time=o_time)
        if observable is None:
            return None

        if observable not in self.observables:
            self.observables.append(observable)
            self.fire_event(self, EVENT_OBSERVABLE_ADDED, observable)

        return observable

    def tag_detection(self, source, event, tag):
        """Adds detections points when tags are added if their score is > 0."""
        if tag.score > 0:
            self.add_detection_point("{} was tagged with {}".format(self, tag.name))

    def observable_detection(self, source, event, observable):
        """Adds detection points when yara rules and crits indicators are added as observables."""
        from saq.observables import YaraRuleObservable, IndicatorObservable

        #if isinstance(observable, YaraRuleObservable):
            #source.add_detection_point("{} matched yara rule {}".format(source.observable, observable.value))
        if isinstance(observable, IndicatorObservable):
            source.add_detection_point("{} contains crits indicator {}".format(source, observable.value))

    def __str__(self):
        if self.observable is not None:
            '{} for {}'.format(type(self).__name__, self.observable)

        return '{}'.format(type(self).__name__)

    # this is used to sort in the GUI
    def __lt__(self, other):
        if not isinstance(other, Analysis):
            return False

        self_str = self.summary if self.summary is not None else str(self)
        other_str = other.summary if other.summary is not None else str(other)

        return self_str < other_str

    ##########################################################################
    # OVERRIDABLES 

    def initialize_details(self):
        """REQUIRED: Initializes the details property."""
        raise NotImplementedError()

    def generate_summary(self):
        """Returns a human readable summary of the analysis.  Returns None if the analysis is not to be displayed in the GUI."""
        return None

    @property
    def targets(self):
        """Returns an iterator that yields all the available ProfilePointTarget objects available for this analysis."""
        return [] # defaults to no targets

    def is_suspect(self):
        """Returns True if this Analysis or any child Observables have any detection points."""
        if super().is_suspect:
            return True

        for o in self.observables:
            if o.has_detection_points():
                return True

        return False

    def always_visible(self):
        """If this returns True then this Analysis is always visible in the GUI."""
        return False

    def upgrade(self):
        """Override this function to implement any upgrade routines for the details of the analysis."""
        return None

class DeprecatedAnalysis(Analysis):
    """A dummy class used when the data.json references an Analysis class that is no longer available."""
    pass

class Relationship(object):
    """Represents a relationship to another object."""
    KEY_RELATIONSHIP_TYPE = 'type'
    KEY_RELATIONSHIP_TARGET = 'target'

    def __init__(self, r_type=None, target=None, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._r_type = r_type
        self._target = target

    def __str__(self):
        return "Relationship({} -> {})".format(self.r_type, self.target)

    def __repr__(self):
        return str(self)

    @property
    def r_type(self):
        return self._r_type
    
    @r_type.setter
    def r_type(self, value):
        assert value in VALID_RELATIONSHIP_TYPES
        self._r_type = value

    @property
    def target(self):
        return self._target

    @target.setter
    def target(self, value):
        assert isinstance(value, str) or isinstance(value, Observable)
        self._target = value

    @property
    def json(self):
        return {
            Relationship.KEY_RELATIONSHIP_TYPE: self.r_type,
            Relationship.KEY_RELATIONSHIP_TARGET: self.target.id
        }

    @json.setter
    def json(self, value):
        assert isinstance(value, dict)
        if Relationship.KEY_RELATIONSHIP_TYPE in value:
            self.r_type = value[Relationship.KEY_RELATIONSHIP_TYPE]
        if Relationship.KEY_RELATIONSHIP_TARGET in value:
            self.target = value[Relationship.KEY_RELATIONSHIP_TARGET]

class Observable(TaggableObject, DetectableObject, ProfileObject):
    """Represents a piece of information discovered in an analysis that can itself be analyzed."""

    KEY_ID = 'id'
    KEY_TYPE = 'type'
    KEY_VALUE = 'value'
    KEY_TIME = 'time'
    KEY_ANALYSIS = 'analysis'
    KEY_DIRECTIVES = 'directives'
    KEY_REDIRECTION = 'redirection'
    KEY_LINKS = 'links'
    KEY_LIMITED_ANALYSIS = 'limited_analysis'
    KEY_EXCLUDED_ANALYSIS = 'excluded_analysis'
    KEY_RELATIONSHIPS = 'relationships'

    def __init__(self, type, value, time=None, json=None, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._directives = []
        self._redirection = None
        self._links = []
        self._limited_analysis = []
        self._excluded_analysis = []
        self._relationships = []

        if json is not None:
            self.json = json
        else:
            self._id = str(uuid.uuid4())
            self._type = type
            self.value = value
            self._time = time
            self._analysis = {}
            self._directives = [] # of str
            self._redirection = None # (str)
            self._links = [] # [ str ]
            self._limited_analysis = [] # [ str ]
            self._excluded_analysis = [] # [ str ]
            self._relationships = [] # [ Relationship ]

        # reference to the RootAnalysis object
        self.root = None

        # when we add a tag we automatically add a detection if the tag's score is > 0
        self.add_event_listener(EVENT_TAG_ADDED, self.tag_detection)

    def matches(self, value):
        """Returns True if the given value matches this value of this observable.  This can be overridden to provide more advanced matching such as CIDR for ipv4."""
        return self.value == value

    @property
    def display_value(self):
        if isinstance(self.value, str):
            try:
                return self.value.encode('utf-8', errors='ignore').decode()
            except Exception as e:
                logging.warning("unable to decode value: {}".format(e))
        else:
            return self.value

    @property
    def is_suspect(self):
        """Returns True if this Observable or any child Analysis has any detection points."""
        if super().is_suspect:
            return True

        for a in self._analysis.values():
            if not a:
                continue
            if a.has_detection_points():
                return True

        return False

    def always_visible(self):
        """If this returns True then this Analysis is always visible in the GUI."""
        return False

    @property
    def json(self):
        result = TaggableObject.json.fget(self)
        result.update(DetectableObject.json.fget(self))
        result.update(ProfileObject.json.fget(self))
        result.update({
            Observable.KEY_ID: self.id,
            Observable.KEY_TYPE: self.type,
            Observable.KEY_TIME: self.time,
            # TODO these should all probably save as the internal var
            Observable.KEY_VALUE: self._value,
            Observable.KEY_ANALYSIS: self.analysis,
            Observable.KEY_DIRECTIVES: self.directives,
            Observable.KEY_REDIRECTION: self._redirection,
            Observable.KEY_LINKS: self._links,
            Observable.KEY_LIMITED_ANALYSIS: self._limited_analysis,
            Observable.KEY_EXCLUDED_ANALYSIS: self._excluded_analysis,
            Observable.KEY_RELATIONSHIPS: self._relationships,
        })
        return result

    @json.setter
    def json(self, value):
        assert isinstance(value, dict)
        TaggableObject.json.fset(self, value)
        DetectableObject.json.fset(self, value)
        ProfileObject.json.fset(self, value)

        if Observable.KEY_ID in value:
            self.id = value[Observable.KEY_ID]
        if Observable.KEY_TYPE in value:
            self.type = value[Observable.KEY_TYPE]
        if Observable.KEY_TIME in value:
            self.time = value[Observable.KEY_TIME]
        if Observable.KEY_VALUE in value:
            self._value = value[Observable.KEY_VALUE]
        if Observable.KEY_ANALYSIS in value:
            self.analysis = value[Observable.KEY_ANALYSIS]
        if Observable.KEY_DIRECTIVES in value:
            self.directives = value[Observable.KEY_DIRECTIVES]
        if Observable.KEY_REDIRECTION in value:
            self._redirection = value[Observable.KEY_REDIRECTION]
        if Observable.KEY_LINKS in value:
            self._links = value[Observable.KEY_LINKS]
        if Observable.KEY_LIMITED_ANALYSIS in value:
            self._limited_analysis = value[Observable.KEY_LIMITED_ANALYSIS]
        if Observable.KEY_EXCLUDED_ANALYSIS in value:
            self._excluded_analysis = value[Observable.KEY_EXCLUDED_ANALYSIS]
        if Observable.KEY_RELATIONSHIPS in value:
            self._relationships = value[Observable.KEY_RELATIONSHIPS]

    @property
    def id(self):
        """A unique ID for this Observable instance."""
        return self._id

    @id.setter
    def id(self, value):
        assert isinstance(value, str)
        self._id = value

    @property
    def type(self):
        return self._type

    @type.setter
    def type(self, value):
        assert value in VALID_OBSERVABLE_TYPES
        self._type = value

    @property
    def value(self):
        return self._value

    @value.setter
    def value(self, value):
        self._value = value

    @property
    def time(self):
        return self._time

    @time.setter
    def time(self, value):
        self._time = value # TODO check value

    @property
    def directives(self):
        return self._directives

    @directives.setter
    def directives(self, value):
        assert isinstance(value, list)
        self._directives = value

    def add_directive(self, directive):
        """Adds a directive that analysis modules might use to change their behavior."""
        assert isinstance(self.directives, list)
        if directive not in self.directives:
            self.directives.append(directive)
            logging.debug("added directive {} to {}".format(directive, self))
            self.fire_event(self, EVENT_DIRECTIVE_ADDED, directive)

    def has_directive(self, directive):
        """Returns True if this Observable has this directive."""
        if self.directives:
            return directive in self.directives

        return False

    def remove_directive(self, directive):
        """Removes the given directive from this observable."""
        if directive in self.directives:
            self.directives.remove(directive)
            logging.debug("removed directive {} from {}".format(directive, self))

    def copy_directives_to(self, target):
        """Copies all directives applied to this Observable to another Observable."""
        assert isinstance(target, Observable)
        for directive in self.directives:
            target.add_directive(directive)

    @property
    def redirection(self):
        if not self._redirection:
            return None

        return self.root.observable_store[self._redirection]

    @redirection.setter
    def redirection(self, value):
        assert isinstance(value, Observable)
        self._redirection = value.id

    @property
    def links(self):
        if not self._links:
            return []

        return [self.root.observable_store[x] for x in self._links]

    @links.setter
    def links(self, value):
        assert isinstance(value, list)
        for v in value:
            assert isinstance(v, Observable)

        self._links = [x.id for x in value]

    def add_link(self, target):
        """Links this Observable object to another Observable object.  Any tags
           applied to this Observable are also applied to the target Observable."""

        assert isinstance(target, Observable)

        # two observables cannot link to each other
        # that would cause a recursive loop in add_tag override
        if self in target.links:
            logging.warning("{} already links to {}".format(target, self))
            return
        
        if target.id not in self._links:
            self._links.append(target.id)

        logging.debug("linked {} to {}".format(self, target))

    @property
    def limited_analysis(self):
        return self._limited_analysis

    @limited_analysis.setter
    def limited_analysis(self, value):
        assert isinstance(value, list)
        assert all([isinstance(x, str) for x in value])
        self._limited_analysis = value

    @property
    def excluded_analysis(self):
        """Returns a list of analysis modules in the form of module:class that are excluded from analyzing this Observable."""
        return self._excluded_analysis

    @excluded_analysis.setter
    def excluded_analysis(self, value):
        assert isinstance(value, list)
        self._excluded_analysis = value

    def exclude_analysis(self, analysis_module):
        """Directs the engine to avoid analyzing this Observabe with this AnalysisModule.
           analysis_module can be an instance of type AnalysisModule or the type of the AnalysisModule itself"""
        from saq.modules import AnalysisModule
        # TODO check that the type inherits from AnalysisModule
        assert isinstance(analysis_module, type) or isinstance(analysis_module, AnalysisModule)
        if isinstance(analysis_module, AnalysisModule):
            _type = type(analysis_module)
        else:
            _type = analysis_module

        name = '{}:{}'.format(analysis_module.__module__, str(_type))
        if name not in self.excluded_analysis:
            self.excluded_analysis.append(name)

    def is_excluded(self, analysis_module):
        """Returns True if this Observable has been excluded from analysis by this AnalysisModule."""
        from saq.modules import AnalysisModule
        assert isinstance(analysis_module, AnalysisModule)
        name = '{}:{}'.format(analysis_module.__module__, str(type(analysis_module)))
        return name in self.excluded_analysis

    @property
    def relationships(self):
        return self._relationships

    @relationships.setter
    def relationships(self, value):
        self._relationships = value

    def has_relationship(self, _type):
        for r in self.relationships:
            if r.r_type == _type:
                return True

        return False

    def _load_relationships(self):
        temp = []
        for value in self.relationships:
            if isinstance(value, dict):
                r = Relationship()
                r.json = value

                try:
                    # find the observable this points to and reference that
                    r.target = self.root._observable_store[r.target]
                except KeyError:
                    logging.error("missing observable uuid {} in {}".format(r.target, self))
                    continue

                value = r

            temp.append(value)

        self._relationships = temp

    def add_relationship(self, r_type, target):
        """Adds a new Relationship to this Observable.
           Existing relationship is returned, other new Relationship object is added and returned."""
        assert r_type in VALID_RELATIONSHIP_TYPES
        assert isinstance(target, Observable)

        for r in self.relationships:
            if r.r_type == r_type and r.target == target:
                return r

        r = Relationship(r_type, target)
        self.relationships.append(r)
        self.fire_event(self, EVENT_RELATIONSHIP_ADDED, target, relationship=r)
        return r

    def get_relationships_by_type(self, r_type):
        """Returns the list of Relationship objects by type."""
        return [r for r in self.relationships if r.r_type == r_type]

    def get_relationship_by_type(self, r_type):
        """Returns the first Relationship found of a given type, or None if none exist."""
        result = self.get_relationships_by_type(r_type)
        if not result:
            return None

        return result[0]

    def add_tag(self, *args, **kwargs):
        super().add_tag(*args, **kwargs)
        for target in self.links:
            target.add_tag(*args, **kwargs)

    @property
    def time_datetime(self):
        """Return a datetime.datetime representation of self.time."""
        if self.time is None:
            return None

        if isinstance(self.time, datetime.datetime):
            return self.time

        return datetime.datetime.strptime(self.time, event_time_format)

    @property
    def analysis(self):
        """The dict of Analysis objects executed against this Observable.
           key = Analysis.module_path, value = Analysis or False."""
        return self._analysis

    @analysis.setter
    def analysis(self, value):
        assert isinstance(value, dict)
        self._analysis = value

    @property
    def all_analysis(self):
        """Returns a list of an Analysis objects executed against this Observable."""
        # we skip over lookups that return False here
        return [a for a in self._analysis.values() if isinstance(a, Analysis)]

    @property
    def children(self):
        """Returns what is considered all of the "children" of this object (in this case it is the Analysis.)"""
        return [a for a in self.all_analysis if a]

    @property
    def parents(self):
        """Returns a list of Analysis objects that have this Observable."""
        return [a for a in self.root.all_analysis if a and a.has_observable(self)]

    @property
    def dependencies(self):
        """Returns the list of all AnalysisDependency objects targeting this Observable."""
        return [dep for dep in self.root.dependency_tracking if dep.target_observable_id == self.id]

    def add_dependency(self, source_analysis, target_observable, target_analysis):
        self.root.add_dependency(self, source_analysis, target_observable, target_analysis)

    def get_dependency(self, _type):
        assert isinstance(_type, str)
        for dep in self.dependencies:
            if dep.target_analysis_type == _type:
                return dep

        return None

    @property
    def jinja_template_path(self):
        """Return what is to be used when viewing this object via jinja."""
        return "analysis/default_observable.html"

    @property
    def jinja_available_actions(self):
        """Returns a list of ObservableAction-based objects that represent what a user can do with this Observable."""
        return []

    def add_analysis(self, analysis):
        assert isinstance(analysis, Analysis)
        assert isinstance(self.root, RootAnalysis)

        # set the document root for this analysis
        analysis.root = self.root
        # set the source of the Analysis
        analysis.observable = self

        # does this analysis already exist?
        # usually this is because you copied and pasted another AnalysisModule and didn't change the generated_analysis_type function
        if analysis.module_path in self.analysis and not (self.analysis[analysis.module_path] is analysis):
            logging.error("replacing analysis {} with {} for {} (are you returning the correct type from generated_analysis_type()?)".format(
                self.analysis[analysis.module_path], analysis, self))
        
        # newly added analysis is always set to modified so it gets saved to JSON file
        analysis.set_modified()

        self.analysis[analysis.module_path] = analysis
        logging.debug("added analysis {} to observable {}".format(analysis, self))
        self.fire_event(self, EVENT_ANALYSIS_ADDED, analysis)

    def add_no_analysis(self, analysis):
        """Records the fact that the analysis module that generates this Analysis did not for this Observable."""
        assert isinstance(analysis, Analysis)
        assert isinstance(self.root, RootAnalysis)

        # does this analysis already exist?
        # usually this is because you copied and pasted another AnalysisModule and didn't change the generated_analysis_type function
        if analysis.module_path in self.analysis:
            logging.debug("replacing analysis {} with empty analysis - means you returned False from execute_analysis but you still added analysis".format(
                self.analysis[analysis.module_path]))
            return

        # this is used to remember that analysis was not generated
        self.analysis[analysis.module_path] = False
        logging.debug("recorded no analysis of type {} for observable {}".format(type(analysis), self))

    def get_analysis(self, analysis_type):
        """Returns the Analysis object for the given type of analysis, or None if it does not exist (yet).
           analysis_type can either be the type of the Analysis to get or str(type(Analysis))"""
        assert isinstance(analysis_type, type) or isinstance(analysis_type, str)

        if isinstance(analysis_type, type):
            try:
                return self.analysis[analysis_type().module_path]
            except KeyError:
                return None
        else:
            for a in self.analysis.values():
                if str(type(a)) == analysis_type:
                    return a

        return None

    def analysis_exists(self, analysis_type):
        """Returns True if an Analysis of the given type exists."""
        for a in self.analysis.values():
            if type(a) == analysis_type:
                return True

        return False

    def _load_analysis(self):
        assert isinstance(self.analysis, dict)

        # see the module_path property of the Analysis object
        for module_path in self.analysis.keys():
            # was there Analysis generated?
            if isinstance(self.analysis[module_path], bool):
                continue
                
            # have we already translated this?
            if isinstance(self.analysis[module_path], Analysis):
                continue

            assert isinstance(self.analysis[module_path], dict)

            module_json = self.analysis[module_path]
            a = None

            # has this module been deprecated?
            for deprecated_module in saq.CONFIG['deprecated_modules'].values():
                if module_path == deprecated_module:
                    logging.debug("{0} references deprecated module {1}".format(self, module_path))
                    a = DeprecatedAnalysis()
                    break

            if a is None:

                #logging.debug("dynamically loading {0}".format(module_path))
                m = re.match(r'^([^:]+):(.+)$', module_path)
                assert m is not None
                (_module, _class) = m.groups()

                try:
                    m = importlib.import_module(_module)
                except Exception as e:
                    logging.error("unable to import module {0}: {1}".format(_module, str(e)))
                    report_exception()
                    return None

                try:
                    c = getattr(m, _class)
                except Exception as e:
                    logging.error("unable to import class {0} from module {1}: {2}".format(
                        _class, _module, str(e)))
                    report_exception()
                    return None

                try:
                    a = c()
                except Exception as e:
                    logging.error("unable to create instance of {0} from module {1}: {2}".format(
                        _class, _module, str(e)))
                    report_exception()
                    return None

            a.root = self.root # set the analysis root
            a.observable = self # set the source of the analysis
            a.json = module_json

            # set up the EVENT_GLOBAL_* events
            a.add_event_listener(EVENT_OBSERVABLE_ADDED, a.root._fire_global_events)
            a.add_event_listener(EVENT_TAG_ADDED, a.root._fire_global_events)

            self.analysis[module_path] = a # replace the JSON dict with the actual object

    def clear_analysis(self):
        """Deletes all analysis records for this observable."""
        self.analysis = {}

    def search_tree(self, tags=()):
        """Searches this object and every object in it's analysis tree for the given items.  Returns the list of items that matched."""

        if not isinstance(tags, tuple):
            tags = (tags,)
        
        result = []
        def _search(target):
            for tag in tags:
                if target.has_tag(tag):
                    if target not in result:
                        result.append(target)

        recurse_tree(self, _search)
        return result

    def tag_detection(self, source, event, tag):
        """Adds detections points when tags are added if their score is > 0."""
        if tag.score > 0:
            self.add_detection_point("{} was tagged with {}".format(self, tag.name))

    @property
    def targets(self):
        """Observables typically won't have any additional profile point targets."""
        return []

    def __str__(self):
        if self.time is not None:
            return u'{}({}@{})'.format(self.type, self.value, self.time)
        else:
            return u'{}({})'.format(self.type, self.value)

    def _compare_value(self, other_value):
        """Default implementation to compare the value of this observable to the value of another observable.
           By default does == comparison, can be overridden."""
        return self.value == other_value

    def __eq__(self, other):
        if not isinstance(other, Observable):
            return False

        # exactly the same?
        if other.id == self.id:
            return True

        if other.type != self.type:
            return False

        if self.time is not None or other.time is not None:
            return self.time == other.time and self._compare_value(other.value)
        else:
            return self._compare_value(other.value)

    def __lt__(self, other):
        if not isinstance(other, Observable):
            return False

        if other.type == self.type:
            return self.value < other.value

        return self.type < other.type

    def __hash__(self):
        """Returns the hash of type:value."""
        return str(self).__hash__() # XXX this isn't right, is it?

class AnalysisDependency(object):

    # json dictionary keys
    KEY_TARGET_OBSERVABLE_ID = 'target_observable_id'
    KEY_TARGET_ANALYSIS_TYPE = 'target_analysis_type'
    KEY_SOURCE_OBSERVABLE_ID = 'source_observable_id'
    KEY_SOURCE_ANALYSIS_TYPE = 'source_analysis_type'
    KEY_STATUS = 'status'
    KEY_FAILURE_REASON = 'failure_reason'
    KEY_RESOLVED = 'resolved'

    STATUS_READY = 'ready'
    STATUS_FAILED = 'failed'
    STATUS_COMPLETED = 'completed'
    STATUS_RESOLVED = 'resolved'

    """Represents an dependency between two Analysis objects for a given Observable."""
    def __init__(self, target_observable_id, target_analysis_type, source_observable_id, source_analysis_type,
                 status=STATUS_READY, failure_reason=None):

        assert isinstance(target_observable_id, str)
        assert isinstance(target_analysis_type, str)
        assert isinstance(source_observable_id, str)
        assert isinstance(source_analysis_type, str)
        assert isinstance(status, str)
        assert failure_reason is None or isinstance(failure_reason, str)

        self.target_observable_id = target_observable_id
        self.target_analysis_type = target_analysis_type
        self.source_observable_id = source_observable_id
        self.source_analysis_type = source_analysis_type
        self.status = status
        self.failure_reason = failure_reason

        # a reference to the RootAnalysis object
        self.root = None

        # cached references
        self._target_observable = None
        self._target_analysis = None
        self._source_observable = None
        self._source_analysis = None

        self.next = None # the next AnalysisDependency that this one depends on
        self.prev = None 

    def set_status_failed(self, reason=None):
        self.status = AnalysisDependency.STATUS_FAILED
        self.failure_reason = reason

    def set_status_completed(self):
        self.status = AnalysisDependency.STATUS_COMPLETED

    def set_status_resolved(self):
        self.status == AnalysisDependency.STATUS_RESOLVED

    @property
    def ready(self):
        """Returns True if target analysis has not been completed."""
        return self.status == AnalysisDependency.STATUS_READY

    @property
    def completed(self):
        """Returns True if the target analysis has been completed."""
        return self.status == AnalysisDependency.STATUS_COMPLETED

    @property
    def resolved(self):
        """Returns True if the source analysis has been completed."""
        return self.status == AnalysisDependency.STATUS_RESOLVED

    def increment_status(self):
        if self.status == AnalysisDependency.STATUS_READY:
            self.status = AnalysisDependency.STATUS_COMPLETED
        elif self.status == AnalysisDependency.STATUS_COMPLETED:
            self.status = AnalysisDependency.STATUS_RESOLVED

    @property
    def score(self):
        score = 0
        node = self.next
        while node:
            score += 1
            node = node.next

        return score

    @property
    def failed(self):
        """Returns True if this dependency (or any in the chain of dependencies) has failed."""
        node = self
        while node:
            if node.status == AnalysisDependency.STATUS_FAILED:
                return True

            node = node.next

        return False

    @property
    def delayed(self):
        """Returns True if the target analysis (or any in the chain of dependencies) is delayed."""
        if not self.root:
            raise RuntimeError("delayed property of AnalysisDependency called before root property was set")

        node = self
        while node:
            target_analysis = self.root.get_observable(node.target_observable_id).get_analysis(node.target_analysis_type)
            if target_analysis and target_analysis.delayed:
                return True

            node = node.next

        return False

    @property
    def json(self):
        return {
            AnalysisDependency.KEY_TARGET_OBSERVABLE_ID: self.target_observable_id,
            AnalysisDependency.KEY_TARGET_ANALYSIS_TYPE: self.target_analysis_type,
            AnalysisDependency.KEY_SOURCE_OBSERVABLE_ID: self.source_observable_id,
            AnalysisDependency.KEY_SOURCE_ANALYSIS_TYPE: self.source_analysis_type,
            AnalysisDependency.KEY_STATUS: self.status,
            AnalysisDependency.KEY_FAILURE_REASON: self.failure_reason,
        }

    @staticmethod
    def from_json(json_dict):
        """Returns a new AnalysisDependency object from the given JSON dict."""
        return AnalysisDependency(target_observable_id=json_dict[AnalysisDependency.KEY_TARGET_OBSERVABLE_ID],
                                  target_analysis_type=json_dict[AnalysisDependency.KEY_TARGET_ANALYSIS_TYPE],
                                  source_observable_id=json_dict[AnalysisDependency.KEY_SOURCE_OBSERVABLE_ID],
                                  source_analysis_type=json_dict[AnalysisDependency.KEY_SOURCE_ANALYSIS_TYPE],
                                  status=json_dict[AnalysisDependency.KEY_STATUS],
                                  failure_reason=json_dict[AnalysisDependency.KEY_FAILURE_REASON])

    def __str__(self):
        return "Analysis Dependency {}({}) --> {}({}) ({}){}".format(
                self.source_analysis_type, 
                self.source_observable_id if self.root is None else self.source_observable, 
                self.target_analysis_type, 
                self.target_observable_id if self.root is None else self.target_observable, 
                self.status,
                ' failure reason: {}'.format(self.failure_reason) if self.failure_reason else '')

    def __repr__(self):
        return self.__str__()

    @property
    def target_observable(self):
        """Returns the target Observable that needs to be analyzed."""
        if self._target_observable:
            return self._target_observable

        self._target_observable = self.root.get_observable(self.target_observable_id)
        return self._target_observable

    @property
    def source_observable(self):
        """Returns the Observable that was being analyzed when the request was made."""
        if self._source_observable:
            return self._source_observable

        self._source_observable = self.root.get_observable(self.source_observable_id)
        return self._source_observable

#
# saq.database.Alert vs saq.analysis.Alert
# This system is designed to work both with and without the database running.
# This means you can load Alert objects directly from the JSON rather than
# requiring you to do a database query first.
#
# The hiearchy of relationships goes Analysis --> Alert --> saq.database.Alert
# 
# *** Implementation Details ***
# The base saq.analysis.Alert contains properties with leading underscores.
# These are exposed via @property decorators.  The names assigned to the
# @property decorators match the names in saq.database.Alert.
#
# The saq.database.Alert class essentially overwrites these properties with
# SQLAlchemy column objects.
#
# Thus, when working with saq.analysis.Alert objects the properties you are
# working with are the _underscore values stored inside the object.  When
# working with the database object you are accessing Column - based objects.
# Essentially, the _underscore objects are *ignored* when working with the
# database Alert object.
#
# Therefor, it is important to NOT use the _underscore properties (use the
# decoratored @property instead.)
#

class RootAnalysis(LocalLockableObject, Analysis):
    """Root of analysis.  This can potentially become an Alert."""

    def __init__(self, 
                 tool=None, 
                 tool_instance=None, 
                 alert_type=None, 
                 desc=None, 
                 event_time=None, 
                 action_counters=None,
                 details=None, 
                 name=None,
                 remediation=None,
                 state=None,
                 uuid=None,
                 location=None,
                 storage_dir=None,
                 company_name=None,
                 company_id=None,
                 *args, **kwargs):

        import uuid as uuidlib

        super().__init__(*args, **kwargs)

        # this is set to True if a field backed by JSON is modified
        # XXX for now we just force this to write every time
        # XXX it's going to be complex to track all the changes in the tree without a proper event system
        self._is_modified = True

        # we are the root
        self.root = self

        self._uuid = str(uuidlib.uuid4()) # default is new uuid
        if uuid:
            self.uuid = uuid

        self._tool = None
        if tool:
            self.tool = tool

        self._tool_instance = None
        if tool_instance:
            self.tool_instance = tool_instance

        self._alert_type = None
        if alert_type:
            self.alert_type = alert_type

        self._description = None
        if desc:
            self.description = desc

        self._event_time = None
        if event_time:
            self.event_time = event_time

        self._name = None
        if name:
            self.name = name

        self._remediation = None
        if remediation:
            self.remediation = remediation

        self._details = None
        if details:
            self.details = details

        self._action_counters = {}
        if action_counters:
            self.action_counters = action_counters

        self._location = None
        if location:
            self.location = location
        else:
            # if a location is not specified then we default to locally defined value
            self.location = saq.SAQ_NODE

        self._storage_dir = None
        if storage_dir:
            self.storage_dir = storage_dir

        self._state = {}
        if state:
            self.state = state

        self._company_name = None

        try:
            # we take the default company ownership from the config file (if specified)
            self._company_name = saq.CONFIG['global']['company_name']
        except KeyError:
            pass

        if company_name:
            self._company_name = company_name

        try:
            self._company_id = saq.CONFIG['global'].getint('company_id')
        except KeyError:
            pass

        if company_id:
            self._company_id = company_id

        # all of the Observables discovered during analysis go into the observable_store
        # these objects are what are serialized to and from JSON
        self._observable_store = {} # key = uuid, value = Observable object

        # set to True after load() is called
        self.is_loaded = False

        # we keep track of when delayed initially starts here
        # to allow for eventual timeouts when something is wrong
        # key = analysis_module:observable_uuid
        # value = datetime.datetime of when the first analysis request was made
        self.delayed_analysis_tracking = {} 

        # list of AnalysisDependency objects
        self.dependency_tracking = []

        # we fire EVENT_GLOBAL_TAG_ADDED and EVENT_GLOBAL_OBSERVABLE_ADDED when we add tags and observables to anything
        # (note that we also need to add these global event listeners when we deserialize)
        self.add_event_listener(EVENT_TAG_ADDED, self._fire_global_events)
        self.add_event_listener(EVENT_OBSERVABLE_ADDED, self._fire_global_events)

    def _fire_global_events(self, source, event_type, *args, **kwargs):
        """Fires EVENT_GLOBAL_* events."""
        if event_type == EVENT_TAG_ADDED:
            self.fire_event(source, EVENT_GLOBAL_TAG_ADDED, *args, **kwargs)
        elif event_type == EVENT_OBSERVABLE_ADDED:
            observable = args[0]
            observable.add_event_listener(EVENT_TAG_ADDED, self._fire_global_events)
            observable.add_event_listener(EVENT_ANALYSIS_ADDED, self._fire_global_events)
            self.fire_event(source, EVENT_GLOBAL_OBSERVABLE_ADDED, *args, **kwargs)
        elif event_type == EVENT_ANALYSIS_ADDED:
            analysis = args[0]
            analysis.add_event_listener(EVENT_TAG_ADDED, self._fire_global_events)
            analysis.add_event_listener(EVENT_OBSERVABLE_ADDED, self._fire_global_events)
            self.fire_event(source, EVENT_GLOBAL_ANALYSIS_ADDED, *args, **kwargs)
        else:
            logging.error("unsupported global event type: {}".format(event_type))
        
    #
    # the json property is used for internal storage
    #
    
    # json keys
    KEY_ID = 'id'
    KEY_UUID = 'uuid'
    KEY_TOOL = 'tool'
    KEY_TOOL_INSTANCE = 'tool_instance'
    KEY_TYPE = 'type'
    KEY_DESCRIPTION = 'description'
    KEY_EVENT_TIME = 'event_time'
    KEY_ACTION_COUNTERS = 'action_counters'
    KEY_DETAILS = 'details'
    KEY_OBSERVABLE_STORE = 'observable_store'
    KEY_NAME = 'name'
    KEY_REMEDIATION = 'remediation'
    KEY_STATE = 'state'
    KEY_LOCATION = 'location'
    KEY_NETWORK = 'network'
    KEY_COMPANY_NAME = 'company_name'
    KEY_COMPANY_ID = 'company_id'
    KEY_DELAYED_ANALYSIS_TRACKING = 'delayed_analysis_tracking'
    KEY_DEPENDECY_TRACKING = 'dependency_tracking'

    @property
    def json(self):
        result = Analysis.json.fget(self)
        result.update({
            RootAnalysis.KEY_UUID: self.uuid,
            RootAnalysis.KEY_TOOL: self.tool,
            RootAnalysis.KEY_TOOL_INSTANCE: self.tool_instance,
            RootAnalysis.KEY_TYPE: self.alert_type,
            RootAnalysis.KEY_DESCRIPTION: self.description,
            RootAnalysis.KEY_EVENT_TIME: self.event_time,
            RootAnalysis.KEY_ACTION_COUNTERS: self.action_counters,
            #RootAnalysis.KEY_DETAILS: self.details, <-- this is saved externally
            RootAnalysis.KEY_OBSERVABLE_STORE: self.observable_store,
            RootAnalysis.KEY_NAME: self.name,
            RootAnalysis.KEY_REMEDIATION: self.remediation,
            RootAnalysis.KEY_STATE: self.state,
            RootAnalysis.KEY_LOCATION: self.location,
            RootAnalysis.KEY_COMPANY_NAME: self.company_name,
            RootAnalysis.KEY_COMPANY_ID: self.company_id,
            RootAnalysis.KEY_DELAYED_ANALYSIS_TRACKING: self.delayed_analysis_tracking,
            RootAnalysis.KEY_DEPENDECY_TRACKING: self.dependency_tracking,
        })
        return result

    @json.setter
    def json(self, value):
        assert isinstance(value, dict)

        # this is important to do first before we load Observable references
        if RootAnalysis.KEY_OBSERVABLE_STORE in value:
            self.observable_store = value[RootAnalysis.KEY_OBSERVABLE_STORE]

        Analysis.json.fset(self, value)

        # load this alert from the given json data
        if RootAnalysis.KEY_UUID in value:
            self.uuid = value[RootAnalysis.KEY_UUID]
        if RootAnalysis.KEY_TOOL in value:
            self.tool = value[RootAnalysis.KEY_TOOL]
        if RootAnalysis.KEY_TOOL_INSTANCE in value:
            self.tool_instance = value[RootAnalysis.KEY_TOOL_INSTANCE]
        if RootAnalysis.KEY_TYPE in value:
            self.alert_type = value[RootAnalysis.KEY_TYPE]
        if RootAnalysis.KEY_DESCRIPTION in value:
            self.description = value[RootAnalysis.KEY_DESCRIPTION]
        if RootAnalysis.KEY_EVENT_TIME in value:
            self.event_time = value[RootAnalysis.KEY_EVENT_TIME]
        if RootAnalysis.KEY_ACTION_COUNTERS in value:
            self.action_counters = value[RootAnalysis.KEY_ACTION_COUNTERS]
        if RootAnalysis.KEY_NAME in value:
            self.name = value[RootAnalysis.KEY_NAME]
        if RootAnalysis.KEY_REMEDIATION in value:
            self.remediation = value[RootAnalysis.KEY_REMEDIATION]
        if RootAnalysis.KEY_STATE in value:
            self.state = value[RootAnalysis.KEY_STATE]
        if RootAnalysis.KEY_LOCATION in value:
            self.location = value[RootAnalysis.KEY_LOCATION]
        if RootAnalysis.KEY_COMPANY_NAME in value:
            self.company_name = value[RootAnalysis.KEY_COMPANY_NAME]
        if RootAnalysis.KEY_COMPANY_ID in value:
            self.company_id = value[RootAnalysis.KEY_COMPANY_ID]
        if RootAnalysis.KEY_DELAYED_ANALYSIS_TRACKING in value:
            self.delayed_analysis_tracking = value[RootAnalysis.KEY_DELAYED_ANALYSIS_TRACKING]
            for key in self.delayed_analysis_tracking.keys():
                self.delayed_analysis_tracking[key] = dateutil.parser.parse(self.delayed_analysis_tracking[key])
        if RootAnalysis.KEY_DEPENDECY_TRACKING in value:
            self.dependency_tracking = value[RootAnalysis.KEY_DEPENDECY_TRACKING]

    @property
    def uuid(self):
        return self._uuid

    @uuid.setter
    def uuid(self, value):
        assert isinstance(value, str)
        self._uuid = value
        self.set_modified()

    @property
    def tool(self):
        """The name of the tool that generated the alert (ex: splunk)."""
        return self._tool

    @tool.setter
    def tool(self, value):
        assert value is None or isinstance(value, str)
        self._tool = value
        self.set_modified()

    @property
    def tool_instance(self):
        """The instance of the tool that generated the alert (ex: the hostname of the sensor)."""
        return self._tool_instance

    @tool_instance.setter
    def tool_instance(self, value):
        assert value is None or isinstance(value, str)
        self._tool_instance = value
        self.set_modified()

    @property
    def alert_type(self):
        """The type of the alert (ex: splunk - ipv4 search)."""
        return self._alert_type

    @alert_type.setter
    def alert_type(self, value):
        assert value is None or isinstance(value, str)
        self._alert_type = value
        self.set_modified()

    @property
    def description(self):
        """A brief one line description of the alert (ex: high_pdf_xor_kernel32 match in email attachment)."""
        return self._description

    @description.setter
    def description(self, value):
        assert value is None or isinstance(value, str)
        self._description = value
        self.set_modified()

    @property
    def event_time(self):
        #"""YYYY-MM-DD HH:MM:SS UTC <-- the time the event occurred, NOT when SAQ received it."""
        return self._event_time

    @event_time.setter
    def event_time(self, value):
        if value is None:
            self._event_time = None
        elif isinstance(value, datetime.datetime):
            self._event_time = value.strftime(event_time_format) 
        elif isinstance(value, str):
            self._event_time = value
        else:
            raise ValueError("event_time must be a datetime.datetime object or a string in the format "
                             "%Y-%m-%d %H:%M:%S you passed {}".format(type(value).__name__))

        self.set_modified()

    # override the summary property of the Analysis object to reflect the description
    @property
    def summary(self):
        return self.description

    @summary.setter
    def summary(self, value):
        """This does nothing, but it does get called when you assign to the json property."""
        pass

    @property
    def event_time_datetime(self):
        """Return a datetime.datetime representation of self.event_time."""
        if self._event_time is None:
            return None
        return datetime.datetime.strptime(self._event_time, event_time_format)

    @property
    def action_counters(self):
        """A dict() with generic key:value pairs used by the modules to limit specific actions."""
        return self._action_counters

    @action_counters.setter
    def action_counters(self, value):
        assert value is None or isinstance(value, dict)
        self._action_counters = value
        self.set_modified()

    def get_action_counter(self, value):
        """Get the current value of an action counter.  Returns 0 if the action counter doesn't exist yet."""
        try:
            return self.action_counters[value]
        except KeyError:
            return 0

    def increment_action_counter(self, value):
        """Increment the value of an action counter.  Creates a new one if needed."""
        if value not in self.action_counters:
            self.action_counters[value] = 0

        self.action_counters[value] += 1
        logging.debug("action counter {} for {} incremented to {}".format(value, self, self.action_counters[value]))
        self.set_modified()

    @property
    def observable_store(self):
        """Hash of the actual Observable objects generated during the analysis of this Alert.  key = uuid, value = Observable."""
        return self._observable_store

    @observable_store.setter
    def observable_store(self, value):
        assert isinstance(value, dict)
        self._observable_store = value
        self.set_modified()

    @property
    def storage_dir(self):
        """The base storage directory for output."""
        return self._storage_dir

    @storage_dir.setter
    def storage_dir(self, value):
        assert isinstance(value, str)
        self._storage_dir = value
        self.set_modified()

    def initialize_storage(self):
        assert self.storage_dir
        try:
            target_dir = os.path.join(saq.SAQ_RELATIVE_DIR, self.storage_dir)
            if not os.path.exists(target_dir):
                os.makedirs(target_dir)

            target_dir = os.path.join(target_dir, '.ace')
            if not os.path.exists(target_dir):
                os.makedirs(target_dir)

            logging.debug("initialized storage directory {}".format(target_dir))

        except Exception as e:
            logging.error("unable to initialize storage: {}".format(e))
            report_exception()
            raise e

    @property
    def location(self):
        """Returns the FQDN of the host that contains this analysis."""
        return self._location

    @location.setter
    def location(self, value):
        assert isinstance(value, str)
        self._location = value
        self.set_modified()

    @property
    def json_path(self):
        """Path to the JSON file that stores this alert."""
        return os.path.join(saq.SAQ_RELATIVE_DIR, self.storage_dir, 'data.json')

    @property
    def name(self):
        """An optional property that defines a name for an alert.  
           Used to track and document analyst response instructions."""
        return self._name

    @name.setter
    def name(self, value):
        self._name = value
        self.set_modified()

    @property
    def remediation(self):
        """A list of remediation actions that are possible for this alert."""
        return self._remediation

    @remediation.setter
    def remediation(self, value):
        assert value is None or isinstance(value, list)
        self._remediation = value
        self.set_modified()

    @property
    def state(self):
        """A free form dict that can store any value. Used by AnalysisModules to maintain state."""
        return self._state

    @state.setter
    def state(self, value):
        self._state = value
        self.set_modified()

    @property
    def company_name(self):
        """The organzaition this analysis belongs to."""
        return self._company_name

    @company_name.setter
    def company_name(self, value):
        self._company_name = value
        self.set_modified()

    @property
    def company_id(self):
        return self._company_id

    @company_id.setter
    def company_id(self, value):
        self._company_id = value
        self.set_modified()

    @property
    def delayed_dir(self):
        """Returns the subdirectory the contains tracking files for delayed analysis."""
        if not self.storage_dir:
            return None

        return os.path.join(self.storage_dir, '.delayed')

    @property
    def delayed(self):
        """Returns True if any delayed analysis is outstanding."""
        try:
            return len(os.listdir(self.delayed_dir)) > 0
        except FileNotFoundError:
            return False

    @delayed.setter
    def delayed(self, value):
        """This is computed so this value is thrown away."""
        pass

    def get_delayed_analysis_start_time(self, observable, analysis_module):
        """Returns the time of the first attempt to delay analysis for this analysis module and observable, or None otherwise."""
        key = '{}:{}'.format(analysis_module.config_section, observable.id)
        try:
            return self.delayed_analysis_tracking[key]
        except KeyError:
            return None

    def track_delayed_analysis_start(self, observable, analysis_module):
        """Called by the engine when we need to start tracking delayed analysis for a given observable."""
        if not os.path.isdir(self.delayed_dir):
            os.mkdir(self.delayed_dir)
        
        target_file = os.path.join(self.delayed_dir, '{}-{}'.format(analysis_module.config_section, observable.id))
        if os.path.exists(target_file):
            logging.warning("delayed analysis tracking file {} already exists".format(target_file))
        else:
            with open(target_file, 'w') as fp:
                pass

            logging.debug("delayed analysis tracking start {}".format(target_file))

        # if this is the first time we've delayed analysis (for this analysis module and observable)
        # then we want to remember when we started so we can eventually time out
        key = '{}:{}'.format(analysis_module.config_section, observable.id)
        if key not in self.delayed_analysis_tracking:
            self.delayed_analysis_tracking[key] = datetime.datetime.now()

    def track_delayed_analysis_stop(self, observable, analysis_module):
        """Called by the engine when we need to stop tracking delayed analysis for a given observable."""
        if not os.path.isdir(self.delayed_dir):
            logging.warning("missing tracking directory {}".format(self.delayed_dir))
            return
        
        target_file = os.path.join(self.delayed_dir, '{}-{}'.format(analysis_module.config_section, observable.id))
        if not os.path.exists(target_file):
            logging.warning("missing delayed analysis tracking file {}".format(target_file))
            return

        os.remove(target_file)
        logging.debug("delayed analysis tracking stop {}".format(target_file))

    def add_dependency(self, source_observable, source_analysis, target_observable, target_analysis):
        from saq.modules import AnalysisModule
        assert isinstance(source_observable, Observable)
        assert isinstance(source_analysis, type)
        assert isinstance(target_observable, Observable)
        assert isinstance(target_analysis, type)

        # does this dependency already exist?
        for dep in self.dependency_tracking:
            if ( dep.source_observable_id == source_observable.id and 
                 dep.source_analysis_type == str(source_analysis) and
                 dep.target_observable_id == target_observable.id and
                 dep.target_analysis_type == str(target_analysis) ):
                # XXX not sure why we would see this -- need to investigate
                logging.debug("already added dependency for {} {} --> {} {}".format(
                              source_observable, source_analysis,
                              target_observable, target_analysis))
                return dep

        # Am -> Bt
        # Bm -> Ct OK

        # Am -> Bt
        # Bt -> At ERROR

        # Am -> Bt
        # Bm -> Ct
        # Cm -> At ERROR

        # english description of logic
        # Am -> Bt 
        # * Do we have anything depending on Am? No
        # Bm -> Ct
        # * Do we have anything depending on Bm? Yes: Am -> Bt
        # * Does Ct == Am?  No
        # Cm -> At
        # * Do we have anything depending on Cm? Yes: Bm -> Ct
        # * Does At == Bm? No
        # * Does anything depend on Bm? Yes: Am -> Bt
        # * Does At == Am? Yes: ERROR

        def resolve_node(so, sa, to, ta): # <-- the node we're currently resolving
            nonlocal target_analysis # reference original target analysis type
            #for index, dep in enumerate(so.dependencies):
                #logging.debug("MARKER: {}) {} {}".format(index, dep.target_analysis_type, sa))

            for dep in [dep for dep in so.dependencies if dep.target_analysis_type == sa]:
                #logging.debug("MARKER: {} {} {} {} : {} == {} = {}".format(so, sa, to, ta, str(target_analysis), dep.source_analysis_type, 
                              #str(target_analysis) == dep.source_analysis_type))
                if str(target_analysis) == dep.source_analysis_type:
                    raise RuntimeError("CIRCULAR DEPENDENCY ERROR: {} {} {} {} -> {}".format(so, sa, to, ta, dep))

                # recurse to the parent nodes
                resolve_node(dep.source_observable, dep.source_analysis_type, 
                             dep.target_observable, dep.target_analysis_type)

        resolve_node(source_observable, str(source_analysis), target_observable, str(target_analysis))

        # no circular dependencies detected
        dep = AnalysisDependency(target_observable.id, str(target_analysis), 
                                 source_observable.id, str(source_analysis))

        dep.root = self
        logging.debug("tracking {}".format(dep))
        self.dependency_tracking.append(dep)
        self.link_dependencies(dep)

    def remove_dependency(self, dep):
        try:
            logging.debug("removing {} from {}".format(dep, self.root))
            self.dependency_tracking.remove(dep)
        except ValueError as e:
            logging.error("requested removal of untracked dependency {} in {}".foramt(dep, self.root))

    def link_dependencies(self, target_dep):
        """Sets the .next and .prev properties of each available AnalysisDependency."""
        for source_dep in self.dependency_tracking:
            if source_dep is target_dep:
                continue

            if ( source_dep.target_observable_id == target_dep.source_observable_id and 
                 source_dep.target_analysis_type == target_dep.source_analysis_type ):

                source_dep.next = target_dep
                target_dep.prev = source_dep

    @property
    def active_dependencies(self):
        """Returns the list of AnalysisDependency objects that have not failed, are not delayed, and not resolved.
           The list is returned in the order they should be handled."""

        # for example
        # A -> B
        # B -> C
        # we need to analysis the second one first

        # also need to consider this chain
        # A -> B
        # B -> C 
        # C -> D but D has failed
        # so B -> C and A -> B have also both failed
        # same for delayed analysis
        
        _buffer = []
        for dep in self.dependency_tracking:
            if dep.failed:
                continue

            if dep.delayed:
                continue

            if dep.resolved:
                continue

            _buffer.append(dep)

        # the score here is based on the number of previous deps each dep has
        # so for A -> B and B -> C, the first has a score of 0, the second has a score of 1
        return sorted(_buffer, key=lambda dep: dep.score, reverse=True)

    @property
    def all_dependencies(self):
        """Returns the list of all AnalysisDependency objects."""
        return self.dependency_tracking

    def record_observable(self, observable):
        """Records the given observable into the observable_store if it does not already exist.  
           Returns the new one if recorded or the existing one if not."""
        assert isinstance(observable, Observable)

        # XXX gross this is probably pretty inefficient
        for o in self.observable_store.values():
            if o == observable:
                logging.debug("returning existing observable {} ({}) [{}] <{}> for {} ({}) [{}] <{}>".format(o, id(o), o.id, o.type, observable, id(observable), observable.id, observable.type))
                return o

        observable.root = self
        self.observable_store[observable.id] = observable
        logging.debug("recorded observable {} with id {}".format(observable, observable.id))
        self.set_modified()
        return observable

    def record_observable_by_spec(self, o_type, o_value, o_time=None):
        """Records the given observable into the observable_store if it does not already exist.  
           Returns the new one if recorded or the existing one if not."""
        from saq.observables import create_observable

        assert isinstance(o_type, str)
        assert isinstance(self.observable_store, dict)
        assert o_time is None or isinstance(o_time, str) or isinstance(o_time, datetime.datetime)

        # if we passed in an actual datetime object for the time then we need to convert into the expected string
        if isinstance(o_time, datetime.datetime):
            o_time = o_time.strftime(event_time_format)

        # create a temporary object to make use of any defined custom __eq__ ops
        observable = create_observable(o_type, o_value, o_time=o_time)
        if observable is None:
            return None

        return self.record_observable(observable)

    def submit(self, target_company=None):
        """Submit this RootAnalysis as an Alert to the ACE system."""
        from saq.network_client import submit_alerts

        # has this already been submitted?
        if self.alerted:
            logging.debug("{} already submitted (not submitting)".format(self))
            return

        # save everything to disk
        self.save()

        # if a target_company is specified then we look up where to send it
        # otherwise we default to what is in the network_client_ace section (old default)

        # submit this to ACE for correlation
        logging.info("submitting {} to ACE".format(self))
        remote_host = saq.CONFIG['network_client_ace']['remote_host']
        remote_port = saq.CONFIG['network_client_ace'].getint('remote_port')
        ssl_hostname = saq.CONFIG['network_client_ace']['ssl_hostname']
        ssl_cert = saq.CONFIG['network_client_ace']['ssl_cert']
        ssl_key = saq.CONFIG['network_client_ace']['ssl_key']
        ca_path = saq.CONFIG['network_client_ace']['ca_path']

        if target_company:
            try:
                target_section = 'network_client_ace_{}'.format(target_company)
                logging.info("sending alert {} to {}".format(self, target_company))
                remote_host = saq.CONFIG[target_section]['remote_host']
                remote_port = saq.CONFIG[target_section].getint('remote_port')
                ssl_hostname = saq.CONFIG[target_section]['ssl_hostname']
                ssl_cert = os.path.join(saq.SAQ_HOME, saq.CONFIG[target_section]['ssl_cert'])
                ssl_key = os.path.join(saq.SAQ_HOME, saq.CONFIG[target_section]['ssl_key'])
                ca_path = os.path.join(saq.SAQ_HOME, saq.CONFIG[target_section]['ca_path'])

            except Exception as e:
                logging.warning("invalid company selection for alert target: {}".format(e))
            
        try:
            submit_alerts(remote_host, remote_port, ssl_cert, ssl_hostname, ssl_key, ca_path, self.storage_dir)
        except Exception as e:
            logging.error("unable to submit {} to remote host {} remote port {} hostname {}: {}".format(
                          self.storage_dir,
                          remote_host,
                          remote_port,
                          ssl_hostname,
                          e))
            
            # copy the failed alert into a directory so it can be submitted later
            failed_dir = os.path.join(saq.SAQ_HOME, 
                                      saq.CONFIG['network_client_ace']['failed_dir'])

            if not os.path.isdir(failed_dir):
                try:
                    os.makedirs(failed_dir)
                except Exception as e:
                    logging.error("unable to create directory {}: {}".format(failed_dir, e))
                    report_exception()
                    return False

            target_dir = os.path.join(failed_dir, os.path.basename(self.storage_dir))

            try:
                shutil.copytree(self.storage_dir, target_dir, copy_function=os.link)
                logging.warning("copy failed submission {} to {}".format(self.storage_dir, target_dir))
            except Exception as e:
                logging.error("unable to copy {} to {}: {}".format(self.storage_dir, target_dir, e))
                report_exception()

        # remember that we sent this
        self.alerted = True

    def save(self):
        """Saves the Alert to disk. Resolves AttachmentLinks into Attachments. Note that this does not insert the Alert into the system."""
        assert self.json_path is not None
        assert self.json is not None

        logging.debug("SAVE: {} ({})".format(self, type(self)))

        # make sure the containing directory exists
        if not os.path.exists(os.path.join(saq.SAQ_RELATIVE_DIR, self.storage_dir)):
            os.makedirs(os.path.join(saq.SAQ_RELATIVE_DIR, self.storage_dir))

        # analysis details go into a hidden directory
        if not os.path.exists(os.path.join(saq.SAQ_RELATIVE_DIR, self.storage_dir, '.ace')):
            os.makedirs(os.path.join(saq.SAQ_RELATIVE_DIR, self.storage_dir, '.ace'))

        # save all analysis
        for analysis in self.all_analysis:
            if analysis is not self:
                analysis.save()

        # save our own details
        Analysis.save(self)

        # now the rest should encode as JSON with the custom JSON encoder
        try:
            # we use a temporary file to deal with very large JSON files taking a long time to encode
            # if we don't do this then the GUI will occasionally hit 0-byte data.json files
            temp_path = '{}.tmp'.format(self.json_path)
            with open(temp_path, 'w') as fp:
                fp.write(_JSONEncoder().encode(self))
                _track_writes()
            shutil.move(temp_path, self.json_path)
        except Exception as e:
            logging.error("json encoding for {0} failed: {1}".format(self, str(e)))
            report_exception()
            return False

        return True

    def load(self):
        """Loads the Alert object from the JSON file.  Note that this does NOT load the details property."""
        assert self.json_path is not None
        logging.debug("LOAD: called load() on {}".format(self))

        if self.is_loaded:
            logging.warning("alert {} already loaded".format(self))

        try:
            with open(self.json_path, 'r') as fp:
                self.json = json.load(fp)

            _track_reads()

            # translate the json into runtime objects
            self._materialize()
            self.is_loaded = True
            # loaded Alerts are read-only until something is modified
            self._ready_only = True
            return True
        
        except Exception as e:
            logging.error("unable to load json from {0}: {1}".format(
                self.json_path, str(e)))
            report_exception()
            raise e

    def flush(self):
        """Calls Analysis.flush on all Analysis objects in this RootAnalysis."""
        #logging.debug("called RootAnalysis.flush() on {}".format(self))
        #Analysis.flush(self) # <-- we don't want to flush out the RootAnalysis details

        # make sure the containing directory exists
        if not os.path.exists(os.path.join(saq.SAQ_RELATIVE_DIR, self.storage_dir)):
            os.makedirs(os.path.join(saq.SAQ_RELATIVE_DIR, self.storage_dir))

        # analysis details go into a hidden directory
        if not os.path.exists(os.path.join(saq.SAQ_RELATIVE_DIR, self.storage_dir, '.ace')):
            os.makedirs(os.path.join(saq.SAQ_RELATIVE_DIR, self.storage_dir, '.ace'))

        for analysis in self.all_analysis:
            if analysis is not self:
                analysis.flush()

        freed_items = gc.collect()
        #logging.debug("{} items freed by gc".format(freed_items))

    def merge(self, target_analysis, other):
        """Merges the Observables and Analysis of an existing RootAnalysis into the target Analysis object."""
        assert isinstance(target_analysis, Analysis)
        assert isinstance(other, RootAnalysis)

        logging.debug("merging {} into {} target {}".format(other, self, target_analysis))

        # maps the observables from the other alert to new ones in this one
        transfer_map = {} # key = uuid of other observable, value = uuid of the new observable
        # go through and copy all the observations over first
        for other_observable in other.all_observables:
            # does this observation already exist?
            existing_observable = self.get_observable_by_spec(other_observable.type, 
                                                              other_observable.value, 
                                                              other_observable.time)

            if existing_observable:
                target_observable = existing_observable
                logging.debug("merging existing observable {}".format(target_observable))
            else:
                # NOTE that here we don't want to actually add this other observable
                # because it has references to Analysis objects we need to add below
                # so we create a new one based on this one
                logging.debug("making copy of {}".format(other_observable))
                target_observable = copy.copy(other_observable)
                target_observable.clear_analysis() # make sure these are cleared out (we'll add them back in later...)
                # note that we use the record_observable here instead of add_observable
                # we're just moving them over into this RootAnalysis right now
                target_observable = self.record_observable(target_observable)

                # if the observable is a file then the actual file needs to be copied over
                # TODO this should go into the functionality of the observable class
                if target_observable.type == F_FILE:
                    src_path = os.path.join(other.storage_dir, other_observable.value)
                    if not os.path.exists(src_path):
                        logging.error("merge for {} has missing file {}".format(other, src_path))
                    else:
                        dest_dir = os.path.join(self.storage_dir, os.path.dirname(other_observable.value))
                        dest_path = os.path.join(dest_dir, os.path.basename(other_observable.value))
                        try:
                            logging.debug("copying merged file observable {} to {}".format(src_path, dest_path))
                            if not os.path.isdir(dest_dir):
                                os.makedirs(dest_dir)
                            shutil.copy(src_path, dest_path)
                        except Exception as e:
                            logging.error("unable to copy {} to {}: {}".format(src_path, dest_path, e))
                            report_exception()

            # keep track of how they are moving over
            transfer_map[other_observable.id] = target_observable.id

        for other_observable in other.all_observables:
            # find the corresponding observable in this alert
            target_observable = self.get_observable_by_spec(other_observable.type,
                                                            other_observable.value,
                                                            other_observable.time)
            if target_observable is None:
                logging.error("could not find target observable {} in {}".format(other_observable, self))
                continue

            # remap relationships
            for r in target_observable.relationships:
                if r.target.id in transfer_map:
                    logging.debug("re-targeting {}".format(r))
                    r.target = self.get_observable_by_spec(other.observable_store[r.target.id].type,
                                                           other.observable_store[r.target.id].value,
                                                           other.observable_store[r.target.id].time)

            for other_analysis in other_observable.all_analysis:
                # do we already have this analysis for this observable in the target?
                existing_analysis = target_observable.get_analysis(type(other_analysis))
                if existing_analysis is None:
                    logging.debug("merging analysis {} into {}".format(other_analysis, target_observable))
                    details = other_analysis.details
                    new_analysis = copy.copy(other_analysis)
                    new_analysis.clear_observables()
                    new_analysis.external_details_path = None
                    new_analysis.external_details_loaded = False
                    new_analysis.external_details = None
                    new_analysis.details = details
                    new_analysis.set_modified()
                    #new_analysis = type(other_analysis)()
                    #new_analysis.details = other_analysis.details
                    target_observable.add_analysis(new_analysis)

                    # and then copy all the observables in
                    for o in other_analysis.observables:
                        # find the corresponding observable in this root
                        current_observable = self.get_observable_by_spec(o.type, o.value, o.time)
                        if current_observable is None:
                            logging.error("could not find current observable {} in {} for {}".format(
                                          o, self, other_analysis))
                        else:
                            new_analysis.add_observable(current_observable)
                else:
                    logging.debug("skipping merge for existing analysis {}".format(existing_analysis))

        # finally, all the observables in the RootAnalysis object get added to the target_analysis
        for other_observable in other.observables:
            existing_observable = self.get_observable_by_spec(other_observable.type, 
                                                              other_observable.value, 
                                                              other_observable.time)
            if existing_observable is None:
                logging.error("cannot find observable type {} value {} time {}".format(other_observable.type,
                                                                                       other_observable.value,
                                                                                       other_observable.time))
            else:
                target_analysis.add_observable(existing_observable)

    def _materialize(self):
        """Utility function to replace specific dict() in json with runtime object references."""
        # in other words, load the JSON
        self._load_observable_store()

        # load the Analysis objects in the Observables
        for observable in self.observable_store.values():
            observable._load_analysis()

        # load the Observable references in the Analysis objects
        for analysis in self.all_analysis:
            analysis._load_observable_references()

        # load Tag objects for analysis
        for analysis in self.all_analysis:
            analysis.tags = [Tag(json=t) for t in analysis.tags]

        # load Tag objects for observables
        for observable in self.observable_store.values():
            observable.tags = [Tag(json=t) for t in observable.tags]

        # load DetectionPoints
        for analysis in self.all_analysis:
            analysis.detections = [DetectionPoint.from_json(dp) for dp in analysis.detections]

        for observable in self.all_observables:
            observable.detections = [DetectionPoint.from_json(dp) for dp in observable.detections]

        # load Relationships
        for observable in self.all_observables:
            observable._load_relationships()

        # load dependency tracking
        _buffer = []
        for dep_dict in self.dependency_tracking:
            _buffer.append(AnalysisDependency.from_json(dep_dict))
            #_buffer.append(AnalysisDependency(dep_dict[AnalysisDependency.KEY_TARGET_OBSERVABLE_ID],
                                              #dep_dict[AnalysisDependency.KEY_TARGET_ANALYSIS_TYPE],
                                              #dep_dict[AnalysisDependency.KEY_SOURCE_OBSERVABLE_ID],
                                              #dep_dict[AnalysisDependency.KEY_SOURCE_ANALYSIS_TYPE],
                                              #dep_dict[AnalysisDependency.KEY_DEPENDENCY_FAILED]))
            for dep in _buffer:
                dep.root = self

        self.dependency_tracking = _buffer
        for dep in self.dependency_tracking:
            self.link_dependencies(dep)
        
    def _load_observable_store(self):
        from saq.observables import create_observable
        invalid_uuids = [] # list of uuids that don't load for whatever reason
        for uuid in self.observable_store.keys():
            # get the JSON dict from the observable store for this uuid
            value = self.observable_store[uuid]
            # create the observable from the type and value
            o = create_observable(value['type'], value['value'])
            # basically this is backwards compatibility with old alerts that have invalid values for observables
            if o:
                o.root = self
                o.json = value # this sets everything else

                # set up the EVENT_GLOBAL_* events
                o.add_event_listener(EVENT_ANALYSIS_ADDED, o.root._fire_global_events)
                o.add_event_listener(EVENT_TAG_ADDED, o.root._fire_global_events)

                self.observable_store[uuid] = o
            else:
                logging.warning("invalid observable type {} value {}".format(value['type'], value['value']))
                invalid_uuids.append(uuid)

        for uuid in invalid_uuids:
            del self.observable_store[uuid]

    def reset(self):
        """Removes analysis, dispositions and any observables that did not originally come with the alert."""

        from subprocess import Popen

        self.set_modified() 
        logging.info("resetting {}".format(self))

        # NOTE that we do not clear the details that came with Alert

        # clear external details storage for all analysis (except self)
        for _analysis in self.all_analysis:
            if _analysis is self:
                continue

            _analysis.reset()

        # remove analysis objects from all observables
        for o in self.observables:
            o.clear_analysis()

        # remove observables from the observable_store that didn't come with the original alert
        original_uuids = set([o.id for o in self.observables])
        remove_list = []
        for uuid in self.observable_store.keys():
            if uuid not in original_uuids:
                remove_list.append(uuid)

        for uuid in remove_list:
            # if the observable is a F_FILE then try to also delete the file
            if self.observable_store[uuid].type == F_FILE or self.observable_store[uuid].type == F_SUSPECT_FILE:
                target_path = os.path.join(saq.SAQ_RELATIVE_DIR, self.storage_dir, self.observable_store[uuid].value)
                if os.path.exists(target_path):
                    logging.debug("deleting observable file {}".format(target_path))

                    try:
                        os.remove(target_path)
                    except Exception as e:
                        logging.error("unable to remove {}: {}".format(target_path, str(e)))

            del self.observable_store[uuid]

        # remove tags from observables
        for o in self.observables:
            o.clear_tags()

        # clear the action counters
        self.action_counters = {} 

        # remove any empty directories left behind
        logging.debug("removing empty directories inside {}".format(self.storage_dir))
        p = Popen(['find', os.path.join(saq.SAQ_HOME, self.storage_dir), '-type', 'd', '-empty', '-delete'])
        p.wait()

    def archive(self):
        """Removes the details of analysis and external files.  Keeps observables and tags."""

        from subprocess import Popen

        logging.info("archiving {}".format(self))

        # NOTE that we do not clear the details that came with Alert

        # clear external details storage for all analysis (except self)
        for _analysis in self.all_analysis:
            if _analysis is self:
                continue

            _analysis.reset()

        retained_files = set()
        for o in self.all_observables:
            # skip the ones that came with the alert
            if o in self.observables:
                logging.debug("{} came with the alert (skipping)".format(o))
                if o.type == F_FILE:
                    retained_files.add(os.path.join(saq.SAQ_RELATIVE_DIR, self.storage_dir, o.value))

                continue

            if o.type == F_FILE:
                target_path = os.path.join(saq.SAQ_RELATIVE_DIR, self.storage_dir, o.value)
                if os.path.exists(target_path):
                    logging.debug("deleting observable file {}".format(target_path))

                    try:
                        os.remove(target_path)
                    except Exception as e:
                        logging.error("unable to remove {}: {}".format(target_path, str(e)))

        for dir_path, dir_names, file_names in os.walk(os.path.join(saq.SAQ_RELATIVE_DIR, self.storage_dir)):
            # ignore anything in the root of the storage directory
            if dir_path == os.path.join(saq.SAQ_RELATIVE_DIR, self.storage_dir):
                logging.debug("skipping core directory {}".format(dir_path))
                continue

            # and ignore anything in the .ace subdirectory
            if dir_path == os.path.join(saq.SAQ_RELATIVE_DIR, self.storage_dir, '.ace'):
                logging.debug("skipping core directory {}".format(dir_path))
                continue

            for file_name in file_names:
                file_path = os.path.join(dir_path, file_name)
                # and ignore any F_FILE we wanted to keep
                if file_path in retained_files:
                    logging.debug("skipping retained file {}".format(file_path))
                    continue

                try:
                    logging.debug("deleting {}".format(file_path))
                    os.remove(file_path)
                except Exception as e:
                    logging.error("unable to remove {}: {}".format(file_path, e))
                    report_exception()

        # remove any empty directories left behind
        logging.debug("removing empty directories inside {}".format(self.storage_dir))
        p = Popen(['find', os.path.join(saq.SAQ_HOME, self.storage_dir), '-type', 'd', '-empty', '-delete'])
        p.wait()

    def move(self, dest_dir):
        """Moves the contents of self.storage_dir into dest_dir."""
        assert dest_dir
        assert self.storage_dir

        # we must be locked for this to work
        if not self.is_locked():
            raise RuntimeError("tried to move unlocked analysis {}".format(self))

        if os.path.exists(dest_dir):
            raise RuntimeError("destination directory {} already exists".format(dest_dir))

        # move the storage directory
        shutil.move(os.path.join(saq.SAQ_RELATIVE_DIR, self.storage_dir), dest_dir)

        # also move the lock
        lock_path = '{}.lock'.format(os.path.join(saq.SAQ_RELATIVE_DIR, self.storage_dir))
        shutil.move(lock_path, dest_dir)

        logging.debug("moved {} to {}".format(self.storage_dir, dest_dir))
        self.storage_dir = dest_dir

    def delete(self):
        """Deletes everything contained in the storage_dir and marks this RootAnalysis as deleted."""
        try:
            if os.path.exists(self.storage_dir):
                shutil.rmtree(self.storage_dir)
                logging.debug("deleted {}".format(self.storage_dir))
        except Exception as e:
            logging.error("unable to delete {}: {}".format(self, e))
            raise e

    def __str__(self):
        return "RootAnalysis({})".format(self.uuid)

    @property   
    def all_analysis(self):
        """Returns the list of all Analysis performed for this Alert."""
        result = []
        result.append(self)
        for observable in self.observable_store.values():
            for analysis in observable.analysis.values():
                if analysis:
                    result.append(analysis)

        return result

    def get_analysis_by_type(self, a_type):
        """Returns the list of all Analysis of a given type()."""
        return [a for a in self.all_analysis if isinstance(a, a_type)]

    @property
    def all_observables(self):
        """Returns the list of all Observables discovered for this Alert."""
        return self.observable_store.values()

    def get_observables_by_type(self, o_type):
        """Returns the list of Observables that match the given type."""
        return [o for o in self.all_observables if o.type == o_type]

    @property
    def all(self):
        """Returns the list of all Observables and Analysis for this RootAnalysis."""
        result = self.all_analysis
        result.extend(self.all_observables)
        return result

    @property
    def all_tags(self):
        """Return all unique tags for the entire Alert."""
        result = []
        for analysis in self.all_analysis:
            if analysis.tags is not None:
                result.extend(analysis.tags)
        for observable in self.all_observables:
            if observable.tags is not None:
                result.extend(observable.tags)

        return list(set(result))

    def iterate_all_references(self, target):
        """Iterators through all objects that refer to target."""
        if isinstance(target, Observable):
            for analysis in self.all_analysis:
                if target in analysis.observables:
                    yield analysis
        elif isinstance(target, Analysis):
            for observable in self.all_observables:
                if target in observable.all_analysis:
                    yield observable
        else:
            raise ValueError("invalid type {} passed to iterate_all_references".format(type(target)))

    def get_observable(self, uuid):
        """Returns the Observable object for the given uuid."""
        return self.observable_store[uuid]

    def get_observable_by_spec(self, o_type, o_value, o_time=None):
        """Returns the Observable object by type and value, and optionally time, or None if it cannot be found."""
        target = Observable(o_type, o_value, o_time)
        for o in self.all_observables:
            if o == target:
                return o

        return None

    @property
    def all_detection_points(self):
        """Returns all DetectionPoint objects found in any DetectableObject in the heiarchy."""
        result = []
        for a in self.all_analysis:
            result.extend(a.detections)
        for o in self.all_observables:
            result.extend(o.detections)

        return result

    def calculate_priority(self):
        """Calculates and returns the priority score for the Alert."""
        score = 0
        for tag in self.all_tags:
            score += tag.score

        return score

    def has_detections(self):
        """Returns True if this RootAnalysis could become an Alert (has at least one DetectionPoint somewhere.)"""
        if saq.FORCED_ALERTS:
            return True
        if self.has_detection_points:
            return True
        for a in self.all_analysis:
            if a.has_detection_points:
                return True
        for o in self.all_observables:
            if o.has_detection_points:
                return True

def recurse_down(target, callback):
    """Calls callback starting at target back to the RootAnalysis."""
    assert isinstance(target, Analysis) or isinstance(target, Observable)
    assert isinstance(target.root, RootAnalysis)

    visited = [] # keep track of what we've looked at
    root = target.root 

    def _recurse(target, callback):
        nonlocal visited, root
        # make sure we haven't already looked at this one
        if target in visited:
            return

        # are we at the end?
        if target is root:
            return

        visited.append(target)

        if isinstance(target, Observable):
            # find all Analysis objects that reference this Observable
            for analysis in root.all_analysis:
                for observable in analysis.observables:
                    # not sure the == part is needed but just in case I screw up later...
                    if target is observable or target == observable:
                        callback(analysis)
                        _recurse(analysis, callback)

        elif isinstance(target, Analysis):
            # find all Observable objects that reference this Analysis
            for observable in root.all_observables:
                for analysis in observable.all_analysis:
                    if analysis is target:
                        callback(observable)
                        _recurse(observable, callback)

    _recurse(target, callback)

def search_down(target, callback):
    """Searches from target down to RootAnalysis looking for callback(obj) to return True."""
    result = None

    def _callback(target):
        nonlocal result
        if result:
            return

        if callback(target):
            result = target

    recurse_down(target, _callback)
    return result

def recurse_tree(target, callback):
    """A utility function to run the given callback on every Observable and Analysis rooted at the given Observable or Analysis object."""
    assert isinstance(target, Analysis) or isinstance(target, Observable)

    def _recurse(target, visited, callback):
        callback(target)
        visited.append(target)

        if isinstance(target, Analysis):
            for observable in target.observables:
                if observable not in visited:
                    _recurse(observable, visited, callback)
        elif isinstance(target, Observable):
            for analysis in target.all_analysis:
                if analysis and analysis not in visited:
                    _recurse(analysis, visited, callback)

    _recurse(target, [], callback)

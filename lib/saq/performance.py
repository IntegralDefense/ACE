# vim: sw=4:ts=4:et:cc=120

import csv
import datetime
import logging
import os, os.path
import sys
import time

import saq

def record_execution_time(function, start, stop):
    logging.debug("EXECUTION TIME {}: {:.3f}".format(function.__name__, stop - start))

def track_execution_time(f):
    def _track_execution_time(*args, **kwargs):
        start = time.clock()
        try:
            f(*args, **kwargs)
        finally:
            stop = time.clock()
            record_execution_time(f, start, stop)

    return _track_execution_time

def record_metric(metric, value):
    with open(os.path.join(saq.SAQ_HOME, 'stats', 'metrics', '{}.csv'.format(metric)), 'a') as fp:
        writer = csv.writer(fp)
        writer.writerow([str(datetime.datetime.now()), os.getpid(), ' '.join(sys.argv), value])

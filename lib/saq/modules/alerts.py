# vim: sw=4:ts=4:et

import fcntl
import gc
import json
import logging
import os
import os.path
import saq

import saq
import saq.database

from saq.analysis import Analysis, Observable
from saq.constants import *
from saq.database import get_db_connection, use_db
from saq.error import report_exception
from saq.modules import AnalysisModule

class ACEDetectionAnalysis(Analysis):
    """Does this analysis contain a detection?"""
    def initialize_details(self):
        self.details = None

    def generate_summary(self):
        return None

class ACEDetectionAnalyzer(AnalysisModule):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.target_mode = self.config['target_mode']

    def verify_environment(self):
        # make sure the target_mode is valid
        if 'analysis_mode_{}'.format(self.config['target_mode']) not in saq.CONFIG:
            raise ValueError("target_mode {} invalid".format(self.config['target_mode']))

    @property
    def generated_analysis_type(self):
        return ACEDetectionAnalysis

    @property
    def valid_observable_types(self):
        return None

    def execute_analysis(self, observable):
        if self.root.has_detections():
            logging.info("{} has {} detection points - changing mode to {}".format(
                         self.root, len(self.root.all_detection_points), self.target_mode))
            self.root.analysis_mode = self.target_mode
            return True

        return None

class ACEAlertDatabaseAnalysis(Analysis):
    """Is this alert in the alert database?"""
    def initialize_details(self):
        self.details = None

    def generate_summary(self):
        return None

class ACEAlertDatabaseAnalyzer(AnalysisModule):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.target_mode = self.config['target_mode']

    def verify_environment(self):
        # make sure the target_mode is valid
        if 'analysis_mode_{}'.format(self.config['target_mode']) not in saq.CONFIG:
            raise ValueError("target_mode {} invalid".format(self.config['target_mode']))
        
    @property
    def generated_analysis_type(self):
        return ACEAlertDatabaseAnalysis

    @property
    def valid_observable_types(self):
        return None

    @use_db
    def execute_analysis(self, observable, db, c):
        # are we in the right analysis mode?
        if self.root.analysis_mode != self.target_mode:
            return False

        analysis = self.create_analysis(observable)

        # is this alert already in the database?
        c.execute("SELECT id FROM alerts WHERE uuid = %s", (self.root.uuid,))
        row = c.fetchone()
        if row:
            logging.warning("uuid {} already exists in alerts table with id {}".format(self.root.uuid, row[0]))
            return True

        # otherwise insert the alert
        alert = saq.database.Alert()
        alert.storage_dir = self.root.storage_dir
        alert.load()
        alert.sync()
        return True

class ACEAlertsAnalysis(Analysis):
    """What other alerts have we seen this in?"""
    
    def initialize_details(self):
        self.details = []

    @property
    def jinja_template_path(self):
        return "analysis/related_alerts.html"

    def generate_summary(self):
        if self.details:
            return "Related Alerts Analysis ({0} alerts)".format(len(self.details))
        return None

class ACEAlertsAnalyzer(AnalysisModule):

    @property
    def generated_analysis_type(self):
        return ACEAlertsAnalysis

    @property
    def valid_observable_types(self):
        return None

    def execute_analysis(self, observable):
        import saq.database

        analysis = self.create_analysis(observable)

        with get_db_connection() as db:
            c = db.cursor()
            sql = """SELECT 
                            a.uuid,
                            a.alert_type,
                            a.insert_date,
                            a.description,
                            a.disposition
                        FROM
                            observables o JOIN observable_mapping om
                                ON o.id = om.observable_id
                            JOIN alerts a
                                ON a.id = om.alert_id
                        WHERE
                            o.type = %s AND o.value = %s {avoid_self}
                        ORDER BY
                            a.insert_date DESC"""

            params = [observable.type, observable.value]

            # if we are analyzing an Alert object then we want to avoid matching ourself
            if isinstance(self.root, saq.database.Alert) and self.root.id:
                sql = sql.format(avoid_self="AND a.id != %s")
                params.append(self.root.id)
            else:
                sql = sql.format(avoid_self='')

            c.execute(sql, tuple(params))

            for uuid, alert_type, insert_date, description, disposition in c:
                analysis.details.append({
                    'uuid': uuid,
                    'insert_date': insert_date,
                    'type': alert_type,
                    'description': description,
                    'disposition': disposition})

        return True

# vim: sw=4:ts=4:et:cc=120
import logging

from hashlib import md5

import saq

from saq.analysis import Analysis, Observable
from saq.database import execute_with_retry, get_db_connection
from saq.constants import *
from saq.modules import AnalysisModule

# 
# this module has a little different functionality than the rest of the modules
# it has two overall purposes
# 1) compute the frequency analysis of all observables and tag them with high_fp or high_mal
# 2) update the hal9000 database with all occurances of observables
#
# the second task requires some special processing
# we wait until analysis has completely finished
# and then check to see if the RootAnalysis will eventually become an Alert
# if NOT then we update the hal9000 database with all the Observables we've seen
# otherwise we need to wait until someone sets a disposition for the Alert
# that is performed in the GUI by the user, which will cause the Alert to get back into the correlation engine
# 
# therefor, the execute_analysis function defined in this analysis module operates differently than others
# it checks to see if it is analyzing the RootAnalysis object and then checks for disposition
# normally you maintain "state" by storing data in the .details property of Analysis objects
# but in this case, we're analyzing an Analysis object, so that doesn't work
# so we maintain state between calls by storing it in the state property of the AnalysisModule
#
# TODO it will be nice to eventually have the ability to have Analysis objects analyze other Analysis objects
#

KEY_TOTAL_COUNT = 'total_count'
KEY_MAL_COUNT = 'mal_count'

STATE_KEY_ID_TRACKING = 'id_tracking'
STATE_KEY_PREVIOUS_DISPOSITION = 'previous_disposition'

def _compute_hal9000_md5(observable: Observable) -> str:
    """Given an Observable, return the hexdigest of the MD5 computation used for hal9000."""
    md5_hasher = md5()
    md5_hasher.update(observable.type.encode('utf-8', errors='ignore'))
    md5_hasher.update(observable.value.encode('utf-8', errors='ignore'))
    return md5_hasher.hexdigest()

class HAL9000Analysis(Analysis):
    """How often do we see this Observable in alerts dispositioned as False Postive or True Positive?"""
    def initialize_details(self):
        self.details = { 
            KEY_TOTAL_COUNT: 0,
            KEY_MAL_COUNT: 0 }

    @property
    def total_count(self):
        return self.details['total_count']

    @total_count.setter
    def total_count(self, value):
        self.details['total_count'] = value

    @property
    def mal_count(self):
        return self.details['mal_count']

    @mal_count.setter
    def mal_count(self, value):
        self.details['mal_count'] = value

    @property
    def mal_percent(self):
        if self.total_count == 0:
            return 0

        return 100 * self.mal_count / self.total_count

    def generate_summary(self):
        if self.total_count == 0:
            return None

        return "Malicious Frequency Analysis {}/{} ({:.2f}%)".format(
            self.mal_count, 
            self.total_count,
            self.mal_percent)

class HAL9000Analyzer(AnalysisModule):
    def verify_environment(self):
        self.verify_config_exists('min_sample_size')
        self.verify_config_exists('mal_threshold')
        self.verify_config_exists('fp_threshold')

    @property
    def min_sample_size(self):
        return self.config.getint('min_sample_size')

    @property
    def mal_threshold(self):
        return self.config.getfloat('mal_threshold')

    @property
    def fp_threshold(self):
        return self.config.getfloat('fp_threshold')

    @property
    def generated_analysis_type(self):
        return HAL9000Analysis

    def execute_analysis(self, observable):
        # create analysis object and add it to the observable
        analysis = self.create_analysis(observable)

        # get the id of the observable
        id = _compute_hal9000_md5(observable)

        # connect to database
        with get_db_connection('hal9000') as db:
            c = db.cursor()

            # lookup the mal frequency of this observavble
            c.execute("""
                SELECT mal_count, total_count
                FROM observables
                WHERE id = UNHEX(%s)
                """, (id))
            result = c.fetchone()
            db.commit()

            if result is not None:
                analysis.mal_count = result[0]
                analysis.total_count = result[1]

            logging.debug("Malicious Frequency Analysis {}/{} ({}%)".format(
                analysis.mal_count,
                analysis.total_count,
                analysis.mal_percent))

            # if we have seen this indicator enough times to use as a flag
            if analysis.total_count > self.min_sample_size:
                # flag observable if its malicous percent is greater than the configured threshold
                if analysis.mal_percent >= self.mal_threshold:
                    observable.add_tag('high_mal_frequency')

                # flag observable as false positive if mal_percent is less than configured threshold
                if analysis.mal_percent < self.fp_threshold:
                    observable.add_tag('high_fp_frequency')

        return True
    
    def execute_post_analysis(self):
        import saq.database
        self.initialize_state({
            STATE_KEY_ID_TRACKING: {}, # key = return value of _compute_hal9000_md5, value = { } (see below) 
            STATE_KEY_PREVIOUS_DISPOSITION: None})

        # start tracking what we do with all the observables
        for observable in self.root.all_observables:
            hal9000_id = _compute_hal9000_md5(observable)
            if hal9000_id not in self.state[STATE_KEY_ID_TRACKING]:
                # we keep track of how we modified the total count and the malicious count for each observable
                # (we record what we ADDED to the value so that we can undo it later if the disposition changes)
                self.state[STATE_KEY_ID_TRACKING][hal9000_id] = { 'id': observable.id,  
                                                                  KEY_TOTAL_COUNT: None, 
                                                                  KEY_MAL_COUNT: None }

        if self.root.analysis_mode != ANALYSIS_MODE_CORRELATION:
            # TODO check to see if this analysis mode has cleanup set to True
            # really what we want to do is see if we can possibly end up in a different analysis mode
            with get_db_connection('hal9000') as db:
                c = db.cursor()

                placeholder_clause = ','.join(['(UNHEX(%s))' for _ in self.state[STATE_KEY_ID_TRACKING].keys()])
                parameters = tuple(self.state[STATE_KEY_ID_TRACKING].keys())

                # record appearance of all hal9000 observables
                execute_with_retry(db, c, f"""
                                   INSERT INTO observables (id)
                                   VALUES {placeholder_clause}
                                   ON DUPLICATE KEY
                                   UPDATE total_count = total_count + 1""", parameters, 
                                   commit=True)

            return True # all we do here
            # we don't really need to record any more state here because 
            # we expect this entire analysis to get deleted

        # are we an alert with a disposition?
        new_disposition = None

        with get_db_connection() as db:
            c = db.cursor()
            c.execute("SELECT disposition FROM alerts WHERE uuid = %s", (self.root.uuid,))
            result = c.fetchone()   
            db.commit()

            if result:
                new_disposition = result[0]

        if new_disposition is None:
            return False # no alert or no disposition -- check again later

        # did we already set a disposition for this alert before?
        previous_disposition = self.state[STATE_KEY_PREVIOUS_DISPOSITION]
        logging.debug("loaded previous disposition of {} for {}".format(previous_disposition, self))

        # if the disposition didn't change then we don't care
        if previous_disposition == new_disposition:
            logging.debug("same disposition {} == {} - not updating".format(previous_disposition, new_disposition))
            return False # check again later

        all_sql = [] # list of SQL commands to execute
        all_parameters = [] # list of SQL parameter tuples for the SQL commands

        # if we've changed state from what we were previously then we want to undo what we did previously
        total_count_parameters = []
        mal_count_parameters = []
        for hal9000_id, value in self.state[STATE_KEY_ID_TRACKING].items():
            if self.state[STATE_KEY_ID_TRACKING][hal9000_id][KEY_TOTAL_COUNT] is not None:
                total_count_parameters.append(hal9000_id)
            if self.state[STATE_KEY_ID_TRACKING][hal9000_id][KEY_MAL_COUNT] is not None:
                mal_count_parameters.append(hal9000_id)

        if total_count_parameters:
            placeholder_clause = ','.join(['UNHEX(%s)' for _ in total_count_parameters])
            all_sql.append(f"""
                UPDATE observables SET total_count = IF(total_count > 0, total_count - 1, 0)
                WHERE id IN ( {placeholder_clause} )""")
            all_parameters.append(tuple(total_count_parameters))

        if mal_count_parameters:
            placeholder_clause = ','.join(['UNHEX(%s)' for _ in mal_count_parameters])
            all_sql.append(f"""
                UPDATE observables SET mal_count = IF(mal_count > 0, mal_count - 1, 0)
                WHERE id IN ( {placeholder_clause} )""")
            all_parameters.append(tuple(mal_count_parameters))

        # we have three major groups of dispositions: IGNORE, MAL and BENIGN
        placeholder_clause = ','.join(['(UNHEX(%s), 1)' for _ in self.state[STATE_KEY_ID_TRACKING].keys()])
        parameters = tuple(self.state[STATE_KEY_ID_TRACKING].keys())

        if new_disposition in MAL_ALERT_DISPOSITIONS:
            placeholder_clause = ','.join(['(UNHEX(%s), 1)' for _ in self.state[STATE_KEY_ID_TRACKING].keys()])
            all_sql.append(f"""
                INSERT INTO observables (id, mal_count)
                VALUES {placeholder_clause}
                ON DUPLICATE KEY
                UPDATE total_count = total_count + 1, mal_count = mal_count + 1 """)
            all_parameters.append(parameters)

        elif new_disposition in BENIGN_ALERT_DISPOSITIONS:
            placeholder_clause = ','.join(['(UNHEX(%s))' for _ in self.state[STATE_KEY_ID_TRACKING].keys()])
            all_sql.append(f"""
                INSERT INTO observables (id)
                VALUES {placeholder_clause}
                ON DUPLICATE KEY
                UPDATE total_count = total_count + 1 """)
            all_parameters.append(parameters)

        with get_db_connection('hal9000') as db:
            c = db.cursor()
            execute_with_retry(db, c, all_sql, all_parameters, commit=True)

        # remember what we did so we can undo it later if we need to
        for hal9000_id in self.state[STATE_KEY_ID_TRACKING].keys():
            if new_disposition in MAL_ALERT_DISPOSITIONS:
                self.state[STATE_KEY_ID_TRACKING][hal9000_id][KEY_TOTAL_COUNT] = 1
                self.state[STATE_KEY_ID_TRACKING][hal9000_id][KEY_MAL_COUNT] = 1
            elif new_disposition in BENIGN_ALERT_DISPOSITIONS:
                self.state[STATE_KEY_ID_TRACKING][hal9000_id][KEY_TOTAL_COUNT] = 1
                self.state[STATE_KEY_ID_TRACKING][hal9000_id][KEY_MAL_COUNT] = None
            else:
                self.state[STATE_KEY_ID_TRACKING][hal9000_id][KEY_TOTAL_COUNT] = None
                self.state[STATE_KEY_ID_TRACKING][hal9000_id][KEY_MAL_COUNT] = None

        # remember what our disposition was
        self.state[STATE_KEY_PREVIOUS_DISPOSITION] = new_disposition
        return False # check again later

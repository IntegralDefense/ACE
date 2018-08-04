# vim: sw=4:ts=4:et:cc=120
import logging
import pymysql

from hashlib import md5
from contextlib import closing

import saq

from saq.analysis import Analysis
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

    @property
    def valid_observable_types(self):
        return None

    def execute_analysis(self, observable):
        # create analysis object and add it to the observable
        analysis = self.create_analysis(observable)

        # create hal9000 observable list for use in post analysis
        if not hasattr(self.root, 'hal9000_observables'):
            self.root.hal9000_observables = set() # of the md5 hashes of the observables

        # get the id of the observable
        md5_hasher = md5()
        md5_hasher.update(observable.type.encode('utf-8', errors='ignore'))
        md5_hasher.update(observable.value.encode('utf-8', errors='ignore'))
        id = md5_hasher.hexdigest()
        logging.debug("id = {}".format(id))

        # append id to hal9000 observables list so we can insert it during post processing
        self.root.hal9000_observables.add(id)

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
            
        # if we are already an Alert AND we have a disposition...
        if isinstance(self.root, saq.database.Alert) and self.root.id and self.root.disposition:

            # keep track of the observables we've already updated in hal
            _updated_observables = set() # of md5 hash hexdigest

            # did we already set a disposition for this alert before?
            previous_disposition = None
            if self.state and 'previous_disposition' in self.state:
                previous_disposition = self.state['previous_disposition']
                logging.debug("loaded previous disposition of {} for {}".format(previous_disposition, self))

            new_disposition = self.root.disposition

            # if the disposition didn't change then we don't care
            if previous_disposition == new_disposition:
                logging.debug("same disposition {} == {} - not updating".format(new_disposition, self.root.disposition))
                return

            with get_db_connection('hal9000') as db:
                c = db.cursor()

                update_count = 0

                # update counts for all observables
                for observable in self.root.all_observables:
                    md5_hasher = md5()
                    md5_hasher.update(observable.type.encode('utf-8', errors='ignore'))
                    md5_hasher.update(observable.value.encode('utf-8', errors='ignore'))
                    id = md5_hasher.hexdigest()

                    # keep track of the ones we've already updated
                    # we only update any single observable value ONCE for each alert
                    if id in _updated_observables:
                        continue

                    _updated_observables.add(id)

                    # we have three major groups of dispositions: IGNORE, MAL and BENIGN
                    # if we've changed state from what we were previously then we want to "undo" what we did previously

                    if previous_disposition is None or previous_disposition in IGNORE_ALERT_DISPOSITIONS:
                        if new_disposition in MAL_ALERT_DISPOSITIONS:
                            execute_with_retry(c, """
                                INSERT INTO observables (id, mal_count)
                                VALUES (UNHEX(%s), 1)
                                ON DUPLICATE KEY
                                UPDATE total_count = total_count + 1, mal_count = mal_count + 1
                                """, (id,))
                        elif new_disposition in BENIGN_ALERT_DISPOSITIONS:
                            execute_with_retry(c, """
                                INSERT INTO observables (id)
                                VALUES (UNHEX(%s))
                                ON DUPLICATE KEY
                                UPDATE total_count = total_count + 1
                                """, (id,))
                    elif previous_disposition in BENIGN_ALERT_DISPOSITIONS:
                        if new_disposition in MAL_ALERT_DISPOSITIONS:
                            execute_with_retry(c, """
                                UPDATE observables
                                SET mal_count = mal_count + 1
                                WHERE id = UNHEX(%s)
                                """, (id,))
                        elif new_disposition in IGNORE_ALERT_DISPOSITIONS:
                            execute_with_retry(c, """
                                UPDATE observables
                                SET total_count = total_count - 1
                                WHERE id = UNHEX(%s) AND total_count > 0
                                """, (id,))
                    elif previous_disposition in MAL_ALERT_DISPOSITIONS:
                        if new_disposition in BENIGN_ALERT_DISPOSITIONS:
                            execute_with_retry(c, """
                                UPDATE observables
                                SET mal_count = mal_count - 1 
                                WHERE id = UNHEX(%s) AND mal_count > 0
                                """, (id,))
                        elif new_disposition in IGNORE_ALERT_DISPOSITIONS:
                            execute_with_retry(c, """
                                UPDATE observables
                                SET total_count = total_count - 1, mal_count = mal_count - 1
                                WHERE id = UNHEX(%s) AND total_count > 0 AND mal_count > 0
                                """, (id,))

                    update_count += 1

                db.commit()

            # remember what our disposition was
            self.state = {}
            self.state['previous_disposition'] = self.root.disposition

            logging.debug("updated {} observables in hal9000".format(update_count))
            return

        # if we're not in the database AND we're not going to be an Alert...
        elif not self.root.has_detections:
            # sanity check
            if not hasattr(self, 'hal9000_observables'):
                logging.error("missing hal9000_observables property")
                return

            with get_db_connection('hal9000') as db:
                c = db.cursor()

                # record appearance of all hal9000 observables
                for id in self.root.hal9000_observables:
                    execute_with_retry(c, """
                                       INSERT INTO observables (id)
                                       VALUES (UNHEX(%s))
                                       ON DUPLICATE KEY
                                       UPDATE total_count = total_count + 1""", (id,))

                db.commit()

            return

        # otherwise we don't care
        logging.debug("{} is not an alert or does not have a disposition".format(self)) 
        return

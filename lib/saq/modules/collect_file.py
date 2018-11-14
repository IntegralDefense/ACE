import logging
import pymysql
from hashlib import md5
from contextlib import closing
import saq
from saq.analysis import Analysis
from saq.constants import *
from saq.modules import AnalysisModule
import ntpath
import os

from cbapi.response import *

class CollectFileAnalysis(Analysis):

    def initialize_details(self):
        self.details = { }

    @property
    def jinja_template_path(self):
        return "analysis/collect_file.html"

    def generate_summary(self):
        return "Collect File Analysis - {}".format(self.details['result'])

class CollectFileAnalyzer(AnalysisModule):

    def verify_environment(self):
        if not 'carbon_black' in saq.CONFIG:
            raise ValueError("missing config section carbon_black")

        key = 'credential_file'
        if not key in saq.CONFIG['carbon_black']:
                raise ValueError("missing config item {} in section carbon_black".format(key))

    @property
    def delay(self):
        return self.config.getint('delay')

    @property
    def generated_analysis_type(self):
        return CollectFileAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE_LOCATION

    #@property
    #def required_directives(self):
    #    return [ DIRECTIVE_COLLECT_FILE ]

    def _get_sensor(self, hostname):
        # Get the right sensor

        cb = CbResponseAPI(credential_file=saq.CONFIG['carbon_black']['credential_file'])

        sensor = None
        try:
            logging.debug("Getting the sensor object from carbonblack")
            return cb.select(Sensor).where("hostname:{}".format(hostname)).one()
        except TypeError as e:
            # Appears to be bug in cbapi library here -> site-packages/cbapi/query.py", line 34, in one
            # Raise MoreThanOneResultError(message="0 results for query {0:s}".format(self._query))
            # That raises a TypeError
            if 'non-empty format string passed to object' in str(e):
                try: # accounting for what appears to be an error in cbapi error handling
                    result = cb.select(Sensor).where("hostname:{}".format(hostname))
                    if isinstance(result[0], models.Sensor):
                        print()
                        warning_string = "MoreThanOneResult Error searching for {0:s} : Sensor IDs = ".format(hostname)
                        sensor_ids = []
                        for s in result:
                            sensor_ids.append(int(s.id))
                            warning_string += "{} ".format(s.id)
                            if int(s.id) == max(sensor_ids):
                                sensor = s
                        default_sid = max(sensor_ids)
                        warning_string += "- Using {}.".format(default_sid)
                        logging.warning(warning_string)
                        return sensor
                    else:
                        logging.error("Unknown CarbonBlack Sensor result: Type={} Value={}".format(type(result), result))
                except Exception as e:
                    logging.error("Error getting CarbonBlack Sensor: {}".format(str(e)))
                    return None
        except Exception as e:
            logging.error("Error selecting CarbonBlack Sensor: {}".format(str(e)))
            return None

    def execute_analysis(self, file_location):

        analysis = self.create_analysis(file_location)

        hostname = file_location.hostname
        location = file_location.full_path

        sensor = self._get_sensor(hostname)

        # delay if the host is offline
        if sensor.status != 'Online':
            return self.delay_analysis(file_location, analysis, seconds=self.delay)

        lr_session = None
        try:
            lr_session = sensor.lr_session()
        except Exception as e:
            message = "Error starting LR session with CarbonBlack on {} : {}".format(hostname, e)
            logging.error(message)
            analysis.details['result'] = "Failed"
            analysis.details['message'] = message
            return False

        result = None
        try:
            result = lr_session.get_file(location)
        except Exception as e:
            message = "Error: '{}' when attempting to get file '{}' from '{}' with Cb".format(e, location, hostname)
            logging.error(message)
            analysis.details['result'] = "Failed"
            analysis.details['message'] = message
            return False

        # default message for the GUI
        analysis.details['result'] = "Succeeded"
        analysis.details['message'] = "'{}' was sucessfully collected from {} via CarbonBlack".format(location, hostname)

        # get file md5
        md5_hasher = md5()
        md5_hasher.update(result)
        file_md5 = md5_hasher.hexdigest().upper()

        # get file name
        file_name = os.path.basename(file_location.full_path)
        if '\\' in file_location.full_path:
            file_name = ntpath.basename(file_location.full_path)

        # create file path
        path = os.path.join(self.root.storage_dir, "collect_file")
        if not os.path.isdir(path):
            os.mkdir(path)
        path = os.path.join(path, file_md5)
        if not os.path.isdir(path):
            os.mkdir(path)
        path = os.path.join(path, file_name)

        # write result to file and add observable
        with open(path, "wb") as fh:
            fh.write(result)

        analysis.add_observable(F_FILE, os.path.relpath(path, start=self.root.storage_dir))

        return True

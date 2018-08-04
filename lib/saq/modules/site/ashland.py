# vim: sw=4:ts=4:et

import logging
import pymssql

import saq
from saq.analysis import Analysis, Observable
from saq.modules import AnalysisModule
from saq.modules.asset import AssetAnalysis
from saq.constants import *


class MatrixAnalysis(Analysis):
    pass


class MatrixAnalyzer(AnalysisModule):
    """ Ashland Matrix Analyzer

The "Matrix" has an inventory list maintained by a team at Ashland.  This is
stored in a SQL Server database.

"""

    @property
    def generated_analysis_type(self):
        return MatrixAnalysis

    @property
    def valid_observable_types(self):
        return F_ASSET

    def __init__(self, *args, **kwargs):
        super(MatrixAnalyzer, self).__init__(*args, **kwargs)

        # load settings from configuration
        self.server = saq.CONFIG.get(self.config_section, 'server')
        self.database = saq.CONFIG.get(self.config_section, 'database')
        self.user = saq.CONFIG.get(self.config_section, 'user')
        self.password = saq.CONFIG.get(self.config_section, 'password')
    
    def execute_analysis(self, asset):

        # do we have host analysis for this asset?
        host_analysis = asset.get_analysis(AssetAnalysis)
        if host_analysis is not None:
            if host_analysis.hostname is not None:
                logging.debug("analyzing asset {0}".format(host_analysis.hostname))
                try:
                    self.acquire_semaphore()
                    analysis = MatrixAnalysis()
                    analysis.details = self.analyze_asset(host_analysis.hostname)
                    asset.add_analysis(analysis)
                finally:
                    self.release_semaphore()

    def analyze_asset(self, hostname):
        assert hostname is not None
        assert len(hostname) > 0
        
        result = []

        conn = None

        logging.debug("connecting to mysql database server {0}".format(self.server))
        with pymssql.connect(self.server, self.user, self.password, self.database) as conn:
            with conn.cursor(as_dict=True) as cursor:
                logging.debug("querying matrix database for {0}".format(hostname))
                cursor.execute("""
SELECT
    *
FROM
    Computer_Listing
WHERE
    LOWER(Hostname) LIKE %s
""", ('%' + hostname + '%'))

                for row in cursor:
                    result.append(row)

                logging.debug("found {0} entries for {1}".format(
                    len(result), hostname))

        return result


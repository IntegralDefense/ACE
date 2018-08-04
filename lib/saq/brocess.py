# vim: sw=4:ts=4:et:cc=120
#
# utility functions to use the brocess databases

import csv
import datetime
import logging
import os.path

import saq
from saq.database import get_db_connection
from saq.modules import AnalysisModule
from saq.util import iterate_fqdn_parts

import pymysql

def query_brocess_by_fqdn(fqdn):
    with get_db_connection('brocess') as connection:
        cursor = connection.cursor()
        cursor.execute('SELECT SUM(numconnections) FROM httplog WHERE host = %s', (fqdn,))
    
        for row in cursor:
            count = row[0]
            return int(count) if count is not None else 0

        raise RuntimeError("failed to return a row for sum() query operation !?")

def query_brocess_by_dest_ipv4(ipv4):
    with get_db_connection('brocess') as connection:
        cursor = connection.cursor()
        cursor.execute('SELECT SUM(numconnections) FROM connlog WHERE destip = INET_ATON(%s)', (ipv4,))
        
        for row in cursor:
            count = row[0]
            return int(count) if count is not None else 0

        raise RuntimeError("failed to return a row for sum() query operation !?")

def query_brocess_by_email_conversation(source_email_address, dest_email_address):
    with get_db_connection('brocess') as connection:
        cursor = connection.cursor()
        cursor.execute('SELECT SUM(numconnections) FROM smtplog WHERE source = %s AND destination = %s', (
                       source_email_address, dest_email_address,))
        
        for row in cursor:
            count = row[0]
            return int(count) if count is not None else 0

        raise RuntimeError("failed to return a row for sum() query operation !?")

def query_brocess_by_source_email(source_email_address):
    with get_db_connection('brocess') as connection:
        cursor = connection.cursor()
        cursor.execute('SELECT SUM(numconnections) FROM smtplog WHERE source = %s', (source_email_address,))
        
        for row in cursor:
            count = row[0]
            return int(count) if count is not None else 0

        raise RuntimeError("failed to return a row for sum() query operation !?")

def add_httplog(fqdn):
    with get_db_connection('brocess') as db:
        c = db.cursor()
        for fqdn_part in iterate_fqdn_parts(fqdn):
            c.execute("""INSERT INTO httplog ( host, numconnections, firstconnectdate ) 
                         VALUES ( LOWER(%s), 1, UNIX_TIMESTAMP(NOW()) )
                         ON DUPLICATE KEY UPDATE numconnections = numconnections + 1""", ( fqdn_part, ))

        db.commit()

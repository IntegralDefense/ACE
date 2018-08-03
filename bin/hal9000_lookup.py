#!/opt/saq/env3/bin/python3
import pymysql
import hashlib
import sys
from contextlib import closing

with closing(pymysql.connect(
    host='149.55.125.43',
    db='hal9000',
    user='saq-user',
    passwd='2SsbuLLvmKdhqtVw',
    charset='utf8')) as db:
    c = db.cursor()

    md5_hasher = hashlib.md5()
    md5_hasher.update(sys.argv[1].encode('utf-8'))
    md5_hasher.update(sys.argv[2].encode('utf-8'))
    id = md5_hasher.hexdigest()
    print("id = {}".format(id))

    c.execute("""
        SELECT mal_count, total_count
        FROM observables
        WHERE id = UNHEX(%s)
        """, id)
    result = c.fetchone()
    if result is None:
        print("id not found")

    print("Malicious Frequency Analysis {}/{} ({}%)".format(result[0], result[1], 100 * result[0] / result[1]))

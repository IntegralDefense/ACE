#!/opt/saq/env3/bin/python3
import pymysql
import hashlib
from contextlib import closing

DISPOSITION_FALSE_POSITIVE = 'FALSE_POSITIVE'
DISPOSITION_IGNORE = 'IGNORE'
DISPOSITION_UNKNOWN = 'UNKNOWN'
DISPOSITION_REVIEWED = 'REVIEWED'
DISPOSITION_GRAYWARE = 'GRAYWARE'
DISPOSITION_POLICY_VIOLATION = 'POLICY_VIOLATION'
DISPOSITION_RECONNAISSANCE = 'RECONNAISSANCE'
DISPOSITION_WEAPONIZATION = 'WEAPONIZATION'
DISPOSITION_DELIVERY = 'DELIVERY'
DISPOSITION_EXPLOITATION = 'EXPLOITATION'
DISPOSITION_INSTALLATION = 'INSTALLATION'
DISPOSITION_COMMAND_AND_CONTROL = 'COMMAND_AND_CONTROL'
DISPOSITION_EXFIL = 'EXFIL'
DISPOSITION_DAMAGE = 'DAMAGE'

IGNORE_ALERT_DISPOSITIONS = [
    DISPOSITION_IGNORE,
    DISPOSITION_UNKNOWN,
    DISPOSITION_REVIEWED
]

MAL_ALERT_DISPOSITIONS = [
    DISPOSITION_WEAPONIZATION,
    DISPOSITION_DELIVERY,
    DISPOSITION_EXPLOITATION,
    DISPOSITION_INSTALLATION,
    DISPOSITION_COMMAND_AND_CONTROL,
    DISPOSITION_EXFIL,
    DISPOSITION_DAMAGE
]

rows = []

print("connecting to prod db")
with closing(pymysql.connect(
    host='149.55.45.210',
    db='saq-production',
    user='saq-user',
    passwd='2SsbuLLvmKdhqtVw',
    charset='utf8')) as db:
    c = db.cursor()

    print("connected")

    c.execute("""
        SELECT disposition, type, value 
        FROM alerts 
        JOIN observable_mapping 
        ON alerts.id = observable_mapping.alert_id
        JOIN observables
        ON observable_mapping.observable_id = observables.id
        """)
    rows = c.fetchall()

print("connecting to hal db")
with closing(pymysql.connect(
    host='149.55.45.210',
    db='hal9000',
    user='saq-user',
    passwd='2SsbuLLvmKdhqtVw',
    charset='utf8')) as db:
    c = db.cursor()
    print("connected")

    for row in rows:
        md5_hasher = hashlib.md5()
        md5_hasher.update(row[1].encode('utf-8'))
        md5_hasher.update(row[2].encode('utf-8'))
        id = md5_hasher.hexdigest()
        print("id = {}".format(id))
        if row[0] is None:
            print("disp == NULL")
        else:
            print("disp = {}".format(row[0]))

        if row[0] is None:
            print("skipping insert")
            continue
        elif row[0] in IGNORE_ALERT_DISPOSITIONS:
            print("skipping insert")
            continue
        elif row[0] in MAL_ALERT_DISPOSITIONS:
            print("inserting as mal")
            c.execute("""
                INSERT INTO observables (id, mal_count)
                VALUES (UNHEX(%s), 1)
                ON DUPLICATE KEY
                UPDATE total_count = total_count + 1, mal_count = mal_count + 1
                """,
                (id))
        else:
            print("inserting as b9")
            c.execute("""
                INSERT INTO observables (id)
                VALUES (UNHEX(%s))
                ON DUPLICATE KEY
                UPDATE total_count = total_count + 1
                """,
                (id))

    print("committing")
    db.commit()

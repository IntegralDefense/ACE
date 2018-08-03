#!/opt/saq/env3/bin/python3
import pymysql
import hashlib
import sys
from contextlib import closing

uuid = sys.argv[1]
new_disposition = sys.argv[2]

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

BENIGN_ALERT_DISPOSITIONS = [
    DISPOSITION_FALSE_POSITIVE,
    DISPOSITION_GRAYWARE,
    DISPOSITION_POLICY_VIOLATION,
    DISPOSITION_RECONNAISSANCE
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

observables = []

print("connecting to prod db")
with closing(pymysql.connect(
    host='149.55.125.43',
    db='saq-crobinette',
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
        WHERE uuid = %s
        """, uuid)
    observables = c.fetchall()

print("connecting to hal db")
with closing(pymysql.connect(
    host='149.55.125.43',
    db='hal9000',
    user='saq-user',
    passwd='2SsbuLLvmKdhqtVw',
    charset='utf8')) as db:
    c = db.cursor()
    print("connected")

    for observable in observables:
        md5_hasher = hashlib.md5()
        md5_hasher.update(observable[1].encode('utf-8'))
        md5_hasher.update(observable[2].encode('utf-8'))
        id = md5_hasher.hexdigest()
        print("id = {}".format(id))
        
        old_disposition = observable[0]

        if old_disposition is None or old_disposition in IGNORE_ALERT_DISPOSITIONS:
            if new_disposition in MAL_ALERT_DISPOSITIONS:
                print("incrementing mal and total count")
                c.execute("""
                    INSERT INTO observables (id, mal_count)
                    VALUES (UNHEX(%s), 1)
                    ON DUPLICATE KEY
                    UPDATE total_count = total_count + 1, mal_count = mal_count + 1
                    """,
                    (id))
            elif new_disposition in BENIGN_ALERT_DISPOSITIONS:
                print("incrementing total count")
                c.execute("""
                    INSERT INTO observables (id)
                    VALUES (UNHEX(%s))
                    ON DUPLICATE KEY
                    UPDATE total_count = total_count + 1
                    """,
                    (id))
        elif old_disposition in BENIGN_ALERT_DISPOSITIONS:
            if new_disposition in MAL_ALERT_DISPOSITIONS:
                print("incrementing mal count")
                c.execute("""
                    UPDATE observables
                    SET mal_count = mal_count + 1
                    WHERE id = UNHEX(%s)
                    """,
                    (id))
            elif new_disposition in IGNORE_ALERT_DISPOSITIONS:
                print("decrementing total count")
                c.execute("""
                    UPDATE observables
                    SET total_count = total_count - 1
                    WHERE id = UNHEX(%s)
                    """,
                    (id))
        elif old_disposition in MAL_ALERT_DISPOSITIONS:
            if new_disposition in BENIGN_ALERT_DISPOSITIONS:
                print("decrementing mal count")
                c.execute("""
                    UPDATE observables
                    SET mal_count = mal_count - 1
                    WHERE id = UNHEX(%s)
                    """,
                    (id))
            elif new_disposition in IGNORE_ALERT_DISPOSITIONS:
                print("decrementing mal and total count")
                c.execute("""
                    UPDATE observables
                    SET total_count = total_count - 1, mal_count = mal_count - 1
                    WHERE id = UNHEX(%s)
                    """,
                    (id))

    print("committing")
    db.commit()

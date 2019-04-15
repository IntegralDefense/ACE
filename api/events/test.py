# vim: sw=4:ts=4:et

from saq.database import get_db_connection
from api.test import APIBasicTestCase

from flask import url_for


class APIEventsTestCase(APIBasicTestCase):

    def test_get_open_events(self):
        with get_db_connection() as db:
            c = db.cursor()

            # Create an alert
            c.execute("""
                INSERT INTO `alerts`
                (`uuid`,
                `insert_date`,
                `storage_dir`,
                `tool`,
                `tool_instance`,
                `alert_type`,
                `description`,
                `priority`,
                `disposition`,
                `disposition_user_id`,
                `disposition_time`,
                `owner_id`,
                `owner_time`,
                `archived`,
                `removal_user_id`,
                `removal_time`,
                `lock_owner`,
                `lock_id`,
                `lock_transaction_id`,
                `lock_time`,
                `company_id`,
                `location`,
                `detection_count`)
                VALUES
                ('87cd9789-0819-4016-b114-2c2d86663779',
                '2019-03-05 17:14:35',
                'data/localhost.localdomain/87c/87cd9789-0819-4016-b114-2c2d86663779',
                'gui',
                'local1',
                'manual',
                'Manual Correlation',
                0,
                'DELIVERY',
                1,
                '2019-03-05 17:15:38',
                1,
                '2019-03-05 17:15:38',
                0,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL,
                1,
                'localhost.localdomain',
                1);
                """)
            db.commit()

            c.execute("SELECT id FROM alerts WHERE uuid='87cd9789-0819-4016-b114-2c2d86663779'")
            alert_id = c.fetchone()[0]

            # Create an event
            c.execute("""
                INSERT INTO `events`
                (`creation_date`,
                `name`,
                `type`,
                `vector`,
                `prevention_tool`,
                `remediation`,
                `status`,
                `comment`,
                `campaign_id`)
                VALUES
                ("2019-03-06",
                "test event",
                "phish",
                "corporate email",
                "response team",
                "not remediated",
                "OPEN",
                "blah blah blah",
                1);""")
            db.commit()

            c.execute("SELECT id FROM events WHERE name='test event'")
            event_id = c.fetchone()[0]

            # Add the alert to the event
            c.execute("""
                INSERT INTO `event_mapping`
                (`event_id`,
                `alert_id`)
                VALUES
                ({},
                {});""".format(event_id, alert_id))
            db.commit()

            # Create a malware
            c.execute("""
                INSERT INTO `malware`
                (`name`)
                VALUES
                ("nanocore");""")
            db.commit()

            c.execute("SELECT id FROM malware WHERE name='nanocore'")
            malware_id = c.fetchone()[0]

            # Add the threat to the malware
            c.execute("""
                INSERT INTO `malware_threat_mapping`
                (`malware_id`,
                `type`)
                VALUES
                ({},
                "RAT");""".format(malware_id))
            db.commit()

            # Add the malware to the event
            c.execute("""
                INSERT INTO `malware_mapping`
                (`event_id`,
                `malware_id`)
                VALUES
                ({},
                {});""".format(event_id, malware_id))
            db.commit()

        # Finally test the API call
        result = self.client.get(url_for('events.get_open_events'))
        result = result.get_json()
        self.assertIsNotNone(result)
        self.assertEqual(event_id, result[0]['id'])

    def test_update_event_status(self):
        with get_db_connection() as db:
            c = db.cursor()

            # Create an event
            c.execute("""
                INSERT INTO `events`
                (`creation_date`,
                `name`,
                `type`,
                `vector`,
                `prevention_tool`,
                `remediation`,
                `status`,
                `comment`,
                `campaign_id`)
                VALUES
                ("2019-03-06",
                "test event",
                "phish",
                "corporate email",
                "response team",
                "not remediated",
                "OPEN",
                "blah blah blah",
                1);""")
            db.commit()

            c.execute("SELECT id FROM events WHERE name='test event'")
            event_id = c.fetchone()[0]

        # Finally test the API call
        result = self.client.put(url_for('events.update_event_status', event_id=event_id), data={'status': 'CLOSED'})
        result = result.get_json()
        self.assertIsNotNone(result)
        self.assertEqual(event_id, result['id'])
        self.assertEqual(result['status'], 'CLOSED')

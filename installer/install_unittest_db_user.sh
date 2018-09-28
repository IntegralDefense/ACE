#!/usr/bin/env bash

if grep ACE_DB_USER_PASSWORD etc/saq.unittest.ini > /dev/null 2>&1
then
	echo "generating unittest mysql account for ACE with random password"
	tr -cd '[:alnum:]' < /dev/urandom | fold -w14 | head -n1 > .mysql.password.sed
	# modify the configuration files to use it
	sed -i -e 's;^;s/ACE_DB_USER_PASSWORD/;' -e 's;$;/g;' .mysql.password.sed
	sed -i -f .mysql.password.sed etc/saq.unittest.ini
	sed -f .mysql.password.sed sql/create_unittest_db_user.sql > sql/create_unittest_db_user.exec.sql
	rm .mysql.password.sed

	# create the mysql database user for unittesting
	sudo mysql < sql/create_unittest_db_user.exec.sql && rm sql/create_unittest_db_user.exec.sql
fi

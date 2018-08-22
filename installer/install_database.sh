#!/usr/bin/env bash
#
# installs and configures MySQL database settings required for ACE
#

source installer/common.sh

if [ "$EUID" != "0" ]
then
	echo "this script must be executed as root"
	exit 1
fi

# is mysql available?
if ! which mysql > /dev/null 2>&1
then
	echo "missing mysql installation"
	exit 1
fi

# set up the ACE database
echo "installing databases..."

mysql -N -B -e 'show databases' > .db_list

for db in saq-production ace-workload brocess email-archive hal9000 cloudphish vt-hash-cache
do
	if ! egrep "^$db\$" .db_list > /dev/null 2>&1
	then
		echo "creating database $db"
		( mysqladmin create $db && mysql --database=$db < sql/$db\_schema.sql ) || fail "unable to install database $db"
	fi
done

rm .db_list
exit 0

#!/usr/bin/env bash
#
# installs any python packages required by ACE
#

source installer/common.sh

echo "installing required python modules..."
# TODO replace with a requirements file

for p in \
	"--upgrade pip" \
	"--upgrade six" \
	"Flask==0.10.1" \
	"Flask-Bootstrap==3.3.2.1" \
	"Flask-Login==0.2.11" \
	"Flask-Script==2.0.5" \
	"Flask-WTF==0.11" \
	"MarkupSafe==0.23" \
	"PyMySQL==0.6.6" \
	"SQLAlchemy==1.2.7" \
	"WTForms==2.0.2" \
	"iptools" \
	"ldap3 " \
	"pyasn1==0.1.8 " \
	"pymongo==2.8 --upgrade " \
	"setuptools_git " \
	"requests --upgrade " \
	"psutil " \
	"Flask-SQLAlchemy " \
	"pytz " \
	"beautifulsoup4" \
	"lxml" \
	"python-memcached" \
	"dnspython" \
	"cbapi" \
	"ply" \
	"businesstime" \
	"html2text" \
	"olefile" \
	"Pandas" \
	"openpyxl" \
	"pysocks" \
	"tld" \
	"python-magic" \
	"oletools" \
	"pcodedmp" \
	"splunklib" \
	"yara_scanner" \
	"vxstreamlib" \
	"urlfinderlib" \
	"msoffice_decrypt" \
    "cbinterface"
do
	python3 -m pip install $p || fail "unable to install python pip package $p"
done

# old python2 stuff
python2 -m pip install officeparser || fail "unable to install python2 pip package officeparser"

exit 0

#!/usr/bin/env bash
cd /opt/ace || { echo "cannot cd to /opt/ace"; exit 1; }

source "installer/common.sh"

#ln -s /opt/signatures /opt/ace/etc/yara || fail

#echo "downloading ASN data..."
#bin/update_asn_data

#echo "downloading snort rules..."
#bin/update_snort_rules

#echo "creating initial crits cache..."
#bin/update_crits_cache

(cd etc && cp -a ace_logging.example.ini ace_logging.ini) || fail
(cd etc && cp -a brotex_logging.example.ini brotex_logging.ini) || fail
(cd etc && cp -a carbon_black_logging.example.ini carbon_black_logging.ini) || fail
(cd etc && cp -a email_scanner_logging.example.ini email_scanner_logging.ini) || fail
(cd etc && cp -a http_scanner_logging.example.ini http_scanner_logging.ini) || fail
(cd etc && cp -a gui_logging.example.ini gui_logging.ini && ln -s gui_logging.ini apache_logging.ini) || fail
(cd etc && cp -a saq.example.ini saq.local.ini && ln -s saq.local.ini saq.ini) || fail

(cd etc && mv brotex.whitelist.sample brotex.whitelist) || fail

# generate a random password to use for the mysql account
tr -cd '[:alnum:]' < /dev/urandom | fold -w14 | head -n1 > .mysql.password.sed
# modify the configuration files to use it
sed -i -e 's;^;s/SAQ_USER_PASSWORD/;' -e 's;$;/g;' .mysql.password.sed
sed -i -f .mysql.password.sed etc/saq.ini
sed -f .mysql.password.sed sql/create_db_user.sql > sql/create_db_user.exec.sql
sed -f .mysql.password.sed etc/mysql_defaults.example > etc/mysql_defaults && chmod 660 etc/mysql_defaults 

# and then one to use as the secret key for flask
tr -cd '[:alnum:]' < /dev/urandom | fold -w30 | head -n1 > .gui_secret_key.sed
sed -i -e 's;^;s/SAQ_SECRET_KEY/;' -e 's;$;/g;' .gui_secret_key.sed
sed -i -f .gui_secret_key.sed etc/saq.ini
rm .gui_secret_key.sed

# create various directories and files
# XXX clean this up
for path in etc/site_tags.csv etc/ssdeep_hashes
do
	if [ ! -e "${path}" ]; then touch "${path}"; fi
done

if [ ! -e etc/organization.json ]; then echo '{}' > etc/organization.json; fi
if [ ! -e etc/local_networks.csv ]; then echo 'Indicator,Indicator_Type' > etc/local_networks.csv; fi

openssl req -x509 -newkey rsa:4096 -keyout ssl/web/localhost.key.pem -out ssl/web/localhost.cert.pem -days 365 -nodes -subj '/CN=localhost'

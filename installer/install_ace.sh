#!/usr/bin/env bash
install_dir=$(dirname $0)
source "$install_dir/common.sh"

echo "installing required packages..."
sudo apt-get -y install \
    nmap \
    libldap2-dev \
    libsasl2-dev \
    libmysqlclient-dev \
    libffi-dev \
    libimage-exiftool-perl \
    p7zip-full \
    p7zip-rar \
    unzip \
    unrar \
    libxml2-dev libxslt1-dev \
    libyaml-dev \
    npm \
    ssdeep \
    mysql-server || fail

exit 0

# things that have been removed
# freetds-dev

sudo ln -s /usr/bin/nodejs /usr/local/bin/node
sudo npm config set strict-ssl false
# sudo npm config set proxy "$http_proxy"
# sudo npm config set https-proxy "$https_proxy"
sudo npm -g install esprima

echo "installing required python modules..."
# TODO replace with a requirements file
sudo -E python3 -m pip install --upgrade pip
sudo -E python3 -m pip install --upgrade six || fail

sudo -E python3 -m pip install Flask==0.10.1 || fail
sudo -E python3 -m pip install Flask-Bootstrap==3.3.2.1 || fail
sudo -E python3 -m pip install Flask-Login==0.2.11 || fail
sudo -E python3 -m pip install Flask-Script==2.0.5 || fail
sudo -E python3 -m pip install Flask-WTF==0.11 || fail
sudo -E python3 -m pip install Jinja2==2.7.3 || fail
sudo -E python3 -m pip install MarkupSafe==0.23 || fail
sudo -E python3 -m pip install PyMySQL==0.6.6 || fail
sudo -E python3 -m pip install SQLAlchemy==1.2.7 || fail
sudo -E python3 -m pip install WTForms==2.0.2 || fail
sudo -E python3 -m pip install Werkzeug==0.10.4 || fail
sudo -E python3 -m pip install iptools==0.6.1 || fail
sudo -E python3 -m pip install itsdangerous==0.24 || fail
sudo -E python3 -m pip install ldap3 || fail
sudo -E python3 -m pip install pyasn1==0.1.7 || fail
sudo -E python3 -m pip install pymongo==2.8 --upgrade || fail
sudo -E python3 -m pip install setuptools_git || fail
#sudo -E python3 -m pip install pymssql || fail
sudo -E python3 -m pip install requests --upgrade || fail
sudo -E python3 -m pip install psutil || fail
sudo -E python3 -m pip install Flask-SQLAlchemy || fail
sudo -E python3 -m pip install pytz || fail
sudo -E python3 -m pip install beautifulsoup4 || fail
sudo -E python3 -m pip install lxml || fail
sudo -E python3 -m pip install python-memcached || fail
sudo -E python3 -m pip install dnspython || fail
sudo -E python3 -m pip install cbapi==1.2.0 || fail
sudo -E python3 -m pip install ply || fail
sudo -E python3 -m pip install businesstime || fail
sudo -E python3 -m pip install html2text || fail
sudo -E python3 -m pip install olefile || fail
sudo -E python3 -m pip install Pandas || fail
sudo -E python3 -m pip install openpyxl || fail
sudo -E python3 -m pip install pysocks || fail
sudo -E python3 -m pip install tld || fail
sudo -E python3 -m pip install python-magic || fail

# set up the ACE database
echo "installing database..."
( mysqladmin --defaults-file=/opt/sensor_installer/mysql_root_defaults create saq-production && \
mysqladmin --defaults-file=/opt/sensor_installer/mysql_root_defaults create ace-workload && \
mysqladmin --defaults-file=/opt/sensor_installer/mysql_root_defaults create brocess && \
mysqladmin --defaults-file=/opt/sensor_installer/mysql_root_defaults create chronos && \
mysqladmin --defaults-file=/opt/sensor_installer/mysql_root_defaults create email-archive && \
mysqladmin --defaults-file=/opt/sensor_installer/mysql_root_defaults create hal9000 && \
mysqladmin --defaults-file=/opt/sensor_installer/mysql_root_defaults create cloudphish && \
mysql --defaults-file=/opt/sensor_installer/mysql_root_defaults --database=saq-production < /opt/saq/sql/ace_schema.sql && \
mysql --defaults-file=/opt/sensor_installer/mysql_root_defaults --database=ace-workload < /opt/saq/sql/ace_workload_schema.sql && \
mysql --defaults-file=/opt/sensor_installer/mysql_root_defaults --database=brocess < /opt/saq/sql/brocess_schema.sql && \
mysql --defaults-file=/opt/sensor_installer/mysql_root_defaults --database=chronos < /opt/saq/sql/chronos_schema.sql && \
mysql --defaults-file=/opt/sensor_installer/mysql_root_defaults --database=email-archive < /opt/saq/sql/email_archive_schema.sql && \
mysql --defaults-file=/opt/sensor_installer/mysql_root_defaults --database=cloudphish < /opt/saq/sql/cloudphish_schema.sql && \
mysql --defaults-file=/opt/sensor_installer/mysql_root_defaults --database=hal9000 < /opt/saq/sql/hal9000_schema.sql ) || fail

# set up environment
echo | sudo tee -a /etc/bash.bashrc
echo 'source /opt/saq/load_environment' | sudo tee -a /etc/bash.bashrc

# set up the rest of ace
cd /opt/saq || fail
ln -s /opt/signatures /opt/saq/etc/yara || fail

mkdir -p \
    data \
    logs \
    archive/email \
    archive/smtp_stream \
    error_reports \
    malicious \
    ole \
    scan_failures \
    stats \
    storage \
    var \
    vt_cache \
    work || fail

export SAQ_HOME=/opt/saq

echo "downloading ASN data..."
bin/update_asn_data

echo "downloading snort rules..."
bin/update_snort_rules

echo "creating initial crits cache..."
bin/update_crits_cache

# TODO these should actually be installed
# link in all the libraries we need
(cd lib && ln -s /opt/splunklib/splunklib .) || fail
(cd lib && ln -s /opt/yara_scanner/yara_scanner .) || fail
(cd lib && ln -s /opt/chronos/chronosapi.py .) || fail
(cd lib && ln -s /opt/virustotal/virustotal.py .) || fail
(cd lib && ln -s /opt/wildfirelib/bin/wildfirelib.py .) || fail
(cd lib && ln -s /opt/vxstreamlib/bin/vxstreamlib.py .) || fail
(cd lib && ln -s /opt/cbinterface/cbinterface.py .) || fail
(cd lib && ln -s /opt/cbinterface/CBProcess.py .) || fail
#(cd lib && ln -s /opt/eventmanager/lib eventmanager) || fail
(cd lib && ln -s /opt/event/lib event) || fail

# assume production installation
(cd etc && ln -s ace_logging.production.ini ace_logging.ini) || fail
(cd etc && ln -s brotex_logging.production.ini brotex_logging.ini) || fail
(cd etc && ln -s carbon_black_logging.production.ini carbon_black_logging.ini) || fail
(cd etc && ln -s email_scanner_logging.production.ini email_scanner_logging.ini) || fail
(cd etc && ln -s http_scanner_logging.production.ini http_scanner_logging.ini) || fail
(cd etc && ln -s orion_logging.production.ini orion_logging.ini) || fail

# install GUI into apache
# see http://askubuntu.com/questions/569550/assertionerror-using-apache2-and-libapache2-mod-wsgi-py3-on-ubuntu-14-04-python/569551#569551
sudo apt-get -y install apache2 apache2-dev || fail
(   
    sudo -E python3 -m pip install mod_wsgi && \
    sudo mod_wsgi-express install-module && \
    echo 'LoadModule wsgi_module /usr/lib/apache2/modules/mod_wsgi-py34.cpython-34m.so' | sudo tee -a /etc/apache2/mods-available/wsgi_express.load && \
    echo 'WSGIPythonHome /usr' | sudo tee -a /etc/apache2/mods-available/wsgi_express.conf && \
    sudo a2enmod wsgi_express && \
    sudo a2enmod ssl
    #sudo ln -s /opt/saq/etc/saq_apache.conf /etc/apache2/sites-available/ace.conf && \
    #sudo a2ensite ace && \
    #sudo service apache2 restart
) || fail

# install site configurations for ace
#cp -r --backup=simple --suffix=.backup /opt/site_configs/$customer/ace/* /opt/saq

# create the database user and assign database permissions
#if [ -e "/opt/site_configs/$customer/flags/INSTALL_MYSQL" ]
#then
    #mysql --defaults-file=/opt/sensor_installer/mysql_root_defaults --database=mysql < /opt/site_configs/$customer/ace/sql/saq_users.sql || fail
#fi

# finish ace installation
sudo ln -s /opt/saq/etc/saq_apache.conf /etc/apache2/sites-available/ace.conf && \
sudo a2ensite ace && \
sudo service apache2 restart

( cd /opt/saq && bin/update_ssdeep )

# update crontabs
crontab -l 2> /dev/null | cat - crontab | crontab

# install splunk forwarder
#./install_splunk_forwarder.sh $customer

#if [ -x /opt/site_configs/$customer/ace/install ]
#then
    #/opt/site_configs/$customer/ace/install
#fi

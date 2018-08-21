#!/usr/bin/env bash

# make sure we're in the installation directory
( cd $(dirname $0) && cd .. ) || { echo "cannot move into installation directory"; exit 1; }

source "installer/common.sh"

# does the ace group exist yet?
if ! grep ^ace: /etc/group > /dev/null 2>&1
then
    echo "creating group ace"
    sudo -H groupadd ace || fail
fi

# does the ace user exist yet?
if ! id -u ace > /dev/null 2>&1
then
    echo "creating user ace"
    sudo -H useradd -c 'funtional account for ACE' -g ace -m -s /bin/bash ace
fi

if [ ! -d /opt/ace ]
then
    # create the main installation directory (hard coded to /opt/ace for now...)
    sudo -H install -o ace -g ace -d /opt/ace
    # create the directory structure
    sudo -H find . -type d ! -ipath '*/.git*' -exec install -v -o ace -g ace -d '/opt/ace/{}' \;
    # copy all the files over
    find . -type f ! -ipath '*/.git*' -print0 | sed -z -n -e p -e 's;^\./;/opt/ace/;' -e p | sudo -H xargs -0 -n 2 install -v -o ace -g ace
    # and then copy the permissions of the files
    find . -type f ! -ipath '*/.git*' -print0 | sed -z -n -e h -e 's;^;--reference=;' -e p -e x -e 's;^\./;/opt/ace/;' -e p | sudo -H xargs -0 -n 2 chmod
    # create required empty directories
    for d in \
        archive \
        archive/email \
        archive/smtp_stream \
        archive/office \
        archive/ole \
        data \
        error_reports \
        etc/snort \
        logs \
        malicious \
        scan_failures \
		ssl \
		ssl/web \
        stats \
        storage \
        var \
        vt_cache \
        work 
    do
        sudo -H install -v -o ace -g ace -d /opt/ace/$d
    done
fi

echo "installing required packages..."
sudo -H apt -y install \
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
    python-pip \
    python3-pip \
	poppler-utils \
    mysql-server || fail

# things that have been removed
# freetds-dev

if ! npm -g ls | grep esprima > /dev/null 2>&1
then 
    sudo -H npm config set strict-ssl false
    # sudo npm config set proxy "$http_proxy"
    # sudo npm config set https-proxy "$https_proxy"
    sudo -H npm -g install esprima
fi

echo "installing required python modules..."
# TODO replace with a requirements file
sudo -H -E python3 -m pip install --upgrade pip || fail
sudo -H -E python3 -m pip install --upgrade six || fail

sudo -H -E python3 -m pip install Flask==0.10.1 || fail
sudo -H -E python3 -m pip install Flask-Bootstrap==3.3.2.1 || fail
sudo -H -E python3 -m pip install Flask-Login==0.2.11 || fail
sudo -H -E python3 -m pip install Flask-Script==2.0.5 || fail
sudo -H -E python3 -m pip install Flask-WTF==0.11 || fail
#sudo -H -E python3 -m pip install Jinja2==2.7.3 || fail
sudo -H -E python3 -m pip install MarkupSafe==0.23 || fail
sudo -H -E python3 -m pip install PyMySQL==0.6.6 || fail
sudo -H -E python3 -m pip install SQLAlchemy==1.2.7 || fail
sudo -H -E python3 -m pip install WTForms==2.0.2 || fail
#sudo -H -E python3 -m pip install Werkzeug==0.10.4 || fail
sudo -H -E python3 -m pip install iptools || fail
#sudo -H -E python3 -m pip install itsdangerous==0.24 || fail
sudo -H -E python3 -m pip install ldap3 || fail
sudo -H -E python3 -m pip install pyasn1==0.1.8 || fail
sudo -H -E python3 -m pip install pymongo==2.8 --upgrade || fail
sudo -H -E python3 -m pip install setuptools_git || fail
#sudo -H -E python3 -m pip install pymssql || fail
sudo -H -E python3 -m pip install requests --upgrade || fail
sudo -H -E python3 -m pip install psutil || fail
sudo -H -E python3 -m pip install Flask-SQLAlchemy || fail
sudo -H -E python3 -m pip install pytz || fail
sudo -H -E python3 -m pip install beautifulsoup4 || fail
sudo -H -E python3 -m pip install lxml || fail
sudo -H -E python3 -m pip install python-memcached || fail
sudo -H -E python3 -m pip install dnspython || fail
sudo -H -E python3 -m pip install cbapi || fail
sudo -H -E python3 -m pip install ply || fail
sudo -H -E python3 -m pip install businesstime || fail
sudo -H -E python3 -m pip install html2text || fail
sudo -H -E python3 -m pip install olefile || fail
sudo -H -E python3 -m pip install Pandas || fail
sudo -H -E python3 -m pip install openpyxl || fail
sudo -H -E python3 -m pip install pysocks || fail
sudo -H -E python3 -m pip install tld || fail
sudo -H -E python3 -m pip install python-magic || fail
sudo -H -E python3 -m pip install oletools || fail
sudo -H -E python3 -m pip install pcodedmp || fail

# install our own custom stuff
sudo -H -E python3 -m pip install splunklib || fail
sudo -H -E python3 -m pip install yara_scanner || fail
sudo -H -E python3 -m pip install vxstreamlib || fail
sudo -H -E python3 -m pip install urlfinderlib || fail
sudo -H -E python3 -m pip install msoffice_decrypt || fail
sudo -H -E python -m pip install officeparser || fail

# set up the ACE database
echo "installing database..."
# TODO check to see if this is already done
sudo -H mysqladmin create saq-production || fail
sudo -H mysqladmin create ace-workload || fail
sudo -H mysqladmin create brocess || fail
sudo -H mysqladmin create chronos || fail
sudo -H mysqladmin create email-archive || fail
sudo -H mysqladmin create hal9000 || fail
sudo -H mysqladmin create cloudphish || fail
sudo -H mysql --database=saq-production < sql/ace_schema.sql || fail
sudo -H mysql --database=ace-workload < sql/ace_workload_schema.sql || fail
sudo -H mysql --database=brocess < sql/brocess_schema.sql || fail
sudo -H mysql --database=chronos < sql/chronos_schema.sql || fail
sudo -H mysql --database=email-archive < sql/email_archive_schema.sql || fail
sudo -H mysql --database=cloudphish < sql/cloudphish_schema.sql || fail
sudo -H mysql --database=hal9000 < sql/hal9000_schema.sql || fail

# set up environment
# TODO do not install globally, just for specific user
echo | sudo -H -u ace tee -a ~ace/.bashrc > /dev/null
echo 'source /opt/ace/load_environment' | sudo -H -u ace tee -a ~ace/.bashrc > /dev/null

# install GUI into apache
# see http://askubuntu.com/questions/569550/assertionerror-using-apache2-and-libapache2-mod-wsgi-py3-on-ubuntu-14-04-python/569551#569551
sudo apt-get -y install apache2 apache2-dev || fail
(   
    sudo -H -E python3 -m pip install mod_wsgi && \
    sudo -H mod_wsgi-express install-module > ~/.mod_wsgi-express.output && \
    sed -n -e 1p ~/.mod_wsgi-express.output | sudo -H tee -a /etc/apache2/mods-available/wsgi_express.load && \
    sed -n -e 2p ~/.mod_wsgi-express.output | sudo -H tee -a /etc/apache2/mods-available/wsgi_express.conf && \
    rm ~/.mod_wsgi-express.output && \
    sudo a2enmod wsgi_express && \
    sudo a2enmod ssl &&
	sudo a2ensite default-ssl
) || fail

sudo -H -u ace /opt/ace/install_ace_s2.sh

# install site configurations for ace
#cp -r --backup=simple --suffix=.backup /opt/site_configs/$customer/ace/* /opt/ace

# create the database user and assign database permissions
#if [ -e "/opt/site_configs/$customer/flags/INSTALL_MYSQL" ]
#then
    #mysql --defaults-file=/opt/sensor_installer/mysql_root_defaults --database=mysql < /opt/site_configs/$customer/ace/sql/saq_users.sql || fail
#fi

# finish ace installation
sudo ln -s /opt/ace/etc/saq_apache.conf /etc/apache2/sites-available/ace.conf && \
sudo a2ensite ace && \
sudo systemctl apache2.service restart

#( cd /opt/ace && bin/update_ssdeep )

# update crontabs
#crontab -l 2> /dev/null | cat - crontab | crontab

# install splunk forwarder
#./install_splunk_forwarder.sh $customer

#if [ -x /opt/site_configs/$customer/ace/install ]
#then
    #/opt/site_configs/$customer/ace/install
#fi

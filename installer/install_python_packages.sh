#!/usr/bin/env bash
#
# installs any python packages required by ACE
#

echo "installing required python modules..."
# TODO replace with a requirements file
# TODO support virtualenv
sudo -H -E python3 -m pip install --upgrade pip
sudo -H -E python3 -m pip install --upgrade six

sudo -H -E python3 -m pip install Flask==0.10.1
sudo -H -E python3 -m pip install Flask-Bootstrap==3.3.2.1
sudo -H -E python3 -m pip install Flask-Login==0.2.11
sudo -H -E python3 -m pip install Flask-Script==2.0.5
sudo -H -E python3 -m pip install Flask-WTF==0.11
#sudo -H -E python3 -m pip install Jinja2==2.7.3
sudo -H -E python3 -m pip install MarkupSafe==0.23
sudo -H -E python3 -m pip install PyMySQL==0.6.6
sudo -H -E python3 -m pip install SQLAlchemy==1.2.7
sudo -H -E python3 -m pip install WTForms==2.0.2
#sudo -H -E python3 -m pip install Werkzeug==0.10.4
sudo -H -E python3 -m pip install iptools
#sudo -H -E python3 -m pip install itsdangerous==0.24 
sudo -H -E python3 -m pip install ldap3 
sudo -H -E python3 -m pip install pyasn1==0.1.8 
sudo -H -E python3 -m pip install pymongo==2.8 --upgrade 
sudo -H -E python3 -m pip install setuptools_git 
#sudo -H -E python3 -m pip install pymssql 
sudo -H -E python3 -m pip install requests --upgrade 
sudo -H -E python3 -m pip install psutil 
sudo -H -E python3 -m pip install Flask-SQLAlchemy 
sudo -H -E python3 -m pip install pytz 
sudo -H -E python3 -m pip install beautifulsoup4
sudo -H -E python3 -m pip install lxml
sudo -H -E python3 -m pip install python-memcached
sudo -H -E python3 -m pip install dnspython
sudo -H -E python3 -m pip install cbapi
sudo -H -E python3 -m pip install ply
sudo -H -E python3 -m pip install businesstime
sudo -H -E python3 -m pip install html2text
sudo -H -E python3 -m pip install olefile
sudo -H -E python3 -m pip install Pandas
sudo -H -E python3 -m pip install openpyxl
sudo -H -E python3 -m pip install pysocks
sudo -H -E python3 -m pip install tld
sudo -H -E python3 -m pip install python-magic
sudo -H -E python3 -m pip install oletools
sudo -H -E python3 -m pip install pcodedmp

# install our own custom stuff
sudo -H -E python3 -m pip install splunklib
sudo -H -E python3 -m pip install yara_scanner
sudo -H -E python3 -m pip install vxstreamlib
sudo -H -E python3 -m pip install urlfinderlib
sudo -H -E python3 -m pip install msoffice_decrypt
sudo -H -E python -m pip install officeparser


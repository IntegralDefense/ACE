#!/usr/bin/env bash
#
# installs and configures ACE gui for Apache
#

# see http://askubuntu.com/questions/569550/assertionerror-using-apache2-and-libapache2-mod-wsgi-py3-on-ubuntu-14-04-python/569551#569551
sudo apt-get -y install apache2 apache2-dev 

sudo -H -E python3 -m pip install mod_wsgi && \
sudo -H mod_wsgi-express install-module > ~/.mod_wsgi-express.output && \
sed -n -e 1p ~/.mod_wsgi-express.output | sudo -H tee -a /etc/apache2/mods-available/wsgi_express.load && \
sed -n -e 2p ~/.mod_wsgi-express.output | sudo -H tee -a /etc/apache2/mods-available/wsgi_express.conf && \
rm ~/.mod_wsgi-express.output && \
sudo a2enmod wsgi_express && \
sudo a2enmod ssl &&
sudo a2ensite default-ssl

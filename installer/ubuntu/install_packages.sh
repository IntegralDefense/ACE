#!/usr/bin/env bash
#
# installs any packages required by ACE on an Ubuntu machine
#

echo "installing required packages..."
sudo -H apt-get -y install \
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
    mysql-server

# things that have been removed
# freetds-dev

if ! npm -g ls | grep esprima > /dev/null 2>&1
then 
    sudo -H npm config set strict-ssl false
	# TODO deal with proxy settings
    # sudo npm config set proxy "$http_proxy"
    # sudo npm config set https-proxy "$https_proxy"
    sudo -H npm -g install esprima
fi


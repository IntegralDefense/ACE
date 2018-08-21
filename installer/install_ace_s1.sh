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

installer/install_packages.sh
installer/install_python_packages.sh
installer/install_database.sh
installer/install_apache_gui.sh

# set up environment
# TODO do not install globally, just for specific user
echo | sudo -H -u ace tee -a ~ace/.bashrc > /dev/null
echo 'source /opt/ace/load_environment' | sudo -H -u ace tee -a ~ace/.bashrc > /dev/null

echo "installing local files..."
sudo -H -u ace /opt/ace/installer/install_ace_s2.sh

# create the mysql database
sudo -H mysql < /opt/ace/sql/create_db_user.exec.sql && sudo rm /opt/ace/sql/create_db_user.exec.sql

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
sudo systemctl restart apache2.service

#( cd /opt/ace && bin/update_ssdeep )

# update crontabs
#crontab -l 2> /dev/null | cat - crontab | crontab

# install splunk forwarder
#./install_splunk_forwarder.sh $customer

#if [ -x /opt/site_configs/$customer/ace/install ]
#then
    #/opt/site_configs/$customer/ace/install
#fi

echo
echo finished installation of ACE
echo
echo add a user for yourself using the following commands
echo sudo su - ace
echo cd /opt/ace
echo ./ace add-user username email_address
echo

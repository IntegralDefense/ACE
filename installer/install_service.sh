#!/usr/bin/env bash

# install the service if systemd exists
if [ -d "/etc/systemd/system/" ]
then
	# allow setting user from first arg
	SERVICE_USER="ace"
	if [ "$#" -ge 1 ]
	then
		SERVICE_USER="$1"
	fi

	# allow setting group from second arg
	SERVICE_GROUP="ace"
	if [ "$#" -ge 2 ]
	then
		SERVICE_GROUP="$2"
	fi

	# create symlink to startupd config
	ln -s startupd.default $SAQ_HOME/etc/startupd

	# create the service config file
	echo "[Unit]" | sudo tee /etc/systemd/system/ace.service
	echo "Description=ace" | sudo tee -a /etc/systemd/system/ace.service
	echo "" | sudo tee -a /etc/systemd/system/ace.service
	echo "[Service]" | sudo tee -a /etc/systemd/system/ace.service
	echo "Type=simple" | sudo tee -a /etc/systemd/system/ace.service
	echo "User=$SERVICE_USER" | sudo tee -a /etc/systemd/system/ace.service
	echo "Group=$SERVICE_GROUP" | sudo tee -a /etc/systemd/system/ace.service
	echo "Restart=always" | sudo tee -a /etc/systemd/system/ace.service
	echo "WorkingDirectory=$SAQ_HOME" | sudo tee -a /etc/systemd/system/ace.service
	echo "ExecStart=$SAQ_HOME/aced" | sudo tee -a /etc/systemd/system/ace.service
	echo "" | sudo tee -a /etc/systemd/system/ace.service
	echo "[Install]" | sudo tee -a /etc/systemd/system/ace.service
	echo "WantedBy=multi-user.target" | sudo tee -a /etc/systemd/system/ace.service
fi

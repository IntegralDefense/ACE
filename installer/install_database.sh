#!/usr/bin/env bash
#
# installs and configures MySQL database settings required for ACE
#

# set up the ACE database
echo "installing database..."
# TODO check to see if this is already done
sudo -H mysqladmin create saq-production
sudo -H mysqladmin create ace-workload
sudo -H mysqladmin create brocess
sudo -H mysqladmin create chronos
sudo -H mysqladmin create email-archive
sudo -H mysqladmin create hal9000
sudo -H mysqladmin create cloudphish
sudo -H mysql --database=saq-production < sql/ace_schema.sql
sudo -H mysql --database=ace-workload < sql/ace_workload_schema.sql
sudo -H mysql --database=brocess < sql/brocess_schema.sql
sudo -H mysql --database=chronos < sql/chronos_schema.sql
sudo -H mysql --database=email-archive < sql/email_archive_schema.sql
sudo -H mysql --database=cloudphish < sql/cloudphish_schema.sql
sudo -H mysql --database=hal9000 < sql/hal9000_schema.sql

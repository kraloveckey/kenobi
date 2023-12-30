#!/usr/bin/env bash

set -o nounset
set -o pipefail

#----------------------------------------------------------------------------------------

if [[ "${TRACE-0}" == "1" ]]; then
    set -o xtrace
fi

#----------------------------------------------------------------------------------------

if [[ "${1-}" =~ ^-*h(elp)?$ ]]; then
    echo 'Usage: ./postgresql-14.sh
 
This is bash script to install and configure postgresql-14 database.
'
    exit
fi

#----------------------------------------------------------------------------------------

if [ -x "$(command -v psql)" ]; then
    echo -e 'PostgreSQL Server is already installed.\n'
    exit 1
fi

#----------------------------------------------------------------------------------------

sudo apt update && sudo apt upgrade -y && sudo apt autoremove --purge -y
sudo sh -c 'echo "deb http://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" > /etc/apt/sources.list.d/pgdg.list'
wget --quiet -O - https://www.postgresql.org/media/keys/ACCC4CF8.asc | sudo apt-key add -
sudo apt-get update
sudo apt install postgresql-14 postgresql-client-14 -y
sudo psql --version

#----------------------------------------------------------------------------------------

var1="local   all             postgres                                peer"
var2="local   all             postgres                                md5"
sudo sed -i "s/$var1/$var2/g" /etc/postgresql/14/main/pg_hba.conf

#----------------------------------------------------------------------------------------

sudo sed -i "/#restart_after_crash = on/d" /etc/postgresql/14/main/postgresql.conf
sudo sed -i "/shared_buffers = 128MB/d" /etc/postgresql/14/main/postgresql.conf
sudo sed -i "/#work_mem = 4MB/d" /etc/postgresql/14/main/postgresql.conf
sudo sed -i "/#shared_preload_libraries =/d" /etc/postgresql/14/main/postgresql.conf
sudo sed -i "/#jit = on/d" /etc/postgresql/14/main/postgresql.conf

sudo cat <<\EOF >> /etc/postgresql/14/main/postgresql.conf
restart_after_crash = on                # reinitialize after backend crash?
shared_buffers = 1024MB                 # min 128kB
work_mem = 2048MB                       # min 64kB
shared_preload_libraries = 'pg_stat_statements'
jit = off
EOF

#----------------------------------------------------------------------------------------

sudo cat <<\EOF >> /etc/postgresql/14/main/pg_hba.conf

# TYPE  DATABASE        USER            ADDRESS                 METHOD
local   all             db-user                                 md5
EOF

#----------------------------------------------------------------------------------------

STRONG_PASSWORD=`< /dev/urandom tr -dc _#A-Z-a-z-0-9 | head -c${1:-24}`
sudo -u postgres psql -c "ALTER USER postgres PASSWORD '${STRONG_PASSWORD}';"
echo -e "\n\nPassword for postgres user: ${STRONG_PASSWORD}\n\nSAVE IT, PLEASE!\n\n"

sudo systemctl restart postgresql.service
sudo systemctl status postgresql.service --no-pager
sudo netstat -tunlp | grep postgres

#----------------------------------------------------------------------------------------

exit 0
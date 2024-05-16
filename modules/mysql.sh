#!/usr/bin/env bash

set -o nounset
set -o pipefail

#----------------------------------------------------------------------------------------

if [[ "${TRACE-0}" == "1" ]]; then
    set -o xtrace
fi

#----------------------------------------------------------------------------------------

if [[ "${1-}" =~ ^-*h(elp)?$ ]]; then
    echo 'Usage: ./mysql.sh
 
This is bash script to install and configure MySQL database.
'
    exit
fi

#----------------------------------------------------------------------------------------

if [ -x "$(command -v mysql)" ]; then
    echo -e 'MySQL Server is already installed.\nPlease, purge old MySQL Server and remove next folders: /etc/mysql, /var/lib/mysql.\n'
    exit 1
fi

#----------------------------------------------------------------------------------------

sudo apt update && sudo apt upgrade -y && sudo apt autoremove --purge -y

[ ! -e /usr/bin/expect ] && { sudo apt install expect -y; }

sudo apt install mysql-server -y

STRONG_PASSWORD=`< /dev/urandom tr -dc _#A-Z-a-z-0-9 | head -c${1:-24}`

sudo mysql --user=root << EOFMYSQLSECURE
SELECT plugin from mysql.user where User='root';
UPDATE mysql.user SET plugin = 'caching_sha2_password' WHERE user = 'root' AND plugin = 'auth_socket';
FLUSH PRIVILEGES;
SELECT User,plugin from mysql.user where User='root';
ALTER USER root@localhost identified by '${STRONG_PASSWORD}';
FLUSH PRIVILEGES;
EOFMYSQLSECURE

cat <<EOF | mysql_secure_installation -u root -p${STRONG_PASSWORD}
y
2
No
y
y
y
y
y
EOF

#----------------------------------------------------------------------------------------

sudo echo "" > /etc/mysql/mysql.conf.d/mysqld.cnf
sudo cat <<\EOF > /etc/mysql/mysql.conf.d/mysqld.cnf
#
# The MySQL database server configuration file.
#
# One can use all long options that the program supports.
# Run program with --help to get a list of available options and with
# --print-defaults to see which it would actually understand and use.
#
# For explanations see
# http://dev.mysql.com/doc/mysql/en/server-system-variables.html

[server]
tmp_table_size= 64M
max_heap_table_size= 64M
slow_query_log = 1
slow_query_log_file = /var/log/mysql/slow.log
long_query_time = 1
 
[client]
default-character-set = utf8mb4
 
[mysqld]
bind-address = 127.0.0.1
mysqlx_bind_address = 127.0.0.1
mysqlx=OFF
default-authentication-plugin = mysql_native_password
collation_server = utf8_general_ci
character_set_server = utf8
max_allowed_packet = 1048576000
group_concat_max_len = 2048
max_connections = 1000
sql_mode = 'NO_ENGINE_SUBSTITUTION'
expire_logs_days = 7
pid-file        = /var/run/mysqld/mysqld.pid
socket          = /var/run/mysqld/mysqld.sock
datadir         = /var/lib/mysql
log-error       = /var/log/mysql/error.log
port  = 3306
skip-external-locking
key_buffer_size = 256M
table_open_cache = 256
sort_buffer_size = 1M
read_buffer_size = 1M
read_rnd_buffer_size = 4M
myisam_sort_buffer_size = 64M
thread_cache_size = 8
open_files_limit=1000000
transaction_isolation = READ-COMMITTED
binlog_format = ROW
EOF

#----------------------------------------------------------------------------------------

sudo sed -i 's/LimitNOFILE=/LimitNOFILE=524288/' /usr/lib/systemd/system/mysql.service

#----------------------------------------------------------------------------------------

sudo systemctl daemon-reload
sudo systemctl restart mysql.service
sudo systemctl enable mysql.service
sudo systemctl status mysql.service --no-pager
echo -e "\n"
sudo netstat -tunlp | grep mysql
echo -e "\n"
sudo mysql -V

echo -e "\n\nPassword for MySQL root user: ${STRONG_PASSWORD}\n\nSAVE IT, PLEASE!\n\n"

#----------------------------------------------------------------------------------------

exit 0
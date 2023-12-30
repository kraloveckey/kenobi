#!/usr/bin/env bash

set -o nounset
set -o pipefail

#----------------------------------------------------------------------------------------

if [[ "${TRACE-0}" == "1" ]]; then
    set -o xtrace
fi

#----------------------------------------------------------------------------------------

if [[ "${1-}" =~ ^-*h(elp)?$ ]]; then
    echo 'Usage: ./mariadb.sh
 
This is bash script to install and configure MariaDB database.
'
    exit
fi

#----------------------------------------------------------------------------------------

if [ -x "$(command -v mariadb)" ]; then
    echo -e 'MariaDB Server is already installed.\nPlease, purge old MariaDB Server and remove next folders: /etc/mysql, /var/lib/mysql*.\n'
    exit 1
fi

#----------------------------------------------------------------------------------------

sudo apt update && sudo apt upgrade -y && sudo apt autoremove --purge -y

cd /tmp && curl -LsS https://r.mariadb.com/downloads/mariadb_repo_setup | sudo bash

sudo apt install mariadb-server mariadb-client -y

STRONG_PASSWORD=`< /dev/urandom tr -dc _#A-Z-a-z-0-9 | head -c${1:-24}`

sudo mariadb --user=root << EOFMYSQLSECURE
ALTER USER root@localhost identified by '${STRONG_PASSWORD}';
FLUSH PRIVILEGES;
EOFMYSQLSECURE

cat <<EOF | mariadb-secure-installation
${STRONG_PASSWORD}
n
n
y
y
y
y
EOF

#----------------------------------------------------------------------------------------

if [ -e "/etc/mysql/my.cnf" ]; then
    echo -e "\nFile /etc/mysql/my.cnf exist...\n"
else
    echo -e "\nFile /etc/mysql/my.cnf does not exist. Creating...\n"
    sudo touch /etc/mysql/my.cnf
    sudo chmod 600 /etc/mysql/my.cnf
fi

sudo echo "" > /etc/mysql/my.cnf
sudo cat <<EOF > /etc/mysql/my.cnf
[client]
host     = localhost
user     = root
password = "${STRONG_PASSWORD}"
socket   = /run/mysqld/mysqld.sock

[mysql_upgrade]
host     = localhost
user     = root
password = "${STRONG_PASSWORD}"
socket   = /run/mysqld/mysqld.sock

[server]
in_predicate_conversion_threshold = 0

[mysqld]
max_prepared_stmt_count = 1000000
#
# * Basic Settings
#
user = mysql
pid-file = /run/mysqld/mysqld.pid
socket = /run/mysqld/mysqld.sock
basedir = /usr
datadir = /var/lib/mysql
tmpdir = /tmp
lc-messages-dir = /usr/share/mysql
port = 3306
bind-address = 127.0.0.1
key_buffer_size = 256M

back_log = 50
max_connections = 100
wait_timeout = 256
max_connect_errors = 10

table_open_cache = 2048
max_allowed_packet = 16M
binlog_cache_size = 512M
max_heap_table_size = 512M
performance_schema = ON

read_buffer_size = 64M
read_rnd_buffer_size = 64M
sort_buffer_size = 64M
join_buffer_size = 64M

thread_cache_size = 8
thread_stack = 240K

query_cache_type = 0
query_cache_size = 128M
query_cache_limit = 2M
ft_min_word_len = 4
default-storage-engine = InnoDB
transaction_isolation = REPEATABLE-READ
tmp_table_size = 512M

log-bin=mysql-bin
binlog_format=mixed
general_log_file = /var/log/mysql/mysql.log
general_log = 1
log_warnings = 1
log_error = /var/log/mysql/error.log
slow_query_log = 1
slow_query_log_file = /var/log/mysql/mysql-slow.log
long_query_time = 2
expire_logs_days = 7

character-set-server = utf8mb4
collation-server = utf8mb4_general_ci
server-id = 1

# INNODB options
innodb_buffer_pool_size = 1G
innodb_buffer_pool_instances = 8
innodb_data_file_path = ibdata1:10M:autoextend

innodb_write_io_threads = 8
innodb_read_io_threads = 8

innodb_thread_concurrency = 16
innodb_flush_log_at_trx_commit = 1

innodb_log_buffer_size = 1GB

innodb_log_file_size = 512M
innodb_log_files_in_group = 3
innodb_max_dirty_pages_pct = 90
innodb_lock_wait_timeout = 256

[mysqldump]
quick
max_allowed_packet = 50M

[mysql]
no-auto-rehash

[mysqlhotcopy]
interactive-timeout

[mysqld_safe]
open-files-limit = 8192
EOF

#----------------------------------------------------------------------------------------

if [ -e "/etc/mysql/debian.cnf" ]; then

echo -e "File /etc/mysql/debian.cnf exist...\n"
sudo echo "" > /etc/mysql/debian.cnf

sudo cat <<EOF > /etc/mysql/debian.cnf
[client]
host     = localhost
user     = root
password = "${STRONG_PASSWORD}"
socket   = /var/run/mysqld/mysqld.sock

[mysql_upgrade]
host     = localhost
user     = root
password = "${STRONG_PASSWORD}"
socket   = /var/run/mysqld/mysqld.sock
EOF

fi

#----------------------------------------------------------------------------------------

sudo sed -i 's/LimitNOFILE=/LimitNOFILE=524288/' /usr/lib/systemd/system/mariadb.service

#----------------------------------------------------------------------------------------

sudo systemctl daemon-reload
sudo systemctl restart mariadb.service
sudo systemctl enable mariadb.service
sudo systemctl status mariadb.service --no-pager
echo -e "\n"
sudo netstat -tunlp | grep mariadb
echo -e "\n"
sudo mariadb -V

echo -e "\n\nPassword for MariaDB root user: ${STRONG_PASSWORD}\n\nSAVE IT, PLEASE!\n\n"

#----------------------------------------------------------------------------------------

exit 0
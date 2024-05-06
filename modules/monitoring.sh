#!/usr/bin/env bash

set -o nounset
set -o pipefail

#----------------------------------------------------------------------------------------

# Colors.
ESC=$(printf '\033') RESET="${ESC}[0m" BLACK="${ESC}[30m" RED="${ESC}[31m"
GREEN="${ESC}[32m" YELLOW="${ESC}[33m" BLUE="${ESC}[34m" MAGENTA="${ESC}[35m"
CYAN="${ESC}[36m" WHITE="${ESC}[37m" DEFAULT="${ESC}[39m"

#----------------------------------------------------------------------------------------

if [[ "${TRACE-0}" == "1" ]]; then
    set -o xtrace
fi

#----------------------------------------------------------------------------------------

if [[ "${1-}" =~ ^-*h(elp)?$ ]]; then
    echo 'Usage: ./prometheus.sh
 
This is bash script to install and configure prometheus and exporters for prometheus.
'
    exit
fi

#----------------Checking that script is runing only from root or with sudo--------------

if [[ $EUID -ne 0 ]]; then
    echo -e "\nBite my shiny metal ass! \nYou don't have enough rights to run the script...\nThis script only works as root user or with sudo!\n" >&2
    exit 1
fi

#------------------------------------Functions-------------------------------------------

# Color Functions.
green_print() { printf "${GREEN}%s${RESET}\n" "$1"; }
blue_print() { printf "${BLUE}%s${RESET}\n" "$1"; }
red_print() { printf "${RED}%s${RESET}\n" "$1"; }
yellow_print() { printf "${YELLOW}%s${RESET}\n" "$1"; }
magenta_print() { printf "${MAGENTA}%s${RESET}\n" "$1"; }
cyan_print() { printf "${CYAN}%s${RESET}\n" "$1"; }

# Exit Functions.
return_input() { return; }
exit_input() { echo -e "\nBye bye.\n"; exit 0; }
fail_input() { echo -e "\nWrong option."; }

prometheus() {

sudo apt update && sudo apt upgrade -y && sudo apt autoremove --purge -y

sudo groupadd --system prometheus
sudo useradd -s /sbin/nologin --system -g prometheus prometheus
sudo mkdir /var/lib/prometheus
for i in rules rules.d files_sd; do sudo mkdir -p /etc/prometheus/${i}; done

sudo mkdir -p /tmp/prometheus && cd /tmp/prometheus
curl -s https://api.github.com/repos/prometheus/prometheus/releases/latest | grep browser_download_url | grep linux-amd64 | cut -d '"' -f 4 | sudo wget -qi -
sudo tar xvf prometheus*.tar.gz && cd prometheus*-amd64
sudo mv prometheus promtool /usr/local/bin/
sudo mv prometheus.yml /etc/prometheus/prometheus.yml
sudo mv consoles/ console_libraries/ /etc/prometheus/

sudo cat <<\EOF > /etc/prometheus/prometheus.yml
global:
  scrape_interval:     15s
  evaluation_interval: 15s
 
  external_labels:
    monitor: 'prometheus-grafana'
 
scrape_configs:
  - job_name: 'prometheus'
    static_configs:
     - targets: ['localhost:9090']
EOF

sudo promtool check config /etc/prometheus/prometheus.yml

sudo cat <<\EOF > /etc/systemd/system/prometheus.service
[Unit]
Description=Prometheus Systemd Service
Wants=network-online.target
After=network-online.target
 
[Service]
User=prometheus
Group=prometheus
Type=simple
Restart=always
SyslogIdentifier=prometheus
ExecStart=/usr/local/bin/prometheus \
--config.file /etc/prometheus/prometheus.yml \
--storage.tsdb.path /var/lib/prometheus/ \
--web.console.templates=/etc/prometheus/consoles \
--web.console.libraries=/etc/prometheus/console_libraries \
--web.listen-address="127.0.0.1:9090"
 
[Install]
WantedBy=multi-user.target
EOF

for i in rules rules.d files_sd; do sudo chown -R prometheus:prometheus /etc/prometheus/${i}; done
for i in rules rules.d files_sd; do sudo chmod -R 775 /etc/prometheus/${i}; done
sudo chown -R prometheus:prometheus /var/lib/prometheus/
sudo chown -R prometheus:prometheus /usr/local/bin/prometheus /usr/local/bin/promtool

sudo systemctl daemon-reload
sudo systemctl start prometheus
sudo systemctl enable prometheus
sudo systemctl status prometheus --no-pager -l

if [[ ! -x "$(command -v nginx)" ]]; then
    sudo mkdir -p /etc/nginx/conf.d/
fi

sudo touch /etc/nginx/conf.d/prometheus.conf
sudo cat <<\EOF > /etc/nginx/conf.d/prometheus.conf
server {
       listen 80;
       server_name prometheus.dns.com;
   
       return 301 https://$server_name$request_uri;
}
 
server {
        # Enable QUIC and HTTP/3.
        listen 443 quic reuseport;

        # Enable HTTP/2.
        listen 443 ssl;
        http2 on;
        server_name prometheus.dns.com;
 
        ssl_certificate /etc/nginx/ssl/server.crt;
        ssl_certificate_key /etc/nginx/ssl/server.key;
 
        include /etc/nginx/ssl.conf;
 
        access_log /var/log/nginx/prometheus-access.log;
        error_log /var/log/nginx/prometheus-error.log;
 
        location / {
                satisfy any;
                allow 127.0.0.1;
                allow IP/32;
                allow IP/32;
                deny all;
                proxy_pass http://127.0.0.1:9090;
                auth_basic "Prometheus Service";
                auth_basic_user_file "/etc/nginx/ssl/.prom_htpasswd";
                proxy_http_version 1.1;
                proxy_set_header Upgrade $http_upgrade;
                proxy_set_header Connection 'upgrade';
                proxy_set_header Host $host;
                proxy_cache_bypass $http_upgrade;
        }
}
EOF

sudo apt install apache2-utils -y

echo -e "\n"
green_print 'NOTE!'
echo -e "Change server_name in /etc/nginx/conf.d/prometheus.conf. And using the htpasswd utility create a new user whose credentials will be used to access the Prometheus. Let's call it swallow: htpasswd -c /etc/nginx/ssl/.prom_htpasswd swallow\n"

}


node_exporter() {

INTERNAL_IP=$(hostname -I | awk '{print $1}')

echo -e ""
read -p "Enter server_name (service-node-exporter.dns.com, for configure nginx and prometheus.yml): " DOMAIN

sudo apt update && sudo apt upgrade -y && sudo apt autoremove --purge -y

sudo groupadd --system node_exporter
sudo useradd -s /sbin/nologin --system -g node_exporter node_exporter

sudo mkdir -p /tmp/node_exporter && cd /tmp/node_exporter
curl -s https://api.github.com/repos/prometheus/node_exporter/releases/latest | grep browser_download_url | grep linux-amd64 | cut -d '"' -f 4 | sudo wget -qi -
sudo tar xvf node_exporter-*linux-amd64.tar.gz && cd node_exporter*-amd64/

sudo mv node_exporter /usr/local/bin/
sudo chown -R node_exporter:node_exporter /usr/local/bin/node_exporter

sudo cat <<\EOF > /etc/systemd/system/node_exporter.service
[Unit]
Description=Node Prometheus Exporter
After=network.target
 
[Service]
User=node_exporter
Group=node_exporter
Type=simple
Restart=always
SyslogIdentifier=node_exporter
ExecStart=/usr/local/bin/node_exporter --collector.systemd --web.listen-address="127.0.0.1:9100"
 
[Install]
WantedBy=multi-user.target
EOF

sudo chown node_exporter:node_exporter /etc/systemd/system/node_exporter.service
sudo systemctl daemon-reload
sudo systemctl start node_exporter
sudo systemctl enable node_exporter
sudo systemctl status node_exporter --no-pager -l

curl 127.0.0.1:9100/metrics

if [[ ! -x "$(command -v nginx)" ]]; then
    sudo mkdir -p /etc/nginx/conf.d/
fi

sudo touch /etc/nginx/conf.d/node_exporter.conf
cat <<\EOF > /etc/nginx/conf.d/node_exporter.conf
server {
       listen 80;
       server_name node-example.dns.com;
 
       return 301 https://$server_name$request_uri;
}
 
server {
        # Enable QUIC and HTTP/3.
        listen 443 quic reuseport;

        # Enable HTTP/2.
        listen 443 ssl;
        http2 on;
        server_name node-example.dns.com;
  
        ssl_certificate /etc/nginx/ssl/server.crt;
        ssl_certificate_key /etc/nginx/ssl/server.key;
  
        include /etc/nginx/ssl.conf;
  
        access_log /var/log/nginx/node-exporter-access.log;
        error_log /var/log/nginx/node-exporter-error.log;
  
        location / {
                satisfy any;
                allow 127.0.0.1;
                allow IP/32;
                allow IP/32;
                deny all;
                proxy_pass http://127.0.0.1:9100;
                auth_basic "Node Exporter Service";
                auth_basic_user_file "/etc/nginx/ssl/.node_htpasswd";
                proxy_http_version 1.1;
                proxy_set_header Upgrade $http_upgrade;
                proxy_set_header Connection 'upgrade';
                proxy_set_header Host $host;
                proxy_cache_bypass $http_upgrade;
        }
}
EOF

sudo sed -i "s/node-example.dns.com/${DOMAIN}/g" /etc/nginx/conf.d/node_exporter.conf;

sudo apt install apache2-utils -y

echo -e "\n"
green_print 'NOTE!'
echo -e "Using the htpasswd utility create a new user whose credentials will be used to access the Node Exporter. Let's call it swallow: htpasswd -c /etc/nginx/ssl/.node_htpasswd swallow\n"

green_print 'Add to /etc/hosts file on Grafana-Prometheus server next string:'
echo -e "${INTERNAL_IP} ${DOMAIN}\n"

green_print 'Configure prometheus service /etc/prometheus/prometheus.yml:'
echo -e "  - job_name: 'JOB_NAME_node'"
echo -e "    scrape_interval: 5s"
echo -e "    scheme: https"
echo -e "    static_configs:"
echo -e "      - targets: ['${DOMAIN}']"
echo -e "    basic_auth:"
echo -e "      username: swallow"
echo -e "      password: HTPASSWD"
echo -e ""

}

blackbox_exporter() {

sudo apt update && sudo apt upgrade -y && sudo apt autoremove --purge -y

sudo groupadd --system blackbox
sudo useradd -s /sbin/nologin --system -g blackbox blackbox

sudo mkdir -p /tmp/blackbox && cd /tmp/blackbox
curl -s https://api.github.com/repos/prometheus/blackbox_exporter/releases/latest | grep browser_download_url | grep linux-amd64 | cut -d '"' -f 4 | sudo wget -qi -
sudo tar xvzf blackbox_exporter-*.linux-amd64.tar.gz && cd blackbox_exporter*-amd64

sudo mv blackbox_exporter /usr/local/bin/
sudo chown -R blackbox:blackbox /usr/local/bin/blackbox_exporter
 
sudo mkdir -p /etc/blackbox
sudo cp blackbox.yml /etc/blackbox
sudo chown -R blackbox:blackbox /etc/blackbox/*

sudo cat <<\EOF > /etc/systemd/system/blackbox_exporter.service
[Unit]
Description=Blackbox Prometheus Exporter
Wants=network-online.target
After=network-online.target
 
[Service]
User=blackbox
Group=blackbox
Type=simple
Restart=always
SyslogIdentifier=blackbox_exporter
ExecStart=/usr/local/bin/blackbox_exporter \
--config.file=/etc/blackbox/blackbox.yml \
--web.listen-address="127.0.0.1:9115"
 
[Install]
WantedBy=multi-user.target
EOF

sudo chown blackbox:blackbox /etc/systemd/system/blackbox_exporter.service
sudo systemctl daemon-relaod
sudo systemctl start blackbox_exporter
sudo systemctl enable blackbox_exporter
sudo systemctl status blackbox_exporter --no-pager -l

curl 127.0.0.1:9115/metrics

echo -e "\n"
green_print 'NOTE!'
echo -e "\n"

green_print 'Add to /etc/blackbox/blackbox.yml file next:'
echo -e "modules:"
echo -e "  http_2xx:"
echo -e "    prober: http"
echo -e "    timeout: 10s"
echo -e "    http:"
echo -e "      valid_status_codes: [200,302,301,304] # Defaults to 2xx"
echo -e "      method: GET"
echo -e "      no_follow_redirects: false"
echo -e "      fail_if_ssl: false"
echo -e "      fail_if_not_ssl: true"
echo -e "      preferred_ip_protocol: "ip4" # defaults to "ip6""
echo -e "      tls_config:"
echo -e "        insecure_skip_verify: true"
echo -e ""
green_print 'Configure prometheus service /etc/prometheus/prometheus.yml:'
echo -e "global:"
echo -e "  scrape_interval:     15s"
echo -e "  evaluation_interval: 15s"
echo -e ""
echo -e "  external_labels:"
echo -e "    monitor: 'prometheus-grafana'"
echo -e ""
echo -e "scrape_configs:"
echo -e "  - job_name: 'prometheus'"
echo -e "    static_configs:"
echo -e "     - targets: ['localhost:9090', 'localhost:9115']"
echo -e ""
echo -e "- job_name: 'blackbox_JOB_NAME'"
echo -e "  metrics_path: /probe"
echo -e "  params:"
echo -e "    module: [http_2xx]"
echo -e "  static_configs:"
echo -e "    - targets:"
echo -e "       - https://HOSTNAME"
echo -e "  relabel_configs:"
echo -e "    - source_labels: [__address__]"
echo -e "      target_label: __param_target"
echo -e "    - source_labels: [__param_target]"
echo -e "      target_label: instance"
echo -e "    - target_label: __address__"
echo -e "      replacement: localhost:9115"
echo -e ""
}

nginx_exporter() {

INTERNAL_IP=$(hostname -I | awk '{print $1}')

echo -e ""
read -p "Enter server_name (service-nginx-exporter.dns.com, for configure nginx and prometheus.yml): " DOMAIN

sudo apt update && sudo apt upgrade -y && sudo apt autoremove --purge -y

sudo groupadd --system nginx_exporter
sudo useradd -s /sbin/nologin --system -g nginx_exporter nginx_exporter

sudo mkdir -p /tmp/nginx_exporter && cd /tmp/nginx_exporter
curl -s https://api.github.com/repos/nginxinc/nginx-prometheus-exporter/releases/latest | grep browser_download_url | grep linux_amd64 |  cut -d '"' -f 4 | sudo wget -qi -
sudo tar xvf nginx-prometheus-exporter_*linux_amd64.tar.gz && cd nginx-prometheus-exporter*-amd64/

sudo mv nginx-prometheus-exporter /usr/local/bin/
sudo chown -R nginx_exporter:nginx_exporter /usr/local/bin/nginx-prometheus-exporter

sudo cat <<\EOF > /etc/systemd/system/nginx_exporter.service
[Unit]
Description=NGINX Prometheus Exporter
After=network.target
 
[Service]
User=nginx_exporter
Group=nginx_exporter
Type=simple
Restart=always
SyslogIdentifier=nginx_exporter
ExecStart=/usr/local/bin/nginx-prometheus-exporter \
-web.listen-address=127.0.0.1:9113 \
-nginx.scrape-uri http://127.0.0.1:81/nginx_status
 
[Install]
WantedBy=multi-user.target
EOF

if [[ ! -x "$(command -v nginx)" ]]; then
    sudo mkdir -p /etc/nginx/conf.d/
fi

sudo touch /etc/nginx/conf.d/nginx_status.conf
cat <<\EOF > /etc/nginx/conf.d/nginx_status.conf
server {
    listen 127.0.0.1:81;
    location /nginx_status
    {
        stub_status on;
        access_log off;
        allow 127.0.0.1;
        deny all;
    }
}
EOF

sudo chown nginx_exporter:nginx_exporter /etc/systemd/system/nginx_exporter.service

sudo systemctl daemon-relaod
sudo systemctl start nginx_exporter
sudo systemctl enable nginx_exporter
sudo systemctl status nginx_exporter --no-pager -l

if [[ -x "$(command -v nginx)" ]]; then
    sudo systemctl restart nginx
    curl 127.0.0.1:9113/metrics
fi

sudo touch /etc/nginx/conf.d/nginx_exporter.conf
cat <<\EOF > /etc/nginx/conf.d/nginx_exporter.conf
server {
       listen 80;
       server_name nginx-example.dns.com;
   
       return 301 https://$server_name$request_uri;
}
 
server {
        # Enable QUIC and HTTP/3.
        listen 443 quic reuseport;

        # Enable HTTP/2.
        listen 443 ssl;
        http2 on;
        server_name nginx-example.dns.com;
 
        ssl_certificate /etc/nginx/ssl/server.crt;
        ssl_certificate_key /etc/nginx/ssl/server.key;
 
        include /etc/nginx/ssl.conf;
 
        access_log /var/log/nginx/nginx-exporter-access.log;
        error_log /var/log/nginx/nginx-exporter-error.log;
 
        location / {
                satisfy any;
                allow 127.0.0.1;
                allow IP/32;
                allow IP/32;
                deny all;
                proxy_pass http://127.0.0.1:9113;
                auth_basic "NGINX Exporter Service";
                auth_basic_user_file "/etc/nginx/ssl/.nginx_htpasswd";
                proxy_http_version 1.1;
                proxy_set_header Upgrade $http_upgrade;
                proxy_set_header Connection 'upgrade';
                proxy_set_header Host $host;
                proxy_cache_bypass $http_upgrade;
        }
}
EOF

sudo sed -i "s/nginx-example.dns.com/${DOMAIN}/g" /etc/nginx/conf.d/nginx_exporter.conf;

sudo apt install apache2-utils -y

echo -e "\n"
green_print 'NOTE!'
echo -e "Using the htpasswd utility create a new user whose credentials will be used to access the Nginx Exporter. Let's call it swallow: htpasswd -c /etc/nginx/ssl/.nginx_htpasswd swallow\n"

green_print 'Add to /etc/hosts file on Grafana-Prometheus server next string:'
echo -e "${INTERNAL_IP} ${DOMAIN}\n"

green_print 'Configure prometheus service /etc/prometheus/prometheus.yml:'
echo -e "  - job_name: 'JOB_NAME_nginx'"
echo -e "    scrape_interval: 5s"
echo -e "    scheme: https"
echo -e "    static_configs:"
echo -e "      - targets: ['${DOMAIN}']"
echo -e "    basic_auth:"
echo -e "      username: swallow"
echo -e "      password: HTPASSWD"
echo -e ""

}

mysqld_exporter() {

INTERNAL_IP=$(hostname -I | awk '{print $1}')

echo -e ""
read -p "Enter server_name (service-mysqld-exporter.dns.com, for configure nginx and prometheus.yml): " DOMAIN

sudo apt update && sudo apt upgrade -y && sudo apt autoremove --purge -y

sudo groupadd --system mysqld_exporter
sudo useradd -s /sbin/nologin --system -g mysqld_exporter mysqld_exporter

sudo mkdir mysqld-exporter && cd mysqld-exporter   
curl -s  https://api.github.com/repos/prometheus/mysqld_exporter/releases/latest | grep browser_download_url | grep linux-amd64 |  cut -d '"' -f 4 | sudo wget -qi -
sudo tar xvzf mysqld_exporter-* && cd mysqld_exporter*-amd64/

sudo mv mysqld_exporter /usr/local/bin/
sudo chmod +x /usr/local/bin/mysqld_exporter
sudo chown mysqld_exporter:mysqld_exporter /usr/local/bin/mysqld_exporter

sudo cat <<\EOF > /etc/systemd/system/mysqld_exporter.service
[Unit]
Description=MySQLD Prometheus Exporter
After=network.target

[Service]
User=mysqld_exporter
Group=mysqld_exporter
Type=simple
Restart=always
ExecStart=/usr/local/bin/mysqld_exporter \
--config.my-cnf /etc/.mysqld_exporter.cnf \
--collect.global_status \
--collect.info_schema.innodb_metrics \
--collect.auto_increment.columns \
--collect.info_schema.processlist \
--collect.binlog_size \
--collect.info_schema.tablestats \
--collect.global_variables \
--collect.info_schema.query_response_time \
--collect.info_schema.userstats \
--collect.info_schema.tables \
--collect.perf_schema.tablelocks \
--collect.perf_schema.file_events \
--collect.perf_schema.eventswaits \
--collect.perf_schema.indexiowaits \
--collect.perf_schema.tableiowaits \
--collect.slave_status \
--web.listen-address=127.0.0.1:9104
 
[Install]
WantedBy=multi-user.target
EOF

sudo chown mysqld_exporter:mysqld_exporter /etc/systemd/system/mysqld_exporter.service

sudo cat <<\EOF > /etc/.mysqld_exporter.cnf
[client]
user=mysqld_exporter
password=STRONG_PASSWORD
EOF

sudo chown root:mysqld_exporter /etc/.mysqld_exporter.cnf

sudo systemctl daemon-reload
sudo systemctl start mysqld_exporter
sudo systemctl enable mysqld_exporter
sudo systemctl status mysqld_exporter --no-pager -l

if [[ ! -x "$(command -v nginx)" ]]; then
    sudo mkdir -p /etc/nginx/conf.d/
fi

sudo touch /etc/nginx/conf.d/mysqld_exporter.conf
cat <<\EOF > /etc/nginx/conf.d/mysqld_exporter.conf
server {
       listen 80;
       server_name mysqld-example.dns.com;
 
       return 301 https://$server_name$request_uri;
}
 
server {
        # Enable QUIC and HTTP/3.
        listen 443 quic reuseport;

        # Enable HTTP/2.
        listen 443 ssl;
        http2 on;
        server_name mysqld-example.dns.com;
  
        ssl_certificate /etc/nginx/ssl/server.crt;
        ssl_certificate_key /etc/nginx/ssl/server.key;
  
        include /etc/nginx/ssl.conf;
  
        access_log /var/log/nginx/mysqld-exporter-access.log;
        error_log /var/log/nginx/mysqld-exporter-error.log;
  
        location / {
                satisfy any;
                allow 127.0.0.1;
                allow IP/32;
                allow IP/32;
                deny all;
                proxy_pass http://127.0.0.1:9104;
                auth_basic "MySQLD Exporter Service";
                auth_basic_user_file "/etc/nginx/ssl/.mysqld_htpasswd";
                proxy_http_version 1.1;
                proxy_set_header Upgrade $http_upgrade;
                proxy_set_header Connection 'upgrade';
                proxy_set_header Host $host;
                proxy_cache_bypass $http_upgrade;
        }
}
EOF

sudo sed -i "s/mysqld-example.dns.com/${DOMAIN}/g" /etc/nginx/conf.d/mysqld_exporter.conf;

sudo apt install apache2-utils -y

echo -e "\n"
green_print 'NOTE!'
echo -e "Using the htpasswd utility create a new user whose credentials will be used to access the MySQLD Exporter. Let's call it swallow: htpasswd -c /etc/nginx/ssl/.mysqld_htpasswd swallow\n"

green_print 'Add to /etc/hosts file on Grafana-Prometheus server next string:'
echo -e "${INTERNAL_IP} ${DOMAIN}\n"

green_print 'Create Prometeus Exporter database user to access the databases and write STRONG_PASSWORD to /etc/.mysqld_exporter.cnf:'
echo -e "CREATE USER 'mysqld_exporter'@'localhost' IDENTIFIED BY 'STRONG_PASSWORD' WITH MAX_USER_CONNECTIONS 2;"
echo -e "GRANT PROCESS, REPLICATION CLIENT, SELECT ON *.* TO 'mysqld_exporter'@'localhost';"
echo -e "FLUSH PRIVILEGES;"
echo -e "EXIT;"

echo -e "\n"
green_print 'Configure prometheus service /etc/prometheus/prometheus.yml:'
echo -e "  - job_name: 'JOB_NAME_mysqld'"
echo -e "    scrape_interval: 5s"
echo -e "    scheme: https"
echo -e "    static_configs:"
echo -e "      - targets: ['${DOMAIN}']"
echo -e "    basic_auth:"
echo -e "      username: swallow"
echo -e "      password: HTPASSWD"
echo -e ""

}

postgres_exporter() {

INTERNAL_IP=$(hostname -I | awk '{print $1}')

echo -e ""
read -p "Enter server_name (service-postgres-exporter.dns.com, for configure nginx and prometheus.yml): " DOMAIN

sudo apt update && sudo apt upgrade -y && sudo apt autoremove --purge -y

sudo groupadd --system postgres_exporter
sudo useradd -s /sbin/nologin --system -g postgres_exporter postgres_exporter

sudo mkdir /opt/postgres_exporter &&  cd /opt/postgres_exporter
curl -s https://api.github.com/repos/prometheus-community/postgres_exporter/releases/latest | grep browser_download_url | grep linux-amd64  | cut -d '"' -f 4 | sudo wget -qi -
sudo tar -xzvf postgres_exporter* && cd postgres_exporter*-amd64
sudo rm -r postgres_exporter*-amd64*

sudo mv postgres_exporter /usr/local/bin/
sudo chmod +x /usr/local/bin/postgres_exporter
sudo chown postgres_exporter:postgres_exporter /usr/local/bin/postgres_exporter

sudo mkdir -p /opt/postgres_exporter
cd /opt/postgres_exporter
sudo touch /opt/postgres_exporter/postgres_exporter.env
sudo cat <<\EOF > /opt/postgres_exporter/postgres_exporter.env
DATA_SOURCE_NAME="postgresql://postgres:STRONG_PASSWORD@localhost:5432/?sslmode=disable"
EOF

sudo chmod 700 /opt/postgres_exporter
sudo chmod 600 /opt/postgres_exporter/postgres_exporter.env

sudo cat <<\EOF > /etc/systemd/system/postgres_exporter.service
[Unit]
Description=PostgreSQL Prometheus Exporter
Wants=network-online.target
After=network-online.target

[Service]
User=postgres_exporter
Group=postgres_exporter
WorkingDirectory=/opt/postgres_exporter
EnvironmentFile=/opt/postgres_exporter/postgres_exporter.env
ExecStart=/usr/local/bin/postgres_exporter --disable-settings-metrics --web.listen-address=127.0.0.1:9187 --web.telemetry-path=/metrics
Restart=always
 
[Install]
WantedBy=multi-user.target
EOF

sudo chown postgres_exporter:postgres_exporter /opt/postgres_exporter/postgres_exporter.env
sudo chown postgres_exporter:postgres_exporter /etc/systemd/system/postgres_exporter.service
sudo systemctl daemon-reload
sudo systemctl start postgres_exporter
sudo systemctl enable postgres_exporter
sudo systemctl status postgres_exporter --no-pager -l

if [[ ! -x "$(command -v nginx)" ]]; then
    sudo mkdir -p /etc/nginx/conf.d/
fi

sudo touch /etc/nginx/conf.d/postgres_exporter.conf
cat <<\EOF >/etc/nginx/conf.d/postgres_exporter.conf
server {
       listen 80;
       server_name postgres-example.dns.com;
 
       return 301 https://$server_name$request_uri;
}
 
server {
        # Enable QUIC and HTTP/3.
        listen 443 quic reuseport;

        # Enable HTTP/2.
        listen 443 ssl;
        http2 on;
        server_name postgres-example.dns.com;
 
        ssl_certificate /etc/nginx/ssl/server.crt;
        ssl_certificate_key /etc/nginx/ssl/server.key;
 
        include /etc/nginx/ssl.conf;
 
        access_log /var/log/nginx/postgres-exporter-access.log;
        error_log /var/log/nginx/postgres-exporter-error.log;
 
        location / {
                satisfy any;
                allow 127.0.0.1;
                allow IP/32;
                allow IP/32;
                deny all;
                proxy_pass http://127.0.0.1:9187;
                auth_basic "PostgreSQL Exporter Service";
                auth_basic_user_file "/etc/nginx/ssl/.postgres_htpasswd";
                proxy_http_version 1.1;
                proxy_set_header Upgrade $http_upgrade;
                proxy_set_header Connection 'upgrade';
                proxy_set_header Host $host;
                proxy_cache_bypass $http_upgrade;
        }
}
EOF

sudo sed -i "s/postgres-example.dns.com/${DOMAIN}/g" /etc/nginx/conf.d/postgres_exporter.conf;

sudo apt install apache2-utils -y

echo -e "\n"
green_print 'NOTE!'
echo -e "Change STRONG_PASSWORD in /opt/postgres_exporter/postgres_exporter.env. And using the htpasswd utility create a new user whose credentials will be used to access the PostgreSQL Exporter. Let's call it swallow: htpasswd -c /etc/nginx/ssl/.postgres_htpasswd swallow\n"

green_print 'Add to /etc/hosts file on Grafana-Prometheus server next string:'
echo -e "${INTERNAL_IP} ${DOMAIN}\n"

green_print 'Configure prometheus service /etc/prometheus/prometheus.yml:'
echo -e "  - job_name: 'JOB_NAME_postgres'"
echo -e "    scrape_interval: 5s"
echo -e "    scheme: https"
echo -e "    static_configs:"
echo -e "      - targets: ['${DOMAIN}']"
echo -e "    basic_auth:"
echo -e "      username: swallow"
echo -e "      password: HTPASSWD"
echo -e ""

}

nextcloud_exporter() {

INTERNAL_IP=$(hostname -I | awk '{print $1}')

echo -e ""
read -p "Enter server_name (service-nextcloud-exporter.dns.com, for configure nginx and prometheus.yml): " DOMAIN

sudo apt update && sudo apt upgrade -y && sudo apt autoremove --purge -y

sudo groupadd --system nextcloud_exporter
sudo useradd -s /sbin/nologin --system -g nextcloud_exporter nextcloud_exporter

sudo mkdir -p /tmp/nextcloud_exporter && cd /tmp/nextcloud_exporter
curl -s https://api.github.com/repos/xperimental/nextcloud-exporter/releases/latest | grep browser_download_url | grep .deb |  cut -d '"' -f 4 | sudo wget -qi -
sudo dpkg -i nextcloud-exporter*.deb

sudo mv /usr/bin/nextcloud-exporter /usr/local/bin/
sudo chown -R nextcloud_exporter:nextcloud_exporter /usr/local/bin/nextcloud-exporter
sudo mv /usr/local/bin/nextcloud-exporter /usr/local/bin/nextcloud_exporter

sudo cat <<\EOF > /etc/systemd/system/nextcloud_exporter.service
[Unit]
Description=Nextcloud Prometheus Exporter
After=network.target
  
[Service]
User=nextcloud_exporter
Group=nextcloud_exporter
Type=simple
Restart=always
SyslogIdentifier=nextcloud_exporter
ExecStart=/usr/local/bin/nextcloud_exporter --config-file /opt/.nc_exporter.yaml
  
[Install]
WantedBy=multi-user.target
EOF

sudo chown nextcloud_exporter:nextcloud_exporter /etc/systemd/system/nextcloud_exporter.service

sudo cat <<\EOF > /opt/.nc_exporter.yaml
# required
server: "https://NEXTCLOUD.dns.com"
# required for token authentication
authToken: "TOKEN"
# optional
listenAddress: "127.0.0.1:9205"
timeout: "5s"
tlsSkipVerify: false
EOF

sudo chmod 660 /opt/.nc_exporter.yaml
sudo chown nextcloud_exporter:nextcloud_exporter /opt/.nc_exporter.yaml

sudo systemctl daemon-relaod
sudo systemctl start nextcloud_exporter
sudo systemctl enable nextcloud_exporter
sudo systemctl status nextcloud_exporter --no-pager -l

if [[ ! -x "$(command -v nginx)" ]]; then
    sudo mkdir -p /etc/nginx/conf.d/
fi

sudo touch /etc/nginx/conf.d/nextcloud_exporter.conf
cat <<\EOF > /etc/nginx/conf.d/nextcloud_exporter.conf
server {
       listen 80;
       server_name nextcloud-example.dns.com;
   
       return 301 https://$server_name$request_uri;
}
 
server {
        # Enable QUIC and HTTP/3.
        listen 443 quic reuseport;

        # Enable HTTP/2.
        listen 443 ssl;
        http2 on;
        server_name nextcloud-example.dns.com;
 
        ssl_certificate /etc/nginx/ssl/server.crt;
        ssl_certificate_key /etc/nginx/ssl/server.key;
 
        include /etc/nginx/ssl.conf;
 
        access_log /var/log/nginx/nextcloud-exporter-access.log;
        error_log /var/log/nginx/nextcloud-exporter-error.log;
 
        location / {
                satisfy any;
                allow 127.0.0.1;
                allow IP/32;
                allow IP/32;
                deny all;
                proxy_pass http://127.0.0.1:9205;
                auth_basic "Nextcloud Exporter Service";
                auth_basic_user_file "/etc/nginx/ssl/.nextcloud_htpasswd";
                proxy_http_version 1.1;
                proxy_set_header Upgrade $http_upgrade;
                proxy_set_header Connection 'upgrade';
                proxy_set_header Host $host;
                proxy_cache_bypass $http_upgrade;
        }
}
EOF

sudo sed -i "s/nextcloud-example.dns.com/${DOMAIN}/g" /etc/nginx/conf.d/nextcloud_exporter.conf;

sudo apt install apache2-utils -y

echo -e "\n"
green_print 'NOTE!'
echo -e "Using the htpasswd utility create a new user whose credentials will be used to access the Nextcloud Exporter. Let's call it swallow: htpasswd -c /etc/nginx/ssl/.nextcloud_htpasswd swallow\n"

green_print 'Add to /etc/hosts file on Grafana-Prometheus server next string:'
echo -e "${INTERNAL_IP} ${DOMAIN}\n"

green_print 'Configure Nextcloud Server and create a configuration file for nextcloud_exporter. It is necessary to install Monitoring application, create serverinfo token and install it in Nextcloud Server. And write TOKEN to /opt/.nc_exporter.yaml:'
echo -e "TOKEN=\$(openssl rand -hex 32)"
echo -e "cd /var/www/nextcloud"
echo -e "sudo -u www-data php occ config:app:set serverinfo token --value \"\$TOKEN\""
echo -e "\n"
green_print 'Configure prometheus service /etc/prometheus/prometheus.yml:'
echo -e "  - job_name: 'JOB_NAME_nextcloud'"
echo -e "    scrape_interval: 5s"
echo -e "    scheme: https"
echo -e "    static_configs:"
echo -e "      - targets: ['${DOMAIN}']"
echo -e "    basic_auth:"
echo -e "      username: swallow"
echo -e "      password: HTPASSWD"
echo -e ""

}

rabbitmq_exporter() {

INTERNAL_IP=$(hostname -I | awk '{print $1}')

echo -e ""
read -p "Enter server_name (service-rabbitmq-exporter.dns.com, for configure nginx and prometheus.yml): " DOMAIN

sudo apt update && sudo apt upgrade -y && sudo apt autoremove --purge -y

if [[ -x "$(command -v rabbitmq-plugins)" ]]; then
    sudo rabbitmq-plugins enable rabbitmq_prometheus
    curl -v -H "Accept:text/plain" "http://localhost:15692/metrics"

    echo -e "\n"
    green_print 'NOTE!'
else
    echo -e "\n"
    green_print 'NOTE!'
    echo -e ""
    green_print 'rabbitmq-server is not installed. Install and run next command:'
    echo -e "sudo rabbitmq-plugins enable rabbitmq_prometheus\ncurl -v -H "Accept:text/plain" "http://localhost:15692/metrics"\n"
fi

green_print 'Nginx config for RabbitMQ Server and Exporter:'

sudo cat <<\EOF
server {
        listen      80;
        server_name example-rabbitmq.dns.com;
 
        return 301 https://$host$request_uri;
}
 
server {
        # Enable QUIC and HTTP/3.
        listen 443 quic reuseport;

        # Enable HTTP/2.
        listen 443 ssl;
        http2 on;
 
        server_name example-rabbitmq.dns.com;
 
        include /etc/nginx/ssl.conf;
 
        location / {
             proxy_pass http://127.0.0.1:15672;
             proxy_set_header Host $host;
             proxy_set_header X-Real-IP $remote_addr;
             proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
             proxy_set_header X-Forwarded-Proto "https";
        }
 
        location /metrics {
                satisfy any;
                allow 127.0.0.1;
                allow IP/32;
                allow IP/32;
                deny all;
                auth_basic "RabbitMQ Exporter Service";
                auth_basic_user_file "/etc/nginx/ssl/.rabbitmq_htpasswd";
                proxy_pass http://127.0.0.1:15692/metrics;
                proxy_http_version 1.1;
                proxy_set_header Upgrade $http_upgrade;
                proxy_set_header Connection 'upgrade';
                proxy_set_header Host $host;
                proxy_cache_bypass $http_upgrade;
        }
 
        location ~ /\.ht {
                deny all;
        }
 
        location /robots.txt {
                return 200 "User-agent: *\nDisallow: /";
        }
}
EOF

echo -e "\nUsing the htpasswd utility create a new user whose credentials will be used to access the RabbitMQ Exporter. Let's call it swallow: htpasswd -c /etc/nginx/ssl/.rabbitmq_htpasswd swallow\n"

green_print 'Add to /etc/hosts file on Grafana-Prometheus server next string:'
echo -e "${INTERNAL_IP} ${DOMAIN}\n"

green_print 'Configure prometheus service /etc/prometheus/prometheus.yml:'
echo -e "  - job_name: 'JOB_NAME_rabbitmq'"
echo -e "    scrape_interval: 5s"
echo -e "    scheme: https"
echo -e "    static_configs:"
echo -e "      - targets: ['${DOMAIN}']"
echo -e "    basic_auth:"
echo -e "      username: swallow"
echo -e "      password: HTPASSWD"
echo -e ""

}

moodle_exporter() {

python_version=$(python3 --version)

if [[ $python_version < "3.6" ]]; then
    echo -e "\nPython version must be at least 3.6...\n"
    exit 1
else
    sudo apt install python3-pip -y
    sudo pip3 install mysql-connector-python
    sudo pip3 install prometheus_client
fi

INTERNAL_IP=$(hostname -I | awk '{print $1}')

echo -e ""
read -p "Enter server_name (service-moodle-exporter.dns.com, for configure nginx and prometheus.yml): " DOMAIN

sudo apt update && sudo apt upgrade -y && sudo apt autoremove --purge -y

sudo groupadd --system moodle_exporter
sudo useradd -s /sbin/nologin --system -g moodle_exporter moodle_exporter

sudo cat <<\EOF > /usr/local/bin/moodle-prometheus-exporter.py
from prometheus_client import start_http_server
from prometheus_client import Gauge
#from prometheus_client import Counter
#from prometheus_client import Histogram
#from prometheus_client import Info
import time
import mysql.connector

#timerange variables
intervall = 10 # sleep intervall - every 10 seconds a query is made by cursor

active_users = 0

#http server variables
server_port = 8899

database = "db_name"

# make sql connection
moodle_db = mysql.connector.connect(
  host = host,
  user = user,
  password = password,
  database = database

)

def get_metrics(moodle_db):

    #get and calc timestamps and generate query
    query_search_intervall = 300 # query intervall - 5min like in moodle
    timestamp_now=int(time.time())
    timestamp_start=(timestamp_now - query_search_intervall)

    DB_QUERY_ACTIVE_USER = "SELECT COUNT(*) FROM mdl_user WHERE deleted=0 AND lastaccess > {} AND lastaccess < {};".format(timestamp_start,timestamp_now)
    DB_QUERY_ONLINE_USER = "SELECT count(*) FROM mdl_user where timestampdiff(MINUTE, from_unixtime(lastaccess), now()) < 5;"
    DB_QUERY_ALL_USERS = "SELECT COUNT(*) FROM mdl_user WHERE deleted=0;"
    DB_QUERY_SIZE = "SELECT table_schema, SUM(data_length + index_length) / 1024 / 1024 AS 'DB Size in MB' FROM information_schema.tables WHERE table_schema = '{}' GROUP BY table_schema;".format(database)

    #create cursor
    moodle_cursor = moodle_db.cursor()

    #should be a function...
    def get_active_users(moodle_cursor):
        moodle_cursor.execute(DB_QUERY_ACTIVE_USER)
        active_users = moodle_cursor.fetchone()  #returns array
        active_users = active_users[0]
        moodle_db.commit() #needed to commit the query and get new result on next query, otherwise result is always equal like first result
        return active_users

    def get_online_users(moodle_cursor):
        moodle_cursor.execute(DB_QUERY_ONLINE_USER)
        online_users = moodle_cursor.fetchone()  #returns array
        online_users = online_users[0]
        moodle_db.commit() #needed to commit the query and get new result on next query, otherwise result is always equal like first result
        return online_users

    def get_all_users(moodle_cursor):
        moodle_cursor.execute(DB_QUERY_ALL_USERS)
        all_users = moodle_cursor.fetchone()  #returns array
        all_users = all_users[0]
        moodle_db.commit() #needed to commit the query and get new result on next query, otherwise result is always equal like first result
        return all_users

    def get_db_size(moodle_cursor):
        moodle_cursor.execute(DB_QUERY_SIZE)
        db_size = moodle_cursor.fetchone()  #returns array
        db_size = db_size[1]
        moodle_db.commit() #needed to commit the query and get new result on next query, otherwise result is always equal like first result
        return db_size


    # run subfunctions
    active_users = get_active_users(moodle_cursor)
    online_users = get_online_users(moodle_cursor)
    all_users = get_all_users(moodle_cursor)
    db_size = get_db_size(moodle_cursor)
    moodle_cursor.close() # really needed to close it every loop step ?

    # print("Active Users: {}, Online Users: {}, All Users: {}, DB Size: {}".format(active_users,online_users,all_users,db_size))
    return active_users,online_users,all_users,db_size


# RUN
start_http_server(server_port,addr='127.0.0.1')
gauge_active = Gauge('python_moodle_active_user_counter', 'This counter counts active users of last 5 minutes from moodle database')
gauge_online = Gauge('python_moodle_online_user_counter', 'This counter counts online users of last 5 minutes from moodle database')
gauge_all = Gauge('python_moodle_all_user_counter', 'This counter counts all users from moodle database')
gauge_db_size = Gauge('python_moodle_db_size_counter', 'This counter returns the size from moodle database')

try:
    while True:

        metrics = get_metrics(moodle_db)

        gauge_active.set(metrics[0])
        gauge_online.set(metrics[1])
        gauge_all.set(metrics[2])
        gauge_db_size.set(metrics[3])

        time.sleep(intervall)

except KeyboardInterrupt:
    moodle_cursor.close()
    moodle_db.close()
    print("Exiting...")
    exit(0)
EOF

sudo chown -R moodle_exporter:moodle_exporter /usr/local/bin/moodle-prometheus-exporter.py
sudo chmod 700 /usr/local/bin/moodle-prometheus-exporter.py

sudo cat <<\EOF > /etc/systemd/system/moodle_exporter.service
[Unit]
Description=Moodle Prometheus Exporter
After=network.target
  
[Service]
User=moodle_exporter
Group=moodle_exporter
Type=simple
Restart=always
SyslogIdentifier=moodle_exporter
ExecStart=/usr/bin/python3 /usr/local/bin/moodle-prometheus-exporter.py
  
[Install]
WantedBy=multi-user.target
EOF

sudo chown moodle_exporter:moodle_exporter /etc/systemd/system/moodle_exporter.service
sudo systemctl daemon-reload
sudo systemctl start moodle_exporter
sudo systemctl enable moodle_exporter
sudo systemctl status moodle_exporter --no-pager -l

curl 127.0.0.1:8899/metrics

if [[ ! -x "$(command -v nginx)" ]]; then
    sudo mkdir -p /etc/nginx/conf.d/
fi

sudo touch /etc/nginx/conf.d/moodle_exporter.conf
cat <<\EOF > /etc/nginx/conf.d/moodle_exporter.conf
server {
       listen 80;
       server_name moodle-example.dns.com;
 
       return 301 https://$server_name$request_uri;
}
 
server {
        # Enable QUIC and HTTP/3.
        listen 443 quic reuseport;

        # Enable HTTP/2.
        listen 443 ssl;
        http2 on;
        server_name moodle-example.dns.com;
  
        ssl_certificate /etc/nginx/ssl/server.crt;
        ssl_certificate_key /etc/nginx/ssl/server.key;
  
        include /etc/nginx/ssl.conf;
  
        access_log /var/log/nginx/moodle-exporter-access.log;
        error_log /var/log/nginx/moodle-exporter-error.log;
  
        location / {
                satisfy any;
                allow 127.0.0.1;
                allow IP/32;
                allow IP/32;
                deny all;
                proxy_pass http://127.0.0.1:8899;
                auth_basic "Moodle Exporter Service";
                auth_basic_user_file "/etc/nginx/ssl/.moodle_htpasswd";
                proxy_http_version 1.1;
                proxy_set_header Upgrade $http_upgrade;
                proxy_set_header Connection 'upgrade';
                proxy_set_header Host $host;
                proxy_cache_bypass $http_upgrade;
        }
}
EOF

sudo sed -i "s/moodle-example.dns.com/${DOMAIN}/g" /etc/nginx/conf.d/moodle_exporter.conf;

sudo apt install apache2-utils -y

echo -e "\n"
green_print 'NOTE!'

echo -e "Using the htpasswd utility create a new user whose credentials will be used to access the Moodle Exporter. Let's call it swallow: htpasswd -c /etc/nginx/ssl/.moodle_htpasswd swallow\n"

green_print 'Change in /usr/local/bin/moodle-prometheus-exporter.py next variables:'
cat <<\EOF
database = "DB_NAME"
...
host = HOST,
user = USER,
password = PASSWORD,
...
EOF

echo -e ""
green_print 'Add to /etc/hosts file on Grafana-Prometheus server next string:'
echo -e "${INTERNAL_IP} ${DOMAIN}\n"

green_print 'Configure prometheus service /etc/prometheus/prometheus.yml:'
echo -e "  - job_name: 'JOB_NAME_moodle'"
echo -e "    scrape_interval: 5s"
echo -e "    scheme: https"
echo -e "    static_configs:"
echo -e "      - targets: ['${DOMAIN}']"
echo -e "    basic_auth:"
echo -e "      username: swallow"
echo -e "      password: HTPASSWD"
echo -e ""

}

grafana() {

sudo apt update && sudo apt upgrade -y && sudo apt autoremove --purge -y

wget -q -O - https://packages.grafana.com/gpg.key | sudo apt-key add -
sudo add-apt-repository "deb https://packages.grafana.com/oss/deb stable main"
sudo apt update
sudo apt install grafana

sudo systemctl start grafana-server
sudo systemctl enable grafana-server
sudo systemctl status grafana-server --no-pager -l

if [[ ! -x "$(command -v nginx)" ]]; then
    sudo mkdir -p /etc/nginx/conf.d/
fi

sudo touch /etc/nginx/conf.d/grafana.conf
cat <<\EOF > /etc/nginx/conf.d/grafana.conf
server {
       listen 80;
       server_name example.dns.com;
  
       return 301 https://$server_name$request_uri;
}
 
server {
        # Enable QUIC and HTTP/3.
        listen 443 quic reuseport;

        # Enable HTTP/2.
        listen 443 ssl;
        http2 on;
        server_name example.dns.com;
 
        ssl_certificate /etc/nginx/ssl/server.crt;
        ssl_certificate_key /etc/nginx/ssl/server.key;
 
        include /etc/nginx/ssl.conf;
 
        access_log /var/log/nginx/grafana-access.log;
        error_log /var/log/nginx/grafana-error.log;
 
        location / {
                proxy_pass http://127.0.0.1:3000;
                proxy_http_version 1.1;
                proxy_set_header Upgrade $http_upgrade;
                proxy_set_header Connection 'upgrade';
                proxy_set_header Host $host;
                proxy_cache_bypass $http_upgrade;
        }
}
EOF

sudo sed -i "s/;type = sqlite3/type = postgres/g" /etc/grafana/grafana.ini
sudo sed -i "s/;host = 127.0.0.1:3306/host = 127.0.0.1:5432/g" /etc/grafana/grafana.ini
sudo sed -i "s/;name = grafana/name = grafana_db/g" /etc/grafana/grafana.ini
sudo sed -i "s/;user = root/user = grafana/g" /etc/grafana/grafana.ini

sudo sed -i "s/;http_addr =/http_addr = 127.0.0.1/g" /etc/grafana/grafana.ini
sudo sed -i "s/;domain = localhost/domain = example.dns.com/g" /etc/grafana/grafana.ini

sudo sed -i "s/;allow_sign_up = true/allow_sign_up = false/g" /etc/grafana/grafana.ini

echo -e "\n"
green_print 'NOTE!'

echo -e ""
green_print 'Configure PostgreSQL Server:'
sudo cat <<\EOF
...
/etc/postgresql/14/main/pg_hba.conf
# TYPE  DATABASE        USER            ADDRESS                 METHOD
local   all             grafana                                 md5
...
/etc/postgresql/14/main/pg_hba.conf
local   all             postgres                                peer # change this to md5
 
## to
 
local   all             postgres                                md5 # like this
...
su - postgres
createuser grafana
psql
ALTER USER grafana WITH ENCRYPTED password 'YOUR_DB_PASSWORD';
CREATE DATABASE grafana_db WITH ENCODING='UTF8' OWNER=grafana;
\q
exit
sudo systemctl restart postgresql.service
EOF

echo -e ""
green_print 'Change next lines in /etc/grafana/grafana.ini:'
sudo cat <<\EOF
...
[database]
# If the password contains # or ; you have to wrap it with triple quotes. Ex """#password;"""
password = YOUR_DB_PASSWORD
...
[server]
# The full public facing url you use in browser, used for redirects and emails
# If you use reverse proxy and sub path specify full url (with sub path)
root_url = https://%(domain)s/
...
[auth.anonymous]
# enable anonymous access
enabled = false
...
[unified_alerting]
#Enable the Unified Alerting sub-system and interface. When enabled we'll migrate all of your alert rules and notification channels to the new system. New alert rules will>
enabled = false
...
EOF
}

# Menu Function.
menu() {

echo -ne "
$(yellow_print 'Monitoring Menu')
$(cyan_print '1)') prometheus
$(green_print '2)') node_exporter
$(blue_print '3)') blackbox_exporter
$(magenta_print '4)') nginx_exporter
$(cyan_print '5)') mysqld_exporter
$(green_print '6)') postgres_exporter
$(blue_print '7)') nextcloud_exporter
$(magenta_print '8)') rabbitmq_exporter
$(cyan_print '9)') moodle_exporter
$(green_print '10)') grafana
$(blue_print '0)') Back
$(red_print 'exit)') Exit
\nChoose an option: "
    read -r ans
    case $ans in
    1)
        if [[ -x "$(command -v /usr/local/bin/prometheus)" ]]; then
            echo -e '\nprometheus is already installed.'
            return
        fi
        prometheus
        menu
        ;;
    2)
        if [[ -x "$(command -v /usr/local/bin/node_exporter)" ]]; then
            echo -e '\nnode_exporter is already installed.'
            return
        fi
        node_exporter
        menu
        ;;
    3)
        if [[ -x "$(command -v /usr/local/bin/blackbox_exporter)" ]]; then
            echo -e '\nblackbox_exporter is already installed.'
            return
        fi
        blackbox_exporter
        menu
        ;;
    4)
        if [[ -x "$(command -v /usr/local/bin/nginx_exporter)" ]]; then
            echo -e '\nnginx_exporter is already installed.'
            return
        fi
        nginx_exporter
        menu
        ;;
    5)
        if [[ -x "$(command -v /usr/local/bin/mysqld_exporter)" ]]; then
            echo -e '\nmysqld_exporter is already installed.'
            return
        fi
        mysqld_exporter
        menu
        ;;
    6)
        if [[ -x "$(command -v /usr/local/bin/postgres_exporter)" ]]; then
            echo -e '\npostgres_exporter is already installed.'
            return
        fi
        postgres_exporter
        menu
        ;;
    7)
        if [[ -x "$(command -v /usr/local/bin/nextcloud_exporter)" ]]; then
            echo -e '\nnextcloud_exporter is already installed.'
            return
        fi
        nextcloud_exporter
        menu
        ;;
    8)
        rabbitmq_exporter
        menu
        ;;
    9)
        if [[ -x "$(command -v /usr/local/bin/moodle-prometheus-exporter.py)" ]]; then
            echo -e '\nnextcloud_exporter is already installed.'
            return
        fi
        moodle_exporter
        menu
        ;;
    10)
        if [[ -x "$(command -v /usr/sbin/grafana)" ]]; then
            echo -e '\ngrafana is already installed.'
            return
        fi
        grafana
        menu
        ;;
    0)
        return_input
        ;;
    exit)
        exit_input
        ;;
    *)
        fail_input
        menu
        ;;
    esac
}

# Main Function.
main() {
    menu
}

#----------------------------------------------------------------------------------------

main "$@"
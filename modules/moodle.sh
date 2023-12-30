#!/usr/bin/env bash

set -o nounset
set -o pipefail

MODULES="$PWD/modules"

#----------------------------------------------------------------------------------------

if [[ "${TRACE-0}" == "1" ]]; then
    set -o xtrace
fi

#----------------------------------------------------------------------------------------

if [[ "${1-}" =~ ^-*h(elp)?$ ]]; then
    echo 'Usage: ./moodle.sh
 
This is bash script to install and configure Moodle Server.
'
    exit
fi

#----------------------------------------------------------------------------------------
php74-install() { 
sudo bash ${MODULES}/php.sh << EOF
2
EOF
}

php80-install() { 
sudo bash ${MODULES}/php.sh << EOF
3
EOF
}

php81-install() { 
sudo bash ${MODULES}/php.sh << EOF
4
EOF
}

#----------------------------------------------------------------------------------------

sudo apt update && sudo apt upgrade -y && sudo apt autoremove --purge -y

echo -e "\nSelect Moodle version:\n"

MOODLE_VERSIONS=("Moodle 4.2.1+" "Moodle 4.1.4+" "Moodle 4.0.9+" "Moodle 3.11.15+" "Moodle 3.9.22+")

select opt in "${MOODLE_VERSIONS[@]}"
do
    case $opt in
        "Moodle 4.2.1+")
            echo -e "\nMoodle 4.2.1+ installing...\n"
            cd /tmp && wget https://download.moodle.org/download.php/direct/stable402/moodle-latest-402.tgz
            php81-install
            break
            ;;
        "Moodle 4.1.4+")
            echo -e "\nMoodle 4.1.4+ installing...\n"
            cd /tmp && wget https://download.moodle.org/download.php/direct/stable401/moodle-latest-401.tgz
            php81-install
            break
            ;;
        "Moodle 4.0.9+")
            echo -e "\nMoodle 4.0.9+ installing...\n"
            cd /tmp && wget https://download.moodle.org/download.php/direct/stable400/moodle-latest-400.tgz
            php80-install
            break
            ;;
        "Moodle 3.11.15+")
            echo -e "\nMoodle 3.11.15+ installing...\n"
            cd /tmp && wget https://download.moodle.org/download.php/direct/stable311/moodle-latest-311.tgz
            php80-install
            break
            ;;
        "Moodle 3.9.22+")
            echo -e "\nMoodle 3.9.22+ installing...\n"
            cd /tmp && wget https://download.moodle.org/download.php/direct/stable39/moodle-latest-39.tgz
            php74-install
            break
            ;;
        *)
            echo -e "\nWrong option! Select right Moodle version...\n"
            ;;
    esac
done

#----------------------------------------------------------------------------------------

cd /tmp && tar xvzf moodle-*
sudo rm /tmp/moodle-*.tgz

sudo mv /tmp/moodle /var/www/
sudo chown -R root:root /var/www/moodle
sudo chmod -R 0755 /var/www/moodle

sudo mkdir -p /var/moodledata
sudo chown -R www-data:www-data /var/moodledata
sudo chmod -R 0777 /var/moodledata

#----------------------------------------------------------------------------------------

if [ -e "/etc/nginx/conf.d/moodle.conf" ]; then
    echo -e "\nFile /etc/nginx/conf.d/moodle.conf exists...\n"
else
    echo -e "\nFile /etc/nginx/conf.d/moodle.conf does not exist. Creating...\n"
    sudo touch /etc/nginx/conf.d/moodle.conf
    sudo chmod 644 /etc/nginx/conf.d/moodle.conf
fi

sudo cat <<\EOF > /etc/nginx/conf.d/moodle.conf
server {
    listen 80;
    server_name moodle.dns.com;
 
    return 301 https://$server_name$request_uri;
}
 
server {
        listen 443 ssl http2;
 
        root /var/www/moodle;
        index index.php index.html index.htm;
        server_name moodle.dns.com;
 
        ssl_certificate /etc/nginx/ssl/server.crt;
        ssl_certificate_key /etc/nginx/ssl/server.key;
 
        include /etc/nginx/ssl.conf;
 
        location / {
            try_files $uri $uri/ =404;
        }
 
        location /dataroot/ {
            internal;
            alias /var/moodledata/;
        }
 
        location ~ [^/]\.php(/|$) {
            fastcgi_split_path_info ^(.+\.php)(/.+)$;
            fastcgi_index index.php;
            fastcgi_pass php-fpm;
            include fastcgi_params;
            fastcgi_param PATH_INFO $fastcgi_path_info;
            fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        }
 
        location ~ /\.ht {
            deny all;
        }
 
        location /robots.txt {
            return 200 "User-agent: *\nDisallow: /";
        }
}
EOF

sudo cat <<\EOF > /etc/nginx/ssl.conf
if ($block_ua) {
    return 403; #Block virus and scans by user agent
}
  
proxy_hide_header Strict-Transport-Security;
  
proxy_hide_header Strict-Transport-Security;
add_header Strict-Transport-Security "max-age=63072000; includeSubdomains; preload" always;
add_header X-Content-Type-Options nosniff always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "no-referrer" always;
add_header X-Download-Options "noopen" always;
add_header X-Permitted-Cross-Domain-Policies "none" always;
add_header X-Robots-Tag "none" always;
  
server_tokens off;
  
ssl_dhparam /etc/nginx/ssl/dhparam.pem; #openssl dhparam -out /etc/nginx/ssl/dhparam.pem 4096
ssl_session_timeout 10m;
ssl_session_tickets off;
ssl_session_cache shared:SSL:10m;
  
ssl_protocols TLSv1.2 TLSv1.3; #For TLSv1.3 requires nginx = 1.13.0+, else use TLSv1.2
ssl_prefer_server_ciphers on;
ssl_ciphers EECDH+AESGCM:EDH+AESGCM; #Valid ciphers find there https://cipherli.st
ssl_stapling on;
ssl_stapling_verify on;
ssl_ecdh_curve secp384r1;
EOF

#----------------------------------------------------------------------------------------

cat << EOF
Configuring MySQL Server for Moodle:

mysql> CREATE DATABASE moodle DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
mysql> CREATE USER 'mduser'@'localhost' IDENTIFIED BY 'PASSWORD_STRONG';
mysql> GRANT SELECT,INSERT,UPDATE,DELETE,CREATE,CREATE TEMPORARY TABLES,DROP,INDEX,ALTER ON moodle.* TO 'mduser'@'localhost';
mysql> FLUSH PRIVILEGES;
mysql> EXIT;
  
systemctl restart mysql.service && systemctl status mysql.service

Configuring Crontab for Moodle:

* * * * *    /usr/bin/php-version /var/www/moodle/admin/cli/cron.php >/dev/null
EOF

#----------------------------------------------------------------------------------------

exit 0
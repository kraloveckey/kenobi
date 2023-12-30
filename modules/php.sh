#!/usr/bin/env bash

set -o pipefail

PHP_VERSION=""

#----------------------------------------------------------------------------------------

if [[ "${TRACE-0}" == "1" ]]; then
    set -o xtrace
fi

#----------------------------------------------------------------------------------------

if [[ "${1-}" =~ ^-*h(elp)?$ ]]; then
    echo 'Usage: ./php.sh
 
This is bash script to install and configure different versions of php.
'
    exit
fi

#----------------------------------------------------------------------------------------
sudo apt update && sudo apt upgrade -y && sudo apt autoremove --purge -y
sudo apt install software-properties-common libmagickcore-6.q16-6-extra swaks -y
sudo add-apt-repository ppa:ondrej/php -y
sudo apt update

php_menu ()
{
  select item; do
    case $item in
        "7.3")
            PHP_VERSION="7.3"
            sudo apt install php7.3 php7.3-apcu php7.3-bcmath php7.3-bz2 php7.3-cli php7.3-common php7.3-curl php7.3-fpm php7.3-gd php7.3-gmp php7.3-dev \
            php7.3-imagick php7.3-intl php7.3-imap php7.3-ldap php7.3-mbstring php7.3-mcrypt php7.3-mysql php7.3-redis php7.3-soap php7.3-xml php7.3-xmlrpc php7.3-zip -y
            break;;
        "7.4")
            PHP_VERSION="7.4"
            sudo apt install php7.4 php7.4-apcu php7.4-bcmath php7.4-bz2 php7.4-cli php7.4-common php7.4-curl php7.4-fpm php7.4-gd php7.4-gmp php7.4-dev \
            php7.4-imagick php7.4-intl php7.4-imap php7.4-ldap php7.4-mbstring php7.4-mcrypt php7.4-mysql php7.4-redis php7.4-soap php7.4-xml php7.4-xmlrpc php7.4-zip -y
            break;;
        "8.0")
            PHP_VERSION="8.0"
            sudo apt install php8.0 php8.0-apcu php8.0-bcmath php8.1-bz2 php8.0-cli php8.0-common php8.0-curl php8.0-fpm php8.0-gd php8.0-gmp php8.0-dev \
            php8.0-imagick php8.0-intl php8.0-imap php8.0-ldap php8.0-mbstring php8.0-mcrypt php8.0-mysql php8.0-redis php8.0-soap php8.0-xml php8.0-xmlrpc php8.0-zip -y
            break;;
        "8.1")
            PHP_VERSION="8.1"
            sudo apt install php8.1 php8.1-apcu php8.1-bcmath php8.1-bz2 php8.1-cli php8.1-common php8.1-curl php8.1-fpm php8.1-gd php8.1-gmp php8.1-dev \
            php8.1-imagick php8.1-intl php8.1-imap php8.1-ldap php8.1-mbstring php8.1-mcrypt php8.1-mysql php8.1-redis php8.1-soap php8.1-xml php8.1-xmlrpc php8.1-zip -y
            break;;
        "8.2")
            PHP_VERSION="8.2"
            sudo apt install php8.2 php8.2-apcu php8.2-bcmath php8.2-bz2 php8.2-cli php8.2-common php8.2-curl php8.2-fpm php8.2-gd php8.2-gmp php8.2-dev \
            php8.2-imagick php8.2-intl php8.2-imap php8.2-ldap php8.2-mbstring php8.2-mcrypt php8.2-mysql php8.2-redis php8.2-soap php8.2-xml php8.2-xmlrpc php8.2-zip -y
            break;;
        *)
            PHP_VERSION=""
            echo -e "\nWrong option! Select right PHP version another time...\n"
            exit 1
            ;;
    esac
  done
}

# Declare the array with php versions.
PHP_VERSIONS=('7.3' '7.4' '8.0' '8.1' '8.2')
echo -e "\nSelect PHP version:\n"
php_menu "${PHP_VERSIONS[@]}"

php -v
echo -e "\n"
php -m

#----------------------------------------------------------------------------------------

sudo sed -i "/pm.max_children =/d" /etc/php/${PHP_VERSION}/fpm/pool.d/www.conf
sudo sed -i "/pm.start_servers =/d" /etc/php/${PHP_VERSION}/fpm/pool.d/www.conf
sudo sed -i "/pm.min_spare_servers =/d" /etc/php/${PHP_VERSION}/fpm/pool.d/www.conf
sudo sed -i "/pm.max_spare_servers =/d" /etc/php/${PHP_VERSION}/fpm/pool.d/www.conf
sudo sed -i "/pm.process_idle_timeout =/d" /etc/php/${PHP_VERSION}/fpm/pool.d/www.conf
sudo sed -i "/pm.max_requests =/d" /etc/php/${PHP_VERSION}/fpm/pool.d/www.conf

sudo cat <<\EOF >> /etc/php/${PHP_VERSION}/fpm/pool.d/www.conf
; The number of child processes to be created when pm is set to 'static' and the
; maximum number of child processes when pm is set to 'dynamic' or 'ondemand'.
; This value sets the limit on the number of simultaneous requests that will be
; served. Equivalent to the ApacheMaxClients directive with mpm_prefork.
; Equivalent to the PHP_FCGI_CHILDREN environment variable in the original PHP
; CGI. The below defaults are based on a server without much resources. Don't
; forget to tweak pm.* to fit your needs.
; Note: Used when pm is set to 'static', 'dynamic' or 'ondemand'
; Note: This value is mandatory.
pm.max_children = 128

; The number of child processes created on startup.
; Note: Used only when pm is set to 'dynamic'
; Default Value: min_spare_servers + (max_spare_servers - min_spare_servers) / 2
pm.start_servers = 64

; The desired minimum number of idle server processes.
; Note: Used only when pm is set to 'dynamic'
; Note: Mandatory when pm is set to 'dynamic'
pm.min_spare_servers = 32

; The desired maximum number of idle server processes.
; Note: Used only when pm is set to 'dynamic'
; Note: Mandatory when pm is set to 'dynamic'
pm.max_spare_servers = 96

; The number of seconds after which an idle process will be killed.
; Note: Used only when pm is set to 'ondemand'
; Default Value: 10s
pm.process_idle_timeout = 10s;

; The number of requests each child process should execute before respawning.
; This can be useful to work around memory leaks in 3rd party libraries. For
; endless request processing specify '0'. Equivalent to PHP_FCGI_MAX_REQUESTS.
; Default Value: 0
pm.max_requests = 10000
EOF

#----------------------------------------------------------------------------------------

sudo sed -i "/max_execution_time =/d" /etc/php/${PHP_VERSION}/fpm/php.ini
sudo sed -i "/max_input_time =/d" /etc/php/${PHP_VERSION}/fpm/php.ini
sudo sed -i "/max_input_nesting_level =/d" /etc/php/${PHP_VERSION}/fpm/php.ini
sudo sed -i "/max_input_vars =/d" /etc/php/${PHP_VERSION}/fpm/php.ini
sudo sed -i "/memory_limit =/d" /etc/php/${PHP_VERSION}/fpm/php.ini

sudo cat <<\EOF >> /etc/php/${PHP_VERSION}/fpm/php.ini
;;;;;;;;;;;;;;;;;;;
; Resource Limits ;
;;;;;;;;;;;;;;;;;;;
 
; Maximum execution time of each script, in seconds
; http://php.net/max-execution-time
; Note: This directive is hardcoded to 0 for the CLI SAPI
max_execution_time = 60
 
; Maximum amount of time each script may spend parsing request data. It's a good
; idea to limit this time on productions servers in order to eliminate unexpectedly
; long running scripts.
; Note: This directive is hardcoded to -1 for the CLI SAPI
; Default Value: -1 (Unlimited)
; Development Value: 60 (60 seconds)
; Production Value: 60 (60 seconds)
; http://php.net/max-input-time
max_input_time = 120
 
; Maximum input variable nesting level
; http://php.net/max-input-nesting-level
;max_input_nesting_level = 64
 
; How many GET/POST/COOKIE input variables may be accepted
max_input_vars = 10000
 
; Maximum amount of memory a script may consume
; http://php.net/memory-limit
memory_limit = 1024M
EOF

#----------------------------------------------------------------------------------------

sudo sed -i "/max_execution_time =/d" /etc/php/${PHP_VERSION}/cli/php.ini
sudo sed -i "/max_input_time =/d" /etc/php/${PHP_VERSION}/cli/php.ini
sudo sed -i "/max_input_nesting_level =/d" /etc/php/${PHP_VERSION}/cli/php.ini
sudo sed -i "/max_input_vars =/d" /etc/php/${PHP_VERSION}/cli/php.ini
sudo sed -i "/memory_limit =/d" /etc/php/${PHP_VERSION}/cli/php.ini

sudo cat <<\EOF >> /etc/php/${PHP_VERSION}/cli/php.ini
;;;;;;;;;;;;;;;;;;;
; Resource Limits ;
;;;;;;;;;;;;;;;;;;;
 
; Maximum execution time of each script, in seconds
; http://php.net/max-execution-time
; Note: This directive is hardcoded to 0 for the CLI SAPI
max_execution_time = 60
 
; Maximum amount of time each script may spend parsing request data. It's a good
; idea to limit this time on productions servers in order to eliminate unexpectedly
; long running scripts.
; Note: This directive is hardcoded to -1 for the CLI SAPI
; Default Value: -1 (Unlimited)
; Development Value: 60 (60 seconds)
; Production Value: 60 (60 seconds)
; http://php.net/max-input-time
max_input_time = 120
 
; Maximum input variable nesting level
; http://php.net/max-input-nesting-level
;max_input_nesting_level = 64
 
; How many GET/POST/COOKIE input variables may be accepted
max_input_vars = 10000
 
; Maximum amount of memory a script may consume
; http://php.net/memory-limit
memory_limit = -1
EOF

#----------------------------------------------------------------------------------------

sudo cat <<\EOF > /etc/php/${PHP_VERSION}/mods-available/pdo_mysql.ini
; configuration for php mysql module
; priority=20
extension=pdo_mysql.so
[mysql]
mysql.allow_local_infile=On
mysql.allow_persistent=On
mysql.cache_size=2000
mysql.max_persistent=-1
mysql.max_links=-1
mysql.default_port=
mysql.default_socket=/var/lib/mysql/mysql.sock  # Debian squeeze: /var/run/mysqld/mysqld.sock
mysql.default_host=
mysql.default_user=
mysql.default_password=
mysql.connect_timeout=60
mysql.trace_mode=Off
EOF

#----------------------------------------------------------------------------------------

if [ -d "/opt/audit" ] 
then
    echo -e "\nDirectory /opt/audit exists..."
    sudo touch sudo touch /opt/audit/warn-php${PHP_VERSION}.sh
else
    sudo mkdir -p /opt/audit && sudo touch /opt/audit/warn-php${PHP_VERSION}.sh
fi

sudo cat <<EOF > /opt/audit/warn-php${PHP_VERSION}.sh
#!/usr/bin/env bash

set -o nounset
set -o pipefail

MAIL_FROM="SERVICE@gmail.com"
MAIL_TO="SERVICE_MONITORING@gmail.com"
MAIL_SMTP="smtp.gmail.com"
MAIL_SMTP_PORT="465"
MAIL_AUTH="SERVICE_AUTH@gmail.com"
MAIL_PASS="SERVICE_AUTH_PASS"
MAIL_PASS="/opt/audit/php_warn.txt"

PHP_LOG="/var/log/php${PHP_VERSION}-fpm.log"

# build a regex pattern that matches any date in the given format from the last 10 minutes
pattern=$(date +'%d-%b-%Y %H:%M')

for i in {6..1}; do
    pattern+=\|$(date -d "$i minutes ago" +'%d-%b-%Y %H:%M')
done

# print all lines starting from the first one that matches one of the dates in the pattern
awk "/$pattern/,0" ${PHP_LOG} | grep "WARNING: \[pool www]" > ${MAIL_PASS}

if [ -s ${MAIL_PASS} ]; then
        # The file is not-empty.
        echo -e "PHP ALERT: php${PHP_VERSION}-fpm.service was restarted!\n\nPlease see ${PHP_LOG} :)" > ${MAIL_PASS}
        /usr/bin/systemctl restart php${PHP_VERSION}-fpm.service
        swaks -f ${MAIL_FROM} -t ${MAIL_TO} -s ${MAIL_SMTP} --auth-user=${MAIL_AUTH} --auth-password=${MAIL_PASS} -tlsc -p ${MAIL_SMTP_PORT} --body ${MAIL_PASS} --header "Subject: PHP Overloaded" --add-header "Content-Type: text/plain; charset=UTF-8" --h-From: '"PHP Alert" <'${MAIL_FROM}'>'
else
        echo "Empty :)"
fi

rm ${MAIL_PASS}

exit 0
EOF

echo -e "\n\nPLEASE, ADD TO CRONTAB NEXT LINE AFTER SCRIPT CONFIGURATION: /opt/audit/warn-php${PHP_VERSION}.sh\n\n*/5 * * * *     /bin/bash /opt/audit/warn-php${PHP_VERSION}.sh\n\n"

#----------------------------------------------------------------------------------------

if [ -d "/etc/nginx/conf.d" ]; then
echo -e "\nDirectory /etc/nginx/conf.d exists...\n"
sudo cat <<EOF > /etc/nginx/conf.d/php-fpm.conf
# PHP-FPM FastCGI server
# network or unix domain socket configuration
  
upstream php-fpm {
        server unix:/run/php/php${PHP_VERSION}-fpm.sock;
#        server 127.0.0.1:9000;
}
EOF
fi

#----------------------------------------------------------------------------------------

sudo systemctl enable php${PHP_VERSION}-fpm.service
sudo systemctl start php${PHP_VERSION}-fpm.service
sudo systemctl status php${PHP_VERSION}-fpm.service --no-pager

#----------------------------------------------------------------------------------------

exit 0
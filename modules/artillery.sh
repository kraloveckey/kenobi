#!/usr/bin/env bash

set -o nounset
set -o pipefail

#----------------------------------------------------------------------------------------

if [[ "${TRACE-0}" == "1" ]]; then
    set -o xtrace
fi

#----------------------------------------------------------------------------------------

if [[ "${1-}" =~ ^-*h(elp)?$ ]]; then
    echo 'Usage: ./artillery.sh
 
This is bash script to install and configure artillery honeypot.
'
    exit
fi

#----------------------------------------------------------------------------------------

sudo apt update && sudo apt upgrade -y && sudo apt autoremove --purge -y
sudo apt install python2.7 swaks -y
sudo ln -s /usr/bin/python2.7 /usr/bin/python

cd /opt/ && git clone https://github.com/BinaryDefense/artillery.git
cd /opt/artillery/
sudo ./setup.py

#----------------------------------------------------------------------------------------

sudo cat <<\EOF > /var/artillery/config
#############################################################################################
#
# This is the Artillery configuration file. Change these variables and flags to change how
# this behaves.
#
# Artillery written by: Dave Kennedy (ReL1K)
# Website: https://www.binarydefense.com
# Email: info [at] binarydefense.com
# Download: git clone https://github.com/binarydefense/artillery artillery/
# Install: python setup.py
#
#############################################################################################
#

# DETERMINE IF YOU WANT TO MONITOR OR NOT
MONITOR="ON"

# THESE ARE THE FOLDERS TO MONITOR, TO ADD MORE, JUST DO "/root","/var/", etc.
MONITOR_FOLDERS="/var/www,/etc/"

# BASED ON SECONDS, 2 = 2 seconds.
MONITOR_FREQUENCY="60"

# PERFORM CERTAIN SYSTEM HARDENING CHECKS
SYSTEM_HARDENING="ON"

# CHECK/WARN IF SSH IS RUNNING ON PORT 22
SSH_DEFAULT_PORT_CHECK="ON"

# EXCLUDE CERTAIN DIRECTORIES OR FILES. USE FOR EXAMPLE: /etc/passwd,/etc/hosts.allow
EXCLUDE=""

# DO YOU WANT TO AUTOMATICALLY BAN ON THE HONEYPOT
HONEYPOT_BAN="OFF"

# WHEN BANNING, DO YOU WANT TO BAN ENTIRE CLASS C AT ONCE INSTEAD OF INDIVIDUAL IP ADDRESS
HONEYPOT_BAN_CLASSC="OFF"

# PUT A PREFIX ON ALL BANNED IP ADDRESSES. HELPFUL FOR WHEN TRYING TO PARSE OR SHOW DETECTIONS THAT YOU ARE PIPING OFF TO OTHER SYSTEMS. WHEN SET, PREFIX IPTABLES LOG ENTRIES WITH THE PROVIDED TEXT
HONEYPOT_BAN_LOG_PREFIX=""

# WHITELIST IP ADDRESSES, SPECIFY BY COMMAS ON WHAT IP ADDRESSES YOU WANT TO WHITELIST
WHITELIST_IP="127.0.0.1,localhost"

# TCP PORTS TO SPAWN HONEYPOT FOR
TCPPORTS="137,25,143,465,993,995,22,3306,139,135,445,1433,3389,8080,21,5900,1553,110,1723,10000,5800,44443,20,5432,1521,16993,27017,6379,443,80"

# UDP PORTS TO SPAWN HONEYPOT FOR
UDPPORTS="139,5060,5061,3478"

# SHOULD THE HONEYPOT AUTOMATICALLY ADD ACCEPT RULES TO THE ARTILLERY CHAIN FOR ANY PORTS ITS LISTENING ON
HONEYPOT_AUTOACCEPT="ON"

# SHOULD EMAIL ALERTS BE SENT
EMAIL_ALERTS="OFF"

# CURRENT SUPPORT IS FOR SMTP. ENTER YOUR USERNAME AND PASSWORD HERE FOR STARTTLS AUTHENTICATION. LEAVE BLANK FOR OPEN RELAY
SMTP_USERNAME=""

# ENTER SMTP PASSWORD HERE
SMTP_PASSWORD=""

# THIS IS WHO TO SEND THE ALERTS TO - EMAILS WILL BE SENT FROM ARTILLERY TO THIS ADDRESS
ALERT_USER_EMAIL="enter_your_email_address_here@localhost"

# FOR SMTP ONLY HERE, THIS IS THE MAILTO
SMTP_FROM="Artillery_Incident@localhost"

# SMTP ADDRESS FOR SENDING EMAIL, DEFAULT IS GMAIL
SMTP_ADDRESS="smtp.gmail.com"

# SMTP PORT FOR SENDING EMAILS DEFAULT IS GMAIL WITH STARTTLS
SMTP_PORT="587"

# THIS WILL SEND EMAILS OUT DURING A CERTAIN FREQUENCY. IF THIS IS SET TO OFF, ALERTS WILL BE SENT IMMEDIATELY (CAN LEAD TO A LOT OF SPAM)
EMAIL_TIMER="ON"

# HOW OFTEN DO YOU WANT TO SEND EMAIL ALERTS (DEFAULT 10 MINUTES) - IN SECONDS
EMAIL_FREQUENCY="600"

# DO YOU WANT TO MONITOR SSH BRUTE FORCE ATTEMPTS
SSH_BRUTE_MONITOR="ON"

# HOW MANY ATTEMPTS BEFORE YOU BAN
SSH_BRUTE_ATTEMPTS="4"

# DO YOU WANT TO MONITOR FTP BRUTE FORCE ATTEMPTS
FTP_BRUTE_MONITOR="OFF"

# HOW MANY ATTEMPTS BEFORE YOU BAN
FTP_BRUTE_ATTEMPTS="4"

# DO YOU WANT TO DO AUTOMATIC UPDATES - ON OR OFF
AUTO_UPDATE="OFF"

# ANTI DOS WILL CONFIGURE MACHINE TO THROTTLE CONNECTIONS, TURN THIS OFF IF YOU DO NOT WANT TO USE
ANTI_DOS="OFF"

# THESE ARE THE PORTS THAT WILL PROVIDE ANTI_DOS PROTECTION
ANTI_DOS_PORTS="80,443"

# THIS WILL THROTTLE HOW MANY CONNECTIONS PER MINUTE ARE ALLOWED HOWEVER THE BUST WILL ENFORCE THIS
ANTI_DOS_THROTTLE_CONNECTIONS="50"

# THIS WILL ONLY ALLOW A CERTAIN BURST PER MINUTE THEN WILL ENFORCE AND NOT ALLOW ANYMORE TO CONNECT
ANTI_DOS_LIMIT_BURST="200"

# THIS IS THE PATH FOR THE APACHE ACCESS LOG
ACCESS_LOG="/var/log/apache2/access.log"

# THIS IS THE PATH FOR THE APACHE ERROR LOG
ERROR_LOG="/var/log/apache2/error.log"

# THIS ALLOWS YOU TO SPECIFY AN IP ADDRESS. LEAVE THIS BLANK TO BIND TO ALL INTERFACES.
BIND_INTERFACE=""

# TURN ON INTELLIGENCE FEED, CALL TO https://www.binarydefense.com/banlist.txt IN ORDER TO GET ALREADY KNOWN MALICIOUS IP ADDRESSES. WILL PULL EVERY 24 HOURS
THREAT_INTELLIGENCE_FEED="OFF"

# CONFIGURE THIS TO BE WHATEVER THREAT FEED YOU WANT BY DEFAULT IT WILL USE BINARY DEFENSE - NOTE YOU CAN SPECIFY MULTIPLE THREAT FEEDS BY DOING #http://urlthreatfeed1,http://urlthreadfeed2
THREAT_FEED="https://www.binarydefense.com/banlist.txt"

# A THREAT SERVER IS A SERVER THAT WILL COPY THE BANLIST.TXT TO A PUBLIC HTTP LOCATION TO BE PULLED BY OTHER ARTILLERY SERVER. THIS IS USED IF YOU DO NOT WANT TO USE THE STANDARD BINARY DEFENSE ONE.
THREAT_SERVER="OFF"

# PUBLIC LOCATION TO PULL VIA HTTP ON THE THREAT SERVER. NOTE THAT THREAT SERVER MUST BE SET TO ON
THREAT_LOCATION="/var/www/"

# FILE TO COPY TO THREAT_LOCATION, TO ACT AS A THREAT_SERVER. CHANGE TO "localbanlist.txt" IF YOU HAVE ENABLED "LOCAL_BANLIST" AND WISH TO HOST YOUR LOCAL BANLIST. IF YOU WISH TO COPY BOTH FILES, SEPARATE THE FILES WITH A COMMA - f.i. "banlist.txt,localbanlist.txt"
THREAT_FILE="banlist.txt"

# CREATE A SEPARATE LOCAL BANLIST FILE (USEFUL IF YOU'RE ALSO USING A THREAT FEED AND WANT TO HAVE A FILE THAT CONTAINS THE IPs THAT HAVE BEEN BANNED LOCALLY
LOCAL_BANLIST="OFF"

# THIS CHECKS TO SEE WHAT PERMISSIONS ARE RUNNING AS ROOT IN A WEB SERVER DIRECTORY
ROOT_CHECK="ON"

# Specify SYSLOG TYPE to be local, file or remote. LOCAL will pipe to syslog, REMOTE will pipe to remote SYSLOG, and file will send to alerts.log in local artillery directory
SYSLOG_TYPE="LOCAL"

# ALERT LOG MESSAGES (You can use the following variables: %time%, %ip%, %port%)
LOG_MESSAGE_ALERT="Artillery has detected an attack from %ip% for a connection on a honeypot port %port%"

# BAN LOG MESSAGES (You can use the following variables: %time%, %ip%, %port%)
LOG_MESSAGE_BAN="Artillery has blocked (and blacklisted) an attack from %ip% for a connection to a honeypot restricted port %port%"

# IF YOU SPECIFY SYSLOG TYPE TO REMOTE, SPECIFY A REMOTE SYSLOG SERVER TO SEND ALERTS TO
SYSLOG_REMOTE_HOST="192.168.0.1"

# IF YOU SPECIFY SYSLOG TYPE OF REMOTE, SEPCIFY A REMOTE SYSLOG PORT TO SEND ALERTS TO
SYSLOG_REMOTE_PORT="514"

# TURN ON CONSOLE LOGGING
CONSOLE_LOGGING="ON"

# RECYCLE LOGS AFTER A CERTAIN AMOUNT OF TIME - THIS WILL WIPE ALL IP ADDRESSES AND START FROM SCRATCH AFTER A CERTAIN INTERVAL
RECYCLE_IPS="OFF"

# RECYCLE INTERVAL AFTER A CERTAIN AMOUNT OF MINUTES IT WILL OVERWRITE THE LOG WITH A BLANK ONE AND ELIMINATE THE IPS - DEFAULT IS 7 DAYS
ARTILLERY_REFRESH="604800"

# PULL ADDITIONAL SOURCE FEEDS FOR BANNED IP LISTS FROM MULTIPLE OTHER SOURCES OTHER THAN ARTILLERY
SOURCE_FEEDS="OFF"

EOF

#----------------------------------------------------------------------------------------

cd /var/artillery/ && sudo touch tailA tailB tailC tailDiff alert.sh

sudo cat <<\EOF > /var/artillery/alert.sh
#!/usr/bin/env bash
 
cd /var/artillery/
cp tailB tailC
cp tailA tailB
cat /var/log/syslog | grep -a "Artillery" | grep -v "Artillery\[INFO\]" > tailA
/usr/sbin/logrotate -f /etc/logrotate.conf
diff tailA tailB > tailDiff

if [ -s tailDiff ]
then
        echo "Host: `hostname`" > alert.txt
        echo "Addr: `hostname -I`" >> alert.txt
        echo >> alert.txt
        echo "Time: `date`" >> alert.txt
        echo "Disk usage: `df -h | grep /dev/sda`" >> alert.txt
        echo >> alert.txt
        free -m >> alert.txt
        echo >> alert.txt
        echo >> alert.txt
        echo "Artillery Alert Log file extract:" >> alert.txt
        cat /var/artillery/tailDiff | grep -a Artillery >> alert.txt
        if [ -s "/var/artillery/tailDiff" ]
        then
                swaks -t "MAIL_TO@gmail.com" -f "MAIL_FROM@gmail.com" --ehlo artillery --header "Subject: Artillery Alert" --body "/var/artillery/alert.txt" -s smtp.gmail.com --auth-user=USERNAME --auth-password=PASSWORD -tlsc -p 465 > /dev/null
        else
                exit 0;
        fi
fi
EOF

sudo chmod 700 /var/artillery/alert.sh

#----------------------------------------------------------------------------------------

sudo timedatectl set-timezone Europe/Kyiv
sudo cat <<\EOF > /etc/logrotate.d/rsyslog
/var/log/syslog
{
        rotate 1
        size 3G
        hourly
        missingok
        notifempty
        compress
        delaycompress
        sharedscripts
        postrotate
                /usr/lib/rsyslog/rsyslog-rotate
        endscript
}
/var/log/mail.info
/var/log/mail.warn
/var/log/mail.err
/var/log/mail.log
/var/log/daemon.log
/var/log/kern.log
/var/log/auth.log
/var/log/user.log
/var/log/lpr.log
/var/log/cron.log
/var/log/debug
/var/log/messages
{
        rotate 5
        daily
        missingok
        notifempty
        compress
        delaycompress
        sharedscripts
        postrotate
                /usr/lib/rsyslog/rsyslog-rotate
        endscript
}
EOF

sudo mv /etc/cron.daily/logrotate /etc/cron.hourly/
sudo systemctl restart rsyslog.service

#----------------------------------------------------------------------------------------

sudo sed -i 's/GRUB_CMDLINE_LINUX=""/GRUB_CMDLINE_LINUX="net.ifnames=0"/' /etc/default/grub
sudo update-grub

sudo cat <<\EOF > /etc/netplan/00-installer-config.yaml
# This is the network config written by 'subiquity'
network:
  renderer: networkd
  ethernets:
    default:
      match:
        name: eth0
      dhcp4: true
      dhcp-identifier: mac
  ethernets:
    eth1:
      dhcp4: false
  version: 2

  vlans:
    eth1.10:
      id: 10
      link: eth1
      dhcp4: true
      dhcp-identifier: mac
EOF

sudo netplan apply

#----------------------------------------------------------------------------------------

sudo systemctl enable artillery.service
sudo systemctl start artillery.service
sudo systemctl restart artillery.service
sudo systemctl status artillery.service --no-pager

sudo ifconfig
sudo netstat -tunlp

echo -e "\n\nPLEASE, ADD TO CRONTAB NEXT LINE AFTER SCRIPT CONFIGURATION: /var/artillery/alert.sh\n\n*/2 * * * *     /var/artillery/alert.sh\n0 4 * * *       /usr/bin/systemctl restart artillery.service\n\n"

exit 0
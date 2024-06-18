#!/usr/bin/env bash

set -o nounset
set -o pipefail

#----------------------------------------------------------------------------------------

if [[ "${TRACE-0}" == "1" ]]; then
    set -o xtrace
fi

#----------------------------------------------------------------------------------------

if [[ "${1-}" =~ ^-*h(elp)?$ ]]; then
    echo 'Usage: ./fail2ban.sh
 
This is bash script to install and configure Fail2ban.
'
    exit
fi

#----------------------------------------------------------------------------------------

if [ -x "$(command -v fail2ban-server)" ]; then
    echo -e 'Fail2ban Server is already installed.\nPlease, purge old Fail2ban Server.\n'
    exit 1
fi

#----------------------------------------------------------------------------------------

sudo apt update && sudo apt upgrade -y && sudo apt autoremove --purge -y

sudo apt install ipset ipset-persistent fail2ban iptables iptables-persistent ssmtp mailutils swaks jq -y

sudo cp $(pwd)/fail2ban/* /etc/fail2ban/
sudo cp $(pwd)/ssmtp/* /etc/ssmtp/


sudo iptables -L -n -v

#----------------------------------------------------------------------------------------

exit 0
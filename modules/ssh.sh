#!/usr/bin/env bash

set -o nounset
set -o pipefail

#----------------------------------------------------------------------------------------

if [[ "${TRACE-0}" == "1" ]]; then
    set -o xtrace
fi

#----------------------------------------------------------------------------------------

if [[ "${1-}" =~ ^-*h(elp)?$ ]]; then
    echo 'Usage: ./ssh.sh
 
This is bash script to install and configure SSH-server.
'
    exit
fi

#----------------------------------------------------------------------------------------

sudo apt update && sudo apt upgrade -y && sudo apt autoremove --purge -y
sudo apt install ssh python3-pip -y

#----------------------------------------------------------------------------------------

echo -e "\nUpdating ssh config, adding ssh key..."
sudo chattr -i /etc/ssh/sshd_config
sudo echo "" > /etc/ssh/sshd_config

sudo cat <<\EOF > /etc/ssh/sshd_config
# Package generated configuration file
# See the sshd_config(5) manpage for details
  
# What ports, IPs and protocols we listen for
Port 221
  
# Use these options to restrict which interfaces/protocols sshd will bind to
ListenAddress 0.0.0.0
Protocol 2
  
MaxAuthTries 3
MaxSessions 5
  
# HostKeys for protocol version 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
  
HostKeyAlgorithms ssh-ed25519-cert-v01@openssh.com,ssh-rsa-cert-v01@openssh.com,ssh-ed25519,ecdsa-sha2-nistp521-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp521,ecdsa-sha2-nistp384
  
KexAlgorithms curve25519-sha256,diffie-hellman-group18-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
  
# Logging
SyslogFacility AUTH
LogLevel INFO
  
# Authentication:
LoginGraceTime 0
PermitRootLogin no
  
PubkeyAuthentication yes
  
# Don't read the user's ~/.rhosts and ~/.shosts files
IgnoreRhosts yes
# similar for protocol version 2
HostbasedAuthentication no
  
# To enable empty passwords, change to yes (NOT RECOMMENDED)
PermitEmptyPasswords no
  
# Change to yes to enable challenge-response passwords (beware issues with
# some PAM modules and threads)
ChallengeResponseAuthentication no
  
# Prevent the use of insecure home directory and key file permissions
StrictModes yes
  
X11Forwarding no
X11DisplayOffset 10
PrintMotd no
PrintLastLog yes
TCPKeepAlive yes
  
ChallengeResponseAuthentication no
KerberosAuthentication no
GSSAPIAuthentication no
  
# Allow client to pass locale environment variables
AcceptEnv LANG LC_*
  
Subsystem sftp /usr/lib/openssh/sftp-server -f AUTHPRIV -l INFO
  
# Set this to 'yes' to enable PAM authentication, account processing,
# and session processing. If this is enabled, PAM authentication will
# be allowed through the ChallengeResponseAuthentication and
# PasswordAuthentication. Depending on your PAM configuration,
# PAM authentication via ChallengeResponseAuthentication may bypass
# the setting of "PermitRootLogin without-password".
# If you just want the PAM account and session checks to run without
# PAM authentication, then enable this but set PasswordAuthentication
# and ChallengeResponseAuthentication to 'no'.
UsePAM yes
EOF

sudo chattr +i /etc/ssh/sshd_config
sudo rm /etc/ssh/ssh_host_*
sudo ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N ""
sudo ssh-keygen -t ecdsa -f /etc/ssh/ssh_host_ecdsa_key -N ""
sudo ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""
sudo awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe
sudo mv /etc/ssh/moduli.safe /etc/ssh/moduli
sudo echo -e "\n# Restrict key exchange, cipher, and MAC algorithms, as per sshaudit.com\n# hardening guide.\nKexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\nMACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\nHostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com" > /etc/ssh/sshd_config.d/ssh-audit_hardening.conf

sudo systemctl restart ssh.service
sudo systemctl enable ssh.service
echo -e "\n"
sudo systemctl status ssh.service --no-pager
echo -e "\n"

#----------------------------------------------------------------------------------------

sudo pip3 install ssh-audit
echo -e "\nSSH-AUDIT TEST...\n"
ssh-audit 127.0.0.1 -p221

exit 0
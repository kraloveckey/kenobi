#!/usr/bin/env bash

set -o nounset
set -o pipefail

#----------------------------------------------------------------------------------------

if [[ "${TRACE-0}" == "1" ]]; then
    set -o xtrace
fi

#----------------------------------------------------------------------------------------

if [[ "${1-}" =~ ^-*h(elp)?$ ]]; then
    echo 'Usage: ./limits.sh
 
This is bash script to configure limits and increase system perfomance.
'
    exit
fi

#----------------------------------------------------------------------------------------

sudo apt update && sudo apt upgrade -y && sudo apt autoremove --purge -y

#----------------------------------------------------------------------------------------

sudo cat <<\EOF > /etc/sysctl.conf
#
# /etc/sysctl.conf - Configuration file for setting system variables
# See /etc/sysctl.d/ for additional system variables.
# See sysctl.conf (5) for information.
#
 
 
#kernel.domainname = example.com
 
# Uncomment the following to stop low-level messages on console
#kernel.printk = 3 4 1 3
 
###################################################################
# Functions previously found in netbase
#
 
# Uncomment the next two lines to enable Spoof protection (reverse-path filter)
# Turn on Source Address Verification in all interfaces to
# prevent some spoofing attacks
#net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.all.rp_filter=0
 
# Uncomment the next line to enable TCP/IP SYN cookies
# See http://lwn.net/Articles/277146/
# Note: This may impact IPv6 TCP sessions too
#net.ipv4.tcp_syncookies=1
 
# Uncomment the next line to enable packet forwarding for IPv4
net.ipv4.ip_forward=1
 
# Uncomment the next line to enable packet forwarding for IPv6
#  Enabling this option disables Stateless Address Autoconfiguration
#  based on Router Advertisements for this host
#net.ipv6.conf.all.forwarding=1
net.ipv4.conf.default.forwarding=1
 
###################################################################
# Additional settings - these settings can improve the network
# security of the host and prevent against some network attacks
# including spoofing attacks and man in the middle attacks through
# redirection. Some network environments, however, require that these
# settings are disabled so review and enable them as needed.
#
# Do not accept ICMP redirects (prevent MITM attacks)
#net.ipv4.conf.all.accept_redirects = 0
#net.ipv6.conf.all.accept_redirects = 0
# _or_
# Accept ICMP redirects only for gateways listed in our default
# gateway list (enabled by default)
# net.ipv4.conf.all.secure_redirects = 1
#
# Do not send ICMP redirects (we are not a router)
#net.ipv4.conf.all.send_redirects = 0
#
# Do not accept IP source route packets (we are not a router)
#net.ipv4.conf.all.accept_source_route = 0
#net.ipv6.conf.all.accept_source_route = 0
#
# Log Martian Packets
#net.ipv4.conf.all.log_martians = 1
#
 
#
## Controls whether core dumps will append the PID to the core filename.
## Useful for debugging multi-threaded applications.
net.ipv4.ip_nonlocal_bind=1
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_synack_retries=5
 
#
## Controls the use of TCP syncookies
net.core.rmem_default=4194304
net.core.wmem_default=4194304
net.core.rmem_max=67108864
net.core.wmem_max=67108864
net.core.netdev_max_backlog=250000
net.core.somaxconn=8192
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_rfc1337=1
net.ipv4.tcp_window_scaling=1
 
# Uncomment the next line to enable packet forwarding for IPv6
#  Enabling this option disables Stateless Address Autoconfiguration
#  based on Router Advertisements for this host
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
 
###################################################################
# Magic system request Key
# 0=disable, 1=enable all, >1 bitmask of sysrq functions
# See https://www.kernel.org/doc/html/latest/admin-guide/sysrq.html
# for what other values do
fs.file-max=524288
kernel.core_uses_pid=1
kernel.pid_max=524288
kernel.sysrq=0
vm.max_map_count=524288
vm.overcommit_memory=1
vm.zone_reclaim_mode=0
vm.vfs_cache_pressure=200
EOF

sudo sysctl -p

#----------------------------------------------------------------------------------------

sudo cat <<\EOF > /etc/security/limits.conf
# /etc/security/limits.conf
#
#Each line describes a limit for a user in the form:
#
#<domain>        <type>  <item>  <value>
#
#Where:
#<domain> can be:
#        - a user name
#        - a group name, with @group syntax
#        - the wildcard *, for default entry
#        - the wildcard %, can be also used with %group syntax,
#                 for maxlogin limit
#        - NOTE: group and wildcard limits are not applied to root.
#          To apply a limit to the root user, <domain> must be
#          the literal username root.
#
#<type> can have the two values:
#        - "soft" for enforcing the soft limits
#        - "hard" for enforcing hard limits
#
#<item> can be one of the following:
#        - core - limits the core file size (KB)
#        - data - max data size (KB)
#        - fsize - maximum filesize (KB)
#        - memlock - max locked-in-memory address space (KB)
#        - nofile - max number of open file descriptors
#        - rss - max resident set size (KB)
#        - stack - max stack size (KB)
#        - cpu - max CPU time (MIN)
#        - nproc - max number of processes
#        - as - address space limit (KB)
#        - maxlogins - max number of logins for this user
#        - maxsyslogins - max number of logins on the system
#        - priority - the priority to run user process with
#        - locks - max number of file locks the user can hold
#        - sigpending - max number of pending signals
#        - msgqueue - max memory used by POSIX message queues (bytes)
#        - nice - max nice priority allowed to raise to values: [-20, 19]
#        - rtprio - max realtime priority
#        - chroot - change root to directory (Debian-specific)
#
#<domain>      <type>  <item>         <value>
#
*               soft    nofile          524288
*               hard    nofile          524288
*               soft    nproc           524288
*               hard    nproc           524288
 
nginx               soft    nofile          524288
nginx               hard    nofile          524288
nginx               soft    nproc           524288
nginx               hard    nproc           524288
 
root               soft    nofile          524288
root               hard    nofile          524288
root               soft    nproc           524288
root               hard    nproc           524288
 
ubuntu               soft    nofile          524288
ubuntu               hard    nofile          524288
ubuntu               soft    nproc           524288
ubuntu               hard    nproc           524288
 
arangodb               soft    nofile          524288
arangodb               hard    nofile          524288
arangodb               soft    nproc           524288
arangodb               hard    nproc           524288
 
rabbitmq               soft    nofile          524288
rabbitmq               hard    nofile          524288
rabbitmq               soft    nproc           524288
rabbitmq               hard    nproc           524288
#*               soft    core            0
#root            hard    core            100000
#*               hard    rss             10000
#@student        hard    nproc           20
#@faculty        soft    nproc           20
#@faculty        hard    nproc           50
#ftp             hard    nproc           0
#ftp             -       chroot          /ftp
#@student        -       maxlogins       4
 
# End of file
EOF

#----------------------------------------------------------------------------------------

sudo sed -i 's/#DefaultLimitNOFILE=/DefaultLimitNOFILE=524288/' /etc/systemd/user.conf
sudo sed -i 's/#DefaultLimitNOFILE=1024:524288/DefaultLimitNOFILE=524288/' /etc/systemd/system.conf

#----------------------------------------------------------------------------------------

sudo apt install sysfsutils -y

sudo cat <<\EOF >> /etc/sysfs.conf
kernel/mm/transparent_hugepage/enabled = madvise
kernel/mm/transparent_hugepage/defrag = madvise
EOF

sudo cat /sys/kernel/mm/transparent_hugepage/defrag
sudo cat /sys/kernel/mm/transparent_hugepage/enabled

#----------------------------------------------------------------------------------------

echo -e "\n\nPLEASE, REBOOT THE SERVER:\n\nsudo shutdown -r now\n\n"

exit 0
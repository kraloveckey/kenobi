#!/usr/bin/env bash

set -o nounset
set -o pipefail

#----------------------------------------------------------------------------------------

if [[ "${TRACE-0}" == "1" ]]; then
    set -o xtrace
fi

#----------------------------------------------------------------------------------------

if [[ "${1-}" =~ ^-*h(elp)?$ ]]; then
    echo 'Usage: ./apache2.sh
 
This is bash script to install and configure apache2 web-server.
'
    exit
fi

#----------------------------------------------------------------------------------------

sudo apt update && sudo apt upgrade -y && sudo apt autoremove --purge -y
sudo apt install apache2 apache2-utils -y

sudo a2enmod headers
sudo a2enmod rewrite
sudo a2enmod ssl

sudo sed -i -r 's/ServerTokens OS/ServerTokens Prod/' /etc/apache2/conf-available/security.conf
sudo sed -i -r 's/ServerSignature On/ServerSignature Off/' /etc/apache2/conf-available/security.conf
sudo sed -i -r '$a Header set X-Frame-Options\: \"SAMEORIGIN\"' /etc/apache2/conf-available/security.conf
sudo echo "<DirectoryMatch \"/\.git/\">" >> /etc/apache2/conf-available/security.conf
sudo echo "   Order 'deny,allow'" >> /etc/apache2/conf-available/security.conf
sudo echo "   Deny from all" >> /etc/apache2/conf-available/security.conf
sudo echo "</DirectoryMatch>" >> /etc/apache2/conf-available/security.conf 

#----------------------------------------------------------------------------------------

sudo cat <<\EOF > /etc/apache2/apache2.conf
# This is the main Apache server configuration file. It contains the
# configuration directives that give the server its instructions.
# See http://httpd.apache.org/docs/2.4/ for detailed information about
# the directives and /usr/share/doc/apache2/README.Debian about Debian specific
# hints.
#
#
# Summary of how the Apache 2 configuration works in Debian:
# The Apache 2 web server configuration in Debian is quite different to
# upstream's suggested way to configure the web server. This is because Debian's
# default Apache2 installation attempts to make adding and removing modules,
# virtual hosts, and extra configuration directives as flexible as possible, in
# order to make automating the changes and administering the server as easy as
# possible.

# It is split into several files forming the configuration hierarchy outlined
# below, all located in the /etc/apache2/ directory:
#
#       /etc/apache2/
#       |-- apache2.conf
#       |       `--  ports.conf
#       |-- mods-enabled
#       |       |-- *.load
#       |       `-- *.conf
#       |-- conf-enabled
#       |       `-- *.conf
#       `-- sites-enabled
#               `-- *.conf
#
#
# * apache2.conf is the main configuration file (this file). It puts the pieces
#   together by including all remaining configuration files when starting up the
#   web server.
#
# * ports.conf is always included from the main configuration file. It is
#   supposed to determine listening ports for incoming connections which can be
#   customized anytime.
#
# * Configuration files in the mods-enabled/, conf-enabled/ and sites-enabled/
#   directories contain particular configuration snippets which manage modules,
#   global configuration fragments, or virtual host configurations,
#   respectively.
#
#   They are activated by symlinking available configuration files from their
#   respective *-available/ counterparts. These should be managed by using our
#   helpers a2enmod/a2dismod, a2ensite/a2dissite and a2enconf/a2disconf. See
#   their respective man pages for detailed information.
#
# * The binary is called apache2. Due to the use of environment variables, in
#   the default configuration, apache2 needs to be started/stopped with
#   /etc/init.d/apache2 or apache2ctl. Calling /usr/bin/apache2 directly will not
#   work with the default configuration.


# Global configuration
#

#
# ServerRoot: The top of the directory tree under which the server's
# configuration, error, and log files are kept.
#
# NOTE! If you intend to place this on an NFS (or otherwise network)
# mounted filesystem then please read the Mutex documentation (available
# at <URL:http://httpd.apache.org/docs/2.4/mod/core.html#mutex>);
# you will save yourself a lot of trouble.
#
# Do NOT add a slash at the end of the directory path.
#
#ServerRoot "/etc/apache2"

#
# The accept serialization lock file MUST BE STORED ON A LOCAL DISK.
#
#Mutex file:${APACHE_LOCK_DIR} default

#
# The directory where shm and other runtime files will be stored.
#

DefaultRuntimeDir ${APACHE_RUN_DIR}

#
# PidFile: The file in which the server should record its process
# identification number when it starts.
# This needs to be set in /etc/apache2/envvars
#
PidFile ${APACHE_PID_FILE}

#
# Timeout: The number of seconds before receives and sends time out.
#
Timeout 300

#
# KeepAlive: Whether or not to allow persistent connections (more than
# one request per connection). Set to "Off" to deactivate.
#
KeepAlive On

#
# MaxKeepAliveRequests: The maximum number of requests to allow
# during a persistent connection. Set to 0 to allow an unlimited amount.
# We recommend you leave this number high, for maximum performance.
#
MaxKeepAliveRequests 100

#
# KeepAliveTimeout: Number of seconds to wait for the next request from the
# same client on the same connection.
#
KeepAliveTimeout 5


# These need to be set in /etc/apache2/envvars
User ${APACHE_RUN_USER}
Group ${APACHE_RUN_GROUP}

#
# HostnameLookups: Log the names of clients or just their IP addresses
# e.g., www.apache.org (on) or 204.62.129.132 (off).
# The default is off because it'd be overall better for the net if people
# had to knowingly turn this feature on, since enabling it means that
# each client request will result in AT LEAST one lookup request to the
# nameserver.
#
HostnameLookups Off

# ErrorLog: The location of the error log file.
# If you do not specify an ErrorLog directive within a <VirtualHost>
# container, error messages relating to that virtual host will be
# logged here. If you *do* define an error logfile for a <VirtualHost>
# container, that host's errors will be logged there and not here.
#
ErrorLog ${APACHE_LOG_DIR}/error.log

#
# LogLevel: Control the severity of messages logged to the error_log.
# Available values: trace8, ..., trace1, debug, info, notice, warn,
# error, crit, alert, emerg.
# It is also possible to configure the log level for particular modules, e.g.
# "LogLevel info ssl:warn"
#
LogLevel warn

# Include module configuration:
IncludeOptional mods-enabled/*.load
IncludeOptional mods-enabled/*.conf

# Include list of ports to listen on
Include ports.conf


# Sets the default security model of the Apache2 HTTPD server. It does
# not allow access to the root filesystem outside of /usr/share and /var/www.
# The former is used by web applications packaged in Debian,
# the latter may be used for local directories served by the web server. If
# your system is serving content from a sub-directory in /srv you must allow
# access here, or in any related virtual host.

<Directory />
        Options FollowSymLinks
        AllowOverride None
        Require all denied
</Directory>

<Directory /var/www/>
        Options Indexes FollowSymLinks
        AllowOverride None
        Require all granted
</Directory>

# AccessFileName: The name of the file to look for in each directory
# for additional configuration directives. See also the AllowOverride
# directive.
#
AccessFileName .htaccess

#
# The following lines prevent .htaccess and .htpasswd files from being
# viewed by Web clients.
#
<FilesMatch "^\.ht">
        Require all denied
</FilesMatch>


#
# The following directives define some format nicknames for use with
# a CustomLog directive.
#
# These deviate from the Common Log Format definitions in that they use %O
# (the actual bytes sent including headers) instead of %b (the size of the
# requested file), because the latter makes it impossible to detect partial
# requests.
#
# Note that the use of %{X-Forwarded-For}i instead of %h is not recommended.
# Use mod_remoteip instead.
#
LogFormat "%v:%p %h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"" vhost_combined
LogFormat "%h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"" combined
LogFormat "%h %l %u %t \"%r\" %>s %O" common
LogFormat "%{Referer}i -> %U" referer
LogFormat "%{User-agent}i" agent

# Include of directories ignores editors' and dpkg's backup files,
# see README.Debian for details.

# Include generic snippets of statements
IncludeOptional conf-enabled/*.conf

# Include the virtual host configurations:
IncludeOptional sites-enabled/*.conf

# vim: syntax=apache ts=4 sw=4 sts=4 sr noet

SSLCipherSuite EECDH+AESGCM:EDH+AESGCM
# Requires Apache 2.4.36 & OpenSSL 1.1.1
SSLProtocol -all +TLSv1.3 +TLSv1.2
SSLOpenSSLConfCmd Curves X25519:secp521r1:secp384r1:prime256v1
# Older versions
# SSLProtocol All -SSLv2 -SSLv3 -TLSv1 -TLSv1.1
SSLHonorCipherOrder On
Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
Header always set X-Frame-Options DENY
Header always set X-Content-Type-Options nosniff
Header set X-XSS-Protection "1; mode=block"
# Requires Apache >= 2.4
SSLCompression off
SSLUseStapling on
SSLStaplingCache "shmcb:logs/stapling-cache(150000)"
# Requires Apache >= 2.4.11
SSLSessionTickets Off
Header set Content-Security-Policy "default-src 'self' http: https: data: blob: 'unsafe-inline' always"
Header set X-Permitted-Cross-Domain-Policies "none"
Header set Referrer-Policy "no-referrer"
EOF

#----------------------------------------------------------------------------------------

cat <<\EOF > /etc/apache2/useragent.conf
RewriteEngine On
RewriteCond %{HTTP_USER_AGENT} ^360Spider [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^80legs [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Abonti [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Aboundex [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^AcoonBot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Acunetix [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^adbeat_bot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^AddThis.com [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^adidxbot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^ADmantX [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^AhrefsBot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^AIBOT [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^aiHitBot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Alexibot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Alligator [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^AllSubmitter [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^AngloINFO [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Antelope [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Apexoo [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^asterias [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^attach [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^BackDoorBot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^BackStreet [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^BackWeb [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Badass [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Baid [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Baiduspider [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^BaiduSpider [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Bandit [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^BatchFTP [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^BBBike [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^BeetleBot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Bigfoot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^billigerbot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^binlar [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^bitlybot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Black.Hole [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^BlackWidow [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^BLEXBot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Blow [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^BlowFish [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^BLP_bbot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^BoardReader [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^BotALot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Buddy [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^BuiltBotTough [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Bullseye [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^BunnySlippers [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^casper [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^CazoodleBot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^CCBot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Cegbfeieh [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^checkprivacy [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^CheeseBot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^CherryPicker [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^ChinaClaw [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^chromeframe [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Clerkbot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Cliqzbot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^clshttp [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Cogentbot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^cognitiveseo [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Collector [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^CommonCrawler [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^comodo [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Copier [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^CopyRightCheck [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^cosmos [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^CPython [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^crawler4j [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Crawlera [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^CRAZYWEBCRAWLER [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Crescent [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^CSHttp [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Curious [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Curl [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Custo [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^CWS_proxy [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Demon [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^DeuSu [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Devil [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^diavol [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^DigExt [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Digincore [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^DIIbot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^DISCo [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^discobot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^DittoSpyder [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^DoCoMo [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^DotBot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Download.Demon [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Download.Devil [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Download.Wonder [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^dragonfly [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Drip [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^DTS.Agent [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^EasouSpider [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^EasyDL [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^ebingbong [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^eCatch [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^ecxi [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^EirGrabber [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Elmer [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^EmailCollector [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^EmailSiphon [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^EmailWolf [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^EroCrawler [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Exabot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^ExaleadCloudView [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^ExpertSearch [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^ExpertSearchSpider [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Express [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^extract [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Extractor [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^ExtractorPro [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^EyeNetIE [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Ezooms [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^F2S [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^FastSeek [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^feedfinder [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^FeedlyBot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^FHscan [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^finbot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^FlappyBot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^FlashGet [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^flicky [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Flipboard [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^FlipboardProxy [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^flunky [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Foobot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^FrontPage [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^g00g1e [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^GalaxyBot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^genieo [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Genieo [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^GetRight [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^GetWeb! [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^GigablastOpenSource [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Go-Ahead-Got-It [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Go!Zilla [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^gotit [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^GozaikBot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^grab [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Grabber [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^GrabNet [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Grafula [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^GrapeshotCrawler [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^GT::WWW [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^GTB5 [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Guzzle [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^harvest [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Harvest [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^HEADMasterSEO [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^heritrix [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^hloader [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^HMView [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^HomePageBot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^htmlparser [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^HTTP::Lite [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^httrack [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^HTTrack [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^HubSpot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^humanlinks [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^ia_archiver [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^icarus6 [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^id-search [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^IDBot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^IlseBot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Image.Stripper [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Image.Sucker [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^imagefetch [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Indigonet [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^InfoNaviRobot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^InfoTekies [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^integromedb [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Intelliseek [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^InterGET [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^InternetSeer.com [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Iria [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^IRLbot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^jakarta [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Jakarta [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Java [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^JennyBot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^JetCar [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^JikeSpider [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^JobdiggerSpider [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^JOC [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Jooblebot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^JustView [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Jyxobot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^kanagawa [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Kenjin.Spider [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Keyword.Density [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^KINGSpider [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^kmccrew [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^larbin [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^LeechFTP [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^LeechGet [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^LexiBot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^lftp [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^libWeb [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^libwww [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^libwww-perl [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^likse [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Lingewoud [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^LinkChecker [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^linkdexbot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^LinkextractorPro [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^LinkScan [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^LinksCrawler [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^LinksManager.com_bot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^linkwalker [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^LinkWalker [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^LinqiaRSSBot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^LivelapBot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^LNSpiderguy [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^ltx71 [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^LubbersBot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^lwp-trivial [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Mag-Net [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Magnet [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Mail.RU_Bot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^majestic12 [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^MarkWatch [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Mass.Downloader [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^masscan [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Mata.Hari [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^maverick [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Maxthon$ [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Mediatoolkitbot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^megaindex [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^MegaIndex [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Memo [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^MetaURI [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^MFC_Tear_Sample [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^microsoft.url [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^MIIxpc [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^miner [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^MJ12bot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Mozilla.*Indy [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Mozilla.*NEWT [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^MSFrontPage [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^MSIECrawler [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^msnbot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^NAMEPROTECT [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Navroad [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^NearSite [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^NetAnts [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Netcraft [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^netEstate [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^NetMechanic [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^NetSpider [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^NetZIP [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^NextGenSearchBot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^NICErsPRO [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^niki-bot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^NimbleCrawler [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Nimbostratus-Bot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Ninja [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^nmap [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Nmap [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^NPbot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^nutch [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Octopus [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Offline.Explorer [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Offline.Navigator [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Openfind [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^OpenindexSpider [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^OpenLinkProfiler [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^OpenWebSpider [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^OrangeBot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^OutfoxBot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Owlin [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^PageGrabber [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^PagesInventory [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^panopta [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^panscient.com [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^pavuk [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^pcBrowser [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^PECL::HTTP [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^PeoplePal [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Photon [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^PHPCrawl [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Pixray [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^planetwork [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^PleaseCrawl [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^PNAMAIN.EXE [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Pockey [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^PodcastPartyBot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^prijsbest [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^probethenet [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^ProPowerBot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^ProWebWalker [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^proximic [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^psbot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Pump [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^purebot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^pycurl [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^python-requests [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^QueryN.Metasearch [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^QuerySeekerSpider [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^R6_CommentReader [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^R6_FeedFetcher [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^RealDownload [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Reaper [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Recorder [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^ReGet [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^RepoMonkey [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Riddler [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Ripper [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^RMA [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^rogerbot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^RSSingBot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^rv:1.9.1 [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^RyzeCrawler [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^SafeSearch [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^SBIder [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^scanbot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Scrapy [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Screaming [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^SeaMonkey$ [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^search_robot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^search.goo.ne.jp [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^SearchmetricsBot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Semrush [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^SemrushBot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^SentiBot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^SEOkicks [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^SEOkicks-Robot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^seoscanners [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^SeznamBot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^ShowyouBot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^SightupBot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Siphon [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^SISTRIX [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^sitecheck.internetseer.com [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^siteexplorer.info [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Siteimprove [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^SiteSnagger [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^SiteSucker [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^skygrid [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Slackbot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Slurp [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^SlySearch [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^SmartDownload [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Snake [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Snapbot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Snoopy [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^sogou [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Sogou [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Sosospider [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^SpaceBison [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^SpankBot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^spanner [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^spaumbot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^spbot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Spinn4r [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Sqworm [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Steeler [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Stripper [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^sucker [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Sucker [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^SuperBot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Superfeedr [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^SuperHTTP [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^SurdotlyBot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Surfbot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^suzuran [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Szukacz [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^tAkeOut [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Teleport [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Telesoft [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^The.Intraformant [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^TheNomad [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^TightTwatBot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^TinEye [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^TinEye-bot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Titan [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Toplistbot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^trendictionbot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^trovitBot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^True_Robot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^turingos [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^turnit [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^TurnitinBot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Twitterbot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^URI::Fetch [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^urllib [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^URLy.Warning [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Vacuum [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Vagabondo [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^VCI [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^VidibleScraper [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^vikspider [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^VoidEYE [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^VoilaBot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^WallpapersHD [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^WBSearchBot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Web.Image.Collector [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^webalta [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^WebAuto [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^WebBandit [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^WebCollage [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^WebCopier [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^WebEnhancer [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^WebFetch [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^WebFuck [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^WebLeacher [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^WebmasterWorldForumBot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^WebPix [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^WebReaper [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^WebSauger [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^WebShag [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Website.eXtractor [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Webster [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^WebStripper [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^WebSucker [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^WebWhacker [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^WebZIP [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^WeSEE [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Wget [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Whack [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Whacker [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Widow [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^WinHTTrack [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^WinInet [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^WISENutbot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^woobot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^woopingbot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^worldwebheritage.org [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Wotbox [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^WPScan [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^WWW-Collector-E [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^WWW-Mechanize [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^WWWOFFLE [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Xaldon [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Xenu [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^XoviBot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^yacybot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Yandex [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^YandexBot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^YisouSpider [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Zade [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^zermelo [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Zeus [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^zh-CN [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^ZmEu [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^ZumBot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Zyborg [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^ZyBorg [NC]
RewriteRule ^ - [F]
EOF

#----------------------------------------------------------------------------------------

sudo cat <<\EOF > /etc/apache2/sites-available/test.conf
<VirtualHost *:80>
        Servername SERVER_NAME

        RewriteEngine On
        RewriteCond %{HTTPS} off
        RewriteRule (.*) https://%{HTTP_HOST}%{REQUEST_URI}
</VirtualHost>

<VirtualHost *:443>
        Servername SERVER_NAME

        SSLEngine on
        SSLCertificateFile "/etc/apache2/ssl/server.crt"
        SSLCertificateKeyFile "/etc/apache2/ssl/server.key"

        VirtualDocumentRoot /home/mds/www/
        VirtualScriptAlias /home/mds/www/cgi-bin/

        Action php-cgi /cgi-bin/php74

        <Directory "/var/www/server">
                Options FollowSymLinks ExecCGI
                        Include /etc/apache2/useragent.conf
                        Include /etc/apache2/secure.conf
                AllowOverride All
                DirectoryIndex index.php
                Require all granted
        </Directory>
</VirtualHost>

#out of virthost
SSLStaplingCache shmcb:/tmp/stapling_cache(128000)
EOF

#----------------------------------------------------------------------------------------

exit 0
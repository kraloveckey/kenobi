#!/usr/bin/env bash

set -o nounset
set -o pipefail

#----------------------------------------------------------------------------------------

if [[ "${TRACE-0}" == "1" ]]; then
    set -o xtrace
fi

#----------------------------------------------------------------------------------------

if [[ "${1-}" =~ ^-*h(elp)?$ ]]; then
    echo 'Usage: ./nginx.sh
 
This is bash script to install and configure nginx web-server.
'
    exit
fi

#----------------------------------------------------------------------------------------

sudo apt update && sudo apt upgrade -y && sudo apt autoremove --purge -y
sudo apt install apache2-utils curl gnupg2 ca-certificates lsb-release -y
echo "deb [arch=amd64] http://nginx.org/packages/ubuntu `lsb_release -cs` nginx" | sudo tee /etc/apt/sources.list.d/nginx.list
curl -o /tmp/nginx_signing.key https://nginx.org/keys/nginx_signing.key
sudo mv /tmp/nginx_signing.key /etc/apt/trusted.gpg.d/nginx_signing.asc
sudo apt update
sudo apt install nginx-extras -y 
sudo apt install nginx -y
sudo rm -rf /etc/nginx/sites-available/default* /etc/nginx/sites-enabled/default* /etc/nginx/conf.d/default*

#----------------------------------------------------------------------------------------

if [ -d "/etc/nginx/ssl" ] 
then
    echo -e "\nDirectory /etc/nginx/ssl exists...\n"
    if [ -e "/etc/nginx/ssl/dhparam.pem" ]; then
        echo -e "\nFile /etc/nginx/ssl/dhparam.pem exists...\n"
    else
        sudo cp $PWD/extra/dhparam.pem /etc/nginx/ssl/
        #sudo openssl dhparam -out /etc/nginx/ssl/dhparam.pem 4096
    fi
else
    echo -e "\nDirectory /etc/nginx/ssl does not exist. Creating...\n"
    sudo mkdir -p /etc/nginx/ssl && sudo openssl dhparam -out /etc/nginx/ssl/dhparam.pem 4096
fi


if [ -e "/etc/nginx/nginx.conf" ]; then
    echo -e "\nFile /etc/nginx/nginx.conf exists...\n"
else
    echo -e "\nFile /etc/nginx/nginx.conf does not exist. Creating...\n"
    sudo touch /etc/nginx/nginx.conf
    sudo chmod 644 /etc/nginx/nginx.conf
fi


if [ -e "/etc/nginx/ssl.conf" ]; then
    echo -e "\nFile /etc/nginx/ssl.conf exists...\n"
else
    echo -e "\nFile /etc/nginx/ssl.conf does not exist. Creating...\n"
    sudo touch /etc/nginx/ssl.conf
    sudo chmod 644 /etc/nginx/ssl.conf
fi

if [ -e "/etc/nginx/sec.conf" ]; then
    echo -e "\nFile /etc/nginx/sec.conf exists...\n"
else
    echo -e "\nFile /etc/nginx/sec.conf does not exist. Creating...\n"
    sudo touch /etc/nginx/sec.conf
    sudo chmod 644 /etc/nginx/sec.conf
fi

if [ -e "/etc/nginx/blacklist" ]; then
    echo -e "\nFile /etc/nginx/blacklist exists...\n"
else
    echo -e "\nFile /etc/nginx/blacklist does not exist. Creating...\n"
    sudo touch /etc/nginx/blacklist
    sudo chmod 644 /etc/nginx/blacklist
fi

sudo rm -r /var/www/html

#----------------------------------------------------------------------------------------

sudo cat <<\EOF > /etc/nginx/nginx.conf
user www-data;

# You must set worker processes based on your CPU cores, nginx does not benefit from setting more than that/
worker_processes auto;

# Number of file descriptors used for nginx/
# The limit for the maximum FDs on the server is usually set by the OS.
# If you don't set FD's then OS settings will be used which is by default 2000
worker_rlimit_nofile 100000;

# PID of the worker process.
pid /run/nginx.pid;

events {
# Determines how much clients will be served per worker.
# Max clients = worker_connections * worker_processes.
# Max clients is also limited by the number of socket connections available on the system (~64k).
        worker_connections 1024;

# Accept as many connections as possible, may flood worker connections if set too low -- for testing environment.
        multi_accept on;
}

http {
        include /etc/nginx/blacklist;
# Cache informations about FDs, frequently accessed files.
# Can boost performance, but you need to test those values.
        open_file_cache max=200000 inactive=20s;
        open_file_cache_valid 30s;
        open_file_cache_min_uses 2;
        open_file_cache_errors on;

# Copies data between one FD and other from within the kernel.
# Faster than read() + write().
        sendfile on;

# Send headers in one piece, it is better than sending them one by one.
        tcp_nopush on;

# Don't buffer data sent, good for small data bursts in real time.
        tcp_nodelay on;

# Sets the maximum size of the types hash tables.
        types_hash_max_size 2048;

# Enables or disables emitting nginx version on error pages and in the “Server” response header field.
        server_tokens off;

# Sets the bucket size for the server names hash tables. The default value depends on the size of the processor’s cache line.
        server_names_hash_bucket_size 512;

# Enables or disables the use of the primary server name, specified by the server_name directive, in absolute redirects issued by nginx. 
# When the use of the primary server name is disabled, the name from the “Host” request header field is used. If this field is not present, the IP address of the server is used. 
        server_name_in_redirect off;

# Defines a timeout for reading client request header. 
# If a client does not transmit the entire header within this time, the request is terminated with the 408 (Request Time-out) error -- default 1m.
        client_max_body_size 30m;

#Allows accurate tuning of per-request memory allocations.
        reset_timedout_connection on;

# If the request body size is more than the buffer size, then the entire (or partial).
# Request body is written into a temporary file.
        client_body_buffer_size  128k;

# If the request body size is more than the buffer size, then the entire (or partial).
# Request body is written into a temporary file.
        client_header_buffer_size 3m;

# Maximum number and size of buffers for large headers to read from client request.
        large_client_header_buffers 4 256k;

# Read timeout for the request body from client -- for testing environment.
        client_body_timeout 3m;

# How long to wait for the client to send a request header -- for testing environment.
        client_header_timeout 3m;

# If client stop responding, free up memory -- default 60.
        send_timeout 2;

# Server will close connection after this time -- default 75.
        keepalive_timeout 30;

# Number of requests client can make over keep-alive -- for testing environment.
        keepalive_requests 100000;

# Logging Settings.
        access_log /var/log/nginx/access.log;
        error_log /var/log/nginx/error.log;

# Gzip Settings.
        gzip on;
        gzip_min_length 10240;
        gzip_comp_level 1;
        gzip_vary on;
        gzip_disable msie6;
        gzip_proxied expired no-cache no-store private auth;

        include /etc/nginx/mime.types;
        default_type application/octet-stream;

# Virtual Host Configs.
        include /etc/nginx/conf.d/*.conf;
        include /etc/nginx/sites-enabled/*;    
}
EOF

#----------------------------------------------------------------------------------------

sudo cat <<\EOF > /etc/nginx/ssl.conf
if ($block_ua) {
    return 403; #Block virus and scans by user agent
}

proxy_hide_header Strict-Transport-Security;
add_header Strict-Transport-Security "max-age=63072000; includeSubdomains; preload" always;
add_header X-Content-Type-Options nosniff always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "no-referrer" always;
add_header X-Download-Options "noopen" always;
add_header X-Permitted-Cross-Domain-Policies "none" always;
add_header X-Robots-Tag "none" always;
add_header X-Frame-Options "DENY" always;

server_tokens off;

ssl_dhparam /etc/nginx/ssl/dhparam.pem; #openssl dhparam -out /etc/nginx/ssl/dhparam.pem 4096
ssl_session_timeout 10m;
ssl_session_tickets off;
ssl_session_cache shared:SSL:10m;

ssl_protocols TLSv1.3; #For TLSv1.3 requires nginx = 1.13.0+, else use TLSv1.2
ssl_prefer_server_ciphers on;
ssl_ciphers EECDH+AESGCM:EDH+AESGCM; #Valid ciphers find there https://cipherli.st
ssl_stapling on;
ssl_stapling_verify on;
ssl_ecdh_curve secp384r1;
EOF

#----------------------------------------------------------------------------------------

sudo cat <<\EOF > /etc/nginx/sec.conf
# Let's Encrypt SSL ACME Challenge Requirements.
# ACME Challenge Rule.
location /.well-known/acme-challenge {
    allow all;
    default_type "text/plain";
    root         /tmp/letsencrypt;
    autoindex    on;
}

# Wordpress specific rules.
# Block access to anything non image/video/music/document related from your uploads folder.
location ~* ^/wp-content/uploads/.*.(asp|cgi|htm|html|js|jsp|php|pl|py|sh|shtml|swf)$ {
    return 444;
}
# Protect any config files in your web root.
location ~* /(wp-config.php|nginx.conf|wp-config-sample.php) {
    return 444;
}
# Disallows Access to all text and readme files in Wordpress root.
location ~* ^/(readme|license|schema|password|passwords).*.(txt|html)$ {
    return 444;
}
# Disallows Access to any .conf or .sql files which you may have stored in your root.
location ~* ^/*.(conf|sql)$ {
    return 444;
}
# Disallows Access to plugin or theme readme files.
# Also helps block Wordpress Theme Detectors.
location ~* /wp-content/.*.txt$ {
    return 444;
}
# End wordpress specific rules.

# Block xmlrpc.php requests.
location /xmlrpc.php {
    return 444;
}

# Deny access to any files with a .php extension in any uploads / files directory.
# Add more folder names to protect as you like.
location ~* /(?:uploads|files)/.*\.php$ {
    return 444;
}

# Protect Perl/CGI/etc files.
# Very few sites run perl or cgi scripts anymore, block them!
# And block people even looking for them.
location ~* \.(pl|cgi|py|sh|lua)\$ {
    return 444;
}

# Similar to PHP file, a dotfile like .htaccess, .user.ini, and .git may contain sensitive information.
# To be on the safer side, it’s better to disable direct access to these files.
location ~ /\.(svn|git)/* {
    return 444;
}
location ~ /\.ht {
    return 444;
}
location ~ /\.user.ini {
    return 444;
}

# Block common hacks.
location ~* .(display_errors|set_time_limit|allow_url_include.*disable_functions.*open_basedir|set_magic_quotes_runtime|webconfig.txt.php|file_put_contentssever_root|wlwmanifest) {
    return 444;
}

location ~* .(globals|encode|localhost|loopback|xmlrpc|revslider|roundcube|webdav|smtp|http\:|soap|w00tw00t) {
    return 444;
}

# Protect other sensitive files.
location ~* \.(engine|inc|info|install|make|module|profile|test|po|sh|.*sql|theme|tpl(\.php)?|xtmpl)$|^(\..*|Entries.*|Repository|Root|Tag|Template)$|\.php_ {
    return 444;
}

# Block access to any disallowed server methods.
if ($request_method = PROPFIND) {
    return 444;
}

# Help guard against SQL injection.
location ~* .(\;|'|\"|%22).*(request|insert|union|declare|drop)$ {
    return 444;
}

location ~* "(\'|\")(.*)(drop|insert|md5|select|union|CONCAT|concat)" {
    return 444;
}

# Block attempts to access PHPMyAdmin.
# If you use phpmyadmin, DO NOT activate this rule!
# Disabled by default.
location ~* .(administrator|[pP]hp[mM]y[aA]dmin) {
    return 444;
}

# Deny backup extensions & log files.
location ~* ^.+\.(bak|log|old|orig|original|php#|php~|php_bak|save|swo|swp|sql)$ {
    return 444;
}

# WordFence.
location ~ \.user\.ini$ {
    return 444;
}

# Return 403 forbidden for readme.(txt|html) or license.(txt|html) or example.(txt|html) or other common git repository files.
location ~*  "/(^$|readme|license|example|README|LEGALNOTICE|INSTALLATION|CHANGELOG)\.(txt|html|md)" {
    return 444;
}

# Deny backup extensions & log files and return 403 forbidden.
location ~* "\.(old|orig|original|php#|php~|php_bak|save|swo|aspx?|tpl|sh|bash|bak?|cfg|cgi|dll|exe|git|hg|ini|jsp|log|mdb|out|sql|svn|swp|tar|rdf)$" {
    return 444;
}

# Common nginx configuration to block sql injection and other attacks.
location ~* "(eval\()" {
    return 444;
}
location ~* "(127\.0\.0\.1)" {
    return 444;
}
location ~* "([a-z0-9]{2000})" {
    return 444;
}
location ~* "(javascript\:)(.*)(\;)" {
    return 444;
}
location ~* "(base64_encode)(.*)(\()" {
    return 444;
}
location ~* "(GLOBALS|REQUEST)(=|\[|%)" {
    return 444;
}
location ~* "(<|%3C).*script.*(>|%3)" {
    return 444;
}
location ~ "(\\|\.\.\.|\.\./|~|`|<|>|\|)" {
    return 444;
}
location ~* "(boot\.ini|win\.ini|sleep|CONCAT|passwd|etc/passwd|self/environ)" {
    return 444;
}
location ~* "(thumbs?(_editor|open)?|tim(thumb)?)\.php" {
    return 444;
}
location ~* "(https?|ftp|php):/" {
    return 444;
}
location ~* "(=\\\'|=\\%27|/\\\'/?)\." {
    return 444;
}
location ~ "(\{0\}|\(/\(|\.\.\.|\+\+\+|\\\"\\\")" {
    return 444;
}
location ~ "(~|`|<|>|:|;|%|\\|\s|\{|\}|\[|\]|\|)" {
    return 444;
}
location ~* "/(=|\$&|_mm|(wp-)?config\.|cgi-|etc/passwd|muieblack)" {
    return 444;
}
location ~* "(&pws=0|_vti_|\(null\)|\{\$itemURL\}|echo(.*)kae|etc/passwd|eval\(|self/environ)" {
    return 444;
}
location ~* "/(^$|mobiquo|phpinfo|shell|sqlpatch|thumb|thumb_editor|thumbopen|timthumb|webshell|config|settings|configuration)\.php" {
    return 444;
}

# Block SQL injections
##
set $block_sql_injections 0; if ($query_string ~ "union.*select.*") { set $block_sql_injections 1; }
if ($query_string ~ "union.*all.*select.*") { set $block_sql_injections 1; }
if ($query_string ~ "concat.*") { set $block_sql_injections 1; }
if ($block_sql_injections = 1) { return 404; }

# Block File injections
##
set $block_file_injections 0;
#if ($query_string ~ "[a-zA-Z0-9_]=http://") { set $block_file_injections 1; }
if ($query_string ~ "[a-zA-Z0-9_]=(..//?)+") { set $block_file_injections 1; }
if ($query_string ~ "[a-zA-Z0-9_]=/([a-z0-9_.]//?)+") { set $block_file_injections 1; }
if ($block_file_injections = 1) { return 404; }

# Block common exploits
##
set $block_common_exploits 0;
if ($query_string ~ "(<|%3C).*script.*(>|%3E)") { set $block_common_exploits 1; }
if ($query_string ~ "GLOBALS(=|[|%[0-9A-Z]{0,2})") { set $block_common_exploits 1; }
if ($query_string ~ "_REQUEST(=|[|%[0-9A-Z]{0,2})") { set $block_common_exploits 1; }
if ($query_string ~ "proc/self/environ") { set $block_common_exploits 1; }
if ($query_string ~ "mosConfig_[a-zA-Z_]{1,21}(=|%3D)") { set $block_common_exploits 1; }
if ($query_string ~ "base64_(en|de)code(.*)") { set $block_common_exploits 1; }
if ($block_common_exploits = 1) { return 404; }

# Block SPAM
##
set $block_spam 0;
if ($query_string ~ "b(ultram|unicauca|valium|viagra|vicodin|xanax|ypxaieo)b") { set $block_spam 1; }
if ($query_string ~ "b(erections|hoodia|huronriveracres|impotence|levitra|libido)b") { set $block_spam 1; }
if ($query_string ~ "b(ambien|bluespill|cialis|cocaine|ejaculation|erectile)b") { set $block_spam 1; }
if ($query_string ~ "b(lipitor|phentermin|pro[sz]ac|sandyauer|tramadol|troyhamby)b") { set $block_spam 1; }
if ($block_spam = 1) { return 404; }

# Block blank user_agent
##
set $block_empty_ua 0;
if ($http_user_agent = "") { set $block_empty_ua 1; }
if ($remote_addr = 127.0.0.1) { set $block_empty_ua 0; }
if ($block_empty_ua = 1) { return 404; }
EOF

#----------------------------------------------------------------------------------------

sudo cat <<\EOF > /etc/nginx/blacklist
# Define list of user agents
map $http_user_agent $block_ua {
    default                                  0;
    
    ~*360Spider                              1;
    ~*404checker                             1;
    ~*404enemy                               1;
    ~*80legs                                 1;
    ~*Abonti                                 1;
    ~*Aboundex                               1;
    ~*Aboundexbot                            1;
    ~*AfD-Verbotsverfahren                   1;
    ~*AcoonBot                               1;
    ~*Acunetix                               1;
    ~*adbeat_bot                             1;
    ~*AddThis.com                            1;
    ~*adidxbot                               1;
    ~*ADmantX                                1;
    ~*AhrefsBot                              1;
    ~*AIBOT                                  1;
    ~*aiHitBot                               1;
    ~*Aipbot                                 1;
    ~*Alexibot                               1;
    ~*Alligator                              1;
    ~*AllSubmitter                           1;
    ~*AlphaBot                               1;
    ~*Anarchie                               1;
    ~*Ankit                                  1;
    ~*AngloINFO                              1;
    ~*Antelope                               1;
    ~*Apexoo                                 1;
    ~*archive.org_bot                        1;
    ~*arquivo.pt                             1;
    ~*arquivo-web-crawler                    1;
    ~*Aspiegel                               1;
    ~*ASPSeek                                1;
    ~*asterias                               1;
    ~*attach                                 1;
    ~*autoemailspider                        1;
    ~*AwarioRssBot                           1;
    ~*AwarioSmartBot                         1;
    ~*BackDoorBot                            1;
    ~*Backlink-Ceck                          1;
    ~*backlink-check                         1;
    ~*BacklinkCrawler                        1;
    ~*BackStreet                             1;
    ~*BackWeb                                1;
    ~*Badass                                 1;
    ~*Baid                                   1;
    ~*Baiduspider                            1;
    ~*BaiduSpider                            1;
    ~*Bandit                                 1;
    ~*Barkrowler                             1;
    ~*BatchFTP                               1;
    ~*Battleztar\ Bazinga                    1;
    ~*BBBike                                 1;
    ~*BDCbot                                 1;
    ~*BDFetch                                1;
    ~*BetaBot                                1;
    ~*BeetleBot                              1;
    ~*Bigfoot                                1;
    ~*Bitacle                                1;
    ~*billigerbot                            1;
    ~*binlar                                 1;
    ~*bitlybot                               1;
    ~*Blackboard                             1;
    ~*Black\ Hole                            1;
    ~*Black.Hole                             1;
    ~*BlackWidow                             1;
    ~*BLEXBot                                1;
    ~*Blow                                   1;
    ~*BlowFish                               1;
    ~*BLP_bbot                               1;
    ~*BoardReader                            1;
    ~*Bolt                                   1;
    ~*Bolt\ 0                                1;
    ~*BOT\ for\ JCE                          1;
    ~*Bot\ mailto\:craftbot@yahoo\.com       1;
    ~*BotALot                                1;
    ~*Brandprotect                           1;
    ~*Brandwatch                             1;
    ~*Buddy                                  1;
    ~*BuiltBotTough                          1;
    ~*Bullseye                               1;
    ~*BunnySlippers                          1;
    ~*BuiltWith                              1;
    ~*BuzzSumo                               1;
    ~*Calculon                               1;
    ~*CATExplorador                          1;
    ~*casper                                 1;
    ~*CazoodleBot                            1;
    ~*CCBot                                  1;
    ~*Cegbfeieh                              1;
    ~*checkprivacy                           1;
    ~*CheeseBot                              1;
    ~*CherryPicker                           1;
    ~*CheTeam                                1;
    ~*Chlooe                                 1;
    ~*ChinaClaw                              1;
    ~*Claritybot                             1;
    ~*chromeframe                            1;
    ~*Clerkbot                               1;
    ~*Cliqzbot                               1;
    ~*Cloud\ mapping                         1;
    ~*clshttp                                1;
    ~*coccocbot-web                          1;
    ~*Cogentbot                              1;
    ~*cognitiveseo                           1;
    ~*Collector                              1;
    ~*CommonCrawler                          1;
    ~*comodo                                 1;
    ~*com.plumanalytics                      1;
    ~*Copier                                 1;
    ~*CopyRightCheck                         1;
    ~*Copyscape                              1;
    ~*cosmos                                 1;
    ~*CPython                                1;
    ~*Craftbot                               1;
    ~*crawler.feedback                       1;
    ~*crawler4j                              1;
    ~*crawl.sogou.com                        1;
    ~*Crawlera                               1;
    ~*CRAZYWEBCRAWLER                        1;
    ~*Crescent                               1;
    ~*CrunchBot                              1;
    ~*CSHttp                                 1;
    ~*Curious                                1;
    ~*Curl                                   1;
    ~*Custo                                  1;
    ~*CWS_proxy                              1;
    ~*DatabaseDriverMysqli                   1;
    ~*DataCha0s                              1;
    ~*DBLBot                                 1;
    ~*Default\ Browser\ 0                    1;
    ~*demandbase-bot                         1;
    ~*Demon                                  1;
    ~*DeuSu                                  1;
    ~*Devil                                  1;
    ~*diavol                                 1;
    ~*DigExt                                 1;
    ~*Digincore                              1;
    ~*DigitalPebble                          1;
    ~*DIIbot                                 1;
    ~*DISCo                                  1;
    ~*discobot                               1;
    ~*Dirbuster                              1;
    ~*Discoverybot                           1;
    ~*Dispatch                               1;
    ~*DittoSpyder                            1;
    ~*DnyzBot                                1;
    ~*DoCoMo                                 1;
    ~*DomainAppender                         1;
    ~*DomainCrawler                          1;
    ~*DomainSigmaCrawler                     1;
    ~*Domains\ Project                       1;
    ~*domainsproject.org                     1;
    ~*DomainStatsBot                         1;
    ~*DotBot                                 1;
    ~*Download.Demon                         1;
    ~*Download.Devil                         1;
    ~*Download.Wonder                        1;
    ~*Download\ Demo                         1;
    ~*dragonfly                              1;
    ~*Drip                                   1;
    ~*DSearch                                1;
    ~*DTS.Agent                              1;
    ~*EasouSpider                            1;
    ~*EasyDL                                 1;
    ~*ebingbong                              1;
    ~*ECCP/1.0                               1;
    ~*eCatch                                 1;
    ~*ecxi                                   1;
    ~*EirGrabber                             1;
    ~*Elmer                                  1;
    ~*EmailCollector                         1;
    ~*EmailSiphon                            1;
    ~*EmailWolf                              1;
    ~*EroCrawler                             1;
    ~*evc-batch                              1;
    ~*Evil                                   1;
    ~*Exabot                                 1;
    ~*ExaleadCloudView                       1;
    ~*ExpertSearch                           1;
    ~*ExpertSearchSpider                     1;
    ~*Express                                1;
    ~*Express\ WebPictures                   1;
    ~*ExtLinksBot                            1;
    ~*extract                                1;
    ~*Extractor                              1;
    ~*Extreme\ Picture\ Finder               1;
    ~*ExtractorPro                           1;
    ~*EyeNetIE                               1;
    ~*Ezooms                                 1;
    ~*facebookscraper                        1;
    ~*FDM                                    1;
    ~*F2S                                    1;
    ~*FastSeek                               1;
    ~*feedfinder                             1;
    ~*FeedlyBot                              1;
    ~*FemtosearchBot                         1;
    ~*FHscan                                 1;
    ~*finbot                                 1;
    ~*Fimap                                  1;
    ~*Firefox/7.0                            1;
    ~*Flamingo_SearchEngine                  1;
    ~*FlappyBot                              1;
    ~*FlashGet                               1;
    ~*flicky                                 1;
    ~*Flipboard                              1;
    ~*FlipboardProxy                         1;
    ~*flunky                                 1;
    ~*Foobot                                 1;
    ~*Freeuploader                           1;
    ~*FrontPage                              1;
    ~*FyberSpider                            1;
    ~*Fyrebot                                1;
    ~*g00g1e                                 1;
    ~*GalaxyBot                              1;
    ~*genieo                                 1;
    ~*Genieo                                 1;
    ~*GetRight                               1;
    ~*GetWeb\!                               1;
    ~*Gigablast                              1;
    ~*GigablastOpenSource                    1;
    ~*Gigabot                                1;
    ~*G-i-g-a-b-o-t                          1;
    ~*Go-Ahead-Got-It                        1;
    ~*Go\-Ahead\-Got\-It                     1;
    ~*Go\!Zilla                              1;
    ~*GoZilla                                1;
    ~*Go!Zilla                               1;
    ~*gotit                                  1;
    ~*GozaikBot                              1;
    ~*grab                                   1;
    ~*Grabber                                1;
    ~*GrabNet                                1;
    ~*Grafula                                1;
    ~*GrapeFX                                1;
    ~*GridBot                                1;
    ~*GrapeshotCrawler                       1;
    ~*GT\:\:WWW                              1;
    ~*GT::WWW                                1;
    ~*GTB5                                   1;
    ~*Guzzle                                 1;
    ~*Haansoft                               1;
    ~*HaosouSpider                           1;
    ~*harvest                                1;
    ~*Harvest                                1;
    ~*Havij                                  1;
    ~*HEADMasterSEO                          1;
    ~*heritrix                               1;
    ~*Heritrix                               1;
    ~*Hloader                                1;
    ~*hloader                                1;
    ~*HMView                                 1;
    ~*HomePageBot                            1;
    ~*HTMLparser                             1;
    ~*htmlparser                             1;
    ~*HTTP\:\:Lite                           1;
    ~*HTTP::Lite                             1;
    ~*httrack                                1;
    ~*HTTrack                                1;
    ~*HubSpot                                1;
    ~*humanlinks                             1;
    ~*Humanlinks                             1;
    ~*HybridBot                              1;
    ~*ia_archiver                            1;
    ~*Iblog                                  1;
    ~*icarus6                                1;
    ~*id\-search                             1;
    ~*IDBot                                  1;
    ~*Id-search                              1;
    ~*IlseBot                                1;
    ~*Image.Stripper                         1;
    ~*Image.Sucker                           1;
    ~*Image\ Stripper                        1;
    ~*Image\ Sucker                          1;
    ~*imagefetch                             1;
    ~*Image\ Fetch                           1;
    ~*IndeedBot                              1;
    ~*Indigonet                              1;
    ~*Indy\ Library                          1;
    ~*InfoNaviRobot                          1;
    ~*InfoTekies                             1;
    ~*instabid                               1;
    ~*integromedb                            1;
    ~*Intelliseek                            1;
    ~*InterGET                               1;
    ~*Internet\ Ninja                        1;
    ~*InternetSeer                           1;
    ~*InternetSeer\.com                      1;
    ~*internetVista\ monitor                 1;
    ~*ips-agent                              1;
    ~*Iria                                   1;
    ~*IRLbot                                 1;
    ~*isitwp.com                             1;
    ~*IstellaBot                             1;
    ~*Iskanie                                1;
    ~*ISC\ Systems\ iRc\ Search\ 2\.1        1;
    ~*jakarta                                1;
    ~*Jakarta                                1;
    ~*JamesBOT                               1;
    ~*Jbrofuzz                               1;
    ~*JennyBot                               1;
    ~*JetCar                                 1;
    ~*JikeSpider                             1;
    ~*JobdiggerSpider                        1;
    ~*JOC                                    1;
    ~*JOC\ Web\ Spider                       1;
    ~*Jooblebot                              1;
    ~*Jorgee                                 1;
    ~*JustView                               1;
    ~*Jyxobot                                1;
    ~*kanagawa                               1;
    ~*Kenjin\ Spider                         1;
    ~*Kenjin.Spider                          1;
    ~*Keyword\ Density                       1;
    ~*Keyword.Density                        1;
    ~*Kinza                                  1;
    ~*KINGSpider                             1;
    ~*kmccrew                                1;
    ~*Kozmosbot                              1;
    ~*Lanshanbot                             1;
    ~*larbin                                 1;
    ~*Larbin                                 1;
    ~*LeechFTP                               1;
    ~*LeechGet                               1;
    ~*LexiBot                                1;
    ~*Lftp                                   1;
    ~*lftp                                   1;
    ~*LibWeb                                 1;
    ~*libWeb                                 1;
    ~*Libwhisker                             1;
    ~*LieBaoFast                             1;
    ~*Lightspeedsystems                      1;
    ~*libwww                                 1;
    ~*libwww-perl                            1;
    ~*Likse                                  1;
    ~*likse                                  1;
    ~*Lingewoud                              1;
    ~*LinkChecker                            1;
    ~*linkdexbot                             1;
    ~*LinkextractorPro                       1;
    ~*LinkScan                               1;
    ~*LinkpadBot                             1;
    ~*LinksCrawler                           1;
    ~*LinksManager\.com_bot                  1;
    ~*LinksManager                           1;
    ~*linkwalker                             1;
    ~*LinkWalker                             1;
    ~*LinqiaRSSBot                           1;
    ~*LinqiaMetadataDownloaderBot            1;
    ~*LinqiaScrapeBot                        1;
    ~*Lipperhey                              1;
    ~*Lipperhey\ Spider                      1;
    ~*Litemage_walker                        1;
    ~*Lmspider                               1;
    ~*LivelapBot                             1;
    ~*LNSpiderguy                            1;
    ~*ltx71                                  1;
    ~*Ltx71                                  1;
    ~*LubbersBot                             1;
    ~*lwp\-trivial                           1;
    ~*lwp-trivial                            1;
    ~*lwp-request                            1;
    ~*LWP::Simple                            1;
    ~*Mag-Net                                1;
    ~*Magnet                                 1;
    ~*magpie-crawler                         1;
    ~*Mail.RU_Bot                            1;
    ~*majestic12                             1;
    ~*Majestic12                             1;
    ~*Majestic-SEO                           1;
    ~*Majestic\ SEO                          1;
    ~*MarkMonitor                            1;
    ~*MarkWatch                              1;
    ~*Mass.Downloader                        1;
    ~*Mass\ Downloader                       1;
    ~*masscan                                1;
    ~*Masscan                                1;
    ~*Mata.Hari                              1;
    ~*Mata\ Hari                             1;
    ~*maverick                               1;
    ~*MauiBot                                1;
    ~*Maxthon$                               1;
    ~*Mb2345Browser                          1;
    ~*Mediatoolkitbot                        1;
    ~*megaindex                              1;
    ~*MegaIndex                              1;
    ~*meanpathbot                            1;
    ~*Meanpathbot                            1;
    ~*MeanPath\ Bot                          1;
    ~*Mediatoolkitbot                        1;
    ~*mediawords                             1;
    ~*MegaIndex.ru                           1;
    ~*Memo                                   1;
    ~*MetaURI                                1;
    ~*Metauri                                1;
    ~*MFC_Tear_Sample                        1;
    ~*Microsoft\ URL\ Control                1;
    ~*microsoft\.url                         1;
    ~*MicroMessenger                         1;
    ~*Microsoft\ Data\ Access                1;
    ~*MIDown\ tool                           1;
    ~*MIIxpc                                 1;
    ~*miner                                  1;
    ~*Missigua\ Locator                      1;
    ~*Mister\ PiX                            1;
    ~*MJ12bot                                1;
    ~*Mozilla.*Indy                          1;
    ~*Mozilla.*NEWT                          1;
    ~*Mojeek                                 1;
    ~*Mojolicious                            1;
    ~*Morfeus\ Fucking\ Scanner              1;
    ~*Mozlila                                1;
    ~*MQQBrowser                             1;
    ~*Mr.4x3                                 1;
    ~*MSFrontPage                            1;
    ~*MSIECrawler                            1;
    ~*Msrabot                                1;
    ~*Musobot                                1;
    ~*muhstik-scan                           1;
    ~*msnbot                                 1;
    ~*Name\ Intelligence                     1;
    ~*Nameprotect                            1;
    ~*NAMEPROTECT                            1;
    ~*Navroad                                1;
    ~*NearSite                               1;
    ~*Needle                                 1;
    ~*Nessus                                 1;
    ~*Net\ Vampire                           1;
    ~*NetAnts                                1;
    ~*Netcraft                               1;
    ~*netEstate                              1;
    ~*NetMechanic                            1;
    ~*NetSpider                              1;
    ~*netEstate\ NE\ Crawler                 1;
    ~*NetLyzer                               1;
    ~*Nettrack                               1;
    ~*Netvibes                               1;
    ~*NetZIP                                 1;
    ~*NextGenSearchBot                       1;
    ~*Nibbler                                1;
    ~*NICErsPRO                              1;
    ~*Niki-bot                               1;
    ~*niki\-bot                              1;
    ~*Nikto                                  1;
    ~*NimbleCrawler                          1;
    ~*Nimbostratus                           1;
    ~*Nimbostratus\-Bot                      1;
    ~*Ninja                                  1;
    ~*nmap                                   1;
    ~*Nmap                                   1;
    ~*NPbot                                  1;
    ~*Nutch                                  1;
    ~*nutch                                  1;
    ~*oBot                                   1;
    ~*Octopus                                1;
    ~*Offline\.Explorer                      1;
    ~*Offline\.Navigator                     1;
    ~*Offline\ Explorer                      1;
    ~*Offline\ Navigator                     1;
    ~*OnCrawl                                1;
    ~*Openfind                               1;
    ~*OpenindexSpider                        1;
    ~*OpenLinkProfiler                       1;
    ~*Openvas                                1;
    ~*OpenVAS                                1;
    ~*OpenVAS                                1;
    ~*OPPO                                   1;
    ~*OPPO\ A33                              1;
    ~*OrangeBot                              1;
    ~*OrangeSpider                           1;
    ~*OutfoxBot                              1;
    ~*OutclicksBot                           1;
    ~*Owlin                                  1;
    ~*PageAnalyzer                           1;
    ~*Page\ Analyzer                         1;
    ~*PageGrabber                            1;
    ~*page\ scorer                           1;
    ~*PageScorer                             1;
    ~*PagesInventory                         1;
    ~*panopta                                1;
    ~*Pandalytics                            1;
    ~*Panscient                              1;
    ~*panscient\.com                         1;
    ~*Papa\ Foto                             1;
    ~*Pavuk                                  1;
    ~*pavuk                                  1;
    ~*pcBrowser                              1;
    ~*PECL\:\:HTTP                           1;
    ~*PECL::HTTP                             1;
    ~*PeoplePal                              1;
    ~*Photon                                 1;
    ~*PHPCrawl                               1;
    ~*Pixray                                 1;
    ~*Picscout                               1;
    ~*Picsearch                              1;
    ~*PictureFinder                          1;
    ~*Pimonster                              1;
    ~*Pi-Monster                             1;
    ~*planetwork                             1;
    ~*PleaseCrawl                            1;
    ~*plumanalytics                          1;
    ~*PNAMAIN\.EXE                           1;
    ~*Pockey                                 1;
    ~*PodcastPartyBot                        1;
    ~*POE-Component-Client-HTTP              1;
    ~*polaris\ version                       1;
    ~*prijsbest                              1;
    ~*probethenet                            1;
    ~*Probethenet                            1;
    ~*ProPowerBot                            1;
    ~*ProWebWalker                           1;
    ~*proximic                               1;
    ~*psbot                                  1;
    ~*Psbot                                  1;
    ~*PxBroker                               1;
    ~*Pump                                   1;
    ~*purebot                                1;
    ~*pycurl                                 1;
    ~*PyCurl                                 1;
    ~*python\-requests                       1;
    ~*QueryN\.Metasearch                     1;
    ~*QueryN\ Metasearch                     1;
    ~*Quick-Crawler                          1;
    ~*QuerySeekerSpider                      1;
    ~*R6_CommentReader                       1;
    ~*R6_FeedFetcher                         1;
    ~*RankActive                             1;
    ~*RankActiveLinkBot                      1;
    ~*RankFlex                               1;
    ~*RankingBot                             1;
    ~*RankingBot2                            1;
    ~*Rankivabot                             1;
    ~*RankurBot                              1;
    ~*RealDownload                           1;
    ~*Reaper                                 1;
    ~*RebelMouse                             1;
    ~*Recorder                               1;
    ~*RedesScrapy                            1;
    ~*ReGet                                  1;
    ~*RepoMonkey                             1;
    ~*Riddler                                1;
    ~*Ripper                                 1;
    ~*Rippers\ 0                             1;
    ~*RMA                                    1;
    ~*RocketCrawler                          1;
    ~*Rogerbot                               1;
    ~*rogerbot                               1;
    ~*RSSingBot                              1;
    ~*rv\:1\.9\.1                            1;
    ~*RyzeCrawler                            1;
    ~*s1z.ru                                 1;
    ~*SalesIntelligent                       1;
    ~*satoristudio.net                       1;
    ~*SafeSearch                             1;
    ~*SBIder                                 1;
    ~*ScanAlert                              1;
    ~*Scanbot                                1;
    ~*scanbot                                1;
    ~*scan.lol                               1;
    ~*ScoutJet                               1;
    ~*Scrapy                                 1;
    ~*Screaming                              1;
    ~*ScreenerBot                            1;
    ~*Searchestate                           1;
    ~*SearchmetricsBot                       1;
    ~*SeaMonkey$                             1;
    ~*search_robot                           1;
    ~*search\.goo\.ne\.jp                    1;
    ~*SearchmetricsBot                       1;
    ~*Semrush                                1;
    ~*SemrushBot                             1;
    ~*SentiBot                               1;
    ~*SEOkicks                               1;
    ~*SEOkicks\-Robot                        1;
    ~*SEOkicks-Robot                         1;
    ~*SEOlyticsCrawler                       1;
    ~*Seomoz                                 1;
    ~*SEOprofiler                            1;
    ~*seoscanners                            1;
    ~*SeoSiteCheckup                         1;
    ~*SEOstats                               1;
    ~*SeznamBot                              1;
    ~*serpstatbot                            1;
    ~*sexsearcher                            1;
    ~*Shodan                                 1;
    ~*ShowyouBot                             1;
    ~*SightupBot                             1;
    ~*Siphon                                 1;
    ~*SISTRIX                                1;
    ~*Sitebeam                               1;
    ~*SiteCheckerBotCrawler                  1;
    ~*sitechecker.pro                        1;
    ~*SiteExplorer                           1;
    ~*sitecheck\.internetseer\.com           1;
    ~*siteexplorer\.info                     1;
    ~*Siteimprove                            1;
    ~*SiteLockSpider                         1;
    ~*SiteSnagger                            1;
    ~*SiteSucker                             1;
    ~*Site\ Sucker                           1;
    ~*Sitevigil                              1;
    ~*skygrid                                1;
    ~*Slackbot                               1;
    ~*Slurp                                  1;
    ~*SlySearch                              1;
    ~*SmartDownload                          1;
    ~*SMTBot                                 1;
    ~*Snake                                  1;
    ~*Snapbot                                1;
    ~*Snoopy                                 1;
    ~*SocialRankIOBot                        1;
    ~*Sociscraper                            1;
    ~*sogouspider                            1;
    ~*Sogou\ web\ spider                     1;
    ~*sogou                                  1;
    ~*Sogou                                  1;
    ~*Sosospider                             1;
    ~*Sottopop                               1;
    ~*SpaceBison                             1;
    ~*Spammen                                1;
    ~*SpankBot                               1;
    ~*spanner                                1;
    ~*Spanner                                1;
    ~*sp_auditbot                            1;
    ~*spaumbot                               1;
    ~*spbot                                  1;
    ~*Spinn3r                                1;
    ~*Spinn4r                                1;
    ~*SputnikBot                             1;
    ~*spyfu                                  1;
    ~*Sqlmap                                 1;
    ~*Sqlworm                                1;
    ~*Sqworm                                 1;
    ~*Steeler                                1;
    ~*Stripper                               1;
    ~*sucker                                 1;
    ~*Sucker                                 1;
    ~*Sucuri                                 1;
    ~*SuperBot                               1;
    ~*Superfeedr                             1;
    ~*SuperHTTP                              1;
    ~*SurdotlyBot                            1;
    ~*Surfbot                                1;
    ~*SurveyBot                              1;
    ~*Suzuran                                1;
    ~*suzuran                                1;
    ~*Swiftbot                               1;
    ~*sysscan                                1;
    ~*Szukacz                                1;
    ~*T0PHackTeam                            1;
    ~*T8Abot                                 1;
    ~*tAkeOut                                1;
    ~*Teleport                               1;
    ~*TeleportPro                            1;
    ~*Teleport\ Pro                          1;
    ~*Telesoft                               1;
    ~*Telesphoreo                            1;
    ~*Telesphorep                            1;
    ~*The\.Intraformant                      1;
    ~*The\ Intraformant                      1;
    ~*TheNomad                               1;
    ~*Thumbor                                1;
    ~*TightTwatBot                           1;
    ~*TinEye                                 1;
    ~*TinEye\-bot                            1;
    ~*Titan                                  1;
    ~*Toata                                  1;
    ~*Toata\ dragostea\ mea\ pentru\ diavola 1;
    ~*Toweyabot                              1;
    ~*Toplistbot                             1;
    ~*Tracemyfile                            1;
    ~*Trendiction                            1;
    ~*Trendictionbot                         1;
    ~*trendictionbot                         1;
    ~*trendiction.com                        1;
    ~*trendiction.de                         1;
    ~*True_Robot                             1;
    ~*trovitBot                              1;
    ~*True_Robot                             1;
    ~*turingos                               1;
    ~*Turingos                               1;
    ~*turnit                                 1;
    ~*Turnitin                               1;
    ~*TurnitinBot                            1;
    ~*TwengaBot                              1;
    ~*Twitterbot                             1;
    ~*Twice                                  1;
    ~*Typhoeus                               1;
    ~*UnisterBot                             1;
    ~*Upflow                                 1;
    ~*URI\:\:Fetch                           1;
    ~*urllib                                 1;
    ~*URLy\.Warning                          1;
    ~*URLy\ Warning                          1;
    ~*Vacuum                                 1;
    ~*Vagabondo                              1;
    ~*VB\ Project                            1;
    ~*VCI                                    1;
    ~*VeriCiteCrawler                        1;
    ~*VidibleScraper                         1;
    ~*Virusdie                               1;
    ~*vikspider                              1;
    ~*VoidEYE                                1;
    ~*VoilaBot                               1;
    ~*Voil                                   1;
    ~*Voltron                                1;
    ~*WallpapersHD                           1;
    ~*Wallpapers/3.0                         1;
    ~*WASALive-Bot                           1;
    ~*WBSearchBot                            1;
    ~*Web.Image.Collector                    1;
    ~*Web\ Image\ Collector                  1;
    ~*Web\ Sucker                            1;
    ~*webalta                                1;
    ~*Webalta                                1;
    ~*WebAuto                                1;
    ~*Web\ Auto                              1;
    ~*WebBandit                              1;
    ~*WebCollage                             1;
    ~*Web\ Collage                           1;
    ~*WebCopier                              1;
    ~*WEBDAV                                 1;
    ~*WebEnhancer                            1;
    ~*Web\ Enhancer                          1;
    ~*WebFetch                               1;
    ~*Web\ Fetch                             1;
    ~*Web\ Fuck                              1;
    ~*WebFuck                                1;
    ~*WebGo\ IS                              1;
    ~*WebImageCollector                      1;
    ~*WebLeacher                             1;
    ~*WebmasterWorldForumBot                 1;
    ~*webmeup-crawler                        1;
    ~*WebPix                                 1;
    ~*Web\ Pix                               1;
    ~*WebReaper                              1;
    ~*WebSauger                              1;
    ~*Web\ Sauger                            1;
    ~*WebShag                                1;
    ~*Webshag                                1;
    ~*WebsiteExtractor                       1;
    ~*Website\.eXtractor                     1;
    ~*Website\ eXtractor                     1;
    ~*Website\ Quester                       1;
    ~*WebsiteQuester                         1;
    ~*Webster                                1;
    ~*WebStripper                            1;
    ~*WebSucker                              1;
    ~*Web\ Sucker                            1;
    ~*WebWhacker                             1;
    ~*WebZIP                                 1;
    ~*Wells\ Search\ II                      1;
    ~*WEP\ Search                            1;
    ~*WeSEE                                  1;
    ~*Whack                                  1;
    ~*Whatweb                                1;
    ~*Whacker                                1;
    ~*Who.is\ Bot                            1;
    ~*Widow                                  1;
    ~*WinHTTrack                             1;
    ~*WinInet                                1;
    ~*WISENutbot                             1;
    ~*WiseGuys\ Robot                        1;
    ~*Wonderbot                              1;
    ~*Woobot                                 1;
    ~*woobot                                 1;
    ~*woopingbot                             1;
    ~*worldwebheritage.org                   1;
    ~*Wotbox                                 1;
    ~*WPScan                                 1;
    ~*Wprecon                                1;
    ~*WWW\-Collector\-E                      1;
    ~*WWW\-Mechanize                         1;
    ~*WWW\:\:Mechanize                       1;
    ~*WWWOFFLE                               1;
    ~*x09Mozilla                             1;
    ~*x22Mozilla                             1;
    ~*Xaldon_WebSpider                       1;
    ~*Xaldon                                 1;
    ~*Xaldon\ WebSpider                      1;
    ~*Xenu                                   1;
    ~*xpymep1.exe                            1;
    ~*XoviBot                                1;
    ~*yacybot                                1;
    ~*Yandex                                 1;
    ~*YandexBot                              1;
    ~*YisouSpider                            1;
    ~*YoudaoBot                              1;
    ~*Zade                                   1;
    ~*Zauba                                  1;
    ~*zauba.io                               1;
    ~*Zermelo                                1;
    ~*zermelo                                1;
    ~*Zeus                                   1;
    ~*zgrab                                  1;
    ~*Zitebot                                1;
    ~*zh\-CN                                 1;
    ~*ZmEu                                   1;
    ~*ZumBot                                 1;
    ~*Zyborg                                 1;
    ~*ZyBorg                                 1;
}
EOF

#----------------------------------------------------------------------------------------

exit 0
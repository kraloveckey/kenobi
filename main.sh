#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

#------------------------------------Variables-------------------------------------------

ROUTE="$PWD/main.sh"
MODULES="$PWD/modules"

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
    echo 'Usage: ./main.sh
 
This is an awesome bash script to make your life better.
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
exit_input() { echo -e "\nBye bye.\n"; exit 0; }
fail_input() { echo -e "\nWrong option."; }

ssh() { 
    sudo chmod 700 ${MODULES}/ssh.sh && sudo bash ${MODULES}/ssh.sh 
}

nginx() { 
    sudo chmod 700 ${MODULES}/nginx.sh && sudo bash ${MODULES}/nginx.sh 
}

apache2() { 
    sudo chmod 700 ${MODULES}/apache2.sh && sudo bash ${MODULES}/apache2.sh 
}

php() { 
    sudo chmod 700 ${MODULES}/php.sh && sudo bash ${MODULES}/php.sh 
}

postgresql-14() { 
    sudo chmod 700 ${MODULES}/postgresql-14.sh && sudo bash ${MODULES}/postgresql-14.sh 
}

mysql() { 
    sudo chmod 700 ${MODULES}/mysql.sh && bash ${MODULES}/mysql.sh 
}

mariadb() { 
    sudo chmod 700 ${MODULES}/mariadb.sh && sudo bash ${MODULES}/mariadb.sh 
}

audit() { 
    sudo chmod 700 ${MODULES}/audit.sh && sudo bash ${MODULES}/audit.sh 
}

artillery() { 
    sudo chmod 700 ${MODULES}/artillery.sh && sudo bash ${MODULES}/artillery.sh 
}

limits() { 
    sudo chmod 700 ${MODULES}/limits.sh && sudo bash ${MODULES}/limits.sh 
}

moodle() { 
    sudo chmod 700 ${MODULES}/moodle.sh && sudo bash ${MODULES}/moodle.sh 
}

monitoring() { 
    sudo chmod 700 ${MODULES}/monitoring.sh && sudo bash ${MODULES}/monitoring.sh
}

fail2ban() { 
    sudo chmod 700 ${MODULES}/fail2ban.sh && sudo bash ${MODULES}/fail2ban.sh
}

# Menu Function.
menu() {

echo -ne "
$(yellow_print 'xInstaller Main Menu')
$(cyan_print '1)') ssh
$(green_print '2)') nginx
$(blue_print '3)') apache2
$(magenta_print '4)') nginx+php
$(cyan_print '5)') php
$(green_print '6)') postgresql-14
$(blue_print '7)') mysql
$(magenta_print '8)') mariadb
$(cyan_print '9)') audit-linux
$(green_print '10)') artillery
$(blue_print '11)') limits
$(magenta_print '12)') moodle
$(cyan_print '13)') monitoring
$(green_print '14)') fail2ban
$(red_print '0)') Exit
\nChoose an option: "
    read -r ans
    case $ans in
    1)
        ssh
        menu
        ;;
    2)
        nginx
        menu
        ;;
    3)
        apache2
        menu
        ;;
    4)
        nginx
        php
        menu
        ;;
    5)
        php
        menu
        ;;
    6)
        postgresql-14
        menu
        ;;
    7)
        mysql
        menu
        ;;
    8)
        mariadb
        menu
        ;;
    9)
        audit
        menu
        ;;
    10)
        artillery
        menu
        ;;
    11)
        limits
        menu
        ;;
    12)
        nginx
        moodle
        mysql
        menu
        ;;
    13)
        monitoring
        menu
        ;;
    14)
        fail2ban
        menu
        ;;
    0)
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
    echo -e "\nPath to the script: ${ROUTE}"
    menu
}

#----------------------------------------------------------------------------------------

main "$@"

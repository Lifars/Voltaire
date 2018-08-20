#!/bin/bash

# exit on the first error or unbound variable use.
set -eu

# global variables
dependencies=('volatility' 'python')
voltaire="voltairedb.py"

# params: none.
# description: display usage.
function usage()
{
    echo "usage: ${0} -s <source> -d <destination> -p <profile> -r <command> -c <case> [-e]"
    echo
    echo "    <source>     : image source to be analyzed."
    echo "    <destination>: output directory."
    echo "    <profile>    : Volatility image profile identification."
    echo "    <command>    : [scan|process] voltaire arguments."
    echo "    <case>       : evidence number (ESXX)."
    echo "    -e           : if used, will encrypt database file."
    echo

    exit 1
}

# params: none.
# description: check if we have root permissions.
function check_root()
{
    if [ "$(id -u)" -ne 0 ]; then
        echo "error: you need root permissions."
        exit 1
    fi

    return 0
}

# params: none.
# description: check if voltaire script is present.
function check_voltaire()
{
    if [ ! -f "${voltaire}" ]; then
        echo "error: we couldn't find ${voltaire} script."
        exit 1
    fi

    return 0
}

# params:
#   $1 : distro identification.
# description: check if the packages are installed already.
function is_installed()
{
    declare distro

    distro="$1"
    case "${distro}" in
    arch)
        if ! pacman -Qi "${dependencies[@]}" &>> /dev/null; then
            echo "DEBUG: dependencies for ARCH based distro aren't met..."
            return 1
        fi
        ;;
    debian)
        if ! dpkg -s "${dependencies[@]}" &>> /dev/null; then
            echo "DEBUG: dependencies for DEBIAN based distro aren't met..."
            return 1
        fi
        ;;
    *)
        echo "error: something wrong happened. Exiting..."
        ;;
    esac

    return 0
}

# params: nome.
# description: check for distro identification and for $dependencies, install if not met.
function check_os()
{
    local os
    
    # source os-release file containing os information.
    if [ -f "/etc/os-release" ]; then
        source "/etc/os-release"
        os="${ID}"
    else
        os="Unknown"
    fi

    # take action according to distro.
    case "${os}" in
    arch|blackarch|mantos)
        if ! is_installed "arch"; then
            echo "DEBUG: installing dependencies for ARCH based distro..."
            pacman -Sy volatility --needed --noconfirm
        fi
        echo "DEBUG: dependencies are okay for ARCH based distro."
        ;;
    kali|debian|ubuntu)
        if ! is_installed "debian"; then
            echo "DEBUG: installing dependencies for DEBIAN based distro..."
            apt-get update
            apt-get --yes install volatility
        fi
        echo "DEBUG: dependencies are okay for DEBIAN based distro."
        ;;
    *)
        echo "error: could not find the OS identification. Exiting..."
        exit 1
        ;;
    esac

    return 0
}

# params:
#   $1 - database output file.
# description: check if db file from voltaire was created and encrypt it.
function encrypt_database()
{
    local database md5
    
    database="$1"
    if [ ! -f "${database}" ]; then
        echo "error: there is not database output."
        exit 1
    fi
    
    md5="$(md5sum ${database} | awk '{ print $1 }')"
    mv -f "${database}" "${md5}.db"
        
    if ! tar czf "${md5}.tar.gz" "${md5}.db" &>> /dev/null; then
        echo "error: trying to get tar.gz file from database."
        exit 1
    fi
    
    # TODO : encrypt database tar'ed file.
    
    return 0
}

# params: 
#   $1 - source file.
#   $2 - destination directory.
#   $3 - profile id for Volatility.
#   $4 - evidence case number.
#   $5 - command to run.
# description: run voltaire python script with args from caller.
function run_voltaire()
{
    local source destination profile evidence run
    
    source="$1"
    destination="$2"
    profile="$3"
    evidence="$4"
    run="$5"
    
    if [ ! -d "${destination}" ]; then
        mkdir -p "${destination}"
    fi
    
    python2 "${PWD}/${voltaire}" "${run}" -s "${source}" -d "${PWD}/${destination}" \
        -e "${evidence}" -p "${profile}"
    
    return 0
}

# params:
#   $@ - from caller (all args from caller, needs to be parsed if necessary).
# description: entry point of the script.
function main()
{
    # local variables
    local source destination profile case run encrypt
    
    if [ "$#" -lt 10 ]; then
        usage
    fi
    
    encrypt="false"
    
    # get args from caller
    while getopts "s:d:p:c:r:e" option; do
        case "${option}" in
        s)
            source="${OPTARG}" ;;
        d)
            destination="${OPTARG}" ;;
        p)
            profile="${OPTARG}" ;;
        c)
            case="${OPTARG}" ;;
        r)
            run="${OPTARG}" ;;
        e)
            encrypt="true" ;;
        *)
            usage ;;
        esac
    done

    # check if we are root, exit if not.
    check_root

    # check if voltaire is present, if not exit (there is no need to continue).
    check_voltaire

    # check what os we have and take actions.
    check_os
    
    # run voltaire on the memory image
    run_voltaire "${source}" "${destination}" "${profile}" "${case}" "${run}"

    # check if database file was created and encrypt it, if asked to.
    if [ "${encrypt}" = "true" ]; then
        encrypt_database "${PWD}/${destination}/ES${case}.db"
    fi

    return 0
}

main "${@}"

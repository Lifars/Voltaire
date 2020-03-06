#!/bin/bash

# exit on the first error or unbound variable use.
set -eu

# dependencies variables, separated by distro
archdeps=('volatility' 'python2' 'python2-networkx' 'python2-setuptools')
debiandeps=('volatility' 'python' 'python-networkx' 'python-setuptools')

# voltaire python script name
voltaire="voltairedb.py"

# params: none.
# description: display usage.
function usage()
{
    echo "usage: ${0} -s <source> -d <destination> -p <profile> -r <command> -c <case> [-e|-n]"
    echo
    echo "    <source>     : image source to be analyzed."
    echo "    <destination>: output directory."
    echo "    <profile>    : Volatility image profile identification."
    echo "    <command>    : [scan|dump] voltaire arguments."
    echo "    <case>       : evidence number (ESXX)."
    echo "    -h           : Show usage."
    echo "    -e           : if used, will encrypt database file."
    echo "    -n           : if used, will specify number of processes to scan simultaneously, by defaut 4."
    echo "    -x           : if used, will specify the commands in comma separated string, to exclude from running Volatility scan."
    echo "    -r <command> : 
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
    local distro

    distro="$1"

    case "${distro}" in
    arch)
        if ! pacman -Qi "${archdeps[@]}" &>> /dev/null; then
            echo "Info: dependencies for ARCH based distro aren't met..."
            return 1
        fi
        ;;
    debian)
        if ! dpkg -s "${debiandeps[@]}" &>> /dev/null; then
            echo "Info: dependencies for DEBIAN based distro aren't met..."
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
            echo "Info: installing dependencies for ARCH based distro..."
            sudo pacman -Sy "${archdeps[@]}" --needed --noconfirm
        fi
        echo "Info: dependencies are okay for ARCH based distro."
        ;;
    kali|debian|ubuntu)
        if ! is_installed "debian"; then
            echo "Info: installing dependencies for DEBIAN based distro..."
            sudo apt-get update
            sudo apt-get --yes install "${debiandeps[@]}"
        fi
        echo "Info: dependencies are okay for DEBIAN based distro."
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
#   $@ - from caller (all args from caller, needs to be parsed if necessary).
# description: entry point of the script.
function main()
{
    # local variables
    local source destination profile evidence run encrypt options

    if [ "$#" -lt 1 ]; then
        usage
    fi

    # default variable values
    source="$1"
    encrypt="false"
    destination="output"
    profile=""
    exclude=""
    processes=4
    evidence="01"
    run="scan"
    options=()

    # get args from caller
    while getopts "s:d:p:c:r:n:x:h:e" option; do
        case "${option}" in
        s)
            source="${OPTARG}" ;;
        d)
            destination="${OPTARG}" ;;
        p)
            profile="${OPTARG}" ;;
        c)
            evidence="${OPTARG}" ;;
        r)
            run="${OPTARG}" ;;
        x)
            exclude="${OPTARG}" ;;
        n)
            processes="${OPTARG}" ;;
        e)
            encrypt="true" ;;
        h)
            usage ;;
        *)
            usage ;;
        esac
    done

    # check if we are root, exit if not.
    #check_root

    # check if voltaire is present, if not exit (there is no need to continue).
    check_voltaire

    # check what os we have and take actions.
    check_os

    # run voltaire on the memory image
    options=("${run}" "-s" "${source}" "-d" "${destination}" "-e" "${evidence}")

    if [ ! -f "${source}" ]; then
        echo "error: ${source} is not a file."
        exit 1
    fi

    if [ ! -z "${profile}" ]; then
        options+=("-p" "${profile}")
    fi

    if [ ! -z "${processes}" ]; then
        options+=("-n" "${processes}")
    fi

    if [ ! -z "${exclude}" ]; then
        echo "exclude=${exclude}"
        options+=("--exclude_commands" "${exclude}")
    fi

    python2 "${PWD}/${voltaire}" "${options[@]}"

    # check if database file was created and encrypt it, if asked to.
    if [ "${encrypt}" = "true" ]; then
        encrypt_database "${PWD}/${destination}/ES${case}.db"
    fi

    return 0
}

main "${@}"

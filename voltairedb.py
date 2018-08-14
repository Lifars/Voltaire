#!/usr/bin/env python
# voltairedb.py
# Short rewrite of voltaire.py to make use of the SQLite3 renderer.

import argparse
import os
import re
import sys
from sys import platform as _platform
from subprocess import call
import sqlite3

# Global variables
# OS we are using
IS_WINDOWS = _platform == "win32"

PROGRAM = os.path.abspath("vol.exe") if IS_WINDOWS \
                                     else os.path.abspath("vol.py")

# Valid profiles
VALID_PROFILES = dict.fromkeys(
    ["VistaSP0x64", "VistaSP0x86", "VistaSP1x64", "VistaSP1x86", "VistaSP2x64",
     "VistaSP2x86", "Win10x64", "Win10x86", "Win2003SP0x86", "Win2003SP1x64",
     "Win2003SP1x86", "Win2003SP2x64", "Win2003SP2x86",
     "Win2008R2SP0x64", "Win2008R2SP1x64", "Win2008SP1x64", "Win2008SP1x86",
     "Win2008SP2x64", "Win2008SP2x86", "Win2012R2x64", "Win2012x64",
     "Win7SP0x64", "Win7SP0x86", "Win7SP1x64", "Win7SP1x86", "Win81U1x64",
     "Win81U1x86", "Win8SP0x64", "Win8SP0x86", "Win8SP1x64", "Win8SP1x86",
     "WinXPSP1x64", "WinXPSP2x64", "WinXPSP2x86", "WinXPSP3x86"])

COMMANDS = ["amcache", "apihooks", "atoms", "atomscan", "bigpools", "bioskbd",
            "cachedump", "clipboard", "cmdline", "cmdscan", "consoles",
            "connscan", "crashinfo", "devicetree", "dlllist", "dumpfiles",
            "dumpregistry", "envars", "filescan", "hashdump", "iehistory",
            "ldrmodules", "lsadump", "malfind", "messagehooks",
            "modscan", "modules", "mutantscan -s", "netscan",
            "notepad", "pslist", "psscan", "pstree", "psxview", "screenshot",
            "sessions", "shellbags", "shimcache", "shutdowntime", "sockets",
            "sockscan", "svcscan", "timeliner", "truecryptmaster",
            "truecryptpassphrase", "truecryptsummary", "unloadedmodules",
            "windows", "wintree", "connections", "userassist"]

COMMANDS_WITH_PROCESSES = [
    "apihooks", "dlldump", "malfind", "procdump"
]

DUMP_COMMANDS = [
    "dlldump", "procdump", "dumpfiles"
]

NON_DB_COMS = ["dumpregistry", "filescan", "iehistory", "screenshot",
               "truecryptmaster", "truecryptpassphrase",
               "truecryptsummary", "windows", "wintree", "userassist"]

# Regex string of public ip addresses that are excluded
PUBLIC_IP_ADDRESSES_TO_EXCLUDE = '|'.join([
    "(^0\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\." + \
    "([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\." + \
    "([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5])))",
    "(^10\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\." + \
    "([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\." + \
    "([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5])))",
    "(^100\.(6[4-9]|[7-9][0-9]|1([0-1][0-9]|2[0-7]))\." + \
    "([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\." + \
    "([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5])))",
    "(^127\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\." + \
    "([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\." + \
    "([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5])))",
    "(^169\.254\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\." + \
    "([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5])))",
    "(^172\.(1[6-9]|2[0-9]|3[0-1])\." + \
    "([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\." + \
    "([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5])))",
    "(^192\.0\.0\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5])))",
    "(^192\.0\.2\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5])))",
    "(^192\.88\.99\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5])))",
    "(^192\.168\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\." + \
    "([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5])))",
    "(^198\.(1[8-9])\." + \
    "([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\." + \
    "([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5])))",
    "(^198\.51\.100\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5])))",
    "(^203\.0\.113\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5])))",
    "(^(2(2[4-9]|3[0-9]))\." + \
    "([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\." + \
    "([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\." + \
    "([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5])))",
    "(^(2(4[0-9]|5[0-5]))\." + \
    "([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\." + \
    "([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\." + \
    "([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5])))"])

# Regex to see if a string is an ip address
VALID_IP_ADDRESSES = \
                   "^([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))" + \
                   "\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))" + \
                   "\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))" + \
                   "\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))"

# Functions
def individual_scan(comargs, command):
    global PROGRAM
    run_command(comargs, PROGRAM, command, None)

def scan(comargs):
    global PROGRAM
    is_valid(comargs)
    for command in COMMANDS:
        run_command(comargs, PROGRAM, command, None)

def scan_pid(comargs):
    global PROGRAM
    path = os.path.abspath(comargs["dest"]) + os.sep
    logfile = "{path}ps_dump.txt".format(path=path)
    for command in COMMANDS_WITH_PROCESSES:
        if not os.path.exists(path + command):
            os.makedirs(path + command)
        with open(logfile) as logf:        # Suppressed encoding='utf-8'
            for line in logf:
                word = line.split()
                run_command(comargs, PROGRAM, command, word[0])

def dump_pid(args):
    path = os.path.abspath(args["dest"]) + os.sep
    fullpath = "{path}ES{number}.db".format(path=path,
                                            number=args["es"])
    ps_dump = "{path}ps_dump.txt".format(path=path)
    ps_dump_file = open(ps_dump, "w")   # Suppressed encoding='utf-8'
    pid_dict = {}
    pid_dict.update(get_process(fullpath))
    for key in sorted(pid_dict, key=float):
        ps_dump_file.write(key + "\n")

def get_process(fullpath):
    """ Returns a dictionary with all the PIDs found by PSList, PSScan,
        PSTree and PsXview.
    """
    temp_dict = {}
    dbconn = sqlite3.connect(fullpath)
    dbcursor = dbconn.cursor()
    queries = [("PID", "PSList"),
               ("PID", "PSScan"),
               ("Pid", "PSTree"),
               ("PID", "PsXview")]
    for qfield, qtable in queries:
        query = "SELECT {field} from {table}".format(field=qfield,
                                                     table=qtable)
        print query
        for row in dbcursor.execute(query):
            for item in row:
                temp_dict[item] = None
    dbconn.close()
    return temp_dict

def filter_mutantscan(args):
    path = os.path.abspath(args["dest"]) + os.sep
    logfile = "{path}ES{number}_{command}.txt".format(path=path,
                                                      number=args["es"],
                                                      command="mutantscan-s")
    outfile = "{path}mutantscan_filter.txt".format(path=args["dest"] + os.sep)
    open_outfile = open(outfile, "w")       # Suppressed encoding='utf-8'

    name_map = {}

    with open(logfile) as f:                # Suppressed encoding='utf-8'
        add_line_flag = 0
        open_outfile.write(next(f))
        open_outfile.write(next(f))
        for line in f:
            for word in line.split():
                if not re.search("0x\w{16}|\.\.\.", word) and \
                   not word.isdigit():
                    add_line_flag = 1

            if add_line_flag == 1:
                name_map[word] = line
                add_line_flag = 0

        for key in sorted(name_map, key=lambda v: v.upper()):
            open_outfile.write(name_map[key])

def filter_netscan(args):
    path = os.path.abspath(args["dest"]) + os.sep
    logfile = "{path}ES{number}_{command}.txt".format(path=path,
                                                      number=args["es"],
                                                      command="netscan")
    outfile = "{path}netscan_filter.txt".format(path=args["dest"] + os.sep)
    open_outfile = open(outfile, "w")       # Suppressed encoding='utf-8'

    with open(logfile) as f:                # Suppressed encoding='utf-8'
        open_outfile.write(next(f))
        for line in f:
            if is_in_range(line):
                open_outfile.write(line)

def is_in_range(line):
    add_line_flag = 0
    for word in line.split():
        if re.search(VALID_IP_ADDRESSES, word) and \
           not re.search(PUBLIC_IP_ADDRESSES_TO_EXCLUDE, word):
            add_line_flag = 1
            break
    return add_line_flag == 1

def is_valid(args):
    args["src"] = "\"{path}\"".format(path=os.path.abspath(args["src"]))
    args["dest"] = os.path.abspath(args["dest"])
    if "src" in args:
        print "Source file: {src}".format(src=args["src"])
    if "dest" in args:
        if not os.path.exists(args["dest"]):
            os.makedirs(args["dest"])
        print "Destination directory: {dest}".format(dest=args["dest"])
    if "profile" in args:
        if args["profile"] in VALID_PROFILES:
            print "Profile name: {profile}".format(profile=args["profile"])
        else:
            print "Profile not valid: {profile}".format(profile=args["profile"])
            sys.exit(1)
    else:
        print "WARNING: No profile set!"
    if "es" in args:
        print "ES: {es}".format(es=args["es"])
    else:
        print "NOTICE: No ES set. Defaulting to ES=1."

def run_command(args, executable, command, pid):
    path = args["dest"] + os.sep
    if command in NON_DB_COMS:
        outfile = "{path}ES{number}-{command}.txt".format(path=path,
                                                          number=args["es"],
                                                          command=command)
        outflag = "--output=text --output-file="
    else:
        outfile = "{path}ES{number}.db".format(path=path,
                                               number=args["es"],
                                               command=command)
        outflag = "--output=sqlite --output-file="
    command_with_flag = command
    outlog = open(args["log"], "at")
    if command in COMMANDS_WITH_PROCESSES:
        outfile = "{path}ES{number}.db".format(path=path,
                                               number=args["es"])
        if command in DUMP_COMMANDS:
            outflag = "--dump-dir="
            outfile = "{path}{command}".format(path=path, command=command)
            if re.search("dlldump", command):
                outfile += "{command}_{pid}".format(command=os.sep + command,
                                                    pid=pid)
                if not os.path.exists(outfile):
                    os.makedirs(outfile)
        command_with_flag = "{command} -p {pid}".format(command=command,
                                                        pid=pid)
    if "profile" in args:
        params = "-f {src} --profile={profile} {command} {destflag}\"{dest}\""
        params = params.format(src=args["src"],
                               profile=args["profile"],
                               command=command_with_flag,
                               destflag=outflag,
                               dest=outfile)
    else:
        params = "-f {src} {command} {destflag}\"{dest}\""
        params = params.format(src=args["src"],
                               command=command_with_flag,
                               destflag=outflag,
                               dest=outfile)
    outlog.write("{program} {params}\n".format(program=executable,
                                               params=params))
    print "Starting {program} {params}".format(program=executable,
                                               params=params)
    result = call("{program} {params}".format(program=executable,
                                              params=params),
                  shell=True, stdout=outlog, stderr=outlog)
    if result == 0:
        print "Completed {command}".format(command=command_with_flag)
    else:
        print "Error running {command}".format(command=command_with_flag)
    print "Volatility files saved to {dest}".format(dest=args["dest"])
    outlog.close()

def export_autorun(args):
    """ Dumps all the keys related to autorun, if present.
    """
    path = args["dest"] + os.sep
    outfile = "{path}ES{number}_autorun.txt".format(path=path,
                                                    number=args["es"])
    outlog = open(args["log"], "at")
    print "Starting exporting autorun keys."
    outlog.write("Starting exporting autorun keys.\n")
    if "profile" in args:
        params = "-f {src} --profile={profile} " + \
                 "printkey -K \"software\\microsoft\\windows" + \
                 "\\currentversion\\run\" " + \
                 "--output=text --output-file={dest}"
        params = params.format(src=args["src"],
                               profile=args["profile"],
                               dest=outfile)
    else:
        params = "-f {src} printkey -K \"software\\microsoft\\windows" + \
                 "\\currentVersion\\run\" " + \
                 "--output=text --output-file={dest}"
        params = params.format(src=args["src"],
                               dest=outfile)
    result = call("{program} {params}".format(program=PROGRAM,
                                              params=params),
                  shell=True, stdout=outlog, stderr=outlog)
    if result == 0:
        print "Completed autorun."
    else:
        print "Error running autorun \n " + params
    outlog.close()

def process(args):
    args["src"] = os.path.abspath(args["src"])
    args["dest"] = os.path.abspath(args["dest"])

# Main
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Batches " + \
                                                 "common Volatility commands")
    sub_parsers = parser.add_subparsers(dest="subparser_name")
    scan_parser = sub_parsers.add_parser('scan')
    scan_parser.set_defaults(which="scan")
    scan_parser.add_argument("-s", "--src",
                             help="Input file", required=True)
    scan_parser.add_argument("-d", "--dest",
                             help="Output directory", required=False,
                             default="voltaire")
    scan_parser.add_argument("-p", "--profile",
                             help="Profile name", required=False)
    scan_parser.add_argument("-e", "--es",
                             help="ES mode", default=1, required=False)
    scan_parser.add_argument("-l", "--log",
                             help="Log file (captures output)",
                             default="voltaire.log",
                             required=False)
    process_parser = sub_parsers.add_parser("process")
    process_parser.set_defaults(which="process")
    process_parser.add_argument("-s", "--src",
                                help="Input directory", required=True)
    process_parser.add_argument("-d", "--dest",
                                help="Output directory",
                                required=False, default="voltaire")
    args = vars(parser.parse_args())
    subcommand = args.get("which", "")
    if subcommand == "scan":
        scan(args)
        dump_pid(args)
        scan_pid(args)
        export_autorun(args)
        #filter_mutantscan(args)
        #filter_netscan(args)
    elif subcommand == "process":
        process(args)
    else:
        parser.print_help()

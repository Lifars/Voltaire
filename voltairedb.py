#!/usr/bin/env python
# voltairedb.py
# Short rewrite of voltaire.py to make use of the SQLite3 renderer.

import argparse
import os
import sys
from sys import platform as _platform
from subprocess import call
import sqlite3
import tempfile
from distutils.spawn import find_executable
from multiprocessing import Pool

from sans_check_image_path import check_image_path
from sans_check_parent import check_parent
from check_dll_path import check_dll_path

# Global variables
# OS we are using
from sans_check_user_account import check_user_account

IS_WINDOWS = _platform == "win32"

PROGRAM = os.path.abspath("vol.exe") if IS_WINDOWS \
                                     else find_executable('vol.py') # automatically find vol.py



# Valid profiles
# Based on https://github.com/volatilityfoundation/volatility/blob/master/README.txt#L170
VALID_PROFILES = dict.fromkeys(
    ["VistaSP0x64", "VistaSP0x86", "VistaSP1x64", "VistaSP1x86", "VistaSP2x64",
     "VistaSP2x86", "Win10x64", "Win10x64_10586", "Win10x64_14393", "Win10x86",
     "Win10x86_10586", "Win10x86_14393", "Win2003SP0x86", "Win2003SP1x64", "Win2003SP1x86",
     "Win2003SP2x64", "Win2003SP2x86", "Win2008R2SP0x64", "Win2008R2SP1x64",
     "Win2008R2SP1x64_23418", "Win2008SP1x64", "Win2008SP1x86", "Win2008SP2x64",
     "Win2008SP2x86", "Win2012R2x64", "Win2012R2x64_18340", "Win2012x64", "Win2016x64_14393",
     "Win7SP0x64", "Win7SP0x86", "Win7SP1x64", "Win7SP1x64_23418", "Win7SP1x86",
     "Win7SP1x86_23418", "Win81U1x64", "Win81U1x86", "Win8SP0x64", "Win8SP0x86",
     "Win8SP1x64", "Win8SP1x64_18340", "Win8SP1x86", "WinXPSP1x64", "WinXPSP2x64",
     "WinXPSP2x86", "WinXPSP3x86"])
# Commands to run
# Scan apihooks is the slowest scan, we make it fast by option -Q / --quick,
# which only scan some critical dlls.
# https://github.com/volatilityfoundation/volatility/blob/master/volatility/plugins/malware/apihooks.py#L361
COMMANDS = ["apihooks", "amcache", "atoms", "atomscan", "bigpools", "bioskbd",
            "cachedump", "clipboard", "cmdline", "cmdscan", "consoles",
            "connscan", "crashinfo", "devicetree", "dlllist", "dumpfiles",
            "dumpregistry", "envars", "filescan", "getsids", "hashdump", "iehistory",
            "ldrmodules", "lsadump", "malfind", "messagehooks",
            "modscan", "modules", "mutantscan -s", "netscan",
            "notepad", "pslist", "psscan", "pstree", "psxview", "screenshot",
            "sessions", "shellbags", "shimcache", "shutdowntime", "sockets",
            "sockscan", "svcscan", "timeliner", "truecryptmaster",
            "truecryptpassphrase", "truecryptsummary", "unloadedmodules",
            "windows", "wintree", "connections", "userassist"]
# Commands that do not log into the database.
NON_DB_COMS = ["dumpregistry", "filescan", "iehistory", "screenshot",
               "truecryptmaster", "truecryptpassphrase",
               "truecryptsummary", "windows", "wintree", "userassist"]

# Title for report and commands that generate a text output
TEXT_COMMANDS = [("AmCache Listing", "amcache"),
                 ("Malware Finder", "malfind")]

# Functions
def individual_scan(comargs, command):
    global PROGRAM
    run_command(comargs, PROGRAM, command, None)

def scan(comargs):
    global PROGRAM

    numOfProcesses = comargs["processes"]
    print "Scan with {processes} processes simultaneously".format(processes=numOfProcesses)
    pool = Pool(int(numOfProcesses))
    for command in COMMANDS:
        pool.apply_async(run_command, (comargs, PROGRAM, command, None))
    pool.close()
    pool.join()
    print "End of scan"

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

def is_valid(args):
    args["src"] = "\"{path}\"".format(path=os.path.abspath(args["src"]))
    args["dest"] = os.path.abspath(args["dest"])
    if "src" in args:
        print "Source file: {src}".format(src=args["src"])
    if "dest" in args:
        if not os.path.exists(args["dest"]):
            os.makedirs(args["dest"])
        print "Destination directory: {dest}".format(dest=args["dest"])
    is_valid_profile(args)
    if "es" in args:
        print "ES: {es}".format(es=args["es"])
    else:
        print "NOTICE: No ES set. Defaulting to ES=1."

def is_valid_profile(args):
    if "profile" in args and args["profile"] is not None:
        if args["profile"] in VALID_PROFILES:
            print "Profile name: {profile}".format(profile=args["profile"])
        else:
            print "Profile not valid: {profile}".format(profile=args["profile"])
            sys.exit(1)
    else:
        print "WARNING: No profile set!"


def run_command(args, executable, command, pid):
    path = args["dest"] + os.sep
    if command in NON_DB_COMS:
        # Only log to DB. Everything else is ignored.
        return
    else:
        outfile = "{path}ES{number}.db".format(path=path,
                                               number=args["es"],
                                               command=command)
        outflag = "--output=sqlite --output-file="
    command_with_flag = command
    outlog = open(args["log"], "at")
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

def run_text_report(comargs):
    """ Generates a text report from a few commands. """
    # Report name
    path = args["dest"] + os.sep
    outfile = "{path}ES{number}_report.txt".format(path=path,
                                                   number=args["es"])
    outargs = "--output=text"
    profargs = "--profile=%s"%(comargs['profile'])
    srcargs = "-f %s"%(comargs["src"])
    with open(outfile, "wt") as freport:
        freport.write("Volatility Memory Report\n")
        freport.write("========================\n\n")
        for (title, command) in TEXT_COMMANDS:
            freport.write(title+"\n")
            freport.write("*"*len(title)+"\n\n")
            tempoutput = tempfile.TemporaryFile("rwt")
            scode = call("%s %s %s %s %s"%(PROGRAM, command, outargs,
                                           profargs, srcargs),
                         stdout=tempoutput,
                         shell=True)
            if scode != 0:
                freport.write("Command '%s' did not complete successfully\n\n"%\
                              (command))
            else:
                tempoutput.seek(0)
                for outline in tempoutput:
                    freport.write(outline)
                freport.write("\n")
            tempoutput.close()

def dump_malfind(comargs):
    """ Dumps the processes identified by malfind """
    path = args["dest"] + os.sep
    dbfile = "{path}ES{number}.db".format(path=path,
                                          number=args["es"])
    dbconn = sqlite3.connect(dbfile)
    dbcursor = dbconn.cursor()
    # Create the table
    query = """create table if not exists procdumps_malfind (pid integer primary key,
                                                     reason text,
                                                     content blob)"""
    dbcursor.execute(query)
    dbconn.commit()
    query = "select distinct pid from malfind"
    dbcursor.execute(query)
    # Although directly use "dbcursor.execute(query)" will have better performance, because getting query's rows lazily. It has issue that there will be repeated rows even with "distinct", when works together with dbcursor2 "insert".
    # Need to use fetchall to get all rows ahead.
    allRows = dbcursor.fetchall()

    for row in allRows:
        pid = row[0]
        print "Dumping process for PID %s" % (pid)
        output = tempfile.mkdtemp()
        dumpargs = "--dump-dir=%s" % (output)
        profargs = "--profile=%s" % (comargs['profile'])
        srcargs = "-f %s" % (comargs["src"])
        pidargs = "-p %s" % (pid)
        scode = call("%s procdump %s %s %s %s"%(PROGRAM,
                                                profargs,
                                                srcargs,
                                                dumpargs,
                                                pidargs),
                     shell=True)
        if scode != 0:
            print "Dumping process memory for pid %s failed." % (pid)
        else:
            # Get all files in the temporary output
            dfiles = [os.path.join(output, ent) for ent in os.listdir(output) \
                      if os.path.isfile(os.path.join(output, ent))]
            if dfiles == []:
                print "Process not in memory."
                continue
            dfile = open(dfiles[0], "rb")
            filec = dfile.read()
            dfile.close()
            dbcursor2 = dbconn.cursor()
            dbcursor2.execute("insert into procdumps_malfind "+
                              "(pid,reason,content) values (?,'Malfind',?)",
                              (pid, sqlite3.Binary(filec)))
            dbconn.commit()
            os.unlink(dfiles[0])
        os.rmdir(output)

def dump(comargs):
    """ Dumps the process identified by PID from the memory image.
        Due to the possible large size, the dump is in a file and not in
        the database.
    """
    comargs["src"] = os.path.abspath(comargs["src"])
    comargs["dest"] = os.path.abspath(comargs["dest"])
    dump_dir = comargs["dest"] + os.sep + \
               "dumps" + os.sep + \
               "ES%s"%(comargs["es"])
    comargs["dest"] = dump_dir
    cliargs = "procdump -f %s --profile=%s " % \
              (comargs["src"],
               comargs["profile"])
    cliargs += "--pid=%s --dump-dir=\"%s\"" % \
               (str(comargs["pid"]),
                dump_dir)
    scode = call("%s %s"%(PROGRAM,
                          cliargs),
                 shell=True)
    if scode != 0:
        print "Dumping process memory for pid %s failed." % (comargs["pid"])
    else:
        print "Dumping process memory for pid %s succesfull." % (comargs["pid"])

def detect_profile(program, comargs):
    """ Run imageinfo on the provided image, ask the user to choose
        a profile if more than one profile are suggested.
        If too many profiles are present in the output, it is possible that it
        will be truncated. In that case, run a manual detection.
    """
    print "Attempting automatic detection of the image profile."
    tempoutput = tempfile.TemporaryFile("rwt")
    params = "imageinfo -f {src}".format(src=comargs['src'])
    result = call("{program} {params}".format(program=program,
                                              params=params),
                  shell=True, stdout=tempoutput)
    if result != 0:
        print "imageinfo failed."
        return False
    tempoutput.seek(0)
    profline = ""
    for i in tempoutput:
        if i.find("Suggested Profile(s) :") > 0:
            # We got the line.
            profline = i.rstrip()
            break
    tempoutput.close()
    if profline == "":
        # imageinfo could not identify at least one profile. Abort.
        return False
    inst_index = profline.find("(Instantiated")
    if inst_index == -1:
        # when there is no "(Instantiated", get string to the end
        profline = profline[33:]
    else:
        profline = profline[33:inst_index]
    print "profline2={profline}".format(profline=profline)
    profiles = profline.split(",")
    if profiles == []:
        return False
    if len(profiles) == 1:
        comargs['profile'] = profiles[0].rstrip().lstrip()
        return True
    valid = False
    while not valid:
        print "Choose a profile."
        print "================="
        print ""
        nprof = 0
        for entry in profiles:
            nprof += 1
            print "{id:>2} : {profile}".format(id=nprof,
                                               profile=entry.rstrip().\
                                                             lstrip())
        print ""
        choice = raw_input("Profile number? ")
        if int(choice) > 0 and int(choice) <= nprof:
            valid = True
        print "Please select a profile."
    comargs["profile"] = profiles[int(choice)-1].lstrip().rstrip()
    is_valid_profile(comargs)
    return True

def exclude_commands(comargs):
    """
    parse comma seperated "exclude_commands" args into exclude_command_list
    remove exclude_command_list from COMMANDS
    in order to exclude long-running Volatility scanning
    :param comargs:
    :return:
    """
    global COMMANDS
    arg_exclude_commands = comargs.get("exclude_commands")
    if (arg_exclude_commands is None) :
        return

    print "Specify exclude commands:{exclude}".format(exclude=arg_exclude_commands)
    exclude_command_list = arg_exclude_commands.split(",")
    COMMANDS = filter(lambda  i: i not in exclude_command_list, COMMANDS)
    print "COMMANDS after exclusion:{COMMANDS}".format(COMMANDS=COMMANDS)


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
                             help="ES number", default=1, required=False)
    scan_parser.add_argument("-l", "--log",
                             help="Log file (captures output)",
                             default="voltaire.log",
                             required=False)
    scan_parser.add_argument("-n", "--processes",
                             help="Number of processes to scan simultaneously",
                             default=4,
                             required=False)
    scan_parser.add_argument("--exclude_commands",
                             help="Specify the commands need to be excluded from predefined COMMAMDS, in comma seperated string",
                             required=False)
    dump_parser = sub_parsers.add_parser("dump")
    dump_parser.set_defaults(which="dump")
    dump_parser.add_argument("-s", "--src",
                             help="Input directory", required=True)
    dump_parser.add_argument("-d", "--dest",
                             help="Output directory",
                             required=False, default="voltaire")
    dump_parser.add_argument("-p", "--profile",
                             help="Profile name",
                             required=True)
    dump_parser.add_argument("-i", "--pid",
                             help="PID of the process to dump",
                             required=True)
    dump_parser.add_argument("-e", "--es",
                             help="ES number", default=1, required=False)
    args = vars(parser.parse_args())
    is_valid(args)
    subcommand = args.get("which", "")
    exclude_commands(args)
    if subcommand == "scan":
        if args["profile"] is None:
            # Profile detection
            if not detect_profile(PROGRAM, args):
                # Profile detection unsuccessful.
                print "Profile detection failed. Please provide a valid profile"
                sys.exit(-1)
        # Run the analysis, first DB then the two text commands
        scan(args)
        run_text_report(args)
        # Run the SANS tests and dump the offending processes in the DB
        check_parent(args)
        check_image_path(args)
        check_user_account(args)
        check_dll_path(args)
        # Run Malfind and dumps the offending processes in the DB
        dump_malfind(args)
        #export_autorun(args)
    elif subcommand == "dump":
        dump(args)
    else:
        parser.print_help()

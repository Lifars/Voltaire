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
    is_valid(comargs)
    for command in COMMANDS:
        run_command(comargs, PROGRAM, command, None)

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
    query = """create table if not exists malprocdump (pid integer primary key,
                                                       content blob)"""
    dbcursor.execute(query)
    dbconn.commit()
    query = "select distinct pid from malfind"
    for row in dbcursor.execute(query):
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
            dfile = open(dfiles[0], "rb")
            filec = dfile.read()
            dfile.close()
            dbcursor2 = dbconn.cursor()
            dbcursor2.execute("insert into malprocdump "+
                              "(pid,content) values (?,?)",
                              (pid, sqlite3.Binary(filec)))
            dbconn.commit()
            os.unlink(dfiles[0])
        os.rmdir(output)

def process(args):
    args["src"] = os.path.abspath(args["src"])
    args["dest"] = os.path.abspath(args["dest"])

def detect_profile(program, comargs):
    """ Run imageinfo on the provided image, ask the user to choose
        a profile if more than one profile are suggested.
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
    profline = profline[33:inst_index]
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
    return True

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
        if args["profile"] is None:
            # Profile detection
            if not detect_profile(PROGRAM, args):
                # Profile detection unsuccessful.
                print "Profile detection failed. Please provide a valid profile"
                sys.exit(-1)
        scan(args)
        run_text_report(args)
        dump_malfind(args)
        #export_autorun(args)
    elif subcommand == "process":
        process(args)
    else:
        parser.print_help()

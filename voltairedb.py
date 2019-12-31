#!/usr/bin/env python
# voltairedb.py
# Short rewrite of voltaire.py to make use of the SQLite3 renderer.


import argparse
import argparse
import os
import sys
from sys import platform as _platform
from subprocess import call
import sqlite3
import tempfile
import networkx as nx

# Global variables
# OS we are using
IS_WINDOWS = _platform == "win32"

PROGRAM = os.path.abspath("vol.exe") if IS_WINDOWS \
                                     else os.path.abspath("vol.py")
# SANS Test
# Each entry is indexed by "Applicable profile", and is
# "test name", "process name", "expected name".
# It checks that all processes called "process name" have a parent named
# "expected name". If a process has no parent, the parent name should be
# "<unknown>".
# "Applicable profile" is a partial match ("WinXP" will match all profiles
# for WinXP (WinXPSP0x86, WinXPSP1x86, ...)).
# Note that all entries are lowercased.

SANS_TEST = {"Win2003": (("svchost.exe", "svchost.exe", "services.exe"),
                         ("System", "system", "<unknown>"),
                         ("smss.exe", "smss.exe", "system")),
             "WinXP": (("svchost.exe", "svchost.exe", "services.exe"),
                       ("System", "system", "<unknown>"),
                       ("smss.exe", "smss.exe", "system")),
             "Win2008": (("System", "system", ""),
                         ("svchost.exe", "svchost.exe", "services.exe"),
                         ("wininit.exe", "wininit.exe", "<unknown>"),
                         ("taskhost.exe", "taskhost.exe", "services.exe"),
                         ("lsass.exe", "lsass.exe", "wininit.exe"),
                         ("winlogon.exe", "winlogon.exe", "<unknown>"),
                         ("csrss.exe", "csrss.exe", "<unknown>"),
                         ("services.exe", "services.exe", "wininit.exe"),
                         ("lsm.exe", "lsm.exe", "wininit.exe"),
                         ("explorer.exe", "explorer.exe", "<unknown>"))}

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
# Commands to run
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
    query = """create table if not exists procdumps (pid integer primary key,
                                                     reason text,
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
            if dfiles == []:
                print "Process not in memory."
                continue
            dfile = open(dfiles[0], "rb")
            filec = dfile.read()
            dfile.close()
            dbcursor2 = dbconn.cursor()
            dbcursor2.execute("insert into procdumps "+
                              "(pid,reason,content) values (?,'Malfind',?)",
                              (pid, sqlite3.Binary(filec)))
            dbconn.commit()
            os.unlink(dfiles[0])
        os.rmdir(output)
def build_process_tree(comargs):
    """ Returns a networkx directed graph with the process hierarchhy in it.
    """
    path = comargs["dest"] + os.sep
    dbfile = "{path}ES{number}.db".format(path=path,
                                          number=comargs["es"])
    dbconn = sqlite3.connect(dbfile)
    dbcursor = dbconn.cursor()
    query = "SELECT Pid, PPid, Name from PsTree"
    results = dbcursor.execute(query)
    # Check what field goes where
    nfield = 0
    index_pid = -1
    index_ppid = -1
    index_name = -1
    for field in dbcursor.description:
        if field[0] == "Name":
            index_name = nfield
        elif field[0] == "Pid":
            index_pid = nfield
        elif field[0] == "PPid":
            index_ppid = nfield
        nfield += 1
    proctree = nx.DiGraph()
    # Do work in two passes
    # 1) create all nodes
    # 2) create all edges (and add the missing nodes with "<unknown>" as the
    #    name
    reslist = results.fetchall()
    for row in reslist:
        procpid = row[index_pid]
        procname = row[index_name]
        proctree.add_node(procpid, name=procname.lower())
    for row in reslist:
        procpid = row[index_pid]
        procppid = row[index_ppid]
        if procppid not in proctree:
            proctree.add_node(procppid, name="<unknown>")
        proctree.add_edge(procppid, procpid)
    return proctree

def run_sans_tests(comargs):
    """ Uses the SANS 'Know Normal - Find Evil' criterion.
    """
    proctree = build_process_tree(comargs)
    path = comargs["dest"] + os.sep
    outfile = "{path}ES{number}_report.txt".format(path=path,
                                                   number=comargs["es"])
    suspiciouspid = []
    with open(outfile, "at") as freport:
        freport.write("SANS 'Know Normal ... Find Evil'\n")
        freport.write("********************************\n\n")
        # Find right set of tests
        for proftest in SANS_TEST.keys():
            if comargs['profile'].find(proftest) > -1:
                seltests = proftest
                freport.write("Running tests for %s.\n\n"%(seltests))
                break
        if seltests is None:
            freport.write("No test found for %s.\n\n"%(comargs['profile']))
            return
        for indtest in SANS_TEST[seltests]:
            tname, procname, pparname = indtest
            title = "Running %s test.\n" % (tname)
            freport.write(title)
            freport.write("-"*len(title)+'\n')
            roguefound = False
            for nodeid in proctree.nodes:
                if proctree.node[nodeid]['name'] == procname:
                    # Check parent's name (predecessors returns an iterable)
                    for ppid in proctree.predecessors(nodeid):
                        if proctree.node[ppid]['name'] != pparname:
                            # The parent name does not match what is expected
                            msg = "Found rogue %s (PID: %s), parent is "
                            msg += "%s (PID: %s)\n"
                            freport.write(msg%(proctree.node[nodeid]['name'],
                                               nodeid,
                                               proctree.node[ppid]['name'],
                                               ppid))
                            if nodeid not in suspiciouspid:
                                suspiciouspid.append(nodeid)
                            roguefound = True
            if not roguefound:
                freport.write("No rogue process found. \n")
            freport.write("\n")
    # Dump the suspicious processes into the database.
    dbfile = "{path}ES{number}.db".format(path=path,
                                          number=args["es"])
    dbconn = sqlite3.connect(dbfile)
    dbcursor = dbconn.cursor()
    # Create the table if it does not already exist.
    query = """create table if not exists procdumps (pid integer primary key,
                                                     reason text,
                                                     content blob)"""
    dbcursor.execute(query)
    dbconn.commit()
    for pid in suspiciouspid:
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
            # Insert the dumped file as a blob in the database.
            dfile = open(dfiles[0], "rb")
            filec = dfile.read()
            dfile.close()
            dbcursor2 = dbconn.cursor()
            dbcursor2.execute("insert or ignore into procdumps "+
                              "(pid,reason,content) values (?,'SANSTest',?)",
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
    is_valid(comargs)
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
                             help="ES number", default=1, required=False)
    scan_parser.add_argument("-l", "--log",
                             help="Log file (captures output)",
                             default="voltaire.log",
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
    subcommand = args.get("which", "")
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
        run_sans_tests(args)
        # Run Malfind and dumps the offending processes in the DB
        dump_malfind(args)
        #export_autorun(args)
    elif subcommand == "dump":
        dump(args)
    else:
        parser.print_help()

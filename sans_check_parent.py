#!/usr/bin/env python
# sans_check_parent.py
import argparse
import os
import sqlite3
import tempfile
from platform import _platform
from subprocess import call
from distutils.spawn import find_executable
import networkx as nx

# Global variables
# OS we are using
IS_WINDOWS = _platform == "win32"
PROGRAM = os.path.abspath("vol.exe") if IS_WINDOWS \
                                     else find_executable('vol.py') # automatically find vol.py
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

def check_parent(comargs):
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
            for nodeid in proctree.nodes():
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
                                          number=comargs["es"])
    dbconn = sqlite3.connect(dbfile)
    dbcursor = dbconn.cursor()
    # Create the table if it does not already exist.
    query = """create table if not exists procdumps_sansparent (pid integer primary key,
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
            dbcursor2.execute("insert or ignore into procdumps_sansparent "+
                              "(pid,reason,content) values (?,'SANSTest',?)",
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


# Main
# Example calling from shell:
#   python sans_check_parent.py  -p WinXPSP1x64 -d /home/sansforensics/Documents/code/Voltaire/output -e 01 -s "/home/sansforensics/Downloads/11420/MEM-APT10-VMWARE.vmsn"
if __name__ == "__main__":
    scan_parser = argparse.ArgumentParser(description="Check if process' parent is wanted, using SANS 'Know Normal - Find Evil' criterion")

    scan_parser.add_argument("-s", "--src", help="Input file", required=True)
    scan_parser.add_argument("-d", "--dest", help="Output directory", required=False, default="voltaire")
    scan_parser.add_argument("-p", "--profile", help="Profile name", required=False)
    scan_parser.add_argument("-e", "--es", help="ES mode", default=1, required=False)

    args = vars(scan_parser.parse_args())
    check_parent(args)


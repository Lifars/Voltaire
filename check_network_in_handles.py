#!/usr/bin/env python
# check_network_in_handles.py

import argparse
import os
import sqlite3
import tempfile
from platform import _platform
from subprocess import call
from distutils.spawn import find_executable


IS_WINDOWS = _platform == "win32"
PROGRAM = os.path.abspath("vol.exe") if IS_WINDOWS \
                                     else find_executable('vol.py') # automatically find vol.py


def check_network_in_handles(comargs) :
    """
    parse the output of handles for PID
    and object/object types \Device\Tcp, \Device\Udp and \Device\Ip
    to report possible network activity,
    even in the absence of reports from connscan/sockscan
    :param comargs:
    :return:
    """

    path = comargs["dest"] + os.sep
    dbfile = "{path}ES{number}.db".format(path=path,
                                          number=comargs["es"])
    dbconn = sqlite3.connect(dbfile)
    pidListDBCursor = dbconn.cursor()
    pidListQuery = "select distinct Pid from Handles where Details='\Device\Tcp' OR Details='\Device\Udp' OR Details='\Device\Ip'"
    pidListDBCursor.execute(pidListQuery)
    dbconn.commit()
    suspiciouspid = pidListDBCursor.fetchall()

    # write result to file
    path = comargs["dest"] + os.sep
    outfile = "{path}ES{number}_report.txt".format(path=path,
                                                   number=comargs["es"])

    with open(outfile, "at") as freport:
        title = "Checking possible network activities in handles"
        freport.write(title + "\n")
        freport.write("-" * len(title) + '\n')
        print title
        print "-" * len(title)

        findEvil = False
        for pid in suspiciouspid:
            freport.write("process: %s.\n" % pid)
            print "process: %s.\n" % pid
            findEvil = True

        if findEvil is False:
            freport.write("No rogue process found. \n")
            print "No rogue process found."

        freport.write("\n")
        print ""

    dbcursor = dbconn.cursor()
    # Create the table if it does not already exist.
    query = """create table if not exists procdumps (pid integer primary key,
                                                         reason text,
                                                         content blob)"""
    dbcursor.execute(query)
    dbconn.commit()
    for row in suspiciouspid:
        pid = row[0]
        print "Dumping process for PID %s" % (pid)
        output = tempfile.mkdtemp()
        dumpargs = "--dump-dir=%s" % (output)
        profargs = "--profile=%s" % (comargs['profile'])
        srcargs = "-f %s" % (comargs["src"])
        pidargs = "-p %s" % (pid)

        scode = call("%s procdump %s %s %s %s" % (PROGRAM,
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
            dbcursor2.execute("insert or ignore into procdumps " +
                              "(pid,reason,content) values (?,'SANSTest',?)",
                              (pid, sqlite3.Binary(filec)))
            dbconn.commit()
            os.unlink(dfiles[0])
        os.rmdir(output)

# Main
# Example calling from shell:
#   python check_network_in_handles.py  -d /home/sansforensics/Documents/code/Voltaire/output -e 01
if __name__ == "__main__":
    scan_parser = argparse.ArgumentParser(
        description="Check if pids are start with suspicious paths")

    scan_parser.add_argument("-d", "--dest", help="Output directory", required=False, default="voltaire")
    scan_parser.add_argument("-e", "--es", help="ES mode", default=1, required=False)

    args = vars(scan_parser.parse_args())

    check_network_in_handles(args)
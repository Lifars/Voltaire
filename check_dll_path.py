#!/usr/bin/env python
# check_dll_path.py

import argparse
import os
import sqlite3

# EVIL_PATH_LIST black list, need to think about how to detect with "C:\\"
EVIL_PATH_LIST = ["c:\\users\\",
                  "c:\\windows\\temp\\",
                  "c:\\temp\\",
                  "c:\\documents and settings\\"
                  ]


def check_dll_path(comargs):
    """
    Use the info from dlllist to identify DLLs, send warning when processes loaded from C:\Users, C:\Windows\Temp, C:\Temp or C:\Documents and Settings\
    :param comargs:
    :return:
    """
    path = comargs["dest"] + os.sep
    dbfile = "{path}ES{number}.db".format(path=path,
                                          number=comargs["es"])
    dbconn = sqlite3.connect(dbfile)
    dllListDBCursor = dbconn.cursor()
    dllListQuery = "select distinct Path from DllList"
    dllListDBCursor.execute(dllListQuery)
    dbconn.commit()
    dllList = dllListDBCursor.fetchall()

    # write result to file
    path = comargs["dest"] + os.sep
    outfile = "{path}ES{number}_report.txt".format(path=path,
                                                   number=comargs["es"])

    with open(outfile, "at") as freport:
        title = "Checking dlllist path"
        freport.write(title + "\n")
        freport.write("-" * len(title) + '\n')
        print title
        print "-" * len(title)

        findEvil = False
        for dll in dllList:
            for evil_path in EVIL_PATH_LIST:
                # print "dll={dll}".format(dll = dll)
                if dll[0].lower().startswith(evil_path):
                    freport.write("Invalid process: %s.\n" % dll)
                    print "Invalid process: %s.\n" % dll
                    findEvil = True

        if findEvil is False:
            freport.write("No rogue process found. \n")
            print "No rogue process found."

        freport.write("\n")
        print ""


# Main
# Example calling from shell:
#   python check_dll_path.py  -d /home/sansforensics/Documents/code/Voltaire/output -e 01
if __name__ == "__main__":
    scan_parser = argparse.ArgumentParser(
        description="Check if dlls are start with suspicious paths")

    scan_parser.add_argument("-d", "--dest", help="Output directory", required=False, default="voltaire")
    scan_parser.add_argument("-e", "--es", help="ES mode", default=1, required=False)

    args = vars(scan_parser.parse_args())

    check_dll_path(args)

#!/usr/bin/env python
#sans_check_user_account
import argparse
import os
import sqlite3


# Process, whose normal user account: Local System
LOCAL_SYSTEM_ACCOUNT_PROCESS = ["smss.exe",
                                "wininit.exe",
                                "winlogon.exe",
                                "csrss.exe",
                                "services.exe",
                                "lsaiso.exe",
                                "lsass.exe"]

def check_user_account(comargs):
    """ Uses the SANS 'Know Normal - Find Evil' criterion, to check the process which should have "User Account: Local System"
    """
    path = comargs["dest"] + os.sep
    dbfile = "{path}ES{number}.db".format(path=path,
                                          number=comargs["es"])
    dbconn = sqlite3.connect(dbfile)
    localSystemDBCursor = dbconn.cursor()

    # get distinct process name which is in LOCAL_SYSTEM_ACCOUNT_PROCESS and name="Local System"
    processQueryStr = getProcessQueryString()
    localSystemQuery = "select distinct Process from GetSIDs where Process in {process} and lower(name) = 'local system'".format(process=processQueryStr)
    localSystemDBCursor.execute(localSystemQuery)
    dbconn.commit()
    localSystemResult = localSystemDBCursor.fetchall()
    localSystemCount = len(localSystemResult)

    # get distinct process name which is in LOCAL_SYSTEM_ACCOUNT_PROCESS
    processDBCursor = dbconn.cursor()
    processQuery = "select distinct Process from GetSIDs where Process in {process} ".format(process=processQueryStr)
    processDBCursor.execute(processQuery)
    dbconn.commit()
    processResult = processDBCursor.fetchall()
    processCount = len(processResult)

    # write result to file
    path = comargs["dest"] + os.sep
    outfile = "{path}ES{number}_report.txt".format(path=path,
                                                   number=comargs["es"])
    with open(outfile, "at") as freport:
        title = "Checking \"User Account: Local System.\""
        freport.write(title + "\n")
        freport.write("-" * len(title) + '\n')
        print title
        print "-" * len(title)

        if localSystemCount != processCount:
            diffProcessSet = set(processResult) - set(localSystemResult)
            for diffProcess in diffProcessSet :
                freport.write("Invalid process: %s.\n" % diffProcess)
                print "Invalid process: %s.\n" % diffProcess
        else :
            freport.write("No rogue process found. \n")
            print "No rogue process found."
        freport.write("\n")
        print ""


def getProcessQueryString():
    """
    Construct string used in query, like:
        ("smss.exe", ..., "lsass.exe")
    :return:
    """
    processStr = repr(LOCAL_SYSTEM_ACCOUNT_PROCESS)
    processQueryList = list(processStr)
    processQueryList[0] = '('
    processQueryList[len(processQueryList) - 1] = ')'
    processQueryStr = ''.join(processQueryList)

    return processQueryStr



# Main
# Example calling from shell:
#   python sans_check_user_account.py  -d /home/sansforensics/Documents/code/Voltaire/output -e 01
if __name__ == "__main__":
    scan_parser = argparse.ArgumentParser(description="Check if processes are \"User Account: Local System\", using SANS 'Know Normal - Find Evil' criterion")

    scan_parser.add_argument("-d", "--dest", help="Output directory", required=False, default="voltaire")
    scan_parser.add_argument("-e", "--es", help="ES mode", default=1, required=False)

    args = vars(scan_parser.parse_args())

    check_user_account(args)
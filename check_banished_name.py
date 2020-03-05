#!/usr/bin/env python
#check_banished_name
import argparse
import os
import sqlite3

# todo, we can get from the MAR and use that to hunt for known malware
BANISHED_NAME_LIST = ["svhost.exe",
                    "svch0st.exe",
                    "svchos1.exe",
                    "svcho5t.exe",
                    "taskh0stw.exe",
                      "winl0g0n.exe",
                      "lsais0.exe",
                      "expl0rer.exe"]


def getProcessQueryString():
    """
    Construct string used in query, like:
        ("smss.exe", ..., "lsass.exe")
    :return:
    """
    processStr = repr(BANISHED_NAME_LIST)
    processQueryList = list(processStr)
    processQueryList[0] = '('
    processQueryList[len(processQueryList) - 1] = ')'
    processQueryStr = ''.join(processQueryList)

    return processQueryStr


def check_banished_name(comargs):
    """ To check if the process name is "svch0st.exe", which is supposed to be svchost.exe
    """
    path = comargs["dest"] + os.sep
    dbfile = "{path}ES{number}.db".format(path=path,
                                          number=comargs["es"])
    dbconn = sqlite3.connect(dbfile)
    banishedNameCursor = dbconn.cursor()
    processQueryStr = getProcessQueryString()
    banishedNameQuery = "select distinct Process from GetSIDs where Process in {process} ".format(process=processQueryStr)
    banishedNameResult = banishedNameCursor.execute(banishedNameQuery).fetchall()
    dbconn.commit()

    # todo, centralize the message and write file function
    # write result to file
    path = comargs["dest"] + os.sep
    outfile = "{path}ES{number}_report.txt".format(path=path,
                                                   number=comargs["es"])
    with open(outfile, "at") as freport:
        title = "Running banished process name check."
        freport.write(title + "\n")
        freport.write("-" * len(title) + '\n')
        print title
        print "-" * len(title)

        if banishedNameResult :
            for banishedNameProcess in banishedNameResult:
                freport.write("Banished name process: %s.\n" % (banishedNameProcess))
                print "Banished name process: %s.\n" % (banishedNameProcess)
        else :
            freport.write("No rogue process found. \n")
            print "No rogue process found."
        freport.write("\n")
        print""


# Main
# Example calling from shell:
# python check_banished_name.py  -d /home/sansforensics/Documents/code/Voltaire/output -e 01
if __name__ == "__main__":
    scan_parser = argparse.ArgumentParser(description="Check if process' image path is wanted, using SANS 'Know Normal - Find Evil' criterion")

    scan_parser.add_argument("-d", "--dest", help="Output directory", required=False, default="voltaire")
    scan_parser.add_argument("-e", "--es", help="ES mode", default=1, required=False)

    args = vars(scan_parser.parse_args())

    check_banished_name(args)

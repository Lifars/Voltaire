#!/usr/bin/env python
#sans_check_image_path
import argparse
import os
import sqlite3

# Map of <Process, Normal image path suffix>
# based on https://digital-forensics.sans.org/media/SANS_Poster_2018_Hunt_Evil_FINAL.pdf
PROCESS_IMAGE_PATH_SUFFIX = {"smss.exe": "\system32\smss.exe",
              "wininit.exe": "\system32\wininit.exe",
              "runtimebroker.exe": "\system32\runtimebroker.exe",
              "taskhostw.exe": "\system32\taskhostw.exe",
              "winlogon.exe": "\system32\winlogon.exe",
              "csrss.exe": "\system32\csrss.exe",
              "services.exe": "\system32\services.exe",
              "svchost.exe": "\system32\svchost.exe",
              "lsaiso.exe": "\system32\lsaiso.exe",
              "lsass.exe": "\system32\lsass.exe",
              "explorer.exe": "\explorer.exe"
                             }


def check_image_path(comargs):
    """ Uses the SANS 'Know Normal - Find Evil' criterion, to check image path of process
    """
    path = comargs["dest"] + os.sep
    dbfile = "{path}ES{number}.db".format(path=path,
                                          number=comargs["es"])
    dbconn = sqlite3.connect(dbfile)
    envDBCursor = dbconn.cursor()
    exeDBCursor = dbconn.cursor()
    # Get systemroot environment variable
    querySystemRoot = "select distinct Value from Envars where LOWER(Variable) = 'systemroot'"
    envSystemRootResult = envDBCursor.execute(querySystemRoot).fetchall()
    dbconn.commit()
    if not envSystemRootResult :
        print "Error: not find environment variable SystemRoot"
        return
    envSystemRoot = envSystemRootResult[0][0]
    print "SystemRoot evironment variable:" + envSystemRoot

    # Get path of all xxxx.exe
    exeQuery = "select distinct path from DllList where path like \"%.exe\""
    exeDBCursor.execute(exeQuery)
    dbconn.commit()
    allImagePath = exeDBCursor.fetchall()

    invalidImagePathList = []
    for row in allImagePath:
        imagePath = row[0]
        pathSplit = imagePath.split('\\')
        processName = pathSplit[len(pathSplit) - 1].lower()
        if PROCESS_IMAGE_PATH_SUFFIX.has_key(processName):
            processSuffix = PROCESS_IMAGE_PATH_SUFFIX[processName]
            # windows path case insensitive
            fullPathEnv = (envSystemRoot + processSuffix).lower()
            fullPathSystemRoot = ("\SystemRoot" + processSuffix).lower()

            # valid path "c:\windows\system32\smss.exe" or "\systemroot\system32\smss.exe" or "\??\C:\WINDOWS\system32\csrss.exe" ("??" stands for device)
            if not imagePath.lower().endswith(fullPathEnv) \
                    and not imagePath.lower().endswith(fullPathSystemRoot):
                invalidImagePathList.append(imagePath)

    # todo, centralize the message and write file function
    # write result to file
    path = comargs["dest"] + os.sep
    outfile = "{path}ES{number}_report.txt".format(path=path,
                                                   number=comargs["es"])
    with open(outfile, "at") as freport:
        title = "Running image path test."
        freport.write(title + "\n")
        freport.write("-" * len(title) + '\n')
        print title
        print "-" * len(title)

        if len(invalidImagePathList) != 0 :
            for invalidPath in invalidImagePathList:
                freport.write("Invalid image path: %s.\n" % (invalidPath))
                print "Invalid image path: %s.\n" % (invalidPath)
        else :
            freport.write("No rogue process found. \n")
            print "No rogue process found."
        freport.write("\n")
        print""


# Main
# Example calling from shell:
# python sans_check_image_path.py  -d /home/sansforensics/Documents/code/Voltaire/output -e 01
if __name__ == "__main__":
    scan_parser = argparse.ArgumentParser(description="Check if process' image path is wanted, using SANS 'Know Normal - Find Evil' criterion")

    scan_parser.add_argument("-d", "--dest", help="Output directory", required=False, default="voltaire")
    scan_parser.add_argument("-e", "--es", help="ES mode", default=1, required=False)

    args = vars(scan_parser.parse_args())

    check_image_path(args)
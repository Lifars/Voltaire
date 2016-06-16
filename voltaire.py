#!/usr/bin/env python
import sys, os, argparse
from sys import platform as _platform
from subprocess import call

# Commands to run
commandlist = ["pslist", "pstree", "netscan", "psxview", "consoles", "psscan", "mutantscan", "cmdscan"]

# Valid profiles
validprofiles = dict.fromkeys(
    ["VistaSP0x64", "VistaSP0x86", "VistaSP1x64", "VistaSP1x86", "VistaSP2x64", "VistaSP2x86", "Win10x64",
     "Win10x86", "Win2003SP0x86", "Win2003SP1x64", "Win2003SP1x86", "Win2003SP2x64", "Win2003SP2x86",
     "Win2008R2SP0x64", "Win2008R2SP1x64", "Win2008SP1x64", "Win2008SP1x86", "Win2008SP2x64",
     "Win2008SP2x86", "Win2012R2x64", "Win2012x64", "Win7SP0x64", "Win7SP0x86", "Win7SP1x64", "Win7SP1x86",
     "Win81U1x64", "Win81U1x86", "Win8SP0x64", "Win8SP0x86", "Win8SP1x64", "Win8SP1x86", "WinXPSP1x64",
     "WinXPSP2x64", "WinXPSP2x86", "WinXPSP3x86"])


def volcall(program, command, args):
    print("Starting {command}".format(command=command))

    path = args["dest"] + os.sep
    outfile = "{path}ES{number}_{command}.txt".format(path=path, number=args["es"], command=command)

    if "profile" in args:
        params = "-f {src} --profile={profile} {command} --output-file={dest}".format(src=args["src"],
                                                                                      profile=args["profile"],
                                                                                      command=command,
                                                                                      dest=outfile)
    else:
        params = "-f {src} {command} --output-file={dest}".format(src=args["src"], command=command, dest=outfile)

    return call("{program} {params}".format(program=program, params=params))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Batches common Volatility commands")
    parser.add_argument("-s", "--src", help="Input file", required=True)
    parser.add_argument("-d", "--dest", help="Output directory", required=True)

    parser.add_argument("-p", "--profile", help="Profile name", required=False)
    parser.add_argument("-e", "--es", help="ES mode", default=1, required=False)

    args = vars(parser.parse_args())

    args["src"] = os.path.abspath(args["src"])
    args["dest"] = os.path.abspath(args["dest"])

    if "src" in args:
        print("Source file: {src}".format(src=args["src"]))

    if "dest" in args:
        print("Destination directory: {dest}".format(dest=args["dest"]))

    if "profile" in args:
        if args["profile"] in validprofiles:
            print("Profile name: {profile}".format(profile=args["profile"]))
        else:
            print("Profile not valid: {profile}".format(profile=args["profile"]))
            sys.exit(1)
    else:
        print("WARNING: No profile set!")

    if "es" in args:
        print("ES: {es}".format(es=args["es"]))
    else:
        print("NOTICE: No ES set. Defaulting to ES=1.")

    windows = _platform == "win32"

    program = os.path.abspath("vol.exe") if windows else "vol.py"

    for command in commandlist:
        result = volcall(program, command, args)
        if result == 0:
            print("Completed {command}".format(command=command))
        else:
            print("Error running {command}".format(command=command))

    if windows:
        path = args["dest"] + os.sep
        outfile = "{path}ES{number}_autorun.txt".format(path=path, number=args["es"])

        if "profile" in args:
            params = "-f {src} --profile={profile} printkey \"Software\\Microsoft\\Windows\\CurrentVersion\\Run\" --output-file={dest}".format(
                src=args["src"], profile=args["profile"], dest=outfile)
        else:
            params = "-f {src} printkey \"Software\\Microsoft\\Windows\\CurrentVersion\\Run\" --output-file={dest}".format(
                src=args["src"], dest=outfile)

        result = call("{program} {params}".format(program=program, params=params))

        if result == 0:
            print("Completed autorun")
        else:
            print("Error running autorun")

    print("Volatility files saved to {dest}".format(dest=args["dest"]))


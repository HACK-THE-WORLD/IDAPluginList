#!/usr/bin/python3

import os
import shutil
import sys

"""
    Installs the symless plugin into your IDA plugins user directory :
    On Windows: %APPDATA%/Hex-Rays/IDA Pro
    On Linux and Mac: $HOME/.idapro


    Install: $ python3 install.py
    Uninstall: $ python3 install.py -u
"""


def usage():
    print(f"Usage: python {sys.argv[0]} [-u] [--dev]")
    print("-u => uninstall plugin")
    print("--dev => use symlinks to sync with git repo folder")


ROOT_DIR = os.path.abspath(os.path.dirname(__file__))
TO_COPY = [("symless_plugin.py", False), ("../symless", True)]


def install(where: str, symlink: bool) -> int:
    # check no installation is present
    for file, is_dir in TO_COPY:
        filepath = os.path.join(where, os.path.basename(file))
        if os.path.exists(filepath):
            print(f"Replacing existing {'directory' if is_dir else 'file'} \"{filepath}\"")
            if is_dir:
                shutil.rmtree(filepath)
            else:
                os.remove(filepath)

    # install
    for file, is_dir in TO_COPY:
        src = os.path.abspath(os.path.join(ROOT_DIR, file))
        dst = os.path.join(where, os.path.basename(file))

        if symlink:
            print(f'Linking "{dst}"')
            os.symlink(src, dst)
        else:
            print(f'Creating "{dst}"')
            if is_dir:
                shutil.copytree(src, dst, dirs_exist_ok=True)
            else:
                shutil.copy(src, dst)

    return 0


def uninstall(where: str) -> int:
    for file, is_dir in TO_COPY:
        path = os.path.join(where, os.path.basename(file))

        print(f"Deleting {path}")
        try:
            if is_dir and not os.path.islink(path):
                shutil.rmtree(path)
            else:
                os.unlink(path)
        except FileNotFoundError:
            pass

    return 0


if __name__ == "__main__":
    # find IDA installation
    if os.name == "posix":
        ida_plugins_dir = os.path.expandvars("/$HOME/.idapro/plugins")
    elif os.name == "nt":
        ida_plugins_dir = os.path.expandvars("%APPDATA%/Hex-Rays/IDA Pro/plugins")
    else:
        print(f"Could not retrieve IDA install folder on OS {os.name}")
        exit(1)

    # make sure the "plugins" dir exists
    os.makedirs(ida_plugins_dir, exist_ok=True)

    # args parsing
    do_install = True
    symlink = False
    for arg in sys.argv[1:]:
        if arg == "-u":
            do_install = False
        elif arg == "--dev":
            symlink = True
        else:
            usage()
            exit(1)

    ok = install(ida_plugins_dir, symlink) if do_install else uninstall(ida_plugins_dir)
    if ok == 0:
        print("Done")

#!/usr/bin/python3

import argparse
import os
import sys

import symless.config as config

""" IDA main """


def ida_main():
    # parse arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=str, help="config file")
    parser.add_argument("--prefix", type=str, default="", help="log prefix")
    args = parser.parse_args(idc.ARGV[1:])
    start_analysis(args.config)

    idc.qexit(0)


""" Command line main """


def cmd_usage():
    print(f"Usage: python {sys.argv[0]} [-c config.csv] <file(s)>")


def cmd_main():
    files = []
    root_dir = os.path.realpath(os.path.join(config.g_settings.root, ".."))
    config_path = os.path.join(root_dir, "symless", "config", "imports.csv")

    # parse arguments
    i, length = 1, len(sys.argv)
    while i < length:
        if sys.argv[i] == "-c":
            i += 1
            if i == length:
                cmd_usage()
                return
            config_path = sys.argv[i]
        else:
            files.append(sys.argv[i])
        i += 1

    if len(files) == 0:
        cmd_usage()
        return

    args = ["--config", config_path]

    runner = os.path.join(root_dir, "symless.py")
    for file in files:
        run_script(runner, os.path.abspath(file), args)


""" Symless main """

if __name__ == "__main__":
    try:
        # flake8: noqa: F401
        import idc

    except ModuleNotFoundError:
        from run_script import run_script

        cmd_main()  # script run from command line

    else:
        from symless.main import start_analysis

        ida_main()  # script run from IDA

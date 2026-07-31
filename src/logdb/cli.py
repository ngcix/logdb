import sys
import argparse

import logdb.core
from logdb.config import CONFIG_FILE_NAME

PROGRAM_NAME = "logdb"




def parser_builder() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog=PROGRAM_NAME)
    sp = ap.add_subparsers(dest="cmd", required=True)
    p = sp.add_parser(
        "config-init",
        help=f"Write {CONFIG_FILE_NAME} into the current directory",
    )

    p.add_argument(
        '-m', '--make',
        action='append',
        type=str, 
        help="",
    )

    p.add_argument(
        '-t', '--table',
        action='append',
        type=str, 
        help=""
    )


def main() -> int:
    argv = sys.argv
    parser = parser_builder()
    try:
        args = parser.parse_args(argv)
    except SystemExit as e:
        return int(e.code) if e.code is not None else 1
    return int(args.func(args))

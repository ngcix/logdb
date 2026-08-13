import argparse
from logdb.__version__ import __version__


def register(parser: argparse.ArgumentParser):
    """Register the version command."""
    parser.set_defaults(func=run)


def run(args: argparse.Namespace) -> int:
    """Print version information."""
    print(f"logdb {__version__}")
    return 0

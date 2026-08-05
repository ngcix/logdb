import argparse
import sys
from pathlib import Path

from logdb.config import load_config, DEFAULT_CONFIG_LOADERS


def register(parser: argparse.ArgumentParser):
    """Register the config command and its subcommands."""
    subparsers = parser.add_subparsers(dest="config_cmd", required=True)

    init_parser = subparsers.add_parser(
        "init",
        help="Generate default configs for all log types",
    )
    init_parser.add_argument(
        "-t",
        "--type",
        choices=("dumpstate", "pcap", "hci"),
        help="Generate config for specific log type (default: all)",
    )
    init_parser.set_defaults(func=run_init)

    open_parser = subparsers.add_parser(
        "open",
        help="Open a config file in default editor",
    )
    open_parser.add_argument(
        "-t",
        "--type",
        required=True,
        choices=("dumpstate", "pcap", "hci"),
        help="Log type to open config for",
    )
    open_parser.set_defaults(func=run_open)


def run_init(args: argparse.Namespace) -> int:
    """Initialize (re)generate default configs."""
    config_dir = Path.home() / ".logdb" / "config"
    config_dir.mkdir(parents=True, exist_ok=True)

    log_types = [args.type] if args.type else list(DEFAULT_CONFIG_LOADERS.keys())

    for log_type in log_types:
        try:
            config_path = config_dir / f"{log_type}.toml"
            default_config = DEFAULT_CONFIG_LOADERS[log_type]()
            config_path.write_text(default_config, encoding="utf-8")
            print(f"Generated: {config_path}")
        except KeyError:
            print(f"error: Unknown log type: {log_type}", file=sys.stderr)
            return 1
        except OSError as error:
            print(f"error: Failed to write config: {error}", file=sys.stderr)
            return 1

    print(f"\nConfig files saved to: {config_dir}")
    return 0


def run_open(args: argparse.Namespace) -> int:
    """Open config file with system default editor."""
    config_dir = Path.home() / ".logdb" / "config"
    config_path = config_dir / f"{args.type}.toml"

    if not config_path.exists():
        print(f"error: Config not found: {config_path}", file=sys.stderr)
        print(f"Run 'logdb config init -t {args.type}' to create it", file=sys.stderr)
        return 1

    try:
        if sys.platform == "win32":
            import os
            os.startfile(str(config_path))
        else:
            import subprocess
            subprocess.run(["xdg-open", str(config_path)], check=True)
    except Exception as error:
        print(f"error: Failed to open config: {error}", file=sys.stderr)
        print(f"Config location: {config_path}", file=sys.stderr)
        return 1

    return 0

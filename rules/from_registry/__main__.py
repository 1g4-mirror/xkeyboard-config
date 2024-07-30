#!/usr/bin/env python3

import argparse
from pathlib import Path

from rules.from_registry import main

if __name__ == "__main__":
    # CLI parser
    parser = argparse.ArgumentParser(description="Generate the evdev keycode lists.")
    parser.add_argument(
        "--xkb-config-root",
        help="The XKB base directory",
        default=Path("."),
        type=Path,
    )
    parser.add_argument("-o", "--output", help="Output file", type=Path)
    parser.add_argument("-c", "--compat", help="Add compat rules", action="store_true")
    parser.add_argument("-r", "--rules", help="rules", type=str, required=True)
    parser.add_argument(
        "registry_files",
        metavar="registry-files",
        nargs="+",
        help="The registry XML files",
        type=Path,
    )
    ns = parser.parse_args()

    # Main program
    main(
        xkb_root=ns.xkb_config_root,
        compat=ns.compat,
        rules=ns.rules,
        registry_files=ns.registry_files,
        output=ns.output,
    )

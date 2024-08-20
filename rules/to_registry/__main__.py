#!/usr/bin/env python3

import argparse
from pathlib import Path

from rules.to_registry import main

if __name__ == "__main__":
    # CLI parser
    parser = argparse.ArgumentParser(description="Migrate XML file.")
    parser.add_argument(
        "--xkb-config-root",
        help="The XKB base directory",
        default=Path("."),
        type=Path,
    )
    parser.add_argument(
        "-i",
        "--input",
        help="Input XML registry file",
        action="append",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "-o", "--output", action="append", help="Output XML registry file", type=Path
    )
    parser.add_argument("-c", "--compat", help="Add compat rules", action="store_true")
    parser.add_argument(
        "--no-skip",
        help="Do not skip rules that could be duplicates, but expressed in another form",
        action="store_true",
    )
    parser.add_argument("files", nargs="+", help="Input rules files", type=Path)
    ns = parser.parse_args()
    if not ns.output:
        ns.output = ns.input
    elif len(ns.output) != len(ns.input):
        raise ValueError(
            "Output paths list should have the same length as the input list"
        )

    # Main program
    main(
        xkb_root=ns.xkb_config_root,
        rules_files=ns.files,
        registry_inputs=ns.input,
        registry_outputs=ns.output,
        compat=ns.compat,
        no_skip=ns.no_skip,
    )

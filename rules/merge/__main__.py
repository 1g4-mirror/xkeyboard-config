import argparse
import operator
from functools import reduce
from pathlib import Path

from rules.merge import Reorder, main

if __name__ == "__main__":
    # CLI parser
    parser = argparse.ArgumentParser(description="Migrate XML file.")
    parser.add_argument("-r", "--rules", help="rules", type=str, required=True)
    parser.add_argument(
        "-R",
        "--reorder",
        help="Reorder type",
        default=[],
        choices=tuple(Reorder) + (Reorder.all,),
        type=Reorder.parse,
        action="append",
    )
    parser.add_argument(
        "--only-rules-headers",
        help="Remove everything except rules headers",
        action="store_true",
    )
    parser.add_argument(
        "--debug",
        help="Add debug comments",
        action="store_true",
    )
    parser.add_argument("files", nargs="+", help="Input rules files", type=Path)
    ns = parser.parse_args()

    if ns.only_rules_headers:
        ns.debug = True

    # Main program
    main(
        ns.rules,
        ns.files,
        reorder=reduce(operator.or_, ns.reorder),
        only_rules_headers=ns.only_rules_headers,
        debug=ns.debug,
    )

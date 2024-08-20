#!/usr/bin/env python3

import argparse
from pathlib import Path

import lxml.etree as ET


def run(rules: Path, stylesheet: Path, output: Path):
    dom = ET.parse(rules)
    xslt = ET.parse(stylesheet)
    transform = ET.XSLT(xslt)
    result = transform(dom)
    with output.open("wb") as fp:
        fp.write(
            ET.tostring(
                result, xml_declaration=True, pretty_print=True, encoding="UTF-8"
            )
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Transform rule set for release", add_help=True
    )
    parser.add_argument("-i", "--input", type=Path, required=True)
    parser.add_argument("-s", "--stylesheet", type=Path, required=True)
    parser.add_argument("-o", "--output", type=Path, required=True)
    args = parser.parse_args()

    run(rules=args.input, stylesheet=args.stylesheet, output=args.output)

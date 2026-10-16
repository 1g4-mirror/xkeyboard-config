# SPDX-License-Identifier: MIT

import io
import re
import runpy
from collections.abc import Iterable
from pathlib import Path


def test_typed_keys_are_not_generated_again():
    root = Path(__file__).resolve().parents[1]
    generator = runpy.run_path(root / ".gitlab-ci" / "generate-evdev-keysyms.py")
    generate_symbols_file = generator["generate_symbols_file"]

    header = io.StringIO(
        "/* Use: XK_F23 _EVDEVK(0x0c1) KEY_F23 */\n"
        "/* Use: XK_F24 _EVDEVK(0x0c2) KEY_F24 */\n"
    )

    evdev = root / "keycodes" / "evdev"
    inet = root / ".gitlab-ci" / "inet.in"

    keys = {"I201", "I202"}
    keys_pattern = "|".join(keys)
    pattern = re.compile(rf"^\s*(?P<comment>//\s*)?key\s+<(?P<keysym>{keys_pattern})>")

    with inet.open("rt", encoding="UTF-8") as template:
        with evdev.open("rt", encoding="UTF-8") as keycodes:
            output: Iterable[str] = generate_symbols_file(template, header, keycodes)
            # Ensure that the test is resilient to changes in `generate_symbols_file`
            # by joining then splitting lines.
            for line in "\n".join(output).splitlines():
                if (m := pattern.search(line)) is None:
                    continue
                key = m.group("keysym")
                assert m.group("comment"), f"Key <{key}> is not commented out: {line}."
                keys.discard(key)

    assert not keys, f"Keys not found: {', '.join(sorted(keys))}"

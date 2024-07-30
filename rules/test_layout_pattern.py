import re
import sys

from rules.to_registry import Rule


LAYOUT_TARGET_INDEX_PATTERN = re.compile(r":(?P<target_index>\d+|%i)")


def layout_variant_pattern(
    raw: str,
    prefix: str | None,
    parenthesis: bool,
    component: str | None,
    index: str | None,
    target_index: str | None,
) -> bool:
    if m := Rule.LAYOUT_VARIANT_PATTERN.match(raw):
        if (
            m.group("prefix") == prefix
            and (m.group("parenthesis") or not parenthesis)
            and m.group("component") == component
            and m.group("index") == index
            and m.group("target_index") == target_index
        ):
            return True
        else:
            print(
                f"[ERROR] test_layout_variant_pattern: {raw}, {m.groupdict()}",
                file=sys.stderr,
            )
            return False
    else:
        return False


def test_layout_variant_pattern():
    assert layout_variant_pattern(
        "%l",
        prefix=None,
        parenthesis=False,
        component="l",
        index=None,
        target_index=None,
    )
    assert layout_variant_pattern(
        "%v",
        prefix=None,
        parenthesis=False,
        component="v",
        index=None,
        target_index=None,
    )

    assert layout_variant_pattern(
        "%l[1]",
        prefix=None,
        parenthesis=False,
        component="l",
        index="1",
        target_index=None,
    )
    assert layout_variant_pattern(
        "%l[1]:1",
        prefix=None,
        parenthesis=False,
        component="l",
        index="1",
        target_index="1",
    )

    assert layout_variant_pattern(
        "%+l",
        prefix="+",
        parenthesis=False,
        component="l",
        index=None,
        target_index=None,
    )
    assert layout_variant_pattern(
        "%+l[1]",
        prefix="+",
        parenthesis=False,
        component="l",
        index="1",
        target_index=None,
    )
    assert layout_variant_pattern(
        "%+l[1]:1",
        prefix="+",
        parenthesis=False,
        component="l",
        index="1",
        target_index="1",
    )

    assert layout_variant_pattern(
        "%(l)",
        prefix=None,
        parenthesis=True,
        component="l",
        index=None,
        target_index=None,
    )
    assert layout_variant_pattern(
        "%(l[1])",
        prefix=None,
        parenthesis=True,
        component="l",
        index="1",
        target_index=None,
    )
    assert layout_variant_pattern(
        "%(l[1]):1",
        prefix=None,
        parenthesis=True,
        component="l",
        index="1",
        target_index="1",
    )


def layout_target_index_pattern(raw: str, target_index: str | None):
    # if m := LAYOUT_TARGET_INDEX_PATTERN.search(raw):
    if m := Rule.LAYOUT_VARIANT_PATTERN.search(raw):
        # return m.group("target_index") == target_index
        return m.group("standalone_target_index") == target_index
    else:
        return False


def test_layout_target_index_pattern():
    assert not layout_target_index_pattern("+abc", None)
    assert layout_target_index_pattern("+abc:1", target_index="1")

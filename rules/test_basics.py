from dataclasses import dataclass
import dataclasses
from enum import IntEnum, auto, unique
import io
import itertools
import textwrap
from typing import Iterable

import pytest
from rules import (
    MAX_LAYOUT_INDEX,
    RMLVO,
    Comment,
    Group,
    Include,
    MLVO_Matcher,
    MLVO_Set,
    Priority,
    Rule,
    RulesFile,
    RulesSet,
    RulesSetKey,
    Section,
)
from rules.components import MainComponents


LAYOUT_INDEXES = ("",) + tuple(map(str, range(1, MAX_LAYOUT_INDEX)))


def powerset(iterable):
    s = tuple(iterable)
    return itertools.chain.from_iterable(
        itertools.combinations(s, r) for r in range(len(s) + 1)
    )


def test_powerset():
    assert tuple(powerset((1, 2, 3))) == (
        (),
        (1,),
        (2,),
        (3,),
        (1, 2),
        (1, 3),
        (2, 3),
        (1, 2, 3),
    )


def test_Section():
    assert Section.keycodes < Section.symbols
    assert Section.geometry < Section.compatibility
    assert Section.keycodes < Section.compatibility


def test_MLVO_Set():
    assert MLVO_Set.parse(("layout", "option")) == (
        MLVO_Set(layout=True, option=True),
        (RMLVO.layout, RMLVO.option),
    )
    assert MLVO_Set.parse(("layout[1]", "option")) == (
        MLVO_Set(layout=True, option=True, layout_range="1"),
        (RMLVO.layout, RMLVO.option),
    )
    for c1, c2 in itertools.product(RMLVO.mlvo(), RMLVO.mlvo()):
        mlvo1 = MLVO_Set(**{c1: True})
        mlvo2 = MLVO_Set(**{c2: True})
        if c1 < c2:
            assert mlvo1 < mlvo2
        elif c1 > c2:
            assert mlvo1 > mlvo2
        else:
            assert mlvo1 == mlvo2
    assert MLVO_Set(model=True, layout=True) < MLVO_Set(layout=True)
    assert MLVO_Set(model=True, variant=True) < MLVO_Set(layout=True)
    assert MLVO_Set(model=True, layout=True) < MLVO_Set(
        model=True, layout=True, variant=True
    )

    assert MLVO_Set(layout=True, layout_range="") < MLVO_Set(
        layout=True, layout_range="1"
    )
    assert MLVO_Set(layout=True, layout_range="1") < MLVO_Set(
        variant=True, layout_range=""
    )
    assert MLVO_Set(model=True, layout=True, layout_range="1") < MLVO_Set(
        model=True, layout=True, variant=True, layout_range=""
    )
    assert MLVO_Set(layout=True) < MLVO_Set(layout=True, layout_range="1", option=True)


@unique
class ComponentValue(IntEnum):
    a = auto()
    b = auto()
    group1 = auto()
    group2 = auto()
    wildcard = auto()

    def __str__(self) -> str:
        if self is self.a or self.b:
            return self.name
        elif self is self.group1 or self.group2:
            return "$" + self.name
        else:
            return "*"


def test_MLVO_Matcher():
    for c in RMLVO.mlvo():
        m = MLVO_Matcher(**{str(c): "a"})
        assert tuple(m) == ((c, "a"),)
        assert m.main_component == (c, "a")
    assert MLVO_Matcher(layout="a", variant="b").main_component == (RMLVO.variant, "b")
    assert MLVO_Matcher(layout="a", variant="$b").main_component == (
        RMLVO.layout,
        "a",
    )
    assert MLVO_Matcher(layout="$a", variant="b").main_component == (
        RMLVO.variant,
        "b",
    )
    assert MLVO_Matcher(layout="$a", variant="$b").main_component == (
        RMLVO.layout,
        "$a",
    )
    assert MLVO_Matcher(layout="a", variant="*").main_component == (RMLVO.layout, "a")
    assert MLVO_Matcher(layout="$a", variant="*").main_component == (RMLVO.layout, "$a")
    assert MLVO_Matcher(layout="*", variant="b").main_component == (RMLVO.variant, "b")
    assert MLVO_Matcher(layout="*", variant="$b").main_component == (RMLVO.layout, "*")
    assert MLVO_Matcher(layout="*", variant="*").main_component == (RMLVO.layout, "*")
    assert MLVO_Matcher(layout="a", variant="b").main_components == MainComponents(
        RMLVO.variant, "b", RMLVO.layout, "a"
    )
    assert MLVO_Matcher(layout="a", variant="$b").main_components == MainComponents(
        RMLVO.layout,
        "a",
    )
    assert MLVO_Matcher(layout="$a", variant="b").main_components == MainComponents(
        RMLVO.variant, "b", RMLVO.layout, "$a"
    )
    assert MLVO_Matcher(layout="a", variant="*").main_components == MainComponents(
        RMLVO.layout, "a"
    )
    assert MLVO_Matcher(layout="*", variant="b").main_components == MainComponents(
        RMLVO.variant, "b", RMLVO.layout, "*"
    )

    assert MLVO_Matcher(model="a") < MLVO_Matcher(model="b")
    assert MLVO_Matcher(model="a") < MLVO_Matcher(model="$a")
    assert MLVO_Matcher(model="a") < MLVO_Matcher(model="*")

    assert MLVO_Matcher(model="a", layout="1") < MLVO_Matcher(model="a", layout="2")
    assert MLVO_Matcher(model="a", layout="1") < MLVO_Matcher(model="a", layout="2")
    assert MLVO_Matcher(model="a", layout="1") < MLVO_Matcher(model="b", layout="1")

    assert MLVO_Matcher(model="a", layout="1") < MLVO_Matcher(model="$a", layout="1")
    assert MLVO_Matcher(model="a", layout="1") < MLVO_Matcher(model="a", layout="$1")
    assert MLVO_Matcher(model="$a", layout="1") < MLVO_Matcher(model="$b", layout="1")
    assert MLVO_Matcher(model="a", layout="$1") < MLVO_Matcher(model="a", layout="$2")

    assert MLVO_Matcher(model="a", layout="1") < MLVO_Matcher(model="*", layout="1")
    assert MLVO_Matcher(model="a", layout="1") < MLVO_Matcher(model="a", layout="*")
    assert MLVO_Matcher(model="*", layout="1") < MLVO_Matcher(model="*", layout="2")

    assert MLVO_Matcher(model="$a", layout="1") < MLVO_Matcher(model="*", layout="1")
    assert MLVO_Matcher(model="a", layout="$1") < MLVO_Matcher(model="a", layout="*")

    assert MLVO_Matcher(model="a", layout="*", variant="1") < MLVO_Matcher(
        model="*", layout="*", variant="1"
    )
    assert MLVO_Matcher(model="a", layout="*", variant="1") < MLVO_Matcher(
        model="*", layout="*", variant="1"
    )

    # Exhaustive test when same components defined
    for mlvo_fields in filter(None, powerset(RMLVO.mlvo())):
        values = tuple(ComponentValue for _ in mlvo_fields)
        for mlvo_values1 in itertools.product(*values):
            mlvo1 = MLVO_Matcher(**dict(zip(mlvo_fields, map(str, mlvo_values1))))
            for mlvo_values2 in itertools.product(*values):
                mlvo2 = MLVO_Matcher(**dict(zip(mlvo_fields, map(str, mlvo_values2))))
                if mlvo_values1 < mlvo_values2:
                    assert mlvo1 < mlvo2
                    assert mlvo1 < dataclasses.replace(
                        mlvo2, layout_range=str(MAX_LAYOUT_INDEX)
                    )
                    assert mlvo1 > dataclasses.replace(mlvo2, priority=Priority.highest)
                elif mlvo_values1 > mlvo_values2:
                    assert mlvo1 > mlvo2
                    assert mlvo1 > dataclasses.replace(
                        mlvo2, layout_range=str(MAX_LAYOUT_INDEX)
                    )
                    assert mlvo1 < dataclasses.replace(mlvo2, priority=Priority.lowest)
                else:
                    assert mlvo1 == mlvo2
                    assert mlvo1 < dataclasses.replace(mlvo2, priority=Priority.lowest)
                    assert mlvo1 > dataclasses.replace(mlvo2, priority=Priority.highest)
                    assert mlvo1 < dataclasses.replace(
                        mlvo2, layout_range=str(MAX_LAYOUT_INDEX)
                    )
                    assert dataclasses.replace(
                        mlvo1, layout_range="1"
                    ) < dataclasses.replace(mlvo2, layout_range=str(MAX_LAYOUT_INDEX))

    # Note: MLVO components are identical within a rule set, so this should not be used
    assert MLVO_Matcher(model="a") < MLVO_Matcher(model="a", layout="1")
    assert MLVO_Matcher(model="b") > MLVO_Matcher(model="a", layout="1")
    assert MLVO_Matcher(model="a", layout="1") > MLVO_Matcher(layout="1", variant="A")
    assert MLVO_Matcher(model="a", layout="1", layout_range="1") > MLVO_Matcher(
        layout="1", variant="A", layout_range="1"
    )
    assert MLVO_Matcher(layout="1") < MLVO_Matcher(layout="1", variant="A")
    assert MLVO_Matcher(layout="1", layout_range="1") < MLVO_Matcher(
        layout="1", variant="A", layout_range="1"
    )
    # Note: layout range is identical within a ruleset, so this should not be used
    assert MLVO_Matcher(layout="1", layout_range="") < MLVO_Matcher(
        layout="1", variant="A", layout_range="1"
    )


def test_Group():
    assert Group.parse_header("! $g = a b cd") == Group("$g", {"a", "b", "cd"})


def test_Include():
    # Valid
    for file in ("foo", "foo/bar", r"%E/base", r"%S/evdev", r"%H/rules/fo%%o/bar"):
        assert Include.parse_header(f"! include {file}") == Include(file)
        assert Include.parse_header(f"!   include    {file}") == Include(file)

    # Invalid
    assert Include.parse_header(file) is None
    paths = (
        '"%S/foo/bar"',  # invalid quotes
        r"foo%",  # incomplete %-expansion
        r"foo%x",  # invalid %-expansion
        r"%S/rules"  # /rules already added by %-expansion
        r"%E/rules",  # /rules already added by %-expansion
    )
    for path in paths:
        raw = io.StringIO(f"! include {path}")
        with pytest.raises(ValueError) as exc:
            tuple(RulesFile.parse(raw))
        assert exc.type is ValueError


@dataclass(frozen=True, order=True)
class _Rule(Rule):
    # Note: we cannot reorder fields, so order will be the same as _Rule
    mlvo: MLVO_Matcher
    section: Section
    section_value: str = ""


def test_Rule():
    assert Rule.parse(
        ("model", "layout"), "", Section.symbols, " abcd l = +foo"
    ) == Rule(
        mlvo=MLVO_Matcher(model="abcd", layout="l"),
        section=Section.symbols,
        section_value="+foo",
    )

    r1 = Rule(
        mlvo=MLVO_Matcher(model="a", layout="1"),
        section=Section.symbols,
        section_value="a",
    )
    r2 = Rule(
        mlvo=MLVO_Matcher(model="b", layout="1"),
        section=Section.keycodes,
        section_value="a",
    )
    assert r2 < r1

    r3 = _Rule(
        mlvo=MLVO_Matcher(model="a", layout="1"),
        section=Section.symbols,
        section_value="a",
    )
    r4 = _Rule(
        mlvo=MLVO_Matcher(model="b", layout="1"),
        section=Section.keycodes,
        section_value="a",
    )
    assert isinstance(r1.mlvo, MLVO_Matcher)
    assert isinstance(r1.section, Section)
    assert r4 < r3  # Cannot reorder fields


def test_RulesSet():
    assert RulesSet.parse_header("! $foo = bar") is None

    mlvo_iter: Iterable[tuple[RMLVO, ...]] = filter(None, powerset(RMLVO.mlvo()))
    for mlvo_fields, section in itertools.product(mlvo_iter, Section):
        if RMLVO.layout in mlvo_fields or RMLVO.variant in mlvo_fields:
            indexes = LAYOUT_INDEXES
        else:
            indexes = ("",)
        for layout_range in indexes:
            mlvo = MLVO_Set(**{c: True for c in mlvo_fields}, layout_range=layout_range)
            assert RulesSet.parse_header(
                f"! {' '.join(mlvo.components)} = {section}"
            ) == (
                RulesSet(mlvo=mlvo, section=section, rules=[]),
                mlvo_fields,
            )


def test_RulesSetKey():
    m = MLVO_Set(model=True)
    l = MLVO_Set(layout=True)
    mlvos = (m, l)
    has_merge_modes = (False, True)
    mlvo1: MLVO_Set
    mlvo2: MLVO_Set
    for mlvo1, mlvo2, s1, s2, has_merge_mode1, has_merge_mode2 in itertools.product(
        mlvos, mlvos, Section, Section, has_merge_modes, has_merge_modes
    ):
        rs1 = RulesSetKey(mlvo=mlvo1, has_merge_mode=has_merge_mode1, section=s1)
        rs2 = dataclasses.replace(rs1, section=s2)

        if s1 == s2:
            # Same section
            assert rs1 == rs2
            if has_merge_mode1 < has_merge_mode2:
                assert rs1 < dataclasses.replace(rs2, has_merge_mode=has_merge_mode2)
                assert rs1 < dataclasses.replace(
                    rs2, mlvo=mlvo2, has_merge_mode=has_merge_mode2
                )
            elif has_merge_mode1 > has_merge_mode2:
                assert rs1 > dataclasses.replace(rs2, has_merge_mode=has_merge_mode2)
                assert rs1 > dataclasses.replace(
                    rs2, mlvo=mlvo2, has_merge_mode=has_merge_mode2
                )
            elif has_merge_mode1:
                rs2 = dataclasses.replace(rs2, mlvo=mlvo2)
                # Both have merge mode
                if mlvo1 < mlvo2:
                    assert rs1 < rs2
                elif mlvo1 > mlvo2:
                    assert rs1 > rs2
                else:
                    continue
            else:
                # None has merge mode: see test in next section
                continue
        elif s1 < s2:
            assert rs1 < rs2
            rs1 < dataclasses.replace(rs2, mlvo=mlvo2)
            rs1 < dataclasses.replace(rs2, has_merge_mode=has_merge_mode2)
            rs1 < dataclasses.replace(rs2, mlvo=mlvo2, has_merge_mode=has_merge_mode2)
        else:
            assert rs1 > rs2
            rs1 > dataclasses.replace(rs2, mlvo=mlvo2)
            rs1 > dataclasses.replace(rs2, has_merge_mode=has_merge_mode2)
            rs1 > dataclasses.replace(rs2, mlvo=mlvo2, has_merge_mode=has_merge_mode2)

    mlvos_fields: tuple[tuple[RMLVO, ...], ...] = tuple(
        filter(None, powerset(RMLVO.mlvo()))
    )

    # Same section and none starts with a merge mode
    for mlvo_fields1_, mlvo_fields2_ in itertools.product(mlvos_fields, mlvos_fields):
        if RMLVO.layout in mlvo_fields1_ or RMLVO.variant in mlvo_fields1_:
            indexes1 = LAYOUT_INDEXES
        else:
            indexes1 = ("",)
        if RMLVO.layout in mlvo_fields2_ or RMLVO.variant in mlvo_fields2_:
            indexes2 = LAYOUT_INDEXES
        else:
            indexes2 = ("",)
        for range1, range2 in itertools.product(indexes1, indexes2):
            mlvo1 = MLVO_Set(**{c: True for c in mlvo_fields1_}, layout_range=range1)
            mlvo2 = MLVO_Set(**{c: True for c in mlvo_fields2_}, layout_range=range2)
            rs1 = RulesSetKey(
                mlvo=mlvo1, has_merge_mode=False, section=Section.keycodes
            )
            rs2 = RulesSetKey(
                mlvo=mlvo2, has_merge_mode=False, section=Section.keycodes
            )
            if mlvo1 == mlvo2:
                assert rs1 == rs2
                continue
            mlvo_fields1 = frozenset(rs1.mlvo.components)
            mlvo_fields2 = frozenset(rs2.mlvo.components)
            if mlvo_fields1.issubset(mlvo_fields2):
                assert rs1 > rs2, (mlvo_fields1, mlvo_fields2)
            elif mlvo_fields2.issubset(mlvo_fields1):
                assert rs1 < rs2
            elif mlvo1.variant and not mlvo2.variant:
                assert rs1 < rs2
            elif not mlvo1.variant and mlvo2.variant:
                assert rs1 > rs2
            elif mlvo1 < mlvo2:
                assert rs1 < rs2
            else:
                assert rs1 > rs2


def test_RulesFile():
    # Comments
    raw = io.StringIO("// comment 1\n\n\n  // comment 2   \n//   comment 3    ")
    assert tuple(RulesFile.parse(raw)) == (
        Comment(" comment 1"),
        Comment(" comment 2\n   comment 3"),
    )
    assert raw.tell() == len(raw.getvalue())

    # Comments: escaped lined
    raw = io.StringIO("// comment 1\\\n   // comment 2")
    assert tuple(RulesFile.parse(raw)) == (Comment(" comment 1\\\n comment 2"),)
    assert raw.tell() == len(raw.getvalue())

    # Include
    raw = io.StringIO(r"! include %H/rules/fo%%o/bar")
    assert tuple(RulesFile.parse(raw)) == (Include(r"%H/rules/fo%%o/bar"),)
    assert raw.tell() == len(raw.getvalue())

    raw = io.StringIO("! include \\\n  foo/bar // comment")
    assert tuple(RulesFile.parse(raw)) == (Include("foo/bar"),)
    assert raw.tell() == len(raw.getvalue())

    # Group: single line
    raw = io.StringIO("! $foo = bar")
    assert tuple(RulesFile.parse(raw)) == (Group(name="$foo", members={"bar"}),)
    assert raw.tell() == len(raw.getvalue())

    # Group: single line with description
    raw = io.StringIO("// comment\n\n// description1\n//   description 2\n! $foo = bar")
    assert tuple(RulesFile.parse(raw)) == (
        Comment(" comment"),
        Group(
            name="$foo", members={"bar"}, description="description1\n  description 2"
        ),
    )
    assert raw.tell() == len(raw.getvalue())

    # Group: multiple lines
    raw = io.StringIO(
        "// description\n! $foo = bar\\\n baz   \\\n  boo // comment 1\n   // comment 2"
    )
    assert tuple(RulesFile.parse(raw)) == (
        Group(name="$foo", members={"bar", "baz", "boo"}, description="description"),
        Comment(" comment 2"),
    )
    assert raw.tell() == len(raw.getvalue())

    # Group: multiple lines (escaped line with no member)
    raw = io.StringIO("! $foo = bar\\\n baz   \\\n  boo \\\n   // comment")
    assert tuple(RulesFile.parse(raw)) == (
        Group(name="$foo", members={"bar", "baz", "boo"}),
    )
    assert raw.tell() == len(raw.getvalue())

    # Rules set: empty
    raw = io.StringIO(
        "! model = keycodes\n! model = symbols // layout = types\n! layout = compat"
    )
    assert tuple(RulesFile.parse(raw)) == (
        RulesSet(MLVO_Set(model=True), section=Section.keycodes, rules=[]),
        RulesSet(MLVO_Set(model=True), section=Section.symbols, rules=[]),
        RulesSet(MLVO_Set(layout=True), section=Section.compatibility, rules=[]),
    )
    assert raw.tell() == len(raw.getvalue())

    # Rules sets: layout index
    raw = io.StringIO("! model  layout[1] = symbols // comment 1\n\n  // fff")
    assert tuple(RulesFile.parse(raw)) == (
        RulesSet(
            MLVO_Set(model=True, layout=True, layout_range="1"),
            section=Section.symbols,
            rules=[],
        ),
        Comment(" fff"),
    )

    # Rules sets: examples
    raw = io.StringIO(
        textwrap.dedent(
            """
            ! model = keycodes
              a     = k
            ! model = compat

            ! model = symbols

              b     = s1
              c     = s2 // comment 1
              // comment 2
              d     = s3
            // description 1
            ! model layout = symbols
                // comment 3
              e     1      = s4 // comment 4

            // description 2
            ! model layout[1] variant[1] option  = types
              f     1         A          foo:bar = t1
              g     2         B          foobar  = \\
                                                   t2 // comment 4
            """
        )
    )
    assert tuple(RulesFile.parse(raw)) == (
        RulesSet(
            MLVO_Set(model=True),
            section=Section.keycodes,
            rules=[
                Rule(
                    mlvo=MLVO_Matcher(model="a"),
                    section=Section.keycodes,
                    section_value="k",
                )
            ],
        ),
        RulesSet(MLVO_Set(model=True), section=Section.compatibility, rules=[]),
        RulesSet(
            MLVO_Set(model=True),
            section=Section.symbols,
            rules=[
                Rule(
                    mlvo=MLVO_Matcher(model="b"),
                    section=Section.symbols,
                    section_value="s1",
                ),
                Rule(
                    mlvo=MLVO_Matcher(model="c"),
                    section=Section.symbols,
                    section_value="s2",
                ),
                Rule(
                    mlvo=MLVO_Matcher(model="d"),
                    section=Section.symbols,
                    section_value="s3",
                ),
            ],
        ),
        RulesSet(
            MLVO_Set(model=True, layout=True),
            section=Section.symbols,
            rules=[
                Rule(
                    mlvo=MLVO_Matcher(model="e", layout="1"),
                    section=Section.symbols,
                    section_value="s4",
                ),
            ],
        ),
        RulesSet(
            MLVO_Set(
                model=True, layout=True, variant=True, option=True, layout_range="1"
            ),
            section=Section.types,
            rules=[
                Rule(
                    mlvo=MLVO_Matcher(
                        model="f",
                        layout="1",
                        variant="A",
                        option="foo:bar",
                        layout_range="1",
                    ),
                    section=Section.types,
                    section_value="t1",
                ),
                Rule(
                    mlvo=MLVO_Matcher(
                        model="g",
                        layout="2",
                        variant="B",
                        option="foobar",
                        layout_range="1",
                    ),
                    section=Section.types,
                    section_value="t2",
                ),
            ],
        ),
    )
    assert raw.tell() == len(raw.getvalue())

    # Rules sets: breaks on other directive
    raw = io.StringIO(
        textwrap.dedent(
            """
            ! model  layout = symbols
              a      1      = s1
            ! include foo/bar
            ! model  layout = types
              b      2      = t1
            // description
            ! $group = A B
            """
        )
    )
    assert tuple(RulesFile.parse(raw)) == (
        RulesSet(
            MLVO_Set(model=True, layout=True),
            section=Section.symbols,
            rules=[
                Rule(
                    mlvo=MLVO_Matcher(model="a", layout="1"),
                    section=Section.symbols,
                    section_value="s1",
                )
            ],
        ),
        Include("foo/bar"),
        RulesSet(
            MLVO_Set(model=True, layout=True),
            section=Section.types,
            rules=[
                Rule(
                    mlvo=MLVO_Matcher(model="b", layout="2"),
                    section=Section.types,
                    section_value="t1",
                )
            ],
        ),
        Group(name="$group", members={"A", "B"}, description="description"),
    )
    assert raw.tell() == len(raw.getvalue())

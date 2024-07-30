from __future__ import annotations

import dataclasses
import functools
import math
import re
import sys
import textwrap
from dataclasses import dataclass
from enum import IntFlag, auto, unique
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, Generator, Iterable, Optional, TextIO

if TYPE_CHECKING:
    from typing import Self
else:
    Self = "Self"

try:
    # Available from Python 3.11
    from enum import StrEnum
except ImportError:
    # Fallback to external package
    from strenum import StrEnum

import lxml.etree as ET

from rules.components import (
    RMLVO,
    LayoutRange,
    MLVO_Matcher,
    MLVO_Set,
    Priority,
    Section,
    TargetRules,
)
from rules.directive import Directive, FileRef, resolve_option
from rules.group import Group, GroupMember, fetch_subelement, find_tag_insertion_index

MAX_LAYOUT_INDEX = 4
AUTO_VALUE = "AUTO"


@dataclass
class Include:
    """
    Include statement in rules files
    """

    INCLUDE_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"""^!\s+include\s+(?P<file>[^\s"]+)\s*$"""
    )

    file: str

    @classmethod
    def parse_header(cls, line: str) -> Self | None:
        if m := cls.INCLUDE_PATTERN.match(line):
            file = m.group("file")
            # Additional checks for “%”
            parts = file.replace(r"%%", "").split("%")
            for part in parts[1:]:
                if part:
                    if part[0] == "H":
                        continue
                    elif part[0] in ("E", "S"):
                        # “/rules” is already added by %-expansion
                        if not part[1:].startswith("/rules"):
                            continue
                return None
            return cls(file)
        else:
            return None


@unique
class RuleCategory(StrEnum):
    compatibility = "compatibility"
    _xml_attribute = "category"

    @classmethod
    def parse(cls, raw: str) -> Self:
        for c in cls:
            if c is not cls._xml_attribute and c == raw:
                return c
        raise ValueError(raw)


@dataclass(frozen=True, order=True)
class Rule:
    """
    A rule associates a MLVO matcher to a section and its value.
    """

    RULE_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"""
        ^
        (?P<mlvo>(?:\s+[^!\s=]+)+)
        \s+=\s+
        (?P<section>\S+)
        \s*$
        """,
        re.VERBOSE,
    )

    LAYOUT_VARIANT_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"""
        (?:
            \%
            (?:
                (?P<prefix>\+|\||-|_)
            | (?P<parenthesis>\()
            )?
            (?P<component>l|v)
            (?:
                \[
                (?P<index>\d+|\%i)
                \]
            )?
            (?(parenthesis)\))
            (?:\:(?P<target_index>\d+|\%i))?
        |   \:(?P<standalone_target_index>\d+|\%i)
        )
        """,
        re.VERBOSE,
    )
    """
    Matches:
    %l, %l[1], %l[2], …, %v, %v[1], %v[2], …
    %+l, %+l[1], %+l[2], …, %+v, %+v[1], %+v[2], …
    %(l), %(l[1]), %(l[2]), …, %(v), %(v[1]), %(v[2]), …
    """

    # NOTE: order of the field is important for the comparison functions
    section: Section
    mlvo: MLVO_Matcher
    section_value: str = ""
    rules_set: str = ""
    category: str = ""
    comment: str = ""

    def __iter__(self) -> Generator[Self, None, None]:
        if (layout_range := self.mlvo.layout_range) and isinstance(
            layout_range, LayoutRange
        ):
            for index in layout_range.indexes:
                mlvo = dataclasses.replace(self.mlvo, layout_range=index)
                section_value = self._replace_section_index(index)
                yield dataclasses.replace(self, mlvo=mlvo, section_value=section_value)
        else:
            yield self

    def _replace_section_index(self, index: str) -> str:
        return Directive.join(
            d.replace_index(index, self.mlvo) for d in self.section_value_directives
        )

    @property
    def section_value_directives(self) -> Generator[Directive, None, None]:
        yield from Directive.parse_multiple(self.section_value)

    @classmethod
    def parse(
        cls, mlvo: Iterable[RMLVO], layout_range: str, section: Section, raw: str
    ) -> Self:
        if (m := cls.RULE_PATTERN.match(raw)) is None:
            raise ValueError(raw)
        mlvo = dict(zip(mlvo, m.group("mlvo").split()))
        return cls(
            mlvo=MLVO_Matcher(layout_range=layout_range, **mlvo),
            section=section,
            section_value=m.group("section"),
        )

    @classmethod
    def parse_xml(
        cls,
        elem: ET.Element,
        implied: dict[RMLVO, str],
        priority: Priority,
        comment="",
    ) -> Self:
        section_value = ""
        for section in Section:
            if section_value := elem.attrib.get(section):
                break
        else:
            raise ValueError(f"Cannot parse rule element section: {elem.attrib}")
        raw_category = elem.attrib.get("category")
        return cls(
            mlvo=MLVO_Matcher.parse_elem(elem, implied, priority),
            rules_set=elem.attrib.get("rules", ""),
            category=RuleCategory.parse(raw_category)
            if raw_category is not None
            else "",
            section=section,
            section_value=section_value,
            comment=comment,
        )

    @classmethod
    def parse_xml_multiple(
        cls,
        config: ET.Element,
        implied: dict[RMLVO, str],
        priority: Priority,
        remove: bool = False,
    ) -> Generator[Rule, None, None]:
        if (rules_elem := fetch_subelement(config, "rules")) is not None:
            for es in iter_subelements_with_comment(rules_elem, "rule"):
                rule_elem, comment = es
                yield cls.parse_xml(
                    rule_elem,
                    implied,
                    priority=priority,
                    comment="" if comment is None else comment.text,
                )
            if remove:
                rules_elem.getparent().remove(rules_elem)
        elif (e := fetch_subelement_with_comment(config, "rule")) is not None:
            rule_elem, comment = e
            yield cls.parse_xml(
                rule_elem,
                implied,
                priority=priority,
                comment="" if comment is None else comment.text,
            )
            if remove:
                rule_elem.getparent().remove(rule_elem)
                if comment is not None:
                    comment.getparent().remove(comment)

    def add_elem(self, parent: ET.Element, *skipped_components: RMLVO):
        if self.comment:
            comment = ET.Comment(self.comment)
            parent.append(comment)
        rule = ET.SubElement(parent, "rule")
        for component, value in self.mlvo:
            if component not in skipped_components:
                rule.set(component, value)
            if component == "layout" and self.mlvo.layout_range:
                rule.set("layout-range", self.mlvo.layout_range)
        rule.set(self.section, self.section_value)
        if self.rules_set:
            rule.set("rules", self.rules_set)
        if self.category:
            rule.set("category", self.category)
        if self.mlvo.priority is not Priority.normal:
            rule.set("priority", self.mlvo.priority.name)

    @classmethod
    def replace_elem(
        cls, config: ET.Element, rules: Iterable[Self], *skipped_components: RMLVO
    ):
        if (elem := fetch_subelement(config, "rules")) is not None:
            config.remove(elem)
        elif (elem := fetch_subelement(config, "rule")) is not None:
            if (e := elem.getprevious()) is not None and isinstance(e, ET._Comment):
                config.remove(e)
            config.remove(elem)

        sorted_rules = sorted(rules)
        if not sorted_rules:
            return
        elif len(sorted_rules) < 2:
            sorted_rules[0].add_elem(config, *skipped_components)
        else:
            parent = config.makeelement("rules")
            config.append(parent)
            for alias in sorted_rules:
                alias.add_elem(parent, *skipped_components)

    @staticmethod
    def replace_index(layout_index: str, original: str, m: re.Match[str]) -> str:
        if target_index_m := m.group("standalone_target_index"):
            if target_index_m == layout_index:
                # Index match: generalize
                target_index = r":%i"
            elif target_index_m == r"%i":
                # Specialize
                target_index = f":{layout_index}" if layout_index else ""
            else:
                # Keep unchanged
                target_index = f":{target_index_m}"
            return target_index

        if (index_m := m.group("index")) is None:
            if not layout_index or layout_index == "1":
                # First index
                index = r"[%i]"
            else:
                # No index
                index = ""
        elif index_m == layout_index:
            # Index match: generalize
            index = r"[%i]"
        elif index_m == r"%i":
            # Specialize
            index = f"[{layout_index}]" if layout_index else ""
        else:
            # Keep unchanged
            index = f"[{index_m}]"

        if (target_index_m := m.group("target_index")) is None:
            end = m.end()
            if end < len(original) and original[end] not in ("+", "|"):
                # Followed by something different than other directive
                target_index = ""
            elif not layout_index or layout_index == "1":
                # First index
                target_index = r":%i"
            else:
                target_index = ""
        elif target_index_m == layout_index:
            # Index match: generalize
            target_index = r":%i"
        elif target_index_m == r"%i":
            # Specialize
            target_index = f":{layout_index}" if layout_index else ""
        else:
            # Keep unchanged
            target_index = f":{target_index_m}"

        component = m.group("component")
        assert component

        if m.group("parenthesis"):
            return f"%({component}{index}){target_index}"
        else:
            prefix = m.group("prefix") or ""
            return f"%{prefix}{component}{index}{target_index}"

    def toggle_section_indexes_generalization(self) -> Self:
        return dataclasses.replace(
            self,
            section_value=self.LAYOUT_VARIANT_PATTERN.sub(
                functools.partial(
                    self.replace_index, self.mlvo.layout_range, self.section_value
                ),
                self.section_value,
            ),
        )

    def groups_used(self) -> Generator[str, None, None]:
        for v in self.mlvo.values:
            if Group.is_group_name(v):
                yield v

    def conflicts(self, other: Rule) -> bool | None:
        if self.section is not other.section:
            return False
        elif (
            (conflict := self.mlvo.conflicts(other.mlvo))
            and self.section_value != other.section_value
        ) or conflict is None:
            return conflict
        else:
            return False

    def resolve_auto_value(self, xkb_root: Path, main_component: RMLVO) -> Self:
        # Build directives from section value
        if AUTO_VALUE in self.section_value:
            # Replace `AUTO` by a value built from the main component
            main_component_value = getattr(self.mlvo, main_component)
            if (
                main_component is RMLVO.variant
                and (layout := getattr(self.mlvo, RMLVO.layout))
                and not MLVO_Matcher.is_wildcard(layout)
            ):
                section_value = self.make_auto_value(
                    xkb_root,
                    self.section,
                    self.section_value,
                    layout,
                    main_component_value,
                )
            elif (
                main_component is RMLVO.layout
                and (variant := getattr(self.mlvo, RMLVO.variant))
                and not MLVO_Matcher.is_wildcard(variant)
            ):
                section_value = self.make_auto_value(
                    xkb_root,
                    self.section,
                    self.section_value,
                    main_component_value,
                    variant,
                )
            else:
                section_value = self.make_auto_value(
                    xkb_root,
                    self.section,
                    self.section_value,
                    main_component_value,
                    None,
                )
            return dataclasses.replace(self, section_value=section_value)
        else:
            return self

    @staticmethod
    def make_auto_value(
        xkb_root: Path,
        section: Section,
        auto_value: str,
        value: str,
        value2: str | None,
    ) -> str:
        """
        Build a section value by replacing its `AUTO_VALUE` using MLVO components.
        """
        raw_value_: str | None
        if value2 is None:
            # Parse option name
            parts = value.split(":")
            parts_length = len(parts)
            if parts_length == 1:
                raw_value_ = parts[0]
                if ref := FileRef.resolve_file(xkb_root, section, parts[0], ""):
                    raw_value_ = ref.filename
                else:
                    raw_value_ = None
            elif parts_length == 2:
                if ref := FileRef.resolve_file(xkb_root, section, parts[0], parts[1]):
                    raw_value_ = f"{ref.filename}({ref.section})"
                else:
                    raw_value_ = None
            else:
                raise ValueError()
        else:
            if ref := FileRef.resolve_file(xkb_root, section, value, value2):
                raw_value_ = f"{ref.filename}({ref.section})"
            else:
                raw_value_ = None
        if raw_value_ is None:
            raise ValueError(f"Cannot resolve ({value}, {value2})")
        return auto_value.replace(AUTO_VALUE, raw_value_)


@functools.total_ordering
@dataclass(frozen=True, order=False, eq=True)
class RulesSetKey:
    """
    A key used to sort rules sets.
    """

    # Field order is important
    section: Section
    has_merge_mode: bool
    mlvo: MLVO_Set

    def __lt__(self, other) -> bool:
        if not isinstance(other, self.__class__):
            return NotImplemented

        # Section take precedence, so we group section definitions together
        if self.section < other.section:
            return True
        elif self.section > other.section:
            return False

        # Then merge mode take precedence, so section values without starting
        # merge mode are defined first, e.g. `foo = bar` before `foo = +bar`.
        if self.has_merge_mode < other.has_merge_mode:
            return True
        elif self.has_merge_mode > other.has_merge_mode:
            return False

        # Then compare MLVO fields:
        if not self.has_merge_mode:
            # None of the section values start with a merge mode. Order:
            # - If fields of one are a subset of another (including layout index),
            #   then the superset has higher priority (e.g. more specific).
            # - A rule with a variant has higher priority.
            # - See MLVO_Set order.
            if self.mlvo == other.mlvo:
                return False
            self_mlvo_fields = frozenset(self.mlvo.components)
            other_mlvo_fields = frozenset(other.mlvo.components)
            if self_mlvo_fields.issubset(other_mlvo_fields):
                return False
            elif other_mlvo_fields.issubset(self_mlvo_fields):
                return True
            elif self.mlvo.variant and not other.mlvo.variant:
                return True
            elif not self.mlvo.variant and other.mlvo.variant:
                return False

        return self.mlvo < other.mlvo


@dataclass
class RulesSet:
    """
    A rules set: group of rules with same MLVO and section type.
    """

    RULES_HEADER_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"""
        ^!
        (?P<mlvo>(?:\s+(?:model|layout|variant|option)(?:\[\d+\])?)+)
        \s+=\s+
        (?P<section>\w+)
        \s*$
        """,
        re.VERBOSE,
    )

    mlvo: MLVO_Set
    section: Section
    rules: list[Rule]

    @classmethod
    def parse_header(cls, line: str) -> tuple[RulesSet, tuple[RMLVO, ...]] | None:
        if (m := cls.RULES_HEADER_PATTERN.match(line)) is None:
            return None
        mlvo = m.group("mlvo").split()
        if (r := MLVO_Set.parse(mlvo)) is None:
            return None
        mlvo_set, mlvo_components = r
        return cls(mlvo_set, Section.parse(m.group("section")), []), mlvo_components


@dataclass
class Comment:
    """
    A generic comment
    """

    text: str = ""

    def __bool__(self) -> bool:
        return bool(self.text)

    def __add__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return dataclasses.replace(self, text=self._add(other.text))

    def __iadd__(self, other):
        if isinstance(other, str):
            self.text = self._add(other)
        elif not isinstance(other, self.__class__):
            return NotImplemented
        else:
            self.text = self._add(other.text)
        return self

    def _add(self, text: str) -> str:
        return f"{self.text}\n{text}"

    @classmethod
    def parse_line(cls, line: str) -> tuple[str, Self] | None:
        parts = line.split("//", maxsplit=1)
        if len(parts) > 1:
            return (parts[0], cls(parts[1]))
        else:
            return None

    def serialize(self) -> str:
        return textwrap.indent(self.text, "//", lambda _: True)


@unique
class Reorder(IntFlag):
    """
    Flags to control rules file items order.
    """

    none = 0
    sections = auto()
    sets = auto()
    rules = auto()
    groups = auto()
    all = sets | rules | groups

    @classmethod
    def parse(cls, raw: str) -> Self:
        try:
            return cls[raw]
        except KeyError:
            raise ValueError(raw)


@dataclass
class RulesFile:
    """
    A rules file
    """

    TAB_SIZE: ClassVar[int] = 8
    HEADER_START: ClassVar[str] = "! "
    LEADING_SPACES_COUNT: ClassVar[int] = len(HEADER_START)
    LEADING_SPACES: ClassVar[str] = LEADING_SPACES_COUNT * " "

    header: Comment
    groups: dict[str, Group]
    rules: dict[RulesSetKey, list[Rule]]

    def __add__(self, other) -> Self:
        if not isinstance(other, self.__class__):
            return NotImplemented

        header = (
            self.header + other.header
            if self.header and other.header
            else (self.header or other.header)
        )

        groups: dict[str, Group] = {}
        for gs in (self.groups, other.groups):
            for g_new in gs.values():
                if g_old := groups.get(g_new.name):
                    g_new = g_old + g_new
                groups[g_new.name] = g_new

        rules: dict[RulesSetKey, list[Rule]] = {
            k: list(rs) for k, rs in self.rules.items()
        }
        for k, rs1 in other.rules.items():
            if (rs2 := rules.get(k)) is None:
                rules[k] = list(rs1)
            else:
                rs2.extend(rs1)

        return dataclasses.replace(
            self,
            header=header,
            groups=groups,
            rules=rules,
        )

    @staticmethod
    def parse(
        fd: TextIO,
    ) -> Generator[RulesSet | Group | Include | Comment, None, None]:
        rules_set: RulesSet | None = None
        mlvo: tuple[RMLVO, ...] = ()
        pending_comment: Comment | None = None
        pending_line: str = ""
        pending_line_number: int | None = None
        for line_number, raw_line in enumerate(fd, start=1):
            # Handle comment
            parts = raw_line.split("//", maxsplit=1)
            line = parts[0]
            if len(parts) > 1:
                comment: Comment | None = Comment(parts[1].rstrip())
            else:
                comment = None
            # Handle EOL escape
            parts = line.split("\\")
            if (length := len(parts)) > 1:
                # Only valid if actually at the end of the line
                if length > 2 or parts[-1] != "\n":
                    raise ValueError(line_number, parts, raw_line)
                else:
                    if pending_line_number is None:
                        pending_line_number = line_number
                    pending_line += raw_line[:-2]
                    continue
            # Complete pending line
            line = pending_line + line
            pending_line = ""
            # Skip line with only whitespaces or comment.
            if not line.lstrip():
                if comment is None:
                    # Yield then reset pending comment on blank line
                    if pending_comment is not None:
                        yield pending_comment
                        pending_comment = None
                elif pending_comment is None:
                    pending_comment = comment
                else:
                    # Gather comments
                    pending_comment += comment
                continue
            # Pending comment will be used for item description or discarded.
            # Rules set header
            if (rs := RulesSet.parse_header(line)) is not None:
                if rules_set is not None:
                    yield rules_set
                rules_set, mlvo = rs
            # Group
            elif (group := Group.parse_header(line)) is not None:
                if rules_set is not None:
                    yield rules_set
                    rules_set = None
                if pending_comment is not None:
                    group.description = textwrap.dedent(pending_comment.text)
                yield group
            # Include
            elif (inc := Include.parse_header(line)) is not None:
                if rules_set is not None:
                    yield rules_set
                    rules_set = None
                yield inc
            # Rules
            elif rules_set is not None:
                if comment is not None:
                    if comment is not None:
                        # Current comment has priority
                        pending_comment = comment
                try:
                    rule = Rule.parse(
                        mlvo=mlvo,
                        layout_range=rules_set.mlvo.layout_range,
                        section=rules_set.section,
                        raw=line,
                    )
                except ValueError:
                    print(f"[ERROR] Invalid line {line_number}: {raw_line}")
                    raise
                # TODO use comment for rule?
                rules_set.rules.append(rule)
            # Unsupported: error
            else:
                line_ref = (
                    str(line_number)
                    if pending_line_number is None
                    else f"{pending_line_number}-{line_number}"
                )
                raise ValueError(f"Cannot parse line {line_ref}: {line}")
            pending_line_number = None
            pending_line = ""
            pending_comment = None
        if pending_line:
            raise ValueError(pending_line)
        if rules_set is not None:
            yield rules_set
        if pending_comment is not None:
            yield pending_comment

    def serialize(
        self, out: TextIO, reorder: Reorder = Reorder.all, debug: bool = False
    ):
        """
        Print the serialization of the rules sets.
        """
        # Header
        if self.header:
            print(self.header.serialize().rstrip(), end="\n\n", file=out)

        # Groups
        if Reorder.groups in reorder:
            sorted_groups = sorted(
                self.groups.values(), key=lambda x: (x.component or "", x.name)
            )
        else:
            sorted_groups = list(self.groups.values())
        for g in sorted_groups:
            print(g.serialize_all(), file=out, end="\n\n")

        # Rules
        if Reorder.sets in reorder:
            rules_sets_keys = sorted(self.rules)
        elif Reorder.sections in reorder:
            rules_sets_keys = sorted(self.rules, key=lambda x: x.section)
        else:
            rules_sets_keys = list(self.rules)

        for key in rules_sets_keys:
            if debug:
                print(f"// {key.has_merge_mode=}", file=out)
            components = key.mlvo.components
            components[0] = self.HEADER_START + components[0]

            rules = self.rules[key]
            if Reorder.rules in reorder:
                # Sort the rules with special treatment of wildcard `*` and groups `$xxx`.
                rules = sorted(rules, key=lambda x: x.mlvo)

            # Pretty-printing: Find the minimal length of each component.
            sizes = [len(c) + 1 for c in components]
            groups = [False for _ in components]
            for rule in rules:
                for k, c in enumerate(rule.mlvo.values):
                    if has_group := Group.is_group_name(c):
                        groups[k] = True
                    xtra_space = (
                        self.LEADING_SPACES_COUNT if k == 0 else (1 if has_group else 0)
                    )
                    sizes[k] = max(sizes[k], len(c) + 1 + xtra_space)

            # Print header
            for k, s in enumerate(sizes):
                sizes[k] = math.ceil(s / self.TAB_SIZE) * self.TAB_SIZE
                components[k] = self.append_tabs(
                    " " + components[k] if groups[k] and k > 0 else components[k],
                    sizes[k],
                )
            print(f"{''.join(components)}= {key.section}", file=out)

            # Print rules
            def prepend_space(c: str, k: int):
                if Group.is_group_name(c):
                    if k == 0:
                        return self.LEADING_SPACES[:-1] + c
                    else:
                        return c
                elif k == 0:
                    return self.LEADING_SPACES + c
                elif groups[k]:
                    return " " + c
                else:
                    return c

            for rule in rules:
                if debug:
                    print("  // ", rule, file=out)
                print(
                    *(
                        self.append_tabs(prepend_space(c, k), s)
                        for k, (c, s) in enumerate(zip(rule.mlvo.values, sizes))
                    ),
                    "= ",
                    rule.section_value,
                    sep="",
                    file=out,
                )
            print(file=out)

    @classmethod
    def append_tabs(cls, text: str, target_length: int) -> str:
        """
        Appends tabs to reach the target string length.
        """
        length = len(text)
        if length > target_length:
            return text
        else:
            count = math.ceil((target_length - length) / cls.TAB_SIZE)
            return text + count * "\t"


@dataclass(frozen=True)
class Alias:
    """
    An alias for a layout
    """

    ALIAS_HIGHER_PRIORITY_TAGS: ClassVar[tuple[str, ...]] = (
        "name",
        "shortDescription",
        "description",
        "vendor",
        "membership",
        "member-of",
        "countryList",
        "languageList",
        "hwList",
    )
    """DTD tag order for <aliases> and <alias>"""
    DEFAULT_PRIORITY: ClassVar[Priority] = Priority.highest

    mlvo: MLVO_Matcher
    target_layout: str
    target_variant: str
    category: RuleCategory | None = None
    rules_set: str = ""
    comment: str = ""

    @classmethod
    def parse(
        cls,
        alias_elem: ET.Element,
        component: RMLVO,
        component_value: str,
        parent_component: RMLVO | None,
        parent_component_value: str,
        comment: str,
        priority: Priority | None = None,
    ) -> Self:
        """
        Parse an explicit alias in a XML file.
        """
        rules_set = alias_elem.attrib.get(RMLVO.rules, "")
        if raw_category := alias_elem.attrib.get(RuleCategory._xml_attribute):
            category = RuleCategory.parse(raw_category)
        else:
            category = None

        # Parse MLVO components

        # Parse layout
        layout = alias_elem.attrib.get(RMLVO.layout)

        # Parse variant
        # TODO: raise error if variant without layout?
        variant = alias_elem.attrib.get(RMLVO.variant)
        target_variant = alias_elem.attrib.get("target-variant", "")

        if component is RMLVO.layout:
            target_layout = component_value
        elif parent_component is RMLVO.layout and component is RMLVO.variant:
            target_layout = parent_component_value
            if target_variant and target_variant != component_value:
                raise ValueError(target_variant, component_value)
            target_variant = component_value
        else:
            raise ValueError()

        if not layout:
            raise ValueError()

        matcher = MLVO_Matcher(
            model="*",
            layout=layout,
            layout_range=LayoutRange.Any,
            variant=variant or "",
            # FIXME not sure of this
            priority=cls.DEFAULT_PRIORITY
            if priority is None or priority is Priority.normal
            else priority,
        )

        return cls(
            mlvo=matcher,
            target_layout=target_layout,
            target_variant=target_variant,
            category=category,
            rules_set=rules_set,
            comment=comment,
        )

    @classmethod
    def parse_multiple(
        cls,
        config: ET.Element,
        component: RMLVO,
        component_value: str,
        parent_component: RMLVO | None,
        parent_component_value: str,
        priority: Priority | None = None,
        remove: bool = False,
    ) -> Generator[Self, None, None]:
        """
        Parse explicit aliases in a XML file.
        """
        if (aliases_elem := fetch_subelement(config, "aliases")) is not None:
            for es in iter_subelements_with_comment(aliases_elem, "alias"):
                alias_elem, comment = es
                yield cls.parse(
                    alias_elem,
                    component,
                    component_value,
                    parent_component,
                    parent_component_value,
                    comment="" if comment is None else comment.text,
                    priority=priority,
                )
            if remove:
                aliases_elem.getparent().remove(aliases_elem)
        elif (e := fetch_subelement_with_comment(config, "alias")) is not None:
            alias_elem, comment = e
            yield cls.parse(
                alias_elem,
                component,
                component_value,
                parent_component,
                parent_component_value,
                comment="" if comment is None else comment.text,
                priority=priority,
            )
            if remove:
                alias_elem.getparent().remove(alias_elem)
                if comment is not None:
                    comment.getparent().remove(comment)

    def add_elem(
        self, parent: ET.Element, index: int | None = None, target_variant: bool = False
    ):
        if self.comment:
            comment = ET.Comment(self.comment)
            if index is None:
                parent.append(comment)
            else:
                parent.insert(index, comment)
                index += 1
        alias = parent.makeelement("alias")
        if index is None:
            parent.append(alias)
        else:
            parent.insert(index, alias)

        if self.rules_set:
            alias.set("rules", self.rules_set)
        if self.category:
            alias.set("category", self.category)
        for component, value in self.mlvo:
            if component is RMLVO.model and MLVO_Matcher.is_wildcard(value):
                continue
            alias.set(component, value)
        if target_variant and self.target_variant:
            alias.set("target-variant", self.target_variant)

    @classmethod
    def add_multiple_elem(
        cls, config: ET.Element, aliases: Iterable[Self], target_variant: bool = False
    ):
        sorted_aliases = sorted(aliases, key=lambda x: x.mlvo)
        if not sorted_aliases:
            return
        elif len(sorted_aliases) < 2:
            alias = sorted_aliases[0]
            alias.add_elem(
                config,
                index=find_tag_insertion_index(cls.ALIAS_HIGHER_PRIORITY_TAGS, config),
                target_variant=target_variant,
            )
        else:
            parent = config.makeelement("aliases")
            config.insert(
                find_tag_insertion_index(cls.ALIAS_HIGHER_PRIORITY_TAGS, config), parent
            )
            for alias in sorted_aliases:
                alias.add_elem(parent, target_variant=target_variant)

    @classmethod
    def replace_elem(
        cls, config: ET.Element, aliases: Iterable[Self], target_variant: bool = False
    ):
        if (elem := fetch_subelement(config, "aliases")) is not None:
            config.remove(elem)
        elif (elem := fetch_subelement(config, "alias")) is not None:
            if (e := elem.getprevious()) is not None and isinstance(e, ET._Comment):
                config.remove(e)
            config.remove(elem)

        sorted_aliases = sorted(aliases, key=lambda x: x.mlvo)
        if not sorted_aliases:
            return
        elif len(sorted_aliases) < 2:
            sorted_aliases[0].add_elem(
                config,
                index=find_tag_insertion_index(cls.ALIAS_HIGHER_PRIORITY_TAGS, config),
                target_variant=target_variant,
            )
        else:
            parent = config.makeelement("aliases")
            config.insert(
                find_tag_insertion_index(cls.ALIAS_HIGHER_PRIORITY_TAGS, config), parent
            )
            for alias in sorted_aliases:
                alias.add_elem(parent, target_variant=target_variant)


@dataclass
class Layout:
    """
    A layout reference
    """

    PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"(?P<layout>[^(]+)\((?P<variant>[^)]+)\)"
    )
    layout: str
    variant: str = ""
    comment: str = ""

    def __init__(self, layout, variant="", comment=""):
        self.layout = layout
        self.variant = variant
        self.comment = comment
        if "(" in layout:
            if variant:
                raise ValueError()
            # parse a `layout(variant)` string
            if match := self.PATTERN.match(layout):
                self.layout = match.group("layout")
                self.variant = match.group("variant")

    def __str__(self):
        if self.variant:
            return "{}({})".format(self.layout, self.variant)
        else:
            return "{}".format(self.layout)

    @classmethod
    def parse_aliases(cls, path: Path) -> Generator[tuple[Self, Self], None, None]:
        with path.open("rt", encoding="UTF-8") as fd:
            for line in fd:
                raw_groups, *rest = line.split("//")
                comment = rest[0].strip() if rest else ""
                groups = raw_groups.split()
                if len(groups) == 2:
                    yield (cls(groups[0]), cls(groups[1], comment=comment))
                else:
                    yield (
                        cls(groups[0], groups[1]),
                        cls(groups[2], groups[3], comment=comment),
                    )

    @classmethod
    def _aliases(
        cls, layout_mappings: tuple[tuple[Layout, Layout], ...]
    ) -> Generator[Alias, None, None]:
        for l1, l2 in layout_mappings:
            mlvo = MLVO_Matcher(
                model="*",
                layout=l1.layout,
                layout_range=LayoutRange.Any,
                variant=l1.variant or "",
                option="",
                priority=Alias.DEFAULT_PRIORITY,
            )
            yield Alias(
                mlvo=mlvo,
                target_layout=l2.layout,
                target_variant=l2.variant,
                category=RuleCategory.compatibility,
                comment=f" {l2.comment} " if l2.comment else "",
            )

    @classmethod
    def aliases(cls) -> Generator[Alias, None, None]:
        for f in ("layoutsMapping.lst", "variantsMapping.lst"):
            path = Path(__file__).parent / "compat" / f
            mappings = tuple(Layout.parse_aliases(path))
            yield from Layout._aliases(mappings)


@dataclass
class MLVO:
    component: RMLVO
    name: str
    description: str
    disabled: bool
    target_rules: TargetRules
    priority: Priority
    rules: list[Rule]
    aliases: list[Alias]
    groups: list[GroupMember]
    elem: ET.Element
    config_elem: ET.Element
    parent_component: RMLVO | None = None
    parent_component_value: str = ""

    @property
    def main_components(self) -> Generator[RMLVO, None, None]:
        if self.parent_component is not None:
            yield self.parent_component
        yield self.component

    @classmethod
    def parse_xml(
        cls,
        elem: ET.Element,
        xkb_root: Path,
        component: RMLVO,
        parent_component: RMLVO | None = None,
        parent_component_value: str = "",
    ) -> Self:
        try:
            elem_rules = TargetRules(elem.attrib.get("rules", ""))
            disabled = elem.attrib.get("disabled") == "true"

            # Get default priority
            if raw_value := elem.attrib.get("priority"):
                priority = Priority.parse(raw_value)
            else:
                # Try to get priority from a parent
                parent: Optional[ET.Element] = None
                if component is RMLVO.option:
                    # Get option group value
                    parent = elem.getparent()
                elif component is RMLVO.variant:
                    # Get layout value
                    parent = elem.getparent().getparent()
                if parent is not None and (raw_value := parent.attrib.get("priority")):
                    priority = Priority.parse(raw_value)
                else:
                    priority = Priority.normal

            if (config := fetch_subelement(elem, "configItem")) is None:
                raise ValueError(component, elem)

            # Name of the main MLVO component
            if (name := fetch_text(config, "name")) is None:
                raise ValueError()
            description = dedent_xml_value(fetch_text(config, "description") or "")
            is_group = Group.is_group_name(name)

            # Lookup for <member-of> tags for group definition
            groups: list[GroupMember] = []
            if (membership := fetch_subelement(config, "membership")) is None:
                membership = config
            for member_elem in membership.iter("member-of"):
                if is_group:
                    raise ValueError(
                        f"Group “{name}” cannot be a member of another group (“{member_elem}”)"
                    )
                if member_elem.text:
                    member_rules = member_elem.attrib.get("rules", "")
                    groups.append(
                        GroupMember(
                            group=member_elem.text,
                            component=component,
                            name=name,
                            target_rules=member_rules,
                        )
                    )
                else:
                    raise ValueError()

            # Look for <aliases> and <alia> tags
            # Parse and yield all explicit rules from aliases
            aliases: list[Alias] = list(
                Alias.parse_multiple(
                    config=config,
                    component=component,
                    component_value=name,
                    parent_component=parent_component,
                    parent_component_value=parent_component_value,
                    priority=priority,
                    remove=False,
                )
            )

            # Look for <rules> and <rule> tags which contain explicit rules
            implied: dict[RMLVO, str] = {component: name}
            if parent_component is not None:
                implied[parent_component] = parent_component_value
            rules: list[Rule] = list(
                Rule.parse_xml_multiple(
                    config=config, implied=implied, priority=priority
                ),
            )

            # Process options with no explicit rules
            if component is RMLVO.option and not rules:
                # These options map "xxx:yyy" to "xxx" file with section "yyy".
                matcher = MLVO_Matcher(
                    option=name,
                    priority=Priority.normal if priority is None else priority,
                )
                directive_set = resolve_option(xkb_root, name)
                if directive_set.is_empty:
                    raise ValueError(
                        f"Option {name} has nor rules and does not resolve to any section"
                    )
                for section, directive in directive_set:
                    rules.append(
                        Rule(
                            mlvo=matcher,
                            section=section,
                            section_value=str(directive),
                            rules_set=elem_rules.rules,
                        )
                    )

        except ValueError as e:
            endl = "\n"  # f{} cannot contain backslashes
            e.args = (
                f"\nFor element {ET.tostring(elem).decode('utf-8')}\n{endl.join(e.args)}",
            )
            raise

        return cls(
            component=component,
            name=name,
            description=description,
            disabled=disabled,
            target_rules=elem_rules,
            priority=priority,
            rules=rules,
            aliases=aliases,
            groups=groups,
            elem=elem,
            config_elem=config,
            parent_component=parent_component,
            parent_component_value=parent_component_value,
        )

    @classmethod
    def parse_xml_all(
        cls, xkb_root: Path, root: ET.Element
    ) -> Generator[Self, None, None]:
        # Iter over <model>, <layout> and <option> tags
        for component in (RMLVO.model, RMLVO.layout, RMLVO.option):
            for elem in root.iter(component):
                entry = cls.parse_xml(elem, xkb_root, component)
                yield entry
                # Process layout variants
                if (
                    component is RMLVO.layout
                    and (variants := fetch_subelement(elem, "variantList")) is not None
                ):
                    for variant in variants.iter(RMLVO.variant):
                        yield cls.parse_xml(
                            variant,
                            xkb_root,
                            RMLVO.variant,
                            entry.component,
                            entry.name,
                        )


################################################################################
## XML
################################################################################


def fetch_subelement_with_comment(
    parent, name
) -> Optional[tuple[ET.Element, ET.Element | None]]:
    """
    Fetch single XML sub-element, if defined.
    """
    comment = None
    for sub_element in parent.iter():
        if isinstance(sub_element, ET._Comment):
            comment = sub_element
        else:
            if sub_element.tag == name:
                return sub_element, comment
            else:
                comment = None
    return None


def iter_subelements_with_comment(
    parent, name
) -> Generator[tuple[ET.Element, ET.Element | None], None, None]:
    """
    Fetch XML sub-element, if defined.
    """
    comment = None
    for sub_element in parent.iter():
        if isinstance(sub_element, ET._Comment):
            comment = sub_element
        else:
            if sub_element.tag == name:
                yield sub_element, comment
            else:
                comment = None


def fetch_text(parent, name) -> str | None:
    """
    Get component name from XML sub-element
    """
    sub_element = fetch_subelement(parent, name)
    if sub_element is None:
        return None
    return sub_element.text


def dedent_xml_value(raw: str | None) -> str:
    """
    Remove leading spaces and remove start and end blank lines
    """
    if raw:
        return textwrap.dedent(raw).strip("\n")
    else:
        return ""

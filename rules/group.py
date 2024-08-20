from __future__ import annotations

import dataclasses
import re
import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, Iterable, Optional

if TYPE_CHECKING:
    from typing import Self
else:
    Self = "Self"

import lxml.etree as ET

from rules.components import RMLVO, is_group_name


@dataclass(frozen=True, order=True)
class GroupMember:
    group: str
    component: RMLVO
    name: str
    target_rules: str = ""

    def add_membership_elem(self, parent: ET.Element, index: int | None = None):
        if index is None:
            member_of = ET.SubElement(parent, "member-of")
        else:
            member_of = parent.makeelement("member-of")
            parent.insert(index, member_of)
        member_of.text = self.group
        if self.target_rules:
            member_of.set("rules", self.target_rules)

    @classmethod
    def replace_memberships_elem(cls, config: ET.Element, ms: Iterable[Self]):
        if (elem := fetch_subelement(config, "membership")) is not None:
            config.remove(elem)
        elif (elem := fetch_subelement(config, "member-of")) is not None:
            config.remove(elem)

        members = sorted(ms)
        if not members:
            return
        elif len(members) > 1:
            membership = config.makeelement("membership")
            config.insert(cls.find_member_index(config), membership)
            for m in members:
                m.add_membership_elem(membership)
        else:
            members[0].add_membership_elem(config, index=cls.find_member_index(config))

    @staticmethod
    def find_member_index(config: ET.Element):
        return find_tag_insertion_index(Group.MEMBER_HIGHER_PRIORITY_TAGS, config)


@dataclass
class Group:
    """
    Group of items used in rules
    """

    MEMBER_HIGHER_PRIORITY_TAGS: ClassVar[tuple[str, ...]] = (
        "name",
        "shortDescription",
        "description",
        "vendor",
    )
    """DTD tag order for <membership> and <member-of>"""

    GROUP_HEADER_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"""
        ^!\s+
        (?P<name>\$(?:\w|-)+)
        \s+=
        (?P<members>(?:\s+(?:\w|-)+)+)
        \s*$
        """,
        re.VERBOSE,
    )

    name: str
    "Groups name starts with $"
    members: set[str]
    component: RMLVO | None = None
    rules_set: str = ""
    disabled: bool | None = None
    description: str = ""
    xml: Path | None = None

    def __add__(self, other) -> Group:
        if not isinstance(other, self.__class__):
            return NotImplemented
        if self.name != other.name or self.component != other.component:
            raise ValueError()

        if self.disabled is None:
            disabled = other.disabled
        elif other.disabled is None:
            disabled = self.disabled
        elif self.disabled == other.disabled:
            disabled = self.disabled
        else:
            raise ValueError()

        if self.rules_set and other.rules_set and self.rules_set != other.rules_set:
            raise ValueError(self, other)
        rules_set = self.rules_set or other.rules_set

        sep = "\n" if self.description and other.description else ""
        description = self.description + sep + other.description
        return dataclasses.replace(
            self,
            description=description,
            rules_set=rules_set,
            disabled=disabled,
            members=self.members.union(other.members),
        )

    def add(self, m: GroupMember):
        if m.component is not self.component or m.group != self.name:
            raise ValueError()
        self.members.add(m.name)

    @staticmethod
    def is_group_name(s: str) -> bool:
        return is_group_name(s)

    @classmethod
    def parse_header(cls, line: str) -> Group | None:
        if m := cls.GROUP_HEADER_PATTERN.match(line):
            name = m.group("name")
            members = m.group("members").split()
            return cls(name=name, members=set(members))
        else:
            return None

    def serialize(self) -> str:
        return f"! {self.name} = {' '.join(sorted(self.members, key=natural_sort_key))}"

    def serialize_all(self) -> str:
        disabled = not self.members or self.disabled
        group = self.serialize()
        eq_index = group.index("=") + 2
        group = " \\\n".join(
            textwrap.wrap(group, width=78, subsequent_indent=eq_index * " ")
        )
        if disabled:
            group = textwrap.indent(group, "//")
        if self.description:
            description = textwrap.indent(self.description, "// ")
            group = f"{description}\n{group}"
        return group


################################################################################
# Utils
################################################################################


def natural_sort_key(s, _nsre=re.compile(r"([0-9]+)")):
    return tuple(
        int(chunk) if chunk.isdigit() else chunk.lower() for chunk in _nsre.split(s)
    )


def find_tag_insertion_index(
    tags_priorities: tuple[str, ...], parent: ET.Element
) -> int:
    """
    Find position to insert that respect the DTD
    """
    for k, e in enumerate(parent):
        if isinstance(e, ET._Comment):
            continue
        if e.tag not in tags_priorities:
            assert k == parent.index(e), (k, parent.index(e))
            return k
    return k + 1


def fetch_subelement(parent, name) -> Optional[ET.Element]:
    """
    Fetch single XML sub-element, if defined.
    """
    sub_element = parent.findall(name)
    if sub_element is not None and len(sub_element) == 1:
        return sub_element[0]
    return None

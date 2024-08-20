"""
This file parses the registry XML files and prints out the rules.
See the meson.build file for how this is used.
"""

from __future__ import annotations

import contextlib
import dataclasses
import functools
import itertools
import operator
import sys
import textwrap
from collections import defaultdict
from pathlib import Path
from typing import (
    TYPE_CHECKING,
    Generator,
    Optional,
)

from rules.components import TargetRules

if TYPE_CHECKING:
    from typing import Self
else:
    Self = "Self"

import lxml.etree as ET

# Local import
from rules import (
    MLVO,
    RMLVO,
    Comment,
    LayoutRange,
    Rule,
    RuleCategory,
    RulesFile,
    RulesSetKey,
    Section,
    dedent_xml_value,
    fetch_subelement,
)
from rules.directive import (
    Directive,
    MergeMode,
)
from rules.group import Group


def parse_xml_registry(
    xkb_root: Path,
    compatibility_rules: bool,
    rules_xml: Path,
    target_rules: TargetRules,
) -> RulesFile:
    """
    Yields all rules from the given XML file
    """
    xml_parser = ET.XMLParser(
        dtd_validation=True, load_dtd=True, no_network=True, resolve_entities=True
    )
    tree = ET.parse(rules_xml, xml_parser)
    root = tree.getroot()

    groups: dict[str, Group] = {}

    def parse_component(
        elem: ET.Element,
        component: RMLVO,
        parent_component: RMLVO | None = None,
        parent_component_value: str = "",
    ) -> Generator[Rule, None, None]:
        entry: MLVO = MLVO.parse_xml(
            elem,
            xkb_root=xkb_root,
            component=component,
            parent_component=parent_component,
            parent_component_value=parent_component_value,
        )
        if not target_rules.matches(entry.target_rules):
            return

        if Group.is_group_name(entry.name):
            group: Group | None = Group(
                name=entry.name,
                disabled=entry.disabled,
                component=entry.component,
                description=entry.description,
                rules_set=entry.target_rules.rules,
                xml=rules_xml,
                members=set(),
            )
            assert group
            if (old_group := groups.get(entry.name)) is None:
                groups[group.name] = group
            else:
                groups[group.name] = old_group + group
        for membership in entry.groups:
            if not target_rules.matches(membership.target_rules):
                continue
            if (group := groups.get(membership.group)) is None:
                group = Group(
                    name=membership.group,
                    disabled=None,
                    rules_set=membership.target_rules,
                    component=membership.component,
                    members=set(),
                )
                groups[group.name] = group
            group.add(membership)
        for alias in entry.aliases if compatibility_rules else []:
            # Skip if the alias has a `rules` attribute that does not match the
            # target rules (base, evdev).
            if not target_rules.matches(alias.rules_set):
                continue

            # Skip if alias is a compatibility alias but those are filtered out
            if alias.category == RuleCategory.compatibility and not compatibility_rules:
                continue

            directive1 = Directive(merge=MergeMode.NoMode, filename="pc")
            directive2 = Directive(
                merge=MergeMode.Override,
                filename=alias.target_layout,
                section=alias.target_variant,
                index=r"%i",
            )
            matcher = dataclasses.replace(alias.mlvo, layout_range=LayoutRange.First)
            yield from Rule(
                mlvo=matcher,
                section=Section.symbols,
                section_value=Directive.join((directive1, directive2)),
            )
            matcher = dataclasses.replace(alias.mlvo, layout_range=LayoutRange.Later)
            yield from Rule(
                mlvo=matcher, section=Section.symbols, section_value=str(directive2)
            )
        for rule in entry.rules:
            if not target_rules.matches(rule.rules_set) or (
                rule.category == RuleCategory.compatibility and not compatibility_rules
            ):
                continue
            yield from rule.resolve_auto_value(xkb_root, component)
        # Process layout variants
        if (
            component is RMLVO.layout
            and (variants := fetch_subelement(elem, "variantList")) is not None
        ):
            for variant in variants.iter(RMLVO.variant):
                yield from parse_component(
                    variant, RMLVO.variant, component, entry.name
                )

    def fetch_all_rules():
        # Iter over <model>, <layout> and <option> tags
        for component in (RMLVO.model, RMLVO.layout, RMLVO.option):
            for elem in root.iter(component):
                for rule in parse_component(elem, component):
                    yield rule

    if (header_elem := fetch_subelement(root, "header")) is None:
        header = Comment()
    else:
        # Remove leading spaces and remove start and end blank lines
        header = Comment(dedent_xml_value(header_elem.text))
        # Normalize surrounding blank lines and indent
        header.text = textwrap.indent(f"\n{header.text}\n\n", "  ")

    rules: dict[RulesSetKey, list[Rule]] = defaultdict(list)
    for rule in fetch_all_rules():
        has_merge_mode = (
            rule.section_value
            and tuple(rule.section_value_directives)[0].merge is not MergeMode.NoMode
        )
        rules[RulesSetKey(rule.section, has_merge_mode, rule.mlvo.mlvo_set)].append(
            rule
        )

    return RulesFile(header=header, groups=groups, rules=rules)


def main(
    xkb_root: Path,
    compat: bool,
    rules: str,
    registry_files: list[Path],
    output: Optional[Path],
):
    target_rules = TargetRules(rules)
    # Extract rules from XML files
    rules_info: RulesFile = functools.reduce(
        operator.add,
        itertools.chain(
            parse_xml_registry(xkb_root, compat, f, target_rules)
            for f in registry_files
        ),
    )

    # Create rule sets: group rules by section, mlvo set and merge mode
    groups_used: set[str] = set()
    for r in itertools.chain.from_iterable(rules_info.rules.values()):
        groups_used.update(r.groups_used())

    groups_unused = tuple(
        g for g in rules_info.groups.values() if g.name not in groups_used
    )
    if any(g.xml is not None for g in groups_unused):
        print("[WARNING] Removed unused groups:", file=sys.stderr)
    for g in groups_unused:
        del rules_info.groups[g.name]
        # No warning for groups not used *and* not found or filtered out in XML
        if g.xml is not None:
            print(f"[WARNING] - {g}", file=sys.stderr)

    for g in rules_info.groups.values():
        if not g.members:
            print("[WARNING] Empty group:", g, file=sys.stderr)

    cm: contextlib.AbstractContextManager
    if output:
        path: Path = output
        cm = path.open("wt", encoding="utf-8")
    else:
        # We do not want to close stdout
        cm = contextlib.nullcontext(sys.stdout)

    with cm as fd:
        rules_info.serialize(fd)

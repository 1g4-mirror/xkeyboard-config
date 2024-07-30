from __future__ import annotations

import dataclasses
import itertools
import sys
from collections import defaultdict
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from typing import TYPE_CHECKING, Iterable, TypeAlias

from rules.components import MainComponents
from rules.group import GroupMember

if TYPE_CHECKING:
    from typing import Self
else:
    Self = "Self"

import lxml.etree as ET

# Local import
from rules import (
    AUTO_VALUE,
    MLVO,
    RMLVO,
    Alias,
    FileRef,
    Group,
    Include,
    Layout,
    LayoutRange,
    MLVO_Matcher,
    Priority,
    Rule,
    RulesFile,
    RulesSet,
    Section,
    find_tag_insertion_index,
)

ParsedRules: TypeAlias = dict[MainComponents, dict[tuple[RMLVO, ...], set[Rule]]]
ParsedAliases: TypeAlias = dict[tuple[str, str], list[Alias]]


@dataclass
class ParsedRulesResult:
    groups: dict[tuple[str, str], Group]
    aliases: ParsedAliases
    rules: ParsedRules


def parse_legacy_rules_file(
    compat: bool,
    groups: dict[tuple[str, str], Group],
    aliases: ParsedAliases,
    legacy_rules: dict[MainComponents, list[Rule]],
    path: Path,
):
    if "-base." in path.stem or path.name.endswith(".base"):
        rules = "base"
    elif "-evdev." in path.stem or path.name.endswith(".evdev"):
        rules = "evdev"
    else:
        rules = ""
    with path.open("rt", encoding="utf-8") as fd:
        for e in RulesFile.parse(fd):
            if isinstance(e, RulesSet):
                for rule in e.rules:
                    rule = dataclasses.replace(rule, rules_set=rules)
                    # Add rule
                    legacy_rules[rule.mlvo.main_components].append(rule)
                    # Check for groups
                    for c, v in rule.mlvo:
                        if not Group.is_group_name(v):
                            continue
                        if (group := groups.get((v, rules))) is None:
                            group = Group(name=v, component=c, members=set())
                            groups[group.name, rules] = group
                        elif group.component is None:
                            group.component = c
                        elif group.component != c:
                            raise ValueError(
                                f"Conflict for group component: {group}, got: {c}"
                            )
            elif isinstance(e, Group):
                group = e
                if group2 := groups.get((group.name, rules)):
                    if group2.members:
                        raise ValueError(f"Duplicated group: {group2} {group}")
                    group2.members.update(group.members)
                else:
                    groups[group.name, rules] = group
            elif isinstance(e, Include):
                raise ValueError(f"Include not supported: {e}")
            else:
                continue

    if compat:
        for alias in Layout.aliases():
            aliases[alias.target_layout, alias.target_variant].append(alias)


def parse_legacy_rules(
    xkb_root: Path, compat: bool, files: Iterable[Path]
) -> ParsedRulesResult:
    groups: dict[tuple[str, str], Group] = {}
    legacy_rules: dict[MainComponents, list[Rule]] = defaultdict(list)
    aliases: ParsedAliases = defaultdict(list)

    for f in files:
        parse_legacy_rules_file(compat, groups, aliases, legacy_rules, f)

    parsed_rules: ParsedRules = {}

    for main_component_key, rules in legacy_rules.items():
        # Prepare new rules
        by_mlvo: dict[tuple[RMLVO, ...], set[Rule]] = defaultdict(set)
        for rule in rules:
            if rule.mlvo.option:
                # Replace option section value with AUTO, if possible
                filename, section_name = rule.mlvo.option.split(":")
                if file_ref := FileRef.resolve_file(
                    xkb_root, rule.section, filename, section_name
                ):
                    file_ref_str = str(file_ref)
                    if file_ref_str in rule.section_value:
                        rule = dataclasses.replace(
                            rule,
                            section_value=rule.section_value.replace(
                                file_ref_str, AUTO_VALUE
                            ),
                        )
            # Group by MLVO (except index) and generalize section indexes
            by_mlvo[tuple(rule.mlvo.components)].add(
                rule.toggle_section_indexes_generalization()
            )
        for mlvo_fields_ in tuple(by_mlvo.keys()):
            g_old = by_mlvo[mlvo_fields_]
            by_section: dict[
                tuple[tuple[str, ...], str, str, Section, str], set[Rule]
            ] = defaultdict(set)
            for rule in g_old:
                by_section[
                    tuple(rule.mlvo.values),
                    rule.rules_set,
                    rule.category,
                    rule.section,
                    rule.section_value,
                ].add(rule)
            # special cases
            for key1 in tuple(by_section):
                mlvo_values, rules_set, category, section, section_value = key1
                if ":" in section_value:
                    continue
                key2 = (
                    mlvo_values,
                    rules_set,
                    category,
                    section,
                    section_value + r":%i",
                )
                if key2 in by_section:
                    by_section[key2].update(
                        dataclasses.replace(r, section_value=r.section_value + r":%i")
                        for r in by_section[key1]
                    )
                    del by_section[key1]

            g_new: set[Rule] = set()
            for g in by_section.values():
                if RMLVO.layout not in mlvo_fields_:
                    g_new.update(g)
                    continue
                indexes = sorted(r.mlvo.layout_range for r in g)
                comment = "\n".join(set(r.comment for r in g if r.comment))
                r = min(g)
                if indexes == [""]:
                    mlvo = dataclasses.replace(r.mlvo, layout_range=LayoutRange.Single)
                    r = r.toggle_section_indexes_generalization()
                    g_new.add(dataclasses.replace(r, mlvo=mlvo, comment=comment))
                elif indexes == ["1"]:
                    mlvo = dataclasses.replace(r.mlvo, layout_range=LayoutRange.One)
                    g_new.add(dataclasses.replace(r, mlvo=mlvo, comment=comment))
                elif indexes == ["", "1"]:
                    mlvo = dataclasses.replace(r.mlvo, layout_range=LayoutRange.First)
                    g_new.add(dataclasses.replace(r, mlvo=mlvo, comment=comment))
                elif indexes == ["", "1", "2", "3", "4"]:
                    mlvo = dataclasses.replace(r.mlvo, layout_range=LayoutRange.Any)
                    g_new.add(dataclasses.replace(r, mlvo=mlvo, comment=comment))
                elif indexes == ["2", "3", "4"]:
                    mlvo = dataclasses.replace(r.mlvo, layout_range=LayoutRange.Later)
                    g_new.add(dataclasses.replace(r, mlvo=mlvo, comment=comment))
                else:
                    print(
                        f"[WARNING] Cannot simplify layout range (bogus rule?): {indexes}",
                        file=sys.stderr,
                    )
                    for r in g:
                        print(f"[WARNING] - {r}", file=sys.stderr)
                    g = set(r.toggle_section_indexes_generalization() for r in g)
                    g_new.update(g)
            by_mlvo[mlvo_fields_] = g_new

        parsed_rules[main_component_key] = by_mlvo

    return ParsedRulesResult(groups, aliases, parsed_rules)


find_member_index = partial(find_tag_insertion_index, Group.MEMBER_HIGHER_PRIORITY_TAGS)


def update_registry(
    xkb_root: Path,
    parsed_rules: ParsedRulesResult,
    input_rules: Path,
    output_rules: Path,
    no_skip: bool,
) -> ParsedRulesResult:
    xml_parser = ET.XMLParser(
        remove_blank_text=True,
        dtd_validation=True,
        load_dtd=True,
        no_network=True,
        resolve_entities=True,
    )
    tree = ET.parse(input_rules, xml_parser)
    root = tree.getroot()

    entries: dict[RMLVO, dict[MainComponents, MLVO]] = defaultdict(dict)
    entry: MLVO | None
    for entry in MLVO.parse_xml_all(xkb_root, root):
        entry_key = MainComponents(
            entry.component,
            entry.name,
            entry.parent_component,
            entry.parent_component_value,
        )
        entries[entry.component][entry_key] = entry

    # Groups

    pending_groups: dict[tuple[str, str], Group] = {}
    for group_key, group in parsed_rules.groups.items():
        _, rules_set = group_key
        component_found = ""
        es: dict[MainComponents, MLVO] | None
        for component, es in entries.items():
            for entry in es.values():
                # Group declaration
                if entry.name == group.name:
                    if group.component and group.component != component:
                        raise ValueError(
                            f"Group {group.name} expected {group.component} component, but got: {component}"
                        )
                    if component_found:
                        raise ValueError(
                            f"Group {group.name} was {component_found}, but got also: {component}"
                        )
                    if group.xml:
                        raise ValueError(
                            f"Group {group.name} was in f{input_rules} is duplicated from file {group.xml}"
                        )
                    component_found = component

                # Group membership
                if entry.name in group.members:
                    entry_groups = set(entry.groups)
                    # FIXME: Check component
                    membership = GroupMember(
                        group=group.name,
                        component=entry.component,
                        name=entry.name,
                        target_rules=rules_set,
                    )
                    entry_groups.add(membership)
                    GroupMember.replace_memberships_elem(
                        entry.config_elem, entry_groups
                    )
                    group.members.remove(entry.name)

        if group.xml is None:
            if not component_found:
                pending_groups[group.name, rules_set] = group
            elif not group.component:
                group.component = RMLVO(component_found)
                group.xml = input_rules
            else:
                group.xml = input_rules
            if not group.component:
                continue
        if not group.members:
            continue

        if group.members:
            pending_groups[group.name, rules_set] = group

    # Aliases
    pending_aliases: ParsedAliases = {
        key: list(xs) for key, xs in parsed_rules.aliases.items()
    }

    for key in tuple(pending_aliases):
        layout, variant = key
        aliases = pending_aliases[key]
        component = RMLVO.variant if variant else RMLVO.layout
        if es := entries.get(component):
            for entry in es.values():
                if component is RMLVO.layout and entry.name != layout:
                    continue
                elif component is RMLVO.variant and (
                    entry.parent_component is not RMLVO.layout
                    or entry.parent_component_value != layout
                    or entry.name != variant
                ):
                    continue
                entry_aliases = set(entry.aliases)
                entry_aliases.update(aliases)
                Alias.replace_elem(entry.config_elem, entry_aliases)
                del pending_aliases[key]
                break
            else:
                # Not found: try layout default section
                if (
                    component is RMLVO.variant
                    and (es := entries.get(RMLVO.layout))
                    and (entry := es.get(MainComponents(RMLVO.layout, layout)))
                ):
                    # Check if this is the default section
                    ref = FileRef.resolve_file(
                        xkb_root,
                        section=Section.symbols,
                        filename=layout,
                        section_name=variant,
                    )
                    if ref is not None and ref.default:
                        entry_aliases = set(entry.aliases)
                        entry_aliases.update(
                            dataclasses.replace(a, target_variant=variant)
                            for a in aliases
                        )
                        Alias.replace_elem(
                            entry.config_elem, entry_aliases, target_variant=True
                        )
                        del pending_aliases[key]

    # Rules

    pending_rules: ParsedRules = {}

    for main_components, new_rules in parsed_rules.rules.items():
        if not new_rules:
            continue
        if (es := entries.get(main_components.main)) is not None and (
            (entry := es.get(main_components)) is not None
        ):
            old_rules: dict[tuple[RMLVO, ...], set[Rule]] = defaultdict(set)
            for rule in entry.rules:
                # Inferred priority
                if rule.mlvo.priority == entry.priority:
                    mlvo = dataclasses.replace(rule.mlvo, priority=Priority.normal)
                    rule = dataclasses.replace(rule, mlvo=mlvo)
                old_rules[tuple(rule.mlvo.components)].add(rule)

            # Add old rules and check generic duplicates
            for mlvo_fields__, g_old in old_rules.items():
                if mlvo_fields__ not in new_rules:
                    new_rules[mlvo_fields__] = set()
                g = new_rules[mlvo_fields__]
                # Remove duplicated rules
                if not no_skip:
                    for r in g_old:
                        if r.rules_set:
                            r2 = dataclasses.replace(r, rules_set="")
                            g.discard(r2)
                            r2 = dataclasses.replace(r, rules_set="", category="")
                            g.discard(r2)
                        r2 = dataclasses.replace(r, category="")
                        g.discard(r2)
                        mlvo = dataclasses.replace(r.mlvo, priority=Priority.normal)
                        r2 = dataclasses.replace(r, mlvo=mlvo)
                        g.discard(r2)
                        if (
                            r.mlvo.layout_range is LayoutRange.Any
                            or r.mlvo.layout_range is LayoutRange.First
                        ) and r":%i" in r.section_value:
                            mlvo = dataclasses.replace(
                                r.mlvo, layout_range=LayoutRange.First
                            )
                            r2 = dataclasses.replace(
                                r,
                                mlvo=mlvo,
                                section_value=r.section_value.replace(r":%i", ""),
                                category="",
                            )
                            mlvo = dataclasses.replace(
                                r.mlvo,
                                layout_range=LayoutRange.Later,
                            )
                            r3 = dataclasses.replace(r, mlvo=mlvo, category="")
                            if (
                                r.mlvo.layout_range is LayoutRange.Any
                                and r2 in g
                                and r3 in g
                            ):
                                g.remove(r2)
                                g.remove(r3)
                            elif r.mlvo.layout_range is LayoutRange.First and r2 in g:
                                g.remove(r2)
                # Add old rules
                g.update(g_old)

            # Remove duplicated rules for: options
            if not no_skip and main_components.main is RMLVO.option:
                # Check for automatic option rules
                for g in new_rules.values():
                    for section in Section:
                        if ":" not in main_components.main_value:
                            continue
                        parts = main_components.main_value.split(":")
                        r2 = Rule(
                            mlvo=MLVO_Matcher(option=main_components.main_value),
                            section=section,
                            section_value=f"+{parts[0]}({parts[1]})",
                        )
                        g.discard(r2)
                        r2 = dataclasses.replace(r2, section_value="+AUTO")
                        g.discard(r2)
                        try:
                            r2 = r2.resolve_auto_value(xkb_root, main_components.main)
                        except ValueError:
                            pass
                        else:
                            g.discard(r2)
            # Remove duplicated rules for: layouts and variants
            elif not no_skip and (
                main_components.main is RMLVO.layout
                or main_components.main is RMLVO.variant
            ):
                # Check for compatibility rules that are expressed by <alias> tags
                for g in new_rules.values():
                    for r in tuple(g):
                        if (
                            r.section is Section.symbols
                            and r.mlvo.model == "*"
                            and r.mlvo.layout
                            and not r.mlvo.option
                            and r.mlvo.layout_range is LayoutRange.First
                            and r.section_value.startswith("pc+")
                        ):
                            r2 = dataclasses.replace(
                                r,
                                mlvo=dataclasses.replace(
                                    r.mlvo,
                                    layout_range=LayoutRange.Later,
                                ),
                                section_value=r.section_value[2:] + r":%i",
                            )
                            if r2 in g:
                                # Compatibility
                                g.remove(r)
                                g.remove(r2)

            # Replace rules in XML
            Rule.replace_elem(
                entry.config_elem,
                itertools.chain.from_iterable(new_rules.values()),
                *entry.main_components,
            )
        elif not no_skip and (
            main_components.main is RMLVO.layout
            or main_components.main is RMLVO.variant
        ):
            # Check for compatibility rules that are expressed by <alias> tags
            layouts = entries.get(RMLVO.layout) or {}
            variants = entries.get(RMLVO.variant) or {}
            for g in new_rules.values():
                for r in tuple(g):
                    if (
                        r.section is Section.symbols
                        and r.mlvo.model == "*"
                        and r.mlvo.layout
                        and not r.mlvo.option
                        and r.mlvo.layout_range is LayoutRange.First
                        and r.section_value.startswith("pc+")
                    ):
                        r2 = dataclasses.replace(
                            r,
                            mlvo=dataclasses.replace(
                                r.mlvo,
                                layout_range=LayoutRange.Later,
                            ),
                            section_value=r.section_value[2:] + r":%i",
                        )
                        if r2 not in g:
                            continue
                        directives = tuple(r2.section_value_directives)
                        if len(directives) != 1:
                            continue
                        # Looks like compatibility rules.
                        # Check if we find corresponding aliases entries.
                        directive = directives[0]
                        if (
                            ref := FileRef.resolve_file(
                                xkb_root,
                                Section.symbols,
                                directive.filename,
                                directive.section,
                            )
                        ) is None:
                            continue
                        if directive.section:
                            entry = variants.get(
                                MainComponents(
                                    RMLVO.variant,
                                    directive.section,
                                    RMLVO.layout,
                                    directive.filename,
                                )
                            )
                            if entry is None and ref.default:
                                entry = layouts.get(
                                    MainComponents(RMLVO.layout, ref.filename)
                                )
                        else:
                            entry = layouts.get(
                                MainComponents(RMLVO.layout, ref.filename)
                            )
                        if entry is None:
                            continue
                        for alias in entry.aliases:
                            if alias.mlvo.layout == r.mlvo.layout and (
                                alias.mlvo.variant == r.mlvo.variant
                                or (not alias.mlvo.variant and ref.default)
                            ):
                                g.remove(r)
                                g.remove(r2)
                                break
            new_rules = {x: rs for x, rs in new_rules.items() if rs}
            if new_rules:
                pending_rules[main_components] = new_rules
        else:
            pending_rules[main_components] = new_rules

    with output_rules.open("wb") as fp:
        # NOTE: xml_declaration=True output wrong quotes
        fp.write(b"""<?xml version="1.0" encoding="utf-8"?>\n""")
        fp.write(ET.tostring(tree, pretty_print=True, encoding="UTF-8"))

    return ParsedRulesResult(pending_groups, pending_aliases, pending_rules)


def main(
    xkb_root: Path,
    rules_files: list[Path],
    registry_inputs: list[Path],
    registry_outputs: list[Path],
    compat: bool,
    no_skip: bool,
):
    legacy_rules = parse_legacy_rules(xkb_root, compat, rules_files)

    input: Path
    output: Path
    for input, output in zip(registry_inputs, registry_outputs):
        legacy_rules = update_registry(xkb_root, legacy_rules, input, output, no_skip)

    for group_key, group in legacy_rules.groups.items():
        _, rules_set = group_key
        if group.xml is None:
            print(
                f"[ERROR] Cannot add group “{group.name}”: component {group.component} not found ({rules_set=})",
                file=sys.stderr,
            )
        if group.members:
            print(
                f"[ERROR] Cannot add group “{group.name}” members (component: {group.component}, {rules_set=}):",
                file=sys.stderr,
            )
            for m in group.members:
                print("[ERROR] -", m)

    for (layout, variant), aliases in legacy_rules.aliases.items():
        print(
            f"[ERROR] Cannot add aliases: component not found: {layout=} {variant=}",
            file=sys.stderr,
        )
        for alias in aliases:
            print(f"[ERROR] - {alias}", file=sys.stderr)

    for main_components, rules in legacy_rules.rules.items():
        print(
            "[ERROR] Cannot add rules: main component not found: ",
            main_components,
            file=sys.stderr,
        )
        for rule in itertools.chain.from_iterable(rules.values()):
            print(f"[ERROR] - {rule}", file=sys.stderr)

from collections import defaultdict
from pathlib import Path
import sys
from typing import TYPE_CHECKING

from rules.directive import MergeMode

if TYPE_CHECKING:
    from typing import Self
else:
    Self = "Self"

from rules import (
    Comment,
    Group,
    Include,
    Reorder,
    Rule,
    RulesSetKey,
    RulesFile,
    RulesSet,
)


def main(
    rules_set: str,
    rules_files: list[Path],
    reorder: Reorder,
    only_rules_headers: bool,
    debug: bool,
):
    rules_sets: dict[RulesSetKey, list[Rule]] = defaultdict(list)
    groups: dict[str, Group] = {}
    header = Comment()
    for path in rules_files:
        if "-base." in path.stem or path.stem.endswith(".base"):
            if rules_set != "base":
                continue
        elif "-evdev." in path.stem or path.stem.endswith(".evdev"):
            if rules_set != "evdev":
                continue
        with path.open("rt", encoding="utf-8") as fd:
            for e in RulesFile.parse(fd):
                if isinstance(e, RulesSet):
                    for rule in e.rules:
                        has_merge_mode = bool(rule.section_value) and (
                            rule.section_value.startswith(MergeMode.Override)
                            or rule.section_value.startswith(MergeMode.Augment)
                        )
                        rules_sets[
                            RulesSetKey(
                                rule.section,
                                has_merge_mode,
                                rule.mlvo.mlvo_set,
                            )
                        ].append(rule)
                        # Check for groups
                        for c, v in rule.mlvo:
                            if not Group.is_group_name(v):
                                continue
                            if (group2 := groups.get(v)) is None:
                                group = Group(name=v, component=c, members=set())
                                groups[group.name] = group
                            elif group2.component is None:
                                group2.component = c
                            elif group2.component != c:
                                raise ValueError(
                                    f"Conflict for group component: {group2}, got: {c}"
                                )
                elif isinstance(e, Group):
                    group = e
                    if group2 := groups.get(group.name):
                        if group2.members:
                            raise ValueError(f"Duplicated group: {group2} {group}")
                            # FIXME
                            # print(
                            #     f"[WARNING] Duplicated group: {group2} {group}",
                            #     file=sys.stderr,
                            # )
                        else:
                            group.component = group2.component
                            groups[group.name] = group
                    else:
                        groups[group.name] = group
                elif isinstance(e, Include):
                    raise ValueError(f"Include not supported: {e}")
                elif isinstance(e, Comment):
                    if not rules_sets and not groups:
                        header += e

    if only_rules_headers:
        header = Comment()
        groups = {}
        for rs in rules_sets.values():
            rs.clear()

    rules_file = RulesFile(header=header, groups=groups, rules=rules_sets)
    rules_file.serialize(out=sys.stdout, reorder=reorder, debug=debug)

#!/usr/bin/env python3

from __future__ import annotations

import argparse
from dataclasses import dataclass
import functools
import itertools
import math
import multiprocessing
from pathlib import Path
import pickle
import subprocess
import sys
from typing import Generator, Iterable
import yaml


@dataclass
class Rule:
    mlvo: list[str]
    section: str


@dataclass
class RulesSet:
    mlvo: list[str]
    layout_index: str
    section: str
    rules: list[Rule]


def parse_rules_group_definition(lines: list[str]) -> tuple[str, set[str]]:
    name = ""
    items: set[str] = set()
    for line in lines:
        end = False
        for word in line.split():
            if end:
                raise ValueError()
            elif word == "!":
                if name or items:
                    raise ValueError()
                continue
            elif word == "=":
                if not name or items:
                    raise ValueError()
                continue
            elif word == "\\":
                end = True
                continue
            elif word.startswith("$"):
                if name or items:
                    raise ValueError()
                name = word
            else:
                items.add(word)
    return name, items


def parse_rules_header(line: str) -> RulesSet:
    words = line.split()[1:]
    eq_index = words.index("=")
    mlvo = words[:eq_index]
    layout_index = ""
    for k, c in enumerate(mlvo):
        if "[" in c:
            layout_index_new = c[c.index("[") + 1 : c.index("]")]
            if layout_index and layout_index != layout_index_new:
                raise ValueError()
            mlvo[k] = c[: c.index("[")]
    return RulesSet(mlvo, layout_index, words[eq_index + 1], [])


def parse_rule(line: str) -> Rule:
    words = line.split()
    eq_index = words.index("=")
    return Rule(words[:eq_index], words[eq_index + 1])


def parse_rules_file(path: Path) -> tuple[list[RulesSet], dict[str, set[str]]]:
    groups: dict[str, set[str]] = {}
    current_group: list[str] = []
    rules_sets: list[RulesSet] = []
    rules_set: RulesSet | None = None
    with path.open("rt", encoding="UTF-8") as fd:
        for line in fd:
            line = line.strip()
            if not line:
                continue
            elif line.startswith("//"):
                continue
            elif current_group:
                current_group.append(line)
                if line.endswith("\\"):
                    continue
                name, items = parse_rules_group_definition(current_group)
                groups[name] = items
                current_group = []
            elif line.startswith("!"):
                rules_set = None
                if line[2:].startswith("include"):
                    raise NotImplementedError("! include")
                elif line[2] == "$":
                    current_group = [line]
                    if line.endswith("\\"):
                        continue
                    name, items = parse_rules_group_definition(current_group)
                    groups[name] = items
                    current_group = []
                else:
                    rules_set = parse_rules_header(line)
                    rules_sets.append(rules_set)
            elif rules_set:
                rule = parse_rule(line)
                rules_set.rules.append(rule)
            else:
                raise ValueError(f"Invalid line: {line}")

    return rules_sets, groups


@dataclass
class MLVO_Items:
    models: set[str]
    models_used_in_groups: set[str]
    layouts: set[Layout]
    layouts_used_in_groups: set[str]
    variants_used_in_groups: set[str]
    options: set[str]
    options_used_in_groups: set[str]


def get_rules_mlvo_items(
    rules_sets: list[RulesSet], groups: dict[str, set[str]]
) -> MLVO_Items:
    models: set[str] = set()
    models_used_in_groups: set[str] = set()
    layouts: set[Layout] = set()
    layouts_used_in_groups: set[str] = set()
    variants_used_in_groups: set[str] = set()
    options: set[str] = set()
    options_used_in_groups: set[str] = set()
    for rules_set in rules_sets:
        for rule in rules_set.rules:
            layout: Layout | None = None
            assert len(rules_set.mlvo) == len(rule.mlvo)
            for c, v in zip(rules_set.mlvo, rule.mlvo):
                if v == "*":
                    continue
                # elif v.startswith("$"):
                #     vs = groups.get(v)
                #     if vs is None:
                #         print(f"[ERROR] Cannot resolve group: {v}", file=sys.stderr)
                #         continue
                #         # raise ValueError(f"Cannot resolve group: {v}")
                # else:
                #     vs = {v}
                if c == "model":
                    models.add(v)
                elif c == "option":
                    options.add(v)
                elif c == "layout":
                    assert not layout
                    layout = Layout(v, "", "")
                elif c == "variant":
                    assert layout
                    layout = Layout(layout.name, v, "")
            if layout:
                # was = len(layouts)
                layouts.add(layout)
                # mlvo = ", ".join(f"{c}: {v}" for c, v in zip(rules_set.mlvo, rule.mlvo))
                # print(f"+++ {mlvo}. Adding {len(rule_layouts)} layouts. Was: {was}, currently: {len(layouts)}")
                # print(rule_layouts)
                # print()

    # Resolve groups
    for c, xs in (("models", models), ("options", options)):
        to_add: set[str] = set()
        to_remove: set[str] = set()
        for x in xs:
            if x.startswith("$"):
                vs = groups.get(x)
                to_remove.add(x)
                if vs is None:
                    print(f"[ERROR] Cannot resolve group: {x}", file=sys.stderr)
                    continue
                if c == "models":
                    models_used_in_groups.update(vs)
                else:
                    options_used_in_groups.update(vs)
                # Add only 1 value that is *not* already in the set
                for v in vs:
                    if v not in xs:
                        to_add.add(v)
                        break
        xs.difference_update(to_remove)
        xs.update(to_add)
    layouts_to_add: set[Layout] = set()
    layouts_to_remove: set[Layout] = set()
    for layout in layouts:
        has_group = False
        if layout.name.startswith("$"):
            has_group = True
            ls = groups.get(layout.name)
            if ls is None:
                print(f"[ERROR] Cannot resolve group: {layout.name}", file=sys.stderr)
                ls = set()
            else:
                layouts_used_in_groups.update(ls)
        else:
            ls = {layout.name}
        if layout.variant.startswith("$"):
            has_group = True
            vs = groups.get(layout.variant)
            if vs is None:
                print(
                    f"[ERROR] Cannot resolve group: {layout.variant}", file=sys.stderr
                )
                vs = set()
            else:
                variants_used_in_groups.update(vs)
        else:
            vs = {layout.variant}
        if not has_group:
            continue
        layouts_to_remove.add(layout)
        # Add only 1 value that is *not* already in the set
        for l, v in itertools.product(ls, vs):
            layout2 = Layout(l, v, "")
            if layout2 not in layouts:
                layouts_to_add.add(layout2)
                break
    layouts.difference_update(layouts_to_remove)
    layouts.update(layouts_to_add)

    return MLVO_Items(
        models=models,
        models_used_in_groups=models_used_in_groups,
        layouts=layouts,
        layouts_used_in_groups=layouts_used_in_groups,
        variants_used_in_groups=variants_used_in_groups,
        options=options,
        options_used_in_groups=options_used_in_groups,
    )


@dataclass
class Model:
    name: str
    vendor: str
    description: str

    @classmethod
    def parse(cls, raw: dict[str, str]) -> Model:
        return cls(
            name=raw.get("name", ""),
            vendor=raw.get("vendor", ""),
            description=raw.get("description", ""),
        )


@dataclass(frozen=True, order=True)
class Layout:
    name: str
    variant: str
    description: str

    @classmethod
    def parse(cls, raw: dict[str, str]) -> Layout:
        return cls(
            name=raw.get("layout", ""),
            variant=raw.get("variant", ""),
            description=raw.get("description", ""),
        )


@dataclass
class Option:
    name: str
    description: str

    @classmethod
    def parse(cls, raw: dict[str, str]) -> Option:
        return cls(name=raw.get("name", ""), description=raw.get("description", ""))


@dataclass
class OptionsGroup:
    name: str
    description: str
    entries: tuple[Option, ...]

    @classmethod
    def parse(cls, raw: dict) -> OptionsGroup:
        entries = tuple(map(Option.parse, raw.get("options", ())))
        return OptionsGroup(
            name=raw.get("name", ""),
            description=raw.get("description", ""),
            entries=entries,
        )


@dataclass
class Registry:
    models: tuple[Model, ...]
    layouts: tuple[Layout, ...]
    options: tuple[OptionsGroup, ...]

    @classmethod
    def parse(cls, raw: dict) -> Registry:
        return Registry(
            models=tuple(map(Model.parse, raw.get("models", ()))),
            layouts=tuple(map(Layout.parse, raw.get("layouts", ()))),
            options=tuple(map(OptionsGroup.parse, raw.get("option_groups", ()))),
        )


def xkbcli_list(
    xkbcommon_build_dir: Path, xkb_dirs: list[Path], rules: str
) -> Registry:
    exe = xkbcommon_build_dir / "xkbcli-list"
    args = [str(exe), "--load-exotic", "--ruleset", rules]
    if xkb_dirs:
        args += ["--skip-default-paths"]
        args += list(map(str, xkb_dirs))
    result = subprocess.run(args, capture_output=True, check=True, encoding="UTF-8")
    raw_registry = yaml.safe_load(result.stdout)
    return Registry.parse(raw_registry)


@dataclass(frozen=True)
class RMLVO:
    rules: str
    model: str
    layout: str
    variant: str
    option: str


def compile_kccgst(
    xkbcommon_build_dir: Path, xkb_dirs: list[Path], rmlvo: RMLVO
) -> str:
    exe = xkbcommon_build_dir / "compile-keymap"
    args: tuple[str, ...] = (
        str(exe),
        "--kccgst",
        "--rules",
        rmlvo.rules,
        "--model",
        rmlvo.model,
        "--layout",
        rmlvo.layout,
        "--variant",
        rmlvo.variant,
        "--option",
        rmlvo.option,
    )
    if xkb_dirs:
        args += tuple(
            itertools.chain.from_iterable(("--include", str(p)) for p in xkb_dirs)
        )
    else:
        args += ("--include-defaults",)

    result = subprocess.run(args, capture_output=True, check=True, encoding="utf-8")

    return result.stdout


def compile_kccgst_factory(
    xkbcommon_build_dir: Path,
    xkb_dirs: list[Path],
):
    exe = xkbcommon_build_dir / "compile-keymap"
    args: tuple[str, ...] = (
        str(exe),
        "--kccgst",
    ) + tuple(itertools.chain.from_iterable(("--include", str(p)) for p in xkb_dirs))

    return functools.partial(compile_kccgst_, args)


def compile_kccgst_(args: tuple[str, ...], rmlvo: RMLVO) -> tuple[RMLVO, str]:
    result = subprocess.run(
        args
        + (
            "--rules",
            rmlvo.rules,
            "--model",
            rmlvo.model,
            "--layout",
            rmlvo.layout,
            "--variant",
            rmlvo.variant,
            "--option",
            rmlvo.option,
        ),
        capture_output=True,
        check=True,
        encoding="utf-8",
    )
    return rmlvo, result.stdout


MAX_MODEL = 100000000000000
MAX_LAYOUT = 1000000000000000


def get_rmvlo_from_registry(
    rules: str, registry: Registry
) -> Generator[RMLVO, None, None]:
    for model in registry.models[:MAX_MODEL]:
        for layout in registry.layouts[:MAX_LAYOUT]:
            for options_group in registry.options:
                for option in options_group.entries:
                    yield RMLVO(
                        rules, model.name, layout.name, layout.variant, option.name
                    )


def get_rmvlo(rules: str, items: MLVO_Items) -> Generator[RMLVO, None, None]:
    for model in items.models:
        for layout in items.layouts:
            for option in items.options:
                yield RMLVO(rules, model, layout.name, layout.variant, option)


def main():
    # CLI parser
    parser = argparse.ArgumentParser(description="Export RMLVO resolutions.")
    parser.add_argument(
        "-r",
        "--rules",
        help="rules set (default: %(default)s)",
        type=str,
        default="evdev",
    )
    parser.add_argument("-i", "--input", type=Path)
    parser.add_argument("-o", "--output", type=Path)
    parser.add_argument("-x", "--xkbcommon-build-dir", type=Path, required=True)
    parser.add_argument("files", nargs="+", help="XKB directories", type=Path)
    args = parser.parse_args()

    # Open previous run
    kccgst_registry_old: dict[RMLVO, str] = {}
    if args.input:
        with args.input.open("rb") as fd:
            kccgst_registry_old = pickle.load(fd)

    # Get registry
    xkbcommon_build_dir = args.xkbcommon_build_dir
    xkb_dirs: list[Path] = args.files
    rules = args.rules
    registry = xkbcli_list(xkbcommon_build_dir, xkb_dirs, rules)

    # Parse rules
    rules_file: Path
    for d in xkb_dirs:
        path: Path = d / "rules" / rules
        if path.exists():
            rules_file = path
            break
    else:
        raise ValueError(f"Cannot find rules file {rules}")

    # Get the MLVO values that appear in the rules
    rules_sets, groups = parse_rules_file(rules_file)
    rules_mlvo_items = get_rules_mlvo_items(rules_sets, groups)

    # Add MLVO values from the registry that are *not* in the rules file
    mlvo_items = MLVO_Items(
        models=set(rules_mlvo_items.models),
        models_used_in_groups=rules_mlvo_items.models_used_in_groups,
        layouts=set(rules_mlvo_items.layouts),
        layouts_used_in_groups=rules_mlvo_items.layouts_used_in_groups,
        variants_used_in_groups=rules_mlvo_items.variants_used_in_groups,
        options=set(rules_mlvo_items.options),
        options_used_in_groups=rules_mlvo_items.options_used_in_groups,
    )

    max_count = 1
    count = 0
    for model in registry.models:
        if (
            model.name not in rules_mlvo_items.models
            and model.name not in rules_mlvo_items.models_used_in_groups
        ):
            mlvo_items.models.add(model.name)
            print(f"*** Add extra model: {model.name}")
            count += 1
            if count >= max_count:
                break
    count = 0
    for layout in registry.layouts:
        layout_ = Layout(layout.name, layout.variant, "")
        if (
            layout_ not in rules_mlvo_items.layouts
            and layout_.name not in rules_mlvo_items.layouts_used_in_groups
            and layout.variant not in rules_mlvo_items.variants_used_in_groups
        ):
            mlvo_items.layouts.add(layout_)
            print(f"*** Add extra layout: {layout}")
            count += 1
            if count >= max_count:
                break
    count = 0
    for option in itertools.chain.from_iterable(g.entries for g in registry.options):
        if (
            option.name not in rules_mlvo_items.options
            and option.name not in rules_mlvo_items.options_used_in_groups
        ):
            mlvo_items.options.add(option.name)
            print(f"*** Add extra option: {option.name}")
            count += 1
            if count >= max_count:
                break

    # print(mlvo_items)

    kccgst_registry: dict[RMLVO, str] = {}

    # options_count = sum(len(g.entries) for g in registry.options)
    # total = (
    #     len(registry.models[:MAX_MODEL])
    #     * len(registry.layouts[:MAX_LAYOUT])
    #     * options_count
    # )
    total = len(mlvo_items.models) * len(mlvo_items.layouts) * len(mlvo_items.options)

    print("Models:", len(mlvo_items.models))
    print()
    print("Layouts:", len(mlvo_items.layouts))
    for l in sorted(mlvo_items.layouts):
        print(l)
    print()
    print("Options:", len(mlvo_items.options))
    for o in sorted(mlvo_items.options):
        print(o)
    print()

    for l in mlvo_items.layouts:
        # print(l)
        for l2 in mlvo_items.layouts:
            if l2 is l:
                continue
            elif l2.name == l.name and l2.variant == l.variant:
                print("#####", l, l2)

    STEP = 10 ** (math.ceil(math.log10(total / 1000)))
    count = 0
    cpu_count = multiprocessing.cpu_count()
    chunksize = math.ceil(STEP / cpu_count)
    print(f"{total=} {STEP=} {chunksize=}")

    # exit(0)

    print(f"Pool workers: {cpu_count}")
    with multiprocessing.Pool(processes=cpu_count) as pool:
        _compile_kccgst = compile_kccgst_factory(xkbcommon_build_dir, xkb_dirs)
        # for rmlvo, kccgst in pool.imap_unordered(
        #     _compile_kccgst, get_rmvlo_from_registry(rules, registry), chunksize=chunksize
        # ):
        for rmlvo, kccgst in pool.imap_unordered(
            _compile_kccgst, get_rmvlo(rules, mlvo_items), chunksize=chunksize
        ):
            # print(kccgst)
            count += 1
            step = count / total
            if count % STEP == 0:
                print(f"{count} / {total} ({step:.2%})", file=sys.stderr, flush=True)
            kccgst_registry[rmlvo] = kccgst

    if args.output:
        with args.output.open("wb") as fd:
            pickle.dump(kccgst_registry, fd)

    if not kccgst_registry_old:
        exit(0)

    for rmlvo, kccgst_old in kccgst_registry_old.items():
        if kccgst_new := kccgst_registry.get(rmlvo):
            if kccgst_new != kccgst_old:
                print(f"[ERROR] KcCGST mismatch: {rmlvo=}", file=sys.stderr)
                print(f"[ERROR] {kccgst_old=}", file=sys.stderr)
                print(f"[ERROR] {kccgst_new=}", file=sys.stderr)
        else:
            print(f"[ERROR] RMLVO not found: {rmlvo}", file=sys.stderr)


if __name__ == "__main__":
    main()

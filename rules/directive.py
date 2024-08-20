#!/usr/bin/env python3
#
# This file is formatted with python ruff
#
# This file parses the base.xml and base.extras.xml file and prints out the rules.
# See the meson.build file for how this is used.

from __future__ import annotations

from enum import unique
import re
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, Generator, Iterable

if TYPE_CHECKING:
    from typing import Self
else:
    Self = "Self"


# Local import
from rules import (
    MLVO_Matcher,
    Section,
)

try:
    # Available from Python 3.11
    from enum import StrEnum
except ImportError:
    # Fallback to external package
    from strenum import StrEnum


@dataclass
class FileRef:
    """
    An XKB section file reference
    """

    filename: str
    section: str
    default: bool
    "Default section of the file"

    def __str__(self) -> str:
        if self.section:
            return f"{self.filename}({self.section})"
        else:
            return self.filename

    @property
    def string(self) -> str:
        if self.section and not self.default:
            return f"{self.filename}({self.section})"
        else:
            return self.filename

    @classmethod
    def resolve_file(
        cls, xkb_root: Path, section: Section, filename: str, section_name: str
    ) -> Self | None:
        """
        Resolve a section reference to its canonical file resolving symlink and
        vendor sub-directories. Then check if the section exists in the file.
        """
        subdir = xkb_root / section
        if not (subdir / filename).exists():
            # Some of our foo:bar entries map to a baz_vndr/foo file
            for vndr in subdir.glob("*_vndr"):
                vndr_path = vndr / filename
                if vndr_path.exists():
                    filename = vndr_path.relative_to(subdir).as_posix()
                    break
            else:
                return None

        if (subdir / filename).is_symlink():
            resolved_filename = (subdir / filename).resolve().name
            assert (subdir / filename).exists()
        else:
            resolved_filename = filename

        # Now check if the target file actually has that section
        f = subdir / resolved_filename
        section_kw = f"xkb_{section.name}"
        with f.open("rt", encoding="utf-8") as fd:
            default = False
            pattern = re.compile(section_kw + r'\s+"(?P<section>[^"]+)"')
            first_section = ""
            for line in fd:
                line = line.split("//")[0]
                if line.startswith("default"):
                    default = True
                if m := pattern.match(line):
                    current_section = m.group("section")
                    if section_name:
                        if section_name == current_section:
                            return cls(
                                filename=resolved_filename,
                                section=section_name,
                                default=default,
                            )
                    elif default:
                        return cls(
                            filename=resolved_filename,
                            section=current_section,
                            default=default,
                        )
                    elif not first_section:
                        first_section = current_section
                    default = False
            if not section_name and first_section:
                return cls(
                    filename=resolved_filename, section=first_section, default=False
                )

        # FIXME: move to other place?
        # print(
        #     f"[ERROR] {section.name.title()} section “{section_name}” not found in: {f.absolute()}",
        #     file=sys.stderr,
        # )

        return None


@unique
class MergeMode(StrEnum):
    """
    A merge mode prefix.
    """

    NoMode = ""
    Override = "+"
    Augment = "|"


@dataclass
class Directive:
    """
    An atomic section value.
    """

    DIRECTIVE_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"^(?P<merge>\+|\|)?(?P<file>[^\:]+)(?:\:(?P<index>.+))?$"
    )
    FILE_SECTION_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"^(?P<file>(?:\w|-)+)(?:\((?P<section>(?:\w|-)+)\))?$"
    )
    INDEX_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"\%(?P<parenthesis>\()?(?P<component>[lv])(?P<index>\[\%i\])(?(parenthesis)\))"
    )

    merge: MergeMode
    filename: str
    section: str = ""
    index: str = ""

    def __str__(self) -> str:
        index = f":{self.index}" if self.index and self.index != "1" else ""
        section = f"({self.section})" if self.section else ""
        return f"{self.merge}{self.filename}{section}{index}"

    @classmethod
    def parse(cls, raw: str) -> Directive:
        if m := cls.DIRECTIVE_PATTERN.match(raw):
            raw_merge = m.group("merge")
            if raw_merge == MergeMode.Override:
                merge = MergeMode.Override
            elif raw_merge == MergeMode.Augment:
                merge = MergeMode.Augment
            else:
                merge = MergeMode.NoMode
            file = m.group("file")
            if m2 := cls.FILE_SECTION_PATTERN.match(file):
                file = m2.group("file")
                section = m2.group("section") or ""
            else:
                section = ""
            index = m.group("index")
            return cls(merge=merge, filename=file, section=section, index=index)
        else:
            raise ValueError(raw)

    @classmethod
    def parse_multiple(cls, raw: str) -> Generator[Directive, None, None]:
        start = 0
        for k, c in enumerate(raw):
            if (c == "+" or c == "|") and k > 0:
                yield cls.parse(raw[start:k])
                start = k
        yield cls.parse(raw[start : k + 1])

    def replace_index(self, index: str, mlvo: MLVO_Matcher) -> Directive:
        def replace(m: re.Match[str]):
            component = m.group("component")
            if (
                component == "l"
                and mlvo.layout
                and not MLVO_Matcher.is_wildcard_or_group(mlvo.layout)
            ):
                return mlvo.layout
            if (
                component == "v"
                and mlvo.variant
                and not MLVO_Matcher.is_wildcard_or_group(mlvo.variant)
            ):
                return mlvo.variant
            _index = f"[{index}]" if index else ""
            if m.group("parenthesis"):
                return f"%({m.group('component')}{_index})"
            else:
                return f"%{m.group('component')}{_index}"

        return self.__class__(
            merge=self.merge,
            filename=self.INDEX_PATTERN.sub(replace, self.filename),
            section=self.INDEX_PATTERN.sub(replace, self.section),
            index=self.index.replace(r"%i", index)
            if self.index and self.index != "1"
            else self.index,
        )

    @classmethod
    def join(cls, directives: Iterable[Self]) -> str:
        return "".join(map(str, directives))


@dataclass
class DirectiveSet:
    """
    Set of directives by section.
    """

    keycodes: Directive | None
    compatibility: Directive | None
    geometry: Directive | None
    symbols: Directive | None
    types: Directive | None

    def __iter__(self) -> Generator[tuple[Section, Directive], None, None]:
        if self.keycodes:
            yield Section.keycodes, self.keycodes
        if self.compatibility:
            yield Section.compatibility, self.compatibility
        if self.geometry:
            yield Section.geometry, self.geometry
        if self.symbols:
            yield Section.symbols, self.symbols
        if self.types:
            yield Section.types, self.types

    @property
    def is_empty(self) -> bool:
        return all(
            x is None
            for x in (
                self.keycodes,
                self.compatibility,
                self.geometry,
                self.symbols,
                self.types,
            )
        )


def resolve_file(
    xkb_root: Path, section: Section, filename: str, section_name: str
) -> Directive | None:
    """
    Resolve a section reference to its canonical file resolving symlink and
    vendor sub-directories. Then check if the section exists in the file.
    """
    subdir = xkb_root / section
    if not (subdir / filename).exists():
        # Some of our foo:bar entries map to a baz_vndr/foo file
        for vndr in subdir.glob("*_vndr"):
            vndr_path = vndr / filename
            if vndr_path.exists():
                filename = vndr_path.relative_to(subdir).as_posix()
                break
        else:
            return None

    if (subdir / filename).is_symlink():
        resolved_filename = (subdir / filename).resolve().name
        # print(
        #     f"***** symlink resolved: {subdir / filename} -> {subdir / resolved_filename}",
        #     file=sys.stderr,
        # )
        assert (subdir / filename).exists()
    else:
        resolved_filename = filename

    # TODO: look for default section
    if not section_name:
        return Directive(
            merge=MergeMode.Override,
            filename=resolved_filename,
            section=section_name,
        )

    # Now check if the target file actually has that section
    f = subdir / resolved_filename
    with f.open("rt", encoding="utf-8") as fd:
        section_header = f'xkb_{section.name} "{section_name}"'
        if any(section_header in line for line in fd):
            return Directive(
                merge=MergeMode.Override,
                filename=resolved_filename,
                section=section_name,
            )

    return None


def resolve_option(xkb_root: Path, option: str) -> DirectiveSet:
    """
    Given an option, resolve its correspond files and sections.
    """
    filename, section_name = option.split(":")
    directives: dict[Section, Directive | None] = {
        s: resolve_file(xkb_root, s, filename, section_name) for s in Section
    }

    return DirectiveSet(
        keycodes=directives[Section.keycodes],
        compatibility=directives[Section.compatibility],
        geometry=directives[Section.geometry],
        symbols=directives[Section.symbols],
        types=directives[Section.types],
    )

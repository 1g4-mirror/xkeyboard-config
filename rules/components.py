from __future__ import annotations

import functools
import re
import sys
from dataclasses import dataclass
from enum import IntEnum, auto, unique
from typing import TYPE_CHECKING, Generator, Iterable

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

MAX_LAYOUT_INDEX = 4
AUTO_VALUE = "AUTO"
MLVO_WITH_LAYOUT_INDEX_PATTERN = re.compile(
    r"^(?P<component>layout|variant)\[(?P<index>\d+)\]$"
)


@unique
class RMLVO(StrEnum):
    """
    RMLVO components.
    """

    rules = "rules"
    model = "model"
    layout = "layout"
    variant = "variant"
    option = "option"

    def __lt__(self, other):
        if not isinstance(other, self.__class__):
            return super().__lt__(other)
        else:
            return self._index < other._index

    def __le__(self, other):
        if not isinstance(other, self.__class__):
            return super().__le__(other)
        else:
            return self._index <= other._index

    def __gt__(self, other):
        if not isinstance(other, self.__class__):
            return super().__gt__(other)
        else:
            return self._index > other._index

    def __ge__(self, other):
        if not isinstance(other, self.__class__):
            return super().__ge__(other)
        else:
            return self._index >= other._index

    @property
    def _index(self):
        """
        Ensure the components respect RMLVO order
        """
        if self is self.rules:
            return 0
        elif self is self.model:
            return 1
        elif self is self.layout:
            return 2
        elif self is self.variant:
            return 3
        elif self is self.option:
            return 4
        else:
            raise ValueError()

    @classmethod
    def parse(cls, raw: str) -> Self:
        for c in cls:
            if raw == c:
                return c
        raise ValueError(raw)

    @classmethod
    def parse_mlvo(cls, raw: str) -> Self:
        if (c := cls.parse(raw)) and c is cls.rules:
            raise ValueError(raw)
        return c

    @classmethod
    def parse_mlvo_with_layout_index(cls, raw: str) -> tuple[Self, str]:
        if m := MLVO_WITH_LAYOUT_INDEX_PATTERN.match(raw):
            return (cls.parse_mlvo(m.group("component")), m.group("index") or "")
        else:
            return (cls.parse_mlvo(raw), "")

    @classmethod
    def mlvo(cls) -> Generator[RMLVO, None, None]:
        for c in cls:
            if c is not cls.rules:
                yield c


@dataclass
class TargetRules:
    rules: str = ""

    def __bool__(self) -> bool:
        return bool(self.rules)

    def matches(self, other: Self | str) -> bool:
        if self.rules and other:
            if isinstance(other, self.__class__):
                return self == other
            else:
                return self.rules == other
        else:
            return True


@unique
class Priority(IntEnum):
    """
    Priority for MLVO_Matcher
    """

    # Order is important for comparison functions
    lowest = auto()
    low = auto()
    normal = auto()
    high = auto()
    highest = auto()

    @classmethod
    def parse(cls, raw: str) -> Self:
        for p in cls:
            if p.name == raw:
                return p
        raise ValueError(raw)


@unique
class LayoutRange(StrEnum):
    """
    Layout range description. Used to simplify layout index handling.
    """

    Single = "single"
    "Match when only one layout defined"
    First = "first"
    "Match first layout in any configuration"
    One = "1"
    "Match first layout if multiple layouts defined"
    Later = "later"
    "Match all but first layout"
    Any = "any"
    "Match any layout index in any configuration"

    @property
    def int_indexes(self) -> Generator[int, None, None]:
        if self is self.Single:
            yield 0
        elif self is self.First:
            yield 0
            yield 1
        elif self is self.One:
            yield 1
        elif self is self.Later:
            yield from range(2, MAX_LAYOUT_INDEX + 1)
        elif self is self.Any:
            yield 0
            yield from range(1, MAX_LAYOUT_INDEX + 1)
        else:
            raise ValueError()

    @property
    def indexes(self) -> Generator[str, None, None]:
        for i in self.int_indexes:
            if i == 0:
                yield ""
            else:
                yield str(i)

    @classmethod
    def parse(cls, raw: str) -> Self:
        for r in cls:
            if raw == r:
                return r
        raise ValueError(f"Cannot parse layout range: {raw}")


@functools.total_ordering
@dataclass(frozen=True, order=False)
class MLVO_Set:
    """
    Set of MLVO components defined in a rules. Used for grouping rules into sets.
    """

    model: bool = False
    layout: bool = False
    layout_range: str = ""
    variant: bool = False
    option: bool = False

    def __iter__(self) -> Generator[RMLVO, None, None]:
        if self.model:
            yield RMLVO.model
        if self.layout:
            yield RMLVO.layout
        if self.variant:
            yield RMLVO.variant
        if self.option:
            yield RMLVO.option

    def __lt__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented

        # • If a component is defined in one set and not in the other,
        #   the set with the definition is lower only if no previous
        #   component is defined.
        # • If the same components are defined, then compare the layout
        #   index.

        if self.model and not other.model:
            return True
        if not self.model and other.model:
            return False

        if self.layout and not other.layout:
            return not self.model
        if not self.layout and other.layout:
            return self.model

        if self.variant and not other.variant:
            return not self.model and not self.layout
        if not self.variant and other.variant:
            return self.model or self.layout

        if self.option and not other.option:
            return not self.model and not self.layout and not self.variant
        if not self.option and other.option:
            return self.model or self.layout or self.variant

        # [WARNING] We are comparing strings
        assert len(self.layout_range) < 2
        assert len(other.layout_range) < 2
        return self.layout_range < other.layout_range

    @property
    def components(self) -> list[str]:
        """
        MLVO components for a rule set header.
        """
        components: list[str] = []
        if self.model:
            components.append(RMLVO.model)
        if self.layout:
            components.append(
                RMLVO.layout + (f"[{self.layout_range}]" if self.layout_range else "")
            )
        if self.variant:
            components.append(
                RMLVO.variant + (f"[{self.layout_range}]" if self.layout_range else "")
            )
        if self.option:
            components.append(RMLVO.option)
        return components

    @classmethod
    def parse(cls, fields: Iterable[str]) -> tuple[Self, tuple[RMLVO, ...]] | None:
        mlvo: dict[RMLVO, bool] = {}
        layout_range = ""
        for field in fields:
            try:
                c, index = RMLVO.parse_mlvo_with_layout_index(field)
                mlvo[c] = True
                if not layout_range:
                    layout_range = index
            except ValueError:
                return None
        return cls(layout_range=layout_range, **mlvo), tuple(mlvo)


@dataclass(frozen=True)
class MainComponents:
    main: RMLVO
    main_value: str
    parent: RMLVO | None = None
    parent_value: str = ""

    @property
    def string(self) -> str:
        return (
            f"{self.parent_value}({self.main_value})"
            if self.parent is not None
            else self.main_value
        )


@functools.total_ordering
@dataclass(frozen=True, order=False)
class MLVO_Matcher:
    """
    MLVO values of a rule.
    """

    model: str = ""
    layout: str = ""
    layout_range: LayoutRange | str = ""
    variant: str = ""
    option: str = ""
    priority: Priority = Priority.normal

    def __iter__(self) -> Generator[tuple[RMLVO, str], None, None]:
        if self.model:
            yield RMLVO.model, self.model
        if self.layout:
            yield RMLVO.layout, self.layout
        if self.variant:
            yield RMLVO.variant, self.variant
        if self.option:
            yield RMLVO.option, self.option

    @property
    def components(self) -> Generator[RMLVO, None, None]:
        for component, _ in self:
            yield component

    @property
    def values(self) -> Generator[str, None, None]:
        for _, value in self:
            yield value

    @property
    def mlvo_set(self) -> MLVO_Set:
        return MLVO_Set(
            model=bool(self.model),
            layout=bool(self.layout),
            layout_range=self.layout_range or "",
            variant=bool(self.variant),
            option=bool(self.option),
        )

    @property
    def main_component(self) -> tuple[RMLVO, str]:
        first: RMLVO | None = None
        first_value: str = ""
        for elem, v in self:
            assert elem
            assert v
            if not self.is_wildcard_or_group(v):
                if (
                    elem is RMLVO.layout
                    and self.variant
                    and not self.is_wildcard_or_group(self.variant)
                ):
                    return RMLVO.variant, self.variant
                return elem, v
            elif not first or (self.is_wildcard(first) and not self.is_wildcard(v)):
                first = elem
                first_value = v
        assert first is not None
        assert first_value
        return first, first_value

    @property
    def main_components(self) -> MainComponents:
        main_component, main_component_value = self.main_component
        if main_component is RMLVO.variant and self.layout:
            return MainComponents(
                main_component, main_component_value, RMLVO.layout, self.layout
            )
        else:
            return MainComponents(main_component, main_component_value)

    @classmethod
    def _compare_component(cls, c1, c2) -> bool | None:
        # Cannot deduce < or > if identical
        if c1 == c2:
            return None
        # Wildcard comes last
        elif cls.is_wildcard(c1):
            return False
        elif cls.is_wildcard(c2):
            return True
        else:
            # Check for groups
            dollar1 = is_group_name(c1)
            dollar2 = is_group_name(c2)
            if dollar1 == dollar2:
                # None is group or both are groups: compare strings
                return c1 < c2
            else:
                # Only one is a group: groups have lower precedence (less specific)
                return dollar2
                # NOTE: previous implementation that set same level of precedence
                #       for group and non-groups.
                # return (c1[1:] if dollar1 else c1) < (c2[1:] if dollar2 else c2)

    @staticmethod
    def is_wildcard(s: str) -> bool:
        return s == "*"

    @classmethod
    def is_wildcard_or_group(cls, s: str) -> bool:
        return cls.is_wildcard(s) or is_group_name(s)

    def __lt__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented

        # Short-circuit with priority
        if self.priority > other.priority:
            return True
        elif self.priority < other.priority:
            return False

        # Compare component by component, in MLVO order

        if (self.model or other.model) and (
            lt := self._compare_component(self.model, other.model)
        ) is not None:
            return lt

        if (self.layout or other.layout) and (
            lt := self._compare_component(self.layout, other.layout)
        ) is not None:
            return lt

        if (self.variant or other.variant) and (
            lt := self._compare_component(self.variant, other.variant)
        ) is not None:
            return lt

        if (self.option or other.option) and (
            lt := self._compare_component(self.option, other.option)
        ) is not None:
            return lt

        if self.layout_range == other.layout_range:
            return False
        elif isinstance(self.layout_range, LayoutRange) and isinstance(
            other.layout_range, LayoutRange
        ):
            return tuple(self.layout_range.int_indexes) < tuple(
                other.layout_range.int_indexes
            )
        elif not isinstance(self.layout_range, LayoutRange) and not isinstance(
            other.layout_range, LayoutRange
        ):
            return int(self.layout_range or 0) < int(other.layout_range or 0)
        else:
            raise ValueError(self.layout_range, other.layout_range)

    def conflicts(self, other: MLVO_Matcher) -> bool | None:
        if self == other:
            return True
        elif self.layout_range != other.layout_range:
            return False
        for c in MLVO_Matcher.__dataclass_fields__:
            v1: str
            v2: str
            if bool(v1 := getattr(self, c)) ^ bool(v2 := getattr(other, c)):
                return False
            if v1 and (
                (isinstance(v1, str) and is_group_name(v1))
                or (isinstance(v1, str) and is_group_name(v2))
            ):
                # Cannot compare groups
                print(
                    f"[WARNING] Cannot compare MLVO: {self} and {other}",
                    file=sys.stderr,
                )
                return None
        return False

    @classmethod
    def parse_elem(
        cls, elem: ET.Element, implied: dict[RMLVO, str], priority: Priority
    ) -> Self:
        mlvo: dict[str, str] = {}
        for c in RMLVO.mlvo():
            if (v := elem.attrib.get(c)) is not None:
                if c in implied and v != implied[c]:
                    raise ValueError(c, v, implied)
                mlvo[c] = v
            elif v := implied.get(c):
                mlvo[c] = v
        raw_layout_range = elem.attrib.get("layout-range")
        raw_priority = elem.attrib.get("priority")
        return cls(
            layout_range=LayoutRange.parse(raw_layout_range)
            if raw_layout_range is not None
            else "",
            priority=Priority.parse(raw_priority) if raw_priority else priority,
            **mlvo,
        )


@unique
class Section(StrEnum):
    """
    XKB sections.
    Name correspond to the header (`xkb_XXX`), value to the subdir/rules header.
    """

    keycodes = "keycodes"
    compatibility = "compat"
    geometry = "geometry"
    symbols = "symbols"
    types = "types"

    def __lt__(self, other):
        if not isinstance(other, self.__class__):
            return super().__lt__(other)
        else:
            return self._index < other._index

    def __le__(self, other):
        if not isinstance(other, self.__class__):
            return super().__le__(other)
        else:
            return self._index <= other._index

    def __gt__(self, other):
        if not isinstance(other, self.__class__):
            return super().__gt__(other)
        else:
            return self._index > other._index

    def __ge__(self, other):
        if not isinstance(other, self.__class__):
            return super().__ge__(other)
        else:
            return self._index >= other._index

    @property
    def _index(self):
        """
        Ensure the section components respect KcCGST order
        """
        if self is Section.keycodes:
            return 0
        # Invert compat and geometry
        elif self is Section.compatibility:
            return 2
        elif self is Section.geometry:
            return 1
        elif self is Section.symbols:
            return 3
        elif self is Section.types:
            return 4
        else:
            raise ValueError()

    @classmethod
    def parse(cls, raw: str) -> Self:
        # Note: in order to display a nice message, argparse requires the error
        # to be one of: ArgumentTypeError, TypeError, or ValueError
        # See: https://docs.python.org/3/library/argparse.html#type

        # try:
        #     return cls[raw]
        # except KeyError:
        #     raise ValueError(raw)

        for s in cls:
            if raw == s:
                return s
        raise ValueError(f"Cannot parse Section: {raw}")


def is_group_name(s: str) -> bool:
    return s.startswith("$")

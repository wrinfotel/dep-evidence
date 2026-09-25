"""Conservative comparison for common Maven-style versions.

Unsupported or ambiguous version shapes return ``None`` so callers must
review rather than silently classifying a component as affected or fixed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_MAX_VERSION_LENGTH = 256

_QUALIFIER_ALIASES = {
    "a": "alpha",
    "b": "beta",
    "m": "milestone",
    "cr": "rc",
}

# Apache Maven ComparableVersion order: alpha < beta < milestone < rc <
# snapshot < release/empty < sp. The following ranks are only for the common
# qualifier subset supported by this project.
_QUALIFIER_RANKS = {
    "alpha": 0,
    "beta": 1,
    "milestone": 2,
    "rc": 3,
    "snapshot": 4,
    "ga": 5,
    "final": 5,
    "release": 5,
    "sp": 6,
}

_VERSION_RE = re.compile(
    r"\A"
    r"(?P<numbers>[0-9]+(?:[.-][0-9]+)*)"
    r"(?:[-.]?"
    r"(?P<qualifier>alpha|a|beta|b|milestone|m|rc|cr|snapshot|ga|final|release|sp)"
    r"(?P<qualifier_number>[0-9]*))?\Z",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class _NumericList:
    items: tuple[int | "_NumericList", ...]


@dataclass(frozen=True)
class _ParsedVersion:
    numbers: _NumericList
    qualifier: str
    qualifier_number: int


def _parse(version: str) -> _ParsedVersion | None:
    if not isinstance(version, str):
        return None
    raw = version.strip()
    if not raw or len(raw) > _MAX_VERSION_LENGTH:
        return None
    match = _VERSION_RE.fullmatch(raw)
    if match is None:
        return None

    raw_numbers = match.group("numbers")
    numeric_items: list[int | list] = []
    current_items = numeric_items
    position = 0
    while position < len(raw_numbers):
        end = position
        while end < len(raw_numbers) and raw_numbers[end].isdigit():
            end += 1
        current_items.append(int(raw_numbers[position:end]))
        if end < len(raw_numbers) and raw_numbers[end] == "-":
            child_items: list[int | list] = []
            current_items.append(child_items)
            current_items = child_items
        position = end + 1
    numbers = _normalize_numeric_list(numeric_items)

    raw_qualifier = (match.group("qualifier") or "").lower()
    qualifier = _QUALIFIER_ALIASES.get(raw_qualifier, raw_qualifier or "ga")
    qualifier_number = int(match.group("qualifier_number") or 0)
    return _ParsedVersion(numbers, qualifier, qualifier_number)


def _normalize_numeric_list(items: list[int | list]) -> _NumericList:
    normalized: list[int | _NumericList] = [
        _normalize_numeric_list(item) if isinstance(item, list) else item
        for item in items
    ]
    while normalized and (
        normalized[-1] == 0
        or (isinstance(normalized[-1], _NumericList) and not normalized[-1].items)
    ):
        normalized.pop()
    if len(normalized) == 1 and isinstance(normalized[0], _NumericList):
        return normalized[0]
    return _NumericList(tuple(normalized))


def _compare_numeric_item_to_null(item: int | _NumericList) -> int:
    if isinstance(item, _NumericList):
        for child in item.items:
            comparison = _compare_numeric_item_to_null(child)
            if comparison:
                return comparison
        return 0
    return 0 if item == 0 else 1


def _compare_numeric_item(left: int | _NumericList, right: int | _NumericList) -> int:
    if isinstance(left, _NumericList) and isinstance(right, _NumericList):
        for index in range(max(len(left.items), len(right.items))):
            left_item = left.items[index] if index < len(left.items) else None
            right_item = right.items[index] if index < len(right.items) else None
            if left_item is None:
                comparison = -_compare_numeric_item_to_null(right_item)
            elif right_item is None:
                comparison = _compare_numeric_item_to_null(left_item)
            else:
                comparison = _compare_numeric_item(left_item, right_item)
            if comparison:
                return comparison
        return 0
    if isinstance(left, _NumericList):
        return -1
    if isinstance(right, _NumericList):
        return 1
    return (left > right) - (left < right)


def _compare_numbers(left: _NumericList, right: _NumericList) -> int:
    return _compare_numeric_item(left, right)


def compare_versions(left: str, right: str) -> int | None:
    """Return -1/0/1 for confidently comparable versions, otherwise ``None``."""
    left_parsed = _parse(left)
    right_parsed = _parse(right)
    if left_parsed is None or right_parsed is None:
        return None

    numeric_result = _compare_numbers(left_parsed.numbers, right_parsed.numbers)
    if numeric_result:
        return numeric_result

    left_qualifier = (_QUALIFIER_RANKS[left_parsed.qualifier], left_parsed.qualifier_number)
    right_qualifier = (_QUALIFIER_RANKS[right_parsed.qualifier], right_parsed.qualifier_number)
    if left_qualifier < right_qualifier:
        return -1
    if left_qualifier > right_qualifier:
        return 1
    return 0

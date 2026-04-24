from __future__ import annotations

import ipaddress
import json
import re
import uuid as uuid_lib

from ast import literal_eval
from collections import OrderedDict
from typing import Any, Callable

from dateutil.parser import parse as parse_date

from .validatedata import (
    _pipe_tokenize,
    _TRANSFORM_MAP,
    _chain_transforms,
    _coerce_range_val,
    BASIC_TYPES,
    EXTENDED_TYPES,
)
from .engine import (
    validate_contains,
    validate_excludes,
    validate_options,
    validate_expression,
    validate_startswith,
    validate_endswith,
    validate_unique,
    validate_length,
    _EMAIL_RE,
    _URL_RE,
    _SLUG_RE,
    _SEMVER_RE,
    _PHONE_E164_RE,
    _HEX_COLOR_RE,
    _RGB_COLOR_RE,
    _HSL_COLOR_RE,
    _NAMED_COLORS,
    _is_prime,
    _is_valid_color,
)


# ---------------------------------------------------------------------------
# Argument-binding helper
#
# All scalar validator functions take (value, arg). The fast path pre-binds
# arg at compile time. We use a closure rather than functools.partial so the
# binding is explicit and avoids any ambiguity about positional vs keyword
# dispatch at call time.
# ---------------------------------------------------------------------------

def _bind(fn: Callable, arg: Any) -> Callable[[Any], bool]:
    """Return a single-argument callable with the second parameter pre-bound.
    """
    return lambda v, _fn=fn, _a=arg: _fn(v, _a)


# ---------------------------------------------------------------------------
# Type-specialized min / max / between variants
# ---------------------------------------------------------------------------

def _validate_min_len(value: Any, min_val: int | float) -> bool:
    return len(value) >= min_val

def _validate_min_val(value: Any, min_val: int | float) -> bool:
    return value >= min_val

validate_min = _validate_min_len  # public alias for documentation

def _validate_max_len(value: Any, max_val: int | float) -> bool:
    return len(value) <= max_val

def _validate_max_val(value: Any, max_val: int | float) -> bool:
    return value <= max_val

validate_max = _validate_max_len  # public alias for documentation

def _validate_between_len(value: Any, bounds: tuple) -> bool:
    lo, hi = bounds
    return lo <= len(value) <= hi

def _validate_between_val(value: Any, bounds: tuple) -> bool:
    lo, hi = bounds
    return lo <= value <= hi


# Types that use len-based range checks vs value-based.
# All non-native types that are strings at runtime (email, url, etc.) match
# the engine's validate_range str branch: lo <= len(value) <= hi.
_ALL_TYPES: frozenset[str] = frozenset(BASIC_TYPES + EXTENDED_TYPES)

_LEN_TYPES: frozenset[str] = frozenset({
    'str', 'list', 'tuple', 'set', 'dict',
    'email', 'url', 'slug', 'semver', 'uuid', 'ip', 'phone', 'regex', 'color',
})
_VAL_TYPES: frozenset[str] = frozenset({'int', 'float', 'even', 'odd', 'prime', 'bool'})


# ---------------------------------------------------------------------------
# Inline range-check factories
#
# These close over the bounds at compile time and perform the comparison
# in a single call — no _bind wrapper, no intermediate function, no tuple
# unpack.  They replace the previous _bind(_validate_between_val, (lo, hi))
# pattern for min / max / between on both value and length types.
# ---------------------------------------------------------------------------

def _mk_min_val(lo: int | float) -> Callable[[Any], bool]:
    return lambda v, _lo=lo: v >= _lo

def _mk_max_val(hi: int | float) -> Callable[[Any], bool]:
    return lambda v, _hi=hi: v <= _hi

def _mk_between_val(lo: int | float, hi: int | float) -> Callable[[Any], bool]:
    return lambda v, _lo=lo, _hi=hi: _lo <= v <= _hi

def _mk_min_len(lo: int | float) -> Callable[[Any], bool]:
    return lambda v, _lo=lo: len(v) >= _lo

def _mk_max_len(hi: int | float) -> Callable[[Any], bool]:
    return lambda v, _hi=hi: len(v) <= _hi

def _mk_between_len(lo: int | float, hi: int | float) -> Callable[[Any], bool]:
    return lambda v, _lo=lo, _hi=hi: _lo <= len(v) <= _hi


def _make_min(type_name: str, lo: int | float) -> Callable[[Any], bool]:
    return _mk_min_len(lo) if type_name in _LEN_TYPES else _mk_min_val(lo)

def _make_max(type_name: str, hi: int | float) -> Callable[[Any], bool]:
    return _mk_max_len(hi) if type_name in _LEN_TYPES else _mk_max_val(hi)

def _make_between(type_name: str, lo: int | float, hi: int | float) -> Callable[[Any], bool]:
    return _mk_between_len(lo, hi) if type_name in _LEN_TYPES else _mk_between_val(lo, hi)


# ---------------------------------------------------------------------------
# Fused type-and-range factories
#
# For the common pattern (strict type + sole range check) these collapse the
# two-closure chain — c0(v) and c1(v) — into a single closure body.
#
# Dedicated factories for int / float / str inline isinstance directly,
# saving *both* Python call dispatches versus the generic two-check path.
# All other types (email, url, list, …) use generic factories that capture
# the pre-built type_check callable, saving one dispatch.
#
# The non-strict coercion path (literal_eval) is not fused here; it's handled
# separately in _build_type_check_callable and is uncommon in practice.
# ---------------------------------------------------------------------------

# int — value comparisons, isinstance inlined
def _fused_int_min(lo: int | float) -> Callable[[Any], bool]:
    return lambda v, _lo=lo: isinstance(v, int) and v >= _lo

def _fused_int_max(hi: int | float) -> Callable[[Any], bool]:
    return lambda v, _hi=hi: isinstance(v, int) and v <= _hi

def _fused_int_between(lo: int | float, hi: int | float) -> Callable[[Any], bool]:
    return lambda v, _lo=lo, _hi=hi: isinstance(v, int) and _lo <= v <= _hi

# float — value comparisons, isinstance inlined
def _fused_float_min(lo: int | float) -> Callable[[Any], bool]:
    return lambda v, _lo=lo: isinstance(v, float) and v >= _lo

def _fused_float_max(hi: int | float) -> Callable[[Any], bool]:
    return lambda v, _hi=hi: isinstance(v, float) and v <= _hi

def _fused_float_between(lo: int | float, hi: int | float) -> Callable[[Any], bool]:
    return lambda v, _lo=lo, _hi=hi: isinstance(v, float) and _lo <= v <= _hi

# str — length comparisons, isinstance inlined
def _fused_str_min(lo: int | float) -> Callable[[Any], bool]:
    return lambda v, _lo=lo: isinstance(v, str) and len(v) >= _lo

def _fused_str_max(hi: int | float) -> Callable[[Any], bool]:
    return lambda v, _hi=hi: isinstance(v, str) and len(v) <= _hi

def _fused_str_between(lo: int | float, hi: int | float) -> Callable[[Any], bool]:
    return lambda v, _lo=lo, _hi=hi: isinstance(v, str) and _lo <= len(v) <= _hi

# Generic — captures a pre-built type_check callable for all other types.
# Saves one Python call dispatch compared to the two-check chain.
def _fused_tc_val_min(tc: Callable, lo: int | float) -> Callable[[Any], bool]:
    return lambda v, _tc=tc, _lo=lo: _tc(v) and v >= _lo

def _fused_tc_val_max(tc: Callable, hi: int | float) -> Callable[[Any], bool]:
    return lambda v, _tc=tc, _hi=hi: _tc(v) and v <= _hi

def _fused_tc_val_between(tc: Callable, lo: int | float, hi: int | float) -> Callable[[Any], bool]:
    return lambda v, _tc=tc, _lo=lo, _hi=hi: _tc(v) and _lo <= v <= _hi

def _fused_tc_len_min(tc: Callable, lo: int | float) -> Callable[[Any], bool]:
    return lambda v, _tc=tc, _lo=lo: _tc(v) and len(v) >= _lo

def _fused_tc_len_max(tc: Callable, hi: int | float) -> Callable[[Any], bool]:
    return lambda v, _tc=tc, _hi=hi: _tc(v) and len(v) <= _hi

def _fused_tc_len_between(tc: Callable, lo: int | float, hi: int | float) -> Callable[[Any], bool]:
    return lambda v, _tc=tc, _lo=lo, _hi=hi: _tc(v) and _lo <= len(v) <= _hi


def _try_fuse_type_range(
    type_name: str,
    type_check: Callable[[Any], bool],
    lo: int | float | None,
    hi: int | float | None,
) -> Callable[[Any], bool]:
    """Fuse a strict type check + range bounds into a single closure.

    Called only when:
      - effective_strict is True (non-strict uses literal_eval; not fused)
      - no other validators are present (|in:, |contains:, etc.)
      - transform_fn is None
      - not a parameterized type (list[str], etc.)

    Dedicated paths for int / float / str inline isinstance directly.
    All other types fall through to the generic tc-capture path.
    """
    has_lo = lo is not None
    has_hi = hi is not None
    use_len = type_name in _LEN_TYPES

    if type_name == 'int':
        if has_lo and has_hi: return _fused_int_between(lo, hi)    # type: ignore[arg-type]
        if has_lo:            return _fused_int_min(lo)             # type: ignore[arg-type]
        return                       _fused_int_max(hi)             # type: ignore[arg-type]

    if type_name == 'float':
        if has_lo and has_hi: return _fused_float_between(lo, hi)   # type: ignore[arg-type]
        if has_lo:            return _fused_float_min(lo)            # type: ignore[arg-type]
        return                       _fused_float_max(hi)            # type: ignore[arg-type]

    if type_name == 'str':
        if has_lo and has_hi: return _fused_str_between(lo, hi)     # type: ignore[arg-type]
        if has_lo:            return _fused_str_min(lo)              # type: ignore[arg-type]
        return                       _fused_str_max(hi)              # type: ignore[arg-type]

    # Generic path for all other types (email, url, list, dict, etc.)
    if use_len:
        if has_lo and has_hi: return _fused_tc_len_between(type_check, lo, hi)  # type: ignore[arg-type]
        if has_lo:            return _fused_tc_len_min(type_check, lo)           # type: ignore[arg-type]
        return                       _fused_tc_len_max(type_check, hi)           # type: ignore[arg-type]
    else:
        if has_lo and has_hi: return _fused_tc_val_between(type_check, lo, hi)  # type: ignore[arg-type]
        if has_lo:            return _fused_tc_val_min(type_check, lo)           # type: ignore[arg-type]
        return                       _fused_tc_val_max(type_check, hi)           # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# _TYPE_CHECK — module-level dispatch table (strict variants only)
#
# Built once at import time. Each entry is a single-argument callable that
# returns bool with no intermediate lookups at call time.
# Native types map directly to isinstance — no dict lookup for the type object.
# ---------------------------------------------------------------------------

def _tc_ip(v: Any) -> bool:
    try:
        ipaddress.ip_address(str(v))
        return True
    except ValueError:
        return False

def _tc_uuid(v: Any) -> bool:
    try:
        uuid_lib.UUID(str(v))
        return True
    except ValueError:
        return False

def _tc_date(v: Any) -> bool:
    from datetime import datetime as _dt
    if isinstance(v, _dt):
        return True
    try:
        return isinstance(parse_date(v), _dt)
    except Exception:
        return False

def _tc_even(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v % 2 == 0

def _tc_odd(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v % 2 == 1

def _tc_phone_e164(v: Any) -> bool:
    return bool(_PHONE_E164_RE.match(str(v).strip()))


_TYPE_CHECK: dict[str, Callable[[Any], bool]] = {
    # native types — direct isinstance, type object captured at table-build time
    'str':   lambda v: isinstance(v, str),
    'int':   lambda v: isinstance(v, int),
    'float': lambda v: isinstance(v, float),
    'bool':  lambda v: isinstance(v, bool),
    'dict':  lambda v: isinstance(v, dict),
    'list':  lambda v: isinstance(v, list),
    'set':   lambda v: isinstance(v, set),
    'tuple': lambda v: isinstance(v, tuple),
    # non-native basic types
    'email':  lambda v: _EMAIL_RE.match(str(v)) is not None,
    'url':    lambda v: _URL_RE.match(str(v)) is not None,
    'ip':     _tc_ip,
    'uuid':   _tc_uuid,
    'slug':   lambda v: _SLUG_RE.match(str(v)) is not None,
    'semver': lambda v: _SEMVER_RE.match(str(v)) is not None,
    'date':   _tc_date,
    'even':   _tc_even,
    'odd':    _tc_odd,
    'prime':  _is_prime,
    'color':  lambda v: _is_valid_color(v),
    'phone':  _tc_phone_e164,
    'regex':  lambda v: isinstance(v, str),
}


# ---------------------------------------------------------------------------
# _COLOR_CHECK — sub-table for format-specific color checks
# Each entry is a pre-compiled single-argument callable; no dispatch at call time.
# ---------------------------------------------------------------------------

_COLOR_CHECK: dict[str, Callable[[Any], bool]] = {
    'hex':   lambda v: bool(_HEX_COLOR_RE.match(str(v).strip())),
    'rgb':   lambda v: bool(_RGB_COLOR_RE.match(str(v).strip())),
    'hsl':   lambda v: bool(_HSL_COLOR_RE.match(str(v).strip())),
    'named': lambda v: str(v).strip().lower() in _NAMED_COLORS,
}


# ---------------------------------------------------------------------------
# Native type map for non-strict coercion closures
# ---------------------------------------------------------------------------

_NATIVE_TYPE_MAP: dict[str, type] = {
    'str': str, 'int': int, 'float': float, 'bool': bool,
    'dict': dict, 'list': list, 'set': set, 'tuple': tuple,
}
_NATIVE_NAMES: frozenset[str] = frozenset(_NATIVE_TYPE_MAP)


# ---------------------------------------------------------------------------
# Parameterized type support — list[str], tuple[int,str], set[email], etc.
# ---------------------------------------------------------------------------

# Matches: list[str], tuple[int,float], set[email,url], etc.
# Item group captures everything inside brackets — split on ',' after match.
_PARAMETERIZED_RE = re.compile(r'^(list|tuple|set)\[([^\]]+)\]$')

# Item-level type check table.
# Identical to _TYPE_CHECK except 'int' excludes bool subclass.
# Kept separate so existing top-level rules are unaffected.
#
# Rationale: isinstance(True, int) is True in Python. At the top level users
# control what they pass; inside a container they don't. list[int] with
# [1, True, 3] silently passing would be a footgun. float is clean —
# isinstance(True, float) is False — so only int needs the guard.
_ITEM_TYPE_CHECK: dict[str, Callable[[Any], bool]] = {
    **_TYPE_CHECK,
    'int': lambda v: isinstance(v, int) and not isinstance(v, bool),
}


# ---------------------------------------------------------------------------
# Build the final type-check callable given compile-time parameters.
#
# This is the only place where strict, fmt, and region are examined.
# The returned callable takes one argument and returns bool — no runtime
# dispatch on any of these modifiers.
# ---------------------------------------------------------------------------

def _build_type_check_callable(
    type_name: str,
    strict: bool,
    fmt: str | None,
    region: str | None,
) -> Callable[[Any], bool]:
    """Return a single-argument bool callable for the given type configuration."""

    # Non-strict native types — build closure at compile time
    if not strict and type_name in _NATIVE_NAMES:
        _expected = _NATIVE_TYPE_MAP[type_name]
        def _nonstrict(v: Any, expected: type = _expected) -> bool:
            try:
                return isinstance(literal_eval(str(v)), expected)
            except (TypeError, ValueError):
                return False
        return _nonstrict

    # Color with format: select pre-compiled sub-table entry
    if type_name == 'color':
        if fmt and fmt in _COLOR_CHECK:
            return _COLOR_CHECK[fmt]
        if fmt:
            raise ValueError(
                f"Unknown color format {fmt!r}. "
                "Supported: 'hex', 'rgb', 'hsl', 'named'."
            )
        return _TYPE_CHECK['color']

    # Phone with region/format: default is e164 (no external package needed)
    if type_name == 'phone':
        if fmt is None or fmt == 'e164':
            return _TYPE_CHECK['phone']
        # Non-e164 requires phonenumbers; close over fmt and region at compile time
        _fmt = fmt
        _region = region
        def _phone_check(v: Any, __fmt: str = _fmt, __region: str | None = _region) -> bool:
            try:
                import phonenumbers
                try:
                    parsed = phonenumbers.parse(str(v).strip(), __region)
                    return phonenumbers.is_valid_number(parsed)
                except Exception:
                    return False
            except ImportError:
                raise ImportError(
                    f"Phone format '{__fmt}' requires the phonenumbers package. "
                    "Install it with: pip install phonenumbers"
                )
        return _phone_check

    # Standard strict lookup
    if type_name not in _TYPE_CHECK:
        raise TypeError(f'{type_name!r} is not a supported type')
    return _TYPE_CHECK[type_name]


# ---------------------------------------------------------------------------
# _build_parameterized_type_check
#
# Compiles a union-item type check for list[str], list[int,str], etc.
# Three runtime variants are selected at compile time:
#
#   all-native:       isinstance(i, (_t1, _t2))   — single C call per item
#   single non-native: _ic(i)                     — no any() overhead
#   mixed/multi:      any(_c(i) for _c in _cs)    — general fallback
#
# Item types always use _ITEM_TYPE_CHECK (strict isinstance) — coercing items
# inside a container would be surprising and inconsistent with validate_types.
#
# Bool subclass guard: when int is in the item types but bool is not explicitly
# listed, True/False are rejected. list[int,bool] is a legitimate rule and
# passes both; list[int] and list[int,str] do not pass bools.
# ---------------------------------------------------------------------------

def _build_parameterized_type_check(
    outer_name: str,
    item_names: list[str],
) -> Callable[[Any], bool]:
    """Compile a union-item type check for list[str], list[int,str], etc."""
    for name in item_names:
        if name not in _ITEM_TYPE_CHECK:
            raise TypeError(
                f'{name!r} is not a recognised item type for '
                f'{outer_name}[{", ".join(item_names)}]. '
                f'Supported item types: {sorted(_ITEM_TYPE_CHECK)}'
            )

    _outer = _NATIVE_TYPE_MAP[outer_name]
    native_types = tuple(_NATIVE_TYPE_MAP[n] for n in item_names if n in _NATIVE_TYPE_MAP)
    non_native = [n for n in item_names if n not in _NATIVE_TYPE_MAP]

    # bool guard: suppress bool when int is present but bool was not explicitly listed
    _exclude_bool = int in native_types and 'bool' not in item_names

    # --- all-native: single isinstance tuple call per item ---
    if not non_native:
        _ts = native_types
        if _exclude_bool:
            return lambda v, _o=_outer, _t=_ts: (
                isinstance(v, _o)
                and all(isinstance(i, _t) and not isinstance(i, bool) for i in v)
            )
        return lambda v, _o=_outer, _t=_ts: (
            isinstance(v, _o) and all(isinstance(i, _t) for i in v)
        )

    # --- single item type (non-native) ---
    if len(item_names) == 1:
        _ic = _ITEM_TYPE_CHECK[item_names[0]]
        return lambda v, _o=_outer, _c=_ic: (
            isinstance(v, _o) and all(_c(i) for i in v)
        )

    # --- 2-checker unroll: avoids any() + generator overhead ---
    # list[email,url] style — the likely real-world multi non-native use
    checkers = tuple(_ITEM_TYPE_CHECK[n] for n in item_names)
    if len(checkers) == 2:
        _c0, _c1 = checkers
        return lambda v, _o=_outer, _a=_c0, _b=_c1: (
            isinstance(v, _o) and all(_a(i) or _b(i) for i in v)
        )

    # --- general fallback ---
    _cs = checkers
    return lambda v, _o=_outer, _cs=_cs: (
        isinstance(v, _o) and all(any(_c(i) for _c in _cs) for i in v)
    )


# ---------------------------------------------------------------------------
# LRU cache
# ---------------------------------------------------------------------------

_COMPILED_CACHE: OrderedDict[str, Callable] = OrderedDict()
_COMPILED_CACHE_MAX: int = 256
# To adjust the cap: import compiled; compiled._COMPILED_CACHE_MAX = N


def _cache_get(key: str) -> Callable | None:
    if key in _COMPILED_CACHE:
        _COMPILED_CACHE.move_to_end(key)
        return _COMPILED_CACHE[key]
    return None


def _cache_set(key: str, fn: Callable) -> None:
    if len(_COMPILED_CACHE) >= _COMPILED_CACHE_MAX:
        _COMPILED_CACHE.popitem(last=False)   # evict oldest (LRU)
    _COMPILED_CACHE[key] = fn


# ---------------------------------------------------------------------------
# Core compiler
# ---------------------------------------------------------------------------

def _compile_pipe_rule(
    rule_str: str,
) -> tuple[Callable | None, list[Callable[[Any], bool]], bool]:
    """Compile a pipe rule string into its fast-path components.

    Returns a 3-tuple: (transform_fn_or_None, [type_check, *validators], nullable).
    Callers must unpack all three before passing to _make_callable.

    Does NOT call _expand_pipe_rule and does NOT materialise a rule dict.
    """
    tokens = _pipe_tokenize(rule_str)

    # --- token 0: type name ---
    type_name = tokens[0].strip()

    # --- detect parameterized types: list[str], tuple[int,str], set[email], etc. ---
    _item_type_names: list[str] | None = None
    _m = _PARAMETERIZED_RE.match(type_name)
    if _m:
        outer_name = _m.group(1)
        _item_type_names = [t.strip() for t in _m.group(2).split(',')]
        type_name = outer_name   # outer drives all range / len / min / max logic below
    elif type_name not in _ALL_TYPES:
        raise TypeError(f'{type_name!r} is not a supported type')

    # --- accumulators ---
    # strict defaults to True for native types, False for date/regex — matching engine.
    # _strict_seen tracks whether the |strict token was explicitly written.
    _strict_seen: bool = False
    nullable: bool = False
    fmt: str | None = None
    region: str | None = None
    transforms: list = []
    validators: list[Callable[[Any], bool]] = []
    min_val: str | None = None
    max_val: str | None = None
    between_seen: bool = False
    seen_validator: bool = False
    # Deferred range bounds — kept as raw floats so _try_fuse_type_range can
    # combine them with the type check into a single closure at build time.
    _fuse_lo: int | float | None = None
    _fuse_hi: int | float | None = None

    for token in tokens[1:]:
        key, _, value = token.partition(':')
        key = key.strip()
        value = value or None

        # --- transform tokens must precede validator tokens ---
        if key in _TRANSFORM_MAP:
            if seen_validator:
                raise ValueError(
                    f'Transform {key!r} must come before validators in rule: {rule_str!r}'
                )
            transforms.append(_TRANSFORM_MAP[key])
            continue

        # --- flag tokens (do not count as validators) ---
        if key == 'nullable':
            nullable = True
            seen_validator = True
            continue

        if key == 'strict':
            _strict_seen = True
            seen_validator = True
            continue

        if key == 'msg':
            # Fast path returns bool only — messages are silently ignored
            seen_validator = True
            continue

        seen_validator = True

        # --- unsupported fast-path tokens ---
        if key == 'of':
            raise ValueError(
                f"'of:' is not supported in the fast path. "
                f"Use validate_data for list-of-type validation, or use "
                f"the bracket syntax e.g. 'list[str]'. Rule: {rule_str!r}"
            )

        # --- modifier tokens (feed into type check, not validators list) ---
        if key == 'format':
            if value is None:
                raise ValueError(f"'format' requires a value in rule: {rule_str!r}")
            fmt = value
            continue

        if key == 'region':
            if value is None:
                raise ValueError(f"'region' requires a value in rule: {rule_str!r}")
            region = value
            continue

        # --- scalar validator tokens ---
        if key == 'unique':
            validators.append(_bind(validate_unique, None))
            continue

        if key == 'length':
            if value is None:
                raise ValueError(f"'length' requires a value in rule: {rule_str!r}")
            try:
                length_int = int(value)
            except (ValueError, TypeError):
                raise ValueError(
                    f"'length' requires an integer value in rule: {rule_str!r}"
                )
            validators.append(_bind(validate_length, length_int))
            continue

        if key == 'in':
            if value is None:
                raise ValueError(f"'in' requires a value in rule: {rule_str!r}")
            opts = frozenset(item.strip() for item in value.split(','))
            validators.append(_bind(validate_options, opts))
            continue

        if key == 'not_in':
            if value is None:
                raise ValueError(f"'not_in' requires a value in rule: {rule_str!r}")
            excl = frozenset(item.strip() for item in value.split(','))
            validators.append(_bind(validate_excludes, excl))
            continue

        if key == 'contains':
            if value is None:
                raise ValueError(f"'contains' requires a value in rule: {rule_str!r}")
            contains_arg: Any = (
                tuple(item.strip() for item in value.split(','))
                if ',' in value
                else value
            )
            validators.append(_bind(validate_contains, contains_arg))
            continue

        if key == 'starts_with':
            if value is None:
                raise ValueError(f"'starts_with' requires a value in rule: {rule_str!r}")
            validators.append(_bind(validate_startswith, value))
            continue

        if key == 'ends_with':
            if value is None:
                raise ValueError(f"'ends_with' requires a value in rule: {rule_str!r}")
            validators.append(_bind(validate_endswith, value))
            continue

        if key == 're':
            if value is None:
                raise ValueError(f"'re' requires a value in rule: {rule_str!r}")
            validators.append(_bind(validate_expression, value))
            continue

        if key == 'min':
            if value is None:
                raise ValueError(f"'min' requires a value in rule: {rule_str!r}")
            min_val = value
            continue

        if key == 'max':
            if value is None:
                raise ValueError(f"'max' requires a value in rule: {rule_str!r}")
            max_val = value
            continue

        if key == 'between':
            if min_val is not None or max_val is not None:
                raise ValueError(
                    f"Cannot combine 'between' with 'min' or 'max' in rule: {rule_str!r}"
                )
            if value is None:
                raise ValueError(f"'between' requires a value in rule: {rule_str!r}")
            parts = value.split(',', 1)
            if len(parts) != 2:
                raise ValueError(
                    f"'between' requires two comma-separated values in rule: {rule_str!r}"
                )
            if type_name == 'date':
                raise ValueError(
                    f"Date ranges via 'between:' are not supported in the fast path. "
                    f"Use validate_data for date range validation. Rule: {rule_str!r}"
                )
            lo = _coerce_range_val(parts[0].strip())
            hi = _coerce_range_val(parts[1].strip())
            _fuse_lo = lo
            _fuse_hi = hi
            between_seen = True
            continue

        raise ValueError(f"Unknown modifier {key!r} in rule: {rule_str!r}")

    # --- post-loop: resolve min/max into validators ---
    if min_val is not None or max_val is not None:
        if between_seen:
            raise ValueError(
                f"Cannot combine 'between' with 'min' or 'max' in rule: {rule_str!r}"
            )
        if type_name == 'date':
            raise ValueError(
                f"Date ranges are not supported in the fast path. "
                f"Use validate_data for date range validation. Rule: {rule_str!r}"
            )
        if min_val is not None and max_val is not None:
            lo = _coerce_range_val(min_val)
            hi = _coerce_range_val(max_val)
            _fuse_lo = lo
            _fuse_hi = hi
        elif min_val is not None:
            lo = _coerce_range_val(min_val)
            _fuse_lo = lo
        else:
            hi = _coerce_range_val(max_val)  # type: ignore[arg-type]
            _fuse_hi = hi

    # --- resolve effective strict ---
    # Match engine defaults: False for date/regex (accepts strings), True for all others.
    # An explicit |strict token forces strict=True regardless of type.
    if _strict_seen:
        effective_strict = True
    else:
        effective_strict = type_name not in ('date', 'regex')

    # --- build type check callable ---
    if _item_type_names is not None:
        type_check = _build_parameterized_type_check(type_name, _item_type_names)
    else:
        type_check = _build_type_check_callable(type_name, effective_strict, fmt, region)

    # --- build transform callable (not part of the bool chain) ---
    transform_fn: Callable | None
    if transforms:
        transform_fn = (
            transforms[0] if len(transforms) == 1
            else _chain_transforms(transforms)
        )
    else:
        transform_fn = None

    # --- Fusion: type check + sole range bound → single closure ---
    # Conditions: strict type, no other validators (|in:, |contains:, …),
    # no transform, and not a parameterized type (list[str], etc.).
    # Non-strict types embed literal_eval in their type_check; fusing the
    # range would require duplicating coercion logic for minimal gain.
    if (
        (_fuse_lo is not None or _fuse_hi is not None)
        and not validators
        and transform_fn is None
        and effective_strict
        and _item_type_names is None
    ):
        return None, [_try_fuse_type_range(type_name, type_check, _fuse_lo, _fuse_hi)], nullable

    # No fusion — materialise the range check and append to validators normally.
    if _fuse_lo is not None or _fuse_hi is not None:
        if _fuse_lo is not None and _fuse_hi is not None:
            validators.append(_make_between(type_name, _fuse_lo, _fuse_hi))
        elif _fuse_lo is not None:
            validators.append(_make_min(type_name, _fuse_lo))
        else:
            validators.append(_make_max(type_name, _fuse_hi))

    checks = [type_check] + validators
    return transform_fn, checks, nullable


def _make_callable(
    transform: Callable | None,
    checks: list[Callable[[Any], bool]],
    nullable: bool,
) -> Callable[[Any], bool]:
    """Wrap compiled checks into a single (value) -> bool callable.

    Caller must unpack the 3-tuple from _compile_pipe_rule before calling::

        transform, checks, nullable = _compile_pipe_rule(rule_str)
        fn = _make_callable(transform, checks, nullable)
    """
    # Unroll the 1-, 2-, and 3-check cases to avoid allocating a generator
    # object on every call — the dominant overhead vs handwritten validators.
    # The 4+ case falls back to all(); by then per-call work dominates anyway.
    n = len(checks)
    if n == 1:
        c0 = checks[0]
        def _run(v: Any) -> bool: return c0(v)
    elif n == 2:
        c0, c1 = checks
        def _run(v: Any) -> bool: return c0(v) and c1(v)  # type: ignore[misc]
    elif n == 3:
        c0, c1, c2 = checks
        def _run(v: Any) -> bool: return c0(v) and c1(v) and c2(v)  # type: ignore[misc]
    else:
        _checks = checks
        def _run(v: Any) -> bool: return all(c(v) for c in _checks)  # type: ignore[misc]

    # Four variants to avoid any nullable/transform branch at call time.
    if nullable and transform is None:
        def _fn_nullable(value: Any) -> bool:
            if value is None:
                return True
            return _run(value)
        return _fn_nullable

    if nullable:  # transform is not None
        def _fn_nullable_transform(value: Any) -> bool:
            if value is None:
                return True
            return _run(transform(value))
        return _fn_nullable_transform

    if transform is not None:
        def _fn_transform(value: Any) -> bool:
            return _run(transform(value))
        return _fn_transform

    return _run


def _compile_dict_rule(
    rule: dict,
) -> list[tuple[str, Callable[[Any], bool], bool]]:
    """Compile a flat {field: pipe_rule_string} dict into compiled field specs.

    Returns a list of (field, check_callable, nullable) triples. The nullable
    flag is surfaced separately so _make_dict_callable can choose the fastest
    field-access strategy at build time rather than at every call.

    Raises ValueError if any rule value is a dict or list (nested rules are
    not supported in this pass — use validate_data instead).
    """
    for field, value in rule.items():
        if isinstance(value, (dict, list)):
            raise ValueError(
                f"Nested rules are not supported in the fast path "
                f"(field {field!r} has a {type(value).__name__} value). "
                "Use validate_data for nested validation."
            )
        if not isinstance(value, str):
            raise ValueError(
                f"Rule values must be pipe-rule strings in the fast path "
                f"(field {field!r} has type {type(value).__name__!r})."
            )

    result: list[tuple[str, Callable[[Any], bool], bool]] = []
    for field, rule_str in rule.items():
        transform, checks, nullable = _compile_pipe_rule(rule_str)
        result.append((field, _make_callable(transform, checks, nullable), nullable))
    return result



def _make_dict_callable(
    field_specs: list[tuple[str, Callable[[Any], bool], bool]],
    *,
    codegen: bool = False,
) -> Callable[[Any], bool]:
    """Build the dict-validator callable from compiled field specs.

    Two compile-time strategies are selected based on nullability:

    all_required (no nullable fields)
        Every field uses ``data[field]`` (direct C-level hash lookup, no
        default-value overhead) wrapped in a per-field ``try/except KeyError``.
        The happy path — a valid dict with every key present — pays only the
        hash lookup, never the attribute-lookup + call overhead of ``dict.get``.

    has_nullable (at least one nullable field)
        Per-field dispatch: required fields still use ``data[field]`` with
        ``KeyError → False``; nullable fields use ``data.get(field)`` so a
        missing key and an explicit ``None`` are treated identically,
        consistent with validate_data.

    Args:
        field_specs: Compiled field triples ``(field_name, check, nullable)``.
        codegen:     When ``True`` emit and ``exec`` a fully unrolled function
                     body — no loop overhead on the hot path, unlimited arity.
                     When ``False`` (default) use a plain loop — zero compile
                     overhead, easier to debug, picklable.

    Codegen notes:
        Tracebacks show ``<dict_validator_n={n}_{strategy}>`` as the filename.
        exec-produced functions are not picklable.
    """
    n = len(field_specs)

    if n == 0:
        return lambda data: isinstance(data, dict)

    all_required = not any(nullable for _, _, nullable in field_specs)
    # Strip the nullable flag for the all_required loop path — safe because
    # nullability is already encoded inside each check callable itself.
    items: tuple[tuple[str, Callable[[Any], bool]], ...] = tuple(
        (f, c) for f, c, _ in field_specs
    )

    if not codegen:
        # --- loop path ---------------------------------------------------
        if all_required:
            def fn_required(data: Any) -> bool:
                if not isinstance(data, dict): return False
                for f, c in items:
                    try:
                        v = data[f]
                    except KeyError:
                        return False
                    if not c(v): return False
                return True
            return fn_required
        else:
            # Per-field dispatch: required fields use data[f] so a missing
            # required key is caught as KeyError, not silently passed as None.
            _specs = tuple(field_specs)
            def fn_mixed(data: Any) -> bool:
                if not isinstance(data, dict): return False
                for f, c, nullable in _specs:
                    if nullable:
                        if not c(data.get(f)): return False
                    else:
                        try:
                            v = data[f]
                        except KeyError:
                            return False
                        if not c(v): return False
                return True
            return fn_mixed

    # --- codegen path ----------------------------------------------------
    # Namespace uses mangled names (_f0, _c0, …) to avoid collisions with
    # field names that happen to be valid Python identifiers.
    ns: dict[str, Any] = {}
    for i, (f, c, _) in enumerate(field_specs):
        ns[f"_f{i}"] = f
        ns[f"_c{i}"] = c

    lines: list[str] = ["def _fn(data):"]
    lines.append("    if not isinstance(data, dict): return False")

    if all_required:
        for i in range(n):
            lines.append(f"    try: _v{i} = data[_f{i}]")
            lines.append(f"    except KeyError: return False")
            if i < n - 1:
                lines.append(f"    if not _c{i}(_v{i}): return False")
            else:
                lines.append(f"    return _c{i}(_v{i})")
        strategy = "required"
    else:
        # Per-field dispatch: required fields use data[f] + KeyError guard;
        # nullable fields use data.get(f) so missing == None.
        for i, (_, _, nullable) in enumerate(field_specs):
            is_last = i == n - 1
            if nullable:
                expr = f"_c{i}(data.get(_f{i}))"
                if is_last:
                    lines.append(f"    return {expr}")
                else:
                    lines.append(f"    if not {expr}: return False")
            else:
                lines.append(f"    try: _v{i} = data[_f{i}]")
                lines.append(f"    except KeyError: return False")
                if is_last:
                    lines.append(f"    return _c{i}(_v{i})")
                else:
                    lines.append(f"    if not _c{i}(_v{i}): return False")
        strategy = "nullable"

    code = compile("\n".join(lines), f"<dict_validator_n={n}_{strategy}>", "exec")
    exec(code, ns)  # noqa: S102  # NOSONAR: S5334 — interpolated values are integer loop indices only; field names and callables enter via ns, never as source text
    return ns["_fn"]  # type: ignore[return-value]




# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def validator(rule: str | dict, codegen=False) -> Callable[[Any], bool]:
    """Compile a pipe rule string or flat dict rule into a fast bool callable.

    The returned callable takes a single value and returns True if valid,
    False otherwise. No error messages are produced — use validate_data when
    you need structured errors.

    Compiled callables are cached (LRU, max 256 entries by default). The same
    rule string always returns the same callable object on a cache hit.

    Parameterized types are supported for list, tuple, and set containers::

        is_valid = validator('list[str]')
        is_valid(['a', 'b'])    # True
        is_valid([1, 2])        # False

        is_valid = validator('list[int,str]')
        is_valid([1, 'a', 2])   # True — union: each item is int or str

    Example::

        is_valid = validator('str|min:2|max:20')
        is_valid('hello')   # True
        is_valid('x')       # False

        validate_user = validator({'name': 'str|min:2', 'age': 'int'})
        validate_user({'name': 'Alice', 'age': 30})   # True
        validate_user({'name': 'A'})                  # False — name too short

    Raises:
        TypeError   if rule is not a str or dict
        TypeError   if a type token is not a recognised type
        ValueError  if a modifier is unknown, malformed, or unsupported in the
                    fast path (of:, nested dict values, date between:)
    """
    if not isinstance(rule, (str, dict)):
        raise TypeError(
            f"validator expects a str or dict, got {type(rule).__name__!r}"
        )

    cache_key: str = rule if isinstance(rule, str) else json.dumps(rule, sort_keys=True)

    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    if isinstance(rule, str):
        transform, checks, nullable = _compile_pipe_rule(rule)
        fn: Callable[[Any], bool] = _make_callable(transform, checks, nullable)
    else:
        field_specs = _compile_dict_rule(rule)
        fn = _make_dict_callable(field_specs, codegen=codegen)  # type: ignore[misc]

    _cache_set(cache_key, fn)
    return fn
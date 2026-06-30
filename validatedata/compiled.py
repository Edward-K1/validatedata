from __future__ import annotations

import ipaddress
import json
import re
import time
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
from .types import get_registered_checker


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

def _tc_email(v: Any) -> bool:
    if not v or "@" not in str(v) or len(str(v)) > 254:
        return False
    return _EMAIL_RE.match(str(v)) is not None


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
    'email':  _tc_email,
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

_ULTRA_LEN_BASED: frozenset[str] = frozenset({
    "str", "email", "url", "uuid", "ip", "slug", "semver", "phone",
    "color", "list", "dict", "set", "tuple",
})

_ULTRA_TYPE_EXPRS: dict[str, tuple[str, dict[str, Any] | None]] = {
    'str':    ('isinstance({v}, str)', None),
    'int':    ('isinstance({v}, int)', None),
    'float':  ('isinstance({v}, float)', None),
    'bool':   ('isinstance({v}, bool)', None),
    'dict':   ('isinstance({v}, dict)', None),
    'list':   ('isinstance({v}, list)', None),
    'set':    ('isinstance({v}, set)', None),
    'tuple':  ('isinstance({v}, tuple)', None),
    'email':  ('_tc_email({v})', {'_tc_email': _tc_email}),
    'url':    ('_RE_url.match(str({v})) is not None', {'_RE_url': _URL_RE}),
    'slug':   ('_RE_slug.match(str({v})) is not None', {'_RE_slug': _SLUG_RE}),
    'semver': ('_RE_semver.match(str({v})) is not None', {'_RE_semver': _SEMVER_RE}),
    'phone':  ('_RE_phone.match(str({v}).strip()) is not None', {'_RE_phone': _PHONE_E164_RE}),
    'ip':     ('_tc_ip({v})', {'_tc_ip': _tc_ip}),
    'uuid':   ('_tc_uuid({v})', {'_tc_uuid': _tc_uuid}),
    'date':   ('_tc_date({v})', {'_tc_date': _tc_date}),
    'color':  ('_is_valid_color({v})', {'_is_valid_color': _is_valid_color}),
    'even':   ('isinstance({v}, int) and not isinstance({v}, bool) and {v} % 2 == 0', None),
    'odd':    ('isinstance({v}, int) and not isinstance({v}, bool) and {v} % 2 == 1', None),
    'prime':  ('_is_prime({v})', {'_is_prime': _is_prime}),
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

    # Standard strict lookup – first try built‑in table
    if type_name in _TYPE_CHECK:
        return _TYPE_CHECK[type_name]

    # Then try custom type registry (strict only, non‑strict not supported for customs)
    custom_checker = get_registered_checker(type_name)
    if custom_checker is not None:
        # Custom checkers always run in strict mode (no literal_eval)
        return custom_checker

    raise TypeError(f'{type_name!r} is not a supported type')


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
        if name not in _ITEM_TYPE_CHECK and get_registered_checker(name) is None:
            raise TypeError(
                f'{name!r} is not a recognised item type for '
                f'{outer_name}[{", ".join(item_names)}]. '
                f'Supported item types: {sorted(_ITEM_TYPE_CHECK)} plus registered custom types'
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
        _ic = _ITEM_TYPE_CHECK.get(item_names[0])
        if _ic is None:
            _ic = get_registered_checker(item_names[0])
            if _ic is None:
                raise TypeError(f'Item type {item_names[0]!r} not found')
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

def _compile_pipe_rule(rule_str: str, *, _fuse: bool = True) -> tuple[Callable | None, list[Callable[[Any], bool]], bool]:
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
        _fuse
        and (_fuse_lo is not None or _fuse_hi is not None)
        and not validators and transform_fn is None
        and effective_strict and _item_type_names is None
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
    
    # Ultra-fast path: 1 check, no nullable, no transform.
    # Return the closure directly to save a Python call frame.
    if n == 1 and not nullable and transform is None:
        return checks[0]
        
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
    *,
    codegen: bool = False,
) -> list[tuple[str, Callable[[Any], bool], bool]]:
    """Compile a {field: rule} dict into compiled field specs.

    Values may be pipe-rule strings or nested dicts (which are compiled
    recursively, mirroring the shape of the data being validated).

    Returns a list of (field, check_callable, nullable) triples. The nullable
    flag is surfaced separately so _make_dict_callable can choose the fastest
    field-access strategy at build time rather than at every call.

    Raises ValueError if any rule value is a list or a non-str/dict type.
    """
    for field, value in rule.items():
        if isinstance(value, list):
            raise ValueError(
                f"List rule values are not supported in the fast path "
                f"(field {field!r} has a list value). "
                "Use validate_data for list-of-rule validation."
            )
        if not isinstance(value, (str, dict)):
            raise ValueError(
                f"Rule values must be pipe-rule strings or nested dicts "
                f"(field {field!r} has type {type(value).__name__!r})."
            )

    result: list[tuple[str, Callable[[Any], bool], bool]] = []
    for field, value in rule.items():
        if isinstance(value, dict):
            nested_specs = _compile_dict_rule(value, codegen=codegen)
            nested_fn = _make_dict_callable(nested_specs, codegen=codegen)
            result.append((field, nested_fn, False))
        else:
            transform, checks, nullable = _compile_pipe_rule(value)
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

import re as _re_module  # Ensure we have a local alias to avoid clashes

def _ultra_compile_dict(schema: dict) -> Callable[[Any], bool]:
    """Generate a fully inlined, single-frame validator for simple schemas.

    Interleaves field extraction and checking so that on invalid input,
    only the fields up to the first failure are extracted — matching the
    performance characteristics of handwritten manual validation.

    Handles nested dicts by recursing without increasing indentation,
    keeping the entire block inside a single try/except.
    """
    ns: dict[str, Any] = {
        "_tc_date": _tc_date,
        "_is_valid_color": _is_valid_color,
    }

    lines: list[str] = ["def _fn(data):"]
    lines.append("    if not isinstance(data, dict): return False")
    lines.append("    try:")

    _counter = [0]

    def _new_var() -> str:
        _counter[0] += 1
        return f"_v{_counter[0]}"
        


    def _build_exprs(var: str, type_tok: str, modifiers: list[str]) -> list[str]:
        exprs = []
    
        # Determine type characteristics for range checks.
        _is_parameterized = _PARAMETERIZED_RE.match(type_tok) is not None
        _is_date = type_tok == "date"
        _is_color = type_tok == "color"
        _is_str_derived = type_tok in (
            "str", "email", "url", "slug", "semver", "phone", "uuid", "ip",
        )
        _is_container = type_tok in ("list", "tuple", "set", "dict")
        _use_len = (type_tok in _ULTRA_LEN_BASED or _is_parameterized) and not _is_date
    
        # Track date range bounds for specialized handling.
        _date_lo: str | None = None
        _date_hi: str | None = None
    
        # Type check — always first for short-circuit safety.
        if _is_parameterized:
            m_p = _PARAMETERIZED_RE.match(type_tok)
            outer = m_p.group(1)
            inner_names = [t.strip() for t in m_p.group(2).split(",")]
            outer_py = outer
            if len(inner_names) == 1:
                inner = inner_names[0]
                if inner == "int":
                    inner_expr = f"isinstance(i, int) and not isinstance(i, bool)"
                elif inner in ("str", "float", "bool"):
                    inner_expr = f"isinstance(i, {inner})"
                else:
                    nm = f"_ic_{_counter[0]}"
                    ns[nm] = _ITEM_TYPE_CHECK.get(inner) or _TYPE_CHECK.get(inner)
                    inner_expr = f"{nm}(i)"
                exprs.append(f"isinstance({var}, {outer_py}) and all({inner_expr} for i in {var})")
            else:
                checkers_nm = f"_ics_{_counter[0]}"
                ns[checkers_nm] = tuple(_ITEM_TYPE_CHECK[n] for n in inner_names)
                exprs.append(
                    f"isinstance({var}, {outer_py}) and "
                    f"all(any(_c(i) for _c in {checkers_nm}) for i in {var})"
                )
        elif _is_date:
            # Will be replaced by range checker if bounds present, else use standard
            exprs.append(f"_tc_date({var})")
        elif _is_color:
            # Default color check; format: modifier may replace exprs[0] below.
            exprs.append(f"_is_valid_color({var})")
        else:
            type_info = _ULTRA_TYPE_EXPRS.get(type_tok)
            if type_info is None:
                raise TypeError(f'{type_tok!r} is not a supported type for ultra compilation')
            template, ns_additions = type_info
            if ns_additions:
                ns.update(ns_additions)
            exprs.append(template.format(v=var))
    
        for tok in modifiers:
            key, _, val = tok.partition(":")
            key = key.strip()
            val = val.strip() if val else None
    
            if key in ("strict", "nullable", "msg"):
                continue
            # ---- format: for color (replaces the type-check expression) ----
            elif key == "format":
                if _is_color and val:
                    if val == "hex":
                        nm = f"_re_{_counter[0]}"
                        ns[nm] = _HEX_COLOR_RE
                        exprs[0] = f"{nm}.match(str({var}).strip()) is not None"
                    elif val == "rgb":
                        nm = f"_re_{_counter[0]}"
                        ns[nm] = _RGB_COLOR_RE
                        exprs[0] = f"{nm}.match(str({var}).strip()) is not None"
                    elif val == "hsl":
                        nm = f"_re_{_counter[0]}"
                        ns[nm] = _HSL_COLOR_RE
                        exprs[0] = f"{nm}.match(str({var}).strip()) is not None"
                    elif val == "named":
                        nm = f"_nc_{_counter[0]}"
                        ns[nm] = _NAMED_COLORS
                        exprs[0] = f"str({var}).strip().lower() in {nm}"
            # ---- set membership ----
            elif key == "in" and val:
                nm = f"_o{_counter[0]}"
                ns[nm] = frozenset(x.strip() for x in val.split(","))
                exprs.append(f"{var} in {nm}")
            elif key == "not_in" and val:
                nm = f"_e{_counter[0]}"
                ns[nm] = frozenset(x.strip() for x in val.split(","))
                exprs.append(f"{var} not in {nm}")
            # ---- regex ----
            elif key == "re" and val:
                nm = f"_r{_counter[0]}"
                ns[nm] = _re_module.compile(val, _re_module.VERBOSE)
                exprs.append(f"{nm}.match({var}) is not None")
            # ---- prefix / suffix (str and derived; list/tuple use first/last element) ----
            elif key == "starts_with" and val:
                if type_tok in ("list", "tuple"):
                    exprs.append(f"bool({var}) and {var}[0] == {val!r}")
                else:
                    exprs.append(f"str({var}).startswith({val!r})")
            elif key == "ends_with" and val:
                if type_tok in ("list", "tuple"):
                    exprs.append(f"bool({var}) and {var}[-1] == {val!r}")
                else:
                    exprs.append(f"str({var}).endswith({val!r})")
            # ---- contains ----
            elif key == "contains" and val:
                if _is_str_derived:
                    # String types: substring containment (AND semantics —
                    # every comma-separated value must be present, matching
                    # engine.py's validate_contains all(r in s for r in required)).
                    if "," in val:
                        nm = f"_ct{_counter[0]}"
                        ns[nm] = tuple(x.strip() for x in val.split(","))
                        exprs.append(f"all(x in {var} for x in {nm})")
                    else:
                        exprs.append(f"{val!r} in {var}")
                elif _is_container:
                    # Container types: item membership (all must be present)
                    if "," in val:
                        nm = f"_ct{_counter[0]}"
                        ns[nm] = tuple(x.strip() for x in val.split(","))
                        exprs.append(f"all(x in {var} for x in {nm})")
                    else:
                        exprs.append(f"{val!r} in {var}")
            # ---- unique (hashable containers only in ultra path) ----
            elif key == "unique":
                if type_tok in ("list", "tuple", "set"):
                    exprs.append(f"len({var}) == len(set({var}))")
            # ---- range bounds ----
            elif key == "between" and val:
                parts = val.split(",")
                if len(parts) == 2:
                    lo, hi = parts[0].strip(), parts[1].strip()
                    if _is_date:
                        _date_lo = lo
                        _date_hi = hi
                    elif _use_len:
                        exprs.append(f"{lo} <= len({var}) <= {hi}")
                    else:
                        exprs.append(f"{lo} <= {var} <= {hi}")
            elif key in ("min", "max", "length") and val:
                if _is_date:
                    if key == "min":
                        _date_lo = val
                    elif key == "max":
                        _date_hi = val
                    # length does not apply to dates
                elif _use_len:
                    if key == "min":
                        exprs.append(f"len({var}) >= {val}")
                    elif key == "max":
                        exprs.append(f"len({var}) <= {val}")
                    elif key == "length":
                        exprs.append(f"len({var}) == {val}")
                else:
                    if key == "min":
                        exprs.append(f"{var} >= {val}")
                    elif key == "max":
                        exprs.append(f"{var} <= {val}")
    
        # ---- date ranges: replace type check with fused range checker ----
        if _is_date and (_date_lo is not None or _date_hi is not None):
            nm = f"_drc{_counter[0]}"
            ns[nm] = _make_date_range_checker(_date_lo, _date_hi)
            exprs[0] = f"{nm}({var})"
    
        return exprs

    def _emit(d: dict, parent_var: str, indent: str):
        for f, rule in d.items():
            if isinstance(rule, dict):
                var = _new_var()
                lines.append(f"{indent}{var} = {parent_var}[{f!r}]")
                lines.append(f"{indent}if not isinstance({var}, dict): return False")
                _emit(rule, var, indent)
            else:
                tokens = rule.split("|")
                type_tok = tokens[0].strip()
    
                # Detect nullable flag.
                is_nullable = any(t.strip() == "nullable" for t in tokens[1:])
    
                # Separate transform tokens from validator modifiers.
                transform_keys: list[str] = []
                modifier_tokens: list[str] = []
                for tok in tokens[1:]:
                    k, _, _ = tok.partition(":")
                    k = k.strip()
                    if k in _TRANSFORM_MAP:
                        transform_keys.append(k)
                    elif k not in ("nullable", "strict", "msg"):
                        modifier_tokens.append(tok)
    
                # Build a single transform callable if any transforms present.
                transform_nm: str | None = None
                if transform_keys:
                    _fns = [_TRANSFORM_MAP[k] for k in transform_keys]
                    transform_nm = f"_tf{_counter[0]}"
                    ns[transform_nm] = (
                        _fns[0] if len(_fns) == 1 else _chain_transforms(_fns)
                    )
    
                var = _new_var()
                exprs = _build_exprs(var, type_tok, modifier_tokens)
                check = " and ".join(exprs) if exprs else "True"
    
                if is_nullable:
                    if transform_nm:
                        # Nullable + transform: fetch raw, skip if None, else transform+check.
                        raw = f"_raw{var}"
                        lines.append(f"{indent}{raw} = {parent_var}.get({f!r})")
                        lines.append(f"{indent}if {raw} is not None:")
                        lines.append(f"{indent}    {var} = {transform_nm}({raw})")
                        lines.append(f"{indent}    if not ({check}): return False")
                    else:
                        # Nullable, no transform: fetch with .get(), skip if None.
                        lines.append(f"{indent}{var} = {parent_var}.get({f!r})")
                        lines.append(f"{indent}if {var} is not None:")
                        lines.append(f"{indent}    if not ({check}): return False")
                else:
                    if transform_nm:
                        # Required + transform: direct index access, transform, check.
                        lines.append(f"{indent}{var} = {transform_nm}({parent_var}[{f!r}])")
                    else:
                        # Required, no transform: direct index access.
                        lines.append(f"{indent}{var} = {parent_var}[{f!r}]")
                    lines.append(f"{indent}if not ({check}): return False")

    # We are inside the try: block, so use 8 spaces for the body
    _emit(schema, "data", "        ")

    # Guard against empty schemas which would leave `try:` empty
    if len(lines) == 3:
        lines.append("        pass")

    lines.append("    except (KeyError, TypeError): return False")
    lines.append("    return True")

    code = compile("\n".join(lines), "<ultra_dict_validator>", "exec")
    exec(code, ns)
    return ns["_fn"]

# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def validator(rule: str | dict, codegen=True) -> Callable[[Any], bool]:
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

        validate_order = validator({
            'id': 'int',
            'address': {
                'street': 'str|min:3',
                'city': 'str',
                'zip': 'str|re:\\d{5}',
            },
        })
        validate_order({'id': 1, 'address': {'street': '1 Main St', 'city': 'Springfield', 'zip': '12345'}})  # True
        validate_order({'id': 1, 'address': {'street': 'X', 'city': 'Springfield', 'zip': '12345'}})          # False — street too short

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

    cache_key: str = (
        rule if isinstance(rule, str)
        else f"{json.dumps(rule, sort_keys=True)}|codegen={codegen}"
    )

    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    if isinstance(rule, str):
        transform, checks, nullable = _compile_pipe_rule(rule)
        fn: Callable[[Any], bool] = _make_callable(transform, checks, nullable)
    else:
        # Ultra-fused path: if schema is simple, generate one flat function
        if codegen and _is_ultra_simple_schema(rule):
            fn = _ultra_compile_dict(rule)
        else:
            field_specs = _compile_dict_rule(rule, codegen=codegen)
            fn = _make_dict_callable(field_specs, codegen=codegen)  # type: ignore[misc]

    _cache_set(cache_key, fn)
    return fn



# ---------------------------------------------------------------------------
# Ultra-fused complexity budget
# ---------------------------------------------------------------------------

_ULTRA_MAX_TOP_FIELDS:   int = 200
_ULTRA_MAX_NESTED_FIELDS: int = 200
_ULTRA_MAX_TOP_BYTES:    int = 4096
_ULTRA_MAX_NESTED_BYTES: int = 4096

# ---------------------------------------------------------------------------
# Ultra-fused type categories
# ---------------------------------------------------------------------------

_ULTRA_NATIVE_TYPES: frozenset[str] = frozenset({
    "str", "int", "float", "bool", "dict", "list", "set", "tuple",
})

_ULTRA_REGEX_TYPES: dict[str, str] = {
    "url":    "_RE_url",
    "slug":   "_RE_slug",
    "semver": "_RE_semver",
    "phone":  "_RE_phone",
}

_ULTRA_FUNC_TYPES: dict[str, str] = {
    "email": "_tc_email",
    "ip":    "_tc_ip",
    "uuid":  "_tc_uuid",
    "date":  "_tc_date",
    "color": "_tc_color",
    "prime": "_tc_prime",
}

_ULTRA_ARITH_INLINE: dict[str, str] = {
    "even": "isinstance({v}, int) and not isinstance({v}, bool) and {v} % 2 == 0",
    "odd":  "isinstance({v}, int) and not isinstance({v}, bool) and {v} % 2 == 1",
}

_ULTRA_ALL_INLINEABLE_TYPES: frozenset[str] = (
    _ULTRA_NATIVE_TYPES
    | frozenset(_ULTRA_REGEX_TYPES)
    | frozenset(_ULTRA_FUNC_TYPES)
    | frozenset(_ULTRA_ARITH_INLINE)
)

# ---------------------------------------------------------------------------
# Ultra-fused modifier categories
# ---------------------------------------------------------------------------

_ULTRA_TRANSFORM_INLINE: dict[str, str] = {
    "strip":  "{v}.strip()",
    "lstrip": "{v}.lstrip()",
    "rstrip": "{v}.rstrip()",
    "lower":  "{v}.lower()",
    "upper":  "{v}.upper()",
    "title":  "{v}.title()",
}

_ULTRA_RANGE_MODIFIERS: frozenset[str] = frozenset({"min", "max", "between", "length"})

_ULTRA_IGNORED_MODIFIERS: frozenset[str] = frozenset({"msg", "strict"})

_ULTRA_UNSUPPORTED_MODIFIERS: frozenset[str] = frozenset({
    "unique", "format", "region", "of",
})

_ULTRA_PATTERN_MODIFIERS: frozenset[str] = frozenset({
    "in", "not_in", "contains", "starts_with", "ends_with", "re"
})

_ULTRA_LEN_TYPES: frozenset[str] = frozenset({
    "str", "email", "url", "uuid", "ip", "slug", "semver",
    "phone", "date", "color", "list", "dict", "set", "tuple",
})

_ULTRA_REGEX_FAST_REJECT: dict[str, str] = {
    "email":  "'@' in {v}",
    "url":    "':' in {v}",
    "phone":  "{v}.startswith('+')",
    "semver": "{v}.count('.') >= 2",
}


# ---------------------------------------------------------------------------
# Ultra-fused eligibility check
# ---------------------------------------------------------------------------

def _is_ultra_simple_schema(
    schema: dict,
    *,
    _depth: int = 0,
    _max_fields: int = _ULTRA_MAX_TOP_FIELDS,
    _max_bytes: int = _ULTRA_MAX_TOP_BYTES,
) -> bool:
    """Return True when every rule in *schema* can be ultra-fused."""

    if not isinstance(schema, dict):
        return False

    if len(schema) > _max_fields:
        return False

    try:
        if len(json.dumps(schema, separators=(",", ":"))) > _max_bytes:
            return False
    except (TypeError, ValueError):
        return False

    nested_max_fields = _ULTRA_MAX_NESTED_FIELDS
    nested_max_bytes  = _ULTRA_MAX_NESTED_BYTES

    for rule in schema.values():
        if isinstance(rule, dict):
            if not _is_ultra_simple_schema(
                rule,
                _depth=_depth + 1,
                _max_fields=nested_max_fields,
                _max_bytes=nested_max_bytes,
            ):
                return False
            continue

        if not isinstance(rule, str):
            return False

        tokens = rule.split("|")
        type_tok = tokens[0].strip()

        # Determine valid modifiers based on type using .union() for type safety
        m = _PARAMETERIZED_RE.match(type_tok)
        if m:
            outer = m.group(1)
            inner = m.group(2).strip()
            if outer not in ("list", "tuple", "set") or inner not in ("str", "int", "float", "bool"):
                return False
            valid_modifiers = _ULTRA_RANGE_MODIFIERS.union(
                _ULTRA_IGNORED_MODIFIERS, {"nullable", "contains", "starts_with", "ends_with"}
            )
        elif type_tok in _ULTRA_NATIVE_TYPES:
            if type_tok == "str":
                valid_modifiers = _ULTRA_RANGE_MODIFIERS.union(
                    _ULTRA_TRANSFORM_INLINE, _ULTRA_IGNORED_MODIFIERS, {"nullable"}, _ULTRA_PATTERN_MODIFIERS
                )
            elif type_tok in ("int", "float", "bool"):
                valid_modifiers = _ULTRA_RANGE_MODIFIERS.union(
                    _ULTRA_IGNORED_MODIFIERS, {"nullable", "in", "not_in", "re"}
                )
            elif type_tok in ("list", "tuple"):
                valid_modifiers = _ULTRA_RANGE_MODIFIERS.union(
                    _ULTRA_IGNORED_MODIFIERS, {"nullable", "contains", "starts_with", "ends_with"}
                )
            elif type_tok in ("set", "dict"):
                valid_modifiers = _ULTRA_RANGE_MODIFIERS.union(
                    _ULTRA_IGNORED_MODIFIERS, {"nullable", "contains"}
                )
        elif type_tok in _ULTRA_REGEX_TYPES or type_tok in _ULTRA_FUNC_TYPES:
            # String-based extended types (email, url, uuid, ip, color, etc.)
            valid_modifiers = _ULTRA_RANGE_MODIFIERS.union(
                _ULTRA_TRANSFORM_INLINE, _ULTRA_IGNORED_MODIFIERS, {"nullable"}, _ULTRA_PATTERN_MODIFIERS
            )
        elif type_tok in _ULTRA_ARITH_INLINE:
            # even, odd
            valid_modifiers = _ULTRA_RANGE_MODIFIERS.union(
                _ULTRA_IGNORED_MODIFIERS, {"nullable", "in", "not_in", "re"}
            )
        else:
            return False

        for tok in tokens[1:]:
            key = tok.split(":")[0].strip()
            if key in _ULTRA_UNSUPPORTED_MODIFIERS:
                return False

            if key not in valid_modifiers:
                return False

    return True

# ---------------------------------------------------------------------------
# Ultra-fused per-rule compiler
# ---------------------------------------------------------------------------

def _ultra_compile_rule_exprs(
    type_tok: str,
    modifier_tokens: list[str],
    var: str,
    idx: int,
) -> tuple[bool, str | None, list[str], dict[str, Any]]:
    """Parse modifier tokens and return (nullable, transform_expr, [bool_exprs], ns_vars)."""
    nullable = False
    transforms = []
    min_val = max_val = between_lo = between_hi = length_val = None
    in_vals = not_in_vals = contains_vals = starts_with_val = ends_with_val = re_val = None
    date_lo = date_hi = None
    _is_date = type_tok == "date"

    ns_vars: dict[str, Any] = {}

    for tok in modifier_tokens:
        key, _, val = tok.partition(":")
        key = key.strip()
        val = val.strip() if val else None

        if key == "nullable":
            nullable = True
        elif key in _ULTRA_TRANSFORM_INLINE:
            transforms.append(_ULTRA_TRANSFORM_INLINE[key])
        elif key == "min":
            if _is_date:
                date_lo = val
            else:
                min_val = val
        elif key == "max":
            if _is_date:
                date_hi = val
            else:
                max_val = val
        elif key == "between":
            if val:
                parts = val.split(",", 1)
                if len(parts) == 2:
                    if _is_date:
                        date_lo, date_hi = parts[0].strip(), parts[1].strip()
                    else:
                        between_lo, between_hi = parts[0].strip(), parts[1].strip()
        elif key == "length":
            length_val = val
        elif key == "in":
            in_vals = val
        elif key == "not_in":
            not_in_vals = val
        elif key == "contains":
            contains_vals = val
        elif key == "starts_with":
            starts_with_val = val
        elif key == "ends_with":
            ends_with_val = val
        elif key == "re":
            re_val = val

    transform_expr: str | None = None
    if transforms:
        expr = var
        for tmpl in transforms:
            expr = tmpl.replace("{v}", expr)
        transform_expr = expr

    chk = transform_expr if transform_expr else var

    # --- Type Expression ---
    _container_scan_expr: str | None = None
    if type_tok in _ULTRA_NATIVE_TYPES:
        type_expr = f"isinstance({chk}, {type_tok})"
    elif type_tok.startswith(('list[', 'tuple[', 'set[')):
        outer = type_tok.split('[')[0]
        inner = type_tok[:-1].split('[')[1].strip()
        if inner == 'int':
            inner_expr = "isinstance(i, int) and not isinstance(i, bool)"
        else:
            inner_expr = f"isinstance(i, {inner})"
        # Cheap isinstance() guard goes in type_expr (must run before any
        # len()/range check below, which assumes a real container). The
        # expensive O(n) item-type scan is kept separate so it can be placed
        # after the cheap length/between checks instead of always running first.
        type_expr = f"isinstance({chk}, {outer})"
        _container_scan_expr = f"all({inner_expr} for i in {chk})"
    elif type_tok in _ULTRA_REGEX_TYPES:
        ns_key = _ULTRA_REGEX_TYPES[type_tok]
        # Coerce to str the same way the regular (non-ultra) path does via
        # _TYPE_CHECK / _tc_phone_e164 — str(v), not isinstance(v, str).
        # This also makes the fast-reject substring checks below safe to run
        # (they assume a string operand) instead of raising TypeError on a
        # non-string input.
        str_expr = f"str({chk}).strip()" if type_tok == "phone" else f"str({chk})"
        fast_reject = _ULTRA_REGEX_FAST_REJECT.get(type_tok)
        if fast_reject:
            sv = f"_sv_{idx}"
            # Walrus binds the coerced string once; reused in the match call
            # without recomputing str(...)/.strip() a second time.
            type_expr = (
                f"{fast_reject.format(v=f'({sv} := {str_expr})')} and "
                f"{ns_key}.match({sv}) is not None"
            )
        else:
            type_expr = f"{ns_key}.match({str_expr}) is not None"
    elif type_tok in _ULTRA_FUNC_TYPES:
        ns_key = _ULTRA_FUNC_TYPES[type_tok]
        type_expr = f"{ns_key}({chk})"
    else:
        type_expr = _ULTRA_ARITH_INLINE[type_tok].replace("{v}", chk)

    bool_exprs: list[str] = [type_expr]

    if _is_date and (date_lo is not None or date_hi is not None):
        nm = f"_drc_{idx}"
        ns_vars[nm] = _make_date_range_checker(date_lo, date_hi)
        bool_exprs[0] = f"{nm}({chk})"
    else:
        use_len = type_tok in _ULTRA_LEN_TYPES or type_tok.startswith(('list[', 'tuple[', 'set['))

        # --- Range Expressions ---
        if between_lo is not None and between_hi is not None:
            if use_len:
                bool_exprs.append(f"{between_lo} <= len({chk}) <= {between_hi}")
            else:
                bool_exprs.append(f"{between_lo} <= {chk} <= {between_hi}")
        else:
            if min_val is not None:
                if use_len:
                    bool_exprs.append(f"len({chk}) >= {min_val}")
                else:
                    bool_exprs.append(f"{chk} >= {min_val}")
            if max_val is not None:
                if use_len:
                    bool_exprs.append(f"len({chk}) <= {max_val}")
                else:
                    bool_exprs.append(f"{chk} <= {max_val}")

    if length_val is not None:
        bool_exprs.append(f"len({chk}) == {length_val}")

    if _container_scan_expr is not None:
        bool_exprs.append(_container_scan_expr)

    # --- Pattern Expressions ---
    is_seq = type_tok in ("list", "tuple") or type_tok.startswith(('list[', 'tuple['))

    # starts_with / ends_with
    # NOTE: for list/tuple, engine.py's validate_startswith/validate_endswith
    # compare only the first/last *element* against the single literal value
    # (bool(value) and value[0] == prefix) — there is no multi-element/slice
    # matching in the original validator, so we must not comma-split here.
    if starts_with_val is not None:
        ns_name = f"_sw_{idx}"
        val = starts_with_val
        if is_seq:
            if type_tok.startswith('list[int') or type_tok.startswith('tuple[int'):
                val = int(val)
            elif type_tok.startswith('list[float') or type_tok.startswith('tuple[float'):
                val = float(val)
        ns_vars[ns_name] = val
        if is_seq:
            bool_exprs.append(f"bool({chk}) and {chk}[0] == {ns_name}")
        else:
            bool_exprs.append(f"str({chk}).startswith({ns_name})")

    if ends_with_val is not None:
        ns_name = f"_ew_{idx}"
        val = ends_with_val
        if is_seq:
            if type_tok.startswith('list[int') or type_tok.startswith('tuple[int'):
                val = int(val)
            elif type_tok.startswith('list[float') or type_tok.startswith('tuple[float'):
                val = float(val)
        ns_vars[ns_name] = val
        if is_seq:
            bool_exprs.append(f"bool({chk}) and {chk}[-1] == {ns_name}")
        else:
            bool_exprs.append(f"str({chk}).endswith({ns_name})")

    # in / not_in (scalars only)
    if in_vals is not None:
        ns_name = f"_in_{idx}"
        tokens = [t.strip() for t in in_vals.split(',')]
        if type_tok == 'int' or type_tok in _ULTRA_ARITH_INLINE:
            ns_vars[ns_name] = frozenset(int(t) for t in tokens)
        elif type_tok == 'float':
            ns_vars[ns_name] = frozenset(float(t) for t in tokens)
        else:  # str and string-based
            ns_vars[ns_name] = frozenset(tokens)
        bool_exprs.append(f"{chk} in {ns_name}")

    if not_in_vals is not None:
        ns_name = f"_nin_{idx}"
        tokens = [t.strip() for t in not_in_vals.split(',')]
        if type_tok == 'int' or type_tok in _ULTRA_ARITH_INLINE:
            ns_vars[ns_name] = frozenset(int(t) for t in tokens)
        elif type_tok == 'float':
            ns_vars[ns_name] = frozenset(float(t) for t in tokens)
        else:
            ns_vars[ns_name] = frozenset(tokens)
        bool_exprs.append(f"{chk} not in {ns_name}")

    # contains
    if contains_vals is not None:
        ns_name = f"_ct_{idx}"
        if ',' in contains_vals:
            items = tuple(t.strip() for t in contains_vals.split(','))
            if type_tok.startswith('list[int') or type_tok.startswith('tuple[int') or type_tok.startswith('set[int'):
                items = tuple(int(t) for t in items)
            elif type_tok.startswith('list[float') or type_tok.startswith('tuple[float') or type_tok.startswith('set[float'):
                items = tuple(float(t) for t in items)
            ns_vars[ns_name] = items
            bool_exprs.append(f"all(_x in {chk} for _x in {ns_name})")
        else:
            item = contains_vals
            if type_tok.startswith('list[int') or type_tok.startswith('tuple[int') or type_tok.startswith('set[int'):
                item = int(item)
            elif type_tok.startswith('list[float') or type_tok.startswith('tuple[float') or type_tok.startswith('set[float'):
                item = float(item)
            ns_vars[ns_name] = item
            bool_exprs.append(f"{ns_name} in {chk}")

    # re (regex match)
    if re_val is not None:
        ns_name = f"_re_{idx}"
        # Compile at codegen time for maximum runtime speed
        ns_vars[ns_name] = re.compile(re_val, re.VERBOSE)
        bool_exprs.append(f"{ns_name}.match({chk}) is not None")

    return nullable, transform_expr, bool_exprs, ns_vars

# ---------------------------------------------------------------------------
# Ultra-fused code emitter
# ---------------------------------------------------------------------------

def _ultra_emit_checks(
    schema: dict,
    lines: list[str],
    indent: str,
    data_var: str,
    *,
    _counter: list[int],
    ns: dict[str, Any],
) -> None:
    """Append ultra-fused field-check lines for *schema* into *lines*.

    Any compile-time namespace values produced for a field (compiled regexes,
    frozensets for in:/not_in:, the date-range checker, etc.) are merged into
    *ns* so they're available in the exec() namespace at call time.
    """
    for field, rule in schema.items():
        idx = _counter[0]
        _counter[0] += 1
        safe_field = repr(field)

        if isinstance(rule, dict):
            sub_var = f"_s{idx}"
            lines.append(f"{indent}{sub_var} = {data_var}[{safe_field}]")
            lines.append(f"{indent}if not isinstance({sub_var}, dict): return False")
            _ultra_emit_checks(rule, lines, indent, sub_var, _counter=_counter, ns=ns)
            continue

        var = f"_v{idx}"
        tokens = rule.split("|")
        type_tok = tokens[0].strip()

        nullable, transform_expr, bool_exprs, ns_vars = _ultra_compile_rule_exprs(
            type_tok, tokens[1:], var, idx
        )
        if ns_vars:
            ns.update(ns_vars)

        if nullable:
            lines.append(f"{indent}{var} = {data_var}.get({safe_field})")
            lines.append(f"{indent}if {var} is not None:")
            inner = indent + "    "
            if transform_expr:
                tmp = f"_t{idx}"
                lines.append(f"{inner}{tmp} = {transform_expr} if isinstance({var}, str) else {var}")
                patched = [e.replace(transform_expr, tmp) for e in bool_exprs]
                combined = " and ".join(patched)
            else:
                combined = " and ".join(bool_exprs)
            lines.append(f"{inner}if not ({combined}): return False")
        else:
            if transform_expr:
                tmp = f"_t{idx}"
                lines.append(f"{indent}{var} = {data_var}[{safe_field}]")
                lines.append(f"{indent}{tmp} = {transform_expr} if isinstance({var}, str) else {var}")
                patched = [e.replace(transform_expr, tmp) for e in bool_exprs]
                combined = " and ".join(patched)
                lines.append(f"{indent}if not ({combined}): return False")
            else:
                uses = sum(expr.count(var) for expr in bool_exprs)
                if uses == 1:
                    fused_exprs = [e.replace(var, f"{data_var}[{safe_field}]", 1) for e in bool_exprs]
                    combined = " and ".join(fused_exprs)
                    lines.append(f"{indent}if not ({combined}): return False")
                else:
                    lines.append(f"{indent}{var} = {data_var}[{safe_field}]")
                    combined = " and ".join(bool_exprs)
                    lines.append(f"{indent}if not ({combined}): return False")


def _make_date_range_checker(
    lo: str | None,
    hi: str | None,
) -> Callable[[Any], bool]:
    """Create an inlined date validator with pre-parsed bounds.
    
    Parses bounds once at compile time; at call time parses the value
    once and compares. Returns False for any non-date input.
    """
    from datetime import datetime as _dt
    
    _lo_dt: _dt | None = parse_date(lo) if lo is not None else None
    _hi_dt: _dt | None = parse_date(hi) if hi is not None else None
    
    if _lo_dt is not None and _hi_dt is not None:
        def _check(v: Any, __lo=_lo_dt, __hi=_hi_dt) -> bool:
            if isinstance(v, _dt):
                dt = v
            else:
                try:
                    dt = parse_date(v)
                    if not isinstance(dt, _dt):
                        return False
                except Exception:
                    return False
            return __lo <= dt <= __hi
    elif _lo_dt is not None:
        def _check(v: Any, __lo=_lo_dt) -> bool:
            if isinstance(v, _dt):
                dt = v
            else:
                try:
                    dt = parse_date(v)
                    if not isinstance(dt, _dt):
                        return False
                except Exception:
                    return False
            return dt >= __lo
    else:  # _hi_dt is not None
        def _check(v: Any, __hi=_hi_dt) -> bool:
            if isinstance(v, _dt):
                dt = v
            else:
                try:
                    dt = parse_date(v)
                    if not isinstance(dt, _dt):
                        return False
                except Exception:
                    return False
            return dt <= __hi
    
    return _check

# ---------------------------------------------------------------------------
# Ultra-fused function factory
# ---------------------------------------------------------------------------

def _make_ultra_fused_validator(schema: dict) -> Callable[[Any], bool]:
    """Emit, compile, and exec a fully inlined dict-validator for *schema*."""
    lines: list[str] = [
        "def _ultra_fn(data):",
        "    if not isinstance(data, dict): return False",
        "    try:",
    ]
    ns: dict[str, Any] = {}
    _ultra_emit_checks(schema, lines, indent="        ", data_var="data", _counter=[0], ns=ns)
    lines.append("        return True")
    lines.append("    except KeyError: return False")

    source = "\n".join(lines)

    used_types: set[str] = set()
    def _collect_types(s: dict) -> None:
        for rule in s.values():
            if isinstance(rule, dict):
                _collect_types(rule)
            elif isinstance(rule, str):
                used_types.add(rule.split("|")[0].strip())
    _collect_types(schema)

    if used_types & frozenset(_ULTRA_REGEX_TYPES):
        _regex_map = {
            "_RE_url":    _URL_RE,
            "_RE_slug":   _SLUG_RE,
            "_RE_semver": _SEMVER_RE,
            "_RE_phone":  _PHONE_E164_RE,
        }
        for type_name, ns_key in _ULTRA_REGEX_TYPES.items():
            if type_name in used_types:
                ns[ns_key] = _regex_map[ns_key]

    if used_types & frozenset(_ULTRA_FUNC_TYPES):
        _func_map = {
            "_tc_email": _tc_email,
            "_tc_ip":    _tc_ip,
            "_tc_uuid":  _tc_uuid,
            "_tc_date":  _tc_date,
            "_tc_color": _is_valid_color,
            "_tc_prime": _is_prime,
        }
        for type_name, ns_key in _ULTRA_FUNC_TYPES.items():
            if type_name in used_types:
                ns[ns_key] = _func_map[ns_key]

    exec(compile(source, f"<ultra_fused_n={len(schema)}>", "exec"), ns)  # noqa: S102
    fn = ns["_ultra_fn"]
    return fn


# ---------------------------------------------------------------------------
# Public entry point — fast_validator()
# ---------------------------------------------------------------------------

def fast_validator(
    schema: dict,
    *,
    codegen: bool = True,
    compile_timeout: float = 0.5,
) -> Callable[[Any], bool]:
    """Return the fastest available validator for *schema*.

    When ``codegen=True`` (default), the ultra-fused path is attempted first:
    a fully inlined function is emitted via ``exec`` with no loop overhead.
    If the schema is not ultra-eligible or compilation exceeds
    ``compile_timeout``, the regular codegen path (``validator(schema,
    codegen=True)``) is used as the first fallback.

    When ``codegen=False``, the ultra-fused path is skipped entirely and the
    interpreter-loop path (``validator(schema, codegen=False)``) is used
    directly — zero compile overhead, easier to debug, picklable.

    Parameters
    ----------
    schema:
        A dict mapping field names to pipe-rule strings or nested dicts.
    codegen:
        When True (default), prefer the ultra-fused emitted function and fall
        back to the regular codegen path only when necessary.
        When False, skip all codegen and use the loop-based validator.
    compile_timeout:
        Wall-clock seconds budget for ultra-fuse compilation (default 500 ms).
        Only consulted when ``codegen=True``.

    Returns
    -------
    Callable[[Any], bool]
        A single-argument callable: returns True when input is valid.
    """
    if not isinstance(schema, dict):
        raise TypeError(
            f"fast_validator expects a dict schema, got {type(schema).__name__!r}"
        )

    if codegen:
        start = time.perf_counter()
        try:
            if _is_ultra_simple_schema(schema):
                fn = _make_ultra_fused_validator(schema)
                if (time.perf_counter() - start) <= compile_timeout:
                    return fn
        except Exception:
            pass
        # Ultra-fused path was ineligible or timed out — fall back to regular codegen.
        return validator(schema, codegen=codegen)

    # codegen=False: skip all emit/exec work, use the plain loop path.
    return validator(schema, codegen=codegen)

from __future__ import annotations

import ipaddress
import json
import logging
import re
import uuid as uuid_lib

from ast import literal_eval
from collections import OrderedDict
from contextvars import ContextVar
from dataclasses import dataclass, field as dc_field
from datetime import datetime
from dateutil.parser import parse as parse_date
from types import SimpleNamespace
from typing import Any, NamedTuple

from .messages import error_messages as errm


# ---------------------------------------------------------------------------
# Public exception
# ---------------------------------------------------------------------------

class ValidationError(Exception):
    pass


# ---------------------------------------------------------------------------
# Nesting limit
# ---------------------------------------------------------------------------

MAX_NESTING_DEPTH = 100


# ---------------------------------------------------------------------------
# Regex constants (type checking)
# ---------------------------------------------------------------------------

_URL_RE = re.compile(
    r'^(https?|ftp)://'
    r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'
    r'localhost|'
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
    r'(?::\d+)?'
    r'(?:/?|[/?]\S+)$',
    re.IGNORECASE,
)

_SLUG_RE = re.compile(r'^[a-z0-9]+(?:-[a-z0-9]+)*$')

_SEMVER_RE = re.compile(
    r'^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)'
    r'(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?'
    r'(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$'
)

_PHONE_E164_RE = re.compile(r'^\+[1-9]\d{6,14}$')

_HEX_COLOR_RE = re.compile(r'^#([A-Fa-f0-9]{3}|[A-Fa-f0-9]{6})$')

_RGB_COLOR_RE = re.compile(
    r'^rgb\(\s*(25[0-5]|2[0-4]\d|[01]?\d\d?)\s*,'
    r'\s*(25[0-5]|2[0-4]\d|[01]?\d\d?)\s*,'
    r'\s*(25[0-5]|2[0-4]\d|[01]?\d\d?)\s*\)$'
)

_HSL_COLOR_RE = re.compile(
    r'^hsl\(\s*(360|3[0-5]\d|[12]\d\d|[1-9]\d|\d)\s*,'
    r'\s*(100|[1-9]\d|\d)%\s*,'
    r'\s*(100|[1-9]\d|\d)%\s*\)$'
)

_NAMED_COLORS = {
    'aliceblue', 'antiquewhite', 'aqua', 'aquamarine', 'azure', 'beige',
    'bisque', 'black', 'blanchedalmond', 'blue', 'blueviolet', 'brown',
    'burlywood', 'cadetblue', 'chartreuse', 'chocolate', 'coral',
    'cornflowerblue', 'cornsilk', 'crimson', 'cyan', 'darkblue', 'darkcyan',
    'darkgoldenrod', 'darkgray', 'darkgreen', 'darkgrey', 'darkkhaki',
    'darkmagenta', 'darkolivegreen', 'darkorange', 'darkorchid', 'darkred',
    'darksalmon', 'darkseagreen', 'darkslateblue', 'darkslategray',
    'darkslategrey', 'darkturquoise', 'darkviolet', 'deeppink', 'deepskyblue',
    'dimgray', 'dimgrey', 'dodgerblue', 'firebrick', 'floralwhite',
    'forestgreen', 'fuchsia', 'gainsboro', 'ghostwhite', 'gold', 'goldenrod',
    'gray', 'green', 'greenyellow', 'grey', 'honeydew', 'hotpink',
    'indianred', 'indigo', 'ivory', 'khaki', 'lavender', 'lavenderblush',
    'lawngreen', 'lemonchiffon', 'lightblue', 'lightcoral', 'lightcyan',
    'lightgoldenrodyellow', 'lightgray', 'lightgreen', 'lightgrey',
    'lightpink', 'lightsalmon', 'lightseagreen', 'lightskyblue',
    'lightslategray', 'lightslategrey', 'lightsteelblue', 'lightyellow',
    'lime', 'limegreen', 'linen', 'magenta', 'maroon', 'mediumaquamarine',
    'mediumblue', 'mediumorchid', 'mediumpurple', 'mediumseagreen',
    'mediumslateblue', 'mediumspringgreen', 'mediumturquoise',
    'mediumvioletred', 'midnightblue', 'mintcream', 'mistyrose', 'moccasin',
    'navajowhite', 'navy', 'oldlace', 'olive', 'olivedrab', 'orange',
    'orangered', 'orchid', 'palegoldenrod', 'palegreen', 'paleturquoise',
    'palevioletred', 'papayawhip', 'peachpuff', 'peru', 'pink', 'plum',
    'powderblue', 'purple', 'red', 'rosybrown', 'royalblue', 'saddlebrown',
    'salmon', 'sandybrown', 'seagreen', 'seashell', 'sienna', 'silver',
    'skyblue', 'slateblue', 'slategray', 'slategrey', 'snow', 'springgreen',
    'steelblue', 'tan', 'teal', 'thistle', 'tomato', 'turquoise', 'violet',
    'wheat', 'white', 'whitesmoke', 'yellow', 'yellowgreen',
}


# ---------------------------------------------------------------------------
# Helper functions for specialised type checks
# ---------------------------------------------------------------------------

def _is_prime(n: Any) -> bool:
    try:
        n = int(n)
    except (ValueError, TypeError):
        return False
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    for i in range(3, int(n ** 0.5) + 1, 2):
        if n % i == 0:
            return False
    return True


def _is_valid_color(value: Any, fmt: str | None = None) -> bool:
    s = str(value).strip()
    if fmt == 'hex':
        return bool(_HEX_COLOR_RE.match(s))
    if fmt == 'rgb':
        return bool(_RGB_COLOR_RE.match(s))
    if fmt == 'hsl':
        return bool(_HSL_COLOR_RE.match(s))
    if fmt == 'named':
        return s.lower() in _NAMED_COLORS
    return (
        bool(_HEX_COLOR_RE.match(s))
        or bool(_RGB_COLOR_RE.match(s))
        or bool(_HSL_COLOR_RE.match(s))
        or s.lower() in _NAMED_COLORS
    )


def _has_nested_rules(rules: Any) -> bool:
    """Detect whether any rules contain nested field definitions (canonical form only)."""
    if isinstance(rules, list):
        return any(_has_nested_rules(r) for r in rules if isinstance(r, dict))
    if isinstance(rules, dict):
        if 'fields' in rules or 'items' in rules:
            return True
        return any(_has_nested_rules(v) for v in rules.values() if isinstance(v, dict))
    return False


# ---------------------------------------------------------------------------
# Module-level regex constants
# ---------------------------------------------------------------------------

_EMAIL_RE = re.compile(
    r"""^(([^<>()\[\]\\.,;:\s@\"]+(\.[^<>()\[\]\\.,;:\s@\"]+)*)|(\".+\"))
        @((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])
        |(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$""",
    re.VERBOSE,
)

# User regex cache: pattern string -> compiled Pattern
_EXPRESSION_CACHE: dict[str, re.Pattern] = {}

# Type sets used in error key and length dispatch
_BASIC_TYPES: frozenset[str] = frozenset({
    'bool', 'color', 'date', 'email', 'even', 'float', 'int', 'ip',
    'odd', 'phone', 'prime', 'semver', 'slug', 'str', 'url', 'uuid',
})
_BASIC_TYPES_PLUS_REGEX: frozenset[str] = _BASIC_TYPES | frozenset({'regex'})

_NATIVE_NAMES: frozenset[str] = frozenset({'bool', 'float', 'int', 'str', 'dict', 'list', 'set', 'tuple'})
_NATIVE_MAP: dict[str, type] = {
    'bool': bool, 'float': float, 'int': int, 'str': str,
    'dict': dict, 'list': list, 'set': set, 'tuple': tuple,
}


# ---------------------------------------------------------------------------
# Type spec — carries all type-checking context as a single immutable arg
# ---------------------------------------------------------------------------

class TypeSpec(NamedTuple):
    name: str
    strict: bool = True
    fmt: str | None = None
    region: str | None = None
    cls: Any = None


# ---------------------------------------------------------------------------
# Per-call context stored in a ContextVar for async safety
# ---------------------------------------------------------------------------

@dataclass
class _CallContext:
    errors: list = dc_field(default_factory=list)
    group_errors: bool = True
    nested: bool = False
    mutate: bool = False
    raise_exceptions: bool = False
    log_errors: bool = False
    full_data: dict = dc_field(default_factory=dict)
    transformed_data: list = dc_field(default_factory=list)

    def begin_field(self) -> None:
        """Open a new error bucket for one top-level field (non-nested grouped mode only)."""
        if not self.nested and self.group_errors:
            self.errors.append([])

    def add_error(self, path: str, message: str) -> None:
        if self.nested:
            prefix = f'{path}: ' if path else ''
            self.errors.append(f'{prefix}{message}')
        else:
            if self.group_errors:
                self.errors[-1].append(message)
            else:
                self.errors.append(message)
        if self.raise_exceptions:
            raise ValidationError(message)

    @property
    def ok(self) -> bool:
        if self.nested:
            return len(self.errors) == 0
        return len(self.errors) == 0 or all(x == [] for x in self.errors)


_ctx_var: ContextVar[_CallContext] = ContextVar('validatedata_ctx')


# ---------------------------------------------------------------------------
# Phone validation (with region bug fixed)
# ---------------------------------------------------------------------------

def _check_phone(value: Any, fmt: str | None, region: str | None) -> bool:
    s = str(value).strip()
    if fmt is None or fmt == 'e164':
        return bool(_PHONE_E164_RE.match(s))
    try:
        import phonenumbers
        try:
            parsed = phonenumbers.parse(s, region)   # region fix: was hardcoded None
            return phonenumbers.is_valid_number(parsed)
        except Exception:
            return False
    except ImportError:
        raise ImportError(
            f"Phone format '{fmt}' requires the phonenumbers package. "
            "Install it with: pip install phonenumbers"
        )


# ---------------------------------------------------------------------------
# Pure validator functions
# Each takes exactly (value, arg) and returns bool.
# These have no side effects and no instance state.
# ---------------------------------------------------------------------------

def check_type(value: Any, spec: TypeSpec) -> bool:
    name = spec.name

    if name in _NATIVE_NAMES:
        expected = _NATIVE_MAP[name]
        if not spec.strict:
            try:
                coerced = literal_eval(str(value))
                return isinstance(coerced, expected)
            except (TypeError, ValueError):
                return False
        return isinstance(value, expected)

    if name == 'date':
        if isinstance(value, datetime):
            return True
        try:
            return isinstance(parse_date(value), datetime)
        except Exception:
            return False

    if name == 'email':
        return _EMAIL_RE.match(str(value)) is not None

    if name == 'even':
        try:
            return isinstance(value, int) and not isinstance(value, bool) and value % 2 == 0
        except Exception:
            return False

    if name == 'odd':
        try:
            return isinstance(value, int) and not isinstance(value, bool) and value % 2 == 1
        except Exception:
            return False

    if name == 'prime':
        return _is_prime(value)

    if name == 'url':
        return _URL_RE.match(str(value)) is not None

    if name == 'ip':
        try:
            ipaddress.ip_address(str(value))
            return True
        except ValueError:
            return False

    if name == 'uuid':
        try:
            uuid_lib.UUID(str(value))
            return True
        except ValueError:
            return False

    if name == 'slug':
        return _SLUG_RE.match(str(value)) is not None

    if name == 'semver':
        return _SEMVER_RE.match(str(value)) is not None

    if name == 'color':
        return _is_valid_color(value, spec.fmt)

    if name == 'phone':
        return _check_phone(value, spec.fmt, spec.region)

    if name in ('object', 'annotation'):
        return isinstance(value, spec.cls) if spec.cls is not None else False

    if name == 'regex':
        return isinstance(value, str)

    return False


def validate_range(value: Any, bounds: tuple) -> bool:
    min_val, max_val = bounds

    # Both bounds 'any' — always valid regardless of type.
    if min_val == 'any' and max_val == 'any':
        return True

    # Date range — bounds are pre-parsed to datetime in _build_range_arg, or
    # the value itself may be a datetime object with one 'any' bound.
    lo_is_dt = isinstance(min_val, datetime)
    hi_is_dt = isinstance(max_val, datetime)
    if lo_is_dt or hi_is_dt or isinstance(value, datetime):
        try:
            cast = value if isinstance(value, datetime) else parse_date(value)
        except Exception:
            return False
        lo = cast if min_val == 'any' else min_val
        hi = cast if max_val == 'any' else max_val
        return lo <= cast <= hi

    if isinstance(value, str):
        lo = 0 if min_val == 'any' else int(min_val)
        hi = float('inf') if max_val == 'any' else int(max_val)
        return lo <= len(value) <= hi

    if isinstance(value, (list, tuple)):
        lo = 0 if min_val == 'any' else int(min_val)
        hi = float('inf') if max_val == 'any' else int(max_val)
        return lo <= len(value) <= hi

    # numeric (int, float, even, odd) — already validated by check_type
    lo = float('-inf') if min_val == 'any' else float(min_val)
    hi = float('inf') if max_val == 'any' else float(max_val)
    return lo <= float(value) <= hi


def validate_length(value: Any, length: int) -> bool:
    # basic types use string representation; others use __len__
    if isinstance(value, str):
        return len(value) == length
    if hasattr(value, '__len__'):
        return len(value) == length
    try:
        return len(str(value)) == length
    except Exception:
        return False


def validate_contains(value: Any, required: Any) -> bool:
    if isinstance(required, str):
        if isinstance(value, dict):
            return required in value
        if isinstance(value, (list, tuple, set)):
            return required in set(value)
        return required in str(value)
    # list/tuple of required values
    if isinstance(value, dict):
        return all(r in value for r in required)
    if isinstance(value, (list, tuple, set)):
        value_set = set(value)
        return all(r in value_set for r in required)
    s = str(value)
    return all(r in s for r in required)


def validate_excludes(value: Any, forbidden: frozenset) -> bool:
    if isinstance(value, (list, tuple, set, dict)):
        return not any(v in forbidden for v in value)
    return value not in forbidden


def validate_options(value: Any, options: frozenset) -> bool:
    if isinstance(value, (list, tuple, set)):
        return all(v in options for v in value)
    return value in options


def validate_expression(value: Any, pattern: str) -> bool:
    if pattern not in _EXPRESSION_CACHE:
        try:
            _EXPRESSION_CACHE[pattern] = re.compile(pattern, re.VERBOSE)
        except Exception as ex:
            raise ValidationError(f'error compiling regex: {ex}')
    return _EXPRESSION_CACHE[pattern].match(str(value)) is not None


def validate_startswith(value: Any, prefix: str) -> bool:
    if isinstance(value, (list, tuple)):
        return bool(value) and value[0] == prefix
    return str(value).startswith(prefix)


def validate_endswith(value: Any, suffix: str) -> bool:
    if isinstance(value, (list, tuple)):
        return bool(value) and value[-1] == suffix
    return str(value).endswith(suffix)


def validate_unique(value: Any, _: None) -> bool:
    if isinstance(value, (list, tuple, set)):
        try:
            return len(value) == len(set(value))
        except TypeError:
            # unhashable elements — fall back to O(n²)
            seen = []
            for item in value:
                if item in seen:
                    return False
                seen.append(item)
    return True


# ---------------------------------------------------------------------------
# Function ordering — THE single source of truth.
# The order of entries here determines the positional contract between
# compiled tuples and args tuples. Never duplicate this ordering elsewhere.
# ---------------------------------------------------------------------------

_FN_ORDER: list[tuple[str, Any]] = [
    ('range',      validate_range),
    ('length',     validate_length),
    ('contains',   validate_contains),
    ('excludes',   validate_excludes),
    ('options',    validate_options),
    ('expression', validate_expression),
    ('startswith', validate_startswith),
    ('endswith',   validate_endswith),
    ('unique',     validate_unique),
]

# Rule key -> function, for error key resolution
_FN_TO_RULE_KEY: dict[Any, str] = {fn: k for k, fn in _FN_ORDER}


# ---------------------------------------------------------------------------
# Compiled function tuple cache
# Maps shape key (type + present validator names, no values) -> fn tuple.
# ---------------------------------------------------------------------------

_FN_CACHE: dict[str, tuple] = {}


def _shape_key(rule_dict: dict) -> str:
    """Build a cache key from rule shape only — type + validator key names, no values.

    NOTE: dict key ordering is not normalised in this implementation. Rules
    written as static literals have stable ordering by construction. Rules
    built programmatically with variable key ordering will produce cache misses.
    This is a known limitation — a future pass can add sort_keys normalisation.
    """
    parts = [rule_dict.get('type', '')]
    for rule_key, _ in _FN_ORDER:
        if rule_key in rule_dict:
            parts.append(rule_key)
    return '|'.join(parts)


def _get_fns(rule_dict: dict) -> tuple:
    """Return (and cache) the function tuple for the given rule shape."""
    key = _shape_key(rule_dict)
    if key not in _FN_CACHE:
        _FN_CACHE[key] = tuple(
            fn for rule_key, fn in _FN_ORDER if rule_key in rule_dict
        )
    return _FN_CACHE[key]


# ---------------------------------------------------------------------------
# Args cache
# Maps content key (full rule values) -> args tuple.
# Expensive preprocessing (date parsing, frozenset construction) happens once
# per unique rule value set and is reused on subsequent calls.
# ---------------------------------------------------------------------------

_ARGS_CACHE: dict[str, tuple] = {}


def _content_key(rule_dict: dict) -> str | None:
    """Build a cache key from full rule content including values.
    Returns None for rules containing non-serialisable values (callables etc).
    """
    try:
        # Structural and runtime keys are excluded from the content key because
        # they are handled by the runner directly, not by the scalar fn tuple.
        skip = frozenset({'fields', 'items', 'depends_on', 'transform', 'object'})
        relevant = {k: v for k, v in rule_dict.items() if k not in skip}
        return json.dumps(relevant, sort_keys=True)
    except (TypeError, ValueError):
        return None


def _build_type_spec(rule_dict: dict) -> TypeSpec:
    type_name = rule_dict.get('type', '')
    # strict defaults to True for all types except date and regex
    default_strict = type_name not in ('date', 'regex')
    return TypeSpec(
        name=type_name,
        strict=rule_dict.get('strict', default_strict),
        fmt=rule_dict.get('format'),
        region=rule_dict.get('region'),
        cls=rule_dict.get('object'),
    )


def _build_range_arg(rule_dict: dict) -> tuple:
    """Return range bounds, pre-parsing date strings to datetime objects."""
    bounds = rule_dict.get('range', ('any', 'any'))
    if rule_dict.get('type') == 'date':
        lo, hi = bounds
        lo_p = lo if lo == 'any' or isinstance(lo, datetime) else parse_date(lo)
        hi_p = hi if hi == 'any' or isinstance(hi, datetime) else parse_date(hi)
        return (lo_p, hi_p)
    return bounds


def _get_args(rule_dict: dict, fns: tuple) -> tuple:
    """Reconstruct args tuple matching the given function tuple positionally.

    Results are cached by full rule content so expensive preprocessing
    (parse_date, frozenset) runs at most once per unique rule.
    """
    ck = _content_key(rule_dict)
    sk = _shape_key(rule_dict)
    cache_key = f'{sk}::{ck}' if ck is not None else None

    if cache_key and cache_key in _ARGS_CACHE:
        return _ARGS_CACHE[cache_key]

    args = []
    fn_set = set(fns)

    for rule_key, fn in _FN_ORDER:
        if fn not in fn_set:
            continue
        if rule_key == 'range':
            args.append(_build_range_arg(rule_dict))
        elif rule_key == 'excludes':
            args.append(frozenset(rule_dict.get('excludes', ())))
        elif rule_key == 'options':
            args.append(frozenset(rule_dict.get('options', ())))
        elif rule_key == 'unique':
            args.append(None)
        else:
            args.append(rule_dict.get(rule_key))

    result = tuple(args)
    if cache_key:
        _ARGS_CACHE[cache_key] = result
    return result


# ---------------------------------------------------------------------------
# Error key dispatch
# ---------------------------------------------------------------------------

# Type name -> error key for check_type failures
_TYPE_ERROR_KEY: dict[str, str] = {
    'email':      'invalid_email',
    'url':        'invalid_url',
    'ip':         'invalid_ip',
    'uuid':       'invalid_uuid',
    'slug':       'invalid_slug',
    'semver':     'invalid_semver',
    'color':      'invalid_color',
    'phone':      'invalid_phone',
    'even':       'not_even',
    'odd':        'not_odd',
    'prime':      'not_prime',
    'date':       'invalid_date',
    'object':     'invalid_object',
    # native types + annotation + regex: default to 'type_invalid'
}


def _error_key_for_fn(fn: Any, rule_dict: dict) -> str:
    """Return the error message key for a scalar validator failure."""
    type_name = rule_dict.get('type', '')

    if fn is validate_range:
        if type_name == 'date':
            return 'date_not_in_range'
        if type_name == 'str':
            return 'string_not_in_range'
        if type_name in ('list', 'tuple'):
            return 'list_or_tuple_not_in_range'
        return 'number_not_in_range'

    if fn is validate_length:
        return 'length_invalid' if type_name in _BASIC_TYPES_PLUS_REGEX else 'object_length_invalid'

    if fn is validate_contains:
        if type_name in _BASIC_TYPES_PLUS_REGEX:
            return 'missing_required_data'
        if type_name == 'dict':
            return 'missing_required_keys'
        return 'missing_required_values'

    _SIMPLE: dict[Any, str] = {
        validate_excludes:   'not_excluded',
        validate_options:    'not_in_options',
        validate_expression: 'does_not_match_regex',
        validate_startswith: 'does_not_startwith',
        validate_endswith:   'does_not_endwith',
        validate_unique:     'not_unique',
    }
    return _SIMPLE.get(fn, 'no_error_message')


# ---------------------------------------------------------------------------
# Message resolution
#
# Priority:
#   1. rule_dict.get('<rule_key>-message')   e.g. 'range-message'
#   2. rule_dict.get('message')
#   3. errm.get('field_<error_key>')         only when field_name is truthy
#   4. errm.get('<error_key>')
#   5. errm['no_error_message']
# ---------------------------------------------------------------------------

def _resolve_message(rule_dict: dict, fn: Any, field_name: str, error_key: str) -> str:
    # 1. Rule-specific message key
    if fn is not None:
        rule_key = _FN_TO_RULE_KEY.get(fn, '')
        specific = rule_dict.get(f'{rule_key}-message', '')
        if specific:
            return specific

    # 2. Generic override
    generic = rule_dict.get('message', '')
    if generic:
        return generic

    # 3 & 4. Default from messages.py — field-prefixed when field_name is truthy
    # The truthy check on field_name: an empty string (positional/list data)
    # must NOT trigger the prefixed lookup.
    if field_name:
        raw = errm.get(f'field_{error_key}', '')
        if raw:
            return raw

    return errm.get(error_key, '') or errm['no_error_message']


# ---------------------------------------------------------------------------
# Type validation with error message production
# ---------------------------------------------------------------------------

def _validate_type(value: Any, rule_dict: dict, field_name: str, path: str, ctx: _CallContext) -> bool:
    """Run check_type, emit the correct error message on failure, return bool."""
    if value is None and rule_dict.get('nullable', False):
        return True

    spec = _build_type_spec(rule_dict)
    if check_type(value, spec):
        return True

    # Build the error message for a type check failure
    error_key = _TYPE_ERROR_KEY.get(spec.name, 'type_invalid')
    custom_msg = rule_dict.get('type-message', '') or rule_dict.get('message', '')

    if error_key == 'type_invalid':
        true_type = spec.cls.__qualname__ if spec.name == 'annotation' and spec.cls else spec.name
        actual = type(value).__qualname__
        if field_name:
            raw = errm.get('field_type_invalid', '') or errm.get('type_invalid', '') or errm['no_error_message']
            msg = custom_msg or raw.format(expected=true_type, field=field_name, actual=actual)
        else:
            raw = errm.get('type_invalid', '') or errm['no_error_message']
            msg = custom_msg or raw.format(expected=true_type, actual=actual)
    else:
        if field_name:
            raw = errm.get(f'field_{error_key}', '') or errm.get(error_key, '') or errm['no_error_message']
        else:
            raw = errm.get(error_key, '') or errm['no_error_message']
        msg = custom_msg or raw

    ctx.add_error(path or field_name, msg)
    return False


# ---------------------------------------------------------------------------
# Scalar validator runner
# ---------------------------------------------------------------------------

def _run_scalar_validators(
    value: Any,
    rule_dict: dict,
    field_name: str,
    path: str,
    ctx: _CallContext,
) -> None:
    """Run all scalar validators for this rule against value."""
    fns = _get_fns(rule_dict)
    if not fns:
        return

    args = _get_args(rule_dict, fns)

    for fn, arg in zip(fns, args):
        try:
            ok = fn(value, arg)
        except (ValidationError, ImportError):
            raise
        except Exception as ex:
            if ctx.log_errors:
                logging.warning(str(ex))
            ok = False

        if not ok:
            error_key = _error_key_for_fn(fn, rule_dict)
            msg = _resolve_message(rule_dict, fn, field_name, error_key)
            ctx.add_error(path or field_name, msg)


# ---------------------------------------------------------------------------
# Transform and depends_on helpers
# ---------------------------------------------------------------------------

def _apply_transform(value: Any, rule_dict: dict, full_data: dict | None = None) -> Any:
    if value is None and rule_dict.get('nullable'):
        return value
    transform = rule_dict.get('transform')
    if transform is None:
        return value
    if isinstance(transform, dict):
        func = transform.get('func')
        pass_data = transform.get('pass_data', False)
        if func:
            return func(value, full_data) if pass_data else func(value)
    elif callable(transform):
        return transform(value)
    return value


def _check_depends_on(rule_dict: dict, value: Any, full_data: dict) -> bool:
    depends_on = rule_dict.get('depends_on')
    if depends_on is None:
        return True
    field = depends_on.get('field')
    if not field or full_data is None:
        return True
    sibling_value = full_data.get(field)
    condition = depends_on.get('condition')
    if condition and callable(condition):
        return condition(sibling_value)
    expected_value = depends_on.get('value')
    if expected_value is not None:
        return sibling_value == expected_value
    return True


# ---------------------------------------------------------------------------
# Path building
# ---------------------------------------------------------------------------

def _build_path(parent_path: str, key: Any, index: int | None = None) -> str:
    if index is not None:
        segment = f'[{index}]'
        return f'{parent_path}{segment}' if parent_path else segment
    if not parent_path:
        return str(key) if key else ''
    return f'{parent_path}.{key}' if key else parent_path


# ---------------------------------------------------------------------------
# Nested structure handlers
# ---------------------------------------------------------------------------

def _handle_fields(
    value: Any,
    rule_dict: dict,
    path: str,
    ctx: _CallContext,
    depth: int,
) -> tuple[Any, bool]:
    """Recurse into a nested dict. Returns (possibly mutated value, ok)."""
    fields = rule_dict.get('fields')
    if not fields or not isinstance(value, dict):
        return value, True

    if depth >= MAX_NESTING_DEPTH:
        raise ValueError(
            f'Maximum nesting depth of {MAX_NESTING_DEPTH} exceeded'
            + (f" at '{path}'" if path else '')
        )

    nested_rules = list(fields.values())
    nested_data = OrderedDict((k, value.get(k)) for k in fields.keys())

    errors_before = len(ctx.errors)
    start_td = len(ctx.transformed_data)

    _run_validate_object(nested_data, nested_rules, {}, ctx, parent_path=path, depth=depth + 1)

    ok = len(ctx.errors) == errors_before

    if ctx.mutate:
        sub_values = ctx.transformed_data[start_td:]
        del ctx.transformed_data[start_td:]
        return dict(zip(fields.keys(), sub_values)), ok

    return value, ok


def _handle_items(
    value: Any,
    rule_dict: dict,
    path: str,
    ctx: _CallContext,
    depth: int,
) -> tuple[Any, bool]:
    """Validate each element of a list/tuple against the items rule.

    items may be:
      - a dict (standard items rule)
      - a tuple of type-name strings (from the of: pipe modifier)
    """
    items_rule = rule_dict.get('items')
    if not items_rule or not isinstance(value, (list, tuple)):
        return value, True

    all_ok = True

    # of: syntax — items is a tuple of type name strings
    if isinstance(items_rule, tuple) and all(isinstance(t, str) for t in items_rule):
        single_type = len(items_rule) == 1
        for i, item in enumerate(value):
            item_path = _build_path(path, '', index=i)
            if single_type:
                item_rule = {'type': items_rule[0], 'strict': True}
                if not _validate_type(item, item_rule, '', item_path, ctx):
                    all_ok = False
            else:
                # union: item must match at least one listed type
                matched = any(
                    check_type(item, TypeSpec(name=t, strict=True))
                    for t in items_rule
                )
                if not matched:
                    msg = _resolve_message(rule_dict, None, '', 'not_permitted_type')
                    ctx.add_error(item_path, msg)
                    all_ok = False
        return value, all_ok

    # Standard items rule dict
    for i, item in enumerate(value):
        item_path = _build_path(path, '', index=i)

        if items_rule.get('fields') and isinstance(item, dict):
            _, ok = _handle_fields(item, items_rule, item_path, ctx, depth)
            if not ok:
                all_ok = False
        else:
            if not _validate_type(item, items_rule, '', item_path, ctx):
                all_ok = False
            else:
                _run_scalar_validators(item, items_rule, '', item_path, ctx)

    return value, all_ok


# ---------------------------------------------------------------------------
# Core validation loop
# ---------------------------------------------------------------------------

def _run_validate_object(
    data: Any,
    rules: list,
    defaults: dict,
    ctx: _CallContext,
    parent_path: str = '',
    depth: int = 0,
) -> None:
    keys_with_defaults: set = set(defaults.keys()) if defaults else set()

    if isinstance(data, OrderedDict):
        full_data = dict(data)
        ctx.full_data = full_data

        for index, (key, value) in enumerate(data.items()):
            path = _build_path(parent_path, key)
            ctx.begin_field()

            if key in keys_with_defaults and value == defaults.get(key):
                ctx.transformed_data.append(value)
                continue

            rule_dict = rules[index]
            transformed = _apply_transform(value, rule_dict, full_data)

            if not _check_depends_on(rule_dict, transformed, full_data):
                ctx.transformed_data.append(transformed if ctx.mutate else value)
                continue

            if rule_dict.get('fields'):
                mutated, _ = _handle_fields(transformed, rule_dict, path, ctx, depth)
                ctx.transformed_data.append(mutated if ctx.mutate else value)
                continue

            if rule_dict.get('items'):
                _handle_items(transformed, rule_dict, path, ctx, depth)
                ctx.transformed_data.append(transformed if ctx.mutate else value)
                continue

            if not _validate_type(transformed, rule_dict, key, path, ctx):
                ctx.transformed_data.append(transformed if ctx.mutate else value)
                continue

            if transformed is None and rule_dict.get('nullable'):
                ctx.transformed_data.append(value)
                continue

            _run_scalar_validators(transformed, rule_dict, key, path, ctx)
            ctx.transformed_data.append(transformed if ctx.mutate else value)

    elif isinstance(data, (list, tuple)):
        for count, value in enumerate(data):
            path = _build_path(parent_path, '', index=count) if ctx.nested else ''
            ctx.begin_field()

            rule_dict = rules[count]
            transformed = _apply_transform(value, rule_dict)

            if rule_dict.get('fields'):
                mutated, _ = _handle_fields(transformed, rule_dict, path, ctx, depth)
                ctx.transformed_data.append(mutated if ctx.mutate else value)
                continue

            if rule_dict.get('items'):
                _handle_items(transformed, rule_dict, path, ctx, depth)
                ctx.transformed_data.append(transformed if ctx.mutate else value)
                continue

            if not _validate_type(transformed, rule_dict, '', path, ctx):
                ctx.transformed_data.append(transformed if ctx.mutate else value)
                continue

            if transformed is None and rule_dict.get('nullable'):
                ctx.transformed_data.append(value)
                continue

            _run_scalar_validators(transformed, rule_dict, '', path, ctx)
            ctx.transformed_data.append(transformed if ctx.mutate else value)

    elif isinstance(data, str):
        ctx.group_errors = False
        rule_dict = rules[0]
        transformed = _apply_transform(data, rule_dict)
        _run_scalar_validators(transformed, rule_dict, '', parent_path, ctx)
        ctx.transformed_data.append(transformed if ctx.mutate else data)

    else:
        raise TypeError('the data parameter should be a string, list, tuple, or dict')


# ---------------------------------------------------------------------------
# Engine entry point — called from validate_data in validatedata.py
# ---------------------------------------------------------------------------

def validate_object_engine(
    data: Any,
    rules: list,
    defaults: dict,
    raise_exceptions: bool = False,
    mutate: bool = False,
    nested: bool = False,
    **kwds: Any,
) -> SimpleNamespace:
    """Run validation through the engine and return a SimpleNamespace result."""
    # kwds may arrive nested as kwds['kwds'] (from @validate / validate_data)
    # or as direct keyword args — handle both.
    if 'kwds' in kwds:
        keywords = kwds['kwds']
        group_errors = keywords.get('group_errors', True)
        log_errors = keywords.get('log_errors', False)
    else:
        group_errors = kwds.get('group_errors', True)
        log_errors = kwds.get('log_errors', False)

    ctx = _CallContext(
        group_errors=group_errors,
        nested=nested,
        mutate=mutate,
        raise_exceptions=raise_exceptions,
        log_errors=log_errors,
    )

    token = _ctx_var.set(ctx)
    try:
        _run_validate_object(data, rules, defaults, ctx, parent_path='', depth=0)
    finally:
        _ctx_var.reset(token)

    result: dict[str, Any] = {'ok': ctx.ok, 'errors': ctx.errors}
    if mutate:
        result['data'] = ctx.transformed_data

    return SimpleNamespace(**result)


# ---------------------------------------------------------------------------
# Global cache handle
#
# Plain dicts are intentional — see design notes. _FN_CACHE is bounded by the
# rule vocabulary (shape keys carry no values). _ARGS_CACHE is bounded by the
# number of distinct rule value combinations, which is small for static rules.
# LRU eviction would hurt more than help: evicting a live shape forces a
# recompile on the next hit rather than a free lookup.
#
# Expose a clear() method as a relief valve for operators who observe unexpected
# memory growth (e.g. dynamic rule construction with high value cardinality),
# and size() for monitoring.
# ---------------------------------------------------------------------------

class _CacheNamespace:
    """Thin handle for the module-level rule caches.

    Usage::

        from validatedata import cache
        cache.clear()          # drop all cached entries
        cache.size()           # -> {'fn': N, 'args': N, 'expression': N, 'compiled': N}
    """

    def clear(self) -> None:
        """Clear all rule caches. Thread-safe for reads; call from a quiescent state."""
        _FN_CACHE.clear()
        _ARGS_CACHE.clear()
        _EXPRESSION_CACHE.clear()
        # Lazy import avoids a circular dependency: compiled imports from
        # engine at module level; engine must not import compiled at module
        # level. Importing inside the method body is safe because both modules
        # are fully initialised by the time any caller reaches this point.
        from .compiled import _COMPILED_CACHE
        _COMPILED_CACHE.clear()

    def size(self) -> dict[str, int]:
        """Return the number of entries in each cache."""
        from .compiled import _COMPILED_CACHE
        return {
            'fn':         len(_FN_CACHE),
            'args':       len(_ARGS_CACHE),
            'expression': len(_EXPRESSION_CACHE),
            'compiled':   len(_COMPILED_CACHE),
        }

    def __repr__(self) -> str:
        s = self.size()
        return (
            f'<validatedata cache  fn={s["fn"]}  args={s["args"]}  '
            f'expression={s["expression"]}  compiled={s["compiled"]}>'
        )


cache = _CacheNamespace()
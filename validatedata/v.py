# validatedata/v.py
"""
V — single-line checks. ``if V.int(data):`` — nothing more.

Motivation
----------
Sometimes you don't want a Rule, a FastModel, or a rule dict — you just
want to ask one question about one value, inline::

    from validatedata import V

    if V.int(x):
        ...
    if not V.email(user_input):
        raise ValueError("bad email")

    if V.between(0, 100, score):
        ...
    if V.regex(r"^[A-Z]{3}[0-9]{4}$", code):
        ...


V.Raise — opt-in exceptions
-----------------------------
By default a failed check just returns ``False``, at zero cost beyond
the bare check itself. Call ``V.raise_on_fail(True)`` to switch every
attribute on this class — both the type checks (``V.int``, ``V.email``)
and the constraint checks (``V.between``, ``V.regex``, ...) — to a
raising variant that throws instead of returning ``False``::

    V.raise_on_fail(True)
    V.int("not an int")
    # TypeError: expected int, got str

    V.between(0, 100, 150)
    # ValueError: 150 failed constraint between(0, 100)

    V.raise_on_fail(False)   # back to bool-returning
    V.int("not an int")      # False


Two families of attribute, one convention
------------------------------------------
- Type checks take exactly one argument, the value: ``V.int(x)``.
- Constraint checks take their configuration first and the value last,
  always: ``V.between(lo, hi, value)``, ``V.regex(pattern, value)``,
  ``V.multiple_of(step, value)``. The value is always the final
  positional argument, so the shape is predictable across the class and
  composes with ``functools.partial`` if you want a reusable checker::

    from functools import partial
    is_pct = partial(V.between, 0, 100)
    is_pct(150)   # False

Every check in this module is hand-written directly against the value
— nothing here calls into ``engine.py``'s ``validate_*`` dispatch, which
carries per-call overhead (type branching for dates/strings/collections
on every call) that a single-purpose inline check doesn't need. V is
the manual-speed layer; ``Rule``/``FastModel`` are the composable one.

What V deliberately does NOT do
--------------------------------
No rule composition, no nesting, no models. Each attribute answers
exactly one question about exactly one value. For anything that needs
multiple constraints combined, defaults, nullability, or nested models,
use ``Rule``/``FastModel`` instead.
"""
from __future__ import annotations

import builtins
import decimal as _decimal_mod
import pathlib as _pathlib_mod
import re as _re_mod
from datetime import date as _date_cls, datetime as _datetime_cls
from typing import Any, Callable, Optional

from .dates import parse_date as _parse_date

from .compiled import _TYPE_CHECK
from .customtypes import get_registered_checker

__all__ = ["V"]

# Names of every predeclared base-type attribute on V, so raise_on_fail()
# knows exactly which class attributes to rebind, in both directions.
_BASE_TYPE_ATTRS = (
    "bool", "color", "date", "datetime", "decimal", "dict", "email", "even",
    "float", "int", "ip", "list", "odd", "path", "phone", "prime", "semver",
    "set", "slug", "str", "tuple", "url", "uuid",
)

# Names of every predeclared constraint attribute on V (config-first,
# value-last). Tracked separately from _BASE_TYPE_ATTRS since they need a
# different raising wrapper (multi-arg, and a ValueError/message shape
# that names the failed constraint rather than a type mismatch).
_CONSTRAINT_ATTRS = (
    "between", "contains", "ends_with", "excludes", "ge", "gt", "le", "lt",
    "length", "max_length", "min_length", "multiple_of", "none_of", "one_of",
    "regex", "starts_with",
)

# Small dedicated regex cache for V.regex — deliberately separate from
# engine._EXPRESSION_CACHE so this module never has to import engine.py.
_REGEX_CACHE: dict[tuple[str, int], "_re_mod.Pattern"] = {}


def _tc_v_datetime(v: Any) -> bool:
    """True datetime-instance check (distinct from V.date's parseable-string sense)."""
    return isinstance(v, _datetime_cls)


def _tc_v_date(v: Any) -> bool:
    """
    Accepts a real ``date``/``datetime`` instance, or a string that parses
    into one via ``dateutil``. Broader than a bare ``isinstance(v, date)``
    since date-like strings ("2024-01-01") are extremely common inputs and
    this mirrors the existing ``compiled._tc_date`` semantics used elsewhere
    in the package.
    """
    if isinstance(v, (_date_cls, _datetime_cls)):
        return True
    if isinstance(v, str):
        try:
            _parse_date(v)
            return True
        except Exception:
            return False
    return False


def _tc_v_decimal(v: Any) -> bool:
    """
    Accepts a real ``Decimal`` instance, or a string/int that converts
    cleanly into one. Floats are deliberately excluded — a float is not
    a reliable decimal representation (binary rounding), so callers who
    want float-derived Decimals should convert explicitly first.
    """
    if type(v) is _decimal_mod.Decimal or isinstance(v, _decimal_mod.Decimal):
        return True
    if type(v) is bool:
        return False
    if type(v) in (str, int):
        try:
            _decimal_mod.Decimal(v)
            return True
        except Exception:
            return False
    return False


def _tc_v_path(v: Any) -> bool:
    """
    Accepts a real ``pathlib.Path`` (or subclass, e.g. ``PosixPath``), or
    any string/``os.PathLike``. Does not check filesystem existence —
    purely a "can this be treated as a path" check.
    """
    if isinstance(v, (_pathlib_mod.PurePath, str)):
        return True
    try:
        import os
        return isinstance(v, os.PathLike)
    except Exception:
        return False


def _builtin_type_checker(name: str) -> Optional[Callable[[Any], bool]]:
    """
    Best-effort resolution of `name` against a real Python type: checked
    against builtins first, then a short list of common stdlib modules
    (datetime.datetime, uuid.UUID, decimal.Decimal, pathlib.Path, etc).
    Matching is case-insensitive. Returns None if nothing matches. Only
    used by V.check(), never by the predeclared base-type attributes.
    """
    candidate = getattr(builtins, name, None)
    if isinstance(candidate, type):
        return lambda v, _t=candidate: isinstance(v, _t)

    lname = name.lower()
    for module_name in ("datetime", "decimal", "pathlib", "uuid", "collections"):
        try:
            mod = __import__(module_name)
        except ImportError:
            continue
        for attr_name in dir(mod):
            if attr_name.startswith("_") or attr_name.lower() != lname:
                continue
            candidate = getattr(mod, attr_name, None)
            if isinstance(candidate, type):
                return lambda v, _t=candidate: isinstance(v, _t)

    return None


def _make_raising(type_name: str, bare_check: Callable[[Any], bool]) -> Callable[[Any], bool]:
    """
    Wrap a single-argument type check so failure raises TypeError naming
    the expected type and the actual type received, instead of returning
    False. Success is still just `return True` — no extra work on the
    happy path beyond the one added call frame this wrapper itself is.
    """
    def _checked(value: Any) -> bool:
        if bare_check(value):
            return True
        raise TypeError(
            f"expected {type_name}, got {type(value).__name__}"
        )
    return _checked


def _make_raising_unique(bare_check: Callable[[Any], bool]) -> Callable[[Any], bool]:
    """
    Wrap V.unique so failure raises ValueError naming the value, instead
    of returning False. Kept distinct from _make_raising since "expected
    unique, got list" would misdescribe the failure — unique isn't a
    type mismatch, it's a duplicate-elements finding.
    """
    def _checked(value: Any) -> bool:
        if bare_check(value):
            return True
        raise ValueError(f"{value!r} contains duplicate elements")
    return _checked


def _make_raising_constraint(
    constraint_name: str, bare_check: Callable[..., bool]
) -> Callable[..., bool]:
    """
    Wrap a config-first, value-last constraint check so failure raises
    ValueError naming the constraint, its configuration, and the value
    that failed it, instead of returning False.

        V.raise_on_fail(True)
        V.between(0, 100, 150)
        # ValueError: 150 failed constraint between(0, 100)
    """
    def _checked(*args: Any) -> bool:
        if bare_check(*args):
            return True
        *config, value = args
        config_str = ", ".join(repr(c) for c in config)
        raise ValueError(
            f"{value!r} failed constraint {constraint_name}({config_str})"
        )
    return _checked


# ---------------------------------------------------------------------------
# Constraint checks — config-first, value-last. Hand-written against the
# value directly (no engine.py calls) so these run at the same speed as
# writing the comparison inline yourself.
# ---------------------------------------------------------------------------

def _v_between(lo: Any, hi: Any, value: Any) -> bool:
    """
    Numeric values (int, float, bool): lo <= value <= hi.
    Strings/lists/tuples/sets/dicts: lo <= len(value) <= hi.
    Anything else: False (never raises — an unsupported type is simply
    not "between" anything, rather than crashing on an unsupported '<=').
    """
    if type(value) in (int, float) or isinstance(value, _decimal_mod.Decimal):
        return lo <= value <= hi
    try:
        return lo <= len(value) <= hi
    except TypeError:
        return False


def _v_length(n: int, value: Any) -> bool:
    try:
        return len(value) == n
    except TypeError:
        return False


def _v_min_length(n: int, value: Any) -> bool:
    try:
        return len(value) >= n
    except TypeError:
        return False


def _v_max_length(n: int, value: Any) -> bool:
    try:
        return len(value) <= n
    except TypeError:
        return False


def _v_gt(bound: Any, value: Any) -> bool:
    try:
        return value > bound
    except TypeError:
        return False


def _v_lt(bound: Any, value: Any) -> bool:
    try:
        return value < bound
    except TypeError:
        return False


def _v_ge(bound: Any, value: Any) -> bool:
    try:
        return value >= bound
    except TypeError:
        return False


def _v_le(bound: Any, value: Any) -> bool:
    try:
        return value <= bound
    except TypeError:
        return False


def _v_multiple_of(step: Any, value: Any) -> bool:
    """True if value is an exact multiple of step."""
    try:
        # Fast path for integers (avoids float precision checks and extra type branches)
        if type(value) is int and type(step) is int:
            if step == 0:
                return False
            return value % step == 0

        # General path for floats / decimals
        if step == 0:
            return False
        if type(value) is float or type(step) is float or isinstance(value, float):
            remainder = value % step
            return remainder < 1e-9 or (step - remainder) < 1e-9
        return value % step == 0
    except TypeError:
        return False


def _v_contains(item: Any, value: Any) -> bool:
    try:
        return item in value
    except TypeError:
        return False


def _v_excludes(item: Any, value: Any) -> bool:
    try:
        return item not in value
    except TypeError:
        return False


def _v_starts_with(prefix: Any, value: Any) -> bool:
    if isinstance(value, str):
        return value.startswith(prefix)
    try:
        return bool(value) and value[0] == prefix
    except (TypeError, KeyError, IndexError):
        return False


def _v_ends_with(suffix: Any, value: Any) -> bool:
    if isinstance(value, str):
        return value.endswith(suffix)
    try:
        return bool(value) and value[-1] == suffix
    except (TypeError, KeyError, IndexError):
        return False


def _v_one_of(options: Any, value: Any) -> bool:
    try:
        return value in options
    except TypeError:
        return False


def _v_none_of(options: Any, value: Any) -> bool:
    try:

        return value not in options
    except TypeError:
        return False


def _v_regex(pattern: str, value: Any, flags: int = 0) -> bool:
    """
    Anchored match (``re.match``, not ``re.search``) against the start of
    ``str(value)`` — consistent with the rest of the library's pattern
    semantics (``Rule(pattern=...)``/``re:`` tokens). Compiled patterns
    are cached locally so repeated calls with the same pattern don't
    recompile.
    """
    key = (pattern, flags)
    compiled = _REGEX_CACHE.get(key)
    if compiled is None:
        compiled = _re_mod.compile(pattern, flags)
        _REGEX_CACHE[key] = compiled
    return compiled.match(value if isinstance(value, str) else str(value)) is not None


def _v_unique(value: Any) -> bool:
    """
    True if every element in a list/tuple/set is distinct. Falls back to
    an O(n^2) scan for unhashable elements (e.g. a list of lists).
    """
    try:
        return len(value) == len(set(value))
    except TypeError:
        seen = []
        for item in value:
            if item in seen:
                return False
            seen.append(item)
        return True


class V:
    """
    Never instantiate this — call attributes directly on the class.

    Two families of attribute:

    - Type checks take exactly one argument: ``V.int(x)``, ``V.email(x)``.
      Each is bound directly to the same function object
      ``compiled._TYPE_CHECK`` uses internally.
    - Constraint checks take their configuration first and the value
      last: ``V.between(lo, hi, value)``, ``V.regex(pattern, value)``.
      Each is a small hand-written function with no dependency on
      ``engine.py``, so it runs at roughly the same speed as writing the
      check inline yourself.

    Call ``V.raise_on_fail(True)`` to switch every attribute in both
    families to a raising variant instead of returning ``False``.

    For a type name that isn't one of the base types below — a
    user-registered type via ``validatedata.customtypes.register_type``, or a
    plain Python/stdlib type — use ``V.check(name, value)``.
    """

    # -- type checks (one argument: the value) ------------------------
    bool = lambda v: type(v) is bool
    dict = lambda v: isinstance(v, dict)
    float = lambda v: type(v) is float
    int = lambda v: type(v) is int
    list = lambda v: isinstance(v, list)
    set = lambda v: isinstance(v, set)
    str = lambda v: isinstance(v, str)
    tuple = lambda v: isinstance(v, tuple)


    color = _TYPE_CHECK["color"]
    date = _tc_v_date
    datetime = _tc_v_datetime
    decimal = _tc_v_decimal
    email = _TYPE_CHECK["email"]
    even = _TYPE_CHECK["even"]
    ip = _TYPE_CHECK["ip"]
    odd = _TYPE_CHECK["odd"]
    path = _tc_v_path
    phone = _TYPE_CHECK["phone"]
    prime = _TYPE_CHECK["prime"]
    semver = _TYPE_CHECK["semver"]
    slug = _TYPE_CHECK["slug"]
    url = _TYPE_CHECK["url"]
    uuid = _TYPE_CHECK["uuid"]

    # -- constraint checks (configuration first, value last) ----------
    between = _v_between
    contains = _v_contains
    ends_with = _v_ends_with
    excludes = _v_excludes
    ge = _v_ge
    gt = _v_gt
    le = _v_le
    lt = _v_lt
    length = _v_length
    max_length = _v_max_length
    min_length = _v_min_length
    multiple_of = _v_multiple_of
    none_of = _v_none_of
    one_of = _v_one_of
    regex = _v_regex
    starts_with = _v_starts_with

    # -- zero-config check (single argument, like the type checks) ----
    unique = _v_unique

    # Tracks current mode so raise_on_fail() is idempotent and so callers
    # can introspect it (`if V._raising: ...`) without re-deriving it from
    # attribute contents.
    _raising: bool = False

    @classmethod
    def raise_on_fail(cls, flag: bool = True) -> None:
        """
        Switch every attribute — type checks and constraint checks alike
        — between bool-returning (default) and raising modes.

            V.raise_on_fail(True)
            V.int("x")               # TypeError: expected int, got str
            V.between(0, 100, 150)   # ValueError: 150 failed constraint between(0, 100)

            V.raise_on_fail(False)
            V.int("x")               # False
            V.between(0, 100, 150)   # False

        This reassigns each predeclared attribute once, not on every
        check call — the mode you're not using costs nothing. Global to
        the V class (not per-thread, not per-call); if you need both
        behaviors concurrently, use ``V.check(...)`` style calls with
        your own try/except instead of toggling this.
        """
        if flag == cls._raising:
            return  # already in requested mode — avoid redundant rebinding

        for attr_name in _BASE_TYPE_ATTRS:
            type_name = attr_name.lower()
            if flag:
                # Wrap whatever bare check is currently live (the true
                # original, since this only ever runs off->on or on->off).
                current = getattr(cls, attr_name)
                setattr(cls, attr_name, _make_raising(type_name, current))
            else:
                setattr(cls, attr_name, _ORIGINAL_CHECKS[attr_name])

        for attr_name in _CONSTRAINT_ATTRS:
            if flag:
                current = getattr(cls, attr_name)
                setattr(cls, attr_name, _make_raising_constraint(attr_name, current))
            else:
                setattr(cls, attr_name, _ORIGINAL_CONSTRAINT_CHECKS[attr_name])

        if flag:
            current = getattr(cls, "unique")
            setattr(cls, "unique", _make_raising_unique(current))
        else:
            setattr(cls, "unique", _ORIGINAL_UNIQUE_CHECK)

        cls._raising = flag

    @staticmethod
    def check(name: str, value: Any) -> bool:
        """
        Fallback for type names that aren't predeclared attributes above:
        user types registered via ``validatedata.customtypes.register_type``
        (by name or by class object), then plain Python/stdlib types.

            V.check("MyType", obj)
            V.check("datetime", some_dt)

        Does not honor V.raise_on_fail() — always returns bool. Raises
        AttributeError if `name` isn't a base type, isn't registered, and
        isn't a recognizable Python/stdlib type.
        """
        checker = _TYPE_CHECK.get(name.lower())
        if checker is not None:
            return checker(value)

        checker = get_registered_checker(name) or get_registered_checker(name.lower())
        if checker is not None:
            return checker(value)

        checker = _builtin_type_checker(name)
        if checker is not None:
            return checker(value)

        raise AttributeError(
            f"V has no type check for {name!r}. It isn't a base type, "
            f"isn't registered via validatedata.customtypes.register_type, and "
            f"isn't a recognizable Python/stdlib type.\n"
            f"For constraints (min/max/pattern/nullable/...) or validation "
            f"errors, use Rule(...) or FastModel instead."
        )


_ORIGINAL_CHECKS = {attr_name: getattr(V, attr_name) for attr_name in _BASE_TYPE_ATTRS}
_ORIGINAL_CONSTRAINT_CHECKS = {attr_name: getattr(V, attr_name) for attr_name in _CONSTRAINT_ATTRS}
_ORIGINAL_UNIQUE_CHECK = getattr(V, "unique")
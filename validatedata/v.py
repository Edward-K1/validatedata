# validatedata/v.py
"""
V — single-line type checks. ``if V.int(data):`` — nothing more.

Motivation
----------
Sometimes you don't want a Rule, a FastModel, or a rule dict — you just
want to ask one question about one value, inline::

    from validatedata import V

    if V.int(x):
        ...
    if not V.email(user_input):
        raise ValueError("bad email")



V.Raise — opt-in exceptions
-----------------------------
By default a failed check just returns ``False``, at zero cost beyond
the bare ``isinstance``/regex call. Call ``V.raise_on_fail(True)`` to
switch every base-type attribute (``V.int``, ``V.email``, ...) to a
raising variant that throws ``TypeError`` naming the expected type and
the actual type received, instead of returning ``False``::

    V.raise_on_fail(True)
    V.int("not an int")
    # TypeError: expected int, got str

    V.raise_on_fail(False)   # back to bool-returning
    V.int("not an int")      # False


What V deliberately does NOT do
--------------------------------
No rules, no pipe strings, no ``Rule`` composition. Constraint logic
(min, max, pattern, nullable...) is ``Rule``/``FastModel``'s job. V only
ever answers "is this value this type" — optionally loudly.
"""
from __future__ import annotations

import builtins
import decimal as _decimal_mod
import pathlib as _pathlib_mod
from datetime import date as _date_cls, datetime as _datetime_cls
from typing import Any, Callable, Optional

from dateutil.parser import parse as _parse_date

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
    if isinstance(v, _decimal_mod.Decimal):
        return True
    if isinstance(v, bool):
        return False
    if isinstance(v, (str, int)):
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
    if isinstance(v, _pathlib_mod.PurePath):
        return True
    if isinstance(v, str):
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
    Wrap a bare checker so failure raises TypeError naming the expected
    type and the actual type received, instead of returning False.
    Success is still just `return True` — no extra work on the happy path
    beyond the one added call frame this wrapper itself is.
    """
    def _checked(value: Any) -> bool:
        if bare_check(value):
            return True
        raise TypeError(
            f"expected {type_name}, got {type(value).__name__}"
        )
    return _checked


class V:
    """
    Never instantiate this — call attributes directly on the class:
    ``V.int(x)``, ``V.email(x)``.

    Each base-type attribute is bound directly to the same function
    object ``compiled._TYPE_CHECK`` uses internally, unless
    ``V.raise_on_fail(True)`` has been called, in which case each is
    rebound to a small wrapper that raises ``TypeError`` on failure
    instead of returning ``False``.

    For a type name that isn't one of the base types below — a
    user-registered type via ``validatedata.customtypes.register_type``, or a
    plain Python/stdlib type — use ``V.check(name, value)``.
    """
   
    bool = lambda v: isinstance(v, bool)
    dict = lambda v: isinstance(v, dict)
    float = lambda v: isinstance(v, float)
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

    # Tracks current mode so raise_on_fail() is idempotent and so callers
    # can introspect it (`if V._raising: ...`) without re-deriving it from
    # attribute contents.
    _raising: bool = False

    @classmethod
    def raise_on_fail(cls, flag: bool = True) -> None:
        """
        Switch every base-type attribute between bool-returning (default)
        and TypeError-raising modes.

            V.raise_on_fail(True)
            V.int("x")          # raises TypeError: expected int, got str

            V.raise_on_fail(False)
            V.int("x")          # False

        This reassigns each of the ~23 base-type class attributes once,
        not on every check call — the mode you're not using costs
        nothing. Global to the V class (not per-thread, not per-call);
        if you need both behaviors concurrently, use ``V.check(...)``
        style calls with your own try/except instead of toggling this.
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
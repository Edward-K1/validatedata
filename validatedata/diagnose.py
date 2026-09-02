# diagnose.py – diagnostic companion to compiled.validator()
#
# Design summary
# --------------
# compiled.validator() stays untouched and remains the hot path: a single
# fused bool callable, no per-constraint information retained.
#
# This module is the *second* call, made only after validator() has already
# returned False. It recompiles the rule into a per-constraint diagnostic
# function — deliberately unfused, since the entire point is to recover the
# constraint boundaries the fast path intentionally erases.
#
# Every value resolvable at compile time (expected type, field name, min/max/
# length/between bounds, constraint kind) is precomputed into a finished
# message string and cached. Only `actual` (the runtime value's type) is
# unavailable until call time — that affects exactly three message keys
# (type_invalid, field_type_invalid, custom_type_invalid). Everything else
# collapses into a zero-cost cached literal the first time a given rule
# fails; on every subsequent failure of that same rule, no string work runs
# at all — only attribute reads and one dict lookup for the type-actual slot
# if applicable.
#
# Two independent axes, both resolved at *compile* time (no runtime
# branching inside the check loop itself):
#
#   mode:       "first" (stop at first failing check, matches validator()'s
#               own short-circuit semantics) or "all" (run every check,
#               report every failure). Implemented as two separate
#               precompiled run functions per rule; the caller picks which
#               one to invoke.
#
#   aggressive: False (default) = full messages, including the runtime
#               `actual` type where relevant.
#               True = generic messages only; `actual` is never computed,
#               never included. Cheaper because it skips type(value).__name__
#               entirely, not just the string formatting.
#
# Cache key: (rule_cache_key, aggressive) -> tuple of precomputed messages,
# one slot per compiled check, in the same left-to-right order
# compiled._compile_pipe_rule() produces. rule_cache_key is exactly the same
# key compiled.validator() already uses (dict rules go through
# json.dumps(sort_keys=True), so field order never affects the key).
# The mode parameter does NOT enter the cache key — "first" vs "all" only
# changes which checks run this call, never what message a given check
# would produce if it failed, so both modes share one cache.

from __future__ import annotations

import json
from typing import Any, Callable, Optional

from . import compiled
from .messages import error_messages as _msg
from .validatedata import _pipe_tokenize

# ----------------------------------------------------------------------
# Reuse fast.py's existing classification tables rather than redefining
# them — they are already correct and exercised by fast.py's message path.
# ----------------------------------------------------------------------
from .fast import (
    _VALIDATOR_TO_MESSAGE,
    _RANGE_MSG_KEYS,
    _NATIVE_NAMES,
    _COLLECTION_TYPES,
    _TYPE_TO_MESSAGE
)

_LEN_TYPES = compiled._LEN_TYPES


# ----------------------------------------------------------------------
# Per-check static metadata recovered from the token stream.
#
# This mirrors fast.py's _compile_pipe_rule_to_struct token walk (same
# token source, same left-to-right order as compiled._compile_pipe_rule's
# `checks` list) but only extracts what message-building needs: kind,
# bound args, and the type name for category lookup (number/len/collection).
# ----------------------------------------------------------------------
def _extract_check_metadata(rule_str: str) -> tuple[str, list[tuple[str, Optional[str]]]]:
    """Return (type_name, [(validator_name, arg), ...]) aligned to the
    `checks` list compiled._compile_pipe_rule() builds for this rule string.

    validator_name is "type" for the implicit leading type check, then one
    entry per validator token in source order. This must stay aligned with
    compiled._compile_pipe_rule's `checks = [type_check] + validators`.
    """
    tokens = _pipe_tokenize(rule_str)
    _raw_type = tokens[0].strip().split(":", 1)[0]
    type_name = _raw_type.split("[", 1)[0]

    names: list[tuple[str, Optional[str]]] = [("type", _raw_type)]
    min_val: Optional[str] = None
    max_val: Optional[str] = None
    between_val: Optional[str] = None

    for token in tokens[1:]:
        key, _, value = token.partition(":")
        key = key.strip()
        value = value.strip() if value else None

        if key in ("nullable", "strict", "msg", "format", "region"):
            continue  # flags / modifiers — never produce a standalone check
        if key == "min":
            min_val = value
            continue
        if key == "max":
            max_val = value
            continue
        if key == "between":
            between_val = value
            continue
        if key in ("gt", "lt", "multiple_of"):
            names.append((key, value))
            continue
        if key in _VALIDATOR_TO_MESSAGE:
            names.append((key, value))

    # min/max/between resolve into a single trailing check, same as
    # compiled._compile_pipe_rule's post-loop range resolution.
    if between_val is not None:
        names.append(("between", between_val))
    elif min_val is not None and max_val is not None:
        names.append(("between", f"{min_val},{max_val}"))
    elif min_val is not None:
        names.append(("min", min_val))
    elif max_val is not None:
        names.append(("max", max_val))

    return type_name, names


def _category_for(type_name: str) -> str:
    if type_name in _COLLECTION_TYPES:
        return "collection"
    if type_name in _LEN_TYPES:
        return "len"
    return "number"


# ----------------------------------------------------------------------
# Message resolution — fully precomputed at compile time wherever possible.
#
# Returns either:
#   - a finished literal string (the common case — no {actual} involved), or
#   - a callable(actual_type_name: str) -> str template-closure, reserved
#     for the three type-check keys where {actual} cannot be known yet.
# ----------------------------------------------------------------------
_TYPE_ACTUAL_KEYS = frozenset({"type_invalid", "field_type_invalid", "custom_type_invalid"})


def _resolve_type_message(
    type_name: str,
    raw_type: str,
    field_name: Optional[str],
    aggressive: bool,
) -> str | Callable[[str], str]:
    display_type = raw_type or type_name
    
    specific_key = _TYPE_TO_MESSAGE.get(type_name)

    if field_name is not None:
        key = "field_type_invalid_generic" if aggressive else "field_type_invalid"
        template = _msg.get(key, _msg.get("field_type_invalid", "invalid type"))
    elif specific_key and specific_key not in ("type_invalid",):
        # Type has a dedicated message (invalid_email, invalid_url, etc.) —
        # use it directly instead of the generic type_invalid template.
        template = _msg.get(specific_key, _msg.get("type_invalid", "invalid type"))
    elif type_name in compiled._TYPE_CHECK or type_name in compiled._NATIVE_TYPE_MAP:
        key = "type_invalid_generic" if aggressive else "type_invalid"
        template = _msg.get(key, _msg.get("type_invalid", "invalid type"))
    else:
        key = "custom_type_invalid_generic" if aggressive else "custom_type_invalid"
        template = _msg.get(key, _msg.get("custom_type_invalid", "invalid type"))

    # {expected} (and {field}) are compile-time literals — substitute now
    # regardless of aggressive mode; only {actual} is ever deferred.
    template = template.replace("{expected}", display_type)
    if field_name is not None:
        template = template.replace("{field}", field_name)

    if aggressive:
        # The "_generic" template was authored with no {actual} placeholder
        # at all — nothing deferred, nothing to strip.
        return template

    if "{actual}" not in template:
        return template

    # One substitution remains, deferred to the actual failing value's type.
    return lambda actual_type_name, _t=template: _t.replace("{actual}", actual_type_name)


def _resolve_validator_message(validator_name: str, arg: Optional[str], type_name: str) -> str:
    if validator_name in ("min", "max", "between"):
        category = _category_for(type_name)
        if validator_name == "between" and "," in (arg or ""):
            # between collapses min+max into one check. For len/number types,
            # use the generic range key since we can't know which bound failed.
            msg_key = _RANGE_MSG_KEYS.get(("between", category), "string_not_in_range")
            template = _msg.get(msg_key, "value out of range")
            lo, hi = arg.split(",", 1)
            template = template.replace("{min}", lo.strip()).replace("{max}", hi.strip())
        else:
            msg_key = _RANGE_MSG_KEYS.get((validator_name, category), "string_not_in_range")
            template = _msg.get(msg_key, "value out of range")
            if arg:
                template = template.replace("{min}", arg).replace("{max}", arg)
        return template

    if validator_name in ("gt", "lt", "multiple_of"):
        msg_key = {
            "gt": "number_not_greater_than",
            "lt": "number_not_less_than",
            "multiple_of": "number_not_multiple_of",
        }[validator_name]
        template = _msg.get(msg_key, "value failed constraint")
        if arg:
            template = template.replace("{min}", arg).replace("{max}", arg)
        return template

    msg_key = _VALIDATOR_TO_MESSAGE.get(validator_name, "validation_failed")
    template = _msg.get(msg_key, "validation failed")
    if validator_name == "length" and arg:
        template = template.replace("{expected}", arg)
    return template


# ----------------------------------------------------------------------
# Compiled diagnostic artifact for one rule.
# ----------------------------------------------------------------------
class _DiagnosticRule:
    __slots__ = (
        "checks", "names", "messages_full", "messages_agg",
        "type_name", "nullable", "transform", "field_name",
    )

    def __init__(
        self,
        checks: list[Callable[[Any], bool]],
        names: list[str],
        messages_full: tuple,
        messages_agg: tuple,
        type_name: str,
        nullable: bool,
        transform: Optional[Callable],
        field_name: Optional[str],
    ):
        self.checks = checks
        self.names = names                  # constraint name per check, aligned index-for-index
        self.messages_full = messages_full  # str OR callable(actual_type_name)->str, per check
        self.messages_agg = messages_agg    # str only — never deferred
        self.type_name = type_name
        self.nullable = nullable
        self.transform = transform
        self.field_name = field_name

    def run_first(self, value: Any, aggressive: bool) -> dict[str, Any]:
        """Stop at the first failing check. Mirrors validator()'s own
        short-circuit semantics — cheapest mode, matches root-cause framing.
        """
        v = value
        if self.transform is not None:
            try:
                v = self.transform(value)
            except Exception:
                return {"valid": False, "field": self.field_name,
                        "constraint": "transform", "message": "transform failed"}

        if v is None:
            if self.nullable:
                return {"valid": True}
            return {"valid": False, "field": self.field_name,
                    "constraint": "required", "message": "value is missing"}

        msgs = self.messages_agg if aggressive else self.messages_full
        for i, check in enumerate(self.checks):
            if not check(v):
                msg = msgs[i]
                if not aggressive and callable(msg):
                    msg = msg(type(v).__name__)
                return {
                    "valid": False,
                    "field": self.field_name,
                    "constraint": self.names[i],
                    "message": msg,
                }
        return {"valid": True}

    def run_all(self, value: Any, aggressive: bool) -> dict[str, Any]:
        """Run every check; report every failure."""
        v = value
        if self.transform is not None:
            try:
                v = self.transform(value)
            except Exception:
                return {"valid": False, "field": self.field_name,
                        "failures": [{"field": self.field_name, "constraint": "transform", "message": "transform failed"}]}

        if v is None:
            if self.nullable:
                return {"valid": True}
            return {"valid": False, "field": self.field_name,
                    "failures": [{"field": self.field_name, "constraint": "required", "message": "value is missing"}]}

        msgs = self.messages_agg if aggressive else self.messages_full
        failures = []
        for i, check in enumerate(self.checks):
            if not check(v):
                msg = msgs[i]
                if not aggressive and callable(msg):
                    msg = msg(type(v).__name__)
                failures.append({"field": self.field_name, "constraint": self.names[i], "message": msg})
                if self.names[i] == "type":
                    # Every remaining check assumes the type check passed
                    # (len(), comparisons, regex match, etc. on a value of
                    # the wrong type can throw or be meaningless) — stop
                    # here even in "all" mode rather than report bogus or
                    # crashing downstream constraints.
                    break
        return {"valid": len(failures) == 0, "field": self.field_name, "failures": failures}


# ----------------------------------------------------------------------
# Compile a single rule string into a _DiagnosticRule.
# ----------------------------------------------------------------------
def _compile_diagnostic_rule(rule_str: str, field_name: Optional[str] = None) -> _DiagnosticRule:
    transform, checks, nullable = compiled._compile_pipe_rule(rule_str, _fuse=False)
    type_name, meta = _extract_check_metadata(rule_str)

    # meta must align 1:1 with checks — both built from the same token walk
    # in the same left-to-right order. If a rule shape ever desyncs this,
    # fail loudly at compile time rather than silently mis-attribute.
    if len(meta) != len(checks):
        raise AssertionError(
            f"diagnostic/check misalignment for rule {rule_str!r}: "
            f"{len(meta)} metadata entries vs {len(checks)} checks"
        )

    names = [n for n, _ in meta]
    messages_full: list[Any] = []
    messages_agg: list[str] = []

    for (vname, arg) in meta:
        if vname == "type":
            messages_full.append(_resolve_type_message(type_name, arg, field_name, aggressive=False))
            messages_agg.append(_resolve_type_message(type_name, arg, field_name, aggressive=True))
        else:
            # Non-type validator messages never contain {actual} — same
            # literal serves both modes.
            m = _resolve_validator_message(vname, arg, type_name)
            messages_full.append(m)
            messages_agg.append(m)

    return _DiagnosticRule(
        checks=checks,
        names=names,
        messages_full=tuple(messages_full),
        messages_agg=tuple(messages_agg),
        type_name=type_name,
        nullable=nullable,
        transform=transform,
        field_name=field_name,
    )


# ----------------------------------------------------------------------
# Cache: (rule_cache_key, field_name) -> _DiagnosticRule
#
# Populated lazily, only on first failure (callers are expected to call
# validator() first and only reach this module when it returns False).
# Keyed the same way compiled.validator() keys its own cache, so dict-rule
# field order never causes a miss.
# ----------------------------------------------------------------------
_DIAG_CACHE: dict[tuple[str, Optional[str]], _DiagnosticRule] = {}


def _rule_cache_key(rule: str | dict) -> str:
    return rule if isinstance(rule, str) else json.dumps(rule, sort_keys=True)


def _get_diagnostic_rule(rule: str, field_name: Optional[str] = None) -> _DiagnosticRule:
    key = (_rule_cache_key(rule), field_name)
    cached = _DIAG_CACHE.get(key)
    if cached is not None:
        return cached
    dr = _compile_diagnostic_rule(rule, field_name)
    _DIAG_CACHE[key] = dr
    return dr


# ----------------------------------------------------------------------
# Dict-rule support — compiles one _DiagnosticRule per field, recursing
# into nested dicts. Mirrors compiled._compile_dict_rule's structure.
# ----------------------------------------------------------------------
def _compile_diagnostic_dict(rule: dict, prefix: str = "") -> dict[str, Any]:
    field_rules: dict[str, Any] = {}
    for field, value in rule.items():
        qualified = f"{prefix}{field}"
        if isinstance(value, dict):
            field_rules[field] = ("nested", _compile_diagnostic_dict(value, prefix=f"{qualified}."))
        else:
            field_rules[field] = ("leaf", _get_diagnostic_rule(value, field_name=qualified))
    return field_rules


def _diagnose_dict(data: Any, field_rules: dict, mode: str, aggressive: bool) -> dict[str, Any]:
    if not isinstance(data, dict):
        return {"valid": False, "failures": [{"field": None, "constraint": "type", "message": "expected dict"}]}

    if mode == "first":
        for field, (kind, fr) in field_rules.items():
            value = data.get(field)
            if kind == "nested":
                result = _diagnose_dict(value, fr, mode, aggressive)
            else:
                result = fr.run_first(value, aggressive)
            if not result["valid"]:
                return result
        return {"valid": True}
    else:
        all_failures = []
        for field, (kind, fr) in field_rules.items():
            value = data.get(field)
            if kind == "nested":
                result = _diagnose_dict(value, fr, mode, aggressive)
            else:
                result = fr.run_all(value, aggressive)
            if not result["valid"]:
                if "failures" in result:
                    all_failures.extend(result["failures"])
                else:
                    all_failures.append(result)
        return {"valid": len(all_failures) == 0, "failures": all_failures}


# ----------------------------------------------------------------------
# Public entry point
# ----------------------------------------------------------------------
def diagnose(
    value: Any,
    rule: str | dict,
    *,
    mode: str = "first",
    aggressive: bool = False,
) -> dict[str, Any]:
    """Diagnose why `value` failed `compiled.validator(rule)`.

    Intended to be called only after validator(rule)(value) has already
    returned False — this recompiles the rule into an unfused, per-constraint
    form, which is strictly slower than the fast path and is not meant to
    run on the happy path.

    mode: "first" (default) stops at the first failing constraint, matching
          validator()'s own short-circuit semantics.
          "all" runs every constraint and reports every failure.

    aggressive: False (default) — full messages, including the actual
                runtime type where relevant (e.g. "found int").
                True — generic messages only; the actual runtime value's
                type is never computed or included. Cheaper, less specific.

    Returns a dict. For string rules::

        {"valid": False, "field": None, "constraint": "min",
         "message": "value is too short (minimum length: 2)"}

    or, in mode="all"::

        {"valid": False, "field": None,
         "failures": [{"constraint": "min", "message": "..."}, ...]}

    For dict rules, returns the same shape recursively, with "field" set to
    the dotted field path (e.g. "address.zip") on each failure.
    """
    if mode not in ("first", "all"):
        raise ValueError(f"mode must be 'first' or 'all', got {mode!r}")

    if isinstance(rule, str):
        # todo: fix so field is added. currently handled in fastmodel
        dr = _get_diagnostic_rule(rule)   # ← field_name missing, defaults to None
        return dr.run_first(value, aggressive) if mode == "first" else dr.run_all(value, aggressive)

    if isinstance(rule, dict):
        key = _rule_cache_key(rule)
        cached = _DIAG_CACHE.get((key, "__dict__"))
        if cached is None:
            cached = _compile_diagnostic_dict(rule)
            _DIAG_CACHE[(key, "__dict__")] = cached
        return _diagnose_dict(value, cached, mode, aggressive)

    raise TypeError(f"diagnose expects a str or dict rule, got {type(rule).__name__!r}")
    
        
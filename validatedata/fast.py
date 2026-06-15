# fast.py – ultra‑fast validator with full error messages
from __future__ import annotations

import re
from functools import lru_cache
from typing import Any, Callable, Optional, Union, List, Dict, Tuple

from . import compiled
from .messages import error_messages as _msg
from .validatedata import _pipe_tokenize, _coerce_range_val
from .engine import register_cache_clear_callback

# ----------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------
_COMPILED_CACHE_MAX = 1024
try:
    compiled._COMPILED_CACHE_MAX = _COMPILED_CACHE_MAX
except AttributeError:
    pass

# ----------------------------------------------------------------------
# Message mapping from validator name (token key) to message key
# ----------------------------------------------------------------------
_VALIDATOR_TO_MESSAGE = {
    "length": "length_invalid",
    "min": "string_not_in_range",      # will be differentiated by type in code
    "max": "string_not_in_range",
    "between": "string_not_in_range",
    "in": "not_in_options",
    "not_in": "not_excluded",
    "contains": "missing_required_data",
    "starts_with": "does_not_startwith",
    "ends_with": "does_not_endwith",
    "re": "does_not_match_regex",
    "unique": "not_unique",
}

_TYPE_TO_MESSAGE = {
    "str": "type_invalid", "int": "type_invalid", "float": "type_invalid",
    "bool": "type_invalid", "list": "type_invalid", "tuple": "type_invalid",
    "set": "type_invalid", "dict": "type_invalid", "email": "invalid_email",
    "url": "invalid_url", "ip": "invalid_ip", "uuid": "invalid_uuid",
    "slug": "invalid_slug", "semver": "invalid_semver", "date": "invalid_date",
    "phone": "invalid_phone", "color": "invalid_color", "even": "not_even",
    "odd": "not_odd", "prime": "not_prime",
}

# OPT 1: Module-level constants — avoids re-creating frozensets on every call.
_NATIVE_NAMES = frozenset({'str', 'int', 'float', 'bool', 'list', 'tuple', 'set', 'dict'})
_COLLECTION_TYPES = frozenset({'list', 'tuple', 'set', 'dict'})

# OPT 2: Flat lookup table for min/max/between message keys — eliminates
# cascading if/elif branches inside the hot error-message path.
_RANGE_MSG_KEYS: Dict[Tuple[str, str], str] = {
    ("between", "collection"): "collection_not_in_range",
    ("between", "len"):        "string_not_in_range",
    ("between", "number"):     "number_not_in_range",
    ("min",     "collection"): "collection_too_few",
    ("min",     "len"):        "string_too_short",
    ("min",     "number"):     "number_too_small",
    ("max",     "collection"): "collection_too_many",
    ("max",     "len"):        "string_too_long",
    ("max",     "number"):     "number_too_large",
}

# ----------------------------------------------------------------------
# Structure for a compiled rule (stores fast validator + per‑check metadata)
# ----------------------------------------------------------------------
class _CompiledRule:
    __slots__ = ("fast_validator", "checks", "nullable", "type_name", "transform",
                 "validator_names", "validator_args", "custom_msg", "non_strict")
    def __init__(
        self,
        fast_validator: Callable[[Any], bool],
        checks: List[Callable[[Any], bool]],
        nullable: bool,
        type_name: str,
        transform: Callable[[Any], Any] | None,
        validator_names: List[str],
        validator_args: List[Any],
        custom_msg: Optional[str] = None,
        non_strict: bool = False,
    ):
        self.fast_validator = fast_validator
        self.checks = checks
        self.nullable = nullable
        self.type_name = type_name
        self.transform = transform
        self.validator_names = validator_names   # parallel to checks
        self.validator_args = validator_args
        self.custom_msg = custom_msg
        self.non_strict = non_strict             # True when literal_eval coercion is in play

# ----------------------------------------------------------------------
# Compile a pipe rule string into a _CompiledRule
# ----------------------------------------------------------------------
def _compile_pipe_rule_to_struct(rule_str: str) -> _CompiledRule:
    # Get fast validator from compiled.validator – this populates _COMPILED_CACHE
    fast_validator = compiled.validator(rule_str)

    # Get per‑check components for message generation (not cached by compiled)
    transform_fn, checks, nullable = compiled._compile_pipe_rule(rule_str)

    # Parse the rule string for validator names and arguments (as before)
    tokens = _pipe_tokenize(rule_str)
    _raw_type = tokens[0].strip().split(":", 1)[0]
    # Normalise parameterized types: "list[str]" → "list", "tuple[int,str]" → "tuple"
    type_name = _raw_type.split("[", 1)[0]

    # OPT 1: Use module-level _NATIVE_NAMES instead of creating a new frozenset here.
    validator_names = []
    validator_args = []
    custom_msg: Optional[str] = None
    strict_seen: bool = False
    for token in tokens[1:]:
        key, _, value = token.partition(":")
        key = key.strip()
        if key == "msg":
            custom_msg = value.strip() if value else None
        elif key == "strict":
            strict_seen = True
        elif key in _VALIDATOR_TO_MESSAGE or key in ("min", "max", "between"):
            validator_names.append(key)
            validator_args.append(value.strip() if value else None)

    # Non-strict coercion applies to native types when |strict is absent.
    # date and regex are also non-strict by engine default but use different
    # logic (no literal_eval), so they are excluded here.
    non_strict = (not strict_seen) and (type_name in _NATIVE_NAMES)

    # Align check count with validator names (prepend "type" if needed).
    # Store _raw_type (e.g. "list[str]") so error messages can display it.
    if len(checks) > len(validator_names):
        validator_names.insert(0, "type")
        validator_args.insert(0, _raw_type)

    return _CompiledRule(
        fast_validator=fast_validator,
        checks=checks,
        nullable=nullable,
        type_name=type_name,
        transform=transform_fn,
        validator_names=validator_names,
        validator_args=validator_args,
        custom_msg=custom_msg,
        non_strict=non_strict,
    )

# ----------------------------------------------------------------------
# Generate an error message for a failing check at a given index
# ----------------------------------------------------------------------
def _message_for_check_at_index(
    idx: int,
    value: Any,
    type_name: str,
    rule_struct: _CompiledRule,
) -> str:

    if rule_struct.custom_msg:
        return rule_struct.custom_msg

    validator_names = rule_struct.validator_names
    validator_args  = rule_struct.validator_args
    validator_name  = validator_names[idx] if idx < len(validator_names) else "unknown"
    arg             = validator_args[idx]  if idx < len(validator_args)  else None

    if validator_name == "type":
        if rule_struct.non_strict:
            template = _msg.get("type_coercion_failed", "value could not be coerced")
            return template.replace("{expected}", type_name)

        display_type = arg if arg and arg != type_name else type_name

        # Custom type handling
        if type_name not in _TYPE_TO_MESSAGE:
            template = _msg.get(
                "custom_type_invalid",
                f"value is not of expected type '{display_type}' (got {{actual}})"
            )
        else:
            template = _msg.get(_TYPE_TO_MESSAGE[type_name], "invalid type")

        if "{expected}" in template:
            template = template.replace("{expected}", display_type)
        if "{actual}" in template:
            template = template.replace("{actual}", type(value).__name__)
        return template

    # For min, max, between
    if validator_name in ("min", "max", "between"):
        # Use module-level constants _COLLECTION_TYPES and _LEN_TYPES (already defined)
        if type_name in _COLLECTION_TYPES:
            category = "collection"
        elif type_name in compiled._LEN_TYPES:
            category = "len"
        else:
            category = "number"
        msg_key = _RANGE_MSG_KEYS.get((validator_name, category))
        if msg_key is None:
            msg_key = "string_not_in_range"   # fallback
        template = _msg.get(msg_key, "value out of range")
        if arg:
            # For between, arg may be like "1,10" – but the stored arg is the raw string.
            if validator_name == "between" and isinstance(arg, str) and "," in arg:
                lo, hi = arg.split(",", 1)
                template = template.replace("{min}", lo.strip()).replace("{max}", hi.strip())
            else:
                template = template.replace("{min}", arg).replace("{max}", arg)
        return template

    # All other validators (length, in, contains, re, etc.)
    msg_key = _VALIDATOR_TO_MESSAGE.get(validator_name)
    if msg_key is None:
        msg_key = "validation_failed"
    template = _msg.get(msg_key, "validation failed")
    if validator_name == "length" and arg:
        template = template.replace("{expected}", arg)
    return template

# ----------------------------------------------------------------------
# Validate a single value with messages
# ----------------------------------------------------------------------
def _validate_value_with_messages(
    value: Any,
    rule_struct: _CompiledRule,
    field_name: Optional[str] = None,
) -> Tuple[bool, List[str], Any]:
    """
    Returns (ok, errors, transformed_value).
    transformed_value is the value after transform (if any), or the original value.
    """
    # Fast path
    if rule_struct.fast_validator(value):
        # fast path includes transform inside compiled callable
        return True, [], value

    # Slow path – run checks one by one
    transformed = value
    if rule_struct.transform is not None:
        try:
            transformed = rule_struct.transform(value)
        except Exception:
            msg = "transform failed"
            return False, [f"{field_name}: {msg}" if field_name else msg], value

    if transformed is None:
        if rule_struct.nullable:
            return True, [], None
        return False, [f"{field_name}: value is missing" if field_name else "value is missing"], value

    checks = rule_struct.checks
    type_name = rule_struct.type_name

    errors = []
    for i, check in enumerate(checks):
        try:
            if not check(transformed):
                msg = _message_for_check_at_index(i, transformed, type_name, rule_struct)
                if field_name:
                    msg = f"{field_name}: {msg}"
                errors.append(msg)
                break
        except Exception:
            msg = "exception during validation"
            if field_name:
                msg = f"{field_name}: {msg}"
            errors.append(msg)
            break
    return len(errors) == 0, errors, transformed

# ----------------------------------------------------------------------
# Caches
# ----------------------------------------------------------------------
@lru_cache(maxsize=_COMPILED_CACHE_MAX)
def _get_compiled_rule(rule_str: str) -> _CompiledRule:
    return _compile_pipe_rule_to_struct(rule_str)

def _hashable_dict_rule(rule: dict) -> Tuple[Tuple[str, Any], ...]:
    items = []
    for k, v in sorted(rule.items()):
        if isinstance(v, dict):
            items.append((k, _hashable_dict_rule(v)))
        elif isinstance(v, list):
            raise ValueError(f"List rules are not supported in nested dicts: {k}={v}")
        else:
            items.append((k, v))
    return tuple(items)

@lru_cache(maxsize=_COMPILED_CACHE_MAX)
def _get_compiled_dict_rule(rule_hashable: Tuple[Tuple[str, Any], ...]) -> Tuple[Callable[[Any], bool], Dict[str, Any]]:
    """Return (fast_dict_validator, {field: compiled_rule}) for a dict rule."""
    def _restore(d):
        result = {}
        for k, v in d:
            if isinstance(v, tuple) and all(isinstance(i, tuple) for i in v):
                result[k] = _restore(v)
            else:
                result[k] = v
        return result

    rule = _restore(rule_hashable)
    field_rules = {}
    for field, field_rule in rule.items():
        if isinstance(field_rule, str):
            field_rules[field] = _get_compiled_rule(field_rule)
        elif isinstance(field_rule, dict):
            nested_hashable = _hashable_dict_rule(field_rule)
            nested_fast, nested_field_rules = _get_compiled_dict_rule(nested_hashable)
            field_rules[field] = (nested_fast, nested_field_rules)
        else:
            raise TypeError(f"Unsupported rule type for field {field}: {type(field_rule)}")

    # Build fast dict validator
    field_items = []
    for field, cr in field_rules.items():
        if isinstance(cr, _CompiledRule):
            field_items.append((field, cr.fast_validator))
        elif isinstance(cr, tuple):  # nested dict
            field_items.append((field, cr[0]))
        else:
            field_items.append((field, cr))
    fast_dict_validator = compiled._make_dict_callable(
        [(f, c, False) for f, c in field_items], codegen=True
    )
    return fast_dict_validator, field_rules

# ----------------------------------------------------------------------
# Validate a dict against a dict rule with messages
# ----------------------------------------------------------------------
def _validate_mapping_with_messages(
    data: dict,
    rule: dict,
    mutate: bool = False,
) -> Tuple[bool, List[str], Optional[dict]]:
    if not isinstance(data, dict):
        return False, [f"expected dict, got {type(data).__name__}"], None

    try:
        rule_hashable = _hashable_dict_rule(rule)
    except TypeError as e:
        return False, [str(e)], None

    fast_validator, field_rules = _get_compiled_dict_rule(rule_hashable)

    if fast_validator(data):
        return True, [], data if mutate else None

    errors = []

    # OPT 3: Split mutate / non-mutate into separate loops so the per-field
    # `if mutate` branches disappear entirely from the common (non-mutate) path.
    if mutate:
        transformed: dict = {}
        for field, cr in field_rules.items():
            value = data.get(field)
            if isinstance(cr, _CompiledRule):
                ok, errs, transformed_val = _validate_value_with_messages(value, cr, field)
                if not ok:
                    errors.extend(errs)
                else:
                    transformed[field] = transformed_val
            elif isinstance(cr, tuple):  # nested dict
                if not isinstance(value, dict):
                    errors.append(f"{field}: expected dict, got {type(value).__name__}")
                    continue
                nested_ok, nested_errs, nested_transformed = _validate_mapping_with_messages(value, rule[field], mutate=True)
                if not nested_ok:
                    errors.extend(f"{field}.{e}" for e in nested_errs)
                else:
                    transformed[field] = nested_transformed
            else:
                errors.append(f"{field}: internal error")
        return len(errors) == 0, errors, transformed
    else:
        for field, cr in field_rules.items():
            value = data.get(field)
            if isinstance(cr, _CompiledRule):
                ok, errs, _ = _validate_value_with_messages(value, cr, field)
                if not ok:
                    errors.extend(errs)
            elif isinstance(cr, tuple):  # nested dict
                if not isinstance(value, dict):
                    errors.append(f"{field}: expected dict, got {type(value).__name__}")
                    continue
                nested_ok, nested_errs, _ = _validate_mapping_with_messages(value, rule[field], mutate=False)
                if not nested_ok:
                    errors.extend(f"{field}.{e}" for e in nested_errs)
            else:
                errors.append(f"{field}: internal error")
        return len(errors) == 0, errors, None

# ----------------------------------------------------------------------
# Public API
# ----------------------------------------------------------------------
def validate_data_fast(
    data: Any,
    rule: Union[str, dict, List[str]],
    raise_exceptions: bool = False,
    defaults: Optional[dict] = None,
    mutate: bool = False,
    codegen: bool = True,
    **kwds,
) -> ValidationResult:
    """Validate data with maximum speed and full error messages."""
    if isinstance(rule, list):
        if not isinstance(data, (list, tuple)):
            if len(rule) == 1:
                return validate_data_fast({"_value": data}, {"_value": rule[0]}, raise_exceptions, defaults, mutate, codegen)
            return ValidationResult(False, ["data must be list/tuple for positional rules"])
        if len(data) != len(rule):
            return ValidationResult(False, ["mismatched values and rules"])
        dict_rule = {f"f{i}": r for i, r in enumerate(rule)}
        dict_data = {f"f{i}": data[i] for i in range(len(rule))}
        return validate_data_fast(dict_data, dict_rule, raise_exceptions, defaults, mutate, codegen)

    if isinstance(rule, str):
        cr = _get_compiled_rule(rule)
        ok, errors, transformed = _validate_value_with_messages(data, cr)
        return ValidationResult(ok, errors, transformed if mutate else None)

    if isinstance(rule, dict):
        ok, errors, transformed = _validate_mapping_with_messages(data, rule, mutate)
        return ValidationResult(ok, errors, transformed)

    raise TypeError(f"Unsupported rule type: {type(rule)}")

# ----------------------------------------------------------------------
# ValidationResult
# ----------------------------------------------------------------------
#
# Todo: Consider importing class exposed in __init__.py
class ValidationResult:
    __slots__ = ("ok", "errors", "data")
    def __init__(self, ok: bool, errors: List[str], data: Optional[Any] = None):
        self.ok = ok
        self.errors = errors
        self.data = data

    # OPT 6: __bool__ lets callers write `if result:` instead of `if result.ok:`
    # with no attribute lookup overhead.
    __bool__ = lambda self: self.ok

# ----------------------------------------------------------------------
# Cache management (extends engine.cache)
# ----------------------------------------------------------------------
def _clear_fast_caches():
    _get_compiled_rule.cache_clear()
    _get_compiled_dict_rule.cache_clear()

register_cache_clear_callback(_clear_fast_caches)
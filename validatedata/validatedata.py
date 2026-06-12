from __future__ import annotations

import difflib
import inspect
import sys
import types
from collections import OrderedDict
from functools import wraps
from inspect import getfullargspec, iscoroutinefunction
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from .engine import (
    MAX_NESTING_DEPTH,
    ValidationError,
    _has_nested_rules,
    validate_object_engine,
)

if sys.version_info < (3, 8):

    def get_origin(tp):
        return getattr(tp, "__origin__", None)

    def get_args(tp):
        return getattr(tp, "__args__", ())
else:
    from typing import get_args, get_origin


class ValidationResult:
    """Return type of :func:`validate_data`.

    Attributes:
        ok: ``True`` if validation passed, ``False`` otherwise.
        errors: A list of error messages. When ``group_errors=True`` (the
            default), each entry is itself a list of strings — one sub-list
            per field. When ``group_errors=False`` errors is a flat list of
            strings.
        data: The transformed values in their original order. Only present
            when ``mutate=True`` was passed to :func:`validate_data`.
    """

    ok: bool
    errors: list[Any]
    data: list[Any]


BASIC_TYPES = (
    "bool",
    "color",
    "date",
    "email",
    "even",
    "float",
    "int",
    "ip",
    "odd",
    "phone",
    "prime",
    "semver",
    "slug",
    "str",
    "url",
    "uuid",
)
EXTENDED_TYPES = ("dict", "list", "object", "annotation", "regex", "set", "tuple")
NATIVE_TYPES = (bool, float, int, str, dict, list, set, tuple)


# ---------------------------------------------------------------------------
# Rule-key allowlist and early validation
# ---------------------------------------------------------------------------

# All keys that may legally appear in a rule dict.
# Anything ending in '-message' is also allowed (e.g. 'range-message').
VALID_RULE_KEYS: frozenset[str] = frozenset(
    {
        # identity / type
        "type",
        "object",
        # structure
        "keys",
        "fields",
        "items",
        # scalar validators
        "length",
        "range",
        "options",
        "excludes",
        "expression",
        "contains",
        "startswith",
        "endswith",
        "unique",
        # modifiers / flags
        "strict",
        "nullable",
        "format",
        "region",
        # transforms
        "transform",
        "mutate",
        # conditional
        "depends_on",
        # messages
        "message",
    }
)

_TYPE_REGISTRY: Dict[str, Callable[[Any], bool]] = {}

def register_type(name: str, checker: Callable[[Any], bool]) -> None:
    _TYPE_REGISTRY[name] = checker

def unregister_type(name: str) -> None:
    _TYPE_REGISTRY.pop(name, None)


def _check_rule_dict(rule: dict[str, Any], path: str = "") -> None:
    """Raise ValueError for any unrecognised key in a rule dict.

    Valid keys are those in VALID_RULE_KEYS plus any key ending in '-message'
    (e.g. 'range-message', 'expression-message').  For each unknown key a
    did-you-mean suggestion is included when a close match exists.
    """
    unknown = [
        k for k in rule if k not in VALID_RULE_KEYS and not k.endswith("-message")
    ]
    if not unknown:
        return

    # all_valid = list(VALID_RULE_KEYS) + ['<key>-message']
    messages = []
    for key in unknown:
        location = f" in rule at '{path}'" if path else " in rule"
        suggestion = difflib.get_close_matches(key, VALID_RULE_KEYS, n=1, cutoff=0.6)
        hint = f" Did you mean '{suggestion[0]}'?" if suggestion else ""
        messages.append(f"Unknown rule key '{key}'{location}.{hint}")

    raise ValueError("\n".join(messages))


def check_rule(rule: dict[str, Any]) -> None:
    """Validate a rule dict in isolation. Raises ValueError for unknown keys."""
    _check_rule_dict(rule)


class EmptyObject:
    def __str__(self):
        return "EmptyObject"

    def __repr__(self):
        return "EmptyObject"


EMPTY = EmptyObject()


def _extract_func_spec(
    func: Any,
    is_class: bool = False,
) -> tuple:
    """Extract the static spec from a function — run once at decoration time.

    Returns (clean_params, func_defaults, obj_is_cls).
    """
    func_defn = getfullargspec(func)
    obj_is_cls = (
        True
        if (is_class or (func_defn.args and func_defn.args[0] == "self"))
        else False
    )
    clean_params = func_defn.args[1:] if obj_is_cls else func_defn.args

    func_defaults: OrderedDict = OrderedDict()
    if func_defn.defaults:
        func_defaults.update(
            zip(clean_params[-len(func_defn.defaults) :], func_defn.defaults)
        )

    return clean_params, func_defaults, obj_is_cls


def _align_func_data(
    clean_params: list,
    func_defaults: OrderedDict,
    obj_is_cls: bool,
    obj: Any,
    args: tuple,
    kwargs: dict,
) -> tuple:
    """Align call-time arguments against the cached spec — run on every call."""
    func_data: OrderedDict = OrderedDict()
    func_data.update(zip(clean_params, [EMPTY] * len(clean_params)))

    if func_defaults:
        func_data.update(func_defaults)

    if not obj_is_cls:
        func_data[clean_params[0]] = obj

    if args:
        if obj_is_cls:
            func_data.update(zip(clean_params, args))
        else:
            func_data.update(zip(clean_params[1:], args))

    if kwargs:
        func_data.update(
            zip(
                [k for k in kwargs.keys() if k in set(func_data.keys())],
                kwargs.values(),
            )
        )

    return func_data, func_defaults, obj_is_cls


def _build_func_data(
    func: Any,
    obj: Any,
    args: tuple,
    kwargs: dict,
    is_class: bool = False,
) -> tuple:
    """Legacy single-call wrapper — used by validate_types which caches the spec itself."""
    clean_params, func_defaults, obj_is_cls = _extract_func_spec(func, is_class)
    return _align_func_data(clean_params, func_defaults, obj_is_cls, obj, args, kwargs)


def validate(
    rule: str | dict[str, Any] | list[str | dict[str, Any]],
    raise_exceptions: bool = False,
    is_class: bool = False,
    mutate: bool = False,
    **kwds: Any,
) -> Any:
    def decorator(func):
        # Extract spec once at decoration time — not on every call.
        _clean_params, _func_defaults, _obj_is_cls = _extract_func_spec(func, is_class)

        if iscoroutinefunction(func):

            @wraps(func)
            async def wrapper(obj=EMPTY, *args, **kwargs):
                func_data, func_defaults, obj_is_cls = _align_func_data(
                    _clean_params, _func_defaults, _obj_is_cls, obj, args, kwargs
                )
                result = validate_data(
                    func_data,
                    rule,
                    raise_exceptions,
                    func_defaults,
                    mutate=mutate,
                    **kwds,
                )
                if result.ok:
                    if mutate and hasattr(result, "data") and result.data:
                        transformed = result.data
                        _tvals = (
                            list(transformed.values())
                            if isinstance(transformed, dict)
                            else transformed
                        )
                        if obj_is_cls:
                            return await func(obj, *_tvals, **kwargs)
                        else:
                            return await func(*_tvals, **kwargs)
                    else:
                        if isinstance(obj, EmptyObject):
                            return await func(*args, **kwargs)
                        else:
                            return await func(obj, *args, **kwargs)
                else:
                    return {"errors": result.errors}
        else:

            @wraps(func)
            def wrapper(obj=EMPTY, *args, **kwargs):
                func_data, func_defaults, obj_is_cls = _align_func_data(
                    _clean_params, _func_defaults, _obj_is_cls, obj, args, kwargs
                )
                result = validate_data(
                    func_data,
                    rule,
                    raise_exceptions,
                    func_defaults,
                    mutate=mutate,
                    **kwds,
                )
                if result.ok:
                    if mutate and hasattr(result, "data") and result.data:
                        transformed = result.data
                        _tvals = (
                            list(transformed.values())
                            if isinstance(transformed, dict)
                            else transformed
                        )
                        if obj_is_cls:
                            return func(obj, *_tvals, **kwargs)
                        else:
                            return func(*_tvals, **kwargs)
                    else:
                        if isinstance(obj, EmptyObject):
                            return func(*args, **kwargs)
                        else:
                            return func(obj, *args, **kwargs)
                else:
                    return {"errors": result.errors}

        return wrapper

    return decorator


def _format_expected(annot: Any) -> str:
    """Human-friendly expected type representation."""
    try:
        return getattr(annot, "__name__", str(annot))
    except Exception:
        return str(annot)


def _check_generic_container(
    value: Any,
    origin: Any,
    args: tuple,
    checkers: Dict[Any, Callable],
    path: str,
    errors: list,
) -> bool:
    """Validate list/dict/tuple/set generics and append contextual errors."""
    # No type args -> just check origin
    if not args:
        try:
            if isinstance(value, origin):
                return True
            else:
                errors.append(
                    f"Expected type {_format_expected(origin)} for '{path}', got {type(value).__name__}"
                )
                return False
        except TypeError:
            errors.append(f"Unsupported type annotation at '{path}': {origin}")
            return False

    # list / Sequence: iterate elements
    if origin in (list, List):
        if not isinstance(value, (list, tuple)):
            errors.append(f"Expected list for '{path}', got {type(value).__name__}")
            return False

        elem_type = args[0]
        ok = True

        for i, v in enumerate(value):
            subpath = f"{path}[{i}]"
            if not _check_type(v, elem_type, checkers, subpath, errors):
                ok = False
        return ok

    # tuple[T1, T2, ...] or tuple[T, ...]
    if origin in (tuple, Tuple):
        if not isinstance(value, tuple):
            errors.append(f"Expected tuple for '{path}', got {type(value).__name__}")
            return False
        if len(args) == 2 and args[1] is Ellipsis:
            elem_type = args[0]
            ok = True
            for i, v in enumerate(value):
                subpath = f"{path}[{i}]"
                if not _check_type(v, elem_type, checkers, subpath, errors):
                    ok = False
            return ok

        if len(args) == len(value):
            ok = True
            for i, (v, t) in enumerate(zip(value, args)):
                subpath = f"{path}[{i}]"
                if not _check_type(v, t, checkers, subpath, errors):
                    ok = False
            return ok
        errors.append(
            f"Tuple length mismatch for '{path}': expected {len(args)}, got {len(value)}"
        )
        return False

    # dict[K, V]
    if origin in (dict,):
        if not isinstance(value, dict):
            errors.append(f"Expected dict for '{path}', got {type(value).__name__}")
            return False

        key_type = args[0] if len(args) >= 1 else Any
        val_type = args[1] if len(args) >= 2 else Any
        ok = True

        for k, v in value.items():
            key_path = f"{path}[{repr(k)}]"
            if not _check_type(k, key_type, checkers, key_path, errors):
                ok = False
            if not _check_type(v, val_type, checkers, key_path, errors):
                ok = False
        return ok

    # set[T]
    if origin in (set, frozenset):
        if not isinstance(value, (set, frozenset)):
            errors.append(f"Expected set for '{path}', got {type(value).__name__}")
            return False
        elem_type = args[0]
        ok = True
        for v in value:
            subpath = f"{path}[{repr(v)}]"
            if not _check_type(v, elem_type, checkers, subpath, errors):
                ok = False
        return ok

    # Fallback
    try:
        if isinstance(value, origin):
            return True
        errors.append(
            f"Expected type {_format_expected(origin)} for '{path}', got {type(value).__name__}"
        )
        return False
    except TypeError:
        errors.append(f"Unsupported annotation at '{path}': {origin}")
        return False


def _check_type(
    value: Any, annot: Any, checkers: Dict[Any, Callable], path: str, errors: list
) -> bool:
    """Return True if value matches annot. Append errors with context to errors list."""
    # 1. Exact match in provided checkers
    if annot in checkers:
        try:
            ok = bool(checkers[annot](value))
            if not ok:
                errors.append(
                    f"Custom checker failed for '{path}': expected {_format_expected(annot)}, got {type(value).__name__}"
                )
            return ok
        except Exception as e:
            errors.append(f"Checker error for '{path}': {e}")
            return False

    # 1b. string annotation lookup
    if isinstance(annot, str) and annot in checkers:
        try:
            ok = bool(checkers[annot](value))
            if not ok:
                errors.append(
                    f"Custom checker '{annot}' failed for '{path}', got {type(value).__name__}"
                )
            return ok
        except Exception as e:
            errors.append(f"Checker error for '{path}': {e}")
            return False

    # 2. Union / Optional
    origin = get_origin(annot)
    # Handle both typing.Union and PEP 604 union (types.UnionType)
    is_pep604_union = hasattr(types, "UnionType") and origin is types.UnionType
    if origin is Union or is_pep604_union:
        args = get_args(annot)
        # try each option; collect no error unless all fail
        sub_errors_snapshot = list(errors)
        for arg in args:
            # try without mutating errors permanently
            temp_errors = []
            if _check_type(value, arg, checkers, path, temp_errors):
                return True
        # none matched: append a combined message
        expected = " or ".join(_format_expected(a) for a in args)
        errors.append(
            f"Expected type {expected} for '{path}', got {type(value).__name__}"
        )
        return False

    # 3. Generics
    if origin is not None:
        args = get_args(annot)
        # prefer origin-level checker
        if origin in checkers:
            try:
                ok = bool(checkers[origin](value))
                if not ok:
                    errors.append(
                        f"Custom origin checker failed for '{path}': expected {_format_expected(origin)}, got {type(value).__name__}"
                    )
                return ok
            except Exception as e:
                errors.append(f"Checker error for '{path}': {e}")
                return False
        return _check_generic_container(value, origin, args, checkers, path, errors)

    # 4. Fallback isinstance
    try:
        if isinstance(value, annot):
            return True
        errors.append(
            f"Expected type {_format_expected(annot)} for '{path}', got {type(value).__name__}"
        )
        return False
    except TypeError:
        # fallback to name-based checker
        name = getattr(annot, "__name__", None) or str(annot)
        if name in checkers:
            try:
                ok = bool(checkers[name](value))
                if not ok:
                    errors.append(
                        f"Custom checker '{name}' failed for '{path}', got {type(value).__name__}"
                    )
                return ok
            except Exception as e:
                errors.append(f"Checker error for '{path}': {e}")
                return False
        errors.append(f"Unsupported annotation for '{path}': {annot}")
        return False


def validate_types(
    func: Any = None,
    raise_exceptions: bool = True,
    is_class: bool = False,
    mutate: bool = False,  # ignored – type validation cannot transform data
    type_checkers: Optional[Dict[Any, Callable[[Any], bool]]] = None,
    **kwds: Any,
) -> Callable:
    """
    Fast, pre‑compiled type‑checking decorator.

    - Uses function annotations to enforce argument types.
    - Supports Union types (e.g., `int | str` or `Union[int, str]`).
    - Ignores `mutate` and all other engine flags.
    - Returns the original function result on success, or `{'errors': [...]}` on failure.
    - Raises `ValidationError` if `raise_exceptions=True`.

    Example:
        @validate_types
        def greet(name: str, age: int = 0) -> str:
            return f"{name} is {age} years old"

        @validate_types
        def process(value: int | str) -> None:
            ...
    """

    _checkers = type_checkers or {}

    def decorator(f: Callable) -> Callable:

        # Skip if this is the autovalidate function itself
        if (
            getattr(f, "__name__", "") == "autovalidate"
            and f.__module__ == "validatedata.autovalidate"
        ):
            return f

        # --- Extract signature and pre‑compile checks once ---
        sig = inspect.signature(f)
        parameters = list(sig.parameters.values())

        # Pre‑compile list of (param_name, annotation, has_default)
        checks = []
        for param in parameters:
            if param.kind in (param.VAR_POSITIONAL, param.VAR_KEYWORD):
                # *args or **kwargs – skip type checking
                continue
            if param.annotation is param.empty:
                continue
            has_default = param.default is not param.empty
            checks.append((param.name, param.annotation, has_default))

        def check_types(bound_args: dict) -> list[str]:
            errors = []
            for name, annot, has_default in checks:
                val = bound_args.get(name)
                if val is None and has_default:
                    continue
                # start path at parameter name
                _check_type(val, annot, _checkers, name, errors)
            return errors

        # --- Sync wrapper ---
        @wraps(f)
        def wrapper(*args, **kwargs):
            # Bind arguments using the signature – this correctly maps positionals
            # and keywords, respects defaults, and handles missing arguments.
            try:
                bound = sig.bind(*args, **kwargs)
                bound.apply_defaults()
            except TypeError as e:
                # Signature mismatch (e.g., wrong number of arguments)
                if raise_exceptions:
                    raise ValidationError(str(e)) from e
                return {"errors": [str(e)]}

            errors = check_types(bound.arguments)
            if not errors:
                return f(*args, **kwargs)

            if raise_exceptions:
                raise ValidationError("\n".join(errors))
            return {"errors": errors}

        # --- Async wrapper ---
        if inspect.iscoroutinefunction(f):

            @wraps(f)
            async def async_wrapper(*args, **kwargs):
                try:
                    bound = sig.bind(*args, **kwargs)
                    bound.apply_defaults()
                except TypeError as e:
                    if raise_exceptions:
                        raise ValidationError(str(e)) from e
                    return {"errors": [str(e)]}

                errors = check_types(bound.arguments)
                if not errors:
                    return await f(*args, **kwargs)

                if raise_exceptions:
                    raise ValidationError("\n".join(errors))
                return {"errors": errors}

            return async_wrapper

        return wrapper

    # Allow @validate_types without parentheses
    if func is not None:
        return decorator(func)
    return decorator


def _expand_shorthand_rule(
    rule: str | dict[str, Any],
    path: str = "",
    depth: int = 0,
) -> dict[str, Any]:
    """Recursively convert shorthand nested dicts to {'fields': {...}} form.

    A dict whose values are field rules (no 'type', 'fields', or 'items' key) is
    treated as a nested field map and wrapped in {'fields': {...}}.  Recursion is
    capped at MAX_NESTING_DEPTH levels; a descriptive ValueError is raised if that
    limit is exceeded.
    """
    if depth >= MAX_NESTING_DEPTH:
        path_info = f" at '{path}'" if path else ""
        raise ValueError(
            f"Maximum nesting depth of {MAX_NESTING_DEPTH} exceeded{path_info}"
        )

    if isinstance(rule, str):
        return expand_rule(rule)[0]

    # Mirror list syntax: [rule] means "a list where every item matches rule"
    if isinstance(rule, list):
        if len(rule) != 1:
            raise ValueError(
                f"Mirror list syntax requires exactly one element at {repr(path) if path else 'rule root'}. "
                "For explicit list validation use: {'type': 'list', 'items': ...}"
            )
        return {
            "type": "list",
            "items": _expand_shorthand_rule(
                rule[0], f"{path}[]" if path else "[]", depth + 1
            ),
        }

    if not isinstance(rule, dict):
        return rule

    child_path = lambda k: f"{path}.{k}" if path else k  # noqa: E731

    # Shorthand: plain dict without type/fields/items — treat as nested field map
    if "type" not in rule and "fields" not in rule and "items" not in rule:
        return {
            "fields": {
                k: _expand_shorthand_rule(v, child_path(k), depth + 1)
                for k, v in rule.items()
            }
        }

    # Explicit rule dict — validate its keys before expanding further
    _check_rule_dict(rule, path=path)

    # rule with fields — recurse into field values
    if "fields" in rule:
        return {
            **rule,
            "fields": {
                k: _expand_shorthand_rule(v, child_path(k), depth + 1)
                for k, v in rule["fields"].items()
            },
        }

    # rule with items that itself has fields — recurse into those fields
    if (
        "items" in rule
        and isinstance(rule["items"], dict)
        and "fields" in rule["items"]
    ):
        items_path = f"{path}[]" if path else "[]"
        return {
            **rule,
            "items": {
                **rule["items"],
                "fields": {
                    k: _expand_shorthand_rule(v, f"{items_path}.{k}", depth + 1)
                    for k, v in rule["items"]["fields"].items()
                },
            },
        }

    return rule


def validate_data(
    data: str | list[Any] | tuple[Any, ...] | dict[str, Any],
    rule: str | dict[str, Any] | list[str | dict[str, Any]],
    raise_exceptions: bool = False,
    defaults: dict[str, Any] | None = None,
    mutate: bool = False,
    **kwds: Any,
) -> ValidationResult:
    if defaults is None:
        defaults = {}
    expanded_rule = expand_rule(rule)

    # Expand shorthand nested dicts before nested-detection so _has_nested_rules
    # only needs to understand {'fields': {...}} form.
    _was_dict_rule = False
    if isinstance(expanded_rule, (dict, OrderedDict)):
        dict_rules = []
        ordered_data = OrderedDict()
        field_map = expanded_rule["keys"] if "keys" in expanded_rule else expanded_rule
        for key in field_map:
            dict_rules.append(_expand_shorthand_rule(field_map[key], path=key))
            ordered_data[key] = data.get(key, EMPTY)
        expanded_rule = dict_rules
        data = ordered_data
        _was_dict_rule = True

    is_nested = _has_nested_rules(expanded_rule)
    result = validate_object_engine(
        data,
        expanded_rule,
        defaults,
        raise_exceptions=raise_exceptions,
        mutate=mutate,
        nested=is_nested,
        **kwds,
    )

    if mutate and _was_dict_rule and hasattr(result, "data"):
        result.data = dict(zip(data.keys(), result.data))

    return result


# ---------------------------------------------------------------------------
# Pipe-syntax shorthand parser
# ---------------------------------------------------------------------------

_PIPE_BARE_KEYWORDS = frozenset(
    {
        "strict",
        "nullable",
        "unique",
        "strip",
        "lstrip",
        "rstrip",
        "lower",
        "upper",
        "title",
    }
)

_PIPE_VALUE_KEYWORDS = frozenset(
    {
        "min:",
        "max:",
        "between:",
        "in:",
        "not_in:",
        "starts_with:",
        "ends_with:",
        "contains:",
        "format:",
        "re:",
        "msg:",
        "of:",
        "length:",
        "region:",
    }
)

_TRANSFORM_MAP = {
    "strip": str.strip,
    "lstrip": str.lstrip,
    "rstrip": str.rstrip,
    "lower": str.lower,
    "upper": str.upper,
    "title": str.title,
}

_BOOL_FLAGS = frozenset({"strict", "nullable", "unique"})

_CSV_KEYS = {"in": "options", "not_in": "excludes"}

_VALUE_KEYS = {
    "contains": "contains",
    "format": "format",
    "re": "expression",
    "starts_with": "startswith",
    "ends_with": "endswith",
}


def _is_pipe_delimiter(s, pos):
    """Return True if the | at pos is a recognised modifier boundary."""
    rest = s[pos + 1 :]
    for kw in _PIPE_VALUE_KEYWORDS:
        if rest.startswith(kw):
            return True
    for kw in _PIPE_BARE_KEYWORDS:
        if rest.startswith(kw):
            after = rest[len(kw) :]
            if after == "" or after[0] == "|":
                return True
    return False


def _pipe_tokenize(s):
    """Split s on | only where followed by a recognised modifier keyword.
    The type token is always split at the first | unconditionally."""
    first_pipe = s.find("|")
    if first_pipe == -1:
        return [s]

    tokens = [s[:first_pipe]]
    rest = s[first_pipe + 1 :]
    start = 0
    pos = rest.find("|")
    while pos != -1:
        if _is_pipe_delimiter(rest, pos):
            tokens.append(rest[start:pos])
            start = pos + 1
        pos = rest.find("|", pos + 1)
    tokens.append(rest[start:])
    return tokens


def _coerce_range_val(v: str) -> int | float | str:
    """Convert a range bound string to int, float, or leave as-is (dates, 'any')."""
    if v == "any":
        return "any"
    try:
        return float(v) if "." in v else int(v)
    except (ValueError, TypeError):
        return v


def _chain_transforms(fns: list[Any]) -> Any:
    def apply(v):
        for fn in fns:
            v = fn(v)
        return v

    return apply


def _expand_pipe_rule(rule: str) -> dict[str, Any]:
    """Parse a pipe-syntax shorthand rule string into an expanded rule dict."""
    tokens = _pipe_tokenize(rule)

    # --- type token ---
    type_token = tokens[0].strip()
    all_types = set(BASIC_TYPES + EXTENDED_TYPES)
    if type_token not in all_types:
        raise TypeError(f"{type_token!r} is not a supported type")

    rule_dict = {"type": type_token}
    transforms = []
    seen_validator = False
    min_val = None
    max_val = None

    def _require_value(k: str, v: str | None) -> str:
        if v is None:
            raise ValueError(f"{k!r} requires a value in rule: {rule!r}")
        return v

    def _split_csv(v: str) -> tuple[str, ...]:
        return tuple(item.strip() for item in v.split(","))

    for token in tokens[1:]:
        key, _, value = token.partition(":")
        key = key.strip()
        value = value or None

        # --- transforms must precede validators ---
        if key in _TRANSFORM_MAP:
            if seen_validator:
                raise ValueError(
                    f"Transform {key!r} must come before validators in rule: {rule!r}"
                )
            transforms.append(_TRANSFORM_MAP[key])
            continue

        seen_validator = True

        if key in _BOOL_FLAGS:
            rule_dict[key] = True

        elif key in _CSV_KEYS:
            rule_dict[_CSV_KEYS[key]] = _split_csv(_require_value(key, value))

        elif key in _VALUE_KEYS:
            v = _require_value(key, value)
            if key == "contains" and "," in v:
                rule_dict[_VALUE_KEYS[key]] = tuple(
                    item.strip() for item in v.split(",")
                )
            else:
                rule_dict[_VALUE_KEYS[key]] = v

        elif key == "of":
            all_types = set(BASIC_TYPES + EXTENDED_TYPES)
            values = _split_csv(_require_value(key, value))
            for t in values:
                if t not in all_types:
                    raise ValueError(
                        f"Unknown type {t!r} in of: modifier in rule: {rule!r}"
                    )
            rule_dict["items"] = values  # tuple of type name strings

        elif key == "length":
            v = _require_value(key, value)
            try:
                rule_dict["length"] = int(v)
            except (ValueError, TypeError):
                raise ValueError(
                    f'"length" requires an integer value in rule: {rule!r}'
                )

        elif key == "region":
            rule_dict["region"] = _require_value(key, value)

        elif key == "msg":
            rule_dict["message"] = value or ""

        elif key == "min":
            min_val = _require_value(key, value)

        elif key == "max":
            max_val = _require_value(key, value)

        elif key == "between":
            if min_val is not None or max_val is not None:
                raise ValueError(
                    f'Cannot combine "between" with "min" or "max" in rule: {rule!r}'
                )
            parts = value.split(",", 1) if value else []
            if len(parts) != 2:
                raise ValueError(
                    f'"between" requires two comma-separated values in rule: {rule!r}'
                )
            rule_dict["range"] = (
                _coerce_range_val(parts[0].strip()),
                _coerce_range_val(parts[1].strip()),
            )

        else:
            raise ValueError(f"Unknown modifier {key!r} in rule: {rule!r}")

    # --- resolve min/max into range ---
    if min_val is not None or max_val is not None:
        if "range" in rule_dict:
            raise ValueError(
                f'Cannot combine "between" with "min" or "max" in rule: {rule!r}'
            )
        rule_dict["range"] = (
            _coerce_range_val(min_val) if min_val is not None else "any",
            _coerce_range_val(max_val) if max_val is not None else "any",
        )

    # --- attach transforms ---
    if transforms:
        rule_dict["transform"] = (
            transforms[0] if len(transforms) == 1 else _chain_transforms(transforms)
        )

    return rule_dict


def expand_rule(
    rule: str | dict[str, Any] | list[str | dict[str, Any]],
) -> list[dict[str, Any]] | dict[str, Any]:
    expanded_rules = []

    if not isinstance(rule, (str, tuple, list, dict)):
        raise TypeError("Validation rule(s) must be of type: str, tuple, list, or dict")

    if len(str(rule)) < 2:
        raise ValueError(f"Invalid rule {rule}")

    def expand_rule_string(rule):
        if "|" in rule:
            return _expand_pipe_rule(rule)

        rule_dict = {}
        _type = rule.split(":")[0].strip() if ":" in rule else rule

        if _type not in set(BASIC_TYPES + EXTENDED_TYPES):
            raise TypeError(f"{_type} is not a supported type")

        msg = rule.split(":msg:")[1] if ":msg:" in rule else ""
        without_msg = rule.split(":msg:")[0] if msg else rule
        to_range = (
            (without_msg.split(":")[-3], without_msg.split(":")[-1])
            if ":to:" in without_msg
            else ""
        )

        rule_dict["type"], rule_dict["message"] = _type, msg

        if to_range:
            rule_dict["range"] = (to_range[0], to_range[1])

        if _type == "regex":
            if len(rule.split(":")) < 2:
                raise ValueError("No regular expression provided")
            rule_dict["expression"] = rule.split(":")[1]

        if len(rule.split(":")) >= 2 and ":to:" not in rule:
            length = rule.split(":")[1]
            if _type not in ("regex", "float") and length.isdigit():
                rule_dict["length"] = int(length)

        return rule_dict

    if isinstance(rule, str):
        expanded_rules.append(expand_rule_string(rule))

    elif isinstance(rule, (dict, OrderedDict)):
        if "keys" in rule:
            expanded_rules = rule  # canonical form: {'keys': {...}, ...}
        elif "type" in rule:
            _check_rule_dict(rule)
            expanded_rules.append(rule)  # single rule dict e.g. {'type': 'str'}
        else:
            expanded_rules = rule  # bare field-map e.g. {'username': 'str|min:3'}

    else:
        for _rule in rule:
            if isinstance(_rule, str):
                expanded_rules.append(expand_rule_string(_rule))
            elif isinstance(_rule, dict):
                _check_rule_dict(_rule)
                expanded_rules.append(_rule)
            else:
                raise TypeError("Error expanding rules: expecting string or dict")

    return expanded_rules

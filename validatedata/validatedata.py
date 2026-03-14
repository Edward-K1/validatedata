from __future__ import annotations

import difflib

from collections import OrderedDict
from functools import wraps
from inspect import getfullargspec, iscoroutinefunction
from typing import Any

from .validator import Validator, ValidationError, _has_nested_rules, MAX_NESTING_DEPTH


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
    'bool',
    'color',
    'date',
    'email',
    'even',
    'float',
    'int',
    'ip',
    'odd',
    'phone',
    'prime',
    'semver',
    'slug',
    'str',
    'url',
    'uuid',
)
EXTENDED_TYPES = ('dict', 'list', 'object', 'annotation', 'regex', 'set', 'tuple')
NATIVE_TYPES = (bool, float, int, str, dict, list, set, tuple)



# ---------------------------------------------------------------------------
# Rule-key allowlist and early validation
# ---------------------------------------------------------------------------

# All keys that may legally appear in a rule dict.
# Anything ending in '-message' is also allowed (e.g. 'range-message').
VALID_RULE_KEYS: frozenset[str] = frozenset({
    # identity / type
    'type',
    'object',
    # structure
    'keys',
    'fields',
    'items',
    # scalar validators
    'length',
    'range',
    'options',
    'excludes',
    'expression',
    'contains',
    'startswith',
    'endswith',
    'unique',
    # modifiers / flags
    'strict',
    'nullable',
    'format',
    'region',
    # transforms
    'transform',
    'mutate',
    # conditional
    'depends_on',
    # messages
    'message',
})


def _check_rule_dict(rule: dict[str, Any], path: str = '') -> None:
    """Raise ValueError for any unrecognised key in a rule dict.

    Valid keys are those in VALID_RULE_KEYS plus any key ending in '-message'
    (e.g. 'range-message', 'expression-message').  For each unknown key a
    did-you-mean suggestion is included when a close match exists.
    """
    unknown = [k for k in rule if k not in VALID_RULE_KEYS and not k.endswith('-message')]
    if not unknown:
        return

    # all_valid = list(VALID_RULE_KEYS) + ['<key>-message']
    messages = []
    for key in unknown:
        location = f" in rule at '{path}'" if path else ' in rule'
        suggestion = difflib.get_close_matches(key, VALID_RULE_KEYS, n=1, cutoff=0.6)
        hint = f" Did you mean '{suggestion[0]}'?" if suggestion else ''
        messages.append(f"Unknown rule key '{key}'{location}.{hint}")

    raise ValueError('\n'.join(messages))

def check_rule(rule: dict[str, Any]) -> None:
    """Validate a rule dict in isolation. Raises ValueError for unknown keys."""
    _check_rule_dict(rule)


class EmptyObject:
    def __str__(self):
        return 'EmptyObject'

    def __repr__(self):
        return 'EmptyObject'


EMPTY = EmptyObject()


def _build_func_data(
    func: Any,
    obj: Any,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    is_class: bool = False,
) -> tuple[OrderedDict[str, Any], OrderedDict[str, Any], bool]:
    """Extract and align positional/keyword arguments into an OrderedDict for validation."""
    func_data = OrderedDict()
    func_defaults = OrderedDict()
    func_defn = getfullargspec(func)
    obj_is_cls = True if (is_class or (func_defn.args and func_defn.args[0] == 'self')) else False
    clean_params = func_defn.args[1:] if obj_is_cls else func_defn.args

    func_data.update(zip(clean_params, [EMPTY] * len(clean_params)))

    if func_defn.defaults:
        defaults_dict = OrderedDict(
            zip(clean_params[-len(func_defn.defaults):], func_defn.defaults)
        )
        func_data.update(defaults_dict)
        func_defaults.update(defaults_dict)

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


def validate(
    rule: str | dict[str, Any] | list[str | dict[str, Any]],
    raise_exceptions: bool = False,
    is_class: bool = False,
    mutate: bool = False,
    **kwds: Any,
) -> Any:
    def decorator(func):
        if iscoroutinefunction(func):
            @wraps(func)
            async def wrapper(obj=EMPTY, *args, **kwargs):
                func_data, func_defaults, obj_is_cls = _build_func_data(
                    func, obj, args, kwargs, is_class
                )
                result = validate_data(
                    func_data, rule, raise_exceptions, func_defaults, mutate=mutate, **kwds
                )
                if result.ok:
                    if mutate and hasattr(result, 'data') and result.data:
                        transformed = result.data
                        if obj_is_cls:
                            return await func(obj, *transformed, **kwargs)
                        else:
                            return await func(*transformed, **kwargs)
                    else:
                        if isinstance(obj, EmptyObject):
                            return await func(*args, **kwargs)
                        else:
                            return await func(obj, *args, **kwargs)
                else:
                    return {'errors': result.errors}
        else:
            @wraps(func)
            def wrapper(obj=EMPTY, *args, **kwargs):
                func_data, func_defaults, obj_is_cls = _build_func_data(
                    func, obj, args, kwargs, is_class
                )
                result = validate_data(
                    func_data, rule, raise_exceptions, func_defaults, mutate=mutate, **kwds
                )
                if result.ok:
                    if mutate and hasattr(result, 'data') and result.data:
                        transformed = result.data
                        if obj_is_cls:
                            return func(obj, *transformed, **kwargs)
                        else:
                            return func(*transformed, **kwargs)
                    else:
                        if isinstance(obj, EmptyObject):
                            return func(*args, **kwargs)
                        else:
                            return func(obj, *args, **kwargs)
                else:
                    return {'errors': result.errors}

        return wrapper

    return decorator


def validate_types(
    func: Any = None,
    raise_exceptions: bool = True,
    is_class: bool = False,
    mutate: bool = False,
    **kwds: Any,
) -> Any:
    """
    Decorator that validates function arguments against their type annotations.

    Can be in any of the formats below:
        @validate_types
        @validate_types()
        @validate_types(raise_exceptions=False)
    """

    def decorator(f):
        func_defn = getfullargspec(f)
        func_annotations = OrderedDict(
            (k, v) for k, v in func_defn.annotations.items() if k != 'return'
        )
        rules = [
            {'type': 'annotation', 'object': func_annotations[key]}
            for key in func_annotations
        ]

        if iscoroutinefunction(f):
            @wraps(f)
            async def wrapper(obj=EMPTY, *args, **kwargs):
                func_data, func_defaults, obj_is_cls = _build_func_data(
                    f, obj, args, kwargs, is_class
                )
                result = validate_data(
                    func_data, rules, raise_exceptions, func_defaults, mutate=mutate, **kwds
                )
                if result.ok:
                    if mutate and hasattr(result, 'data') and result.data:
                        transformed = result.data
                        if obj_is_cls:
                            return await f(obj, *transformed, **kwargs)
                        else:
                            return await f(*transformed, **kwargs)
                    else:
                        if isinstance(obj, EmptyObject):
                            return await f(*args, **kwargs)
                        else:
                            return await f(obj, *args, **kwargs)
                else:
                    return {'errors': result.errors}
        else:
            @wraps(f)
            def wrapper(obj=EMPTY, *args, **kwargs):
                func_data, func_defaults, obj_is_cls = _build_func_data(
                    f, obj, args, kwargs, is_class
                )
                result = validate_data(
                    func_data, rules, raise_exceptions, func_defaults, mutate=mutate, **kwds
                )
                if result.ok:
                    if mutate and hasattr(result, 'data') and result.data:
                        transformed = result.data
                        if obj_is_cls:
                            return f(obj, *transformed, **kwargs)
                        else:
                            return f(*transformed, **kwargs)
                    else:
                        if isinstance(obj, EmptyObject):
                            return f(*args, **kwargs)
                        else:
                            return f(obj, *args, **kwargs)
                else:
                    return {'errors': result.errors}

        return wrapper

    # support both @validate_types and @validate_types(...)
    if func is not None:
        # called as @validate_types without brackets — func is the decorated function
        return decorator(func)

    # called as @validate_types(...) with brackets
    return decorator


def _expand_shorthand_rule(
    rule: str | dict[str, Any],
    path: str = '',
    depth: int = 0,
) -> dict[str, Any]:
    """Recursively convert shorthand nested dicts to {'fields': {...}} form.

    A dict whose values are field rules (no 'type', 'fields', or 'items' key) is
    treated as a nested field map and wrapped in {'fields': {...}}.  Recursion is
    capped at MAX_NESTING_DEPTH levels; a descriptive ValueError is raised if that
    limit is exceeded.
    """
    if depth >= MAX_NESTING_DEPTH:
        path_info = f" at '{path}'" if path else ''
        raise ValueError(
            f'Maximum nesting depth of {MAX_NESTING_DEPTH} exceeded{path_info}'
        )

    if isinstance(rule, str):
        return expand_rule(rule)[0]

    if not isinstance(rule, dict):
        return rule

    child_path = lambda k: f'{path}.{k}' if path else k  # noqa: E731

    # Shorthand: plain dict without type/fields/items — treat as nested field map
    if 'type' not in rule and 'fields' not in rule and 'items' not in rule:
        return {
            'fields': {
                k: _expand_shorthand_rule(v, child_path(k), depth + 1)
                for k, v in rule.items()
            }
        }

    # Explicit rule dict — validate its keys before expanding further
    _check_rule_dict(rule, path=path)

    # rule with fields — recurse into field values
    if 'fields' in rule:
        return {
            **rule,
            'fields': {
                k: _expand_shorthand_rule(v, child_path(k), depth + 1)
                for k, v in rule['fields'].items()
            }
        }

    # rule with items that itself has fields — recurse into those fields
    if 'items' in rule and isinstance(rule['items'], dict) and 'fields' in rule['items']:
        items_path = f'{path}[]' if path else '[]'
        return {
            **rule,
            'items': {
                **rule['items'],
                'fields': {
                    k: _expand_shorthand_rule(v, f'{items_path}.{k}', depth + 1)
                    for k, v in rule['items']['fields'].items()
                }
            }
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
    if isinstance(expanded_rule, (dict, OrderedDict)):
        dict_rules = []
        ordered_data = OrderedDict()
        field_map = expanded_rule['keys'] if 'keys' in expanded_rule else expanded_rule
        for key in field_map:
            dict_rules.append(_expand_shorthand_rule(field_map[key], path=key))
            ordered_data[key] = data.get(key, EMPTY)
        expanded_rule = dict_rules
        data = ordered_data

    is_nested = _has_nested_rules(expanded_rule)
    validator = Validator(
        NATIVE_TYPES,
        BASIC_TYPES,
        EXTENDED_TYPES,
        raise_exceptions,
        mutate=mutate,
        nested=is_nested,
        **kwds,
    )

    result = validator.validate_object(data, expanded_rule, defaults)

    return result


# ---------------------------------------------------------------------------
# Pipe-syntax shorthand parser
# ---------------------------------------------------------------------------

_PIPE_BARE_KEYWORDS = frozenset({
    'strict', 'nullable', 'unique',
    'strip', 'lstrip', 'rstrip', 'lower', 'upper', 'title',
})

_PIPE_VALUE_KEYWORDS = frozenset({
    'min:', 'max:', 'between:', 'in:', 'not_in:',
    'starts_with:', 'ends_with:', 'contains:',
    'format:', 're:', 'msg:',
})

_TRANSFORM_MAP = {
    'strip':  str.strip,
    'lstrip': str.lstrip,
    'rstrip': str.rstrip,
    'lower':  str.lower,
    'upper':  str.upper,
    'title':  str.title,
}

_BOOL_FLAGS = frozenset({'strict', 'nullable', 'unique'})

_CSV_KEYS = {'in': 'options', 'not_in': 'excludes'}

_VALUE_KEYS = {
    'contains':    'contains',
    'format':      'format',
    're':          'expression',
    'starts_with': 'startswith',
    'ends_with':   'endswith',
}


def _is_pipe_delimiter(s, pos):
    """Return True if the | at pos is a recognised modifier boundary."""
    rest = s[pos + 1:]
    for kw in _PIPE_VALUE_KEYWORDS:
        if rest.startswith(kw):
            return True
    for kw in _PIPE_BARE_KEYWORDS:
        if rest.startswith(kw):
            after = rest[len(kw):]
            if after == '' or after[0] == '|':
                return True
    return False


def _pipe_tokenize(s):
    """Split s on | only where followed by a recognised modifier keyword.
    The type token is always split at the first | unconditionally."""
    first_pipe = s.find('|')
    if first_pipe == -1:
        return [s]

    tokens = [s[:first_pipe]]
    rest = s[first_pipe + 1:]
    start = 0
    pos = rest.find('|')
    while pos != -1:
        if _is_pipe_delimiter(rest, pos):
            tokens.append(rest[start:pos])
            start = pos + 1
        pos = rest.find('|', pos + 1)
    tokens.append(rest[start:])
    return tokens


def _coerce_range_val(v: str) -> int | float | str:
    """Convert a range bound string to int, float, or leave as-is (dates, 'any')."""
    if v == 'any':
        return 'any'
    try:
        return float(v) if '.' in v else int(v)
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
        raise TypeError(f'{type_token!r} is not a supported type')

    rule_dict = {'type': type_token}
    transforms = []
    seen_validator = False
    min_val = None
    max_val = None

    def _require_value(k: str, v: str | None) -> str:
        if v is None:
            raise ValueError(f'{k!r} requires a value in rule: {rule!r}')
        return v

    def _split_csv(v: str) -> tuple[str, ...]:
        return tuple(item.strip() for item in v.split(','))

    for token in tokens[1:]:
        key, _, value = token.partition(':')
        key = key.strip()
        value = value or None

        # --- transforms must precede validators ---
        if key in _TRANSFORM_MAP:
            if seen_validator:
                raise ValueError(
                    f'Transform {key!r} must come before validators in rule: {rule!r}'
                )
            transforms.append(_TRANSFORM_MAP[key])
            continue

        seen_validator = True

        if key in _BOOL_FLAGS:
            rule_dict[key] = True

        elif key in _CSV_KEYS:
            rule_dict[_CSV_KEYS[key]] = _split_csv(_require_value(key, value))

        elif key in _VALUE_KEYS:
            rule_dict[_VALUE_KEYS[key]] = _require_value(key, value)

        elif key == 'msg':
            rule_dict['message'] = value or ''

        elif key == 'min':
            min_val = _require_value(key, value)

        elif key == 'max':
            max_val = _require_value(key, value)

        elif key == 'between':
            if min_val is not None or max_val is not None:
                raise ValueError(
                    f'Cannot combine "between" with "min" or "max" in rule: {rule!r}'
                )
            parts = value.split(',', 1) if value else []
            if len(parts) != 2:
                raise ValueError(
                    f'"between" requires two comma-separated values in rule: {rule!r}'
                )
            rule_dict['range'] = (
                _coerce_range_val(parts[0].strip()),
                _coerce_range_val(parts[1].strip()),
            )

        else:
            raise ValueError(f'Unknown modifier {key!r} in rule: {rule!r}')

    # --- resolve min/max into range ---
    if min_val is not None or max_val is not None:
        if 'range' in rule_dict:
            raise ValueError(
                f'Cannot combine "between" with "min" or "max" in rule: {rule!r}'
            )
        rule_dict['range'] = (
            _coerce_range_val(min_val) if min_val is not None else 'any',
            _coerce_range_val(max_val) if max_val is not None else 'any',
        )

    # --- attach transforms ---
    if transforms:
        rule_dict['transform'] = (
            transforms[0] if len(transforms) == 1 else _chain_transforms(transforms)
        )

    return rule_dict


def expand_rule(rule: str | dict[str, Any] | list[str | dict[str, Any]]) -> list[dict[str, Any]] | dict[str, Any]:
    expanded_rules = []

    if not isinstance(rule, (str, tuple, list, dict)):
        raise TypeError('Validation rule(s) must be of type: str, tuple, list, or dict')

    if len(str(rule)) < 2:
        raise ValueError(f'Invalid rule {rule}')

    def expand_rule_string(rule):
        if '|' in rule:
            return _expand_pipe_rule(rule)

        rule_dict = {}
        _type = rule.split(':')[0].strip() if ':' in rule else rule

        if _type not in set(BASIC_TYPES + EXTENDED_TYPES):
            raise TypeError(f'{_type} is not a supported type')

        msg = rule.split(':msg:')[1] if ':msg:' in rule else ''
        without_msg = rule.split(':msg:')[0] if msg else rule
        to_range = (
            (without_msg.split(':')[-3], without_msg.split(':')[-1])
            if ':to:' in without_msg
            else ''
        )

        rule_dict['type'], rule_dict['message'] = _type, msg

        if to_range:
            rule_dict['range'] = (to_range[0], to_range[1])

        if _type == 'regex':
            if len(rule.split(':')) < 2:
                raise ValueError('No regular expression provided')
            rule_dict['expression'] = rule.split(':')[1]

        if len(rule.split(':')) >= 2 and ':to:' not in rule:
            length = rule.split(':')[1]
            if _type not in ('regex', 'float') and length.isdigit():
                rule_dict['length'] = int(length)

        return rule_dict

    if isinstance(rule, str):
        expanded_rules.append(expand_rule_string(rule))

    elif isinstance(rule, (dict, OrderedDict)):
        if 'keys' in rule:
            expanded_rules = rule          # canonical form: {'keys': {...}, ...}
        elif 'type' in rule:
            _check_rule_dict(rule)
            expanded_rules.append(rule)    # single rule dict e.g. {'type': 'str'}
        else:
            expanded_rules = rule          # bare field-map e.g. {'username': 'str|min:3'}

    else:
        for _rule in rule:
            if isinstance(_rule, str):
                expanded_rules.append(expand_rule_string(_rule))
            elif isinstance(_rule, dict):
                _check_rule_dict(_rule)
                expanded_rules.append(_rule)
            else:
                raise TypeError('Error expanding rules: expecting string or dict')

    return expanded_rules

import ipaddress
import logging
import re
import uuid as uuid_lib

from ast import literal_eval
from collections import OrderedDict
from datetime import datetime
from dateutil.parser import parse as parse_date
from types import SimpleNamespace
from enum import Enum

from .messages import error_messages as errm


class ErrorKeys(str, Enum):
    DATE_NOT_IN_RANGE = 'date_not_in_range'
    DOES_NOT_ENDWITH = 'does_not_endwith'
    DOES_NOT_MATCH_REGEX = 'does_not_match_regex'
    DOES_NOT_STARTWITH = 'does_not_startwith'
    INVALID_COLOR = 'invalid_color'
    INVALID_DATE = 'invalid_date'
    INVALID_EMAIL = 'invalid_email'
    INVALID_IP = 'invalid_ip'
    INVALID_OBJECT = 'invalid_object'
    INVALID_OBJECT_LENGTH = 'object_length_invalid'
    INVALID_PHONE = 'invalid_phone'
    INVALID_SEMVER = 'invalid_semver'
    INVALID_SLUG = 'invalid_slug'
    INVALID_TYPE = 'type_invalid'
    INVALID_LENGTH = 'length_invalid'
    INVALID_URL = 'invalid_url'
    INVALID_UUID = 'invalid_uuid'
    LIST_OR_TUPLE_NOT_IN_RANGE = 'list_or_tuple_not_in_range'
    MISSING_REQUIRED_DATA = 'missing_required_data'
    MISSING_REQUIRED_KEYS = 'missing_required_keys'
    MISSING_REQUIRED_VALUES = 'missing_required_values'
    NOT_EVEN = 'not_even'
    NOT_ODD = 'not_odd'
    NOT_IN_OPTIONS = 'not_in_options'
    NOT_EXCLUDED = 'not_excluded'
    NOT_IN_RANGE = 'not_in_range'
    NOT_PRIME = 'not_prime'
    NOT_UNIQUE = 'not_unique'
    NUMBER_NOT_IN_RANGE = 'number_not_in_range'
    STRING_NOT_IN_RANGE = 'string_not_in_range'
    DEPENDS_ON_FAILED = 'depends_on_failed'


class ValidationError(Exception):
    pass


# --- helpers for new types ---

_URL_RE = re.compile(
    r'^(https?|ftp)://'
    r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'
    r'localhost|'
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
    r'(?::\d+)?'
    r'(?:/?|[/?]\S+)$',
    re.IGNORECASE
)

_SLUG_RE = re.compile(r'^[a-z0-9]+(?:-[a-z0-9]+)*$')

_SEMVER_RE = re.compile(
    r'^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)'
    r'(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?'
    r'(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$'
)

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
    'wheat', 'white', 'whitesmoke', 'yellow', 'yellowgreen'
}

_PHONE_E164_RE = re.compile(r'^\+[1-9]\d{6,14}$')


def _is_prime(n):
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


def _is_valid_color(value, fmt=None):
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
        bool(_HEX_COLOR_RE.match(s)) or
        bool(_RGB_COLOR_RE.match(s)) or
        bool(_HSL_COLOR_RE.match(s)) or
        s.lower() in _NAMED_COLORS
    )


def _is_valid_phone(value, fmt=None):
    s = str(value).strip()
    if fmt is None or fmt == 'e164':
        return bool(_PHONE_E164_RE.match(s))
    try:
        import phonenumbers
        try:
            parsed = phonenumbers.parse(s, None)
            return phonenumbers.is_valid_number(parsed)
        except Exception:
            return False
    except ImportError:
        raise ImportError(
            f"Phone format '{fmt}' requires the phonenumbers package. "
            "Install it with: pip install phonenumbers"
        )


def _has_nested_rules(rules):
    """Detect whether any rules contain nested field definitions."""
    if isinstance(rules, list):
        return any(
            isinstance(r, dict) and ('fields' in r or 'items' in r)
            for r in rules
        )
    if isinstance(rules, dict):
        if 'keys' in rules:
            return any(
                isinstance(v, dict) and ('fields' in v or 'items' in v)
                for v in rules['keys'].values()
            )
        return 'fields' in rules or 'items' in rules
    return False


class Validator:
    def __init__(self, native_types, basic_types, extended_types,
                 raise_exceptions, mutate=False, nested=False, **kwds):
        self.errors = []
        self.error_keys = []
        self.log_errors = False
        self.group_errors = True
        self.keys_with_defaults = {}
        self.basic_types = basic_types
        self.extended_types = extended_types
        self.raise_exceptions = raise_exceptions
        self.mutate = mutate
        self.nested = nested
        self.basic_types_plus_regex = set(basic_types + ('regex',))
        self.native_types = {f'{nt.__qualname__}': nt for nt in native_types}
        self.transformed_data = []

        if 'kwds' in kwds:
            keywords = kwds['kwds']
            self.log_errors = keywords.get('log_errors', False)
            self.group_errors = keywords.get('group_errors', True)

        self._type = None
        self.data_key = None
        self.data_value = None
        self.rule_key = None
        self.rule_value = None
        self.current_rules = None
        self.is_known_exception = False
        self.error_key = ErrorKeys.INVALID_TYPE

    def _build_path(self, parent_path, key, index=None):
        if index is not None:
            segment = f'[{index}]'
            return f'{parent_path}{segment}' if parent_path else segment
        if not parent_path:
            return str(key) if key else ''
        return f'{parent_path}.{key}' if key else parent_path

    def _append_nested_error(self, path, message):
        prefix = f'{path}: ' if path else ''
        self.errors.append(f'{prefix}{message}')

    def _store_error(self, path, message):
        """Route error to the right format based on nested mode."""
        if self.nested:
            self._append_nested_error(path, message)
        else:
            if self.group_errors:
                self.errors[-1].append(message)
            else:
                self.errors.append(message)

        if self.raise_exceptions:
            raise ValidationError(message)

    def validate_object(self, data, rules, defaults, parent_path=''):
        result = {'ok': False}

        def add_strict_rule(_rules):
            new_rules = dict(_rules)
            if _rules.get('type') not in ('date', 'regex'):
                if 'strict' not in _rules:
                    new_rules['strict'] = True
            return new_rules

        def value_is_of_type(current_rules, key, value, path=''):
            if value is None and current_rules.get('nullable', False):
                return True
            return self.is_type(
                current_rules.get('type'), value, current_rules,
                True, '', key, current_rules.get('strict', False), path=path
            )

        def apply_transform(value, rules, full_data=None):
            transform = rules.get('transform')
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

        def handle_nested_dict(value, current_rules, path):
            fields = current_rules.get('fields')
            if not fields or not isinstance(value, dict):
                return value, True
            nested_rules = list(fields.values())
            nested_data = OrderedDict(
                (k, value.get(k)) for k in fields.keys()
            )
            nested_result = self.validate_object(
                nested_data, nested_rules, {}, parent_path=path
            )
            return value, nested_result.ok

        def handle_nested_list(value, current_rules, path):
            items_rule = current_rules.get('items')
            if not items_rule or not isinstance(value, (list, tuple)):
                return value, True
            all_ok = True
            for i, item in enumerate(value):
                item_path = f'{path}[{i}]'
                item_rules = add_strict_rule(dict(items_rule))
                if items_rule.get('fields') and isinstance(item, dict):
                    _, ok = handle_nested_dict(item, items_rule, item_path)
                    if not ok:
                        all_ok = False
                else:
                    if not self.is_type(
                        items_rule.get('type'), item, item_rules,
                        True, '', '', item_rules.get('strict', False),
                        path=item_path
                    ):
                        all_ok = False
                    else:
                        self.validate_rule('', item, item_rules, path=item_path)
            return value, all_ok

        if isinstance(data, OrderedDict):
            full_data = dict(data)

            if defaults:
                self.keys_with_defaults = set(defaults.keys())

            for index, (key, value) in enumerate(data.items()):
                path = self._build_path(parent_path, key)

                if not self.nested:
                    if self.group_errors:
                        self.errors.append([])

                if key in self.keys_with_defaults:
                    if value == defaults.get(key):
                        self.transformed_data.append(value)
                        continue

                current_rules = add_strict_rule(rules[index])
                transformed_value = apply_transform(value, current_rules, full_data)

                if not self._check_depends_on(current_rules, key, transformed_value, full_data):
                    self.transformed_data.append(transformed_value if self.mutate else value)
                    continue

                if current_rules.get('fields'):
                    handle_nested_dict(transformed_value, current_rules, path)
                    self.transformed_data.append(transformed_value if self.mutate else value)
                    continue

                if current_rules.get('items'):
                    handle_nested_list(transformed_value, current_rules, path)
                    self.transformed_data.append(transformed_value if self.mutate else value)
                    continue

                if not value_is_of_type(current_rules, key, transformed_value, path=path):
                    self.transformed_data.append(transformed_value if self.mutate else value)
                    continue

                self.validate_rule(key, transformed_value, current_rules, path=path)
                self.transformed_data.append(transformed_value if self.mutate else value)

        elif isinstance(data, (list, tuple)):
            for count, value in enumerate(data):
                path = self._build_path(parent_path, '', index=count) if self.nested else ''

                if not self.nested:
                    if self.group_errors:
                        self.errors.append([])

                current_rules = add_strict_rule(rules[count])
                transformed_value = apply_transform(value, current_rules)

                if current_rules.get('fields'):
                    handle_nested_dict(transformed_value, current_rules, path)
                    self.transformed_data.append(transformed_value if self.mutate else value)
                    continue

                if current_rules.get('items'):
                    handle_nested_list(transformed_value, current_rules, path)
                    self.transformed_data.append(transformed_value if self.mutate else value)
                    continue

                if not value_is_of_type(current_rules, '', transformed_value, path=path):
                    self.transformed_data.append(transformed_value if self.mutate else value)
                    continue

                self.validate_rule('', transformed_value, current_rules, path=path)
                self.transformed_data.append(transformed_value if self.mutate else value)

        elif isinstance(data, str):
            self.group_errors = False
            current_rules = add_strict_rule(rules[0])
            transformed_value = apply_transform(data, current_rules)
            self.validate_rule('', transformed_value, current_rules, path=parent_path)
            self.transformed_data.append(transformed_value if self.mutate else data)

        else:
            raise TypeError(
                'the data parameter should be a string, list, tuple, or dict')

        result['errors'] = self.errors

        if self.nested:
            result['ok'] = len(self.errors) == 0
        else:
            result['ok'] = len(self.errors) == 0 or all(x == [] for x in self.errors)

        if self.mutate:
            result['data'] = self.transformed_data

        return SimpleNamespace(**result)

    def _check_depends_on(self, rules, key, value, full_data):
        depends_on = rules.get('depends_on')
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

    def raise_known_exception(self, message, ex_type=ValidationError):
        self.is_known_exception = True
        raise ex_type(message)

    def set_validation_data(self, **kwargs):
        self.data_key = kwargs['data_key']
        self.data_value = kwargs['data_value']
        self.rule_key = kwargs['rule_key']
        self.rule_value = kwargs['rule_value']
        self.current_rules = kwargs['all_rules']
        self._type = kwargs['all_rules']['type']

    def _get_error_message(self, error_key, rules, field='', rule_key=''):
        raw_error = errm.get(f'field_{error_key}', '') if field else ''
        raw_error = raw_error or errm.get(error_key, '') or errm['no_error_message']
        custom_message = rules.get(f'{rule_key}-message', '') or rules.get('message', '')
        return custom_message or raw_error

    def append_error(self, path='', **kwargs):
        key = self.data_key
        rules = self.current_rules
        rule_key = self.rule_key
        error_key = self.error_key
        message = self._get_error_message(error_key, rules, key, rule_key)
        self._store_error(path or key, message)

    def validate_length(self, path='', **kwargs):
        self.set_validation_data(**kwargs)
        self.error_key = ErrorKeys.INVALID_LENGTH
        if not isinstance(kwargs['rule_value'], int):
            self.raise_known_exception('int value expected for length')
        if self._type in self.basic_types_plus_regex:
            if len(f"{self.data_value}") != self.rule_value:
                self.append_error(path=path)
        else:
            self.error_key = ErrorKeys.INVALID_OBJECT_LENGTH
            if hasattr(self.data_value, '__len__'):
                if len(self.data_value) != self.rule_value:
                    self.append_error(path=path)
            else:
                self.append_error(path=path)

    def validate_contains(self, path='', **kwargs):
        self.set_validation_data(**kwargs)
        self.error_key = ErrorKeys.MISSING_REQUIRED_DATA
        if isinstance(self.rule_value, str):
            if self._type in self.basic_types_plus_regex:
                if self.rule_value not in str(self.data_value):
                    self.append_error(path=path)
            elif self._type == 'dict':
                self.error_key = ErrorKeys.MISSING_REQUIRED_KEYS
                if self.rule_value not in self.data_value:
                    self.append_error(path=path)
            else:
                self.error_key = ErrorKeys.MISSING_REQUIRED_VALUES
                if self.rule_value not in set(self.data_value):
                    self.append_error(path=path)
        else:
            if isinstance(self.rule_value, (list, tuple)):
                if self._type in self.basic_types_plus_regex:
                    if not all(val in str(self.data_value) for val in self.rule_value):
                        self.append_error(path=path)
                elif self._type == 'dict':
                    self.error_key = ErrorKeys.MISSING_REQUIRED_KEYS
                    if not all(val in set(self.data_value.keys()) for val in self.rule_value):
                        self.append_error(path=path)
                else:
                    self.error_key = ErrorKeys.MISSING_REQUIRED_VALUES
                    if not all(val in set(self.data_value) for val in self.rule_value):
                        self.append_error(path=path)

    def validate_excludes(self, path='', **kwargs):
        self.set_validation_data(**kwargs)
        self.error_key = ErrorKeys.NOT_EXCLUDED
        if self._type in self.basic_types_plus_regex:
            if self.data_value in set(self.rule_value):
                self.append_error(path=path)
        else:
            if any(val in set(self.data_value) for val in self.rule_value):
                self.append_error(path=path)

    def validate_options(self, path='', **kwargs):
        self.set_validation_data(**kwargs)
        self.error_key = ErrorKeys.NOT_IN_OPTIONS
        if self._type in self.basic_types_plus_regex:
            if self.data_value not in set(self.rule_value):
                self.append_error(path=path)
        else:
            if not all(val in set(self.rule_value) for val in self.data_value):
                self.append_error(path=path)

    def validate_expression(self, path='', **kwargs):
        self.set_validation_data(**kwargs)
        self.error_key = ErrorKeys.DOES_NOT_MATCH_REGEX
        try:
            regex = re.compile(self.rule_value, re.VERBOSE)
        except Exception as ex:
            self.raise_known_exception(f'error compiling regex: {ex}')
        if regex.match(self.data_value) is None:
            self.append_error(path=path)

    def validate_range(self, path='', **kwargs):
        self.set_validation_data(**kwargs)
        self.error_key = ErrorKeys.NOT_IN_RANGE
        if not isinstance(self.rule_value, (list, tuple)):
            self.raise_known_exception('list or tuple expected for range')
        if len(self.rule_value) != 2:
            self.raise_known_exception('range object should have 2 values')

        if self._type == 'str':
            self.error_key = ErrorKeys.STRING_NOT_IN_RANGE
            if not (len(self.data_value) >= self.rule_value[0] and
                    len(self.data_value) <= self.rule_value[1]):
                self.append_error(path=path)

        elif self._type == 'date':
            self.error_key = ErrorKeys.DATE_NOT_IN_RANGE
            cast_date = self.data_value if isinstance(
                self.data_value, datetime) else parse_date(self.data_value)
            if isinstance(self.data_value, datetime):
                min_date = self.data_value if self.rule_value[0] == 'any' else parse_date(self.rule_value[0])
                max_date = self.data_value if self.rule_value[1] == 'any' else parse_date(self.rule_value[1])
            else:
                min_date = parse_date(self.data_value) if self.rule_value[0] == 'any' else parse_date(self.rule_value[0])
                max_date = parse_date(self.data_value) if self.rule_value[1] == 'any' else parse_date(self.rule_value[1])
            if not (cast_date >= min_date and cast_date <= max_date):
                self.append_error(path=path)

        elif self._type in ('list', 'tuple'):
            self.error_key = ErrorKeys.LIST_OR_TUPLE_NOT_IN_RANGE
            if not (len(self.data_value) >= self.rule_value[0] and
                    len(self.data_value) <= self.rule_value[1]):
                self.append_error(path=path)

        elif self._type in ('int', 'float', 'even', 'odd'):
            self.error_key = ErrorKeys.NUMBER_NOT_IN_RANGE
            min_value = float('-inf') if self.rule_value[0] == 'any' else self.rule_value[0]
            max_value = float('inf') if self.rule_value[1] == 'any' else self.rule_value[1]
            cast_value = literal_eval(str(self.data_value))
            if not (cast_value >= float(min_value) and cast_value <= float(max_value)):
                self.append_error(path=path)

    def validate_startswith(self, path='', **kwargs):
        self.set_validation_data(**kwargs)
        self.error_key = ErrorKeys.DOES_NOT_STARTWITH
        if self._type in self.basic_types_plus_regex:
            if not str(self.data_value).startswith(self.rule_value):
                self.append_error(path=path)
        else:
            if self._type in ('list', 'tuple'):
                if not self.data_value or self.data_value[0] != self.rule_value:
                    self.append_error(path=path)

    def validate_endswith(self, path='', **kwargs):
        self.set_validation_data(**kwargs)
        self.error_key = ErrorKeys.DOES_NOT_ENDWITH
        if self._type in self.basic_types_plus_regex:
            if not str(self.data_value).endswith(self.rule_value):
                self.append_error(path=path)
        else:
            if self._type in ('list', 'tuple'):
                if not self.data_value or self.data_value[-1] != self.rule_value:
                    self.append_error(path=path)

    def validate_unique(self, path='', **kwargs):
        self.set_validation_data(**kwargs)
        self.error_key = ErrorKeys.NOT_UNIQUE
        if self._type in ('list', 'tuple', 'set'):
            if len(self.data_value) != len(set(self.data_value)):
                self.append_error(path=path)

    def validate_unknown(self, path='', **kwargs):
        pass

    def validate_rule(self, key, value, rules, path=''):
        rule_map = {
            'range': self.validate_range,
            'length': self.validate_length,
            'contains': self.validate_contains,
            'excludes': self.validate_excludes,
            'options': self.validate_options,
            'expression': self.validate_expression,
            'startswith': self.validate_startswith,
            'endswith': self.validate_endswith,
            'unique': self.validate_unique,
            'unknown': self.validate_unknown,
        }

        rule_set = set(rule_map.keys())
        non_rule_keys = {
            'type', 'strict', 'message', 'nullable', 'transform', 'mutate',
            'depends_on', 'object', 'format', 'region', 'fields', 'items'
        }

        def is_message_key(k):
            return k.endswith('-message')

        for rule_key, rule_value in rules.items():
            if rule_key in non_rule_keys or is_message_key(rule_key):
                continue
            try:
                if rule_key in rule_set:
                    rule_map[rule_key](
                        rule_key=rule_key,
                        rule_value=rule_value,
                        data_key=key,
                        data_value=value,
                        all_rules=rules,
                        path=path
                    )
            except ValidationError:
                raise
            except Exception as ex:
                if self.is_known_exception:
                    self.is_known_exception = False
                    raise
                else:
                    if self.log_errors:
                        logging.warning(str(ex))
                    self.append_error(path=path)

    def is_type(self, data_type, data, rules, append_errors=False,
                message='', field_name='', strict=False, path=''):

        status = False

        def append_type_error(error_key=ErrorKeys.INVALID_TYPE):
            true_type = data_type
            if true_type == 'annotation':
                true_type = rules['object'].__qualname__

            raw_error = errm.get(f'field_{error_key}', '') if field_name else ''
            raw_error = raw_error or errm.get(error_key, '') or errm['no_error_message']
            custom_message = rules.get('type-message', '') or rules.get('message', '')

            if error_key == ErrorKeys.INVALID_TYPE:
                ev = (true_type, type(data).__qualname__)
                error_fields = (ev[0], field_name, ev[1]) if field_name else ev
                formatted = custom_message or raw_error % error_fields
            else:
                formatted = custom_message or raw_error

            if append_errors:
                self._store_error(path or field_name, formatted)

        try:
            if data_type in set(self.native_types.keys()):
                if not strict:
                    try:
                        coerced_type = literal_eval(str(data))
                        expected_type = self.native_types.get(data_type)
                        if not isinstance(coerced_type, expected_type):
                            append_type_error()
                    except (TypeError, ValueError):
                        append_type_error()
                else:
                    if not isinstance(data, self.native_types.get(data_type)):
                        append_type_error()

            elif data_type == 'date':
                if not isinstance(data, datetime):
                    if not isinstance(parse_date(data), datetime):
                        append_type_error(ErrorKeys.INVALID_DATE)

            elif data_type == 'email':
                email_re = re.compile(
                    r"""^(([^<>()\[\]\\.,;:\s@\"]+(\.[^<>()\[\]\\.,;:\s@\"]+)*)
                |(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])
                |(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$""", re.VERBOSE)
                if email_re.match(str(data)) is None:
                    append_type_error(ErrorKeys.INVALID_EMAIL)

            elif data_type == 'even':
                if not (self.is_type('int', data, rules, strict=strict) and int(data) % 2 == 0):
                    append_type_error(ErrorKeys.NOT_EVEN)

            elif data_type == 'odd':
                if not (self.is_type('int', data, rules, strict=strict) and int(data) % 2 == 1):
                    append_type_error(ErrorKeys.NOT_ODD)

            elif data_type == 'prime':
                if not _is_prime(data):
                    append_type_error(ErrorKeys.NOT_PRIME)

            elif data_type == 'url':
                if _URL_RE.match(str(data)) is None:
                    append_type_error(ErrorKeys.INVALID_URL)

            elif data_type == 'ip':
                try:
                    ipaddress.ip_address(str(data))
                except ValueError:
                    append_type_error(ErrorKeys.INVALID_IP)

            elif data_type == 'uuid':
                try:
                    uuid_lib.UUID(str(data))
                except ValueError:
                    append_type_error(ErrorKeys.INVALID_UUID)

            elif data_type == 'slug':
                if _SLUG_RE.match(str(data)) is None:
                    append_type_error(ErrorKeys.INVALID_SLUG)

            elif data_type == 'semver':
                if _SEMVER_RE.match(str(data)) is None:
                    append_type_error(ErrorKeys.INVALID_SEMVER)

            elif data_type == 'color':
                fmt = rules.get('format')
                if not _is_valid_color(data, fmt):
                    append_type_error(ErrorKeys.INVALID_COLOR)

            elif data_type == 'phone':
                fmt = rules.get('format')
                try:
                    if not _is_valid_phone(data, fmt):
                        append_type_error(ErrorKeys.INVALID_PHONE)
                except ImportError as e:
                    self.raise_known_exception(str(e), ImportError)

            elif data_type == 'object':
                if not isinstance(data, rules['object']):
                    append_type_error(ErrorKeys.INVALID_OBJECT)

            elif data_type == 'annotation':
                if not isinstance(data, rules['object']):
                    append_type_error(ErrorKeys.INVALID_TYPE)

            status = True

        except (ValidationError, ImportError):
            raise
        except Exception as ex:
            if self.log_errors:
                logging.warning(str(ex))
            append_type_error()

        return status

    def format_error(self, error_key, error_values=[], rules={}, field='',
                     rule_key='', append_errors=True,
                     raised_exception_type=ValidationError):
        raw_error = errm.get(f'field_{error_key}', '') if field else ''
        raw_error = raw_error or errm.get(error_key, '') or errm['no_error_message']
        custom_message = rules.get(f'{rule_key}-message', '') or rules.get('message', '')

        if error_key == ErrorKeys.INVALID_TYPE:
            ev = error_values
            error_fields = (ev[0], field, ev[1]) if field else (ev[0], ev[1])
            formatted_message = custom_message or raw_error % error_fields
        else:
            formatted_message = custom_message or raw_error

        return formatted_message

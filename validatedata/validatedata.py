from collections import OrderedDict
from functools import wraps
from inspect import getfullargspec

from .validator import Validator

BASIC_TYPES = ('bool', 'date', 'email', 'even', 'float', 'int', 'odd', 'str')
EXTENDED_TYPES = ('dict', 'list', 'regex', 'set', 'tuple')
NATIVE_TYPES = (bool, float, int, str, dict, list, set, tuple)


class ValidationNull:
    def __str__(self):
        return 'ValidationNull'

    def __repr__(self):
        return 'ValidationNull'


VNULL = ValidationNull()


def validate(rule, raise_exceptions=False, is_class=False, **kwds):
    def decorator(func):
        @wraps(func)
        def wrapper(obj=VNULL, *args, **kwargs):
            func_data = OrderedDict()
            func_defaults = OrderedDict()
            func_defn = getfullargspec(func)
            obj_is_cls = True if (is_class == True
                                  or func_defn.args[0] == 'self') else False
            clean_params = func_defn.args[1:] if obj_is_cls else func_defn.args

            # initialize keys with empty strings
            func_data.update(
                zip(clean_params, ['' for x in range(len(clean_params))]))

            # assign default values to keys that had them
            if func_defn.defaults:
                defaults_dict = OrderedDict(
                    zip(clean_params[-len(func_defn.defaults):],
                        func_defn.defaults))
                func_data.update(defaults_dict)
                func_defaults.update(defaults_dict)

            # if obj is not a class, it contains the value of the first parameter
            if not obj_is_cls:
                func_data[clean_params[0]] = obj

            if args:
                if obj_is_cls:
                    func_data.update(zip(clean_params, args))
                else:
                    func_data.update(zip(clean_params[1:], args))

            if kwargs:
                func_data.update(
                    zip([
                        k for k in kwargs.keys() if k in set(func_data.keys())
                    ], kwargs.values()))

            result = validate_data(func_data, rule, raise_exceptions,
                                   func_defaults, **kwds)

            if result.ok:
                if isinstance(obj, ValidationNull):
                    return func(*args, **kwargs)
                else:

                    return func(obj, *args, **kwargs)
            else:
                return {'errors': result.errors}

        return wrapper

    return decorator


def validate_data(data, rule, raise_exceptions=False, defaults={}, **kwds):

    validator = Validator(NATIVE_TYPES, BASIC_TYPES, EXTENDED_TYPES,
                          raise_exceptions, **kwds)
    expanded_rule = expand_rule(rule)

    if isinstance(expanded_rule, (dict, OrderedDict)):
        dict_rules = []
        ordered_data = OrderedDict()
        for key in expanded_rule['keys']:
            dict_rules.append(expanded_rule['keys'][key])
            ordered_data[key] = data.get(key, '')

        expanded_rule = dict_rules
        data = ordered_data

    result = validator.validate_object(data, expanded_rule, defaults)

    return result


def expand_rule(rule):
    expanded_rules = []

    if not isinstance(rule, (str, tuple, list, dict)):
        raise TypeError(
            'Validation rule(s) must be of type: str, tuple, list, or dict')

    if len(str(rule)) < 3:
        raise ValueError(f'Invalid rule {rule}')

    def expand_rule_string(rule):
        rule_dict = {}
        _type = rule.split(':')[0].strip() if ':' in rule else rule

        if _type not in set(BASIC_TYPES + EXTENDED_TYPES):
            raise TypeError(f'{_type} is not a supported type')

        msg = rule.split(':msg:')[1] if ':msg:' in rule else ''
        without_msg = rule.split(':msg:')[0] if msg else rule
        to_range = (
            without_msg.split(':')[-3],
            without_msg.split(':')[-1]) if ':to:' in without_msg else ''

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
        if 'keys' not in rule:
            expanded_rules.append(rule)
        else:
            expanded_rules = rule

    else:
        for _rule in rule:
            if isinstance(_rule, str):
                expanded_rules.append(expand_rule_string(_rule))

            elif isinstance(_rule, dict):

                expanded_rules.append(_rule)

            else:
                raise TypeError(
                    'Error expanding rules: expecting string or dict')

    return expanded_rules

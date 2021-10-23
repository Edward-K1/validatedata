from collections import OrderedDict
from functools import wraps
from inspect import getfullargspec

from .validator import Validator

_BASIC_TYPES = ('bool', 'date', 'email', 'even', 'float', 'int', 'odd', 'str')
_EXTENDED_TYPES = ('dict', 'list', 'regex', 'set', 'tuple')
_NATIVE_TYPES = (bool, float, int, str, dict, list, set, tuple)


def validate(rule, raise_exceptions=False, is_class=False):
    def decorator(func):
        @wraps(func)
        def wrapper(obj, *args, **kwargs):
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
                                   func_defaults)

            if result.ok:
                return func(obj, *args, **kwargs)
            else:
                return {'errors': result.errors}

        return wrapper

    return decorator


def validate_data(data, rule, raise_exceptions=False, defaults={}):

    validator = Validator(_NATIVE_TYPES, _BASIC_TYPES, _EXTENDED_TYPES,
                          raise_exceptions)
    expanded_rule = expand_rule(rule)

    result = validator.validate_object(data, expanded_rule, defaults)

    return result


def expand_rule(rule):
    expanded_rules = []

    if not isinstance(rule, (str, tuple, dict)):
        raise TypeError(
            'Validation rule(s) must be of type: str, tuple, or dict')

    if len(str(rule)) < 3:
        raise ValueError(f'Invalid rule {rule}')

    def expand_rule_string(rule):
        rule_dict = {}
        _type = rule.split(':')[0].strip() if ':' in rule else rule

        if _type not in set(_BASIC_TYPES + _EXTENDED_TYPES):
            raise TypeError(f'{_type} is not a supported type')

        msg = rule.split(':msg:')[1] if ':msg:' in rule else ''
        without_msg = rule.split(':msg:')[0] if msg else rule
        to_range = (
            without_msg.split(':')[-3],
            without_msg.split(':')[-1]) if ':to:' in without_msg else ''

        rule_dict['type'], rule_dict['message'] = _type, msg

        if to_range:
            rule_dict['range'] = (to_range[0], to_range[1])

        if _type in {'int', 'float'}:
            rule_dict['strict'] = True if ':strict' in rule else False

        # prevent ast.literal_eval on object data if user hasn't requested for it
        if _type in {'bool', 'dict', 'list', 'set', 'tuple'}:
            rule_dict['strict'] = True

        if _type == 'regex':
            if len(rule.split(':')) < 2:
                raise ValueError('No regex string provided')

            rule_dict['expression'] = rule.split(':')[1]

        if len(rule.split(':')) >= 2:
            length = rule.split(':')[1]
            if _type not in {'regex', 'float'} and length.isdigit():
                rule_dict['length'] = int(length)

        return rule_dict

    if isinstance(rule, str):
        expanded_rules = expand_rule_string(rule)

    elif isinstance(rule, dict):
        expanded_rules = rule

    else:
        for _rule in rule:
            if isinstance(_rule, str):
                expanded_rules.append(expand_rule_string(_rule))

            elif isinstance(_rule, dict):
                new_rule = _rule
                if _rule.get('type') in {
                        'bool', 'dict', 'list', 'set', 'tuple'
                }:
                    if 'strict' not in _rule:
                        new_rule['strict'] = True
                expanded_rules.append(new_rule)

            else:
                raise TypeError(
                    'Error expanding rules: expecting string or dict')

    return expanded_rules

from functools import wraps

from .validator import Validator

_BASIC_TYPES = ('bool', 'date', 'email', 'even', 'float', 'int', 'odd', 'str')
_EXTENDED_TYPES = ('dict', 'list', 'regex', 'set', 'tuple')


def validate(rule, message='', data=':*params:', raise_exceptions=False):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            result = validate_data(data, rule, message, raise_exceptions, func)
            if result.ok:
                return func(*args, **kwargs)
            else:
                return {'errors': result.errors}

        return wrapper

    return decorator


def validate_data(data, rule, message='', raise_exceptions=False, func=None):
    errors = []
    result = {'ok': False}

    validator = Validator(_BASIC_TYPES, _EXTENDED_TYPES, raise_exceptions)
    _type, expanded_rule = expand_rule(rule)

    type_map = {
        'bool': validator.validate_bool,
        'date': validator.validate_date,
        'dict': validator.validate_dict,
        'email': validator.validate_email,
        'even': validator.validate_number,
        'float': validator.validate_number,
        'int': validator.validate_number,
        'list': validator.validate_container,
        'odd': validator.validate_number,
        'str': validator.validate_string,
        'regex': validator.validate_regex,
        'set': validator.validate_container,
        'tuple': validator.validate_container
    }

    if len(validator.errors) == 0:
        result.ok = True
    else:
        result['errors'] = errors + validator.errors
    return result


def expand_rule(rule):
    expanded_rules = []

    if not isinstance(rule, (str, list, tuple, dict)):
        raise TypeError(
            'Validation rule must be of type: str, list, tuple, or dict')

    if len(str(rule)) < 3:
        raise ValueError('Invalid rule')




    def expand_rule_string(rule):
        rule_dict = {}
        _type = rule.split(':')[0] if ':' in rule else rule

        if _type not in _BASIC_TYPES + _EXTENDED_TYPES:
            raise TypeError(f'{_type} is not supported')

        message = rule.split(':msg:')[1] if ':msg:' in rule else ''
        without_msg = rule.split(':msg:')[0] if message else rule
        to_range = without_msg.split(':')[-3], without_msg.split(
            ':')[-1] if ':to:' in without_msg else ''

        rule_dict['type'], rule_dict['message'] = _type, message

        if to_range:
            rule_dict['range'] = (to_range[0], to_range[1])

        if _type in ('int', 'float'):
            rule_dict['strict'] = True if ':strict:' in rule else False

        if _type == 'regex':
            if len(rule.split(':')) < 2:
                raise ValueError('No regex string provided')

            rule_dict['expression'] = rule.split(':')[1]

        if len(rule.split(':')) == 2:
            length = rule.split(':')[1]
            if _type not in ('regex', 'float', 'date') and length.isdigit():
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
                expanded_rules.append(_rule)

            else:
                raise TypeError(
                    'Error expanding rules: unsupported type in list')

    return expanded_rules

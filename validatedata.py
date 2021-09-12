from functools import wraps

from .validator import Validator


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
    basic_types = ('bool', 'date', 'email', 'even', 'float', 'int', 'odd', 'str')
    extended_types = ('dict', 'list', 'regex', 'set', 'tuple')

    validator = Validator(basic_types, extended_types, raise_exceptions)
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

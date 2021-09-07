from functools import wraps

from .validator import Validator


def validate(data, type, rule='', message='', raise_exceptions=False):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            result = validate_data(data, type, rule, message, raise_exceptions)
            if result.ok:
                return func(*args, **kwargs)
            else:
                return {'errors': result.errors}

        return wrapper

    return decorator


def validate_data(data, type, rule='', message='', raise_exceptions=False):
    errors = []
    result = {'ok': False}
    basic_types = ['date', 'email', 'even', 'float', 'int', 'odd', 'str']
    extended_types = ['dict', 'list', 'regex', 'set', 'tuple']

    validator = Validator(basic_types, extended_types, raise_exceptions)

    type_map = {
        'date': validator.validate_date,
        'email': validator.validate_email,
        'even': validator.validate_number,
        'float': validator.validate_number,
        'int': validator.validate_number,
        'odd': validator.validate_number,
        'str': validator.validate_string,
        'dict': validator.validate_dict,
        'list': validator.validate_collection,
        'regex': validator.validate_regex,
        'set': validator.validate_collection,
        'tuple': validator.validate_collection
    }

    if len(errors) == 0:
        result.ok = True
    else:
        result['errors'] = errors
    return result

import re

from ast import literal_eval
from collections import OrderedDict
from datetime import datetime
from dateutil.parser import parse as parse_date
from types import SimpleNamespace

from messages import error_messages as errm

_ALL_RULES = {
    'length', 'contains', 'excludes', 'options', 'strict', 'expression',
    'type', 'range', 'startswith', 'endswith'
}


class Validator:
    def __init__(self, native_types, basic_types, extended_types,
                 raise_exceptions):
        self.errors = []
        self.keys_with_defaults = {}
        self.basic_types = basic_types
        self.extended_types = extended_types
        self.raise_exceptions = raise_exceptions
        self.basic_types_plus_regex = set(basic_types + ('regex'))
        self.native_types = {f'{nt.__qualname__}': nt for nt in native_types}

    def validate_object(self, data, rules, defaults):
        result = {'ok': False}
        if isinstance(data, OrderedDict):
            if defaults:
                self.keys_with_defaults = set(defaults.keys())

            for index, (key, value) in enumerate(data.items()):
                if key in self.keys_with_defaults:
                    # skip default values
                    if value == defaults.get(key): continue

                self.validate_rule(key, value, rules[index])

        elif isinstance(data, (list, tuple)):
            pass

        elif isinstance(data, str):
            pass

        else:
            raise TypeError('the data parameter should be a list or tuple')

        result['errors'] = self.errors

        if len(self.errors) == 0:
            result['ok'] = True

        return SimpleNamespace(**result)

    def validate_rule(self, key, value, rules):

        _type = rules['type']
        rule_error_key = 'type_invalid'

        if 'message' not in rules: rules['message'] = ''

        if not self.is_type(_type, value, rules, True, rules, key,
                            rules.get('strict', False)):
            return

        def append_error(error_key=''):
            error_key = error_key or rule_error_key
            self.format_error(error_key, (key, ), rules, key, rule_key)

        for rule_key, rule_value in rules.items():
            if rule_key in _ALL_RULES and rule_key not in {
                    'message', 'type', 'strict'
            }:

                if rule_key == 'length':
                    rule_error_key = 'length_invalid'
                    if not isinstance(rule_value, int):
                        raise TypeError('int value expected for length')

                    if _type in self.basic_types_plus_regex:
                        if len(f'{value}') != rule_value:
                            append_error()

                    else:

                        if not hasattr(value,
                                       '__len__') or len(value) != rule_value:
                            append_error()

                elif rule_key == 'options':
                    rule_error_key = 'not_in_options'
                    if _type in self.basic_types_plus_regex:
                        if value not in set(rule_value):
                            append_error()
                    else:
                        if not all(val in set(rule_value) for val in value):
                            append_error()

                elif rule_key == 'excludes':
                    rule_error_key = 'not_excluded'
                    if _type in self.basic_types_plus_regex:

                        if value in set(rule_value):
                            append_error()

                    else:
                        if any(val in set(value) for val in rule_value):
                            append_error()

                elif rule_key == 'contains':
                    rule_error_key = 'does_not_contain'
                    if isinstance(rule_value, str):
                        if _type in self.basic_types_plus_regex:
                            if rule_value not in str(value):
                                append_error()

                        elif _type == 'dict':
                            if rule_value not in value:
                                append_error()

                        else:
                            if rule_value not in set(value):
                                append_error()

                    else:
                        if isinstance(rule_value, (list, tuple)):
                            #Todo: modify so that user can know the specific values missing
                            if _type in self.basic_types_plus_regex:

                                if not all(val in str(value)
                                           for val in rule_value):
                                    append_error()

                            elif _type == 'dict':

                                if not all(val in set(value.keys())
                                           for val in rule_value):
                                    append_error()
                            else:
                                if not all(val in set(value)
                                           for val in rule_value):
                                    append_error()

                elif rule_key == 'expression':
                    regex = None
                    rule_error_key = 'does_not_match_regex'
                    try:
                        regex = re.compile(rule_value, re.VERBOSE)

                    except Exception as ex:
                        raise Exception(f'Error Compiling Regex: {ex}')

                    if regex.match(value) == None:
                        append_error()

                elif rule_key == 'startswith':
                    rule_error_key = 'does_not_startwith'
                    if _type in self.basic_types_plus_regex:
                        if not str(value).startswith(rule_value):
                            append_error()
                    else:
                        if _type in {'list', 'tuple'}:
                            if not value or value[0] != rule_value:
                                append_error()

                elif rule_key == 'endswith':
                    rule_error_key = 'does_not_endwith'
                    if _type in self.basic_types_plus_regex:
                        if not str(value).endswith(rule_value):
                            append_error()
                        else:
                            if _type in {'list', 'tuple'}:
                                if not value or value[-1] != rule_value:
                                    append_error()

                elif rule_key == 'range':
                    rule_error_key = 'not_in_range'
                    if not isinstance(rule_value, (list, tuple)):
                        raise TypeError('list or tuple expected for range')

                    if len(rule_value) != 2:
                        raise ValueError('range object should have 2 values')

                    if _type in {'int', 'float', 'even', 'odd'}:
                        pass

                    elif _type == 'date':
                        pass

                    elif _type == 'str':
                        pass

                    elif _type in {'list', 'tuple'}:
                        pass

    def is_type(self,
                data_type,
                data,
                rules,
                append_errors=False,
                message='',
                field_name='',
                strict=False):

        status = False

        def raise_type_error(error_key='type_invalid'):
            self.format_error(error_key, (data_type, type(data).__qualname__),
                              message,
                              rules,
                              field_name,
                              'type',
                              append_errors,
                              raised_exception_type=TypeError)

        try:
            if data_type in set(self.native_types.keys()):
                if strict == False:
                    if not isinstance(literal_eval(str(data)),
                                      self.native_types.get(data_type)):
                        raise_type_error()
                else:
                    if not isinstance(data, data_type):
                        raise_type_error()

            elif data_type == 'date':
                date = parse_date(data)
                if not isinstance(date, datetime):
                    raise_type_error('invalid_date')

            elif data_type == 'email':
                email_re = re.compile(
                    """^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)
                |(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])
                |(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$""", re.VERBOSE)

                if email_re.match(data) == None:
                    raise_type_error('invalid_email')

            elif data_type == 'even':
                if not (self.is_type('int', data, strict=strict)
                        and int(data) % 2 == 0):
                    raise_type_error('not_even')

            elif data_type == 'odd':
                if not (self.is_type('int', data, strict=strict)
                        and int(data) % 2 == 1):
                    raise_type_error('not_odd')

            status = True

        except Exception:
            raise_type_error()

        return status

    def format_error(self,
                     error_key,
                     error_values=[],
                     rules={},
                     field='',
                     rule_key='',
                     append_errors=True,
                     raised_exception_type=ValueError):

        formatted_message = ''
        raw_error = errm.get(f'field_{error_key}', '') or errm[error_key]
        custom_message = rules.get(f'{rule_key}-message', '') or rules.get(
            'message', '')

        if error_key == 'type_invalid':
            ev = error_values
            error_fields = (ev[0], field, ev[1]) if field else (ev[0], ev[1])
            formatted_message = custom_message or raw_error % error_fields
        else:
            formatted_message = custom_message or raw_error % error_values

        if append_errors:
            self.errors.append(formatted_message)

        if self.raise_exceptions and raised_exception_type is not None:
            raise raised_exception_type(formatted_message)

        return formatted_message

import logging
import re

from ast import literal_eval
from collections import OrderedDict
from datetime import datetime
from dateutil.parser import parse as parse_date
from types import SimpleNamespace

from .messages import error_messages as errm

_ALL_RULES = {
    'length', 'contains', 'excludes', 'options', 'strict', 'expression',
    'type', 'range', 'startswith', 'endswith'
}


class Validator:
    def __init__(self, native_types, basic_types, extended_types,
                 raise_exceptions, **kwds):
        self.errors = []
        self.error_keys = []
        self.log_errors = False
        self.group_errors = True
        self.keys_with_defaults = {}
        self.basic_types = basic_types
        self.extended_types = extended_types
        self.raise_exceptions = raise_exceptions
        self.basic_types_plus_regex = set(basic_types + ('regex', ))
        self.native_types = {f'{nt.__qualname__}': nt for nt in native_types}

        if 'kwds' in kwds:
            keywords = kwds['kwds']
            self.log_errors = keywords.get('log_errors', False)
            self.group_errors = keywords.get('group_errors', True)

    def validate_object(self, data, rules, defaults):
        result = {'ok': False}
        if isinstance(data, OrderedDict):
            if defaults:
                self.keys_with_defaults = set(defaults.keys())

            for index, (key, value) in enumerate(data.items()):
                if self.group_errors:
                    self.errors.append([])

                if key in self.keys_with_defaults:
                    # skip default values
                    if value == defaults.get(key): continue

                current_rules = rules[index]
                
                if current_rules.get('type') not in ('date', 'regex'):
                    if 'strict' not in current_rules:
                        current_rules['strict'] = True

                if not self.is_type(current_rules.get('type'), value,
                                    current_rules, True, '', key,
                                    current_rules.get('strict', False)):
                    break

                self.validate_rule(key, value, current_rules)

        elif isinstance(data, (list, tuple)):
            for count, value in enumerate(data):
                if self.group_errors:
                    self.errors.append([])

                current_rules = rules[count]

                if current_rules.get('type') not in ('date', 'regex'):
                    if 'strict' not in current_rules:
                        current_rules['strict'] = True

                if not self.is_type(current_rules.get('type'), value,
                                    current_rules, True, '', '',
                                    current_rules.get('strict', False)):
                    break

                self.validate_rule('', value, current_rules)

        elif isinstance(data, str):
            self.group_errors = False

            if rules[0].get('type') not in ('date', 'regex'):
                if 'strict' not in rules[0]:
                    rules[0]['strict'] = True

            self.validate_rule('', data, rules[0])

        else:
            raise TypeError('the data parameter should be a string, list, or tuple')

        result['errors'] = self.errors

        if len(self.errors) == 0 or all(x == [] for x in self.errors):
            result['ok'] = True

        return SimpleNamespace(**result)

    def validate_rule(self, key, value, rules):

        _type = rules['type']
        rule_error_key = 'type_invalid'
        known_exception = False

        if 'message' not in rules: rules['message'] = ''

        def append_error(error_key=''):
            error_key = error_key or rule_error_key
            self.format_error(error_key, (key, ), rules, key, rule_key)

        def raise_invalid_rule(data_type, rule_name):
            raise TypeError(f'{rule_name} not valid for {data_type}')

        for rule_key, rule_value in rules.items():

            try:
                if rule_key == 'length':
                    rule_error_key = 'length_invalid'
                    if not isinstance(rule_value, int):
                        known_exception = True
                        raise TypeError('int value expected for length')

                    if _type in self.basic_types_plus_regex:
                        if len(f'{value}') != rule_value:
                            append_error()

                    else:
                        rule_error_key = 'object_length_invalid'

                        if hasattr(value, '__len__'):
                            if len(value) != rule_value:
                                append_error()
                        else:
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
                    rule_error_key = 'missing_required_data'
                    if isinstance(rule_value, str):
                        if _type in self.basic_types_plus_regex:
                            if rule_value not in str(value):
                                append_error()

                        elif _type == 'dict':
                            rule_error_key = 'missing_required_keys'
                            if rule_value not in value:
                                append_error()

                        else:
                            rule_error_key = 'missing_required_values'
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
                                rule_error_key = 'missing_required_keys'

                                if not all(val in set(value.keys())
                                           for val in rule_value):
                                    append_error()
                            else:
                                rule_error_key = 'missing_required_values'
                                if not all(val in set(value)
                                           for val in rule_value):
                                    append_error()

                elif rule_key == 'expression':
                    regex = None
                    rule_error_key = 'does_not_match_regex'
                    try:
                        regex = re.compile(rule_value, re.VERBOSE)

                    except Exception as ex:
                        known_exception = True
                        raise Exception(f'error compiling regex: {ex}')

                    if regex.match(value) == None:
                        append_error()

                elif rule_key == 'startswith':
                    rule_error_key = 'does_not_startwith'
                    if _type in self.basic_types_plus_regex:
                        if not str(value).startswith(rule_value):
                            append_error()
                    else:
                        if _type in ('list', 'tuple'):
                            if not value or value[0] != rule_value:
                                append_error()

                        else:
                            raise_invalid_rule(_type, rule_key)

                elif rule_key == 'endswith':
                    rule_error_key = 'does_not_endwith'
                    if _type in self.basic_types_plus_regex:
                        if not str(value).endswith(rule_value):
                            append_error()
                    else:
                        if _type in ('list', 'tuple'):
                            if not value or value[-1] != rule_value:
                                append_error()

                        else:
                            raise_invalid_rule(_type, rule_key)

                elif rule_key == 'range':
                    rule_error_key = 'not_in_range'
                    if not isinstance(rule_value, (list, tuple)):
                        known_exception = True
                        raise TypeError('list or tuple expected for range')

                    if len(rule_value) != 2:
                        known_exception = True
                        raise ValueError('range object should have 2 values')

                    if _type == 'str':
                        rule_error_key = 'string_not_in_range'
                        if not len(value) >= rule_value[0] and len(
                                value) <= rule_value[1]:
                            append_error()

                    elif _type == 'date':
                        rule_error_key = 'date_not_in_range'
                        min_date = None
                        max_date = None
                        cast_date = value if isinstance(
                            value, datetime) else parse_date(value)

                        if isinstance(value, datetime):
                            min_date = value if rule_value[
                                0] == 'any' else parse_date(rule_value[0])
                            max_date = value if rule_value[
                                1] == 'any' else parse_date(rule_value[1])

                        else:
                            min_date = parse_date(value) if rule_value[
                                0] == 'any' else parse_date(rule_value[0])
                            max_date = parse_date(value) if rule_value[
                                1] == 'any' else parse_date(rule_value[1])

                        if not (cast_date >= min_date
                                and cast_date <= max_date):
                            append_error()

                    elif _type in ('list', 'tuple'):
                        rule_error_key = 'list_or_tuple_not_in_range'
                        if not len(value) >= rule_value[0] and len(
                                value) <= rule_value[1]:
                            append_error()

                    elif _type in ('int', 'float', 'even', 'odd'):
                        rule_error_key = 'number_not_in_range'
                        min_value = float(
                            '-inf'
                        ) if rule_value[0] == 'any' else rule_value[0]
                        max_value = float(
                            'inf') if rule_value[1] == 'any' else rule_value[1]
                        cast_value = literal_eval(str(value))

                        if not (cast_value >= min_value
                                and cast_value <= max_value):
                            append_error()

                    else:
                        raise_invalid_rule(_type, rule_key)

            except Exception as ex:
                if known_exception:
                    raise
                else:
                    if self.log_errors:
                        logging.warning(str(ex))

                    append_error()

    def is_type(self,
                data_type,
                data,
                rules,
                append_errors=False,
                message='',
                field_name='',
                strict=False):

        status = False

        def append_type_error(error_key='type_invalid'):
            self.format_error(error_key, (data_type, type(data).__qualname__),
                              rules,
                              field_name,
                              'type',
                              append_errors,
                              raised_exception_type=TypeError)

        try:

            if str(data).strip() == '':
                append_type_error('missing_value')
                return False
            

            if data_type in set(self.native_types.keys()):
                if strict == False:
                    try:
                        if not isinstance(literal_eval(str(data)),
                                          self.native_types.get(data_type)):
                            append_type_error()

                    except (TypeError, ValueError):
                        append_type_error()
                else:
                    if not isinstance(data, self.native_types.get(data_type)):
                        append_type_error()

            elif data_type == 'date':
                if not isinstance(data, datetime):

                    if not isinstance(parse_date(data), datetime):
                        append_type_error('invalid_date')

            elif data_type == 'email':
                try:
                    email_re = re.compile(
                        """^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)
                    |(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])
                    |(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$""", re.VERBOSE)

                    if email_re.match(data) == None:
                        append_type_error('invalid_email')

                except Exception:
                    append_type_error('invalid_email')

            elif data_type == 'even':
                if not (self.is_type('int', data, rules, strict=strict)
                        and int(data) % 2 == 0):
                    append_type_error('not_even')

            elif data_type == 'odd':
                if not (self.is_type('int', data, rules, strict=strict)
                        and int(data) % 2 == 1):
                    append_type_error('not_odd')

            status = True

        except Exception as ex:
            if self.log_errors:
                logging.warning(str(ex))
            append_type_error()

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
        raw_error = errm.get(f'field_{error_key}', '') if field else errm[error_key]
        custom_message = rules.get(f'{rule_key}-message', '') or rules.get(
            'message', '')

        if error_key == 'type_invalid':
            ev = error_values
            error_fields = (ev[0], field, ev[1]) if field else (ev[0], ev[1])
            formatted_message = custom_message or raw_error % error_fields
        else:
            formatted_message = custom_message or raw_error

        if append_errors:
            if self.group_errors:
                self.errors[-1].append(formatted_message)
            else:
                self.errors.append(formatted_message)

        if self.raise_exceptions and raised_exception_type is not None:
            raise raised_exception_type(formatted_message)

        return formatted_message

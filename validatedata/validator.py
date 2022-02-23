import logging
import re

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
    INVALID_DATE = 'invalid_date'
    INVALID_EMAIL = 'invalid_email'
    INVALID_TYPE = 'type_invalid'
    INVALID_LENGTH = 'length_invalid'
    INVALID_OBJECT = 'invalid_object'
    INVALID_OBJECT_LENGTH = 'object_length_invalid'
    LIST_OR_TUPLE_NOT_IN_RANGE = 'list_or_tuple_not_in_range'
    MISSING_REQUIRED_DATA = 'missing_required_data'
    MISSING_REQUIRED_KEYS = 'missing_required_keys'
    MISSING_REQUIRED_VALUES = 'missing_required_values'
    NOT_EVEN = 'not_even'
    NOT_ODD = 'not_odd'
    NOT_IN_OPTIONS = 'not_in_options'
    NOT_EXCLUDED = 'not_excluded'
    NOT_IN_RANGE = 'not_in_range'
    NUMBER_NOT_IN_RANGE = 'number_not_in_range'
    STRING_NOT_IN_RANGE = 'string_not_in_range'


class ValidationError(Exception):
    pass


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

        # Values used by rule functions
        self._type = None
        self.data_key = None
        self.data_value = None
        self.rule_key = None
        self.rule_value = None
        self.current_rules = None
        self.is_known_exception = False
        self.error_key = ErrorKeys.INVALID_TYPE

    def validate_object(self, data, rules, defaults):
        result = {'ok': False}

        def add_strict_rule(_rules):
            new_rules = _rules
            if _rules.get('type') not in ('date', 'regex'):
                if 'strict' not in _rules:
                    new_rules['strict'] = True
            return new_rules

        def value_is_of_type(current_rules, key, value):
            cr = current_rules
            return self.is_type(cr.get('type'), value, cr, True, '', key,
                                cr.get('strict', False))

        if isinstance(data, OrderedDict):
            if defaults:
                self.keys_with_defaults = set(defaults.keys())

            for index, (key, value) in enumerate(data.items()):
                if self.group_errors:
                    self.errors.append([])

                if key in self.keys_with_defaults:
                    # skip default values
                    if value == defaults.get(key): continue

                current_rules = add_strict_rule(rules[index])

                if not value_is_of_type(current_rules, key, value):
                    break

                self.validate_rule(key, value, current_rules)

        elif isinstance(data, (list, tuple)):
            for count, value in enumerate(data):
                if self.group_errors:
                    self.errors.append([])

                current_rules = add_strict_rule(rules[count])

                if not value_is_of_type(current_rules, '', value):
                    break

                self.validate_rule('', value, current_rules)

        elif isinstance(data, str):
            self.group_errors = False

            current_rules = add_strict_rule(rules[0])

            self.validate_rule('', data, current_rules)

        else:
            raise TypeError(
                'the data parameter should be a string, list, or tuple')

        result['errors'] = self.errors

        if len(self.errors) == 0 or all(x == [] for x in self.errors):
            result['ok'] = True

        return SimpleNamespace(**result)

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

    def append_error(self, **kwargs):
        key = self.data_key
        rules = self.current_rules
        rule_key = self.rule_key
        error_key = self.error_key
        self.format_error(error_key, (key, ), rules, key, rule_key)

    def validate_length(self, **kwargs):
        self.set_validation_data(**kwargs)
        self.error_key = ErrorKeys.INVALID_LENGTH

        if not isinstance(kwargs['rule_value'], int):
            self.raise_known_exception('int value expected for length')

        if self._type in self.basic_types_plus_regex:
            if len(f"{self.data_value}") != self.rule_value:
                self.append_error()

        else:
            self.error_key = ErrorKeys.INVALID_OBJECT_LENGTH

            if hasattr(self.data_value, '__len__'):
                if len(self.data_value) != self.rule_value:
                    self.append_error()
            else:
                self.append_error()

    def validate_contains(self, **kwargs):
        self.set_validation_data(**kwargs)
        self.error_key = ErrorKeys.MISSING_REQUIRED_DATA

        if isinstance(self.rule_value, str):
            if self._type in self.basic_types_plus_regex:
                if self.rule_value not in str(self.data_value):
                    self.append_error()

            elif self._type == 'dict':
                self.error_key = ErrorKeys.MISSING_REQUIRED_KEYS
                if self.rule_value not in self.data_value:
                    self.append_error()

            else:
                self.error_key = ErrorKeys.MISSING_REQUIRED_VALUES
                if self.rule_value not in set(self.data_value):
                    self.append_error()

        else:
            if isinstance(self.rule_value, (list, tuple)):
                #Todo: modify so user can know the specific values missing
                if self._type in self.basic_types_plus_regex:

                    if not all(val in str(self.data_value)
                               for val in self.rule_value):
                        self.append_error()

                elif self._type == 'dict':
                    self.error_key = ErrorKeys.MISSING_REQUIRED_KEYS

                    if not all(val in set(self.data_value.keys())
                               for val in self.rule_value):
                        self.append_error()
                else:
                    self.error_key = ErrorKeys.MISSING_REQUIRED_VALUES
                    if not all(val in set(self.data_value)
                               for val in self.rule_value):
                        self.append_error()

    def validate_excludes(self, **kwargs):
        self.set_validation_data(**kwargs)
        self.error_key = ErrorKeys.NOT_EXCLUDED
        if self._type in self.basic_types_plus_regex:

            if self.data_value in set(self.rule_value):
                self.append_error()

        else:
            if any(val in set(self.data_value) for val in self.rule_value):
                self.append_error()

    def validate_options(self, **kwargs):
        self.set_validation_data(**kwargs)
        self.error_key = ErrorKeys.NOT_IN_OPTIONS

        if self._type in self.basic_types_plus_regex:
            if self.data_value not in set(self.rule_value):
                self.append_error()
        else:
            if not all(val in set(self.rule_value) for val in self.data_value):
                self.append_error()

    def validate_expression(self, **kwargs):
        regex = None
        self.set_validation_data(**kwargs)
        self.error_key = ErrorKeys.DOES_NOT_MATCH_REGEX
        try:
            regex = re.compile(self.rule_value, re.VERBOSE)

        except Exception as ex:
            self.raise_known_exception(f'error compiling regex: {ex}')

        if regex.match(self.data_value) == None:
            self.append_error()

    def validate_range(self, **kwargs):
        self.set_validation_data(**kwargs)
        self.error_key = ErrorKeys.NOT_IN_RANGE
        if not isinstance(self.rule_value, (list, tuple)):
            self.raise_known_exception('list or tuple expected for range')

        if len(self.rule_value) != 2:
            self.raise_known_exception('range object should have 2 values')

        if self._type == 'str':
            self.error_key = ErrorKeys.STRING_NOT_IN_RANGE
            if not len(self.data_value) >= self.rule_value[0] and len(
                    self.data_value) <= self.rule_value[1]:
                self.append_error()

        elif self._type == 'date':
            self.error_key = ErrorKeys.DATE_NOT_IN_RANGE
            min_date = None
            max_date = None
            cast_date = self.data_value if isinstance(
                self.data_value, datetime) else parse_date(self.data_value)

            if isinstance(self.data_value, datetime):
                min_date = self.data_value if self.rule_value[
                    0] == 'any' else parse_date(self.rule_value[0])
                max_date = self.data_value if self.rule_value[
                    1] == 'any' else parse_date(self.rule_value[1])

            else:
                min_date = parse_date(
                    self.data_value
                ) if self.rule_value[0] == 'any' else parse_date(
                    self.rule_value[0])
                max_date = parse_date(
                    self.data_value
                ) if self.rule_value[1] == 'any' else parse_date(
                    self.rule_value[1])

            if not (cast_date >= min_date and cast_date <= max_date):
                self.append_error()

        elif self._type in ('list', 'tuple'):
            self.error_key = ErrorKeys.LIST_OR_TUPLE_NOT_IN_RANGE
            if not len(self.data_value) >= self.rule_value[0] and len(
                    self.data_value) <= self.rule_value[1]:
                self.append_error()

        elif self._type in ('int', 'float', 'even', 'odd'):
            self.error_key = ErrorKeys.NUMBER_NOT_IN_RANGE
            min_value = float(
                '-inf') if self.rule_value[0] == 'any' else self.rule_value[0]
            max_value = float(
                'inf') if self.rule_value[1] == 'any' else self.rule_value[1]
            cast_value = literal_eval(str(self.data_value))

            if not (cast_value >= float(min_value)
                    and cast_value <= float(max_value)):
                self.append_error()

    def validate_startswith(self, **kwargs):
        self.set_validation_data(**kwargs)
        self.error_key = ErrorKeys.DOES_NOT_STARTWITH
        if self._type in self.basic_types_plus_regex:
            if not str(self.data_value).startswith(self.rule_value):
                self.append_error()
        else:
            if self._type in ('list', 'tuple'):
                if not self.data_value or self.data_value[0] != self.rule_value:
                    self.append_error()

    def validate_endswith(self, **kwargs):
        self.set_validation_data(**kwargs)
        self.error_key = ErrorKeys.DOES_NOT_ENDWITH
        if self._type in self.basic_types_plus_regex:
            if not str(self.data_value).endswith(self.rule_value):
                self.append_error()
        else:
            if self._type in ('list', 'tuple'):
                if not self.data_value or self.data_value[
                        -1] != self.rule_value:
                    self.append_error()

    def validate_unknown(self, **kwargs):
        pass

    def validate_rule(self, key, value, rules):

        rule_map = {
            # 'type': self.validate_type,
            'range': self.validate_range,
            'length': self.validate_length,
            'contains': self.validate_contains,
            'excludes': self.validate_excludes,
            'options': self.validate_options,
            'expression': self.validate_expression,
            'startswith': self.validate_startswith,
            'endswith': self.validate_endswith,
            'unknown': self.validate_unknown,
        }

        rule_set = set(rule_map.keys())

        for rule_key, rule_value in rules.items():

            try:

                if rule_key in rule_set:
                    rule_map.get(rule_key, 'unknown')(rule_key=rule_key,
                                                      rule_value=rule_value,
                                                      data_key=key,
                                                      data_value=value,
                                                      all_rules=rules)

            except Exception as ex:
                if self.is_known_exception:
                    self.is_known_exception = False
                    raise
                else:
                    if self.log_errors:
                        logging.warning(str(ex))

                    self.append_error()

    def is_type(self,
                data_type,
                data,
                rules,
                append_errors=False,
                message='',
                field_name='',
                strict=False):

        status = False

        def append_type_error(error_key=ErrorKeys.INVALID_TYPE):
            true_type = data_type
            if true_type == 'annotation':
                true_type = rules['object'].__qualname__

            self.format_error(error_key, (true_type, type(data).__qualname__),
                              rules,
                              field_name,
                              'type',
                              append_errors,
                              raised_exception_type=ValidationError)

        try:

            if data_type in set(self.native_types.keys()):
                if strict == False:
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
                    """^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)
                |(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])
                |(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$""", re.VERBOSE)

                if email_re.match(str(data)) == None:
                    append_type_error(ErrorKeys.INVALID_EMAIL)

            elif data_type == 'even':
                if not (self.is_type('int', data, rules, strict=strict)
                        and int(data) % 2 == 0):
                    append_type_error(ErrorKeys.NOT_EVEN)

            elif data_type == 'odd':
                if not (self.is_type('int', data, rules, strict=strict)
                        and int(data) % 2 == 1):
                    append_type_error(ErrorKeys.NOT_ODD)

            elif data_type == 'object':
                if not isinstance(data, rules['object']):
                    append_type_error(ErrorKeys.INVALID_OBJECT)

            elif data_type == 'annotation':
                if not isinstance(data, rules['object']):
                    append_type_error(ErrorKeys.INVALID_TYPE)

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
                     raised_exception_type=ValidationError):

        formatted_message = ''
        raw_error = errm.get(f'field_{error_key}', '') if field else ''
        raw_error = raw_error or errm[error_key] or errm['no_error_message']
        custom_message = rules.get(f'{rule_key}-message', '') or rules.get(
            'message', '')

        if error_key == ErrorKeys.INVALID_TYPE:
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

        if self.raise_exceptions:
            raise raised_exception_type(formatted_message)

        return formatted_message

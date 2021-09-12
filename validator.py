from messages import error_messages as errm


class Validator:
    def __init__(self, basic_types, extended_types, raise_exceptions):
        self.basic_types = basic_types
        self.extended_types = extended_types
        self.raise_exceptions = raise_exceptions
        self.errors = []

    def validate_bool(self, data, rule, message):
        pass

    def validate_date(self, data, rule, message):
        pass

    def validate_dict(self, data, rule, message):
        pass

    def validate_email(self, data, rule, message):
        pass

    def validate_number(self, data, rule, message, _type):
        if _type == 'even':
            if not self.is_type(int, data) or int(data) % 2 != 0:
                self.errors.append(
                    self.format_error('value_not_even', [], message))

    def validate_container(self, data, rule, message):
        pass

    def validate_regex(self, data, rule, message):
        pass

    def validate_string(self, data, rule, message):
        pass

    def is_type(self,
                cast_type,
                data,
                append_errors=False,
                message='',
                field_name=''):
        status = False
        try:
            if cast_type.__qualname__ in ('int', 'float'):
                cast_type(data)

            else:
                if not isinstance(data, cast_type):
                    raise TypeError('Invalid Type')

            status = True

        except (TypeError, ValueError):

            self.format_error('type_invalid',
                              (cast_type.__qualname__, type(data).__qualname__),
                              message,
                              field_name,
                              append_errors,
                              raised_exception_type=ValueError)

        return status

    def format_error(self,
                     error_key,
                     error_values=[],
                     custom_message='',
                     field='',
                     append_errors=False,
                     raised_exception_type=None):

        error_fields = []
        formatted_message = ''
        raw_error = errm[f'field_{error_key}'] if field else errm[error_key]

        if error_key == 'type_invalid':
            ev = error_values
            error_fields = (ev[0], field, ev[1]) if field else (ev[0], ev[1])
            formatted_message = custom_message or raw_error % error_fields
        else:
            pass

        if append_errors:
            self.errors.append(formatted_message)

        if self.raise_exceptions and raised_exception_type is not None:
            raise raised_exception_type(formatted_message)

        return formatted_message

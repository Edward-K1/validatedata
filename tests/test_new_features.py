from collections import OrderedDict
from validatedata.validatedata import validate, validate_data, validate_types
from validatedata.validator import ValidationError
from validatedata.messages import error_messages
from .base import BaseTest


class TestNullable(BaseTest):

    def test_nullable_allows_none(self):
        rule = [{'type': 'str', 'nullable': True}]
        self.assertTrue(validate_data([None], rule).ok)

    def test_nullable_still_validates_non_none(self):
        rule = [{'type': 'str', 'nullable': True}]
        self.assertTrue(validate_data(['hello'], rule).ok)
        self.assertFalse(validate_data([42], rule).ok)

    def test_non_nullable_rejects_none(self):
        rule = [{'type': 'str', 'nullable': False}]
        self.assertFalse(validate_data([None], rule).ok)

    def test_nullable_default_is_false(self):
        # Without nullable key, None should fail
        rule = [{'type': 'str'}]
        self.assertFalse(validate_data([None], rule).ok)


class TestCustomMessages(BaseTest):

    def test_type_message_key(self):
        rule = [{'type': 'int', 'message': 'must be a whole number'}]
        result = validate_data(['oops'], rule)
        self.assertFalse(result.ok)
        self.assertIn('must be a whole number', result.errors[0])

    def test_rule_specific_message_key(self):
        rule = [
            {
                'type': 'int',
                'range': (18, 'any'),
                'range-message': 'must be 18 or older',
            }
        ]
        result = validate_data([10], rule)
        self.assertFalse(result.ok)
        self.assertIn('must be 18 or older', result.errors[0])

    def test_expression_message_key(self):
        rule = [
            {
                'type': 'str',
                'expression': r'^\d{4}$',
                'expression-message': 'must be 4 digits',
            }
        ]
        result = validate_data(['abc'], rule)
        self.assertFalse(result.ok)
        self.assertIn('must be 4 digits', result.errors[0])

    def test_custom_message_in_dict_rule(self):
        rule = {
            'keys': {
                'age': {
                    'type': 'int',
                    'range': (18, 'any'),
                    'range-message': 'must be 18+',
                }
            }
        }
        result = validate_data({'age': 10}, rule)
        self.assertFalse(result.ok)
        self.assertIn('must be 18+', result.errors[0])


class TestMutateAndTransform(BaseTest):

    def test_transform_callable(self):
        rule = [{'type': 'str', 'transform': str.strip}]
        result = validate_data(['  hello  '], rule, mutate=True)
        self.assertTrue(result.ok)
        self.assertEqual(result.data, ['hello'])

    def test_transform_lambda(self):
        rule = [{'type': 'int', 'transform': lambda v: v * 2}]
        result = validate_data([5], rule, mutate=True)
        self.assertTrue(result.ok)
        self.assertEqual(result.data, [10])

    def test_transform_dict_with_func(self):
        rule = [{'type': 'str', 'transform': {'func': str.upper}}]
        result = validate_data(['hello'], rule, mutate=True)
        self.assertTrue(result.ok)
        self.assertEqual(result.data, ['HELLO'])

    def test_transform_dict_pass_data(self):
        """Transform with pass_data=True receives the full sibling data dict."""
        data = OrderedDict([('base', 100), ('multiplier', 3)])
        rules = [
            {'type': 'int'},
            {
                'type': 'int',
                'transform': {
                    'func': lambda v, d: v * d.get('base', 1),
                    'pass_data': True,
                },
            },
        ]
        result = validate_data(data, rules, mutate=True)
        self.assertTrue(result.ok)
        self.assertEqual(result.data[1], 300)

    def test_mutate_false_leaves_original_data(self):
        rule = [{'type': 'str', 'transform': str.upper}]
        result = validate_data(['hello'], rule, mutate=False)
        self.assertTrue(result.ok)
        self.assertFalse(hasattr(result, 'data'))

    def test_transform_then_validate(self):
        """Transform fires before validation rules run on the transformed value."""
        rule = [{'type': 'str', 'transform': str.strip, 'length': 5}]
        # '  hello  ' stripped → 'hello' (length 5) → should pass
        result = validate_data(['  hello  '], rule, mutate=True)
        self.assertTrue(result.ok)
        # 'world!' stripped → 'world!' (length 6) → should fail length check
        result2 = validate_data(['world!'], rule, mutate=True)
        self.assertFalse(result2.ok)


class TestDependsOn(BaseTest):

    def test_depends_on_value_match_validates(self):
        """Field is validated when sibling matches expected value."""
        data = OrderedDict([('role', 'admin'), ('secret', 'abc123')])
        rules = [
            {'type': 'str'},
            {
                'type': 'str',
                'length': 6,
                'depends_on': {'field': 'role', 'value': 'admin'},
            },
        ]
        self.assertTrue(validate_data(data, rules).ok)

    def test_depends_on_value_match_fails_validation(self):
        """Field validation fires and fails when sibling matches."""
        data = OrderedDict([('role', 'admin'), ('secret', 'x')])
        rules = [
            {'type': 'str'},
            {
                'type': 'str',
                'length': 6,
                'depends_on': {'field': 'role', 'value': 'admin'},
            },
        ]
        self.assertFalse(validate_data(data, rules).ok)

    def test_depends_on_value_no_match_skips_validation(self):
        """Field validation is skipped when sibling doesn't match."""
        data = OrderedDict([('role', 'user'), ('secret', 'x')])
        rules = [
            {'type': 'str'},
            {
                'type': 'str',
                'length': 6,
                'depends_on': {'field': 'role', 'value': 'admin'},
            },
        ]
        self.assertTrue(validate_data(data, rules).ok)

    def test_depends_on_condition_callable(self):
        """depends_on condition can be a callable."""
        data = OrderedDict([('has_discount', True), ('code', 'SAVE10')])
        rules = [
            {'type': 'bool'},
            {
                'type': 'str',
                'depends_on': {
                    'field': 'has_discount',
                    'condition': lambda v: v is True,
                },
            },
        ]
        self.assertTrue(validate_data(data, rules).ok)

    def test_depends_on_condition_callable_skips(self):
        data = OrderedDict([('has_discount', False), ('code', '')])
        rules = [
            {'type': 'bool'},
            {
                'type': 'str',
                'length': 6,
                'depends_on': {
                    'field': 'has_discount',
                    'condition': lambda v: v is True,
                },
            },
        ]
        # condition is False, so the 'code' field is skipped entirely
        self.assertTrue(validate_data(data, rules).ok)


class TestNestedFields(BaseTest):

    def test_nested_dict_valid(self):
        data = OrderedDict([('user', {'name': 'alice', 'age': 30})])
        rules = [
            {
                'type': 'dict',
                'fields': {'name': {'type': 'str'}, 'age': {'type': 'int'}},
            }
        ]
        self.assertTrue(validate_data(data, rules).ok)

    def test_nested_dict_wrong_field_type(self):
        data = OrderedDict([('user', {'name': 123, 'age': 30})])
        rules = [
            {
                'type': 'dict',
                'fields': {'name': {'type': 'str'}, 'age': {'type': 'int'}},
            }
        ]
        result = validate_data(data, rules)
        self.assertFalse(result.ok)
        # path should be included in the error message
        self.assertTrue(any('user.name' in e for e in result.errors))

    def test_nested_dict_multiple_invalid_fields(self):
        data = OrderedDict([('user', {'name': 123, 'age': 'old'})])
        rules = [
            {
                'type': 'dict',
                'fields': {'name': {'type': 'str'}, 'age': {'type': 'int'}},
            }
        ]
        result = validate_data(data, rules)
        self.assertFalse(result.ok)
        self.assertTrue(any('user.name' in e for e in result.errors))
        self.assertTrue(any('user.age' in e for e in result.errors))


class TestNestedItems(BaseTest):

    def test_nested_list_items_valid(self):
        data = OrderedDict([('tags', ['python', 'django', 'rest'])])
        rules = [{'type': 'list', 'items': {'type': 'str'}}]
        self.assertTrue(validate_data(data, rules).ok)

    def test_nested_list_items_wrong_type(self):
        data = OrderedDict([('scores', [1, 'oops', 3])])
        rules = [{'type': 'list', 'items': {'type': 'int'}}]
        result = validate_data(data, rules)
        self.assertFalse(result.ok)
        self.assertTrue(any('scores[1]' in e for e in result.errors))

    def test_nested_list_items_with_rule(self):
        """Items rule can include sub-rules like range."""
        data = OrderedDict([('ages', [20, 25, 30])])
        rules = [{'type': 'list', 'items': {'type': 'int', 'range': (18, 65)}}]
        self.assertTrue(validate_data(data, rules).ok)

    def test_nested_list_items_rule_violation(self):
        data = OrderedDict([('ages', [20, 10, 30])])  # 10 is out of range
        rules = [{'type': 'list', 'items': {'type': 'int', 'range': (18, 65)}}]
        result = validate_data(data, rules)
        self.assertFalse(result.ok)
        self.assertTrue(any('ages[1]' in e for e in result.errors))

    def test_nested_list_of_dicts(self):
        """Items can themselves have nested fields."""
        data = OrderedDict(
            [
                (
                    'users',
                    [
                        {'name': 'alice', 'age': 30},
                        {'name': 'bob', 'age': 25},
                    ],
                )
            ]
        )
        rules = [
            {
                'type': 'list',
                'items': {
                    'type': 'dict',
                    'fields': {'name': {'type': 'str'}, 'age': {'type': 'int'}},
                },
            }
        ]
        self.assertTrue(validate_data(data, rules).ok)

    def test_nested_list_of_dicts_invalid(self):
        data = OrderedDict(
            [
                (
                    'users',
                    [
                        {'name': 'alice', 'age': 30},
                        {'name': 999, 'age': 25},  # name should be str
                    ],
                )
            ]
        )
        rules = [
            {
                'type': 'list',
                'items': {
                    'type': 'dict',
                    'fields': {'name': {'type': 'str'}, 'age': {'type': 'int'}},
                },
            }
        ]
        result = validate_data(data, rules)
        self.assertFalse(result.ok)


class TestRaiseExceptions(BaseTest):

    def test_raise_exceptions_on_validate_data(self):
        rule = [{'type': 'int'}]
        with self.assertRaises(ValidationError):
            validate_data(['not-int'], rule, raise_exceptions=True)

    def test_no_raise_exceptions_returns_result(self):
        rule = [{'type': 'int'}]
        result = validate_data(['not-int'], rule, raise_exceptions=False)
        self.assertFalse(result.ok)
        self.assertIsNotNone(result.errors)

    def test_decorator_raise_exceptions(self):
        @validate([{'type': 'int'}], raise_exceptions=True)
        def process(value):
            return value

        with self.assertRaises(ValidationError):
            process('bad')

    def test_decorator_no_raise_returns_dict(self):
        @validate([{'type': 'int'}], raise_exceptions=False)
        def process(value):
            return value

        result = process('bad')
        self.assertIsInstance(result, dict)
        self.assertIn('errors', result)

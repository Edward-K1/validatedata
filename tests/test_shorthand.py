"""
Tests for the pipe-syntax shorthand rule parser.

Covers tokenizer behaviour, individual modifiers, transforms,
full combinations, error cases, and end-to-end validation.

"""

import unittest

from validatedata.validatedata import (
    _expand_pipe_rule,
    _pipe_tokenize,
    validate_data,
)
from validatedata import ValidationError
from .base import BaseTest


# ---------------------------------------------------------------------------
# Tokenizer
# ---------------------------------------------------------------------------

class TestPipeTokenizer(unittest.TestCase):

    def test_no_pipe_returns_single_token(self):
        self.assertEqual(_pipe_tokenize('email'), ['email'])

    def test_normal_split(self):
        self.assertEqual(
            _pipe_tokenize('str|strip|lower|min:3|max:32'),
            ['str', 'strip', 'lower', 'min:3', 'max:32'],
        )

    def test_pipe_in_starts_with_value_not_split(self):
        # the | in 'image/png' is not preceded by a known keyword
        self.assertEqual(
            _pipe_tokenize('str|starts_with:image/png|min:3'),
            ['str', 'starts_with:image/png', 'min:3'],
        )

    def test_pipe_in_regex_pattern_not_split(self):
        self.assertEqual(
            _pipe_tokenize(r'str|min:8|re:(?=.*[A-Z]|.*\d).+|msg:strong'),
            ['str', 'min:8', r're:(?=.*[A-Z]|.*\d).+', 'msg:strong'],
        )

    def test_pipe_in_in_values_not_split(self):
        self.assertEqual(
            _pipe_tokenize('str|in:a|b,c|d|msg:bad'),
            ['str', 'in:a|b,c|d', 'msg:bad'],
        )

    def test_pipe_in_msg_not_split(self):
        self.assertEqual(
            _pipe_tokenize('int|min:18|msg:must be 18 | older'),
            ['int', 'min:18', 'msg:must be 18 | older'],
        )

    def test_type_always_split_at_first_pipe(self):
        tokens = _pipe_tokenize('str|min:3')
        self.assertEqual(tokens[0], 'str')


# ---------------------------------------------------------------------------
# Basic modifiers
# ---------------------------------------------------------------------------

class TestPipeBasicModifiers(BaseTest):

    def test_bare_type(self):
        self.assertEqual(_expand_pipe_rule('email'), {'type': 'email'})

    def test_strict(self):
        self.assertEqual(
            _expand_pipe_rule('int|strict'),
            {'type': 'int', 'strict': True},
        )

    def test_nullable(self):
        self.assertEqual(
            _expand_pipe_rule('email|nullable'),
            {'type': 'email', 'nullable': True},
        )

    def test_strict_and_nullable(self):
        self.assertEqual(
            _expand_pipe_rule('str|strict|nullable'),
            {'type': 'str', 'strict': True, 'nullable': True},
        )

    def test_unique(self):
        self.assertEqual(
            _expand_pipe_rule('list|unique'),
            {'type': 'list', 'unique': True},
        )


# ---------------------------------------------------------------------------
# Range modifiers
# ---------------------------------------------------------------------------

class TestPipeRangeModifiers(BaseTest):

    def test_min_only(self):
        self.assertEqual(
            _expand_pipe_rule('int|min:18'),
            {'type': 'int', 'range': (18, 'any')},
        )

    def test_max_only(self):
        self.assertEqual(
            _expand_pipe_rule('int|max:100'),
            {'type': 'int', 'range': ('any', 100)},
        )

    def test_min_and_max(self):
        self.assertEqual(
            _expand_pipe_rule('int|min:0|max:100'),
            {'type': 'int', 'range': (0, 100)},
        )

    def test_between(self):
        self.assertEqual(
            _expand_pipe_rule('int|between:0,100'),
            {'type': 'int', 'range': (0, 100)},
        )

    def test_str_length_range(self):
        self.assertEqual(
            _expand_pipe_rule('str|min:3|max:32'),
            {'type': 'str', 'range': (3, 32)},
        )

    def test_float_range(self):
        self.assertEqual(
            _expand_pipe_rule('float|min:1.5|max:9.9'),
            {'type': 'float', 'range': (1.5, 9.9)},
        )

    def test_open_upper_bound(self):
        self.assertEqual(
            _expand_pipe_rule('int|min:18'),
            {'type': 'int', 'range': (18, 'any')},
        )

    def test_open_lower_bound(self):
        self.assertEqual(
            _expand_pipe_rule('int|max:100'),
            {'type': 'int', 'range': ('any', 100)},
        )


# ---------------------------------------------------------------------------
# Collection and string modifiers
# ---------------------------------------------------------------------------

class TestPipeCollectionModifiers(BaseTest):

    def test_in(self):
        self.assertEqual(
            _expand_pipe_rule('str|in:admin,user,guest'),
            {'type': 'str', 'options': ('admin', 'user', 'guest')},
        )

    def test_not_in(self):
        self.assertEqual(
            _expand_pipe_rule('str|not_in:root,admin'),
            {'type': 'str', 'excludes': ('root', 'admin')},
        )

    def test_starts_with(self):
        self.assertEqual(
            _expand_pipe_rule('str|starts_with:https'),
            {'type': 'str', 'startswith': 'https'},
        )

    def test_ends_with(self):
        self.assertEqual(
            _expand_pipe_rule('str|ends_with:.pdf'),
            {'type': 'str', 'endswith': '.pdf'},
        )

    def test_contains(self):
        self.assertEqual(
            _expand_pipe_rule('str|contains:@'),
            {'type': 'str', 'contains': '@'},
        )

    def test_starts_with_pipe_in_value(self):
        """A | inside the starts_with value must not be treated as a delimiter."""
        self.assertEqual(
            _expand_pipe_rule('str|starts_with:image/png|min:3'),
            {'type': 'str', 'startswith': 'image/png', 'range': (3, 'any')},
        )


# ---------------------------------------------------------------------------
# Format modifier
# ---------------------------------------------------------------------------

class TestPipeFormatModifier(BaseTest):

    def test_color_hex(self):
        self.assertEqual(
            _expand_pipe_rule('color|format:hex'),
            {'type': 'color', 'format': 'hex'},
        )

    def test_color_rgb(self):
        self.assertEqual(
            _expand_pipe_rule('color|format:rgb'),
            {'type': 'color', 'format': 'rgb'},
        )

    def test_phone_national_nullable(self):
        self.assertEqual(
            _expand_pipe_rule('phone|format:national|nullable'),
            {'type': 'phone', 'format': 'national', 'nullable': True},
        )


# ---------------------------------------------------------------------------
# Transforms
# ---------------------------------------------------------------------------

class TestPipeTransforms(BaseTest):

    def test_single_transform_is_callable(self):
        r = _expand_pipe_rule('str|strip|min:3')
        self.assertTrue(callable(r['transform']))

    def test_single_transform_strips(self):
        r = _expand_pipe_rule('str|strip|min:3')
        self.assertEqual(r['transform']('  hi  '), 'hi')

    def test_chained_transforms(self):
        r = _expand_pipe_rule('str|strip|lower|min:3|max:32')
        self.assertEqual(r['transform']('  HELLO  '), 'hello')

    def test_upper_transform(self):
        r = _expand_pipe_rule('str|upper|min:3')
        self.assertEqual(r['transform']('hello'), 'HELLO')

    def test_title_transform(self):
        r = _expand_pipe_rule('str|title|min:3')
        self.assertEqual(r['transform']('hello world'), 'Hello World')

    def test_transform_after_validator_raises(self):
        with self.assertRaises(ValueError):
            _expand_pipe_rule('str|min:3|strip')

    def test_multiple_transforms_before_validators_ok(self):
        r = _expand_pipe_rule('str|strip|lower|upper|min:3')
        self.assertTrue(callable(r['transform']))


# ---------------------------------------------------------------------------
# Regex modifier
# ---------------------------------------------------------------------------

class TestPipeRegexModifier(BaseTest):

    def test_simple_regex(self):
        self.assertEqual(
            _expand_pipe_rule(r'str|re:[A-Z]{3}'),
            {'type': 'str', 'expression': r'[A-Z]{3}'},
        )

    def test_regex_with_pipe_in_pattern(self):
        r = _expand_pipe_rule(r'str|min:8|re:(?=.*[A-Z]|.*\d).+|msg:strong password')
        self.assertEqual(r['expression'], r'(?=.*[A-Z]|.*\d).+')
        self.assertEqual(r['message'], 'strong password')
        self.assertEqual(r['range'], (8, 'any'))

    def test_regex_with_colons_in_pattern(self):
        r = _expand_pipe_rule(r'str|re:https?://\S+')
        self.assertEqual(r['expression'], r'https?://\S+')

    def test_regex_no_pattern_raises(self):
        with self.assertRaises(ValueError):
            _expand_pipe_rule('str|re:')


# ---------------------------------------------------------------------------
# Message modifier
# ---------------------------------------------------------------------------

class TestPipeMessageModifier(BaseTest):

    def test_msg_at_end(self):
        self.assertEqual(
            _expand_pipe_rule('str|min:3|max:32|msg:bad username'),
            {'type': 'str', 'range': (3, 32), 'message': 'bad username'},
        )

    def test_msg_with_pipe_inside(self):
        self.assertEqual(
            _expand_pipe_rule('int|min:18|msg:must be 18 | older'),
            {'type': 'int', 'range': (18, 'any'), 'message': 'must be 18 | older'},
        )

    def test_msg_with_regex(self):
        r = _expand_pipe_rule(r'str|re:[A-Z]+|msg:uppercase only')
        self.assertEqual(r['expression'], r'[A-Z]+')
        self.assertEqual(r['message'], 'uppercase only')


# ---------------------------------------------------------------------------
# Full combinations
# ---------------------------------------------------------------------------

class TestPipeFullCombinations(BaseTest):

    def test_everything_combined(self):
        r = _expand_pipe_rule('str|strip|lower|strict|nullable|min:3|max:32|msg:bad')
        self.assertEqual(r['type'], 'str')
        self.assertTrue(r['strict'])
        self.assertTrue(r['nullable'])
        self.assertEqual(r['range'], (3, 32))
        self.assertEqual(r['message'], 'bad')
        self.assertTrue(callable(r['transform']))
        self.assertEqual(r['transform']('  ALICE  '), 'alice')

    def test_role_enum_with_message(self):
        r = _expand_pipe_rule('str|in:admin,user,guest|msg:invalid role')
        self.assertEqual(r['options'], ('admin', 'user', 'guest'))
        self.assertEqual(r['message'], 'invalid role')

    def test_password_rule(self):
        r = _expand_pipe_rule(r'str|min:8|re:(?=.*[A-Z])(?=.*\d).+|msg:weak password')
        self.assertEqual(r['range'], (8, 'any'))
        self.assertIn('expression', r)
        self.assertEqual(r['message'], 'weak password')


# ---------------------------------------------------------------------------
# Error cases
# ---------------------------------------------------------------------------

class TestPipeErrorCases(BaseTest):

    def test_unknown_type_raises(self):
        with self.assertRaises(TypeError):
            _expand_pipe_rule('notatype|min:3')

    def test_unknown_modifier_raises(self):
        with self.assertRaises(ValueError):
            _expand_pipe_rule('str|florp:3')

    def test_between_and_min_raises(self):
        with self.assertRaises(ValueError):
            _expand_pipe_rule('int|between:0,100|min:5')

    def test_between_and_max_raises(self):
        with self.assertRaises(ValueError):
            _expand_pipe_rule('int|between:0,100|max:50')

    def test_min_without_value_raises(self):
        with self.assertRaises(ValueError):
            _expand_pipe_rule('str|min:')

    def test_max_without_value_raises(self):
        with self.assertRaises(ValueError):
            _expand_pipe_rule('str|max:')

    def test_in_without_value_raises(self):
        with self.assertRaises(ValueError):
            _expand_pipe_rule('str|in:')


# ---------------------------------------------------------------------------
# End-to-end via validate_data
# ---------------------------------------------------------------------------

class TestPipeEndToEnd(BaseTest):

    def test_email_nullable_valid(self):
        result = validate_data(['alice@example.com'], ['email|nullable'])
        self.assertTrue(result.ok)

    def test_email_nullable_with_none(self):
        result = validate_data([None], ['email|nullable'])
        self.assertTrue(result.ok)

    def test_email_nullable_invalid(self):
        result = validate_data(['not-an-email'], ['email|nullable'])
        self.assertFalse(result.ok)

    def test_str_length_range_valid(self):
        result = validate_data(['alice'], ['str|min:3|max:32'])
        self.assertTrue(result.ok)

    def test_str_length_range_too_short(self):
        result = validate_data(['ab'], ['str|min:3|max:32'])
        self.assertFalse(result.ok)

    def test_int_range_valid(self):
        result = validate_data([25], ['int|min:18|max:100'])
        self.assertTrue(result.ok)

    def test_int_range_too_low(self):
        result = validate_data([15], ['int|min:18|max:100'])
        self.assertFalse(result.ok)

    def test_options_valid(self):
        result = validate_data(['admin'], ['str|in:admin,user,guest'])
        self.assertTrue(result.ok)

    def test_options_invalid(self):
        result = validate_data(['root'], ['str|in:admin,user,guest'])
        self.assertFalse(result.ok)

    def test_transform_applied_before_validation(self):
        result = validate_data(['  ALICE  '], ['str|strip|lower|min:3|max:32'], mutate=True)
        self.assertTrue(result.ok)
        self.assertEqual(result.data, ['alice'])

    def test_transform_strip_enables_length_pass(self):
        # without strip, '  hi  ' has len 6; after strip, 'hi' has len 2 → fails min:3
        result = validate_data(['  hi  '], ['str|strip|min:3'])
        self.assertFalse(result.ok)

    def test_color_format_valid(self):
        result = validate_data(['#ff0000'], ['color|format:hex'])
        self.assertTrue(result.ok)

    def test_color_format_invalid(self):
        result = validate_data(['red'], ['color|format:hex'])
        self.assertFalse(result.ok)

    def test_mixed_pipe_and_dict_rules(self):
        """Pipe shorthand and dict rules can be mixed in the same list."""
        rules = [
            'str|min:3|max:32',
            {'type': 'email'},
            'int|min:18',
        ]
        result = validate_data(['alice', 'alice@example.com', 25], rules)
        self.assertTrue(result.ok)

    def test_old_colon_syntax_unchanged(self):
        """Existing colon shorthand must continue to work alongside pipe syntax."""
        result = validate_data(['hello'], ['str:5'])
        self.assertTrue(result.ok)

    def test_strict_mode_rejects_coercion(self):
        result = validate_data(['42'], ['int|strict'])
        self.assertFalse(result.ok)

    def test_unique_list_valid(self):
        result = validate_data([[1, 2, 3]], ['list|unique'])
        self.assertTrue(result.ok)

    def test_unique_list_invalid(self):
        result = validate_data([[1, 2, 2]], ['list|unique'])
        self.assertFalse(result.ok)


class TestKeysShorthandExpansion(unittest.TestCase):

    def test_shorthand_in_keys_does_not_raise(self):
        """Passing shorthand strings inside {'keys': {...}} should not raise ValueError."""
        try:
            result = validate_data(
                data={'username': 'alice', 'email': 'alice@example.com', 'age': 25},
                rule={'keys': {
                    'username': 'str|min:3|max:32',
                    'email': 'email',
                    'age': 'int|min:18',
                }},
            )
        except ValueError as e:
            self.fail(
                f"validate_data raised ValueError with shorthand inside 'keys': {e}"
            )

    def test_shorthand_in_keys_valid_data_passes(self):
        """Valid data against shorthand keys rules should return ok=True."""
        result = validate_data(
            data={'username': 'alice', 'email': 'alice@example.com', 'age': 25},
            rule={'keys': {
                'username': 'str|min:3|max:32',
                'email': 'email',
                'age': 'int|min:18',
            }},
        )
        self.assertTrue(result.ok)

    def test_shorthand_in_keys_invalid_data_fails(self):
        """Invalid data against shorthand keys rules should return ok=False."""
        result = validate_data(
            data={'username': 'al', 'email': 'not-an-email', 'age': 15},
            rule={'keys': {
                'username': 'str|min:3|max:32',
                'email': 'email',
                'age': 'int|min:18',
            }},
        )
        self.assertFalse(result.ok)

    def test_shorthand_in_keys_matches_flat_list_behaviour(self):
        """Keys-dict shorthand and flat-list shorthand should produce the same result."""
        data_valid = ['alice', 'alice@example.com', 25]
        data_dict = {'username': 'alice', 'email': 'alice@example.com', 'age': 25}

        flat_result = validate_data(
            data=data_valid,
            rule=[
                'str|min:3|max:32',
                'email',
                'int|min:18',
            ],
        )

        keys_result = validate_data(
            data=data_dict,
            rule={'keys': {
                'username': 'str|min:3|max:32',
                'email': 'email',
                'age': 'int|min:18',
            }},
        )

        self.assertEqual(flat_result.ok, keys_result.ok)
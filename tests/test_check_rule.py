"""
Tests for the 0.4.0 rule-validation features:
  - VALID_RULE_KEYS exported frozenset
  - Unknown rule key detection with did-you-mean suggestions
  - check_rule() public function
"""

import unittest

from validatedata import check_rule, VALID_RULE_KEYS, validate_data
from .base import BaseTest


class TestValidRuleKeys(BaseTest):

    def test_is_frozenset(self):
        self.assertIsInstance(VALID_RULE_KEYS, frozenset)

    def test_contains_expected_keys(self):
        for key in ('type', 'keys', 'fields', 'items', 'range', 'length',
                    'nullable', 'strict', 'message', 'transform', 'depends_on'):
            self.assertIn(key, VALID_RULE_KEYS, f"Expected '{key}' in VALID_RULE_KEYS")

    def test_is_immutable(self):
        with self.assertRaises(AttributeError):
            VALID_RULE_KEYS.add('fake_key')


class TestUnknownKeyDetection(BaseTest):

    def test_unknown_key_raises_value_error(self):
        with self.assertRaises(ValueError):
            validate_data(['hello'], [{'type': 'str', 'nulable': True}])

    def test_error_message_includes_bad_key(self):
        with self.assertRaises(ValueError) as ctx:
            validate_data(['hello'], [{'type': 'str', 'nulable': True}])
        self.assertIn('nulable', str(ctx.exception))

    def test_did_you_mean_suggestion(self):
        with self.assertRaises(ValueError) as ctx:
            validate_data(['hello'], [{'type': 'str', 'nulable': True}])
        self.assertIn('nullable', str(ctx.exception))

    def test_no_suggestion_for_gibberish(self):
        # A key with no close match should still raise but without a suggestion
        with self.assertRaises(ValueError) as ctx:
            validate_data(['hello'], [{'type': 'str', 'zzzzfake': True}])
        self.assertNotIn('Did you mean', str(ctx.exception))

    def test_multiple_unknown_keys_reported(self):
        with self.assertRaises(ValueError) as ctx:
            validate_data(['hello'], [{'type': 'str', 'nulable': True, 'strikt': True}])
        msg = str(ctx.exception)
        self.assertIn('nulable', msg)
        self.assertIn('strikt', msg)

    def test_message_suffix_keys_are_allowed(self):
        # Any '<key>-message' key should not raise
        rule = [{'type': 'int', 'range': (1, 10), 'range-message': 'out of range'}]
        self.assertTrue(validate_data([5], rule).ok)

    def test_valid_rule_dict_does_not_raise(self):
        rule = [{'type': 'str', 'nullable': True, 'length': 5, 'strict': True}]
        try:
            validate_data(['hello'], rule)
        except ValueError:
            self.fail("validate_data raised ValueError on a valid rule dict")


class TestCheckRule(BaseTest):

    def test_valid_rule_passes_silently(self):
        try:
            check_rule({'type': 'str', 'nullable': True})
        except ValueError:
            self.fail("check_rule raised ValueError on a valid rule")

    def test_unknown_key_raises_value_error(self):
        with self.assertRaises(ValueError):
            check_rule({'type': 'str', 'nulable': True})

    def test_did_you_mean_in_message(self):
        with self.assertRaises(ValueError) as ctx:
            check_rule({'type': 'str', 'nulable': True})
        self.assertIn('nullable', str(ctx.exception))

    def test_keys_wrapper_is_valid(self):
        # The canonical {'keys': {...}} form must not raise
        try:
            check_rule({'keys': {'username': {'type': 'str'}}})
        except ValueError:
            self.fail("check_rule raised ValueError on canonical {'keys': {...}} rule")

    def test_returns_none_on_success(self):
        result = check_rule({'type': 'int', 'range': (1, 100)})
        self.assertIsNone(result)

    def test_does_not_accept_path_as_argument(self):
        # check_rule is a clean public API — path param must not be exposed
        import inspect
        sig = inspect.signature(check_rule)
        self.assertNotIn('path', sig.parameters)


if __name__ == '__main__':
    unittest.main()

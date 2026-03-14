"""
Tests for the nested dict shorthand feature.

A bare dict whose values are field rules (rather than a single rule dict
with a 'type' key) is treated as a shorthand for the canonical
{'type': 'dict', 'fields': {...}} form, mirroring the shape of the data.

Covers: bare field map, keys wrapper, valid/invalid data, error paths,
and mutate=True data reconstruction.
"""

import unittest

from validatedata import validate_data
from .base import BaseTest


# ---------------------------------------------------------------------------
# Bare field map (no 'keys' wrapper)
# ---------------------------------------------------------------------------

class TestNestedShorthandBareMap(BaseTest):

    def test_valid_data_passes(self):
        result = validate_data(
            data={'app': {'name': 'QuickScript', 'version': '1.0.0'}},
            rule={'app': {'name': 'str|min:3', 'version': 'semver'}},
        )
        self.assertTrue(result.ok)

    def test_invalid_semver_fails(self):
        result = validate_data(
            data={'app': {'name': 'QuickScript', 'version': '1'}},
            rule={'app': {'name': 'str|min:3', 'version': 'semver'}},
        )
        self.assertFalse(result.ok)

    def test_invalid_semver_error_path(self):
        result = validate_data(
            data={'app': {'name': 'QuickScript', 'version': '1'}},
            rule={'app': {'name': 'str|min:3', 'version': 'semver'}},
        )
        self.assertTrue(any('app.version' in e for e in result.errors))

    def test_invalid_field_in_nested_dict(self):
        result = validate_data(
            data={'app': {'name': 'ab', 'version': '1.0.0'}},
            rule={'app': {'name': 'str|min:3', 'version': 'semver'}},
        )
        self.assertFalse(result.ok)

    def test_invalid_field_error_path(self):
        result = validate_data(
            data={'app': {'name': 'ab', 'version': '1.0.0'}},
            rule={'app': {'name': 'str|min:3', 'version': 'semver'}},
        )
        self.assertTrue(any('app.name' in e for e in result.errors))

    def test_multiple_nested_dicts_both_valid(self):
        result = validate_data(
            data={
                'app': {'name': 'QuickScript', 'version': '1.0.0'},
                'database': {'host': '127.0.0.1', 'port': 5432},
            },
            rule={
                'app': {'name': 'str|min:3', 'version': 'semver'},
                'database': {'host': 'ip', 'port': 'int|between:1,65535'},
            },
        )
        self.assertTrue(result.ok)

    def test_multiple_nested_dicts_one_invalid(self):
        result = validate_data(
            data={
                'app': {'name': 'QuickScript', 'version': '1'},
                'database': {'host': '127.0.0.1', 'port': 5432},
            },
            rule={
                'app': {'name': 'str|min:3', 'version': 'semver'},
                'database': {'host': 'ip', 'port': 'int|between:1,65535'},
            },
        )
        self.assertFalse(result.ok)

    def test_multiple_nested_dicts_error_only_on_failing_field(self):
        result = validate_data(
            data={
                'app': {'name': 'QuickScript', 'version': '1'},
                'database': {'host': '127.0.0.1', 'port': 5432},
            },
            rule={
                'app': {'name': 'str|min:3', 'version': 'semver'},
                'database': {'host': 'ip', 'port': 'int|between:1,65535'},
            },
        )
        self.assertTrue(any('app.version' in e for e in result.errors))
        self.assertFalse(any('database' in e for e in result.errors))


# ---------------------------------------------------------------------------
# Keys wrapper form
# ---------------------------------------------------------------------------

class TestNestedShorthandKeysWrapper(BaseTest):

    def test_valid_data_passes(self):
        result = validate_data(
            data={'app': {'name': 'QuickScript', 'version': '1.0.0'}},
            rule={'keys': {'app': {'name': 'str|min:3', 'version': 'semver'}}},
        )
        self.assertTrue(result.ok)

    def test_invalid_semver_fails(self):
        result = validate_data(
            data={'app': {'name': 'QuickScript', 'version': '1'}},
            rule={'keys': {'app': {'name': 'str|min:3', 'version': 'semver'}}},
        )
        self.assertFalse(result.ok)

    def test_invalid_semver_error_path(self):
        result = validate_data(
            data={'app': {'name': 'QuickScript', 'version': '1'}},
            rule={'keys': {'app': {'name': 'str|min:3', 'version': 'semver'}}},
        )
        self.assertTrue(any('app.version' in e for e in result.errors))

    def test_mixed_flat_and_nested_rules(self):
        """A keys dict can mix flat string rules and nested dict shorthand."""
        result = validate_data(
            data={
                'owner': 'alice',
                'app': {'name': 'QuickScript', 'version': '1.0.0'},
            },
            rule={'keys': {
                'owner': 'str|min:3',
                'app': {'name': 'str|min:3', 'version': 'semver'},
            }},
        )
        self.assertTrue(result.ok)

    def test_mixed_flat_and_nested_flat_field_invalid(self):
        result = validate_data(
            data={
                'owner': 'al',
                'app': {'name': 'QuickScript', 'version': '1.0.0'},
            },
            rule={'keys': {
                'owner': 'str|min:3',
                'app': {'name': 'str|min:3', 'version': 'semver'},
            }},
        )
        self.assertFalse(result.ok)


# ---------------------------------------------------------------------------
# mutate=True — data reconstruction
# ---------------------------------------------------------------------------

class TestNestedShorthandMutate(BaseTest):

    def test_mutate_valid_data_reconstructs_nested_dict(self):
        result = validate_data(
            data={
                'app': {'name': 'QuickScript', 'version': '1.0.0'},
                'database': {'host': '127.0.0.1', 'port': 5432},
            },
            rule={
                'app': {'name': 'str|min:3', 'version': 'semver'},
                'database': {'host': 'ip', 'port': 'int|between:1,65535'},
            },
            mutate=True,
        )
        self.assertTrue(result.ok)
        self.assertEqual(result.data, [
            {'name': 'QuickScript', 'version': '1.0.0'},
            {'host': '127.0.0.1', 'port': 5432},
        ])

    def test_mutate_preserves_nested_dict_structure(self):
        """result.data must be a list of dicts, not a flat list of leaf values."""
        result = validate_data(
            data={'app': {'name': 'QuickScript', 'version': '1.0.0'}},
            rule={'app': {'name': 'str|min:3', 'version': 'semver'}},
            mutate=True,
        )
        self.assertEqual(len(result.data), 1)
        self.assertIsInstance(result.data[0], dict)
        self.assertIn('name', result.data[0])
        self.assertIn('version', result.data[0])

    def test_mutate_with_transform_in_nested_field(self):
        """Transforms on nested fields should be reflected in the reconstructed dict."""
        result = validate_data(
            data={'app': {'name': '  quickscript  ', 'version': '1.0.0'}},
            rule={'app': {'name': 'str|strip|min:3', 'version': 'semver'}},
            mutate=True,
        )
        self.assertTrue(result.ok)
        self.assertEqual(result.data[0]['name'], 'quickscript')

    def test_mutate_invalid_data_has_no_data_key(self):
        """When validation fails, result.data should still be present but reflect input."""
        result = validate_data(
            data={'app': {'name': 'QuickScript', 'version': '1'}},
            rule={'app': {'name': 'str|min:3', 'version': 'semver'}},
            mutate=True,
        )
        self.assertFalse(result.ok)
        # data is present even on failure — it should still be a list of dicts
        self.assertIsInstance(result.data[0], dict)

    def test_mutate_false_has_no_data_attribute(self):
        result = validate_data(
            data={'app': {'name': 'QuickScript', 'version': '1.0.0'}},
            rule={'app': {'name': 'str|min:3', 'version': 'semver'}},
            mutate=False,
        )
        self.assertFalse(hasattr(result, 'data'))


# ---------------------------------------------------------------------------
# Recursion — multi-level shorthand
# ---------------------------------------------------------------------------

class TestNestedShorthandRecursion(BaseTest):

    def test_two_levels_valid(self):
        result = validate_data(
            data={'company': {'address': {'postcode': 'AB1 2CD'}}},
            rule={'company': {'address': {'postcode': 'str|min:6'}}},
        )
        self.assertTrue(result.ok)

    def test_two_levels_invalid_inner_field(self):
        result = validate_data(
            data={'company': {'address': {'postcode': '123'}}},
            rule={'company': {'address': {'postcode': 'str|min:6'}}},
        )
        self.assertFalse(result.ok)

    def test_two_levels_error_path(self):
        result = validate_data(
            data={'company': {'address': {'postcode': '123'}}},
            rule={'company': {'address': {'postcode': 'str|min:6'}}},
        )
        self.assertTrue(any('company.address.postcode' in e for e in result.errors))

    def test_three_levels_valid(self):
        result = validate_data(
            data={'a': {'b': {'c': {'value': 42}}}},
            rule={'a': {'b': {'c': {'value': 'int'}}}},
        )
        self.assertTrue(result.ok)

    def test_three_levels_invalid(self):
        result = validate_data(
            data={'a': {'b': {'c': {'value': 'not-an-int'}}}},
            rule={'a': {'b': {'c': {'value': 'int'}}}},
        )
        self.assertFalse(result.ok)

    def test_three_levels_error_path(self):
        result = validate_data(
            data={'a': {'b': {'c': {'value': 'not-an-int'}}}},
            rule={'a': {'b': {'c': {'value': 'int'}}}},
        )
        self.assertTrue(any('a.b.c.value' in e for e in result.errors))

    def test_mutate_two_levels(self):
        result = validate_data(
            data={'company': {'address': {'postcode': 'AB1 2CD'}}},
            rule={'company': {'address': {'postcode': 'str|min:6'}}},
            mutate=True,
        )
        self.assertTrue(result.ok)
        self.assertEqual(result.data, [{'address': {'postcode': 'AB1 2CD'}}])

    def test_mutate_three_levels(self):
        result = validate_data(
            data={'a': {'b': {'c': {'value': 42}}}},
            rule={'a': {'b': {'c': {'value': 'int'}}}},
            mutate=True,
        )
        self.assertTrue(result.ok)
        self.assertEqual(result.data, [{'b': {'c': {'value': 42}}}])

    def test_mutate_with_transform_propagates_through_levels(self):
        result = validate_data(
            data={'user': {'profile': {'name': '  alice  '}}},
            rule={'user': {'profile': {'name': 'str|strip|min:3'}}},
            mutate=True,
        )
        self.assertTrue(result.ok)
        self.assertEqual(result.data[0]['profile']['name'], 'alice')

    def test_ten_levels_allowed(self):
        """Nesting up to MAX_NESTING_DEPTH levels must not raise."""
        def make_deep(n):
            rule = 'str'
            data = 'hello'
            for _ in range(n):
                rule = {'x': rule}
                data = {'x': data}
            return data, rule

        data, rule = make_deep(100)
        try:
            result = validate_data(data=data, rule=rule)
        except ValueError:
            self.fail('validate_data raised ValueError within the allowed depth of 10')

    def test_one_hundred_one_levels_raises(self):
        """Nesting beyond MAX_NESTING_DEPTH must raise ValueError with path info."""
        def make_deep(n):
            rule = 'str'
            data = 'hello'
            for _ in range(n):
                rule = {'x': rule}
                data = {'x': data}
            return data, rule

        data, rule = make_deep(101)
        with self.assertRaises(ValueError) as ctx:
            validate_data(data=data, rule=rule)
        self.assertIn('100', str(ctx.exception))

    def test_mixed_flat_and_deep_shorthand(self):
        """Top-level can mix flat string rules with multi-level nested shorthand."""
        result = validate_data(
            data={
                'owner': 'alice',
                'company': {'address': {'postcode': 'AB1 2CD'}},
            },
            rule={
                'owner': 'str|min:3',
                'company': {'address': {'postcode': 'str|min:6'}},
            },
        )
        self.assertTrue(result.ok)

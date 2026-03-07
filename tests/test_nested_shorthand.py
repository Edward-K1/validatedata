"""
Tests for the nested dict shorthand feature.

A bare dict whose values are field rules (rather than a single rule dict
with a 'type' key) is treated as a shorthand for the canonical
{'type': 'dict', 'fields': {...}} form, mirroring the shape of the data.

Covers: bare field map, keys wrapper, valid/invalid data, error paths,
and mutate=True data reconstruction.
"""


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

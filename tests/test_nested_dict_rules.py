"""Tests for nested dict rule support in compiled.py fast path.

A dict rule value that is itself a dict is compiled recursively, mirroring
the shape of the data being validated. These tests cover:

  - single-level nesting: valid/invalid data, missing fields, wrong type
  - double and triple nesting
  - codegen=True path
  - cache behaviour
  - interaction with inner pipe modifiers (nullable, transforms, ranges)
  - list values still rejected
  - extra keys in data are ignored at every level
  - empty nested rule dict
"""
from __future__ import annotations

import unittest

from validatedata import validator
from validatedata.compiled import _COMPILED_CACHE


# ===========================================================================
# Single-level nesting
# ===========================================================================

class TestSingleLevelNesting(unittest.TestCase):

    def test_valid_data_passes(self):
        v = validator({'user': {'name': 'str', 'age': 'int'}})
        self.assertTrue(v({'user': {'name': 'Alice', 'age': 30}}))

    def test_inner_field_invalid_returns_false(self):
        v = validator({'user': {'name': 'str|min:3', 'age': 'int'}})
        self.assertFalse(v({'user': {'name': 'Al', 'age': 30}}))

    def test_missing_inner_required_field_returns_false(self):
        v = validator({'user': {'name': 'str', 'age': 'int'}})
        self.assertFalse(v({'user': {'name': 'Alice'}}))

    def test_missing_outer_field_returns_false(self):
        v = validator({'user': {'name': 'str'}})
        self.assertFalse(v({}))

    def test_non_dict_value_for_nested_field_returns_false(self):
        v = validator({'user': {'name': 'str'}})
        self.assertFalse(v({'user': 'not-a-dict'}))
        self.assertFalse(v({'user': None}))
        self.assertFalse(v({'user': 42}))

    def test_extra_keys_in_nested_data_are_ignored(self):
        v = validator({'user': {'name': 'str'}})
        self.assertTrue(v({'user': {'name': 'Alice', 'extra': True}}))

    def test_multiple_nested_fields_at_top_level(self):
        v = validator({
            'app': {'name': 'str|min:3', 'version': 'semver'},
            'db':  {'host': 'ip',        'port':    'int|between:1,65535'},
        })
        self.assertTrue(v({
            'app': {'name': 'QuickScript', 'version': '1.0.0'},
            'db':  {'host': '127.0.0.1',   'port':    5432},
        }))

    def test_one_of_multiple_nested_fields_invalid(self):
        v = validator({
            'app': {'name': 'str|min:3', 'version': 'semver'},
            'db':  {'host': 'ip',        'port':    'int'},
        })
        self.assertFalse(v({
            'app': {'name': 'QuickScript', 'version': 'not-semver'},
            'db':  {'host': '127.0.0.1',   'port':    5432},
        }))


# ===========================================================================
# Mixed flat and nested fields at the top level
# ===========================================================================

class TestMixedFlatAndNestedFields(unittest.TestCase):

    def test_flat_and_nested_both_valid(self):
        v = validator({
            'owner': 'str|min:2',
            'address': {'street': 'str', 'city': 'str'},
        })
        self.assertTrue(v({
            'owner': 'Alice',
            'address': {'street': '1 Main St', 'city': 'Springfield'},
        }))

    def test_flat_field_invalid(self):
        v = validator({
            'owner': 'str|min:5',
            'address': {'street': 'str'},
        })
        self.assertFalse(v({'owner': 'Al', 'address': {'street': '1 Main St'}}))

    def test_nested_field_invalid(self):
        v = validator({
            'owner': 'str',
            'address': {'street': 'str|min:5'},
        })
        self.assertFalse(v({'owner': 'Alice', 'address': {'street': 'X'}}))


# ===========================================================================
# Deep nesting
# ===========================================================================

class TestDeepNesting(unittest.TestCase):

    def test_two_levels_valid(self):
        v = validator({'company': {'address': {'postcode': 'str|min:6'}}})
        self.assertTrue(v({'company': {'address': {'postcode': 'AB1 2CD'}}}))

    def test_two_levels_inner_field_invalid(self):
        v = validator({'company': {'address': {'postcode': 'str|min:6'}}})
        self.assertFalse(v({'company': {'address': {'postcode': '123'}}}))

    def test_two_levels_missing_middle_field(self):
        v = validator({'company': {'address': {'postcode': 'str'}}})
        self.assertFalse(v({'company': {}}))

    def test_three_levels_valid(self):
        v = validator({'a': {'b': {'c': {'value': 'int'}}}})
        self.assertTrue(v({'a': {'b': {'c': {'value': 42}}}}))

    def test_three_levels_invalid(self):
        v = validator({'a': {'b': {'c': {'value': 'int'}}}})
        self.assertFalse(v({'a': {'b': {'c': {'value': 'not-an-int'}}}}))

    def test_three_levels_missing_innermost_field(self):
        v = validator({'a': {'b': {'c': {'value': 'int'}}}})
        self.assertFalse(v({'a': {'b': {'c': {}}}}))


# ===========================================================================
# Inner pipe modifiers propagate correctly
# ===========================================================================

class TestInnerPipeModifiers(unittest.TestCase):

    def test_inner_nullable_missing_key_passes(self):
        v = validator({'user': {'name': 'str', 'nickname': 'str|nullable'}})
        self.assertTrue(v({'user': {'name': 'Alice'}}))

    def test_inner_nullable_explicit_none_passes(self):
        v = validator({'user': {'name': 'str', 'nickname': 'str|nullable'}})
        self.assertTrue(v({'user': {'name': 'Alice', 'nickname': None}}))

    def test_inner_range_enforced(self):
        v = validator({'config': {'timeout': 'int|between:1,300'}})
        self.assertTrue(v({'config': {'timeout': 60}}))
        self.assertFalse(v({'config': {'timeout': 0}}))
        self.assertFalse(v({'config': {'timeout': 301}}))

    def test_inner_transform_applied(self):
        v = validator({'meta': {'tag': 'str|strip|lower|min:2'}})
        self.assertTrue(v({'meta': {'tag': '  HELLO  '}}))
        self.assertFalse(v({'meta': {'tag': '  X  '}}))

    def test_inner_in_options_enforced(self):
        v = validator({'settings': {'theme': 'str|in:light,dark,system'}})
        self.assertTrue(v({'settings': {'theme': 'dark'}}))
        self.assertFalse(v({'settings': {'theme': 'neon'}}))


# ===========================================================================
# codegen=True path
# ===========================================================================

class TestCodegenPath(unittest.TestCase):

    def test_single_level_valid(self):
        v = validator({'user': {'name': 'str', 'age': 'int'}}, codegen=True)
        self.assertTrue(v({'user': {'name': 'Alice', 'age': 30}}))

    def test_single_level_invalid(self):
        v = validator({'user': {'name': 'str|min:5', 'age': 'int'}}, codegen=True)
        self.assertFalse(v({'user': {'name': 'Al', 'age': 30}}))

    def test_two_levels(self):
        v = validator({'company': {'address': {'postcode': 'str'}}}, codegen=True)
        self.assertTrue(v({'company': {'address': {'postcode': 'AB1 2CD'}}}))
        self.assertFalse(v({'company': {'address': {}}}))

    def test_non_dict_outer_value(self):
        v = validator({'user': {'name': 'str'}}, codegen=True)
        self.assertFalse(v({'user': 'not-a-dict'}))


# ===========================================================================
# Cache behaviour
# ===========================================================================

class TestNestedDictCache(unittest.TestCase):

    def setUp(self):
        _COMPILED_CACHE.clear()

    def test_same_nested_rule_returns_same_object(self):
        v1 = validator({'user': {'name': 'str', 'age': 'int'}})
        v2 = validator({'user': {'name': 'str', 'age': 'int'}})
        self.assertIs(v1, v2)

    def test_different_nested_rules_are_different_objects(self):
        v1 = validator({'user': {'name': 'str|min:2'}})
        v2 = validator({'user': {'name': 'str|min:5'}})
        self.assertIsNot(v1, v2)

    def test_deep_nested_rule_cache_hit(self):
        v1 = validator({'a': {'b': {'c': 'int'}}})
        v2 = validator({'a': {'b': {'c': 'int'}}})
        self.assertIs(v1, v2)

    def test_key_order_independent_cache_hit(self):
        """json.dumps sort_keys=True means insertion order doesn't affect the key."""
        v1 = validator({'user': {'age': 'int', 'name': 'str'}})
        v2 = validator({'user': {'name': 'str', 'age': 'int'}})
        self.assertIs(v1, v2)


# ===========================================================================
# Error cases
# ===========================================================================

class TestNestedDictErrors(unittest.TestCase):

    def test_list_value_in_nested_rule_raises(self):
        with self.assertRaises(ValueError):
            validator({'user': {'tags': ['str']}})

    def test_list_value_at_top_level_still_raises(self):
        with self.assertRaises(ValueError):
            validator({'tags': ['str']})

    def test_non_str_non_dict_value_in_nested_rule_raises(self):
        with self.assertRaises(ValueError):
            validator({'user': {'age': 42}})

    def test_unknown_type_in_nested_rule_raises(self):
        with self.assertRaises(TypeError):
            validator({'user': {'x': 'notareal_type'}})

    def test_unknown_modifier_in_nested_rule_raises(self):
        with self.assertRaises(ValueError):
            validator({'user': {'x': 'str|unknown_modifier'}})


# ===========================================================================
# Edge cases
# ===========================================================================

class TestNestedDictEdgeCases(unittest.TestCase):

    def test_empty_nested_rule_passes_any_dict(self):
        v = validator({'meta': {}})
        self.assertTrue(v({'meta': {}}))
        self.assertTrue(v({'meta': {'anything': 'goes'}}))

    def test_empty_nested_rule_fails_non_dict(self):
        v = validator({'meta': {}})
        self.assertFalse(v({'meta': 'not-a-dict'}))
        self.assertFalse(v({}))

    def test_non_dict_top_level_data_returns_false(self):
        v = validator({'user': {'name': 'str'}})
        self.assertFalse(v('not a dict'))
        self.assertFalse(v(None))
        self.assertFalse(v(42))


if __name__ == '__main__':
    unittest.main()
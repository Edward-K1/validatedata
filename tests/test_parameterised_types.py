"""
Tests for parameterized type support in compiled.py fast path.

Covers: list[str], tuple[int], set[email], union types list[int,str],
the bool subclass guard, container modifiers (min/max/length/nullable),
dict rules, error cases, tokenizer compatibility, and cache behaviour.

"""
from __future__ import annotations

import unittest

from validatedata import validator
from validatedata.compiled import (
    _COMPILED_CACHE,
    _build_parameterized_type_check,
    _ITEM_TYPE_CHECK,
    _PARAMETERIZED_RE,
)


# ===========================================================================
# Module-level constants — sanity checks
# ===========================================================================

class TestModuleConstants(unittest.TestCase):
    """_PARAMETERIZED_RE and _ITEM_TYPE_CHECK must exist with the right shape."""

    def test_parameterized_re_matches_list_str(self):
        m = _PARAMETERIZED_RE.match('list[str]')
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), 'list')
        self.assertEqual(m.group(2), 'str')

    def test_parameterized_re_matches_tuple_int(self):
        m = _PARAMETERIZED_RE.match('tuple[int]')
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), 'tuple')
        self.assertEqual(m.group(2), 'int')

    def test_parameterized_re_matches_set_email(self):
        m = _PARAMETERIZED_RE.match('set[email]')
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), 'set')
        self.assertEqual(m.group(2), 'email')

    def test_parameterized_re_matches_union(self):
        m = _PARAMETERIZED_RE.match('list[int,str]')
        self.assertIsNotNone(m)
        self.assertEqual(m.group(2), 'int,str')

    def test_parameterized_re_does_not_match_plain_list(self):
        self.assertIsNone(_PARAMETERIZED_RE.match('list'))

    def test_parameterized_re_does_not_match_dict(self):
        # dict is not a supported outer container in the fast path
        self.assertIsNone(_PARAMETERIZED_RE.match('dict[str]'))

    def test_parameterized_re_does_not_match_nested(self):
        # nested parameterization is not supported
        self.assertIsNone(_PARAMETERIZED_RE.match('list[list[str]]'))

    def test_item_type_check_has_int_override(self):
        """_ITEM_TYPE_CHECK['int'] must exclude bool; top-level _TYPE_CHECK['int'] must not."""
        from validatedata.compiled import _TYPE_CHECK
        # top-level int still passes bool (documented engine behaviour)
        self.assertTrue(_TYPE_CHECK['int'](True))
        # item-level int must reject bool
        self.assertFalse(_ITEM_TYPE_CHECK['int'](True))
        self.assertFalse(_ITEM_TYPE_CHECK['int'](False))

    def test_item_type_check_int_accepts_real_int(self):
        self.assertTrue(_ITEM_TYPE_CHECK['int'](1))
        self.assertTrue(_ITEM_TYPE_CHECK['int'](0))
        self.assertTrue(_ITEM_TYPE_CHECK['int'](-5))

    def test_item_type_check_inherits_all_other_types(self):
        """Everything except int should be identical between the two tables."""
        from validatedata.compiled import _TYPE_CHECK
        for key in _TYPE_CHECK:
            if key == 'int':
                continue
            self.assertIs(
                _ITEM_TYPE_CHECK[key], _TYPE_CHECK[key],
                f'_ITEM_TYPE_CHECK[{key!r}] should be the same object as _TYPE_CHECK[{key!r}]',
            )


# ===========================================================================
# _build_parameterized_type_check — unit tests
# ===========================================================================

class TestBuildParameterizedTypeCheck(unittest.TestCase):
    """Test the helper function directly, independent of the compiler."""

    # --- single native ---

    def test_list_str_single(self):
        fn = _build_parameterized_type_check('list', ['str'])
        self.assertTrue(fn(['a', 'b', 'c']))
        self.assertFalse(fn(['a', 1, 'c']))
        self.assertFalse(fn('not a list'))

    def test_list_int_single(self):
        fn = _build_parameterized_type_check('list', ['int'])
        self.assertTrue(fn([1, 2, 3]))
        self.assertFalse(fn([1, '2', 3]))

    def test_tuple_float_single(self):
        fn = _build_parameterized_type_check('tuple', ['float'])
        self.assertTrue(fn((1.0, 2.5)))
        self.assertFalse(fn((1, 2.5)))    # 1 is int, not float

    def test_set_str_single(self):
        fn = _build_parameterized_type_check('set', ['str'])
        self.assertTrue(fn({'a', 'b'}))
        self.assertFalse(fn({1, 2}))

    # --- empty container passes (no items to fail) ---

    def test_empty_list_passes(self):
        fn = _build_parameterized_type_check('list', ['str'])
        self.assertTrue(fn([]))

    def test_empty_tuple_passes(self):
        fn = _build_parameterized_type_check('tuple', ['int'])
        self.assertTrue(fn(()))

    # --- non-native single ---

    def test_list_email_single(self):
        fn = _build_parameterized_type_check('list', ['email'])
        self.assertTrue(fn(['a@b.com', 'x@y.org']))
        self.assertFalse(fn(['a@b.com', 'not-an-email']))

    def test_list_url_single(self):
        fn = _build_parameterized_type_check('list', ['url'])
        self.assertTrue(fn(['https://example.com']))
        self.assertFalse(fn(['not-a-url']))

    def test_list_uuid_single(self):
        fn = _build_parameterized_type_check('list', ['uuid'])
        self.assertTrue(fn(['123e4567-e89b-12d3-a456-426614174000']))
        self.assertFalse(fn(['not-a-uuid']))

    # --- all-native union ---

    def test_list_int_str_union(self):
        fn = _build_parameterized_type_check('list', ['int', 'str'])
        self.assertTrue(fn([1, 'a', 2, 'b']))
        self.assertFalse(fn([1, 'a', 2.5]))   # float not in union

    def test_list_int_float_union(self):
        fn = _build_parameterized_type_check('list', ['int', 'float'])
        self.assertTrue(fn([1, 2.5, 3]))
        self.assertFalse(fn([1, 2.5, 'x']))

    # --- mixed native/non-native union ---

    def test_list_email_url_union(self):
        fn = _build_parameterized_type_check('list', ['email', 'url'])
        self.assertTrue(fn(['a@b.com', 'https://example.com']))
        self.assertFalse(fn(['a@b.com', 'not-either']))

    # --- 3-way union fallback path ---

    def test_list_int_str_float_union(self):
        fn = _build_parameterized_type_check('list', ['int', 'str', 'float'])
        self.assertTrue(fn([1, 'a', 2.5]))
        self.assertFalse(fn([1, 'a', None]))

    # --- wrong outer type rejects non-container ---

    def test_rejects_non_list(self):
        fn = _build_parameterized_type_check('list', ['str'])
        self.assertFalse(fn('just a string'))
        self.assertFalse(fn(None))
        self.assertFalse(fn(42))

    # --- bad item type raises TypeError at compile time ---

    def test_bad_item_type_raises(self):
        with self.assertRaises(TypeError):
            _build_parameterized_type_check('list', ['notareal'])

    def test_second_item_bad_raises(self):
        with self.assertRaises(TypeError):
            _build_parameterized_type_check('list', ['str', 'notareal'])


# ===========================================================================
# Bool subclass guard — the critical edge case
# ===========================================================================

class TestBoolSubclassGuard(unittest.TestCase):
    """bool is a subclass of int in Python. list[int] must NOT silently pass bools."""

    def test_list_int_rejects_true(self):
        v = validator('list[int]')
        self.assertFalse(v([1, True, 3]))

    def test_list_int_rejects_false(self):
        v = validator('list[int]')
        self.assertFalse(v([1, False, 3]))

    def test_list_int_rejects_all_bool(self):
        v = validator('list[int]')
        self.assertFalse(v([True, False]))

    def test_list_int_accepts_real_ints(self):
        v = validator('list[int]')
        self.assertTrue(v([1, 2, 3]))
        self.assertTrue(v([0, -1, 100]))

    def test_list_bool_accepts_bools(self):
        """bool explicitly requested — should pass."""
        v = validator('list[bool]')
        self.assertTrue(v([True, False, True]))

    def test_list_bool_rejects_int(self):
        """isinstance(1, bool) is False — int is not bool."""
        v = validator('list[bool]')
        self.assertFalse(v([1, 0]))

    def test_list_int_bool_union_accepts_both(self):
        """bool explicitly in the union — both int and bool should pass."""
        v = validator('list[int,bool]')
        self.assertTrue(v([1, True, 2, False]))

    def test_list_int_str_rejects_bool(self):
        """bool is not in the int,str union — must be rejected."""
        v = validator('list[int,str]')
        self.assertFalse(v([1, 'a', True]))

    def test_tuple_int_rejects_bool(self):
        v = validator('tuple[int]')
        self.assertFalse(v((1, True, 3)))

    def test_set_int_rejects_bool(self):
        # Note: {1, True} in Python deduplicates to {1} because True == 1.
        # The set itself only contains one element (int 1), so this passes.
        # Test the meaningful case: a set that still has a bool after dedup.
        v = validator('set[int]')
        # {True} — the sole element is a bool, not a plain int
        self.assertFalse(v({True}))


# ===========================================================================
# Single item type via validator() — all container types
# ===========================================================================

class TestSingleItemTypes(unittest.TestCase):

    # --- list ---

    def test_list_str_valid(self):
        self.assertTrue(validator('list[str]')(['a', 'b', 'c']))

    def test_list_str_invalid_item(self):
        self.assertFalse(validator('list[str]')(['a', 1]))

    def test_list_int_valid(self):
        self.assertTrue(validator('list[int]')([1, 2, 3]))

    def test_list_int_invalid_item(self):
        self.assertFalse(validator('list[int]')([1, '2']))

    def test_list_float_valid(self):
        self.assertTrue(validator('list[float]')([1.0, 2.5, 3.14]))

    def test_list_float_rejects_int_item(self):
        # int is not float in the strict item check
        self.assertFalse(validator('list[float]')([1, 2.5]))

    def test_list_bool_valid(self):
        self.assertTrue(validator('list[bool]')([True, False]))

    def test_list_email_valid(self):
        self.assertTrue(validator('list[email]')(['a@b.com', 'x@y.org']))

    def test_list_email_invalid(self):
        self.assertFalse(validator('list[email]')(['a@b.com', 'bad']))

    def test_list_url_valid(self):
        self.assertTrue(validator('list[url]')(['https://a.com', 'http://b.org']))

    def test_list_uuid_valid(self):
        self.assertTrue(validator('list[uuid]')(['123e4567-e89b-12d3-a456-426614174000']))

    def test_list_slug_valid(self):
        self.assertTrue(validator('list[slug]')(['my-slug', 'another-one']))

    def test_list_slug_invalid(self):
        self.assertFalse(validator('list[slug]')(['my-slug', 'Bad Slug!']))

    # --- tuple ---

    def test_tuple_str_valid(self):
        self.assertTrue(validator('tuple[str]')(('a', 'b')))

    def test_tuple_str_invalid(self):
        self.assertFalse(validator('tuple[str]')(('a', 1)))

    def test_tuple_int_valid(self):
        self.assertTrue(validator('tuple[int]')((1, 2, 3)))

    def test_tuple_float_valid(self):
        self.assertTrue(validator('tuple[float]')((1.0, 2.5)))

    # --- set ---

    def test_set_str_valid(self):
        self.assertTrue(validator('set[str]')({'a', 'b', 'c'}))

    def test_set_str_invalid(self):
        self.assertFalse(validator('set[str]')({'a', 1}))

    def test_set_int_valid(self):
        self.assertTrue(validator('set[int]')({1, 2, 3}))

    # --- wrong outer type ---

    def test_list_str_rejects_tuple(self):
        self.assertFalse(validator('list[str]')(('a', 'b')))

    def test_tuple_str_rejects_list(self):
        self.assertFalse(validator('tuple[str]')(['a', 'b']))

    def test_set_str_rejects_list(self):
        self.assertFalse(validator('set[str]')(['a', 'b']))

    # --- non-container input ---

    def test_list_str_rejects_string(self):
        self.assertFalse(validator('list[str]')('just a string'))

    def test_list_int_rejects_none(self):
        self.assertFalse(validator('list[int]')(None))


# ===========================================================================
# Union item types via validator()
# ===========================================================================

class TestUnionItemTypes(unittest.TestCase):

    def test_list_int_str_accepts_mixed(self):
        v = validator('list[int,str]')
        self.assertTrue(v([1, 'a', 2, 'b']))

    def test_list_int_str_rejects_float(self):
        v = validator('list[int,str]')
        self.assertFalse(v([1, 2.5]))

    def test_list_int_float_accepts_mixed(self):
        v = validator('list[int,float]')
        self.assertTrue(v([1, 2.5, 3]))

    def test_list_email_url_accepts_either(self):
        v = validator('list[email,url]')
        self.assertTrue(v(['a@b.com', 'https://example.com', 'x@y.org']))

    def test_list_email_url_rejects_plain_string(self):
        v = validator('list[email,url]')
        self.assertFalse(v(['a@b.com', 'not-either']))

    def test_list_int_str_float_three_way(self):
        v = validator('list[int,str,float]')
        self.assertTrue(v([1, 'a', 2.5]))
        self.assertFalse(v([1, 'a', None]))

    def test_tuple_int_str_union(self):
        v = validator('tuple[int,str]')
        self.assertTrue(v((1, 'a')))
        self.assertFalse(v((1, 2.5)))

    def test_set_int_str_union(self):
        v = validator('set[int,str]')
        self.assertTrue(v({1, 'a'}))


# ===========================================================================
# Container modifiers — applied to outer container, not items
# ===========================================================================

class TestContainerModifiers(unittest.TestCase):

    def test_min_non_empty(self):
        v = validator('list[str]|min:1')
        self.assertTrue(v(['a']))
        self.assertFalse(v([]))

    def test_max_length(self):
        v = validator('list[int]|max:3')
        self.assertTrue(v([1, 2, 3]))
        self.assertFalse(v([1, 2, 3, 4]))

    def test_between_length(self):
        v = validator('list[str]|between:2,4')
        self.assertTrue(v(['a', 'b']))
        self.assertTrue(v(['a', 'b', 'c', 'd']))
        self.assertFalse(v(['a']))
        self.assertFalse(v(['a', 'b', 'c', 'd', 'e']))

    def test_exact_length(self):
        v = validator('tuple[float]|length:3')
        self.assertTrue(v((1.0, 2.0, 3.0)))
        self.assertFalse(v((1.0, 2.0)))
        self.assertFalse(v((1.0, 2.0, 3.0, 4.0)))

    def test_nullable_passes_none(self):
        v = validator('list[str]|nullable')
        self.assertTrue(v(None))
        self.assertTrue(v(['a', 'b']))
        self.assertFalse(v(['a', 1]))

    def test_nullable_still_validates_items(self):
        v = validator('list[int]|nullable')
        self.assertTrue(v(None))
        self.assertFalse(v(['a', 'b']))   # non-None invalid items still fail

    def test_min_and_item_type_both_enforced(self):
        v = validator('list[str]|min:2')
        self.assertFalse(v(['a']))         # fails min
        self.assertFalse(v(['a', 1]))      # passes min, fails item type
        self.assertTrue(v(['a', 'b']))     # passes both

    def test_min_max_combined(self):
        v = validator('list[int]|min:1|max:5')
        self.assertTrue(v([1, 2, 3]))
        self.assertFalse(v([]))
        self.assertFalse(v([1, 2, 3, 4, 5, 6]))


# ===========================================================================
# Dict rule integration
# ===========================================================================

class TestDictRuleWithParameterizedTypes(unittest.TestCase):

    def test_all_fields_valid(self):
        v = validator({'tags': 'list[str]', 'scores': 'list[int]'})
        self.assertTrue(v({'tags': ['a', 'b'], 'scores': [1, 2, 3]}))

    def test_one_field_invalid_item_type(self):
        v = validator({'tags': 'list[str]', 'scores': 'list[int]'})
        self.assertFalse(v({'tags': ['a', 1], 'scores': [1, 2]}))   # tags bad

    def test_one_field_invalid_container(self):
        v = validator({'tags': 'list[str]'})
        self.assertFalse(v({'tags': 'not a list'}))

    def test_with_modifiers_in_dict_rule(self):
        v = validator({'tags': 'list[str]|max:5', 'coords': 'tuple[float]|length:3'})
        self.assertTrue(v({'tags': ['a'], 'coords': (1.0, 2.0, 3.0)}))
        self.assertFalse(v({'tags': ['a'], 'coords': (1.0, 2.0)}))   # wrong length

    def test_missing_key_fails_non_nullable(self):
        v = validator({'tags': 'list[str]'})
        self.assertFalse(v({}))   # missing → None → fails list[str]

    def test_missing_key_passes_nullable(self):
        v = validator({'tags': 'list[str]|nullable'})
        self.assertTrue(v({}))    # missing → None → passes nullable

    def test_union_in_dict_rule(self):
        v = validator({'values': 'list[int,str]'})
        self.assertTrue(v({'values': [1, 'a', 2]}))
        self.assertFalse(v({'values': [1, 2.5]}))


# ===========================================================================
# Tokenizer compatibility
# ===========================================================================

class TestParameterizedTokenizerCompatibility(unittest.TestCase):
    """_pipe_tokenize must correctly split parameterized type tokens."""

    def test_list_str_alone(self):
        from validatedata.validatedata import _pipe_tokenize
        self.assertEqual(_pipe_tokenize('list[str]'), ['list[str]'])

    def test_list_str_with_modifier(self):
        from validatedata.validatedata import _pipe_tokenize
        self.assertEqual(
            _pipe_tokenize('list[str]|min:1'),
            ['list[str]', 'min:1'],
        )

    def test_list_union_with_modifier(self):
        from validatedata.validatedata import _pipe_tokenize
        self.assertEqual(
            _pipe_tokenize('list[int,str]|max:10'),
            ['list[int,str]', 'max:10'],
        )

    def test_tuple_float_length(self):
        from validatedata.validatedata import _pipe_tokenize
        self.assertEqual(
            _pipe_tokenize('tuple[float]|length:3'),
            ['tuple[float]', 'length:3'],
        )

    def test_multiple_modifiers(self):
        from validatedata.validatedata import _pipe_tokenize
        self.assertEqual(
            _pipe_tokenize('list[str]|min:1|max:10|nullable'),
            ['list[str]', 'min:1', 'max:10', 'nullable'],
        )


# ===========================================================================
# Error cases
# ===========================================================================

class TestParameterizedErrorCases(unittest.TestCase):

    def test_unknown_item_type_raises_type_error(self):
        with self.assertRaises(TypeError):
            validator('list[notareal]')

    def test_unknown_second_item_type_raises_type_error(self):
        with self.assertRaises(TypeError):
            validator('list[str,notareal]')

    def test_dict_container_not_supported(self):
        """dict[str] is not a supported parameterized outer — must raise TypeError."""
        with self.assertRaises(TypeError):
            validator('dict[str]')

    def test_of_modifier_still_raises(self):
        """list|of:str remains unsupported in the fast path — must still raise ValueError."""
        with self.assertRaises(ValueError):
            validator('list|of:str')

    def test_parameterized_with_unknown_modifier_raises(self):
        with self.assertRaises(ValueError):
            validator('list[str]|unknown_modifier')


# ===========================================================================
# Cache behaviour
# ===========================================================================

class TestParameterizedTypeCache(unittest.TestCase):

    def setUp(self):
        _COMPILED_CACHE.clear()

    def test_same_rule_returns_same_object(self):
        v1 = validator('list[str]')
        v2 = validator('list[str]')
        self.assertIs(v1, v2)

    def test_different_parameterized_rules_are_different_objects(self):
        v1 = validator('list[str]')
        v2 = validator('list[int]')
        self.assertIsNot(v1, v2)

    def test_parameterized_rule_is_cached(self):
        _COMPILED_CACHE.clear()
        validator('list[str]')
        self.assertIn('list[str]', _COMPILED_CACHE)

    def test_parameterized_with_modifier_is_cached(self):
        _COMPILED_CACHE.clear()
        validator('list[str]|min:1')
        self.assertIn('list[str]|min:1', _COMPILED_CACHE)

    def test_union_rule_is_cached(self):
        _COMPILED_CACHE.clear()
        validator('list[int,str]')
        self.assertIn('list[int,str]', _COMPILED_CACHE)


# ===========================================================================
# Regression — existing plain list/tuple/set rules unaffected
# ===========================================================================

class TestNoRegressionOnPlainContainers(unittest.TestCase):
    """Parameterized type additions must not break existing non-parameterized rules."""

    def test_plain_list_still_works(self):
        v = validator('list')
        self.assertTrue(v([1, 'a', None]))   # any content passes
        self.assertFalse(v('not a list'))

    def test_plain_tuple_still_works(self):
        v = validator('tuple')
        self.assertTrue(v((1, 2)))

    def test_plain_set_still_works(self):
        v = validator('set')
        self.assertTrue(v({1, 2}))

    def test_plain_list_with_min_still_works(self):
        v = validator('list|min:2')
        self.assertTrue(v([1, 2]))
        self.assertFalse(v([1]))

    def test_plain_list_unique_still_works(self):
        v = validator('list|unique')
        self.assertTrue(v([1, 2, 3]))
        self.assertFalse(v([1, 2, 2]))

    def test_of_still_raises(self):
        """list|of:str must still raise ValueError — not silently redirected."""
        with self.assertRaises(ValueError):
            validator('list|of:str')


if __name__ == '__main__':
    unittest.main()
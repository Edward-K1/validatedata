"""Tests for validatedata/compiled.py — fast-path validator."""
from __future__ import annotations

import json
import unittest
from datetime import datetime

from validatedata import validator, cache
from validatedata.compiled import (
    _COMPILED_CACHE,
    _COMPILED_CACHE_MAX,
    _compile_pipe_rule,
    _make_callable,
    _build_type_check_callable,
)


# ===========================================================================
# Pipe rules — type checks
# ===========================================================================

class TestPipeTypeChecks(unittest.TestCase):

    # --- native types ---

    def test_str_accepts_string(self):
        v = validator('str')
        self.assertTrue(v('hello'))

    def test_str_rejects_int(self):
        v = validator('str')
        self.assertFalse(v(42))

    def test_int_accepts_int(self):
        v = validator('int')
        self.assertTrue(v(42))

    def test_int_rejects_string(self):
        v = validator('int')
        self.assertFalse(v('42'))

    def test_float_accepts_float(self):
        v = validator('float')
        self.assertTrue(v(3.14))

    def test_float_rejects_string(self):
        v = validator('float')
        self.assertFalse(v('3.14'))

    def test_bool_accepts_bool(self):
        v = validator('bool')
        self.assertTrue(v(True))
        self.assertTrue(v(False))

    def test_bool_rejects_int(self):
        v = validator('bool')
        # int is NOT bool in the _TYPE_CHECK table (isinstance(1, bool) is False)
        self.assertFalse(v(1))

    def test_dict_accepts_dict(self):
        v = validator('dict')
        self.assertTrue(v({'a': 1}))

    def test_dict_rejects_list(self):
        v = validator('dict')
        self.assertFalse(v([1, 2]))

    def test_list_accepts_list(self):
        v = validator('list')
        self.assertTrue(v([1, 2, 3]))

    def test_list_rejects_tuple(self):
        v = validator('list')
        self.assertFalse(v((1, 2)))

    def test_set_accepts_set(self):
        v = validator('set')
        self.assertTrue(v({1, 2, 3}))

    def test_tuple_accepts_tuple(self):
        v = validator('tuple')
        self.assertTrue(v((1, 2)))

    # --- non-native types ---

    def test_email_accepts_valid(self):
        v = validator('email')
        self.assertTrue(v('user@example.com'))

    def test_email_rejects_invalid(self):
        v = validator('email')
        self.assertFalse(v('not-an-email'))

    def test_url_accepts_valid(self):
        v = validator('url')
        self.assertTrue(v('https://example.com'))

    def test_url_rejects_invalid(self):
        v = validator('url')
        self.assertFalse(v('not a url'))

    def test_ip_accepts_valid(self):
        v = validator('ip')
        self.assertTrue(v('192.168.1.1'))
        self.assertTrue(v('::1'))

    def test_ip_rejects_invalid(self):
        v = validator('ip')
        self.assertFalse(v('999.999.999.999'))

    def test_uuid_accepts_valid(self):
        v = validator('uuid')
        self.assertTrue(v('123e4567-e89b-12d3-a456-426614174000'))

    def test_uuid_rejects_invalid(self):
        v = validator('uuid')
        self.assertFalse(v('not-a-uuid'))

    def test_slug_accepts_valid(self):
        v = validator('slug')
        self.assertTrue(v('my-slug-here'))

    def test_slug_rejects_invalid(self):
        v = validator('slug')
        self.assertFalse(v('My Slug!'))

    def test_semver_accepts_valid(self):
        v = validator('semver')
        self.assertTrue(v('1.2.3'))
        self.assertTrue(v('1.0.0-alpha+001'))

    def test_semver_rejects_invalid(self):
        v = validator('semver')
        self.assertFalse(v('1.2'))

    def test_date_accepts_string(self):
        # date defaults to non-strict (accepts date strings)
        v = validator('date')
        self.assertTrue(v('2024-01-15'))

    def test_date_accepts_datetime_object(self):
        v = validator('date')
        self.assertTrue(v(datetime(2024, 1, 15)))

    def test_date_rejects_garbage(self):
        v = validator('date')
        self.assertFalse(v('not-a-date'))

    def test_even_accepts_even_int(self):
        v = validator('even')
        self.assertTrue(v(4))
        self.assertTrue(v(0))

    def test_even_rejects_odd_int(self):
        v = validator('even')
        self.assertFalse(v(3))

    def test_even_rejects_bool(self):
        # bool is excluded from even/odd checks
        v = validator('even')
        self.assertFalse(v(True))

    def test_odd_accepts_odd_int(self):
        v = validator('odd')
        self.assertTrue(v(3))

    def test_odd_rejects_even_int(self):
        v = validator('odd')
        self.assertFalse(v(4))

    def test_prime_accepts_prime(self):
        v = validator('prime')
        self.assertTrue(v(7))
        self.assertTrue(v(2))

    def test_prime_rejects_non_prime(self):
        v = validator('prime')
        self.assertFalse(v(4))
        self.assertFalse(v(1))

    def test_regex_accepts_string(self):
        v = validator('regex')
        self.assertTrue(v(r'\d+'))

    def test_regex_rejects_non_string(self):
        v = validator('regex')
        self.assertFalse(v(123))

    def test_phone_e164_accepts_valid(self):
        v = validator('phone')
        self.assertTrue(v('+12025551234'))

    def test_phone_e164_rejects_invalid(self):
        v = validator('phone')
        self.assertFalse(v('5551234'))


# ===========================================================================
# Pipe rules — strict mode
# ===========================================================================

class TestPipeStrictMode(unittest.TestCase):

    def test_date_strict_is_noop(self):
        # The engine date check has no strict branch -- it always parses strings.
        # date|strict therefore behaves identically to plain date.
        v = validator('date')
        v_strict = validator('date|strict')
        self.assertTrue(v('2024-01-15'))
        self.assertTrue(v_strict('2024-01-15'))
        self.assertTrue(v_strict(datetime(2024, 1, 15)))

    def test_non_strict_native_accepts_coerced(self):
        # Test _build_type_check_callable directly for non-strict native path
        check = _build_type_check_callable('int', strict=False, fmt=None, region=None)
        self.assertTrue(check('42'))     # coerced '42' -> int
        self.assertFalse(check('hello')) # can't coerce

    def test_non_strict_float_accepts_coerced(self):
        check = _build_type_check_callable('float', strict=False, fmt=None, region=None)
        self.assertTrue(check('3.14'))
        self.assertFalse(check('abc'))

    def test_non_strict_str_accepts_coerced(self):
        check = _build_type_check_callable('str', strict=False, fmt=None, region=None)
        self.assertTrue(check('"hello"'))    # literal_eval of a quoted string
        self.assertFalse(check(42))          # 42 literal_evals to int, not str


# ===========================================================================
# Pipe rules — min, max, between
# ===========================================================================

class TestPipeRanges(unittest.TestCase):

    def test_min_string_length(self):
        v = validator('str|min:3')
        self.assertTrue(v('abc'))
        self.assertFalse(v('ab'))

    def test_max_string_length(self):
        v = validator('str|max:5')
        self.assertTrue(v('hello'))
        self.assertFalse(v('toolong'))

    def test_min_max_string(self):
        v = validator('str|min:2|max:5')
        self.assertTrue(v('hi'))
        self.assertTrue(v('hello'))
        self.assertFalse(v('h'))
        self.assertFalse(v('toolong'))

    def test_min_numeric(self):
        v = validator('int|min:10')
        self.assertTrue(v(10))
        self.assertTrue(v(99))
        self.assertFalse(v(9))

    def test_max_numeric(self):
        v = validator('int|max:100')
        self.assertTrue(v(100))
        self.assertFalse(v(101))

    def test_between_string(self):
        v = validator('str|between:2,5')
        self.assertTrue(v('ab'))
        self.assertTrue(v('hello'))
        self.assertFalse(v('h'))
        self.assertFalse(v('toolong'))

    def test_between_numeric(self):
        v = validator('int|between:1,10')
        self.assertTrue(v(1))
        self.assertTrue(v(10))
        self.assertFalse(v(0))
        self.assertFalse(v(11))

    def test_between_list_length(self):
        v = validator('list|between:1,3')
        self.assertTrue(v([1]))
        self.assertTrue(v([1, 2, 3]))
        self.assertFalse(v([]))
        self.assertFalse(v([1, 2, 3, 4]))

    def test_min_max_combined_uses_between_internally(self):
        # min+max with same semantics as between
        v = validator('int|min:5|max:10')
        self.assertTrue(v(7))
        self.assertFalse(v(4))
        self.assertFalse(v(11))

    def test_between_and_min_raises(self):
        with self.assertRaises(ValueError):
            validator('int|between:1,10|min:2')

    def test_between_and_max_raises(self):
        with self.assertRaises(ValueError):
            validator('int|between:1,10|max:8')

    def test_date_between_raises(self):
        with self.assertRaises(ValueError):
            validator('date|between:2020-01-01,2024-12-31')

    def test_date_min_raises(self):
        with self.assertRaises(ValueError):
            validator('date|min:2020-01-01')


# ===========================================================================
# Pipe rules — scalar validators
# ===========================================================================

class TestPipeValidators(unittest.TestCase):

    def test_length_exact(self):
        v = validator('str|length:5')
        self.assertTrue(v('hello'))
        self.assertFalse(v('hi'))

    def test_contains_substring(self):
        v = validator('str|contains:foo')
        self.assertTrue(v('foobar'))
        self.assertFalse(v('barbaz'))

    def test_contains_multiple(self):
        v = validator('str|contains:foo,bar')
        self.assertTrue(v('foobar'))
        self.assertFalse(v('foobaz'))

    def test_starts_with(self):
        v = validator('str|starts_with:hello')
        self.assertTrue(v('hello world'))
        self.assertFalse(v('world hello'))

    def test_ends_with(self):
        v = validator('str|ends_with:.txt')
        self.assertTrue(v('file.txt'))
        self.assertFalse(v('file.csv'))

    def test_regex(self):
        v = validator(r'str|re:^\d{3}-\d{4}$')
        self.assertTrue(v('123-4567'))
        self.assertFalse(v('abc-defg'))

    def test_unique(self):
        v = validator('list|unique')
        self.assertTrue(v([1, 2, 3]))
        self.assertFalse(v([1, 2, 2]))

    def test_in_options(self):
        v = validator('str|in:foo,bar,baz')
        self.assertTrue(v('foo'))
        self.assertTrue(v('bar'))
        self.assertFalse(v('qux'))

    def test_not_in(self):
        v = validator('str|not_in:foo,bar')
        self.assertTrue(v('baz'))
        self.assertFalse(v('foo'))


# ===========================================================================
# Pipe rules — nullable
# ===========================================================================

class TestPipeNullable(unittest.TestCase):

    def test_none_passes_nullable_rule(self):
        v = validator('str|nullable')
        self.assertTrue(v(None))

    def test_non_none_still_validated_nullable(self):
        v = validator('str|min:3|nullable')
        self.assertTrue(v('hello'))
        self.assertFalse(v('hi'))

    def test_none_fails_non_nullable_rule(self):
        v = validator('str')
        self.assertFalse(v(None))


# ===========================================================================
# Pipe rules — color format
# ===========================================================================

class TestPipeColorFormat(unittest.TestCase):

    def test_color_any_accepts_hex(self):
        v = validator('color')
        self.assertTrue(v('#ff0000'))

    def test_color_any_accepts_named(self):
        v = validator('color')
        self.assertTrue(v('red'))

    def test_color_hex_format(self):
        v = validator('color|format:hex')
        self.assertTrue(v('#abc'))
        self.assertTrue(v('#aabbcc'))
        self.assertFalse(v('red'))
        self.assertFalse(v('rgb(0,0,0)'))

    def test_color_rgb_format(self):
        v = validator('color|format:rgb')
        self.assertTrue(v('rgb(255, 0, 0)'))
        self.assertFalse(v('#ff0000'))

    def test_color_hsl_format(self):
        v = validator('color|format:hsl')
        self.assertTrue(v('hsl(0, 100%, 50%)'))
        self.assertFalse(v('red'))

    def test_color_named_format(self):
        v = validator('color|format:named')
        self.assertTrue(v('blue'))
        self.assertTrue(v('aliceblue'))
        self.assertFalse(v('#0000ff'))


# ===========================================================================
# Pipe rules — phone format
# ===========================================================================

class TestPipePhoneFormat(unittest.TestCase):

    def test_phone_default_e164(self):
        v = validator('phone')
        self.assertTrue(v('+12025551234'))
        self.assertFalse(v('2025551234'))

    def test_phone_explicit_e164_format(self):
        v = validator('phone|format:e164')
        self.assertTrue(v('+442071234567'))
        self.assertFalse(v('not-a-phone'))


# ===========================================================================
# Pipe rules — transforms
# ===========================================================================

class TestPipeTransforms(unittest.TestCase):

    def test_lower_transform(self):
        v = validator('str|lower|in:foo,bar')
        self.assertTrue(v('FOO'))
        self.assertTrue(v('Bar'))
        self.assertFalse(v('baz'))

    def test_strip_transform(self):
        v = validator('str|strip|min:3')
        self.assertTrue(v('  hello  '))
        self.assertFalse(v('   x   '))

    def test_chained_transforms(self):
        v = validator('str|strip|lower|in:foo,bar')
        self.assertTrue(v('  FOO  '))
        self.assertTrue(v(' BAR '))
        self.assertFalse(v('  BAZ  '))

    def test_transform_before_validator_order_enforced(self):
        with self.assertRaises(ValueError):
            validator('str|min:3|lower')


# ===========================================================================
# Pipe rules — msg token
# ===========================================================================

class TestPipeMsgToken(unittest.TestCase):

    def test_msg_token_does_not_affect_bool_result_pass(self):
        v = validator('str|min:2|msg:too short')
        self.assertTrue(v('hello'))

    def test_msg_token_does_not_affect_bool_result_fail(self):
        v = validator('str|min:2|msg:too short')
        self.assertFalse(v('x'))


# ===========================================================================
# Pipe rules — error cases
# ===========================================================================

class TestPipeErrors(unittest.TestCase):

    def test_unknown_type_raises_type_error(self):
        with self.assertRaises(TypeError):
            validator('notareal_type')

    def test_unknown_modifier_raises_value_error(self):
        with self.assertRaises(ValueError):
            validator('str|unknown_modifier:x')

    def test_of_raises_value_error(self):
        with self.assertRaises(ValueError):
            validator('list|of:str')

    def test_non_str_non_dict_raises_type_error(self):
        with self.assertRaises(TypeError):
            validator(42)

    def test_none_raises_type_error(self):
        with self.assertRaises(TypeError):
            validator(None)

    def test_list_raises_type_error(self):
        with self.assertRaises(TypeError):
            validator(['str|min:2'])


# ===========================================================================
# Dict rules
# ===========================================================================

class TestDictRules(unittest.TestCase):

    def test_all_fields_valid_returns_true(self):
        v = validator({'name': 'str|min:2', 'age': 'int'})
        self.assertTrue(v({'name': 'Alice', 'age': 30}))

    def test_one_field_invalid_returns_false(self):
        v = validator({'name': 'str|min:2', 'age': 'int'})
        self.assertFalse(v({'name': 'A', 'age': 30}))

    def test_short_circuits_on_first_failure(self):
        # Both fields invalid; still returns False without running all checks
        v = validator({'name': 'str|min:5', 'age': 'int|min:0'})
        self.assertFalse(v({'name': 'X', 'age': -1}))

    def test_missing_key_fails_non_nullable_rule(self):
        v = validator({'name': 'str', 'age': 'int'})
        self.assertFalse(v({'name': 'Alice'}))   # age missing → None → fails int

    def test_missing_key_passes_nullable_rule(self):
        v = validator({'name': 'str', 'age': 'int|nullable'})
        self.assertTrue(v({'name': 'Alice'}))    # age missing → None → passes nullable

    def test_explicit_none_fails_non_nullable(self):
        v = validator({'name': 'str'})
        self.assertFalse(v({'name': None}))

    def test_explicit_none_passes_nullable(self):
        v = validator({'name': 'str|nullable'})
        self.assertTrue(v({'name': None}))

    def test_non_dict_data_returns_false(self):
        v = validator({'name': 'str'})
        self.assertFalse(v('not a dict'))
        self.assertFalse(v(None))

    def test_nested_dict_value_compiles(self):
        # Nested dict rules are now supported in the fast path.
        v = validator({'user': {'name': 'str'}})
        self.assertTrue(v({'user': {'name': 'Alice'}}))

    def test_nested_list_value_raises(self):
        with self.assertRaises(ValueError):
            validator({'tags': ['str']})


# ===========================================================================
# Cache behaviour
# ===========================================================================

class TestCache(unittest.TestCase):

    def setUp(self):
        # Clear only the compiled cache between tests
        _COMPILED_CACHE.clear()

    def test_same_rule_string_returns_same_object(self):
        v1 = validator('str|min:3')
        v2 = validator('str|min:3')
        self.assertIs(v1, v2)

    def test_same_dict_rule_returns_same_object(self):
        v1 = validator({'name': 'str', 'age': 'int'})
        v2 = validator({'name': 'str', 'age': 'int'})
        self.assertIs(v1, v2)

    def test_different_rules_are_different_objects(self):
        v1 = validator('str|min:2')
        v2 = validator('str|min:5')
        self.assertIsNot(v1, v2)

    def test_cache_does_not_exceed_max_size(self):
        _COMPILED_CACHE.clear()
        original_max = _COMPILED_CACHE_MAX
        # Fill past the default max via unique rules
        for i in range(original_max + 10):
            validator(f'str|min:{i}')
        self.assertLessEqual(len(_COMPILED_CACHE), original_max)

    def test_lru_eviction_removes_oldest_entry(self):
        import validatedata.compiled as cr
        old_max = cr._COMPILED_CACHE_MAX
        try:
            cr._COMPILED_CACHE_MAX = 3
            _COMPILED_CACHE.clear()
            validator('str|min:1')
            validator('str|min:2')
            validator('str|min:3')
            # Cache is now at capacity; adding a 4th evicts 'str|min:1'
            validator('str|min:4')
            self.assertNotIn('str|min:1', _COMPILED_CACHE)
            self.assertIn('str|min:4', _COMPILED_CACHE)
        finally:
            cr._COMPILED_CACHE_MAX = old_max
            _COMPILED_CACHE.clear()

    def test_cache_clear_empties_compiled_cache(self):
        validator('str|min:3')
        cache.clear()
        self.assertEqual(len(_COMPILED_CACHE), 0)

    def test_cache_clear_also_clears_engine_caches(self):
        from validatedata.engine import _FN_CACHE, _ARGS_CACHE
        from validatedata import validate_data
        validate_data(['hello'], [{'type': 'str'}])  # populate engine caches
        cache.clear()
        self.assertEqual(len(_FN_CACHE), 0)
        self.assertEqual(len(_ARGS_CACHE), 0)

    def test_cache_size_includes_compiled_key(self):
        _COMPILED_CACHE.clear()
        validator('str|min:3')
        s = cache.size()
        self.assertIn('compiled', s)
        self.assertEqual(s['compiled'], 1)

    def test_cache_size_includes_all_existing_keys(self):
        s = cache.size()
        for key in ('fn', 'args', 'expression', 'compiled'):
            self.assertIn(key, s)

    def test_cache_repr_includes_compiled(self):
        r = repr(cache)
        self.assertIn('compiled=', r)




# ===========================================================================
# Ordering enforcement — seen_validator parity with engine
# ===========================================================================

class TestTransformOrderingEnforcement(unittest.TestCase):
    """Transforms must precede ALL validator/modifier tokens, including nullable
    and msg, matching _expand_pipe_rule behaviour exactly."""

    def test_nullable_before_transform_raises(self):
        # nullable sets seen_validator; transform after it must raise
        with self.assertRaises(ValueError):
            validator('str|nullable|lower|min:3')

    def test_msg_before_transform_raises(self):
        # msg sets seen_validator; transform after it must raise
        with self.assertRaises(ValueError):
            validator('str|msg:too short|lower')

    def test_format_before_transform_raises(self):
        # format falls through to seen_validator=True in main loop
        with self.assertRaises(ValueError):
            validator('color|format:hex|upper')

    def test_region_before_transform_raises(self):
        # region falls through to seen_validator=True in main loop
        with self.assertRaises(ValueError):
            validator('phone|region:US|lower')

    def test_transform_before_nullable_ok(self):
        # correct order: transform, then nullable, then validators
        v = validator('str|lower|nullable|min:2')
        self.assertTrue(v('HELLO'))
        self.assertTrue(v(None))
        self.assertFalse(v('X'))

    def test_transform_before_format_ok(self):
        v = validator('color|upper|format:named')
        # upper transforms 'red' to 'RED'; _is_valid_color('RED', 'named') checks lower
        # This tests ordering is accepted; actual result depends on named color lookup
        # (named colors are lowercase), so 'RED'.lower() is checked inside _is_valid_color
        self.assertIsInstance(v('red'), bool)


# ===========================================================================
# Non-native string types — min/max/between use len(), not value comparison
# ===========================================================================

class TestNonNativeStringTypeRanges(unittest.TestCase):
    """email, url, slug, semver, uuid, ip, phone, regex, color are strings at
    runtime. Their min/max/between checks must use len(), matching the engine's
    validate_range str branch."""

    def test_email_min_len(self):
        v = validator('email|min:5')
        self.assertTrue(v('user@example.com'))   # len=16 >= 5
        self.assertFalse(v('a@b'))               # len=3 < 5, but also fails email check

    def test_email_max_len(self):
        # email type check runs first, so only valid emails reach max check
        v = validator('email|max:20')
        self.assertTrue(v('user@example.com'))    # len=16 <= 20
        self.assertFalse(v('verylongemail@verylongdomain.com'))  # len > 20

    def test_url_min_len(self):
        # Key test: no TypeError raised (was broken before fix)
        v = validator('url|min:10')
        self.assertIsInstance(v('https://example.com'), bool)
        # Long URL passes min:10
        self.assertTrue(v('https://example.com'))
        # min:25 rejects short URL
        v2 = validator('url|min:25')
        self.assertFalse(v2('https://x.co'))        # len=12 < 25

    def test_slug_min_len(self):
        v = validator('slug|min:3')
        self.assertTrue(v('my-slug'))
        self.assertFalse(v('ab'))

    def test_slug_max_len(self):
        v = validator('slug|max:5')
        self.assertTrue(v('hello'))
        self.assertFalse(v('abc-def-ghi'))

    def test_ip_min_len(self):
        v = validator('ip|min:5')
        self.assertTrue(v('192.168.1.1'))    # len=11

    def test_phone_min_len(self):
        v = validator('phone|min:5')
        self.assertTrue(v('+12025551234'))

    def test_color_min_len(self):
        v = validator('color|min:3')
        self.assertTrue(v('#ff0000'))        # len=7
        self.assertTrue(v('red'))            # len=3

    def test_semver_between_len(self):
        v = validator('semver|between:3,10')
        self.assertTrue(v('1.2.3'))          # len=5, in [3,10]
        self.assertFalse(v('1.2.3-alpha.1')) # len=13 > 10

    def test_min_max_no_type_error_for_string_types(self):
        """The previous bug caused TypeError: '>=' not supported between str and int.
        All of these must complete without raising."""
        string_type_rules = [
            'email|min:5', 'url|min:5', 'slug|min:2',
            'ip|min:3', 'phone|min:5', 'regex|min:1', 'color|min:3',
        ]
        test_vals = {
            'email': 'user@example.com',
            'url': 'https://example.com',
            'slug': 'my-slug',
            'ip': '10.0.0.1',
            'phone': '+12025551234',
            'regex': r'\d+',
            'color': '#ffffff',
        }
        for rule in string_type_rules:
            type_name = rule.split('|')[0]
            val = test_vals[type_name]
            try:
                result = validator(rule)(val)
                self.assertIsInstance(result, bool, f'Expected bool for {rule!r}')
            except TypeError as e:
                self.fail(f'{rule!r} raised TypeError: {e}')


# ===========================================================================
# even/odd/prime/bool min/max use value comparison
# ===========================================================================

class TestNumericTypeRanges(unittest.TestCase):

    def test_even_min_val(self):
        v = validator('even|min:4')
        self.assertTrue(v(4))
        self.assertTrue(v(6))
        self.assertFalse(v(2))

    def test_odd_max_val(self):
        v = validator('odd|max:9')
        self.assertTrue(v(7))
        self.assertFalse(v(11))

    def test_prime_between_val(self):
        v = validator('prime|between:5,20')
        self.assertTrue(v(7))
        self.assertTrue(v(19))
        self.assertFalse(v(3))     # prime but < 5
        self.assertFalse(v(23))    # prime but > 20

    def test_float_min_val(self):
        v = validator('float|min:1.5')
        self.assertTrue(v(2.0))
        self.assertFalse(v(1.0))

    def test_bool_is_val_type(self):
        # bool uses value comparison (subclass of int)
        v = validator('bool|min:0')
        self.assertTrue(v(True))   # True == 1 >= 0
        self.assertTrue(v(False))  # False == 0 >= 0

if __name__ == '__main__':
    unittest.main()


# ===========================================================================
# Edge cases — dict rule behaviour
# ===========================================================================

class TestDictRuleEdgeCases(unittest.TestCase):

    def test_extra_keys_in_data_are_ignored(self):
        """Only compiled fields are checked; surplus keys pass through silently."""
        v = validator({'name': 'str'})
        self.assertTrue(v({'name': 'Alice', 'age': 30, 'extra': None}))

    def test_empty_dict_rule_always_passes(self):
        v = validator({})
        self.assertTrue(v({}))
        self.assertTrue(v({'anything': 'goes'}))

    def test_dict_cache_key_is_order_independent(self):
        """json.dumps with sort_keys=True means insertion order doesn't matter."""
        v1 = validator({'a': 'str', 'b': 'int'})
        v2 = validator({'b': 'int', 'a': 'str'})
        self.assertIs(v1, v2)


# ===========================================================================
# Edge cases — token parsing
# ===========================================================================

class TestTokenParsingEdgeCases(unittest.TestCase):

    def test_in_values_trimmed(self):
        """Spaces around CSV values in 'in:' are stripped."""
        v = validator('str|in:foo, bar, baz')
        self.assertTrue(v('foo'))
        self.assertTrue(v('bar'))
        self.assertFalse(v(' bar'))   # leading space not in options

    def test_not_in_values_trimmed(self):
        v = validator('str|not_in:foo, bar')
        self.assertTrue(v('baz'))
        self.assertFalse(v('foo'))

    def test_contains_multi_value(self):
        """Comma in contains: builds a tuple — all substrings required."""
        v = validator('str|contains:foo,bar')
        self.assertTrue(v('foobar'))
        self.assertFalse(v('foobaz'))  # 'bar' missing

    def test_between_with_float_bounds(self):
        v = validator('float|between:0.5,1.5')
        self.assertTrue(v(1.0))
        self.assertFalse(v(2.0))

    def test_strip_before_max(self):
        v = validator('str|strip|max:5')
        self.assertTrue(v('  hi  '))   # 'hi' after strip, len=2 <= 5

    def test_nullable_with_transform(self):
        v = validator('str|lower|nullable')
        self.assertTrue(v('FOO'))
        self.assertTrue(v(None))

    def test_re_pattern(self):
        v = validator(r'str|re:^\d{3}$')
        self.assertTrue(v('123'))
        self.assertFalse(v('12'))
        self.assertFalse(v('1234'))


# ===========================================================================
# Edge cases — specific type behaviours
# ===========================================================================

class TestTypeEdgeCases(unittest.TestCase):

    def test_uuid_case_insensitive(self):
        v = validator('uuid')
        self.assertTrue(v('123e4567-e89b-12d3-a456-426614174000'))
        self.assertTrue(v('123E4567-E89B-12D3-A456-426614174000'))

    def test_prime_boundary_values(self):
        v = validator('prime')
        self.assertTrue(v(2))    # smallest prime
        self.assertFalse(v(1))   # 1 is not prime
        self.assertFalse(v(0))   # 0 is not prime
        self.assertFalse(v(-7))  # negative not prime

    def test_date_accepts_multiple_formats(self):
        v = validator('date')
        self.assertTrue(v('2024-01-15'))
        self.assertTrue(v('January 15 2024'))
        self.assertTrue(v('15/01/2024'))

    def test_date_rejects_non_parseable(self):
        v = validator('date')
        self.assertFalse(v('not-a-date-xyz-999'))

    def test_bool_rejects_int_one(self):
        """isinstance(1, bool) is False — int is not bool."""
        v = validator('bool')
        self.assertFalse(v(1))
        self.assertFalse(v(0))

    def test_int_accepts_bool_subclass(self):
        """isinstance(True, int) is True in Python — bool is a subclass of int."""
        v = validator('int')
        # This matches engine behaviour. Document rather than change it.
        self.assertTrue(v(True))

    def test_slug_rejects_consecutive_hyphens(self):
        v = validator('slug')
        self.assertFalse(v('a--b'))

    def test_slug_rejects_leading_hyphen(self):
        v = validator('slug')
        self.assertFalse(v('-abc'))

    def test_semver_with_prerelease_and_build(self):
        v = validator('semver')
        self.assertTrue(v('1.0.0-alpha.1'))
        self.assertTrue(v('1.0.0+20240101'))
        self.assertTrue(v('1.0.0-beta+exp.sha.5114f85'))


# ===========================================================================
# Performance — fast path is materially faster than engine
# ===========================================================================

class TestPerformance(unittest.TestCase):
    """Lightweight sanity-check: fast path must be at least 5x faster than engine
    on a simple rule. This guards against accidental regression to engine-level
    overhead without requiring a full benchmark suite."""

    def test_fast_path_faster_than_engine(self):
        import timeit
        from validatedata import validate_data

        rule = 'str|min:2|max:20'
        val = 'hello'
        n = 5000

        fast_fn = validator(rule)
        # warm-up
        for _ in range(100):
            fast_fn(val)
            validate_data([val], [rule])

        fast_t = timeit.timeit(lambda: fast_fn(val), number=n)
        engine_t = timeit.timeit(lambda: validate_data([val], [rule]), number=n)

        ratio = engine_t / fast_t
        self.assertGreater(
            ratio, 5.0,
            f'Fast path should be >5x faster than engine, got {ratio:.1f}x'
        )
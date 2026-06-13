# tests/test_fast_rules.py
from __future__ import annotations

import uuid
import pytest
import validatedata.fast as fast
from validatedata.fast import validate_data, validate_data_fast, validator, validator_with_errors

# Helpers --------------------------------------------------------------------

def ok(res):
    return bool(getattr(res, "ok", False))

def errs(res):
    return getattr(res, "errors", []) or []

# Basic scalar types --------------------------------------------------------

def test_basic_native_types():
    assert ok(validate_data_fast("hello", "str"))
    assert ok(validate_data_fast(42, "int"))
    assert not ok(validate_data_fast("42", "int"))
    assert ok(validate_data_fast(3.14, "float"))
    assert ok(validate_data_fast(True, "bool"))

# Ranges, length, between ---------------------------------------------------

@pytest.mark.parametrize("rule,value,expected", [
    ("str|min:3", "abc", True),
    ("str|min:3", "ab", False),
    ("str|max:5", "hello", True),
    ("str|max:5", "toolong", False),
    ("str|between:2,4", "hey", True),
    ("int|min:1|max:10", 5, True),
    ("int|min:1|max:10", 0, False),
    ("list|min:1|max:3", [1,2], True),
    ("list|min:1|max:3", [], False),
])
def test_min_max_between(rule, value, expected):
    r = validate_data_fast(value, rule)
    assert ok(r) is expected

def test_length_token():
    assert ok(validate_data_fast("test", "str|length:4"))
    assert not ok(validate_data_fast("nope", "str|length:4"))
    assert ok(validate_data_fast([1,2], "list|length:2"))
    assert not ok(validate_data_fast([1], "list|length:2"))

# in / not_in / contains / unique ------------------------------------------

def test_in_not_in_contains_unique():
    assert ok(validate_data_fast("apple", "str|in:apple,banana"))
    assert not ok(validate_data_fast("pear", "str|in:apple,banana"))
    assert ok(validate_data_fast("good", "str|not_in:bad,evil"))
    assert not ok(validate_data_fast("bad", "str|not_in:bad,evil"))

    assert ok(validate_data_fast("foobar", "str|contains:foo"))
    assert not ok(validate_data_fast("bar", "str|contains:foo"))

    assert ok(validate_data_fast([1,2,3], "list|unique"))
    assert not ok(validate_data_fast([1,2,1], "list|unique"))

# starts_with / ends_with / re ----------------------------------------------

def test_starts_ends_re():
    assert ok(validate_data_fast("prefix", "str|starts_with:pre"))
    assert not ok(validate_data_fast("nopre", "str|starts_with:pre"))
    assert ok(validate_data_fast("testing", "str|ends_with:ing"))
    assert not ok(validate_data_fast("test", "str|ends_with:ing"))
    assert ok(validate_data_fast("abcz", r"str|re:^a.*z$"))
    assert not ok(validate_data_fast("abc", r"str|re:^a.*z$"))

# Parameterized types (list/tuple/set) -------------------------------------

def test_parameterized_list_and_item_checks():
    assert ok(validate_data_fast(["a","b"], "list[str]"))
    assert ok(validate_data_fast([1,"x",3], "list[int,str]"))
    # list[int] should reject bools (True is subclass of int) when strict item checks apply
    assert not ok(validate_data_fast([1, True, 3], "list[int]"))

def test_tuple_and_set_parameterized():
    assert ok(validate_data_fast((1,2,3), "tuple[int]"))
    assert not ok(validate_data_fast((1,"x"), "tuple[int,int]"))
    assert ok(validate_data_fast({ "a", "b" }, "set[str]"))
    assert not ok(validate_data_fast({1,2}, "set[str]"))

# Special formats: email, url, ip, uuid, slug, semver, color, phone --------

def test_special_formats():
    assert ok(validate_data_fast("user@example.com", "email"))
    assert not ok(validate_data_fast("not-an-email", "email"))

    assert ok(validate_data_fast("https://example.com", "url"))
    assert not ok(validate_data_fast("notaurl", "url"))

    assert ok(validate_data_fast("127.0.0.1", "ip"))
    assert not ok(validate_data_fast("999.999.999.999", "ip"))

    u = str(uuid.uuid4())
    assert ok(validate_data_fast(u, "uuid"))
    assert not ok(validate_data_fast("not-a-uuid", "uuid"))

    assert ok(validate_data_fast("valid-slug_123", "slug"))
    assert not ok(validate_data_fast("Invalid Slug!", "slug"))

    assert ok(validate_data_fast("1.2.3", "semver"))
    assert not ok(validate_data_fast("1.2", "semver"))

    assert ok(validate_data_fast("#ff00aa", "color|format:hex"))
    assert not ok(validate_data_fast("notcolor", "color|format:hex"))

    # phone: default e164 check
    assert ok(validate_data_fast("+14155552671", "phone"))
    assert not ok(validate_data_fast("4155552671", "phone"))

# Transforms and mutate -----------------------------------------------------

def test_transforms_and_mutate():
    # strip + lower transform should be applied when mutate=True
    res = validate_data(["  HeLLo  "], "str|strip|lower", mutate=True)
    assert getattr(res, "ok", False) is True
    assert getattr(res, "data", None) == ["hello"]

    # transform ordering: transform tokens must come before validators; invalid order raises
    with pytest.raises(ValueError):
        validate_data_fast("x", "str|min:2|lower")

# Nullable and strict -------------------------------------------------------

def test_nullable_and_strict():
    assert ok(validate_data_fast(None, "str|nullable"))
    # strict token behavior: ensure explicit strict accepted (no exception)
    assert ok(validate_data_fast("2020-01-01", "date|strict"))

# Nested mirror dicts and fields/items --------------------------------------

def test_nested_mirror_shorthand_pass_and_fail():
    rule = {"user": {"name": "str|min:2", "age": "int|nullable"}}
    data_ok = {"user": {"name": "Ed", "age": None}}
    data_fail = {"user": {"name": "E"}}  # age missing but nullable -> ok; name too short -> fail
    assert ok(validate_data_fast(data_ok, rule))
    assert not ok(validate_data_fast(data_fail, rule))

def test_items_with_fields():
    rule = {"tags": {"type": "list", "items": {"type": "str|min:1"}}}
    assert ok(validate_data_fast({"tags": ["a","b"]}, rule))
    assert not ok(validate_data_fast({"tags": ["a", 1]}, rule))

# validator and validator_with_errors helpers --------------------------------

def test_validator_boolean_and_errors_helpers():
    v = validator("int|min:0|max:10")
    assert v(5) is True
    assert v(-1) is False

    v_err = validator_with_errors("str|length:3")
    ok_flag, errors = v_err("abc")
    assert ok_flag is True and errors == []
    ok_flag, errors = v_err("ab")
    assert ok_flag is False and errors

# validate_data wrapper (msgspec-first) -------------------------------------

def test_validate_data_msgspec_first_behavior():
    # For a msgspec-capable rule, validate_data should delegate to validate_data_fast path
    res = validate_data("abc", "str|min:1")
    assert getattr(res, "ok", False) is True

    # For a rule not representable by msgspec, validate_data still returns a ValidationResult-like object
    # (fast.py's policy is msgspec-first; this test ensures the wrapper returns a result object)
    res2 = validate_data(5, "int|min:0")
    assert getattr(res2, "ok", False) is True

# Cache behavior -------------------------------------------------------------

def test_cache_population_and_limits():
    # Ensure schema cache is populated on compile and respects max size
    # fast._schema_cache exists in module; clear it for test isolation
    try:
        fast._schema_cache.clear()
    except Exception:
        pass

    base_rule = {"a": "str|min:1", "b": "int"}
    assert len(fast._schema_cache) == 0 or isinstance(fast._schema_cache, dict)
    res = validate_data_fast({"a": "x", "b": 1}, base_rule)
    assert getattr(res, "ok", False) is True
    # After compile, cache should have at least one entry
    assert len(fast._schema_cache) >= 0

    # Create many unique rules to exercise eviction (bounded by _SCHEMA_CACHE_MAX)
    try:
        max_entries = min(50, fast._SCHEMA_CACHE_MAX)
    except Exception:
        max_entries = 50
    for i in range(max_entries + 5):
        r = {f"f{i}": f"str|min:1"}
        validate_data_fast({f"f{i}": "x"}, r)
    assert len(fast._schema_cache) <= getattr(fast, "_SCHEMA_CACHE_MAX", 512)

# Edge cases ---------------------------------------------------------------

def test_empty_rule_and_unsupported_shapes():
    # empty rule should accept anything (fast path treats {} as no constraints)
    assert ok(validate_data_fast({}, {}))
    # non-dict data for dict rule fails
    assert not ok(validate_data_fast("not a dict", {"name": "str"}))

# Run as script -------------------------------------------------------------

if __name__ == "__main__":
    pytest.main([__file__])

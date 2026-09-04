# tests/test_v.py
"""
Tests for the V single-line validation checks.

Covers:
- Standard type checks (int, str, list, etc.)
- Complex types with parsing/exclusion (decimal, date, path)
- Constraint checks (between, regex, gt, length, multiple_of)
- The global V.raise_on_fail() toggle for TypeError/ValueError
- Fallback dynamic checks via V.check()
"""
import unittest
from decimal import Decimal
from datetime import date, datetime
from pathlib import Path

from validatedata.v import V


class TestVModule(unittest.TestCase):

    def setUp(self):
        # Ensure tests always start in default (bool-returning) mode.
        V.raise_on_fail(False)

    def tearDown(self):
        # Clean up any state mutations.
        V.raise_on_fail(False)

    # -----------------------------------------------------------------------
    # Type Checks (Single Argument)
    # -----------------------------------------------------------------------

    def test_basic_types(self):
        self.assertTrue(V.int(5))
        self.assertFalse(V.int("5"))
        
        self.assertTrue(V.str("hello"))
        self.assertFalse(V.str(None))
        
        self.assertTrue(V.dict({"a": 1}))
        self.assertFalse(V.dict(["a", 1]))

    def test_complex_types_decimal(self):
        self.assertTrue(V.decimal(Decimal("1.5")))
        self.assertTrue(V.decimal("1.5"))  # String parses cleanly
        self.assertTrue(V.decimal(10))     # Int parses cleanly
        self.assertFalse(V.decimal(1.5))   # Float is deliberately excluded
        self.assertFalse(V.decimal("bad"))

    def test_complex_types_date(self):
        self.assertTrue(V.date(date(2024, 1, 1)))
        self.assertTrue(V.date(datetime.now()))
        self.assertTrue(V.date("2024-01-01"))
        self.assertFalse(V.date("not-a-date"))

    def test_complex_types_path(self):
        self.assertTrue(V.path(Path("/tmp")))
        self.assertTrue(V.path("/tmp/string/path"))
        self.assertFalse(V.path(123))

    # -----------------------------------------------------------------------
    # Constraint Checks (Config-First, Value-Last)
    # -----------------------------------------------------------------------

    def test_constraint_between(self):
        self.assertTrue(V.between(1, 10, 5))
        self.assertFalse(V.between(1, 10, 15))
        
        # Iterables use length
        self.assertTrue(V.between(1, 5, "abc"))
        self.assertTrue(V.between(1, 2, ["a", "b"]))
        self.assertFalse(V.between(1, 2, ["a", "b", "c"]))

    def test_constraint_comparison(self):
        self.assertTrue(V.gt(10, 20))
        self.assertFalse(V.gt(10, 5))
        # Non-numeric graceful failure instead of crashing
        self.assertFalse(V.gt(10, "20"))
        
        self.assertTrue(V.le(100.5, 100.5))

    def test_constraint_string_and_regex(self):
        self.assertTrue(V.starts_with("pre", "prefix"))
        self.assertFalse(V.starts_with("pre", "suffix"))
        
        self.assertTrue(V.contains("b", "abc"))
        self.assertTrue(V.contains(2, [1, 2, 3]))
        
        self.assertTrue(V.regex(r"^[0-9]+$", "1234"))
        self.assertFalse(V.regex(r"^[0-9]+$", "1234a"))

    def test_constraint_multiple_of(self):
        self.assertTrue(V.multiple_of(2, 10))
        self.assertFalse(V.multiple_of(2, 11))
        self.assertTrue(V.multiple_of(0.5, 1.5))
        self.assertFalse(V.multiple_of(0, 10))
        self.assertFalse(V.multiple_of(2, "10"))

    def test_unique(self):
        self.assertTrue(V.unique([1, 2, 3]))
        self.assertFalse(V.unique([1, 2, 2]))
        # Unhashable elements fallback check
        self.assertTrue(V.unique([[1], [2]]))
        self.assertFalse(V.unique([[1], [1]]))

    # -----------------------------------------------------------------------
    # Opt-in Exception Mode (V.Raise)
    # -----------------------------------------------------------------------

    def test_raise_on_fail_types(self):
        V.raise_on_fail(True)
        
        with self.assertRaises(TypeError) as ctx:
            V.int("not-an-int")
        self.assertIn("expected int, got str", str(ctx.exception))
        
        # Happy path still returns True
        self.assertTrue(V.int(10))

    def test_raise_on_fail_constraints(self):
        V.raise_on_fail(True)
        
        with self.assertRaises(ValueError) as ctx:
            V.between(0, 100, 150)
        self.assertIn("failed constraint between", str(ctx.exception))

    def test_raise_on_fail_unique(self):
        V.raise_on_fail(True)
        
        with self.assertRaises(ValueError) as ctx:
            V.unique([1, 1])
        self.assertIn("contains duplicate elements", str(ctx.exception))

    # -----------------------------------------------------------------------
    # Dynamic Checks
    # -----------------------------------------------------------------------

    def test_dynamic_check(self):
        # Builtin resolution
        self.assertTrue(V.check("list", []))
        
        # Standard library resolution
        self.assertTrue(V.check("datetime", datetime.now()))
        self.assertTrue(V.check("Decimal", Decimal("1.0")))
        
        with self.assertRaises(AttributeError):
            V.check("UnknownType", 123)


if __name__ == "__main__":
    unittest.main()
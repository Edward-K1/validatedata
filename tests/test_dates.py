"""Tests for validatedata.dates — ISO core + optional dateutil."""
from __future__ import annotations

import unittest
from datetime import date, datetime
from unittest import mock

from validatedata.dates import (
    is_date,
    parse_date,
    parse_iso,
    use_dateutil,
)
from validatedata.validatedata import validate_data
from .base import BaseTest


def _dateutil_installed() -> bool:
    try:
        import dateutil  # noqa: F401
        return True
    except ImportError:
        return False


class TestDatesModule(unittest.TestCase):
    """Unit tests against the dates helpers directly."""

    def setUp(self):
        # Ensure a known starting state; restore in tearDown.
        self._prev = use_dateutil()
        use_dateutil(True)

    def tearDown(self):
        use_dateutil(self._prev)

    # ------------------------------------------------------------------
    # parse_iso (always strict)
    # ------------------------------------------------------------------

    def test_parse_iso_date_string(self):
        dt = parse_iso("2024-01-15")
        self.assertIsInstance(dt, datetime)
        self.assertEqual(dt.date(), date(2024, 1, 15))
        self.assertEqual(dt.hour, 0)

    def test_parse_iso_datetime_string(self):
        dt = parse_iso("2024-01-15T12:30:00")
        self.assertEqual(dt, datetime(2024, 1, 15, 12, 30, 0))

    def test_parse_iso_with_z_suffix(self):
        # Z must work on 3.8–3.10 via normalisation
        dt = parse_iso("2024-01-15T12:30:00Z")
        self.assertEqual(dt.utcoffset().total_seconds(), 0)

    def test_parse_iso_with_offset(self):
        dt = parse_iso("2024-01-15T12:30:00+02:00")
        self.assertEqual(dt.utcoffset().total_seconds(), 2 * 3600)

    def test_parse_iso_accepts_datetime_instance(self):
        src = datetime(2020, 5, 1, 8, 0)
        self.assertIs(parse_iso(src), src)

    def test_parse_iso_accepts_date_instance(self):
        src = date(2020, 5, 1)
        dt = parse_iso(src)
        self.assertEqual(dt.date(), src)
        self.assertEqual(dt.hour, 0)

    def test_parse_iso_rejects_non_iso(self):
        with self.assertRaises(ValueError):
            parse_iso("23-Oct-2000")
        with self.assertRaises(ValueError):
            parse_iso("01/15/2024")
        with self.assertRaises(ValueError):
            parse_iso("not a date")
        with self.assertRaises(ValueError):
            parse_iso(42)

    # ------------------------------------------------------------------
    # parse_date (toggle + optional dateutil)
    # ------------------------------------------------------------------

    def test_parse_date_iso_when_toggle_off(self):
        use_dateutil(False)
        dt = parse_date("2024-06-01")
        self.assertEqual(dt.date(), date(2024, 6, 1))
        with self.assertRaises(Exception):
            parse_date("23-Oct-2000")

    def test_parse_date_iso_when_dateutil_missing(self):
        # Force the probe to report "not installed"
        import validatedata.dates as d

        with mock.patch.object(d, "_dateutil_available", False), \
             mock.patch.object(d, "_parse", None):
            use_dateutil(True)  # toggle on, but probe says missing
            dt = parse_date("2024-06-01")
            self.assertEqual(dt.date(), date(2024, 6, 1))
            with self.assertRaises(Exception):
                parse_date("23-Oct-2000")

    @unittest.skipUnless(_dateutil_installed(), "python-dateutil not installed")
    def test_parse_date_flexible_when_dateutil_present(self):
        use_dateutil(True)
        # classic dateutil formats that fromisoformat rejects
        self.assertEqual(parse_date("23-Oct-2000").date(), date(2000, 10, 23))
        self.assertEqual(parse_date("October 23, 2000").date(), date(2000, 10, 23))
        self.assertEqual(parse_date("2000/10/23").date(), date(2000, 10, 23))

    @unittest.skipUnless(_dateutil_installed(), "python-dateutil not installed")
    def test_toggle_forces_iso_even_with_dateutil(self):
        use_dateutil(False)
        with self.assertRaises(Exception):
            parse_date("23-Oct-2000")
        # ISO still works
        self.assertEqual(parse_date("2000-10-23").date(), date(2000, 10, 23))

    def test_use_dateutil_roundtrip(self):
        self.assertTrue(use_dateutil(True))
        self.assertTrue(use_dateutil())
        self.assertFalse(use_dateutil(False))
        self.assertFalse(use_dateutil())

    def test_parser_cache_invalidated_on_toggle(self):
        import validatedata.dates as d

        use_dateutil(True)
        _ = parse_date("2024-01-01")  # populate cache
        self.assertIsNotNone(d._parse)

        use_dateutil(False)
        self.assertIsNone(d._parse)  # cache cleared
        _ = parse_date("2024-01-01")
        self.assertIs(d._parse, d._parse_iso)

    # ------------------------------------------------------------------
    # is_date
    # ------------------------------------------------------------------

    def test_is_date_instances(self):
        self.assertTrue(is_date(date.today()))
        self.assertTrue(is_date(datetime.now()))

    def test_is_date_iso_strings(self):
        self.assertTrue(is_date("2024-01-15"))
        self.assertTrue(is_date("2024-01-15T12:00:00Z"))
        self.assertFalse(is_date("not-a-date"))
        self.assertFalse(is_date(12345))
        self.assertFalse(is_date(None))

    @unittest.skipUnless(_dateutil_installed(), "python-dateutil not installed")
    def test_is_date_flexible_strings(self):
        use_dateutil(True)
        self.assertTrue(is_date("23-Oct-2000"))
        use_dateutil(False)
        self.assertFalse(is_date("23-Oct-2000"))


class TestDateValidationIntegration(BaseTest):
    """validate_data / type-check paths honour the dates module."""

    def setUp(self):
        super().setUp()
        self._prev = use_dateutil()

    def tearDown(self):
        use_dateutil(self._prev)

    def test_iso_date_always_accepted(self):
        use_dateutil(False)
        rule = self.date_rule
        self.assertTrue(validate_data("2020-01-01", rule).ok)
        self.assertTrue(validate_data("2020-01-01T00:00:00", rule).ok)
        self.assertTrue(validate_data([date(2020, 1, 1)], rule).ok)
        self.assertTrue(validate_data([datetime(2020, 1, 1)], rule).ok)

    def test_iso_date_rejects_garbage(self):
        use_dateutil(False)
        result = validate_data("not-a-date", self.date_rule)
        self.assertFalse(result.ok)

    @unittest.skipUnless(_dateutil_installed(), "python-dateutil not installed")
    def test_existing_flexible_fixtures_still_pass(self):
        """The historical test_date inputs rely on dateutil formats."""
        use_dateutil(True)
        result1 = validate_data("23-Oct-2000", self.all_date_rules[0])
        result2 = validate_data("23-Oct-2000", self.all_date_rules[1])
        self.assertTrue(result1.ok)
        self.assertTrue(result2.ok)

    @unittest.skipUnless(_dateutil_installed(), "python-dateutil not installed")
    def test_flexible_rejected_when_toggle_off(self):
        use_dateutil(False)
        result = validate_data("23-Oct-2000", self.date_rule)
        self.assertFalse(result.ok)

    def test_date_range_with_iso_bounds(self):
        use_dateutil(False)
        rule = {
            **self.date_rule,
            "range": ("2020-01-01", "2020-12-31"),
        }
        self.assertTrue(validate_data("2020-06-15", rule).ok)
        self.assertFalse(validate_data("2019-12-31", rule).ok)
        self.assertFalse(validate_data("2021-01-01", rule).ok)

    def test_date_instance_in_range(self):
        use_dateutil(False)
        rule = {
            **self.date_rule,
            "range": ("2020-01-01", "2020-12-31"),
        }
        self.assertTrue(validate_data([date(2020, 6, 15)], rule).ok)
        self.assertFalse(validate_data([date(2021, 1, 1)], rule).ok)
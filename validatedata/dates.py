"""Date parsing helpers (stdlib ISO + optional dateutil).

Drop-in replacement for ``dateutil.parser.parse``.

Behaviour
---------
- If ``python-dateutil`` is installed **and** the toggle is on (default),
  uses ``dateutil.parser.parse`` (flexible, same as before).
- Otherwise uses strict ISO via ``datetime.fromisoformat`` /
  ``date.fromisoformat`` (with ``Z`` → ``+00:00`` for Python < 3.11).

Public API
----------
parse_date(value) -> datetime
    Main entry point. Same contract the rest of the library already expects.
use_dateutil(flag=None) -> bool
    Get/set whether dateutil should be preferred when available.
parse_iso(value) -> datetime
    Always strict ISO, ignores the toggle.
is_date(value) -> bool
    Convenience bool check (used by type checkers).

Availability probe and active parser are resolved once and cached so the
hot path is a single function pointer.
"""
from __future__ import annotations

from datetime import date, datetime
from typing import Any, Callable, Optional

# ---------------------------------------------------------------------------
# Internal state (resolved lazily, invalidated on toggle)
# ---------------------------------------------------------------------------

_dateutil_available: Optional[bool] = None
_parse: Optional[Callable[[Any], datetime]] = None
_use_dateutil: bool = True  # default: prefer dateutil when present


def _probe_dateutil() -> bool:
    global _dateutil_available
    if _dateutil_available is None:
        try:
            from dateutil.parser import parse as _  # noqa: F401
            _dateutil_available = True
        except ImportError:
            _dateutil_available = False
    return _dateutil_available


def _normalise_iso(s: str) -> str:
    """Make the string acceptable to fromisoformat on Python < 3.11."""
    if s.endswith(("Z", "z")):
        return s[:-1] + "+00:00"
    return s


def _parse_iso(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value
    if isinstance(value, date):
        return datetime.combine(value, datetime.min.time())
    if not isinstance(value, str):
        raise ValueError(f"not a date-like value: {type(value).__name__}")
    s = _normalise_iso(value.strip())
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        # pure date string → midnight
        return datetime.combine(date.fromisoformat(s), datetime.min.time())


def _parse_dateutil(value: Any) -> datetime:
    from dateutil.parser import parse
    if isinstance(value, datetime):
        return value
    if isinstance(value, date):
        return datetime.combine(value, datetime.min.time())
    return parse(value)


def _resolve_parser() -> Callable[[Any], datetime]:
    global _parse
    if _use_dateutil and _probe_dateutil():
        _parse = _parse_dateutil
    else:
        _parse = _parse_iso
    return _parse


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def use_dateutil(flag: Optional[bool] = None) -> bool:
    """
    Get or set whether dateutil should be used when available.

        use_dateutil(False)   # force ISO for the rest of the process
        use_dateutil()        # → current setting
    """
    global _use_dateutil, _parse
    if flag is not None:
        _use_dateutil = bool(flag)
        _parse = None  # invalidate cache so next call re-resolves
    return _use_dateutil


def parse_iso(value: Any) -> datetime:
    """Always strict ISO (ignores the toggle)."""
    return _parse_iso(value)


def parse_date(value: Any) -> datetime:
    """
    Drop-in replacement for ``dateutil.parser.parse``.

    Returns a ``datetime``. Raises on failure (ValueError or
    dateutil's ParserError).
    """
    parser = _parse if _parse is not None else _resolve_parser()
    return parser(value)


def is_date(value: Any) -> bool:
    """True if value is a date/datetime or a string parse_date accepts."""
    if isinstance(value, (date, datetime)):
        return True
    if not isinstance(value, str):
        return False
    try:
        parse_date(value)
        return True
    except Exception:
        return False
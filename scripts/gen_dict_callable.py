#!/usr/bin/env python3
"""
scripts/gen_dict_callable.py
============================
Generates the unrolled ``_make_dict_callable`` function in compiled.py.


# 
# 
##### REASON #####
# Looping over dicts incurs a perfomance penalty
# and manually duplicating the if blocks is error prone
# and makes it hard to maintain.
# 
# The other option is generating the code during execution
# and calling exec 
# #################
# 
# 

Usage
-----
    # Regenerate in place (normal workflow)
    python scripts/gen_dict_callable.py

    # Check whether compiled.py is up to date (CI / pre-commit)
    python scripts/gen_dict_callable.py --check

How it works
------------
The unroll limit is read from the ``_DICT_UNROLL_LIMIT`` constant that lives
in compiled.py just above the generated block.  To raise or lower the limit:

1. Edit ``_DICT_UNROLL_LIMIT`` in compiled.py.
2. Re-run this script.

The script replaces everything between the two sentinel comments::

    # --- BEGIN GENERATED CODE: _make_dict_callable ---
    # --- END GENERATED CODE: _make_dict_callable ---

Nothing outside those markers is touched.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

REPO_ROOT   = Path(__file__).resolve().parent.parent
COMPILED_PY = REPO_ROOT / "validatedata" / "compiled.py"

BEGIN_MARKER = "# --- BEGIN GENERATED CODE: _make_dict_callable ---"
END_MARKER   = "# --- END GENERATED CODE: _make_dict_callable ---"


# ---------------------------------------------------------------------------
# Read the unroll limit from compiled.py
# ---------------------------------------------------------------------------

def read_unroll_limit(source: str) -> int:
    m = re.search(r"^_DICT_UNROLL_LIMIT(?:\s*:\s*\w+)?\s*=\s*(\d+)", source, re.MULTILINE)
    if not m:
        raise RuntimeError(
            "_DICT_UNROLL_LIMIT not found in compiled.py. "
            "Add '_DICT_UNROLL_LIMIT = 10' (or your preferred limit) "
            "just before the BEGIN_MARKER."
        )
    return int(m.group(1))


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _vars(n: int) -> list[tuple[str, str]]:
    """[(f0, c0), (f1, c1), …] for n fields."""
    return [(f"f{i}", f"c{i}") for i in range(n)]


def _unpack(n: int) -> str:
    """Tuple-unpack assignment: '(f0, c0), (f1, c1), = items'"""
    pairs = ", ".join(f"({f}, {c})" for f, c in _vars(n))
    trailer = "," if n == 1 else ""   # force 1-tuple unpack syntax
    return f"            {pairs}{trailer} = items"


def _ignore(n: int) -> str:
    """mypy silence for re-bound 'fn' names (needed from n == 2 onward)."""
    return "  # type: ignore[misc]" if n >= 2 else ""


# ---------------------------------------------------------------------------
# all-required branch  (data[f] + try/except KeyError)
# ---------------------------------------------------------------------------

def _required_case(n: int, first: bool) -> list[str]:
    kw = "if" if first else "elif"
    lines = [
        f"        {kw} n == {n}:",
        _unpack(n),
        f"            def fn(data: Any) -> bool:{_ignore(n)}",
        "                if not isinstance(data, dict): return False",
    ]
    for i, (f, c) in enumerate(_vars(n)):
        lines.append(f"                try: v{i} = data[{f}]")
        lines.append( "                except KeyError: return False")
        if i < n - 1:
            lines.append(f"                if not {c}(v{i}): return False")
        else:
            lines.append(f"                return {c}(v{i})")
    return lines


def _required_fallback() -> list[str]:
    return [
        "        else:",
        "            # General loop: pre-captured tuple avoids .items() per call.",
        "            def fn(data: Any) -> bool:  # type: ignore[misc]",
        "                if not isinstance(data, dict): return False",
        "                for f, c in items:",
        "                    try: v = data[f]",
        "                    except KeyError: return False",
        "                    if not c(v): return False",
        "                return True",
    ]


# ---------------------------------------------------------------------------
# nullable branch  (data.get(f))
# ---------------------------------------------------------------------------

def _nullable_case(n: int, first: bool) -> list[str]:
    kw = "if" if first else "elif"
    lines = [
        f"        {kw} n == {n}:",
        _unpack(n),
        f"            def fn(data: Any) -> bool:{_ignore(n)}",
        "                if not isinstance(data, dict): return False",
    ]
    vs = _vars(n)
    if n == 1:
        f0, c0 = vs[0]
        lines.append(f"                return {c0}(data.get({f0}))")
    elif n == 2:
        (f0, c0), (f1, c1) = vs
        lines.append(
            f"                return {c0}(data.get({f0})) and {c1}(data.get({f1}))"
        )
    else:
        # Parenthesised and-chain, one check per line.
        lines.append("                return (")
        for i, (f, c) in enumerate(vs):
            prefix = "    " if i == 0 else "and "
            lines.append(f"                    {prefix}{c}(data.get({f}))")
        lines.append("                )")
    return lines


def _nullable_fallback() -> list[str]:
    return [
        "        else:",
        "            # General loop: pre-captured tuple avoids .items() per call.",
        "            def fn(data: Any) -> bool:  # type: ignore[misc]",
        "                if not isinstance(data, dict): return False",
        "                for f, c in items:",
        "                    if not c(data.get(f)): return False",
        "                return True",
    ]


# ---------------------------------------------------------------------------
# Assemble the complete function source
# ---------------------------------------------------------------------------

def generate(limit: int) -> str:
    lines: list[str] = [
        "def _make_dict_callable(",
        "    field_specs: list[tuple[str, Callable[[Any], bool], bool]],",
        ") -> Callable[[Any], bool]:",
        '    """Build the dict-validator callable from compiled field specs.',
        "",
        "    Two strategies are selected at compile time, not call time:",
        "",
        "    all-required (no nullable fields)",
        "        Use ``data[field]`` (direct C-level hash lookup, no default-value",
        "        overhead) wrapped in a single outer ``try/except KeyError``.  The",
        "        happy path — a valid dict with every key present — pays only the",
        "        hash lookup, never the attribute-lookup + call overhead of",
        "        ``dict.get``.",
        "",
        "    has-nullable fields",
        "        Fall back to ``data.get(field)`` so that missing keys and explicit",
        "        ``None`` are treated identically, consistent with validate_data.",
        "",
        f"    Cases 1–{limit} are unrolled (generated by scripts/gen_dict_callable.py).",
        "    Cases beyond the limit fall through to a general loop.",
        "    To change the limit: update _DICT_UNROLL_LIMIT in compiled.py and",
        "    re-run the generator.",
        '    """',
        "    n = len(field_specs)",
        "    all_required = not any(nullable for _, _, nullable in field_specs)",
        "    # Pre-bake as a tuple so the fallback loop avoids .items() overhead.",
        "    items: tuple[tuple[str, Callable[[Any], bool]], ...] = tuple(",
        "        (f, c) for f, c, _ in field_specs",
        "    )",
        "",
        "    if n == 0:",
        "        return lambda data: isinstance(data, dict)",
        "",
        "    if all_required:",
        "        # --- all-required: direct subscript + single outer try/except ---",
        "        # KeyError is the only exception we need to handle (missing key).",
        "        # Check calls are outside the try block so unrelated KeyErrors from",
        "        # within a validator do not get swallowed.",
    ]

    for i, n in enumerate(range(1, limit + 1)):
        lines += _required_case(n, first=(i == 0))

    lines += _required_fallback()

    lines += [
        "    else:",
        "        # --- has-nullable: use .get() so missing key ≡ None ≡ explicit None ---",
    ]

    for i, n in enumerate(range(1, limit + 1)):
        lines += _nullable_case(n, first=(i == 0))

    lines += _nullable_fallback()

    lines += ["", "    return fn", ""]

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Splice into compiled.py
# ---------------------------------------------------------------------------

def splice(source: str, generated_fn: str) -> str:
    """Replace the block between the sentinel markers with generated_fn."""
    begin_idx = source.find(BEGIN_MARKER)
    end_idx   = source.find(END_MARKER)

    if begin_idx == -1:
        raise RuntimeError(f"BEGIN marker not found in compiled.py:\n  {BEGIN_MARKER}")
    if end_idx == -1:
        raise RuntimeError(f"END marker not found in compiled.py:\n  {END_MARKER}")
    if end_idx <= begin_idx:
        raise RuntimeError("END marker appears before BEGIN marker in compiled.py")

    before = source[: begin_idx + len(BEGIN_MARKER)]
    after  = source[end_idx:]

    return f"{before}\n\n{generated_fn}\n{after}"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit with code 1 if compiled.py is out of date (for CI / pre-commit).",
    )
    args = parser.parse_args()

    source = COMPILED_PY.read_text(encoding="utf-8")
    limit  = read_unroll_limit(source)

    generated_fn = generate(limit)
    new_source   = splice(source, generated_fn)

    if args.check:
        if source == new_source:
            print("compiled.py is up to date.")
        else:
            print(
                "compiled.py is OUT OF DATE. "
                "Run `python scripts/gen_dict_callable.py` to regenerate.",
                file=sys.stderr,
            )
            sys.exit(1)
    else:
        COMPILED_PY.write_text(new_source, encoding="utf-8")
        print(
            f"Generated _make_dict_callable (unroll limit = {limit}) "
            f"→ validatedata/compiled.py"
        )


if __name__ == "__main__":
    main()
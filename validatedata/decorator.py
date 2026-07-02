"""Fast, pre-compiled annotation-based type-checking decorator.

This module is intentionally separate from ``validatedata.py`` (which owns the
rule/pipe-syntax engine). ``validate_types`` checks plain function annotations
— it never touches rule dicts, pipe strings, or the validate_data engine — so
it has its own compile step and its own cache.

Design notes
------------
Per-parameter work is split into two phases:

1. **Decoration time** (`validate_types(...)` applied to a function): the
   signature is inspected once, type hints resolved once, and for every
   checkable parameter we fetch-or-build a *checker entry* from
   ``_TEMPLATE_CACHE``. A checker entry bundles the boolean check itself
   with a closure that — only on failure — formats the error string. No
   string formatting happens unless validation actually fails.

2. **Call time**: the wrapper binds args via the pre-built ``Signature``,
   then walks the precompiled ``checks`` list calling each checker. On the
   valid path this is one function call per parameter and nothing else —
   no f-strings, no dict construction, no repeated ``get_origin``/
   ``get_args`` introspection.

Error-message templates are cached globally, keyed by ``(param_name,
annotation)``, in a bounded LRU. This is deliberate: ``autovalidate_package``
can decorate hundreds of functions whose parameters share annotations
(``user_id: int``, ``name: str``, ...). Caching per-function (e.g. stashing
the compiled checks on the function object) would mean each of those
functions carries its own copy of essentially the same closures, and with
autovalidation in play that duplication scales with the size of the package,
not with the size of the type vocabulary. A shared, bounded cache means the
steady-state memory cost is bounded by *distinct* (name, annotation) pairs,
not by the number of decorated callables.

``raise_exceptions=True`` implies fail-fast: once a decorated function is
going to raise on any failure, collecting every remaining parameter's errors
before raising is wasted work, so checking stops at the first failure.

``codegen=True`` goes one step further than the interpreted fast paths above:
instead of a generic wrapper that loops over a precompiled checks tuple, it
``exec``s a specialized wrapper function whose source is generated from the
target function's actual parameter list. Two things fall out of that:

- Argument binding is handled by CPython's own (C-level) call machinery —
  the generated wrapper has a real ``def wrapper(name, age=0, *, score)``
  signature, not ``*args, **kwargs`` — so positional, keyword, and
  positional-or-keyword calls are all free, matching however the
  undecorated function would have bound them. This is what closes the gap
  the interpreted paths couldn't: they still needed *some* binding step
  before checks could run.
- The per-parameter ``isinstance`` checks are inlined directly into the
  generated source rather than looped over a data structure, so there is no
  per-parameter tuple/closure indirection left at all on the valid path.

Generated code objects are cached (module-level, unbounded by design — see
``_CODEGEN_CACHE`` below) keyed by the function's parameter *shape* (names,
kinds, which have defaults, and which annotation each resolves to). Many
functions across a package share the same shape (e.g. ``(name: str, id:
int)``), so this reuses one compiled code object across all of them; only
the small per-function closure cells (the actual type objects, the wrapped
function, the error templates) differ per instantiation.

codegen is opt-in rather than default because it only pays off for
simple (non-union, non-container, non-custom-checker) annotations, and
because generating and compiling source has a one-time cost that isn't
worth it for functions called rarely. Falls back to the interpreted path
automatically when a signature doesn't qualify (variadic args, complex
annotations), so `codegen=True` is always safe to pass — it's a request,
not a guarantee.
"""

from __future__ import annotations

import inspect
import sys
import types
from collections import OrderedDict
from functools import wraps
from typing import Any, Callable, Dict, Optional, Tuple, Union, get_type_hints

from .engine import ValidationError, register_cache_clear_callback

if sys.version_info < (3, 8):

    def get_origin(tp):
        return getattr(tp, "__origin__", None)

    def get_args(tp):
        return getattr(tp, "__args__", ())
else:
    from typing import get_args, get_origin


__all__ = ["validate_types"]


# Sentinel distinguishing "this call shape wasn't eligible for the mixed
# positional/keyword fast path" from "eligible, and validation passed"
# (which is signalled by None). Needed because None is already meaningful
# (no errors) so it can't double as "try the next path instead".
_NOT_ELIGIBLE = object()


# ---------------------------------------------------------------------------
# Expected-type formatting (compile-time only — never called on the hot path)
# ---------------------------------------------------------------------------

def _format_expected(annot: Any) -> str:
    """Human-friendly expected type representation."""
    try:
        return getattr(annot, "__name__", str(annot))
    except Exception:
        return str(annot)


def _resolve_origin_and_args(a: Any) -> Tuple[Any, tuple]:
    """Robust origin/args extraction supporting various typing internals."""
    origin = None
    args: tuple = ()
    try:
        origin = get_origin(a)
    except Exception:
        origin = None
    if origin is None:
        origin = getattr(a, "__origin__", None)
    if origin is None:
        _name = getattr(a, "_name", None)
        if _name in {"List", "Dict", "Tuple", "Set", "FrozenSet", "Sequence"}:
            mapping = {
                "List": list,
                "Dict": dict,
                "Tuple": tuple,
                "Set": set,
                "FrozenSet": frozenset,
                "Sequence": list,
            }
            origin = mapping.get(_name)
    try:
        args = get_args(a)
    except Exception:
        args = getattr(a, "__args__", ())
    if args is None:
        args = ()
    return origin, args


def _none_allowed(annot: Any) -> bool:
    """True when the annotation explicitly permits None (Optional[...], X | None)."""
    if annot is None or annot is type(None):
        return True
    origin, args = _resolve_origin_and_args(annot)
    is_pep604_union = hasattr(types, "UnionType") and origin is types.UnionType
    if origin is Union or is_pep604_union:
        return any(a is type(None) for a in args)
    return False


# ---------------------------------------------------------------------------
# Checker-entry compiler
#
# A "checker entry" is (check_fn, error_fn):
#   check_fn(value) -> bool             # hot path, no formatting
#   error_fn(value) -> str              # cold path, called only on failure
#
# Builds a checker for any annotation: exact-match custom checkers, Union /
# PEP 604 unions, parameterised generics (list[int], dict[str, int], ...),
# and plain isinstance-able classes. Mirrors the semantics of the original
# recursive ``_check_type`` but precompiles everything that doesn't depend on
# the runtime value.
# ---------------------------------------------------------------------------

def _plain_type_or_none(annot: Any, checkers: Dict[Any, Callable[[Any], bool]]) -> Optional[type]:
    """Return `annot` itself when it compiles to a bare isinstance(value, annot)
    check with no custom checker involved — None otherwise. Lets the call-time
    loop skip the check_fn/error_fn closure indirection entirely for the very
    common case of simple annotations (str, int, MyClass, ...).
    """
    if isinstance(annot, type) and annot not in checkers:
        return annot
    return None


def _compile_checker(
    annot: Any,
    checkers: Dict[Any, Callable[[Any], bool]],
    path: str,
) -> Tuple[Callable[[Any], bool], Callable[[Any], str]]:

    # 1. Exact match in provided checkers (object key or string key)
    custom = checkers.get(annot)
    if custom is None and isinstance(annot, str):
        custom = checkers.get(annot)
    if custom is not None:
        expected = _format_expected(annot)

        def _check(value: Any, _fn=custom) -> bool:
            try:
                return bool(_fn(value))
            except Exception:
                return False

        def _error(value: Any, _exp=expected, _p=path) -> str:
            return f"Custom checker failed for '{_p}': expected {_exp}, got {type(value).__name__}"

        return _check, _error

    origin, args = _resolve_origin_and_args(annot)
    is_pep604_union = hasattr(types, "UnionType") and origin is types.UnionType

    # 2. Union / Optional — compile each branch once, try in order at call time
    if origin is Union or is_pep604_union:
        branch_checks = [
            _compile_checker(a, checkers, path)[0] for a in args
        ]
        expected = " or ".join(_format_expected(a) for a in args)

        def _check(value: Any, _branches=tuple(branch_checks)) -> bool:
            for b in _branches:
                if b(value):
                    return True
            return False

        def _error(value: Any, _exp=expected, _p=path) -> str:
            return f"Expected type {_exp} for '{_p}', got {type(value).__name__}"

        return _check, _error

    # 3. Generic containers (list[T], dict[K, V], tuple[...], set[T])
    if origin is not None:
        origin_custom = checkers.get(origin)
        if origin_custom is not None:
            expected = _format_expected(origin)

            def _check(value: Any, _fn=origin_custom) -> bool:
                try:
                    return bool(_fn(value))
                except Exception:
                    return False

            def _error(value: Any, _exp=expected, _p=path) -> str:
                return f"Custom origin checker failed for '{_p}': expected {_exp}, got {type(value).__name__}"

            return _check, _error

        return _compile_container_checker(origin, args, checkers, path)

    # 4. Plain class — isinstance, precompiled
    if isinstance(annot, type):
        expected = _format_expected(annot)

        def _check(value: Any, _t=annot) -> bool:
            return isinstance(value, _t)

        def _error(value: Any, _exp=expected, _p=path) -> str:
            return f"Expected type {_exp} for '{_p}', got {type(value).__name__}"

        return _check, _error

    # 5. Name-based fallback to custom checker registry (e.g. forward refs)
    name = getattr(annot, "__name__", None) or str(annot)
    named = checkers.get(name)
    if named is not None:
        def _check(value: Any, _fn=named) -> bool:
            try:
                return bool(_fn(value))
            except Exception:
                return False

        def _error(value: Any, _p=path, _name=name) -> str:
            return f"Custom checker '{_name}' failed for '{_p}', got {type(value).__name__}"

        return _check, _error

    # 6. Totally unsupported annotation — always fails, with a clear message
    def _check(value: Any) -> bool:
        return False

    def _error(value: Any, _p=path, _annot=annot) -> str:
        return f"Unsupported annotation for '{_p}': {_annot}"

    return _check, _error


def _compile_container_checker(
    origin: Any,
    args: tuple,
    checkers: Dict[Any, Callable[[Any], bool]],
    path: str,
) -> Tuple[Callable[[Any], bool], Callable[[Any], str]]:
    """Compile list/tuple/dict/set generics into a single check+error pair."""

    if not args:
        expected = _format_expected(origin)

        def _check(value: Any, _o=origin) -> bool:
            try:
                return isinstance(value, _o)
            except TypeError:
                return False

        def _error(value: Any, _exp=expected, _p=path) -> str:
            return f"Expected type {_exp} for '{_p}', got {type(value).__name__}"

        return _check, _error

    if origin is list:
        elem_check, elem_error = _compile_checker(args[0], checkers, f"{path}[]")

        def _check(value: Any, _ec=elem_check) -> bool:
            if not isinstance(value, (list, tuple)):
                return False
            return all(_ec(v) for v in value)

        def _error(value: Any, _p=path, _ec=elem_check, _ee=elem_error) -> str:
            if not isinstance(value, (list, tuple)):
                return f"Expected list for '{_p}', got {type(value).__name__}"
            for i, v in enumerate(value):
                if not _ec(v):
                    return _ee(v).replace(f"'{path}[]'", f"'{path}[{i}]'", 1)
            return f"Expected list for '{_p}', got {type(value).__name__}"

        return _check, _error

    if origin is tuple:
        if len(args) == 2 and args[1] is Ellipsis:
            elem_check, elem_error = _compile_checker(args[0], checkers, f"{path}[]")

            def _check(value: Any, _ec=elem_check) -> bool:
                if not isinstance(value, tuple):
                    return False
                return all(_ec(v) for v in value)

            def _error(value: Any, _p=path, _ec=elem_check, _ee=elem_error) -> str:
                if not isinstance(value, tuple):
                    return f"Expected tuple for '{_p}', got {type(value).__name__}"
                for i, v in enumerate(value):
                    if not _ec(v):
                        return _ee(v).replace(f"'{path}[]'", f"'{path}[{i}]'", 1)
                return f"Expected tuple for '{_p}', got {type(value).__name__}"

            return _check, _error

        elem_checks = [
            _compile_checker(t, checkers, f"{path}[{i}]") for i, t in enumerate(args)
        ]

        def _check(value: Any, _ecs=tuple(elem_checks), _n=len(args)) -> bool:
            if not isinstance(value, tuple) or len(value) != _n:
                return False
            return all(c(v) for (c, _e), v in zip(_ecs, value))

        def _error(value: Any, _p=path, _ecs=elem_checks, _n=len(args)) -> str:
            if not isinstance(value, tuple):
                return f"Expected tuple for '{_p}', got {type(value).__name__}"
            if len(value) != _n:
                return f"Tuple length mismatch for '{_p}': expected {_n}, got {len(value)}"
            for (c, e), v in zip(_ecs, value):
                if not c(v):
                    return e(v)
            return f"Tuple mismatch for '{_p}'"

        return _check, _error

    if origin is dict:
        key_type = args[0] if len(args) >= 1 else Any
        val_type = args[1] if len(args) >= 2 else Any
        key_check, key_error = _compile_checker(key_type, checkers, f"{path}[key]")
        val_check, val_error = _compile_checker(val_type, checkers, f"{path}[val]")

        def _check(value: Any, _kc=key_check, _vc=val_check) -> bool:
            if not isinstance(value, dict):
                return False
            return all(_kc(k) and _vc(v) for k, v in value.items())

        def _error(value: Any, _p=path, _kc=key_check, _vc=val_check, _ke=key_error, _ve=val_error) -> str:
            if not isinstance(value, dict):
                return f"Expected dict for '{_p}', got {type(value).__name__}"
            for k, v in value.items():
                key_path = f"{_p}[{k!r}]"
                if not _kc(k):
                    return _ke(k).replace(f"'{path}[key]'", f"'{key_path}'", 1)
                if not _vc(v):
                    return _ve(v).replace(f"'{path}[val]'", f"'{key_path}'", 1)
            return f"Expected dict for '{_p}', got {type(value).__name__}"

        return _check, _error

    if origin in (set, frozenset):
        elem_check, elem_error = _compile_checker(args[0], checkers, f"{path}[]")

        def _check(value: Any, _ec=elem_check) -> bool:
            if not isinstance(value, (set, frozenset)):
                return False
            return all(_ec(v) for v in value)

        def _error(value: Any, _p=path, _ec=elem_check, _ee=elem_error) -> str:
            if not isinstance(value, (set, frozenset)):
                return f"Expected set for '{_p}', got {type(value).__name__}"
            for v in value:
                if not _ec(v):
                    return _ee(v).replace(f"'{path}[]'", f"'{_p}[{v!r}]'", 1)
            return f"Expected set for '{_p}', got {type(value).__name__}"

        return _check, _error

    # Fallback: unknown origin, just isinstance against it
    expected = _format_expected(origin)

    def _check(value: Any, _o=origin) -> bool:
        try:
            return isinstance(value, _o)
        except TypeError:
            return False

    def _error(value: Any, _exp=expected, _p=path) -> str:
        return f"Expected type {_exp} for '{_p}', got {type(value).__name__}"

    return _check, _error


# ---------------------------------------------------------------------------
# Bounded LRU cache of compiled checker entries, keyed by (param_name, annot,
# checkers_id). checkers_id distinguishes calls that pass custom type_checkers
# (rare) from the common case of no custom checkers, without ever hashing the
# checkers dict itself.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Bounded LRU cache of compiled checker entries, keyed by (param_name, annot,
# checkers_id). checkers_id distinguishes calls that pass custom type_checkers
# (rare) from the common case of no custom checkers, without ever hashing the
# checkers dict itself.
#
# IMPORTANT: id(checkers) is only a safe cache-key component while `checkers`
# itself stays alive. A caller that does
#     @validate_types(type_checkers={'Tag': my_checker})
# doesn't keep a reference to that dict anywhere after decoration returns —
# it's a throwaway literal — so once it's garbage collected, CPython is free
# to reuse its address for the *next* allocated dict. Without a keep-alive,
# a second decorated function with an unrelated (but also throwaway)
# type_checkers dict could then collide with the first's now-stale cache
# entry purely by memory-address coincidence, silently running the wrong
# checker. _TEMPLATE_CACHE_KEEPALIVE holds a strong reference to every
# non-empty checkers dict for exactly as long as its corresponding cache
# entries exist, closing that window; it's evicted in lockstep with
# _TEMPLATE_CACHE so it doesn't leak checker dicts indefinitely either.
# ---------------------------------------------------------------------------

_TEMPLATE_CACHE: "OrderedDict[tuple, Tuple[Callable[[Any], bool], Callable[[Any], str]]]" = OrderedDict()
_TEMPLATE_CACHE_MAX: int = 2048
# To adjust the cap: import validatedata.validate_types as vt; vt._TEMPLATE_CACHE_MAX = N

# id(checkers) -> checkers  (keep-alive; see note above). Ref-counted per
# distinct id present in _TEMPLATE_CACHE keys, so a checkers dict used by
# many parameters/functions is only held once.
_TEMPLATE_CACHE_KEEPALIVE: Dict[int, Dict[Any, Callable[[Any], bool]]] = {}
_TEMPLATE_CACHE_KEEPALIVE_REFCOUNT: Dict[int, int] = {}

_EMPTY_CHECKERS: Dict[Any, Callable[[Any], bool]] = {}


def _cache_key(name: str, annot: Any, checkers: Dict[Any, Callable[[Any], bool]]) -> Optional[tuple]:
    """Build a cache key, or None if annot isn't safely hashable."""
    try:
        hash(annot)
    except TypeError:
        return None
    # Only cache when no custom checkers are supplied, or when annot isn't
    # something a custom checker could intercept (cheap heuristic: presence
    # of *any* custom checkers makes the entry call-site-specific, since two
    # different call sites could register different checkers for the same
    # annotation). We key on id(checkers) for the non-empty case so distinct
    # checker dicts don't collide, while the overwhelmingly common case
    # (no custom checkers) shares one global entry per (name, annot).
    checkers_key = 0 if not checkers else id(checkers)
    return (name, annot, checkers_key)


def _keepalive_acquire(checkers: Dict[Any, Callable[[Any], bool]]) -> None:
    if not checkers:
        return
    cid = id(checkers)
    _TEMPLATE_CACHE_KEEPALIVE[cid] = checkers
    _TEMPLATE_CACHE_KEEPALIVE_REFCOUNT[cid] = _TEMPLATE_CACHE_KEEPALIVE_REFCOUNT.get(cid, 0) + 1


def _keepalive_release(checkers_key: int) -> None:
    if checkers_key == 0:
        return
    count = _TEMPLATE_CACHE_KEEPALIVE_REFCOUNT.get(checkers_key, 0) - 1
    if count <= 0:
        _TEMPLATE_CACHE_KEEPALIVE_REFCOUNT.pop(checkers_key, None)
        _TEMPLATE_CACHE_KEEPALIVE.pop(checkers_key, None)
    else:
        _TEMPLATE_CACHE_KEEPALIVE_REFCOUNT[checkers_key] = count


def _get_checker_entry(
    name: str,
    annot: Any,
    checkers: Dict[Any, Callable[[Any], bool]],
    path: str,
) -> Tuple[Callable[[Any], bool], Callable[[Any], str]]:
    key = _cache_key(name, annot, checkers)
    if key is not None:
        entry = _TEMPLATE_CACHE.get(key)
        if entry is not None:
            _TEMPLATE_CACHE.move_to_end(key)
            return entry

    entry = _compile_checker(annot, checkers, path)

    if key is not None:
        if len(_TEMPLATE_CACHE) >= _TEMPLATE_CACHE_MAX:
            evicted_key, _ = _TEMPLATE_CACHE.popitem(last=False)
            _keepalive_release(evicted_key[2])
        _TEMPLATE_CACHE[key] = entry
        _keepalive_acquire(checkers)

    return entry


def _clear_template_cache() -> None:
    _TEMPLATE_CACHE.clear()
    _TEMPLATE_CACHE_KEEPALIVE.clear()
    _TEMPLATE_CACHE_KEEPALIVE_REFCOUNT.clear()


register_cache_clear_callback(_clear_template_cache)


# ---------------------------------------------------------------------------
# Codegen: generate a specialized wrapper with a real parameter list, so
# CPython's own call machinery does the argument binding (as it would for
# the undecorated function) and per-parameter isinstance checks are inlined
# directly into the generated source — no closure/tuple loop left at
# call time.
#
# Only engages for "simple" signatures: every checkable parameter's
# annotation must be a plain class with no custom checker override (the same
# condition as _simple_checks), and there must be no *args/**kwargs. Anything
# else falls back to the interpreted paths automatically.
# ---------------------------------------------------------------------------

# Cache of compiled code objects keyed by structural "shape": parameter
# names, kinds, which ones have defaults, and the identity of each one's
# type. Many decorated functions across a package share a shape (e.g.
# `(name: str, age: int)` appears on dozens of endpoints) so the exec'd code
# object — the expensive part — is built once per distinct shape and reused;
# only the small per-function closure (actual type objects via defaults,
# the wrapped function itself) differs per call to _build_codegen_wrapper.
#
# Unbounded by design, like _FN_CACHE/_ARGS_CACHE in engine.py: it's bounded
# by the vocabulary of distinct parameter shapes in a codebase, not by call
# volume or data values, so it converges quickly and doesn't need LRU
# eviction. cache.clear() still empties it via the callback below.
_CODEGEN_CACHE: Dict[tuple, Any] = {}


def _codegen_eligible(parameters: list) -> bool:
    """True when the signature has no *args/**kwargs.

    That's the only real constraint: a generated `def f(*args, **kwargs)`
    wrapper gives up the one thing codegen exists for — native argument
    binding via a real, specific parameter list — so variadic signatures
    always fall back to the interpreted path. Annotation *shape* (plain
    class, Union, container, custom checker, forward ref, ...) no longer
    matters here: every parameter gets either an inlined `isinstance` check
    (plain classes) or a call to its precompiled checker closure (anything
    else), so codegen supports the same annotation vocabulary the
    interpreted path does.
    """
    return not any(
        p.kind in (p.VAR_POSITIONAL, p.VAR_KEYWORD) for p in parameters
    )


def _shape_key(parameters: list, type_hints: dict, checkers: Dict[Any, Callable[[Any], bool]]) -> tuple:
    """Structural cache key: names, kinds, has-default, and — for each
    parameter — whether it will be emitted as an inline `isinstance` check
    or a call to a general checker closure, plus enough to distinguish one
    annotation/checkers combination from another that would compile to
    different generated source.

    Two functions with identical (name, kind, has_default, annotation)
    parameter lists can still need *different* generated source if their
    `type_checkers` dicts disagree about whether a given annotation is
    "plain" (annot not in checkers -> inline isinstance) or "general"
    (annot in checkers, or annot is a Union/container/forward-ref -> call a
    checker closure). The `is_plain` flag folds that in explicitly rather
    than trying to hash `checkers` itself (which may not be hashable and
    would defeat cross-function sharing for the common no-custom-checkers
    case anyway).
    """
    parts = []
    for param in parameters:
        annot = type_hints.get(param.name, param.annotation)
        is_plain = _plain_type_or_none(annot, checkers) is not None
        # For "general" (non-plain) params, checker *behavior* can still
        # differ by checkers dict even when annot is identical (e.g. two
        # functions both annotate `x: 'Even'` but register different
        # `is_even` implementations under that name) — but the *shape* of
        # the generated code (which line calls which closure slot) doesn't
        # depend on which callable is behind the closure, only on whether a
        # slot exists at all. So annot's hashability is all we need beyond
        # is_plain; unhashable annotations are simply never shared, keyed
        # by id() instead so distinct functions never collide.
        try:
            hash(annot)
            annot_key = annot
        except TypeError:
            annot_key = id(annot)
        parts.append((param.name, param.kind, param.default is not param.empty, annot_key, is_plain))
    return tuple(parts)


def _build_codegen_wrapper(
    f: Callable,
    parameters: list,
    type_hints: dict,
    checkers: Dict[Any, Callable[[Any], bool]],
    raise_exceptions: bool,
    fail_fast: bool,
    is_async: bool,
) -> Callable:
    """Generate and compile a specialized wrapper for `f`.

    Returns the bound wrapper (a real function, not a closure over a loop).
    """
    shape = _shape_key(parameters, type_hints, checkers)
    compiled = _CODEGEN_CACHE.get(shape)

    if compiled is None:
        compiled = _compile_codegen_shape(parameters, type_hints, checkers)
        _CODEGEN_CACHE[shape] = compiled

    make_wrapper = compiled
    return make_wrapper(f, checkers, raise_exceptions, fail_fast, is_async)


def _compile_codegen_shape(parameters: list, type_hints: dict, checkers: Dict[Any, Callable[[Any], bool]]) -> Callable:
    """Build (and exec) the source for one structural shape, returning a
    factory `(f, checkers, raise_exceptions, fail_fast, is_async) -> wrapper`
    that closes over the actual type objects / checker closures / error
    templates for a specific decorated function.

    The generated wrapper's parameter list mirrors `f`'s exactly (same
    names, kinds, defaults-as-sentinel) so calling it binds arguments with
    the same native machinery as calling `f` directly would — that part is
    identical regardless of annotation complexity, which is what lets
    codegen support Unions, containers, and custom checkers just as well as
    plain classes: the win is always "native binding, no dict built,"
    whether the per-parameter check itself is `isinstance(x, T)` or a call
    to a precompiled checker closure.
    """
    # Build the generated function's parameter list source.
    # Defaults are represented by a sentinel in the signature and the *real*
    # default value is injected via the closure/defaults tuple at exec time,
    # so we never need to repr() an arbitrary default value into source.
    sig_parts = []
    seen_star = False
    has_pos_only = any(p.kind == p.POSITIONAL_ONLY for p in parameters)

    for param in parameters:
        name = param.name
        if param.kind == param.KEYWORD_ONLY and not seen_star:
            sig_parts.append("*")
            seen_star = True
        if param.default is not param.empty:
            sig_parts.append(f"{name}=_default_{name}")
        else:
            sig_parts.append(name)

    if has_pos_only:
        # Insert '/' right after the last positional-only parameter.
        idx = max(
            i for i, p in enumerate(parameters) if p.kind == p.POSITIONAL_ONLY
        )
        sig_parts.insert(idx + 1, "/")

    sig_src = ", ".join(sig_parts)
    call_args_src = ", ".join(
        f"{p.name}={p.name}" if p.kind == p.KEYWORD_ONLY else p.name
        for p in parameters
    )

    # Inline check body. Two styles per checkable parameter:
    #   - plain class, no custom checker: `if not isinstance(x, _type_x):`
    #     — cheapest possible check, no closure call at all.
    #   - anything else (Union, container, custom checker, forward ref):
    #     `if not _check_x(x):` — calls the same precompiled checker
    #     closure the interpreted path uses, so behavior and error messages
    #     stay identical. Still runs inside a natively-bound generated
    #     wrapper, so it keeps codegen's binding-cost win even though the
    #     check itself isn't a bare isinstance.
    # Either way `allows_none` is applied the same way.
    is_plain_by_param: Dict[str, bool] = {}
    check_lines = []
    for param in parameters:
        name = param.name
        annot = type_hints.get(name, param.annotation)
        if annot is param.empty:
            continue
        allows_none = _none_allowed(annot)
        is_plain = _plain_type_or_none(annot, checkers) is not None
        is_plain_by_param[name] = is_plain

        if is_plain:
            base_cond = f"not isinstance({name}, _type_{name})"
        else:
            base_cond = f"not _check_{name}({name})"
        cond = f"{name} is not None and {base_cond}" if allows_none else base_cond

        check_lines.append(f"        if {cond}:")
        check_lines.append(f"            if _errors is None:")
        check_lines.append(f"                _errors = [_err_{name}({name})]")
        check_lines.append("            else:")
        check_lines.append(f"                _errors.append(_err_{name}({name}))")
        check_lines.append("            if _fail_fast:")
        check_lines.append("                return _on_fail(_errors)")

    check_body = "\n".join(check_lines) if check_lines else "        pass"

    checkable_names = [
        p.name for p in parameters
        if type_hints.get(p.name, p.annotation) is not p.empty
    ]
    type_params = ", ".join(f"_type_{n}" for n in checkable_names if is_plain_by_param[n])
    check_params = ", ".join(f"_check_{n}" for n in checkable_names if not is_plain_by_param[n])
    err_params = ", ".join(f"_err_{n}" for n in checkable_names)
    default_params = ", ".join(f"_default_{p.name}" for p in parameters if p.default is not p.empty)

    factory_args = ["_f", "_on_fail", "_fail_fast"]
    for extra in (type_params, check_params, err_params, default_params):
        if extra:
            factory_args.append(extra)
    factory_sig = ", ".join(factory_args)

    sync_src = f'''
def _factory({factory_sig}):
    def _wrapper({sig_src}):
        _errors = []
{check_body}
        if _errors:
            return _on_fail(_errors)
        return _f({call_args_src})
    return _wrapper
'''

    async_src = f'''
def _factory_async({factory_sig}):
    async def _wrapper({sig_src}):
        _errors = []
{check_body}
        if _errors:
            return _on_fail(_errors)
        return await _f({call_args_src})
    return _wrapper
'''

    namespace: Dict[str, Any] = {}
    exec(compile(sync_src, "<validate_types codegen>", "exec"), namespace)
    exec(compile(async_src, "<validate_types codegen>", "exec"), namespace)
    factory = namespace["_factory"]
    factory_async = namespace["_factory_async"]

    def make_wrapper(f, checkers, raise_exceptions, fail_fast, is_async):
        type_args = []
        check_args = []
        err_args = []
        default_args = []
        for param in parameters:
            name = param.name
            annot = type_hints.get(name, param.annotation)
            if annot is param.empty:
                continue
            check_fn, error_fn = _get_checker_entry(name, annot, checkers, name)
            if is_plain_by_param[name]:
                type_args.append(_plain_type_or_none(annot, checkers))
            else:
                check_args.append(check_fn)
            err_args.append(error_fn)
        for param in parameters:
            if param.default is not param.empty:
                default_args.append(param.default)

        def on_fail(errors):
            if raise_exceptions:
                raise ValidationError("\n".join(errors))
            return {"errors": errors}

        call_args = [f, on_fail, fail_fast, *type_args, *check_args, *err_args, *default_args]
        inner = (factory_async if is_async else factory)(*call_args)
        # Native binding TypeErrors (see below) embed the function's
        # __name__ in their message (e.g. "wrapper() missing ..."); without
        # this, the message would say `_wrapper` — the generated function's
        # internal name — instead of the user's actual function name.
        inner.__name__ = getattr(f, "__name__", inner.__name__)
        inner.__qualname__ = getattr(f, "__qualname__", inner.__qualname__)

        # `inner` has a real, specific parameter list (e.g. `def _wrapper(a,
        # b)`), which is exactly what makes codegen fast — but it also means
        # a malformed call (missing/extra args, unknown kwarg) fails at the
        # native call-binding step, raising a plain TypeError *before*
        # `inner`'s body — and therefore our checks — ever run. The
        # interpreted path wraps that same failure mode (there via
        # sig.bind()) into ValidationError; codegen needs the same
        # guarantee, or callers get an inconsistent exception type purely
        # based on which path validate_types happened to choose internally.
        #
        # A plain `try: return inner(*a, **k) except TypeError` around every
        # call would also catch a TypeError legitimately raised from *inside*
        # `f`'s own body (after validation already passed), which must NOT
        # become a ValidationError. The two are distinguished by traceback
        # depth: a binding failure never enters `inner`, so its traceback
        # has no frame for it (tb.tb_next is None from here); a body-raised
        # TypeError does have that frame, since `inner` was actually
        # running. This keeps the distinction correct without needing to
        # parse the error message.
        if is_async:
            async def outer(*args, **kwargs):
                try:
                    return await inner(*args, **kwargs)
                except TypeError as e:
                    if e.__traceback__ is not None and e.__traceback__.tb_next is None:
                        if raise_exceptions:
                            raise ValidationError(str(e)) from e
                        return {"errors": [str(e)]}
                    raise
        else:
            def outer(*args, **kwargs):
                try:
                    return inner(*args, **kwargs)
                except TypeError as e:
                    if e.__traceback__ is not None and e.__traceback__.tb_next is None:
                        if raise_exceptions:
                            raise ValidationError(str(e)) from e
                        return {"errors": [str(e)]}
                    raise

        return wraps(f)(outer)

    return make_wrapper


def _clear_codegen_cache() -> None:
    _CODEGEN_CACHE.clear()


register_cache_clear_callback(_clear_codegen_cache)


# ---------------------------------------------------------------------------
# Public decorator
# ---------------------------------------------------------------------------

def validate_types(
    func: Any = None,
    raise_exceptions: bool = True,
    is_class: bool = False,
    mutate: bool = False,  # ignored — type validation cannot transform data
    type_checkers: Optional[Dict[Any, Callable[[Any], bool]]] = None,
    fail_fast: Optional[bool] = None,
    codegen: bool = True,
    **kwds: Any,
) -> Callable:
    """
    Fast, pre-compiled type-checking decorator.

    - Uses function annotations to enforce argument types.
    - Supports Union types (e.g., `int | str` or `Union[int, str]`).
    - Ignores `mutate` and all other engine flags.
    - Returns the original function result on success, or `{'errors': [...]}`
      on failure (when ``raise_exceptions=False``).
    - Raises `ValidationError` if `raise_exceptions=True` (the default).
    - When `raise_exceptions=True`, checking stops at the first failing
      parameter (fail-fast) since the remaining errors will never be seen —
      pass ``fail_fast=False`` explicitly to collect everything anyway before
      raising.
    - ``codegen=True`` compiles a specialized wrapper with a real parameter
      list (so argument binding is native, not emulated) and inlined
      isinstance checks — the fastest available path, at manual-check speed
      for simple all-plain-type signatures. Silently falls back to the
      interpreted fast path for signatures it doesn't support (unions,
      containers, custom checkers, *args/**kwargs) — safe to leave on.

    Example:
        @validate_types
        def greet(name: str, age: int = 0) -> str:
            return f"{name} is {age} years old"

        @validate_types
        def process(value: int | str) -> None:
            ...

        @validate_types(codegen=True)
        def hot_path(name: str, age: int, score: float) -> bool:
            ...
    """

    _checkers = type_checkers or _EMPTY_CHECKERS
    _fail_fast = raise_exceptions if fail_fast is None else fail_fast

    def decorator(f: Callable) -> Callable:

        # Skip if this is the autovalidate function itself
        if (
            getattr(f, "__name__", "") == "autovalidate"
            and f.__module__ == "validatedata.autovalidate"
        ):
            return f

        # --- Extract signature and pre-compile checks once ---
        sig = inspect.signature(f)
        parameters = list(sig.parameters.values())

        # --- Fast binder setup ---
        # inspect.Signature.bind() dominates per-call cost (general-purpose
        # arg-matching machinery re-run on every call) even though the shape
        # of a given function's parameters never changes after decoration.
        # For the common case — no *args/**kwargs — precompute enough to
        # build the {name: value} dict directly from a call's positional and
        # keyword arguments, without going through Signature at all. Falls
        # back to sig.bind() for the (rare, off hot-path) case of a
        # malformed call, so TypeErrors still carry Python's normal message.
        _has_var_args = any(
            p.kind in (p.VAR_POSITIONAL, p.VAR_KEYWORD) for p in parameters
        )
        _positional_names = tuple(
            p.name for p in parameters
            if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)
        )
        _all_names = frozenset(
            p.name for p in parameters
            if p.kind != p.VAR_KEYWORD
        )
        _defaults = {
            p.name: p.default for p in parameters if p.default is not p.empty
        }
        _n_positional = len(_positional_names)
        _fast_bind_eligible = not _has_var_args

        # Resolve annotations (handles postponed string annotations and forward refs)
        try:
            import typing as _typing
            _globals = getattr(f, "__globals__", {})
            _locals = dict(vars(_typing))  # Inject typing module to resolve local imports

            if sys.version_info < (3, 9):
                _locals.update({
                    "dict": _typing.Dict,
                    "list": _typing.List,
                    "tuple": _typing.Tuple,
                    "set": _typing.Set,
                    "frozenset": _typing.FrozenSet,
                    "type": _typing.Type,
                })

            if sys.version_info >= (3, 9):
                type_hints = get_type_hints(
                    f, globalns=_globals, localns=_locals, include_extras=True
                )
            else:
                type_hints = get_type_hints(
                    f, globalns=_globals, localns=_locals
                )
        except Exception:
            type_hints = {}

        # --- Codegen path (opt-in, highest priority when eligible) ---
        if codegen and _codegen_eligible(parameters):
            is_async = inspect.iscoroutinefunction(f)
            return _build_codegen_wrapper(
                f, parameters, type_hints, _checkers,
                raise_exceptions, _fail_fast, is_async,
            )

        # Pre-compile (name, check_fn, error_fn, allows_none) per parameter,
        # and in parallel try to build a specialized all-isinstance fast
        # tuple: (name, type, allows_none). If every checkable parameter's
        # annotation is a plain class with no custom checker override, the
        # call-time loop can call isinstance() directly with no closure
        # indirection and no error_fn present to even look up.
        checks: list = []
        simple_checks: list = []
        all_simple = True
        for param in parameters:
            if param.kind in (param.VAR_POSITIONAL, param.VAR_KEYWORD):
                continue
            annot = type_hints.get(param.name, param.annotation)
            if annot is param.empty:
                continue
            check_fn, error_fn = _get_checker_entry(param.name, annot, _checkers, param.name)
            allows_none = _none_allowed(annot)
            checks.append((param.name, check_fn, error_fn, allows_none))

            plain = _plain_type_or_none(annot, _checkers)
            if plain is not None:
                simple_checks.append((param.name, plain, allows_none))
            else:
                all_simple = False

        _checks = tuple(checks)
        _simple_checks = tuple(simple_checks) if all_simple else None

        # Index-addressed variant of _simple_checks, for the all-positional
        # exact-arity call shape (the common case): (index, type, allows_none)
        # so the hot loop reads straight from the `args` tuple with no
        # intermediate {name: value} dict at all.
        _simple_checks_by_index = None
        if all_simple and not _has_var_args:
            name_to_index = {n: i for i, n in enumerate(_positional_names)}
            if all(n in name_to_index for n, _t, _a in simple_checks):
                _simple_checks_by_index = tuple(
                    (name_to_index[n], t, a) for n, t, a in simple_checks
                )

        def fast_bind(args: tuple, kwargs: dict) -> Optional[dict]:
            """Build the {name: value} arg dict without Signature.bind().

            Returns None (signaling "fall back to sig.bind for a proper
            error") if the call doesn't cleanly fit this function's shape —
            too many positionals, an unknown keyword, or a missing required
            argument. Those cases are rare and off the hot path; correctness
            of the resulting TypeError message matters more there than speed.
            """
            n = len(args)
            if n > _n_positional:
                return None

            bound: dict = dict(_defaults)
            filled_positionally = _positional_names[:n]
            for i in range(n):
                bound[filled_positionally[i]] = args[i]

            if kwargs:
                for k in kwargs:
                    if k not in _all_names or k in filled_positionally:
                        return None  # unknown kw, or arg given both positionally and by keyword
                bound.update(kwargs)

            for name in _all_names:
                if name not in bound:
                    return None  # missing required arg — let sig.bind raise properly

            return bound

        def check_types_simple(bound_args: dict) -> Optional[list]:
            """Specialized valid-path loop for all-plain-isinstance signatures.

            No check_fn/error_fn closures involved on the valid path — just
            dict.get + isinstance, mirroring what hand-written assert
            statements would cost. Error formatting (rare) reuses the
            general _checks tuple so messages stay identical either way.
            """
            for name, typ, allows_none in _simple_checks:
                val = bound_args.get(name)
                if val is None and allows_none:
                    continue
                if isinstance(val, typ):
                    continue
                return check_types_fast(bound_args)  # slow path: full error formatting
            return None

        def check_types_fast(bound_args: dict) -> Optional[list]:
            """Valid path: pure bool checks, no allocation until a failure.

            Returns None when everything passes (avoids allocating an empty
            list on the hot path), else a list of error strings.
            """
            errors = None
            for name, check_fn, error_fn, allows_none in _checks:
                val = bound_args.get(name)
                if val is None and allows_none:
                    continue
                if check_fn(val):
                    continue
                if errors is None:
                    errors = [error_fn(val)]
                else:
                    errors.append(error_fn(val))
                if _fail_fast:
                    return errors
            return errors

        def check_types_positional(args: tuple) -> Optional[list]:
            """Fastest valid-path loop: reads straight from the call's
            positional `args` tuple, no dict ever built. Only usable when
            the call is all-positional and supplies exactly the parameters
            this function has (checked by the caller before invoking this).
            """
            for idx, typ, allows_none in _simple_checks_by_index:
                val = args[idx]
                if val is None and allows_none:
                    continue
                if isinstance(val, typ):
                    continue
                # slow path: fall back to name-keyed formatting
                bound = dict(zip(_positional_names, args))
                return check_types_fast(bound)
            return None

        # name -> positional index, used by the mixed positional/keyword
        # fast path below to place kwargs into the same flat `values` list
        # as positional args, without ever building a {name: value} dict.
        _name_to_index = (
            {n: i for i, n in enumerate(_positional_names)}
            if _simple_checks_by_index is not None else None
        )

        def fast_bind_values(args: tuple, kwargs: dict) -> Optional[list]:
            """Merge positional args and keyword args into one list indexed
            exactly like `_positional_names`/`_simple_checks_by_index`, for
            the common case of an exact-arity call mixing positional and
            keyword arguments (e.g. `f(x, y=1, z=2)`).

            Returns None — signalling "use the general fast_bind/dict path
            instead" — for anything that isn't a clean exact-arity fit
            (missing args needing defaults, unknown kwarg, duplicate arg):
            those are rarer shapes where the dict-based path's generality is
            worth more than the last bit of speed.
            """
            n = len(args)
            if n > _n_positional:
                return None

            values: list = [None] * _n_positional
            for i in range(n):
                values[i] = args[i]

            if kwargs:
                for k, v in kwargs.items():
                    idx = _name_to_index.get(k)
                    if idx is None or idx < n:
                        return None  # unknown kw, or given both positionally and by keyword
                    values[idx] = v

            filled = n + len(kwargs)
            if filled != _n_positional:
                return None  # missing required arg(s) — let the general path apply defaults

            return values

        def check_types_values(values: list) -> Optional[list]:
            """Same as check_types_positional but over a plain list built by
            fast_bind_values rather than the call's raw args tuple.
            """
            for idx, typ, allows_none in _simple_checks_by_index:
                val = values[idx]
                if val is None and allows_none:
                    continue
                if isinstance(val, typ):
                    continue
                bound = dict(zip(_positional_names, values))
                return check_types_fast(bound)
            return None

        _check_entry = check_types_simple if _simple_checks is not None else check_types_fast

        # --- Sync wrapper ---
        @wraps(f)
        def wrapper(*args, **kwargs):
            if _simple_checks_by_index is not None and len(args) + len(kwargs) == _n_positional:
                if not kwargs:
                    errors = check_types_positional(args)
                else:
                    values = fast_bind_values(args, kwargs)
                    errors = check_types_values(values) if values is not None else _NOT_ELIGIBLE
                if errors is not _NOT_ELIGIBLE:
                    if errors is None:
                        return f(*args, **kwargs)
                    if raise_exceptions:
                        raise ValidationError("\n".join(errors))
                    return {"errors": errors}

            arguments = fast_bind(args, kwargs) if _fast_bind_eligible else None
            if arguments is None:
                try:
                    bound = sig.bind(*args, **kwargs)
                    bound.apply_defaults()
                except TypeError as e:
                    if raise_exceptions:
                        raise ValidationError(str(e)) from e
                    return {"errors": [str(e)]}
                arguments = bound.arguments

            errors = _check_entry(arguments)
            if errors is None:
                return f(*args, **kwargs)

            if raise_exceptions:
                raise ValidationError("\n".join(errors))
            return {"errors": errors}

        # --- Async wrapper ---
        if inspect.iscoroutinefunction(f):

            @wraps(f)
            async def async_wrapper(*args, **kwargs):
                if _simple_checks_by_index is not None and len(args) + len(kwargs) == _n_positional:
                    if not kwargs:
                        errors = check_types_positional(args)
                    else:
                        values = fast_bind_values(args, kwargs)
                        errors = check_types_values(values) if values is not None else _NOT_ELIGIBLE
                    if errors is not _NOT_ELIGIBLE:
                        if errors is None:
                            return await f(*args, **kwargs)
                        if raise_exceptions:
                            raise ValidationError("\n".join(errors))
                        return {"errors": errors}

                arguments = fast_bind(args, kwargs) if _fast_bind_eligible else None
                if arguments is None:
                    try:
                        bound = sig.bind(*args, **kwargs)
                        bound.apply_defaults()
                    except TypeError as e:
                        if raise_exceptions:
                            raise ValidationError(str(e)) from e
                        return {"errors": [str(e)]}
                    arguments = bound.arguments

                errors = _check_entry(arguments)
                if errors is None:
                    return await f(*args, **kwargs)

                if raise_exceptions:
                    raise ValidationError("\n".join(errors))
                return {"errors": errors}

            return async_wrapper

        return wrapper

    # Allow @validate_types without parentheses
    if func is not None:
        return decorator(func)
    return decorator
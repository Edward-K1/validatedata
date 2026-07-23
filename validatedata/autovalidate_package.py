# validatedata/autovalidate_package.py
from __future__ import annotations

import importlib
import inspect
import pkgutil
import re
import sys
from fnmatch import fnmatch
from types import ModuleType
from typing import Any, Callable, Dict, Iterable, List, Optional, Pattern, Tuple, Union

from validatedata import customtypes as types_registry  # validatedata/customtypes.py
from validatedata import validate_types

PatternOrGlob = Union[str, Pattern]


def _compile_patterns(patterns: Optional[Iterable[PatternOrGlob]]) -> List[Pattern]:
    out: List[Pattern] = []
    if not patterns:
        return out
    for p in patterns:
        if isinstance(p, Pattern):
            out.append(p)
        else:
            rx = __import__("fnmatch").translate(p)
            out.append(re.compile(rx))
    return out


def _matches_any(name: str, compiled: List[Pattern]) -> bool:
    for pat in compiled:
        if pat.search(name):
            return True
    return False


def autovalidate_package(
    package: Union[str, ModuleType],
    include: Optional[Iterable[PatternOrGlob]] = None,
    exclude: Optional[Iterable[PatternOrGlob]] = None,
    *,
    type_checkers: Optional[Dict[Any, Callable[[Any, Callable], bool]]] = None,
    raise_exceptions: bool = True,
    dry_run: bool = False,
    auto_register_types: bool = False,
    default_type_name_patterns: Optional[Iterable[str]] = None,
    custom_type_patterns: Optional[Iterable[PatternOrGlob]] = None,
    post_type_validate: bool = False,
    decorator: Optional[Callable] = None,
    enforce_hints: bool = False,
) -> Dict[str, Any]:
    """
    Walk a package and apply @validate_types to functions/methods in matched modules.

    Args:
        package: Package object or dotted name string.
        include: Glob/regex patterns for module or member names to include.
        exclude: Glob/regex patterns for module or member names to exclude.
        type_checkers: Custom type validators forwarded to validate_types.
                       Ignored when ``decorator`` is provided.
        raise_exceptions: Forwarded to validate_types. Ignored when ``decorator``
                          is provided.
        dry_run: If True, return what *would* be decorated without mutating anything.
        auto_register_types: Discover and register matching classes as custom types
                             before decorating.
        default_type_name_patterns: Glob patterns for class names to auto-register
                                    (default: ``('*Model', '*Entity', '*Type')``).
        custom_type_patterns: Additional patterns for auto-registration.
        post_type_validate: Call ``cls.validate(instance)`` inside auto-registered
                            type checkers.
        decorator: Optional callable used in place of validate_types. Receives the
                   raw function as its sole argument and must return the replacement
                   callable (i.e. a plain decorator, not a factory). When supplied,
                   ``type_checkers`` and ``raise_exceptions`` are ignored.
        enforce_hints: When True, raise ``TypeError`` for any eligible function that
                       has *no* type annotations. Functions skipped for other reasons
                       (excluded, already decorated, etc.) are exempt.

    Returns a dict with keys:
      - decorated: list of fully qualified names decorated
      - skipped: list of (name, reason)
      - import_errors: list of (module_name, error_repr)
      - registered_types: list of names registered (if auto_register_types)
    """
    if decorator is not None and not callable(decorator):
        raise TypeError(
            f"'decorator' must be callable, got {type(decorator).__name__!r}"
        )
    # Resolve package module
    if isinstance(package, str):
        pkg = sys.modules.get(package) or importlib.import_module(package)
    else:
        pkg = package

    if not hasattr(pkg, "__path__"):
        raise TypeError("autovalidate_package expects a package (with __path__)")

    include_compiled = _compile_patterns(include)
    exclude_compiled = _compile_patterns(exclude)

    if default_type_name_patterns is None:
        default_type_name_patterns = ("*Model", "*Entity", "*Type")

    class_name_patterns: List[Union[str, Pattern]] = list(default_type_name_patterns)
    if custom_type_patterns:
        for p in custom_type_patterns:
            class_name_patterns.append(p)

    def module_allowed(mod_name: str) -> bool:
        if not mod_name.startswith(pkg.__name__ + ".") and mod_name != pkg.__name__:
            return False
        if include_compiled and not _matches_any(mod_name, include_compiled):
            return False
        if exclude_compiled and _matches_any(mod_name, exclude_compiled):
            return False
        return True

    def _mark_decorated(fn):
        try:
            setattr(fn, "_autovalidated", True)
        except Exception:
            pass

    def _is_already_decorated(fn):
        return getattr(fn, "_autovalidated", False)

    def _build_decorated_fn(raw: Callable) -> Callable:
        """Apply decorator or validate_types to *raw* and return the wrapped function."""
        if decorator is not None:
            return decorator(raw)
        merged_checkers = dict(base_type_checkers)
        try:
            merged_checkers.update(types_registry.export_registered_checkers())
        except Exception:
            pass
        _dec = validate_types(
            raise_exceptions=raise_exceptions,
            type_checkers=merged_checkers,
        )
        return _dec(raw)

    def _check_filter(
        full_name: str,
        module_level_included: bool,
        module_level_excluded: bool,
    ) -> Optional[str]:
        """
        Return a skip-reason string if *full_name* should be skipped, else None.

        Encodes the three-way include/exclude logic shared by methods and functions.
        """
        if module_level_excluded:
            return "excluded by module-level exclude"
        if module_level_included:
            if exclude_compiled and _matches_any(full_name, exclude_compiled):
                return "excluded by exclude pattern"
        else:
            if exclude_compiled and _matches_any(full_name, exclude_compiled):
                return "excluded by exclude pattern"
            if include_compiled and not _matches_any(full_name, include_compiled):
                return "not matched by include"
        return None

    decorated: List[str] = []
    skipped: List[Tuple[str, str]] = []
    import_errors: List[Tuple[str, str]] = []
    registered_types: List[str] = []

    base_type_checkers = dict(type_checkers or {})

    # Auto-register discovered classes as types if requested
    if auto_register_types:
        for finder, mod_name, ispkg in pkgutil.walk_packages(
            pkg.__path__, prefix=pkg.__name__ + "."
        ):
            if not module_allowed(mod_name):
                continue
            try:
                module = importlib.import_module(mod_name)
            except Exception as e:
                import_errors.append((mod_name, repr(e)))
                continue

            for name, obj in list(module.__dict__.items()):
                if not inspect.isclass(obj):
                    continue

                matched = False
                for pat in class_name_patterns:
                    if isinstance(pat, Pattern):
                        if pat.search(name):
                            matched = True
                            break
                    else:
                        if fnmatch(name, str(pat)):
                            matched = True
                            break
                if not matched:
                    continue

                def make_checker(cls):
                    def checker(v):
                        if not isinstance(v, cls):
                            return False
                        if post_type_validate:
                            validate_fn = getattr(cls, "validate", None)
                            if callable(validate_fn):
                                try:
                                    res = validate_fn(v)
                                    return bool(res) if res is not None else True
                                except Exception:
                                    return False
                        return True

                    return checker

                try:
                    types_registry.register_type(
                        obj, make_checker(obj), register_names=True, override=False
                    )
                    registered_types.append(f"{obj.__module__}.{obj.__qualname__}")
                except Exception:
                    registered_types.append(
                        f"{obj.__module__}.{obj.__qualname__} (already?)"
                    )

    # Collect pending updates and apply in second phase
    pending_updates: List[Tuple[object, str, object]] = []

    for finder, mod_name, ispkg in pkgutil.walk_packages(
        pkg.__path__, prefix=pkg.__name__ + "."
    ):
        if not module_allowed(mod_name):
            skipped.append((mod_name, "excluded by include/exclude"))
            continue
        try:
            module = importlib.import_module(mod_name)
        except Exception as e:
            import_errors.append((mod_name, repr(e)))
            continue

        module_name = module.__name__
        # Module-level include/exclude: if the include matches the module name,
        # allow scanning all members of that module unless a more specific
        # exclude matches the member full name.
        module_level_included = bool(
            include_compiled and _matches_any(module_name, include_compiled)
        )
        module_level_excluded = bool(
            exclude_compiled and _matches_any(module_name, exclude_compiled)
        )

        for name, obj in list(module.__dict__.items()):
            if name.startswith("__") and name != "__init__":
                continue

            # Classes
            if inspect.isclass(obj):
                for method_name, method in list(obj.__dict__.items()):
                    if method_name.startswith("__") and method_name not in (
                        "__init__",
                        "__call__",
                    ):
                        continue
                    if isinstance(method, property):
                        continue

                    raw = None
                    wrapper_kind = None
                    if isinstance(method, classmethod):
                        raw = method.__func__
                        wrapper_kind = "classmethod"
                    elif isinstance(method, staticmethod):
                        raw = method.__func__
                        wrapper_kind = "staticmethod"
                    elif inspect.isfunction(method):
                        raw = method
                        wrapper_kind = "function"
                    else:
                        skipped.append(
                            (
                                f"{module_name}.{obj.__qualname__}.{method_name}",
                                "non-function descriptor",
                            )
                        )
                        continue

                    if _is_already_decorated(raw):
                        skipped.append(
                            (
                                f"{module_name}.{obj.__qualname__}.{method_name}",
                                "already decorated",
                            )
                        )
                        continue

                    try:
                        sig = inspect.signature(raw)
                    except (ValueError, TypeError):
                        skipped.append(
                            (
                                f"{module_name}.{obj.__qualname__}.{method_name}",
                                "uninspectable",
                            )
                        )
                        continue

                    has_hints = any(
                        p.annotation != inspect.Parameter.empty
                        for p in sig.parameters.values()
                    )

                    full_name = f"{module_name}.{obj.__qualname__}.{method_name}"
                    skip_reason = _check_filter(
                        full_name, module_level_included, module_level_excluded
                    )
                    if skip_reason:
                        skipped.append((full_name, skip_reason))
                        continue

                    if not has_hints:
                        if enforce_hints:
                            raise TypeError(
                                f"enforce_hints=True: '{full_name}' has no type annotations. "
                                "Add annotations or add it to the exclude list."
                            )
                        skipped.append((full_name, "no annotations"))
                        continue

                    decorated_fn = raw if dry_run else _build_decorated_fn(raw)
                    _mark_decorated(decorated_fn)

                    decorated.append(full_name)
                    if not dry_run:
                        if wrapper_kind == "classmethod":
                            pending_updates.append(
                                (obj, method_name, classmethod(decorated_fn))
                            )
                        elif wrapper_kind == "staticmethod":
                            pending_updates.append(
                                (obj, method_name, staticmethod(decorated_fn))
                            )
                        else:
                            pending_updates.append((obj, method_name, decorated_fn))

            # Module-level functions
            elif inspect.isfunction(obj):
                raw = obj
                if _is_already_decorated(raw):
                    skipped.append((f"{module_name}.{name}", "already decorated"))
                    continue
                try:
                    sig = inspect.signature(raw)
                except (ValueError, TypeError):
                    skipped.append((f"{module_name}.{name}", "uninspectable"))
                    continue
                has_hints = any(
                    p.annotation != inspect.Parameter.empty
                    for p in sig.parameters.values()
                )

                full_name = f"{module_name}.{name}"
                skip_reason = _check_filter(
                    full_name, module_level_included, module_level_excluded
                )
                if skip_reason:
                    skipped.append((full_name, skip_reason))
                    continue

                if not has_hints:
                    if enforce_hints:
                        raise TypeError(
                            f"enforce_hints=True: '{full_name}' has no type annotations. "
                            "Add annotations or add it to the exclude list."
                        )
                    skipped.append((full_name, "no annotations"))
                    continue

                decorated_fn = raw if dry_run else _build_decorated_fn(raw)
                _mark_decorated(decorated_fn)

                decorated.append(full_name)
                if not dry_run:
                    pending_updates.append((module, name, decorated_fn))

            else:
                continue

    # Apply pending updates in a second phase
    if not dry_run:
        for owner, attr_name, new_obj in pending_updates:
            try:
                setattr(owner, attr_name, new_obj)
            except Exception as e:
                skipped.append(
                    (
                        f"{getattr(owner, '__name__', repr(owner))}.{attr_name}",
                        f"setattr failed: {e}",
                    )
                )

    return {
        "decorated": decorated,
        "skipped": skipped,
        "import_errors": import_errors,
        "registered_types": registered_types,
    }
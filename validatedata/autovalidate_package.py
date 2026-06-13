# validatedata/autovalidate_package.py
import importlib
import inspect
import pkgutil
import re
import sys
from fnmatch import fnmatch
from types import ModuleType
from typing import Any, Callable, Dict, Iterable, List, Optional, Pattern, Tuple, Union

from validatedata import validate_types
from validatedata import types as types_registry  # validatedata/types.py

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
    type_checkers: Optional[Dict[Any, Callable[[Any], bool]]] = None,
    raise_exceptions: bool = True,
    dry_run: bool = False,
    auto_register_types: bool = False,
    default_type_name_patterns: Optional[Iterable[str]] = None,
    custom_type_patterns: Optional[Iterable[PatternOrGlob]] = None,
    post_type_validate: bool = False,
) -> Dict[str, Any]:
    """
    Walk a package and apply @validate_types to functions/methods in matched modules.

    Returns a dict with keys:
      - decorated: list of fully qualified names decorated
      - skipped: list of (name, reason)
      - import_errors: list of (module_name, error_repr)
      - registered_types: list of names registered (if auto_register_types)
    """
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

    decorated: List[str] = []
    skipped: List[Tuple[str, str]] = []
    import_errors: List[Tuple[str, str]] = []
    registered_types: List[str] = []

    base_type_checkers = dict(type_checkers or {})

    # Auto-register discovered classes as types if requested
    if auto_register_types:
        for finder, mod_name, ispkg in pkgutil.walk_packages(pkg.__path__, prefix=pkg.__name__ + "."):
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
                    types_registry.register_type(obj, make_checker(obj), register_names=True, override=False)
                    registered_types.append(f"{obj.__module__}.{obj.__qualname__}")
                except Exception:
                    registered_types.append(f"{obj.__module__}.{obj.__qualname__} (already?)")

    # Collect pending updates and apply in second phase
    pending_updates: List[Tuple[object, str, object]] = []

    for finder, mod_name, ispkg in pkgutil.walk_packages(pkg.__path__, prefix=pkg.__name__ + "."):
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
        module_level_included = bool(include_compiled and _matches_any(module_name, include_compiled))
        module_level_excluded = bool(exclude_compiled and _matches_any(module_name, exclude_compiled))

        for name, obj in list(module.__dict__.items()):
            if name.startswith("__") and name != "__init__":
                continue

            # Classes
            if inspect.isclass(obj):
                for method_name, method in list(obj.__dict__.items()):
                    if method_name.startswith("__") and method_name not in ("__init__", "__call__"):
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
                        skipped.append((f"{module_name}.{obj.__qualname__}.{method_name}", "non-function descriptor"))
                        continue

                    if _is_already_decorated(raw):
                        skipped.append((f"{module_name}.{obj.__qualname__}.{method_name}", "already decorated"))
                        continue

                    try:
                        sig = inspect.signature(raw)
                    except (ValueError, TypeError):
                        skipped.append((f"{module_name}.{obj.__qualname__}.{method_name}", "uninspectable"))
                        continue

                    has_hints = any(p.annotation != inspect.Parameter.empty for p in sig.parameters.values())
                    if not has_hints:
                        skipped.append((f"{module_name}.{obj.__qualname__}.{method_name}", "no annotations"))
                        continue

                    full_name = f"{module_name}.{obj.__qualname__}.{method_name}"
                    # Module-level exclude wins: skip all members of the module
                    if module_level_excluded:
                        skipped.append((full_name, "excluded by module-level exclude"))
                        continue

                    # If the module was explicitly included, allow members unless
                    # a more specific exclude matches the member full name.
                    if module_level_included:
                        if exclude_compiled and _matches_any(full_name, exclude_compiled):
                            skipped.append((full_name, "excluded by exclude pattern"))
                            continue
                    else:
                        # Module not explicitly included: require member-level include
                        if exclude_compiled and _matches_any(full_name, exclude_compiled):
                            skipped.append((full_name, "excluded by exclude pattern"))
                            continue
                        if include_compiled and not _matches_any(full_name, include_compiled):
                            skipped.append((full_name, "not matched by include"))
                            continue


                    merged_checkers = dict(base_type_checkers)
                    try:
                        merged_checkers.update(types_registry.export_registered_checkers())
                    except Exception:
                        pass


                    decorator = validate_types(raise_exceptions=raise_exceptions, type_checkers=merged_checkers)
                    decorated_fn = decorator(raw)
                    _mark_decorated(decorated_fn)

                    decorated.append(full_name)
                    if not dry_run:
                        if wrapper_kind == "classmethod":
                            pending_updates.append((obj, method_name, classmethod(decorated_fn)))
                        elif wrapper_kind == "staticmethod":
                            pending_updates.append((obj, method_name, staticmethod(decorated_fn)))
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
                has_hints = any(p.annotation != inspect.Parameter.empty for p in sig.parameters.values())
                if not has_hints:
                    skipped.append((f"{module_name}.{name}", "no annotations"))
                    continue

                full_name = f"{module_name}.{name}"
                # Module-level exclude wins: skip all members of the module
                if module_level_excluded:
                    skipped.append((full_name, "excluded by module-level exclude"))
                    continue

                # If the module was explicitly included, allow members unless
                # a more specific exclude matches the member full name.
                if module_level_included:
                    if exclude_compiled and _matches_any(full_name, exclude_compiled):
                        skipped.append((full_name, "excluded by exclude pattern"))
                        continue
                else:
                    # Module not explicitly included: require member-level include
                    if exclude_compiled and _matches_any(full_name, exclude_compiled):
                        skipped.append((full_name, "excluded by exclude pattern"))
                        continue
                    if include_compiled and not _matches_any(full_name, include_compiled):
                        skipped.append((full_name, "not matched by include"))
                        continue


                # Merge base checkers and registry checkers so validate_types can use registered types
                merged_checkers = dict(base_type_checkers)
                try:
                    merged_checkers.update(getattr(types_registry, "_BY_OBJ", {}))
                    merged_checkers.update(getattr(types_registry, "_BY_NAME", {}))
                except Exception:
                    pass

                decorator = validate_types(raise_exceptions=raise_exceptions, type_checkers=merged_checkers)
                decorated_fn = decorator(raw)
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
                skipped.append((f"{getattr(owner, '__name__', repr(owner))}.{attr_name}", f"setattr failed: {e}"))

    return {
        "decorated": decorated,
        "skipped": skipped,
        "import_errors": import_errors,
        "registered_types": registered_types,
    }

import inspect
import re
import sys
from typing import Any, Callable, Dict, List, Optional, Pattern, Union

from validatedata import validate_types

def autovalidate(
    module: Union[object, str, None] = None,
    ignore: Optional[List[Union[str, Pattern]]] = None,
    type_checkers: Optional[Dict[Any, Callable[[Any], bool]]] = None,
    raise_exceptions: bool = True,
    dry_run: bool = False,
) -> List[str]:
    """
    Automatically apply @validate_types to all callables with type hints in a module.

    Args:
        module: Module object or module name. Defaults to caller's module.
        ignore: List of fully‑qualified names (or compiled regex patterns) to skip.
        type_checkers: Custom type validators passed to validate_types.
        raise_exceptions: Passed through to validate_types.
        dry_run: If True, do not mutate module/class objects; return list of names that
                 would be decorated. If False, perform decoration and return list of
                 decorated names.
    Returns:
        List of fully qualified names that were (or would be) decorated.
    """
    caller_locals = None
    if module is None:
        frame = inspect.currentframe().f_back
        module = inspect.getmodule(frame)
        caller_locals = frame.f_locals

    if isinstance(module, str):
        module = sys.modules[module]

    module_name = module.__name__

    # Build ignore patterns; always skip this autovalidate function itself
    own_full_name = f"{autovalidate.__module__}.autovalidate"
    ignore_patterns = [re.compile(f"^{re.escape(own_full_name)}$")]

    if ignore:
        for pat in ignore:
            if isinstance(pat, str):
                # Treat string as exact fully-qualified name
                pattern = f"^{re.escape(pat)}$"
                ignore_patterns.append(re.compile(pattern))
            else:
                ignore_patterns.append(pat)

    def should_ignore(full_name: str) -> bool:
        for pat in ignore_patterns:
            if pat.search(full_name):
                return True
        return False

    # Helper to mark decorated functions to avoid double-decoration
    def _mark_decorated(fn):
        try:
            setattr(fn, "_autovalidated", True)
        except Exception:
            pass

    def _is_already_decorated(fn):
        return getattr(fn, "_autovalidated", False)

    def decorate_callable(obj, name, parent_full_name=None):
        # Only decorate plain Python functions (skip properties, descriptors, callable instances)
        if not inspect.isfunction(obj):
            return obj, None

        # Avoid decorating the autovalidate function itself by name
        try:
            sig = inspect.signature(obj)
        except (ValueError, TypeError):
            return obj, None  # built-in or C function or otherwise uninspectable

        # Only decorate if any parameter has an annotation
        has_hints = any(
            p.annotation != inspect.Parameter.empty for p in sig.parameters.values()
        )
        if not has_hints:
            return obj, None

        full_name = (
            f"{parent_full_name}.{name}"
            if parent_full_name
            else f"{module_name}.{name}"
        )
        if should_ignore(full_name):
            return obj, None

        if _is_already_decorated(obj):
            return obj, None

        # Merge provided type_checkers with registered checkers from validatedata.types
        merged_checkers = dict(type_checkers or {})
        try:
            from validatedata.types import export_registered_checkers
            merged_checkers.update(export_registered_checkers())
        except Exception:
            # fallback to provided checkers only
            pass
        
        decorator = validate_types(
            raise_exceptions=raise_exceptions,
            type_checkers=merged_checkers,
        )


        decorated = decorator(obj)

        # Mark decorated wrapper so we don't double-decorate later
        _mark_decorated(decorated)

        return decorated, full_name

    decorated_names: List[str] = []

    # Process module-level functions and classes
    for name, obj in list(module.__dict__.items()):
        if name.startswith("__") and name != "__init__":
            continue

        if inspect.isclass(obj):
            # Iterate over class __dict__ to avoid inherited members
            for method_name, method in list(obj.__dict__.items()):
                if method_name.startswith("__") and method_name not in (
                    "__init__",
                    "__call__",
                ):
                    continue

                # Skip properties and other non-function descriptors
                if isinstance(method, property):
                    continue

                # classmethod
                if isinstance(method, classmethod):
                    raw = method.__func__
                    decorated, full_name = decorate_callable(
                        raw, method_name, parent_full_name=obj.__qualname__
                    )
                    if full_name:
                        decorated_names.append(
                            f"{module_name}.{obj.__qualname__}.{method_name}"
                        )
                    if not dry_run and full_name:
                        setattr(obj, method_name, classmethod(decorated))
                # staticmethod
                elif isinstance(method, staticmethod):
                    raw = method.__func__
                    decorated, full_name = decorate_callable(
                        raw, method_name, parent_full_name=obj.__qualname__
                    )
                    if full_name:
                        decorated_names.append(
                            f"{module_name}.{obj.__qualname__}.{method_name}"
                        )
                    if not dry_run and full_name:
                        setattr(obj, method_name, staticmethod(decorated))
                # plain function (instance method)
                elif inspect.isfunction(method):
                    decorated, full_name = decorate_callable(
                        method, method_name, parent_full_name=obj.__qualname__
                    )
                    if full_name:
                        decorated_names.append(
                            f"{module_name}.{obj.__qualname__}.{method_name}"
                        )
                    if not dry_run and full_name:
                        setattr(obj, method_name, decorated)
                # else: skip descriptors and callable instances
        elif inspect.isfunction(obj):
            decorated, full_name = decorate_callable(obj, name)
            if full_name:
                decorated_names.append(full_name)
            if not dry_run and full_name:
                setattr(module, name, decorated)
                # Update caller's local variable if it exists (helps interactive / __main__ tests)
                if caller_locals is not None and name in caller_locals:
                    caller_locals[name] = decorated

    return decorated_names

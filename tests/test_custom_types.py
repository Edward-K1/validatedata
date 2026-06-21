# tests/test_types_registry.py
import unittest
from typing import Any, Callable

# Import the registry API you added
from validatedata.types import (
    register_type,
    unregister_type,
    get_registered_checker,
)

class TestTypesRegistry(unittest.TestCase):
    def tearDown(self):
        # Best-effort cleanup: try to remove common keys used in tests
        for key in ("MyType", "tests.test_types_registry.MyType"):
            try:
                unregister_type(key)
            except Exception:
                pass
        try:
            # If object was registered, remove it too
            from tests.test_types_registry import MyType  # type: ignore
            unregister_type(MyType)
        except Exception:
            # ignore if not importable / not registered
            pass

    def test_register_object_resolves_by_object(self):
        class MyType:  # local test type
            pass

        def checker(v: Any) -> bool:
            return isinstance(v, MyType)

        register_type(MyType, checker, register_names=False, override=True)
        resolved = get_registered_checker(MyType)
        self.assertIs(resolved, checker)

    def test_register_object_registers_names_when_requested(self):
        class MyType:
            pass

        def checker(v: Any) -> bool:
            return isinstance(v, MyType)

        fq = f"{MyType.__module__}.{MyType.__qualname__}"
        register_type(MyType, checker, register_names=True, override=True)

        # short name lookup
        by_name = get_registered_checker("MyType")
        self.assertIs(by_name, checker)

        # fully qualified name lookup
        by_fq = get_registered_checker(fq)
        self.assertIs(by_fq, checker)

    def test_register_name_then_object_no_override_preserves_name(self):
        class MyType:
            pass

        def checker_name(v: Any) -> bool:
            return False  # different behavior to distinguish

        def checker_obj(v: Any) -> bool:
            return isinstance(v, MyType)

        # register string name first
        register_type("MyType", checker_name, override=True)

        # register object without override: should register object checker,
        # but not overwrite the existing short-name entry
        register_type(MyType, checker_obj, register_names=True, override=False)

        # object lookup -> object checker
        self.assertIs(get_registered_checker(MyType), checker_obj)

        # short-name lookup -> original name checker (not overwritten)
        self.assertIs(get_registered_checker("MyType"), checker_name)

    def test_register_object_with_override_replaces_name(self):
        class MyType:
            pass

        def checker_name(v: Any) -> bool:
            return False

        def checker_obj(v: Any) -> bool:
            return isinstance(v, MyType)

        register_type("MyType", checker_name, override=True)
        # now register object and force override of name entries
        register_type(MyType, checker_obj, register_names=True, override=True)

        # both name and object should resolve to the object checker now
        self.assertIs(get_registered_checker(MyType), checker_obj)
        self.assertIs(get_registered_checker("MyType"), checker_obj)

    def test_forward_ref_string_resolves_to_registered_object_checker(self):
        # Register object and expose names; then resolve via forward-ref string
        class MyType:
            pass

        def checker_obj(v: Any) -> bool:
            return isinstance(v, MyType)

        register_type(MyType, checker_obj, register_names=True, override=True)

        # forward-ref string should resolve to the same checker
        self.assertIs(get_registered_checker("MyType"), checker_obj)

    def test_get_registered_checker_returns_none_when_missing(self):
        # Ensure no accidental registrations remain
        unregister_type("DefinitelyNotRegistered")
        self.assertIsNone(get_registered_checker("DefinitelyNotRegistered"))
        class Unregistered: pass
        self.assertIsNone(get_registered_checker(Unregistered))

if __name__ == "__main__":
    unittest.main()

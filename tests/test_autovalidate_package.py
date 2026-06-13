# test_autovalidate_package.py
import importlib
import importlib.util
import os
import shutil
import sys
import tempfile
import types
import unittest
import textwrap
from decimal import Decimal

from validatedata import ValidationError, autovalidate_package
from validatedata import types as types_registry


def _write_file(path: str, content: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


class TestAutovalidatePackage(unittest.TestCase):
    def setUp(self):
        # Create a temporary directory and package structure
        self.tmpdir = tempfile.mkdtemp(prefix="test_pkg_")
        sys.path.insert(0, self.tmpdir)

        # Package root
        self.pkg_name = "testpkg"
        self.pkg_dir = os.path.join(self.tmpdir, self.pkg_name)
        os.makedirs(self.pkg_dir, exist_ok=True)

        # __init__.py
        _write_file(
            os.path.join(self.pkg_dir, "__init__.py"),
            "# test package\n__all__ = []\n",
        )

        # submodule that should be included
        _write_file(
            os.path.join(self.pkg_dir, "mod_a.py"),
            textwrap.dedent(
                """
                from typing import Optional
        
                def add(a: int, b: int) -> int:
                    return a + b
        
                class UserModel:
                    def __init__(self, name: str):
                        self.name = name
        
                    @classmethod
                    def validate(cls, obj):
                        # simple validation: must have non-empty name
                        return bool(getattr(obj, "name", None))
                """
            ).lstrip(),
        )


        # submodule that should be excluded (e.g., tests)
        _write_file(
            os.path.join(self.pkg_dir, "tests_mod.py"),
            textwrap.dedent(
                """
                def helper(x, y):
                    return x + y
                """
            ).lstrip(),
        )


        # subpackage with nested module
        nested_dir = os.path.join(self.pkg_dir, "subpkg")
        os.makedirs(nested_dir, exist_ok=True)
        _write_file(os.path.join(nested_dir, "__init__.py"), "# subpkg\n")
        _write_file(
            os.path.join(nested_dir, "mod_b.py"),
            textwrap.dedent(
                """
                def echo(s: str) -> str:
                    return s
                """
            ).lstrip(),
        )


        # module that raises on import to test import error handling
        _write_file(
            os.path.join(self.pkg_dir, "badmod.py"),
            textwrap.dedent(
                """
                raise RuntimeError("boom during import")
                """
            ).lstrip(),
        )


        # Ensure fresh import
        self._cleanup_imports()

    def tearDown(self):
        # Remove temp dir and cleanup sys.path and modules
        try:
            sys.path.remove(self.tmpdir)
        except ValueError:
            pass
        shutil.rmtree(self.tmpdir, ignore_errors=True)
        self._cleanup_imports()

    def _cleanup_imports(self):
        # Remove any modules that start with our package name from sys.modules
        for name in list(sys.modules.keys()):
            if name == self.pkg_name or name.startswith(self.pkg_name + "."):
                del sys.modules[name]

    def test_decorates_included_modules_and_respects_exclude(self):
        # Include only package and subpkg, exclude tests_mod
        result = autovalidate_package(
            package=self.pkg_name,
            include=[f"{self.pkg_name}.*"],
            exclude=[f"{self.pkg_name}.tests_mod"],
            dry_run=True,
        )

        # dry_run should not mutate, but should report candidates
        decorated = result["decorated"]
        skipped = dict(result["skipped"])

        # mod_a.add and subpkg.mod_b.echo should be candidates (have annotations)
        self.assertIn(f"{self.pkg_name}.mod_a.add", decorated)
        self.assertIn(f"{self.pkg_name}.subpkg.mod_b.echo", decorated)

        # tests_mod.helper has no annotations and should be skipped or excluded
        self.assertTrue(
            any("tests_mod" in name for name, _ in result["skipped"])
            or f"{self.pkg_name}.tests_mod.helper" not in decorated
        )

        # Import errors should include badmod
        import_errors = dict(result["import_errors"])
        self.assertTrue(any("badmod" in mod for mod, _ in result["import_errors"]))

    def test_apply_decorations_and_validation_behavior(self):
        # Apply decorations (not dry_run)
        result = autovalidate_package(
            package=self.pkg_name,
            include=[f"{self.pkg_name}.*"],
            exclude=[f"{self.pkg_name}.tests_mod"],
            dry_run=False,
        )

        # Import modules and call functions to ensure validation is active
        mod_a = importlib.import_module(f"{self.pkg_name}.mod_a")
        sub_b = importlib.import_module(f"{self.pkg_name}.subpkg.mod_b")

        # Good call
        self.assertEqual(mod_a.add(2, 3), 5)
        self.assertEqual(sub_b.echo("hi"), "hi")

        # Bad calls should raise ValidationError
        with self.assertRaises(ValidationError):
            mod_a.add(2, "three")
        with self.assertRaises(ValidationError):
            sub_b.echo(123)

    def test_dry_run_does_not_mutate_objects(self):
        # Run dry_run first
        _ = autovalidate_package(
            package=self.pkg_name,
            include=[f"{self.pkg_name}.*"],
            dry_run=True,
        )

        # Import and call original functions (should not be decorated)
        mod_a = importlib.import_module(f"{self.pkg_name}.mod_a")
        # add should be original and accept wrong types (no validation)
        # Note: original add expects ints but without decoration it will still run and may error;
        # we assert that calling with wrong type does not raise ValidationError specifically.
        try:
            mod_a.add("x", "y")
        except ValidationError:
            self.fail("dry_run mutated module; ValidationError raised unexpectedly")

    def test_auto_register_types_and_post_validate_hook(self):
        # Ensure registry is clean for our test types
        # Unregister any names that might collide
        # (best-effort cleanup)
        try:
            types_registry.unregister_type(f"{self.pkg_name}.mod_a.UserModel")
        except Exception:
            pass

        result = autovalidate_package(
            package=self.pkg_name,
            include=[f"{self.pkg_name}.*"],
            dry_run=False,
            auto_register_types=True,
            default_type_name_patterns=["*Model"],
            post_type_validate=True,
        )

        # registered_types should include UserModel
        registered = result["registered_types"]
        self.assertTrue(
            any("UserModel" in name for name in registered),
            msg=f"expected UserModel in registered types, got {registered}",
        )

        # Now test that the registered checker enforces class validate:
        mod_a = importlib.import_module(f"{self.pkg_name}.mod_a")
        UserModel = mod_a.UserModel

        # Create an instance that fails validate (empty name)
        bad = UserModel(name="")

        # The registered checker is used when a function expects UserModel; create a small function
        def takes_user(u: UserModel) -> str:
            return u.name

        # Put function into a temporary module and run autovalidate on it
        temp_mod = types.ModuleType("temp_mod_for_user")
        temp_mod.takes_user = takes_user
        sys.modules["temp_mod_for_user"] = temp_mod

        try:
            # Decorate the temp module function with the same registry in effect
            from validatedata import autovalidate

            autovalidate(module=temp_mod, type_checkers=None, raise_exceptions=True)

            # Calling with bad instance should raise ValidationError because validate returns False
            with self.assertRaises(ValidationError):
                temp_mod.takes_user(bad)

            # Good instance passes
            good = UserModel(name="Alice")
            self.assertEqual(temp_mod.takes_user(good), "Alice")
        finally:
            del sys.modules["temp_mod_for_user"]

    def test_include_exclude_glob_and_regex(self):
        # Use include to only target mod_a, and exclude to skip mod_a.add by full name regex
        include = [f"{self.pkg_name}.mod_a"]
        import re

        exclude = [re.compile(rf"{self.pkg_name}\.mod_a\.add$")]

        result = autovalidate_package(
            package=self.pkg_name,
            include=include,
            exclude=exclude,
            dry_run=True,
        )

        # mod_a.add should be excluded, but mod_a (module) may still be scanned
        self.assertFalse(
            any(name.endswith(".mod_a.add") for name in result["decorated"])
        )
        # mod_a should appear in skipped reasons for the add function
        self.assertTrue(
            any("mod_a.add" in name or "mod_a" in name for name, _ in result["skipped"])
        )

    def test_import_errors_reported_but_do_not_stop_run(self):
        # Run with include that will attempt to import badmod
        result = autovalidate_package(
            package=self.pkg_name,
            include=[f"{self.pkg_name}.*"],
            dry_run=True,
        )

        # badmod import error should be present
        self.assertTrue(any("badmod" in mod for mod, _ in result["import_errors"]))

        # Other modules should still be processed
        self.assertIn(f"{self.pkg_name}.mod_a.add", result["decorated"])

    def test_custom_type_checker_passed_through(self):
        # Create a function that expects Decimal and place it in a temp module
        temp_mod = types.ModuleType("temp_mod_decimal")

        def price_total(p: Decimal) -> Decimal:
            return p

        temp_mod.price_total = price_total
        sys.modules["temp_mod_decimal"] = temp_mod

        try:
            # Provide a custom checker for Decimal
            def is_decimal(v):
                return isinstance(v, Decimal)

            from validatedata import autovalidate

            autovalidate(module=temp_mod, type_checkers={Decimal: is_decimal})

            # Good call
            self.assertEqual(temp_mod.price_total(Decimal("1.23")), Decimal("1.23"))
            # Bad call should raise ValidationError
            with self.assertRaises(ValidationError):
                temp_mod.price_total(1.23)
        finally:
            del sys.modules["temp_mod_decimal"]


if __name__ == "__main__":
    unittest.main()

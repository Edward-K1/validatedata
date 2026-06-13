# test_autovalidate.py
import sys
import types
import unittest
from decimal import Decimal
from unittest.mock import patch

from validatedata import autovalidate, ValidationError


class TestAutovalidate(unittest.TestCase):

    def setUp(self):
        # Create a fresh module for each test
        self.test_module = types.ModuleType("test_module")
        sys.modules["test_module"] = self.test_module

    def tearDown(self):
        # Clean up the temporary module
        if "test_module" in sys.modules:
            del sys.modules["test_module"]

    def test_decorates_function_with_hints(self):
        # Define a function with hints in the test module
        def add(a: int, b: int) -> int:
            return a + b
        self.test_module.add = add

        autovalidate(module=self.test_module)

        # Should raise ValidationError on bad input
        with self.assertRaises(ValidationError):
            self.test_module.add(2, "three")
        # Should work normally on good input
        self.assertEqual(self.test_module.add(2, 3), 5)

    def test_ignores_function_without_hints(self):
        # Function without type hints – body works for int+str concatenation
        def no_hints(x, y):
            return str(x) + str(y)
        self.test_module.no_hints = no_hints

        autovalidate(module=self.test_module, dry_run=True)
   
        # No hints, so no validation – should not raise and return correct string
        self.assertEqual(self.test_module.no_hints(2, "three"), "2three")

    def test_ignore_list_exact_name(self):
        def vulnerable(a: int) -> int:
            return a * 2
        self.test_module.vulnerable = vulnerable

        autovalidate(module=self.test_module, ignore=["test_module.vulnerable"])

        # Should NOT be decorated, so no error on bad input
        self.assertEqual(self.test_module.vulnerable("bad"), "badbad")

    def test_ignore_list_regex(self):
        import re
        # Function with hint but ignored via regex pattern
        def internal_func(x: int):
            return str(x) + "1"
        self.test_module._internal_func = internal_func

        autovalidate(module=self.test_module, ignore=[re.compile(r"_internal")])

        # Should be ignored – original function works with string
        self.assertEqual(self.test_module._internal_func("bad"), "bad1")

    def test_instance_method(self):
        class Greeter:
            def greet(self, name: str) -> str:
                return f"Hello {name}"
        self.test_module.Greeter = Greeter

        autovalidate(module=self.test_module)

        g = self.test_module.Greeter()
        self.assertEqual(g.greet("Alice"), "Hello Alice")
        with self.assertRaises(ValidationError):
            g.greet(123)

    def test_class_method(self):
        class Math:
            @classmethod
            def double(cls, x: int) -> int:
                return x * 2
        self.test_module.Math = Math

        autovalidate(module=self.test_module)

        self.assertEqual(self.test_module.Math.double(5), 10)
        with self.assertRaises(ValidationError):
            self.test_module.Math.double("five")

    def test_static_method(self):
        class Utils:
            @staticmethod
            def concat(a: str, b: str) -> str:
                return a + b
        self.test_module.Utils = Utils

        autovalidate(module=self.test_module)

        self.assertEqual(self.test_module.Utils.concat("ab", "cd"), "abcd")
        with self.assertRaises(ValidationError):
            self.test_module.Utils.concat(1, 2)

    def test_custom_type_checker(self):
        def is_decimal(v):
            return isinstance(v, Decimal)

        def multiply(price: Decimal, tax: Decimal) -> Decimal:
            return price * (Decimal('1') + tax)

        self.test_module.multiply = multiply

        autovalidate(
            module=self.test_module,
            type_checkers={Decimal: is_decimal}
        )

        good = multiply(Decimal('100'), Decimal('0.2'))
        self.assertEqual(good, Decimal('120'))
        with self.assertRaises(ValidationError):
            self.test_module.multiply(100, 0.2)  # not Decimal

    def test_union_type_int_or_str(self):
        from typing import Union
        def handle(value: Union[int, str]) -> str:
            return f"got {value}"
        self.test_module.handle = handle

        autovalidate(module=self.test_module)

        self.assertEqual(self.test_module.handle(42), "got 42")
        self.assertEqual(self.test_module.handle("hello"), "got hello")
        with self.assertRaises(ValidationError):
            self.test_module.handle([1, 2])

    def test_optional_type(self):
        from typing import Optional
        def show(data: Optional[str] = None) -> str:
            return data or "none"
        self.test_module.show = show

        autovalidate(module=self.test_module)

        self.assertEqual(self.test_module.show(None), "none")
        self.assertEqual(self.test_module.show("hello"), "hello")
        with self.assertRaises(ValidationError):
            self.test_module.show(123)

    def test_async_function(self):
        import asyncio
        async def fetch(uid: int) -> str:
            return f"user_{uid}"
        self.test_module.fetch = fetch

        autovalidate(module=self.test_module)

        async def run():
            self.assertEqual(await self.test_module.fetch(42), "user_42")
            with self.assertRaises(ValidationError):
                await self.test_module.fetch("not-int")

        asyncio.run(run())

    def test_module_name_string(self):
        # Test passing module name as string
        mod_name = "test_module_string"
        mod = types.ModuleType(mod_name)
        sys.modules[mod_name] = mod

        def square(x: int) -> int:
            return x * x
        mod.square = square

        autovalidate(module=mod_name)

        with self.assertRaises(ValidationError):
            mod.square("bad")

        del sys.modules[mod_name]

    def test_default_caller_module(self):
        # Define a function in the current module (the test module)
        def local_func(a: int) -> int:
            return a + 1

        current_module = sys.modules[__name__]
        original_func = getattr(current_module, "local_func", None)
        setattr(current_module, "local_func", local_func)

        try:
            autovalidate()  # should apply to this module
            # Call the function via the module attribute (now decorated)
            with self.assertRaises(ValidationError):
                current_module.local_func("bad")
        finally:
            # Restore
            if original_func is not None:
                setattr(current_module, "local_func", original_func)
            else:
                delattr(current_module, "local_func")

    def test_inherited_methods_keep_decorator(self):
        class Parent:
            def method(self, x: int) -> int:
                return x

        class Child(Parent):
            pass

        self.test_module.Parent = Parent
        self.test_module.Child = Child

        autovalidate(module=self.test_module)

        # Parent method should be decorated
        p = Parent()
        with self.assertRaises(ValidationError):
            p.method("bad")

        # Child inherits the same decorated method
        c = Child()
        with self.assertRaises(ValidationError):
            c.method("bad")

    def test_raises_on_nonexistent_module(self):
        with self.assertRaises(KeyError):
            autovalidate(module="does_not_exist")


if __name__ == "__main__":
    unittest.main()
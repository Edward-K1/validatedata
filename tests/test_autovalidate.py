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

    # ------------------------------------------------------------------
    # decorator= tests
    # ------------------------------------------------------------------

    def test_custom_decorator_replaces_validate_types(self):
        """A custom decorator is applied instead of validate_types."""
        calls = []

        def tracking_decorator(fn):
            def wrapper(*args, **kwargs):
                calls.append(args)
                return fn(*args, **kwargs)
            return wrapper

        def greet(name: str) -> str:
            return f"hi {name}"

        self.test_module.greet = greet
        autovalidate(module=self.test_module, decorator=tracking_decorator)

        result = self.test_module.greet("Alice")
        self.assertEqual(result, "hi Alice")
        # The tracking wrapper should have been called
        self.assertEqual(len(calls), 1)

    def test_custom_decorator_receives_unannotated_functions_unchanged(self):
        """Functions without annotations are still skipped even with a custom decorator."""
        applied_to = []

        def spy_decorator(fn):
            applied_to.append(fn.__name__)
            return fn

        def no_hints(x, y):
            return x + y

        self.test_module.no_hints = no_hints
        autovalidate(module=self.test_module, decorator=spy_decorator)

        # no_hints has no annotations; the decorator must not have been applied
        self.assertNotIn("no_hints", applied_to)

    def test_custom_decorator_applied_to_instance_method(self):
        """Custom decorator wraps instance methods on classes."""
        wrapped = []

        def marking_decorator(fn):
            def wrapper(*args, **kwargs):
                wrapped.append(fn.__name__)
                return fn(*args, **kwargs)
            return wrapper

        class Counter:
            def increment(self, value: int) -> int:
                return value + 1

        self.test_module.Counter = Counter
        autovalidate(module=self.test_module, decorator=marking_decorator)

        c = self.test_module.Counter()
        self.assertEqual(c.increment(4), 5)
        self.assertIn("increment", wrapped)

    def test_custom_decorator_applied_to_classmethod(self):
        """Custom decorator wraps classmethods."""
        wrapped = []

        def marking_decorator(fn):
            def wrapper(*args, **kwargs):
                wrapped.append(fn.__name__)
                return fn(*args, **kwargs)
            return wrapper

        class Factory:
            @classmethod
            def create(cls, n: int):
                return n * 10

        self.test_module.Factory = Factory
        autovalidate(module=self.test_module, decorator=marking_decorator)

        result = self.test_module.Factory.create(3)
        self.assertEqual(result, 30)
        self.assertIn("create", wrapped)

    def test_custom_decorator_applied_to_staticmethod(self):
        """Custom decorator wraps staticmethods."""
        wrapped = []

        def marking_decorator(fn):
            def wrapper(*args, **kwargs):
                wrapped.append(fn.__name__)
                return fn(*args, **kwargs)
            return wrapper

        class Util:
            @staticmethod
            def double(n: int) -> int:
                return n * 2

        self.test_module.Util = Util
        autovalidate(module=self.test_module, decorator=marking_decorator)

        result = self.test_module.Util.double(7)
        self.assertEqual(result, 14)
        self.assertIn("double", wrapped)

    def test_custom_decorator_type_checkers_and_raise_exceptions_ignored(self):
        """When decorator= is supplied, type_checkers and raise_exceptions have no effect —
        only the custom decorator's own logic applies."""

        def passthrough_decorator(fn):
            # Does zero validation; simply calls the function
            def wrapper(*args, **kwargs):
                return fn(*args, **kwargs)
            return wrapper

        def typed_fn(x: int) -> int:
            return x

        self.test_module.typed_fn = typed_fn
        autovalidate(
            module=self.test_module,
            decorator=passthrough_decorator,
            raise_exceptions=True,   # would normally raise on bad input
            type_checkers={int: lambda v: isinstance(v, int)},
        )

        # The passthrough bypasses all validation, so a bad call must NOT raise
        result = self.test_module.typed_fn("not-an-int")
        self.assertEqual(result, "not-an-int")

    def test_custom_decorator_non_callable_raises_type_error(self):
        """Passing a non-callable as decorator raises TypeError."""
        def fn(x: int) -> int:
            return x

        self.test_module.fn = fn

        with self.assertRaises(TypeError):
            autovalidate(module=self.test_module, decorator="not_a_function")

    def test_custom_decorator_dry_run_does_not_call_decorator(self):
        """dry_run=True with a custom decorator must not invoke the decorator."""
        applied = []

        def spy(fn):
            applied.append(fn.__name__)
            return fn

        def typed(x: int) -> int:
            return x

        self.test_module.typed = typed
        result = autovalidate(module=self.test_module, decorator=spy, dry_run=True)

        # The name should be reported as a candidate ...
        self.assertIn("test_module.typed", result)
        # ... but the decorator itself must not have been called
        self.assertEqual(applied, [])

    def test_custom_decorator_ignored_names_not_decorated(self):
        """Functions on the ignore list are not passed to the custom decorator."""
        applied = []

        def spy(fn):
            applied.append(fn.__name__)
            return fn

        def secret(x: int) -> int:
            return x

        self.test_module.secret = secret
        autovalidate(
            module=self.test_module,
            decorator=spy,
            ignore=["test_module.secret"],
        )

        self.assertNotIn("secret", applied)

    # ------------------------------------------------------------------
    # enforce_hints= tests
    # ------------------------------------------------------------------

    def test_enforce_hints_raises_for_unannotated_function(self):
        """enforce_hints=True raises TypeError when an eligible function has no annotations."""
        def no_hints(x, y):
            return x + y

        self.test_module.no_hints = no_hints

        with self.assertRaises(TypeError) as ctx:
            autovalidate(module=self.test_module, enforce_hints=True)

        self.assertIn("no_hints", str(ctx.exception))
        self.assertIn("enforce_hints", str(ctx.exception))

    def test_enforce_hints_passes_when_all_functions_annotated(self):
        """enforce_hints=True succeeds silently when every eligible function is annotated."""
        def add(a: int, b: int) -> int:
            return a + b

        def mul(a: int, b: int) -> int:
            return a * b

        self.test_module.add = add
        self.test_module.mul = mul

        # Should not raise
        decorated = autovalidate(module=self.test_module, enforce_hints=True)

        self.assertIn("test_module.add", decorated)
        self.assertIn("test_module.mul", decorated)

    def test_enforce_hints_error_message_names_function(self):
        """The TypeError message includes the fully-qualified function name."""
        def calculate(x, y):
            return x - y

        self.test_module.calculate = calculate

        with self.assertRaises(TypeError) as ctx:
            autovalidate(module=self.test_module, enforce_hints=True)

        self.assertIn("test_module.calculate", str(ctx.exception))

    def test_enforce_hints_ignored_functions_exempt_from_check(self):
        """Functions on the ignore list are not subject to enforce_hints."""
        def no_hints(x, y):
            return x + y

        def has_hints(a: int) -> int:
            return a

        self.test_module.no_hints = no_hints
        self.test_module.has_hints = has_hints

        # no_hints is ignored, so enforce_hints must not raise for it
        decorated = autovalidate(
            module=self.test_module,
            enforce_hints=True,
            ignore=["test_module.no_hints"],
        )

        self.assertIn("test_module.has_hints", decorated)

    def test_enforce_hints_unannotated_method_raises(self):
        """enforce_hints=True triggers for unannotated instance methods."""
        class Processor:
            def run(self, x, y):   # no annotations
                return x + y

        self.test_module.Processor = Processor

        with self.assertRaises(TypeError) as ctx:
            autovalidate(module=self.test_module, enforce_hints=True)

        self.assertIn("run", str(ctx.exception))

    def test_enforce_hints_false_is_default_behaviour(self):
        """enforce_hints defaults to False; unannotated functions are silently skipped."""
        def no_hints(x, y):
            return x + y

        self.test_module.no_hints = no_hints

        # Must not raise, and the unannotated function must not appear in the returned list
        decorated = autovalidate(module=self.test_module)
        self.assertNotIn("test_module.no_hints", decorated)

    def test_enforce_hints_dry_run_still_raises(self):
        """enforce_hints=True combined with dry_run=True still raises before any mutation."""
        def no_hints(x, y):
            return x + y

        self.test_module.no_hints = no_hints

        with self.assertRaises(TypeError):
            autovalidate(module=self.test_module, enforce_hints=True, dry_run=True)

        # Confirm the module was not mutated (original function still in place)
        self.assertIs(self.test_module.no_hints, no_hints)

    def test_enforce_hints_with_custom_decorator_still_raises(self):
        """enforce_hints= interacts with decorator=: missing annotations still raise."""
        def passthrough(fn):
            return fn

        def no_hints(x, y):
            return x + y

        self.test_module.no_hints = no_hints

        with self.assertRaises(TypeError):
            autovalidate(
                module=self.test_module,
                decorator=passthrough,
                enforce_hints=True,
            )


if __name__ == "__main__":
    unittest.main()
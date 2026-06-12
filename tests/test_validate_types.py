"""
Unit tests for the fixed `validate_types` decorator.

Tests cover:
- Correct argument mapping (positional, keyword, defaults)
- Union types (`int | str`, `Optional`, `Union`)
- Methods (instance, class, static)
- Async functions
- `*args` and `**kwargs` (ignored)
- Signature mismatch handling
- Return type annotation ignored
- `raise_exceptions=False` behaviour
"""

import sys
import unittest
from typing import Union, Optional

from validatedata.validatedata import validate_types
from validatedata import ValidationError


# ---------------------------------------------------------------------------
# Helper to conditionally run async tests
# ---------------------------------------------------------------------------

if sys.version_info >= (3, 8):
    from unittest import IsolatedAsyncioTestCase as AsyncTestCase
else:
    AsyncTestCase = object  # fallback, tests will be skipped


# ---------------------------------------------------------------------------
# Sync tests
# ---------------------------------------------------------------------------

class TestValidateTypesFixed(unittest.TestCase):

    def test_positional_args(self):
        @validate_types
        def add(a: int, b: int) -> int:
            return a + b

        self.assertEqual(add(2, 3), 5)
        with self.assertRaises(ValidationError):
            add(2, "three")

    def test_keyword_args(self):
        @validate_types
        def greet(name: str, age: int) -> str:
            return f"{name} is {age}"

        self.assertEqual(greet(name="Alice", age=30), "Alice is 30")
        with self.assertRaises(ValidationError):
            greet(name="Bob", age="thirty")

    def test_default_values(self):
        @validate_types
        def repeat(msg: str, count: int = 3) -> str:
            return msg * count

        self.assertEqual(repeat("ha", 2), "haha")
        # Default count=3 → "ho" * 3 = "hohoho"
        self.assertEqual(repeat("ho"), "hohoho")
        with self.assertRaises(ValidationError):
            repeat("bad", "not-int")

    def test_mixed_positional_keyword(self):
        @validate_types
        def product(x: int, y: int, scale: int = 1) -> int:
            return x * y * scale

        self.assertEqual(product(2, 3), 6)
        self.assertEqual(product(2, 3, scale=10), 60)
        self.assertEqual(product(2, y=4), 8)

    def test_union_type_int_or_str(self):
        @validate_types
        def handle(value: int | str) -> str:
            return f"got {value}"

        self.assertEqual(handle(42), "got 42")
        self.assertEqual(handle("hello"), "got hello")
        with self.assertRaises(ValidationError):
            handle([1, 2])  # list not allowed

    def test_union_using_typing_union(self):
        @validate_types
        def process(value: Union[float, str]) -> str:
            return f"processed {value}"

        self.assertEqual(process(3.14), "processed 3.14")
        self.assertEqual(process("text"), "processed text")
        with self.assertRaises(ValidationError):
            process(True)

    def test_optional_type(self):
        @validate_types
        def show(data: Optional[str] = None) -> str:
            return data or "none"

        self.assertEqual(show(None), "none")
        self.assertEqual(show("hello"), "hello")
        with self.assertRaises(ValidationError):
            show(123)

    def test_instance_method(self):
        class Greeter:
            @validate_types
            def greet(self, name: str, loud: bool = False) -> str:
                msg = f"Hello {name}"
                return msg.upper() if loud else msg

        g = Greeter()
        self.assertEqual(g.greet("world"), "Hello world")
        self.assertEqual(g.greet("world", loud=True), "HELLO WORLD")
        with self.assertRaises(ValidationError):
            g.greet(123)

    def test_class_method(self):
        class Math:
            @classmethod
            @validate_types
            def multiply(cls, a: int, b: int) -> int:
                return a * b

        self.assertEqual(Math.multiply(3, 4), 12)
        with self.assertRaises(ValidationError):
            Math.multiply(3, "four")

    def test_static_method(self):
        class Utils:
            @staticmethod
            @validate_types
            def concat(a: str, b: str) -> str:
                return a + b

        self.assertEqual(Utils.concat("ab", "cd"), "abcd")
        with self.assertRaises(ValidationError):
            Utils.concat(1, 2)

    def test_raise_exceptions_false_returns_error_dict(self):
        @validate_types(raise_exceptions=False)
        def safe_add(a: int, b: int) -> int:
            return a + b

        result = safe_add(2, "three")
        self.assertIsInstance(result, dict)
        self.assertIn("errors", result)
        self.assertEqual(result["errors"][0], "Expected type int for 'b', got str")

        # When valid, returns normal result
        self.assertEqual(safe_add(2, 3), 5)

    def test_return_annotation_ignored(self):
        """Return type annotation should not be enforced."""
        @validate_types
        def double(x: int) -> str:   # returns int, but annotation says str
            return x * 2

        # Should not raise because return annotation is ignored
        self.assertEqual(double(5), 10)

    def test_args_ignored(self):
        @validate_types
        def variadic(*args, **kwargs) -> int:
            return len(args) + len(kwargs)

        # Should not raise despite args/kwargs not being typed
        self.assertEqual(variadic(1, 2, 3, a=4, b=5), 5)

    def test_signature_mismatch_handling(self):
        @validate_types
        def required_two(a: int, b: int) -> int:
            return a + b

        # Too few arguments
        with self.assertRaises(ValidationError) as ctx:
            required_two(1)
        self.assertIn("missing a required argument", str(ctx.exception))

        # Too many arguments
        with self.assertRaises(ValidationError) as ctx:
            required_two(1, 2, 3)
        # Python's error message for too many positional arguments
        self.assertIn("too many positional arguments", str(ctx.exception))

        # With raise_exceptions=False, returns error dict
        @validate_types(raise_exceptions=False)
        def safe_two(a: int, b: int) -> int:
            return a + b

        result = safe_two(1)
        self.assertIn("errors", result)
        self.assertIn("missing", result["errors"][0])

    def test_decorator_no_parentheses(self):
        """@validate_types (bare) should work identically."""
        @validate_types
        def square(x: int) -> int:
            return x * x

        self.assertEqual(square(4), 16)
        with self.assertRaises(ValidationError):
            square("four")

    def test_method_with_self_typing(self):
        """The 'self' parameter may be unannotated; should be ignored."""
        class Demo:
            @validate_types
            def update(self, value: int) -> int:
                return value + 1

        d = Demo()
        self.assertEqual(d.update(5), 6)
        with self.assertRaises(ValidationError):
            d.update("not-int")

    def test_multiple_decorators(self):
        """validate_types should compose with other decorators (e.g., @staticmethod)."""
        class Calc:
            @staticmethod
            @validate_types
            def power(base: int, exp: int) -> int:
                return base ** exp

        self.assertEqual(Calc.power(2, 3), 8)
        with self.assertRaises(ValidationError):
            Calc.power(2, "three")


# ---------------------------------------------------------------------------
# Async tests
# ---------------------------------------------------------------------------

if sys.version_info >= (3, 8):

    class TestAsyncValidateTypesFixed(AsyncTestCase):

        async def test_async_function_valid(self):
            @validate_types
            async def fetch(uid: int) -> str:
                return f"user_{uid}"

            result = await fetch(42)
            self.assertEqual(result, "user_42")

        async def test_async_function_invalid(self):
            @validate_types
            async def fetch(uid: int) -> str:
                return f"user_{uid}"

            with self.assertRaises(ValidationError):
                await fetch("not-int")

        async def test_async_method(self):
            class Service:
                @validate_types
                async def get(self, name: str, age: int) -> dict:
                    return {"name": name, "age": age}

            s = Service()
            result = await s.get("Alice", 30)
            self.assertEqual(result, {"name": "Alice", "age": 30})

            with self.assertRaises(ValidationError):
                await s.get("Bob", "thirty")

        async def test_async_raise_false(self):
            @validate_types(raise_exceptions=False)
            async def safe_fetch(uid: int) -> str:
                return f"user_{uid}"

            result = await safe_fetch("bad")
            self.assertIn("errors", result)

        async def test_async_no_parentheses(self):
            @validate_types
            async def echo(msg: str) -> str:
                return msg

            self.assertEqual(await echo("hi"), "hi")
            with self.assertRaises(ValidationError):
                await echo(123)


# ---------------------------------------------------------------------------
# Run tests if executed directly
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    unittest.main()
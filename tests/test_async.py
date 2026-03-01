"""
Tests for async support in @validate and @validate_types.

Uses unittest.IsolatedAsyncioTestCase (stdlib, Python 3.8+) so this file
integrates with the existing test suite without any extra dependencies.

"""

import unittest
from inspect import iscoroutinefunction

from validatedata.validatedata import validate, validate_types
from validatedata.validator import ValidationError
from .base import BaseTest


# ---------------------------------------------------------------------------
# Ensure existing sync behaviour is unaffected
# ---------------------------------------------------------------------------

class TestSyncValidate(BaseTest):

    def test_valid_input(self):
        class Shop:
            @validate(({'type': 'int'},))
            def buy(self, quantity):
                return quantity * 100

        self.assertEqual(Shop().buy(3), 300)

    def test_invalid_input_returns_errors(self):
        class Shop:
            @validate(({'type': 'int'},))
            def buy(self, quantity):
                return quantity * 100

        result = Shop().buy('lots')
        self.assertIn('errors', result)

    def test_wrapper_is_not_coroutine(self):
        class Shop:
            @validate(({'type': 'int'},))
            def buy(self, quantity):
                return quantity * 100

        self.assertFalse(iscoroutinefunction(Shop.buy))


class TestSyncValidateTypes(BaseTest):

    def test_valid_input(self):
        @validate_types
        def add(x: int, y: int):
            return x + y

        self.assertEqual(add(2, 3), 5)

    def test_invalid_input_raises(self):
        @validate_types
        def add(x: int, y: int):
            return x + y

        with self.assertRaises(ValidationError):
            add(2, 'three')

    def test_raise_false_returns_errors(self):
        @validate_types(raise_exceptions=False)
        def add(x: int, y: int):
            return x + y

        result = add(2, 'three')
        self.assertIn('errors', result)

    def test_wrapper_is_not_coroutine(self):
        @validate_types
        def add(x: int, y: int):
            return x + y

        self.assertFalse(iscoroutinefunction(add))


# ---------------------------------------------------------------------------
# Async — @validate on async functions and class methods
# ---------------------------------------------------------------------------

class TestAsyncValidate(unittest.IsolatedAsyncioTestCase):

    async def test_valid_input(self):
        class UserService:
            @validate([{'type': 'str'}, {'type': 'int', 'range': (0, 120)}])
            async def create(self, name, age):
                return f'created {name} age {age}'

        result = await UserService().create('alice', 30)
        self.assertEqual(result, 'created alice age 30')

    async def test_invalid_type_returns_errors(self):
        class UserService:
            @validate([{'type': 'str'}, {'type': 'int', 'range': (0, 120)}])
            async def create(self, name, age):
                return f'created {name} age {age}'

        result = await UserService().create('alice', 'not-a-number')
        self.assertIn('errors', result)

    async def test_out_of_range_returns_errors(self):
        class UserService:
            @validate([{'type': 'str'}, {'type': 'int', 'range': (0, 120)}])
            async def create(self, name, age):
                return f'created {name} age {age}'

        result = await UserService().create('alice', 200)
        self.assertIn('errors', result)

    async def test_raise_exceptions_true_raises(self):
        @validate([{'type': 'email'}], raise_exceptions=True)
        async def send(email):
            return f'sent to {email}'

        with self.assertRaises(ValidationError):
            await send('not-an-email')

    def test_wrapper_is_coroutine(self):
        @validate([{'type': 'str'}])
        async def fn(name):
            pass

        self.assertTrue(iscoroutinefunction(fn))


# ---------------------------------------------------------------------------
# Async — @validate_types on async functions and class methods
# ---------------------------------------------------------------------------

class TestAsyncValidateTypes(unittest.IsolatedAsyncioTestCase):

    async def test_valid_input(self):
        class Greeter:
            @validate_types
            async def greet(self, name: str, count: int) -> str:
                return f'{name} x{count}'

        result = await Greeter().greet('bob', 3)
        self.assertEqual(result, 'bob x3')

    async def test_invalid_type_raises_by_default(self):
        class Greeter:
            @validate_types
            async def greet(self, name: str, count: int) -> str:
                return f'{name} x{count}'

        with self.assertRaises(ValidationError):
            await Greeter().greet('bob', 'three')

    async def test_raise_false_returns_errors(self):
        class Greeter:
            @validate_types(raise_exceptions=False)
            async def greet(self, name: str, count: int) -> str:
                return f'{name} x{count}'

        result = await Greeter().greet('bob', 'three')
        self.assertIn('errors', result)

    async def test_return_annotation_is_ignored(self):
        """Return type annotation must not be treated as a parameter rule."""
        @validate_types
        async def double(n: int) -> int:
            return n * 2

        result = await double(5)
        self.assertEqual(result, 10)

    def test_wrapper_is_coroutine(self):
        @validate_types
        async def fn(name: str):
            pass

        self.assertTrue(iscoroutinefunction(fn))

    def test_bare_decorator_wrapper_is_coroutine(self):
        """@validate_types without brackets should still produce an async wrapper."""
        @validate_types
        async def fn(name: str):
            pass

        self.assertTrue(iscoroutinefunction(fn))

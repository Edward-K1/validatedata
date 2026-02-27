from collections import OrderedDict
from validatedata.validatedata import (
    validate,
    validate_data,
    expand_rule,
    validate_types,
)
from validatedata.validator import ValidationError
from validatedata.messages import error_messages
from .base import BaseTest


class TestCore(BaseTest):

    def test_decorator_on_function(self):
        @validate(self.buy_qty_rule)
        def buy(quantity):
            return quantity * 500

        self.assertEqual(buy(1), 500)

        # invalid input returns error dict, not raises
        result = buy('not-an-int')
        self.assertIn('errors', result)

    def test_decorator_on_class(self):
        class Shop:
            @validate(self.buy_qty_rule)
            def buy(self, quantity):
                return quantity * 100

            @classmethod
            @validate(self.total_stock_rule, is_class=True)
            def count_stock(cls, item):
                stock = {'cups': 5, 'plates': 10}
                return stock[item]

        shop = Shop()
        self.assertEqual(shop.buy(1), 100)
        self.assertEqual(shop.count_stock('cups'), 5)

        # invalid input returns error dict
        result = shop.buy('bad')
        self.assertIn('errors', result)

    def test_validate_data_function(self):
        result = validate_data(self.user_data, self.user_data_dict_rule)
        self.assertTrue(result.ok)

    def test_validate_data_failure(self):
        bad_data = {
            'firstname': 'x',  # too short (range 2-50)
            'lastname': 'Hollens',
            'email': 'not-an-email',
            'age': 15,  # under 18
        }
        result = validate_data(bad_data, self.user_data_dict_rule)
        self.assertFalse(result.ok)

    def test_expand_rule(self):
        expanded_str_rule = expand_rule(self.str_with_len_rule)
        expanded_int_rule = expand_rule(self.compressed_int_rule)
        expanded_dict = expand_rule(self.sample_dict_rule)

        self.assertEqual(expanded_str_rule, self.expanded_str_with_len_rule)
        self.assertEqual(expanded_int_rule, self.expanded_int_rule)
        self.assertEqual(expanded_dict, self.sample_dict_rule)

    def test_expand_rule_invalid_type_raises(self):
        with self.assertRaises(TypeError):
            expand_rule('notavalidtype')

    def test_expand_rule_too_short_raises(self):
        with self.assertRaises(ValueError):
            expand_rule('ab')

    def test_type_decorator(self):
        class User:
            @validate_types()
            def buy(self, item: str, qty: int, price: int):
                return OrderedDict({'item': item, 'qty': qty, 'price': price})

            @validate_types(is_class=True)
            def buy_again(klass, item: str, qty: int, price: int):
                return OrderedDict({'item': item, 'qty': qty, 'price': price})

        @validate_types()
        def add(num1: int, num2: int):
            return num1 + num2

        user = User()
        expected = OrderedDict({'item': 'bread', 'qty': 1, 'price': 4000})

        self.assertEqual(user.buy('bread', 1, 4000), expected)
        self.assertEqual(user.buy_again('bread', 1, 4000), expected)
        self.assertEqual(add(4, 6), 10)

        # invalid type should raise ValidationError (raise_exceptions defaults True)
        with self.assertRaises(ValidationError) as ctx:
            user.buy([89], 1, 4000)
        self.assertIn('str', str(ctx.exception))

    def test_type_decorator_bare(self):
        """@validate_types without parentheses should work."""

        @validate_types
        def greet(name: str):
            return f'hello {name}'

        self.assertEqual(greet('world'), 'hello world')

        with self.assertRaises(ValidationError):
            greet(123)

    def test_type_decorator_return_annotation_ignored(self):
        """Return type annotations must not be treated as a parameter rule."""

        @validate_types()
        def double(n: int) -> int:
            return n * 2

        # Should not raise or error — return annotation must be filtered out
        self.assertEqual(double(5), 10)

    def test_type_decorator_raises_false(self):
        """With raise_exceptions=False, validation failure returns an error dict."""

        @validate_types(raise_exceptions=False)
        def square(n: int) -> int:
            return n * n

        result = square('not-an-int')
        self.assertIsInstance(result, dict)
        self.assertIn('errors', result)

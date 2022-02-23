from typing import OrderedDict
from unittest import result
from validatedata.validatedata import validate, validate_data, expand_rule, validate_types
from validatedata.validator import ValidationError
from .base import BaseTest


class TestCore(BaseTest):
    def test_decorator_on_function(self):
        @validate(self.buy_qty_rule)
        def buy(quantity):
            return quantity * 500

        cost = buy(1)
        self.assertEqual(cost, 500)

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
        cost = shop.buy(1)
        total_stock = shop.count_stock('cups')

        self.assertEqual(cost, 100)
        self.assertEqual(total_stock, 5)

    def test_validate_data_function(self):
        result = validate_data(self.user_data, self.user_data_dict_rule)
        self.assertEqual(result.ok, True)

    def test_expand_rule(self):
        expanded_str_rule = expand_rule(self.str_with_len_rule)
        expanded_int_rule = expand_rule(self.compressed_int_rule)
        expanded_dict = expand_rule(self.sample_dict_rule)

        self.assertEqual(expanded_str_rule, self.expanded_str_with_len_rule)
        self.assertEqual(expanded_int_rule, self.expanded_int_rule)
        self.assertEqual(expanded_dict, self.sample_dict_rule)



    def test_type_decorator(self):

        class User:

            @validate_types()
            def buy(self, item:str, qty:int, price:int):
                return OrderedDict({'item':item, 'qty':qty, 'price':price})

            @validate_types(is_class=True)
            def buy_again(klass, item:str, qty:int, price:int):
                return OrderedDict({'item':item, 'qty':qty, 'price':price})

        @validate_types()
        def sum(num1:int, num2:int):
            return num1 + num2
        
        user = User()
        result1 = user.buy('bread', 1, 4000)
        result2 = user.buy_again('bread', 1, 4000)
        
        expected_result = OrderedDict({'item':'bread', 'qty':1, 'price':4000})
        self.assertEqual(result1, expected_result)
        self.assertEqual(result2, expected_result)

        with self.assertRaises(ValidationError) as err:
            result3 = user.buy([89], 1, 4000)

        result4 = sum(4, 6)
        self.assertEqual(result4, 10)





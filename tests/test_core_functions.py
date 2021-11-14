from validatedata.validatedata import validate, validate_data, expand_rule
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
        pass

    def test_expand_rule(self):
        pass
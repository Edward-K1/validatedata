import unittest


class BaseTest(unittest.TestCase):
    def setUp(self):
        self.buy_qty_rule = ({'type': 'int'})
        self.total_stock_rule = 'str'

    def tearDown(self):
        pass

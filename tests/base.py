import unittest

from collections import OrderedDict
from dateutil.parser import parse as parse_date


class BaseTest(unittest.TestCase):
    def setUp(self):

        self.bool_rule = self.get_type_dict('bool')
        self.date_rule = self.get_type_dict('date')
        self.email_rule = self.get_type_dict('email')
        self.even_rule = self.get_type_dict('even')
        self.float_rule = self.get_type_dict('float')
        self.int_rule = self.get_type_dict('int')
        self.odd_rule = self.get_type_dict('odd')
        self.str_rule = self.get_type_dict('str')
        self.dict_rule = self.get_type_dict('dict')
        self.list_rule = self.get_type_dict('list')
        self.regex_rule = self.get_type_dict('regex')
        self.set_rule = self.get_type_dict('set')
        self.tuple_rule = self.get_type_dict('tuple')

        self.all_bool_rules = [self.bool_rule]

        self.all_date_rules = [
            dict(
                self.date_rule.items() | {
                    'length': 11,
                    'range': ('any', '24-Oct-2025'),
                    'options': ('23-Oct-2000', '11-02-2019'),
                    'startswith': '23-Oct',
                    'endswith': '2000',
                    'excludes': ('02-October-2090', ),
                    'contains': 'Oct'
                }.items()),
            dict(self.date_rule.items() | {
                'range': ('28-02-1990', 'any'),
                'strict': True
            }.items()),
        ]

        self.all_email_rules = [
            self.email_rule,
            dict(
                self.email_rule.items() | {
                    'length': 16,
                    'options': ('test@example.com', 'you@me.com'),
                    'excludes': ('peter@pan.co.uk', ),
                    'startswith': 'test',
                    'endswith': '.com'
                }.items())
        ]

        self.all_even_rules = [
            self.even_rule,
            dict(
                self.even_rule.items() | {
                    'length': 5,
                    'range': ('any', 50000),
                    'options': (10000, 20000, 22000),
                    'excludes': (28000, 300000)
                }.items()),
            dict(self.even_rule.items() | {'range': (10, 'any')}.items()),
            dict(self.even_rule.items() | {'range': (40, 80)}.items())
        ]

        self.all_float_rules = [
            self.float_rule,
            dict(
                self.float_rule.items() | {
                    'range': (3.25, 200.5),
                    'options': (1.4, 6.5, 28.6, 88.8),
                    'excludes': (400.8, )
                }.items()),
            dict(self.float_rule.items() | {
                'strict': False,
                'range': ('any', 50.4)
            }.items()),
        ]

        self.all_int_rules = [
            self.int_rule,
            dict(
                self.even_rule.items() | {
                    'length': 5,
                    'range': ('any', 50000),
                    'options': (10000, 20000, 22000),
                    'excludes': (28000, 300000)
                }.items()),
            dict(self.even_rule.items() | {'range': (10, 'any')}.items()),
            dict(self.even_rule.items() | {'range': (40, 80)}.items())
        ]

        self.all_odd_rules = [
            self.odd_rule,
            dict(
                self.odd_rule.items() | {
                    'length': 5,
                    'range': ('any', 50001),
                    'options': (10001, 20001, 22011),
                    'excludes': (28001, 99999)
                }.items()),
            dict(self.odd_rule.items() | {'range': (11, 'any')}.items()),
            dict(self.odd_rule.items() | {'range': (41, 81)}.items())
        ]

        self.all_str_rules = [
            self.str_rule,
            dict(
                self.str_rule.items() | {
                    'length': 8,
                    'range': (6, 'any'),
                    'options': ('validate', 'central', 'town'),
                    'excludes': ('neo', 'bread'),
                    'startwith': 'valid',
                    'endswith': 'ate',
                    'contains': 'lid'
                }.items()),
            dict(self.str_rule.items() | {
                'expression': r'\d{8,}',
                'range': ('any', 20)
            }.items())
        ]

        self.all_dict_rules = [
            self.dict_rule,
            dict(self.dict_rule.items() | {
                'length': 3,
                'contains': ('name', 'age', 'city')
            }.items())
        ]

        self.all_list_rules = [
            self.list_rule,
            dict(
                self.list_rule.items() | {
                    'length': 4,
                    'contains': (5, 6, 9),
                    'excludes': (8, ),
                    'options': (5, 6, 7, 9, 10),
                    'startswith': 5,
                    'endswith': 10
                }.items())
        ]

        self.all_regex_rules = [
            dict(self.regex_rule.items() | {'expression': r'\w{4,}'}.items())
        ]

        self.all_set_rules = [
            self.set_rule,
            dict(
                self.set_rule.items() | {
                    'length': 3,
                    'contains': (5, 6, 9),
                    'excludes': (8, ),
                    'options': (5, 6, 7, 9, 10),
                }.items())
        ]

        self.all_tuple_rules = [
            self.tuple_rule,
            dict(
                self.tuple_rule.items() | {
                    'length': 4,
                    'contains': (5, 6, 9),
                    'excludes': (8, ),
                    'options': (5, 6, 7, 9, 10),
                    'startswith': 5,
                    'endswith': 10
                }.items())
        ]



        self.buy_qty_rule = ({'type': 'int'}, )
        self.total_stock_rule = 'str'
        self.str_with_len_rule = 'str:20'
        self.compressed_int_rule = 'int:5:to:100:msg:should be an int 5 to 100 digits long'
        self.expanded_str_with_len_rule = [{
            'type': 'str',
            'message': '',
            'length': 20
        }]
        self.sample_dict_rule = {
            'keys': {
                'email': {
                    'type': 'email'
                },
                'username': {
                    'type': 'str',
                    'range': (4, 'any')
                }
            }
        }

        self.expanded_int_rule = [{
            'type': 'int',
            'message': 'should be an int 5 to 100 digits long',
            'range': ('5', '100')
        }]

        self.user_data = {
            'firstname': 'peter',
            'lastname': 'Hollens',
            'email': 'peterhollens69@example.com',
            'age': 38
        }

        self.user_data_dict_rule = {
            'keys':
            OrderedDict({
                'firstname': {
                    'type': 'str',
                    'range': (2, 50)
                },
                'lastname': {
                    'type': 'str',
                    'range': (2, 50)
                },
                'email': {
                    'type': 'email'
                },
                'age': {
                    'type': 'int',
                    'range': (18, 'any')
                }
            })
        }
        self.user_data_list_rule = [
            {
                'type': 'str',
                'range': (2, 50)
            },
        ]


    def append_rule(self, base_rule: dict, new_rule: dict):
        return base_rule.update(new_rule)

    def get_type_dict(self, type_str):
        return {'type': type_str}

    def tearDown(self):
        pass

import unittest

from collections import OrderedDict


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
        self.object_rule = self.get_type_dict('object')
        self.url_rule = self.get_type_dict('url')
        self.ip_rule = self.get_type_dict('ip')
        self.uuid_rule = self.get_type_dict('uuid')
        self.slug_rule = self.get_type_dict('slug')
        self.semver_rule = self.get_type_dict('semver')
        self.color_rule = self.get_type_dict('color')
        self.phone_rule = self.get_type_dict('phone')
        self.prime_rule = self.get_type_dict('prime')

        self.all_bool_rules = [self.bool_rule]

        self.all_date_rules = [
            {**self.date_rule,
                'length': 11,
                'range': ('any', '24-Oct-2025'),
                'options': ('23-Oct-2000', '11-02-2019'),
                'startswith': '23-Oct',
                'endswith': '2000',
                'excludes': ('02-October-2090', ),
                'contains': 'Oct'},
            {**self.date_rule, 'range': ('28-02-1990', 'any'), 'strict': True},
        ]

        self.all_email_rules = [
            self.email_rule,
            {**self.email_rule,
                'length': 16,
                'options': ('test@example.com', 'you@me.com'),
                'excludes': ('peter@pan.co.uk', ),
                'startswith': 'test',
                'endswith': '.com'},
        ]

        self.all_even_rules = [
            self.even_rule,
            {**self.even_rule,
                'length': 5,
                'range': ('any', 50000),
                'options': (10000, 20000, 22000),
                'excludes': (28000, 300000)},
            {**self.even_rule, 'range': (10, 'any')},
            {**self.even_rule, 'range': (40, 80)},
        ]

        self.all_float_rules = [
            self.float_rule,
            {**self.float_rule,
                'range': (3.25, 200.5),
                'options': (1.4, 6.5, 28.6, 88.8),
                'excludes': (400.8, )},
            {**self.float_rule, 'strict': False, 'range': ('any', 50.4)},
        ]

        self.all_int_rules = [
            self.int_rule,
            {**self.int_rule,
                'length': 5,
                'range': ('any', 50000),
                'options': (10000, 20000, 22000),
                'excludes': (28000, 300000)},
            {**self.int_rule, 'range': (10, 'any')},
            {**self.int_rule, 'range': (40, 80)},
        ]

        self.all_odd_rules = [
            self.odd_rule,
            {**self.odd_rule,
                'length': 5,
                'range': ('any', 50001),
                'options': (10001, 20001, 22011),
                'excludes': (28001, 99999)},
            {**self.odd_rule, 'range': (11, 'any')},
            {**self.odd_rule, 'range': (41, 81)},
        ]

        self.all_str_rules = [
            self.str_rule,
            {**self.str_rule,
                'length': 8,
                'range': (6, 'any'),
                'options': ('validate', 'central', 'town'),
                'excludes': ('neo', 'bread'),
                'startswith': 'valid',
                'endswith': 'ate',
                'contains': 'lid'},
            {**self.str_rule, 'expression': r'\d{8,}', 'range': ('any', 20)},
        ]

        self.all_dict_rules = [
            self.dict_rule,
            {**self.dict_rule, 'length': 3, 'contains': ('name', 'age', 'city')},
        ]

        self.all_list_rules = [
            self.list_rule,
            {**self.list_rule,
                'length': 4,
                'contains': (5, 6, 9),
                'excludes': (8, ),
                'options': (5, 6, 7, 9, 10),
                'startswith': 5,
                'endswith': 10},
        ]

        self.all_regex_rules = [
            {**self.regex_rule, 'expression': r'\w{4,}'},
        ]

        self.all_set_rules = [
            self.set_rule,
            {**self.set_rule,
                'length': 3,
                'contains': (5, 6, 9),
                'excludes': (8, ),
                'options': (5, 6, 7, 9, 10)},
        ]

        self.all_tuple_rules = [
            self.tuple_rule,
            {**self.tuple_rule,
                'length': 4,
                'contains': (5, 6, 9),
                'excludes': (8, ),
                'options': (5, 6, 7, 9, 10),
                'startswith': 5,
                'endswith': 10},
        ]

        # --- new type rule sets ---

        self.all_url_rules = [
            self.url_rule,
            {**self.url_rule, 'startswith': 'https'},
        ]

        self.all_ip_rules = [self.ip_rule]

        self.all_uuid_rules = [self.uuid_rule]

        self.all_slug_rules = [
            self.slug_rule,
            {**self.slug_rule, 'length': 5},
        ]

        self.all_semver_rules = [self.semver_rule]

        self.all_color_rules = [
            self.color_rule,
            {**self.color_rule, 'format': 'hex'},
            {**self.color_rule, 'format': 'rgb'},
            {**self.color_rule, 'format': 'hsl'},
            {**self.color_rule, 'format': 'named'},
        ]

        self.all_phone_rules = [self.phone_rule]

        self.all_prime_rules = [self.prime_rule]

        # --- core fixture data ---

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
                'email': {'type': 'email'},
                'username': {'type': 'str', 'range': (4, 'any')}
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
            'keys': OrderedDict({
                'firstname': {'type': 'str', 'range': (2, 50)},
                'lastname': {'type': 'str', 'range': (2, 50)},
                'email': {'type': 'email'},
                'age': {'type': 'int', 'range': (18, 'any')}
            })
        }

        class Person:
            pass

        class Animal:
            pass

        self.person_class = Person
        self.animal_class = Animal
        self.all_object_rules = [
            {**self.object_rule, 'object': Person}
        ]

    def append_rule(self, base_rule: dict, new_rule: dict) -> dict:
        return {**base_rule, **new_rule}

    def get_type_dict(self, type_str):
        return {'type': type_str}

    def tearDown(self):
        pass

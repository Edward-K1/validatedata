from os import truncate
from validatedata.validatedata import validate_data
from validatedata.messages import error_messages
from .base import BaseTest


class TestTypes(BaseTest):
    def test_bool(self):
        result1 = validate_data([True], self.all_bool_rules[0])
        result2 = validate_data([False], self.all_bool_rules[0])
        result3 = validate_data(['nope'], self.all_bool_rules[0])

        self.assertEqual(result1.ok, True)
        self.assertEqual(result2.ok, True)
        self.assertEqual(result3.ok, False)
        

    def test_date(self):
        result1 = validate_data('23-Oct-2000', self.all_date_rules[0])
        result2 = validate_data('23-Oct-2000', self.all_date_rules[1])
        result3 = validate_data('02-October-2090', self.all_date_rules[0])
        result4 = validate_data([556], self.all_date_rules[0])

        self.assertEqual(result1.ok, True)
        self.assertEqual(result2.ok, True)
        self.assertEqual(result3.ok, False)
        self.assertEqual(result4.ok, False)

        expected_errors = [
            error_messages['does_not_startwith'],
            error_messages['does_not_endwith'],
            error_messages['length_invalid'],
            error_messages['date_not_in_range'],
            error_messages['not_in_options'], error_messages['not_excluded']
        ]

        for message in expected_errors:
            self.assertIn(message, result3.errors)

    def test_email(self):
        result1 = validate_data('test@example.com', self.all_email_rules[0])
        result2 = validate_data(['test@example.com'], self.all_email_rules[0])
        result3 = validate_data('test@example.com', self.all_email_rules[1])
        result4 = validate_data('peter@pan.co.uk', self.all_email_rules[1])
        result5 = validate_data([290], self.all_email_rules[1])

        self.assertEqual(result1.ok, True)
        self.assertEqual(result2.ok, True)
        self.assertEqual(result3.ok, True)
        self.assertEqual(result4.ok, False)
        self.assertEqual(result5.ok, False)

    def test_even(self):
        result1 = validate_data([20000], self.all_even_rules[0])
        result2 = validate_data([20000], self.all_even_rules[1])
        result3 = validate_data([300000], self.all_even_rules[1])
        result4 = validate_data([300000], self.all_even_rules[2])
        result5 = validate_data([355], self.all_even_rules[2])
        result6 = validate_data('lala', self.all_even_rules[2])

        self.assertEqual(result1.ok, True)
        self.assertEqual(result2.ok, True)
        self.assertEqual(result3.ok, False)
        self.assertEqual(result4.ok, True)
        self.assertEqual(result5.ok, False)
        self.assertEqual(result6.ok, False)

    def test_float(self):
        result1 = validate_data([6.5], self.all_float_rules[0])
        result2 = validate_data([6.5], self.all_float_rules[1])
        result3 = validate_data([400.8], self.all_float_rules[1])
        result4 = validate_data(['40.6'], self.all_float_rules[2])

        self.assertEqual(result1.ok, True)
        self.assertEqual(result2.ok, True)
        self.assertEqual(result3.ok, False)
        self.assertEqual(result4.ok, True)

    def test_int(self):
        result1 = validate_data([20000], self.all_int_rules[0])
        result2 = validate_data([20000], self.all_int_rules[1])
        result3 = validate_data([20000], self.all_int_rules[2])
        result4 = validate_data([60], self.all_int_rules[3])
        result5 = validate_data([20000], self.all_int_rules[3])

        self.assertEqual(result1.ok, True)
        self.assertEqual(result2.ok, True)
        self.assertEqual(result3.ok, True)
        self.assertEqual(result4.ok, True)
        self.assertEqual(result5.ok, False)

    def test_odd(self):
        result1 = validate_data([15], self.all_odd_rules[0])
        result2 = validate_data([20], self.all_odd_rules[0])

        self.assertEqual(result1.ok, True)
        self.assertEqual(result2.ok, False)

    def test_str(self):
        result1 = validate_data(['validate'], self.all_str_rules[0])
        result2 = validate_data(['validate'], self.all_str_rules[1])

        self.assertEqual(result1.ok, True)
        self.assertEqual(result2.ok, True)

    def test_dict(self):
        dict1 = {'name': 'james', 'age': 22, 'city': 'kampala'}
        dict2 = {'name': 'james', 'age': 22}

        result1 = validate_data([dict1], self.all_dict_rules[0])
        result2 = validate_data([dict1], self.all_dict_rules[1])
        result3 = validate_data([dict2], self.all_dict_rules[1])
        result4 = validate_data([{'he','llo'}], self.all_dict_rules[1])

        self.assertEqual(result1.ok, True)
        self.assertEqual(result2.ok, True)
        self.assertEqual(result3.ok, False)
        self.assertEqual(result4.ok, False)

    def test_list(self):
        result1 = validate_data([[5, 6, 9, 10]], self.all_list_rules[0])
        result2 = validate_data([[5, 6, 9, 10]], self.all_list_rules[1])

        self.assertEqual(result1.ok, True)
        self.assertEqual(result2.ok, True)

    def test_regex(self):
        result1 = validate_data('hello', self.all_regex_rules[0])

        self.assertEqual(result1.ok, True)

    def test_set(self):
        result1 = validate_data([{2, 3}], self.all_set_rules[0])
        result2 = validate_data(['wrong'], self.all_set_rules[0])
        result3 = validate_data([{5, 6, 9}], self.all_set_rules[1])
        result4 = validate_data([{1, 1, 2, 8}], self.all_set_rules[1])

        self.assertEqual(result1.ok, True)
        self.assertEqual(result2.ok, False)
        self.assertEqual(result3.ok, True)
        self.assertEqual(result4.ok, False)

    def test_tuple(self):
        result1 = validate_data([(5, 6, 9, 10)], self.all_tuple_rules[0])
        result2 = validate_data([(5, 6, 9, 10)], self.all_tuple_rules[1])

        self.assertEqual(result1.ok, True)
        self.assertEqual(result2.ok, True)

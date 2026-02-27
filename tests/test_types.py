from validatedata.validatedata import validate_data
from validatedata.messages import error_messages
from .base import BaseTest


class TestTypes(BaseTest):

    def test_bool(self):
        result1 = validate_data([True], self.all_bool_rules[0])
        result2 = validate_data([False], self.all_bool_rules[0])
        result3 = validate_data(['nope'], self.all_bool_rules[0])

        self.assertTrue(result1.ok)
        self.assertTrue(result2.ok)
        self.assertFalse(result3.ok)
        # error message is already formatted (e.g. "Expected value of type bool, found str")
        self.assertTrue(any('bool' in msg for msg in result3.errors[0]))

    def test_date(self):
        result1 = validate_data('23-Oct-2000', self.all_date_rules[0])
        result2 = validate_data('23-Oct-2000', self.all_date_rules[1])
        result3 = validate_data('02-October-2090', self.all_date_rules[0])
        result4 = validate_data([556], self.all_date_rules[0])

        self.assertTrue(result1.ok)
        self.assertTrue(result2.ok)
        self.assertFalse(result3.ok)
        self.assertFalse(result4.ok)

        expected_errors = [
            error_messages['does_not_startwith'],
            error_messages['does_not_endwith'],
            error_messages['length_invalid'],
            error_messages['date_not_in_range'],
            error_messages['not_in_options'],
            error_messages['not_excluded'],
        ]
        for message in expected_errors:
            self.assertIn(message, result3.errors)

    def test_email(self):
        result1 = validate_data('test@example.com', self.all_email_rules[0])
        result2 = validate_data(['test@example.com'], self.all_email_rules[0])
        result3 = validate_data('test@example.com', self.all_email_rules[1])
        result4 = validate_data('peter@pan.co.uk', self.all_email_rules[1])
        result5 = validate_data([290], self.all_email_rules[1])

        self.assertTrue(result1.ok)
        self.assertTrue(result2.ok)
        self.assertTrue(result3.ok)
        self.assertFalse(result4.ok)
        self.assertFalse(result5.ok)

    def test_even(self):
        result1 = validate_data([20000], self.all_even_rules[0])
        result2 = validate_data([20000], self.all_even_rules[1])
        result3 = validate_data([300000], self.all_even_rules[1])
        result4 = validate_data([300000], self.all_even_rules[2])
        result5 = validate_data([355], self.all_even_rules[2])
        result6 = validate_data('lala', self.all_even_rules[2])

        self.assertTrue(result1.ok)
        self.assertTrue(result2.ok)
        self.assertFalse(result3.ok)
        self.assertTrue(result4.ok)
        self.assertFalse(result5.ok)
        self.assertFalse(result6.ok)

    def test_float(self):
        result1 = validate_data([6.5], self.all_float_rules[0])
        result2 = validate_data([6.5], self.all_float_rules[1])
        result3 = validate_data([400.8], self.all_float_rules[1])
        result4 = validate_data(['40.6'], self.all_float_rules[2])
        result5 = validate_data(['not-a-float'], self.all_float_rules[0])

        self.assertTrue(result1.ok)
        self.assertTrue(result2.ok)
        self.assertFalse(result3.ok)
        self.assertTrue(result4.ok)
        self.assertFalse(result5.ok)

    def test_int(self):
        result1 = validate_data([20000], self.all_int_rules[0])
        result2 = validate_data([20000], self.all_int_rules[1])
        result3 = validate_data([20000], self.all_int_rules[2])
        result4 = validate_data([60], self.all_int_rules[3])
        result5 = validate_data([20000], self.all_int_rules[3])
        result6 = validate_data(['hello'], self.all_int_rules[0])

        self.assertTrue(result1.ok)
        self.assertTrue(result2.ok)
        self.assertTrue(result3.ok)
        self.assertTrue(result4.ok)
        self.assertFalse(result5.ok)
        self.assertFalse(result6.ok)
        # confirm all_int_rules is actually int not even
        self.assertEqual(self.all_int_rules[1]['type'], 'int')

    def test_odd(self):
        # basic pass/fail
        self.assertTrue(validate_data([15], self.all_odd_rules[0]).ok)
        self.assertFalse(validate_data([20], self.all_odd_rules[0]).ok)

        # with length + range + options + excludes
        self.assertTrue(validate_data([10001], self.all_odd_rules[1]).ok)
        self.assertFalse(validate_data([99999], self.all_odd_rules[1]).ok)  # excluded

        # range lower-bound with 'any' upper
        self.assertTrue(validate_data([999], self.all_odd_rules[2]).ok)
        self.assertFalse(validate_data([9], self.all_odd_rules[2]).ok)

        # bounded range
        self.assertTrue(validate_data([55], self.all_odd_rules[3]).ok)
        self.assertFalse(validate_data([91], self.all_odd_rules[3]).ok)

    def test_str(self):
        # rule[0]: bare str
        self.assertTrue(validate_data(['validate'], self.all_str_rules[0]).ok)
        self.assertFalse(validate_data([42], self.all_str_rules[0]).ok)

        # rule[1]: length + range(any-bound) + options + excludes + startswith + endswith + contains
        self.assertTrue(validate_data(['validate'], self.all_str_rules[1]).ok)
        self.assertFalse(validate_data(['neo'], self.all_str_rules[1]).ok)       # excluded
        self.assertFalse(validate_data(['wrongval'], self.all_str_rules[1]).ok)  # not in options

        # rule[2]: regex expression + range with 'any' lower bound
        self.assertTrue(validate_data(['12345678'], self.all_str_rules[2]).ok)
        self.assertFalse(validate_data(['abc'], self.all_str_rules[2]).ok)       # fails regex

    def test_dict(self):
        dict1 = {'name': 'james', 'age': 22, 'city': 'kampala'}
        dict2 = {'name': 'james', 'age': 22}

        result1 = validate_data([dict1], self.all_dict_rules[0])
        result2 = validate_data([dict1], self.all_dict_rules[1])
        result3 = validate_data([dict2], self.all_dict_rules[1])  # missing 'city' key
        result4 = validate_data([{'he', 'llo'}], self.all_dict_rules[1])  # not a dict

        self.assertTrue(result1.ok)
        self.assertTrue(result2.ok)
        self.assertFalse(result3.ok)
        self.assertFalse(result4.ok)

    def test_list(self):
        result1 = validate_data([[5, 6, 9, 10]], self.all_list_rules[0])
        result2 = validate_data([[5, 6, 9, 10]], self.all_list_rules[1])
        result3 = validate_data([[1, 2, 3]], self.all_list_rules[1])    # wrong length + missing values
        result4 = validate_data(['notalist'], self.all_list_rules[0])   # not a list

        self.assertTrue(result1.ok)
        self.assertTrue(result2.ok)
        self.assertFalse(result3.ok)
        self.assertFalse(result4.ok)

    def test_regex(self):
        result1 = validate_data('hello', self.all_regex_rules[0])   # matches \w{4,}
        result2 = validate_data('hi', self.all_regex_rules[0])      # too short

        self.assertTrue(result1.ok)
        self.assertFalse(result2.ok)
        self.assertIn(error_messages['does_not_match_regex'], result2.errors)

    def test_set(self):
        result1 = validate_data([{2, 3}], self.all_set_rules[0])
        result2 = validate_data(['wrong'], self.all_set_rules[0])
        result3 = validate_data([{5, 6, 9}], self.all_set_rules[1])
        result4 = validate_data([{1, 2, 8}], self.all_set_rules[1])  # contains excluded value 8

        self.assertTrue(result1.ok)
        self.assertFalse(result2.ok)
        self.assertTrue(result3.ok)
        self.assertFalse(result4.ok)

    def test_tuple(self):
        result1 = validate_data([(5, 6, 9, 10)], self.all_tuple_rules[0])
        result2 = validate_data([(5, 6, 9, 10)], self.all_tuple_rules[1])
        result3 = validate_data([(1, 2, 3)], self.all_tuple_rules[1])   # wrong length
        result4 = validate_data(['notuple'], self.all_tuple_rules[0])   # not a tuple

        self.assertTrue(result1.ok)
        self.assertTrue(result2.ok)
        self.assertFalse(result3.ok)
        self.assertFalse(result4.ok)

    def test_object(self):
        person = self.person_class()
        animal = self.animal_class()

        result1 = validate_data([person], self.all_object_rules[0])  # correct type
        result2 = validate_data([animal], self.all_object_rules[0])  # wrong type
        result3 = validate_data(['string'], self.all_object_rules[0])  # wrong type (primitive)

        self.assertTrue(result1.ok)
        self.assertFalse(result2.ok)
        self.assertFalse(result3.ok)
        self.assertIn(error_messages['invalid_object'], result2.errors[0])

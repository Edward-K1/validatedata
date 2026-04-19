# NOSONAR
# prevent sonarcube from complaining about hardcoded test passwords
#

from collections import OrderedDict

from validatedata import validate, validate_data
from validatedata import ValidationError
from .base import BaseTest


# ---------------------------------------------------------------------------
# Original examples — signup via @validate decorator
# ---------------------------------------------------------------------------

class TestExamples(BaseTest):

    def test_signup_valid(self):
        signup_rules = [
            {
                'type': 'str',
                'expression': r'^[^\d\W_]+[\w\d_-]{2,31}$',
                'expression-message': 'invalid username',
            },
            'email:msg:invalid email',
            {
                'type': 'str',
                'expression': r'(?=\S*[a-z])(?=\S*[A-Z])(?=\S*\d)(?=\S*[^\w\s])\S{8,}$',
                'message': 'password must contain a number, an uppercase letter, '
                'and should be at least 8 characters long without spaces',
            },
        ]

        class User:
            @validate(signup_rules, raise_exceptions=True)
            def signup(self, username, email, password):
                return 'Account Created'

        user = User()
        self.assertEqual(
            user.signup('hello', 'p@j.com', 'dlllj89@jlH'), 'Account Created'
        )

    def test_signup_invalid_email_raises(self):
        signup_rules = [
            {
                'type': 'str',
                'expression': r'^[^\d\W_]+[\w\d_-]{2,31}$',
                'expression-message': 'invalid username',
            },
            'email:msg:invalid email',
            {
                'type': 'str',
                'expression': r'(?=\S*[a-z])(?=\S*[A-Z])(?=\S*\d)(?=\S*[^\w\s])\S{8,}$',
                'message': 'password must contain a number, an uppercase letter, '
                'and should be at least 8 characters long without spaces',
            },
        ]

        class User:
            @validate(signup_rules, raise_exceptions=True)
            def signup(self, username, email, password):
                return 'Account Created'

        user = User()
        with self.assertRaises(ValidationError) as ctx:
            user.signup('helterskelter', 'paddle', 'Arosebyanyname?1')
        self.assertIn('invalid email', str(ctx.exception))


# ---------------------------------------------------------------------------
# Example 1 — User registration
# ---------------------------------------------------------------------------

class TestUserRegistration(BaseTest):

    rule = {
        'username': r'str|strip|min:3|max:32|re:^[\w.-]+$|msg:username must be 3-32 characters, letters, digits, dots, or hyphens only',
        'email':    'email|msg:please enter a valid email address',
        'password': r'str|min:8|re:(?=.*[A-Z])(?=.*\d).+|msg:password must be at least 8 characters with one uppercase letter and one digit',
        'phone':    'phone|nullable',
    }

    def test_valid_registration(self):
        result = validate_data(
            data={
                'username': 'alice_99',
                'email':    'alice@example.com',
                'password': 'Secure123',  # NOSONAR
                'phone':    None,
            },
            rule=self.rule,
        )
        self.assertTrue(result.ok)

    def test_invalid_username_too_short(self):
        result = validate_data(
            data={'username': 'al', 'email': 'alice@example.com', 'password': 'Secure123', 'phone': None},  # NOSONAR
            rule=self.rule,
        )
        self.assertFalse(result.ok)

    def test_invalid_email(self):
        result = validate_data(
            data={'username': 'alice_99', 'email': 'not-an-email', 'password': 'Secure123', 'phone': None},  # NOSONAR
            rule=self.rule,
        )
        self.assertFalse(result.ok)
        self.assertTrue(any('please enter a valid email address' in e for e in result.errors))

    def test_weak_password(self):
        result = validate_data(
            data={'username': 'alice_99', 'email': 'alice@example.com', 'password': 'weakpass', 'phone': None},  # NOSONAR
            rule=self.rule,
        )
        self.assertFalse(result.ok)

    def test_phone_nullable(self):
        result = validate_data(
            data={'username': 'alice_99', 'email': 'alice@example.com', 'password': 'Secure123', 'phone': None},  # NOSONAR
            rule=self.rule,
        )
        self.assertTrue(result.ok)


# ---------------------------------------------------------------------------
# Example 2 — Flask route logic (no Flask dependency)
# ---------------------------------------------------------------------------

class TestFlaskRouteLogic(BaseTest):

    signup_rule = {
        'username': 'str|strip|min:3|max:32',
        'email':    'email',
        'password': r'str|min:8|re:(?=.*[A-Z])(?=.*\d).+',  # NOSONAR
    }

    def test_valid_payload_passes(self):
        result = validate_data(
            data={'username': 'alice_99', 'email': 'alice@example.com', 'password': 'Secure123'},  # NOSONAR
            rule=self.signup_rule,
        )
        self.assertTrue(result.ok)

    def test_invalid_payload_returns_errors(self):
        result = validate_data(
            data={'username': 'alice_99', 'email': 'not-an-email', 'password': 'Secure123'},  # NOSONAR
            rule=self.signup_rule,
        )
        self.assertFalse(result.ok)
        self.assertIsNotNone(result.errors)

    def test_decorator_valid(self):
        @validate(self.signup_rule, raise_exceptions=False)
        def signup(username, email, password):
            return 'created'

        self.assertEqual(signup('alice_99', 'alice@example.com', 'Secure123'), 'created')

    def test_decorator_invalid_returns_error_dict(self):
        @validate(self.signup_rule, raise_exceptions=False)
        def signup(username, email, password):
            return 'created'

        result = signup('alice_99', 'not-an-email', 'Secure123')
        self.assertIsInstance(result, dict)
        self.assertIn('errors', result)


# ---------------------------------------------------------------------------
# Example 3 — Application config validation
# ---------------------------------------------------------------------------

class TestAppConfig(BaseTest):

    rule = {
        'app': {
            'name':    'str|min:1',
            'version': 'semver',
            'debug':   'bool',
        },
        'database': {
            'host': 'ip',
            'port': 'int|between:1,65535',
            'name': 'str|min:1',
        },
        'server': {
            'host': 'ip',
            'port': 'int|between:1024,65535',
        },
    }

    valid_config = {
        'app':      {'name': 'MyService', 'version': '1.4.0', 'debug': False},
        'database': {'host': '127.0.0.1', 'port': 5432,       'name': 'mydb'},
        'server':   {'host': '0.0.0.0',   'port': 8080},
    }

    def test_valid_config_passes(self):
        self.assertTrue(validate_data(data=self.valid_config, rule=self.rule).ok)

    def test_invalid_semver_fails(self):
        config = {**self.valid_config, 'app': {**self.valid_config['app'], 'version': '1.4'}}
        self.assertFalse(validate_data(data=config, rule=self.rule).ok)

    def test_invalid_db_port_fails(self):
        config = {**self.valid_config, 'database': {**self.valid_config['database'], 'port': 99999}}
        self.assertFalse(validate_data(data=config, rule=self.rule).ok)

    def test_invalid_server_ip_fails(self):
        config = {**self.valid_config, 'server': {'host': 'not-an-ip', 'port': 8080}}
        result = validate_data(data=config, rule=self.rule)
        self.assertFalse(result.ok)
        # dict validation returns flat error strings with dotted paths
        self.assertTrue(any('server.host' in e for e in result.errors))

    def test_error_path_includes_nested_key(self):
        config = {**self.valid_config, 'database': {**self.valid_config['database'], 'host': 'not-an-ip'}}
        result = validate_data(data=config, rule=self.rule)
        self.assertTrue(any('database.host' in e for e in result.errors))


# ---------------------------------------------------------------------------
# Example 4 — Bulk data import
# ---------------------------------------------------------------------------

class TestBulkImport(BaseTest):

    row_rule = [
        'str|strip|min:1|max:128',
        'email',
        'int|min:0',
        'str|in:active,inactive',
    ]

    def test_all_valid_rows_pass(self):
        rows = [
            ['Alice', 'alice@example.com', 30, 'active'],
            ['Bob',   'bob@example.com',   25, 'active'],
        ]
        for row in rows:
            self.assertTrue(validate_data(row, self.row_rule).ok)

    def test_blank_name_fails(self):
        self.assertFalse(validate_data(['', 'bob@example.com', 25, 'active'], self.row_rule).ok)

    def test_bad_email_fails(self):
        self.assertFalse(validate_data(['Carol', 'not-an-email', 28, 'active'], self.row_rule).ok)

    def test_negative_age_fails(self):
        self.assertFalse(validate_data(['Dave', 'dave@example.com', -1, 'active'], self.row_rule).ok)

    def test_invalid_status_fails(self):
        self.assertFalse(validate_data(['Dave', 'dave@example.com', 25, 'pending'], self.row_rule).ok)

    def test_bad_rows_are_collected(self):
        rows = [
            ['Alice', 'alice@example.com', 30, 'active'],
            ['',      'bob@example.com',   25, 'active'],
            ['Carol', 'not-an-email',       28, 'active'],
            ['Dave',  'dave@example.com',  -1,  'pending'],
        ]
        bad_rows = [i for i, row in enumerate(rows) if not validate_data(row, self.row_rule).ok]
        self.assertEqual(bad_rows, [1, 2, 3])


# ---------------------------------------------------------------------------
# Example 5 — Conditional fields on a checkout form
# ---------------------------------------------------------------------------

class TestCheckoutForm(BaseTest):

    rule = {
        'delivery_method': 'str|in:pickup,delivery',
        'address': {
            'type':       'str',
            'range':      (10, 'any'),
            'depends_on': {'field': 'delivery_method', 'value': 'delivery'},
            'message':    'a delivery address is required',
        },
        'promo_code': {
            'type':     'str',
            'length':   8,
            'nullable': True,
            'message':  'promo code must be exactly 8 characters',
        },
    }

    def test_pickup_without_address_passes(self):
        result = validate_data(
            data=OrderedDict([('delivery_method', 'pickup'), ('address', None), ('promo_code', None)]),
            rule=self.rule,
        )
        self.assertTrue(result.ok)

    def test_delivery_with_valid_address_passes(self):
        result = validate_data(
            data=OrderedDict([('delivery_method', 'delivery'), ('address', '123 Main Street'), ('promo_code', None)]),
            rule=self.rule,
        )
        self.assertTrue(result.ok)

    def test_delivery_without_address_fails(self):
        result = validate_data(
            data=OrderedDict([('delivery_method', 'delivery'), ('address', None), ('promo_code', None)]),
            rule=self.rule,
        )
        self.assertFalse(result.ok)

    def test_valid_promo_code_passes(self):
        result = validate_data(
            data=OrderedDict([('delivery_method', 'pickup'), ('address', None), ('promo_code', 'SAVE2024')]),
            rule=self.rule,
        )
        self.assertTrue(result.ok)

    def test_invalid_promo_code_length_fails(self):
        result = validate_data(
            data=OrderedDict([('delivery_method', 'pickup'), ('address', None), ('promo_code', 'SHORT')]),
            rule=self.rule,
        )
        self.assertFalse(result.ok)

    def test_null_promo_code_passes(self):
        result = validate_data(
            data=OrderedDict([('delivery_method', 'delivery'), ('address', '123 Main Street'), ('promo_code', None)]),
            rule=self.rule,
        )
        self.assertTrue(result.ok)


# ---------------------------------------------------------------------------
# Example 6 — Normalising data before saving (mutate + transforms)
# ---------------------------------------------------------------------------

class TestNormalisingBeforeSaving(BaseTest):

    rule = {
        'username': 'str|strip|lower|min:3|max:32',
        'bio':      'str|strip|max:280|nullable',
        'website':  'url|nullable',
    }

    def test_username_is_stripped_and_lowercased(self):
        result = validate_data(
            data={'username': '  Alice_99  ', 'bio': None, 'website': None},
            rule=self.rule,
            mutate=True,
        )
        self.assertTrue(result.ok)
        self.assertEqual(result.data['username'], 'alice_99')

    def test_bio_accepts_none(self):
        result = validate_data(
            data={'username': 'alice_99', 'bio': None, 'website': None},
            rule=self.rule,
            mutate=True,
        )
        self.assertTrue(result.ok)

    def test_bio_is_stripped(self):
        result = validate_data(
            data={'username': 'alice_99', 'bio': '  Building things.  ', 'website': None},
            rule=self.rule,
            mutate=True,
        )
        self.assertTrue(result.ok)
        self.assertEqual(result.data['bio'], 'Building things.')

    def test_valid_website_passes(self):
        result = validate_data(
            data={'username': 'alice_99', 'bio': None, 'website': 'https://alice.dev'},
            rule=self.rule,
            mutate=True,
        )
        self.assertTrue(result.ok)

    def test_invalid_website_fails(self):
        result = validate_data(
            data={'username': 'alice_99', 'bio': None, 'website': 'not-a-url'},
            rule=self.rule,
        )
        self.assertFalse(result.ok)

    def test_decorator_mutates_arguments(self):
        @validate(rule=self.rule, mutate=True)
        def update_profile(username, bio, website):
            return username

        result = update_profile('  Alice_99  ', None, None)
        self.assertEqual(result, 'alice_99')
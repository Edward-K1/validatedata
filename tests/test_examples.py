from validatedata.validatedata import validate, validate_data
from validatedata.validator import ValidationError
from .base import BaseTest


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

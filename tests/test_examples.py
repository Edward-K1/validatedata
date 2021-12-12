from validatedata.validatedata import validate, validate_data
from .base import BaseTest


class TestExamples(BaseTest):
    def test_signup_rule(self):
        signup_rules = [{
            'type': 'str',
            'expression': r'^[^\d\W_]+[\w\d_-]{2,31}$',
            'expression-message': 'invalid username'
        }, 
        'email:msg:invalid email', 
        {
            'type': 'str',
            'expression': r'(?=\S*[a-z])(?=\S*[A-Z])(?=\S*\d)(?=\S*[^\w\s])\S{8,}$',
            'message':'password must contain a number, an uppercase letter, and should be at least 8 characters long without spaces'
        }]

        class User:
            @validate(signup_rules, raise_exceptions=True)
            def signup(self, username, email, password):
                return "Account Created"


        user = User()
        status = user.signup('hello', 'p@j.com', 'dlllj89@jlH')
        self.assertEqual(status, "Account Created")
        
        with self.assertRaises(TypeError) as ex:
            user.signup('helterskelter', 'paddle', 'Arosebyanyname?1')
            self.assertEqual('invalid email', str(ex))


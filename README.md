# Validatedata
![build workflow](https://github.com/Edward-K1/validatedata/actions/workflows/release.yml/badge.svg)
&nbsp;

An easier way to validate data in python


## Installation

```shell
pip install validatedata
```


> Note: This is an alpha release. Please test all required functionality


### Types

- bool
- date
- email
- even
- float
- int
- odd
- str
- dict
- list
- regex
- set
- tuple

&nbsp;



### Rules
- length - integer - expected length of a string, int, or object
- contains - string or tuple of values expected in an object
- excludes - string or tuple of values not permitted
- options - tuple - a tuple of permitted values
- strict - boolean indicating whether data should be type cast or not
- expression - string - ensures data matches a given regular expression
- type - string - specifies type of data expected. Should always be included
- range - tuple - specifies permitted range or values. Used with numbers and dates
- startswith - object - string, int, et cetera that a type starts with
- endswith - object - string, int, et cetera that a type ends with

&nbsp;


## Usage



There are two ways to validate data:

**1. Using the decorator**

```python
from validatedata import validate

rules = ['int', 'int']

@validate(rules)
def sum(a, b):
    return a + b

```

**Parameters**

* rule - *str or list or tuple or dict* - rule(s) used to validate data. They should have the same index as the data.
* raise_exceptions - *bool* - whether exceptions should be thrown when data is invalid. Default is False
* is_class - *bool* - required for class methods that don't have the `self` parameter
* kwds - *dict* - takes configuration parameters that aren't explicitly catered for, e.g `log_errors` and `group_errors`

Set `log_errors` to True if you wish to log unhandled errors occuring in the background i.e `@validate(rules, ..., kwds={'log_errors': True})`

Set `group_errors` to False if you wish to disable grouping of errors

When the data does not match the rules, a dictionary is returned in the following format:

```python
{
    'errors': [[group1], [group2], ...]
}

or

{
    'errors': [error1, error2, ...]
}
```


**2. Using the validate_data function**

```python
from validatedata import validate_data

rules = [{
    'type': 'int',
    'range': (1, 'any'),
    'range-message': 'value should be an integer greater than zero'
}, {
    'type': 'int',
    'range': (1, 'any')
}]

def sum(a, b):
    total = 0

    result = validate_data(data=[a, b], rule=rules)

    if result.ok:
        total = a + b
    
    return total

```


Custom messages can be set by adding a key that matches the format, `{rule}-message` e.g range-message, length-message, et cetera. They are recommeded since the present defaults might be too generic in some circumstances


**Parameters**

- data - *list or str or dict* - the data to be validated
- rule - same as decorator
- raise_exceptions - same as decorator
- is_class - same as decorator
- kwds - same as decorator

> When the `data` parameter is a dict, `rule` should also be a dict in this format
```python
{'keys': OrderedDict({
    'key1': {'type':'<type>', ...},
    'key2': {'type': 'int', 'range': (5, 1000)}
})}
```
For Python versions `>= 3.7` you can replace `OrderedDict` with a standard dict since they are said to maintain insertion order

&nbsp;

A SimpleNamespace object with the attributes `ok` and `errors` is returned. It can be accessed like so:

```python
result = validate_data(...)

if result.ok:
    pass # do x

else:
    errors = result.errors
    pass # do y

```

&nbsp;


### Examples
```python

signup_rules = [{
    'type': 'str',
    'expression': r'^[^\d\W_]+[\w\d_-]{2,31}$',
    'expression-message': 'invalid username'
}, 
'email:msg:invalid email',
 {
    'type':'str',
    'expression':r'(?=\S*[a-z])(?=\S*[A-Z])(?=\S*\d)(?=\S*[^\w\s])\S{8,}$',
    'message':'password must contain a number, an uppercase letter, and should be at least 8 characters long without spaces'
}]


class User:
    @validate(signup_rules, raise_exceptions=True)
    def signup(self, username, email, password):
        return "Account Created"


user = User()
user.signup('helterskelter', 'paddle', 'Arosebyanyname?1')



rules = ['str:20', 'int:10', 'list:5']

rules = [{'type':'str', 'length':20}, {'type':'int', 'length':10}, {'type':'list', 'length': 5}]

rules = [{'type':'date', 'range': ('01-Jan-2021', 'any'), 'range-message':'the lowest date is 1st Jan 2021'}]



class User:

    @classmethod
    @validate(rule=['str', 'str'], is_class=True)
    def format_name(cls, firstname, lastname):
        return f'{firstname} {lastname}'

```

&nbsp;
## Additional Notes

- The functionality of a rule depends on the type it's working upon, e.g

```python
{'type':'int', 'range':(2, 100)} # int >= 2 and <= 100

{'type': 'str', 'range':(2, 100)} # string of variable length: len(s) >= 2 and len(s) <= 100


```

- The equivalence rules `equal to` and `not equal to` aren't included but their effect can be achieved using `options` and `excludes`

```python
{..., 'options': (200, )}

{..., 'excludes': ('Bill', ... )}
```


- The current version does not support nested data



## License
MIT
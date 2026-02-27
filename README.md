# Validatedata
![build workflow](https://github.com/Edward-K1/validatedata/actions/workflows/test.yml/badge.svg)
[![PyPI version](https://badge.fury.io/py/validatedata.svg)](https://badge.fury.io/py/validatedata)

An easier way to validate data in python.

Validatedata is for when you want expressive, inline validation rules without defining model classes. It is not a Pydantic alternative — it is a different tool for a different workflow: scripts, lightweight APIs, CLI tools, and anywhere defining a full model class feels like overkill.

## Installation

```
pip install validatedata
```

For extended phone number validation (national, international, and region-specific formats):

```
pip install phonenumbers
```

---

## Quick Start

```python
from validatedata import validate_data

result = validate_data(
    data={'username': 'alice', 'email': 'alice@example.com', 'age': 25},
    rule={'keys': {
        'username': {'type': 'str', 'range': (3, 32)},
        'email': {'type': 'email'},
        'age': {'type': 'int', 'range': (18, 'any')}
    }}
)

if result.ok:
    print('valid!')
else:
    print(result.errors)
```

---

## Three Ways to Validate

### 1. validate_types decorator

Validates function arguments against their Python type annotations. Works with or without brackets.

```python
from validatedata import validate_types

@validate_types
def create_user(username: str, age: int):
    return f'{username} ({age})'

create_user('alice', 30)        # works
create_user('alice', 'thirty')  # raises ValidationError

# with options — brackets required
@validate_types(raise_exceptions=False)
def create_user(username: str, age: int):
    return f'{username} ({age})'

result = create_user('alice', 'thirty')
# returns {'errors': [...]} instead of raising
```

### 2. validate decorator

```python
from validatedata import validate

signup_rules = [
    {
        'type': 'str',
        'expression': r'^[^\d\W_]+[\w\d_-]{2,31}$',
        'expression-message': 'invalid username'
    },
    'email:msg:invalid email address',
    {
        'type': 'str',
        'expression': r'(?=\S*[a-z])(?=\S*[A-Z])(?=\S*\d)(?=\S*[^\w\s])\S{8,}$',
        'message': 'password must contain uppercase, lowercase, number and symbol'
    }
]

class User:
    @validate(signup_rules, raise_exceptions=True)
    def signup(self, username, email, password):
        return 'Account Created'

user = User()
user.signup('alice_99', 'alice@example.com', 'Secure@123')  # works
user.signup('alice_99', 'not-an-email', 'weak')              # raises ValidationError
```

Class methods:

```python
class User:
    @classmethod
    @validate(rule=['str', 'str'], is_class=True)
    def format_name(cls, firstname, lastname):
        return f'{firstname} {lastname}'
```

### 3. validate_data function

```python
from validatedata import validate_data

rules = [
    {'type': 'int', 'range': (1, 'any'), 'range-message': 'must be greater than zero'},
    {'type': 'int', 'range': (1, 'any')}
]

result = validate_data(data=[a, b], rule=rules)

if result.ok:
    total = a + b
else:
    print(result.errors)
```

Dict input:

```python
rules = {'keys': {
    'username': {'type': 'str', 'range': (3, 32)},
    'age': {'type': 'int', 'range': (18, 'any'), 'range-message': 'must be 18 or older'}
}}

result = validate_data(data={'username': 'alice', 'age': 25}, rule=rules)
```

---

## Parameters

**validate and validate_data:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `rule` | str, list, tuple, dict | required | validation rules matching the data by index |
| `raise_exceptions` | bool | `False` | raise `ValidationError` on failure instead of returning errors |
| `is_class` | bool | `False` | set to `True` for classmethods without `self` |
| `mutate` | bool | `False` | apply transforms to the original values and return them |
| `kwds` | dict | — | extra config: `log_errors`, `group_errors` |

**validate_types:**

Same as above except `raise_exceptions` defaults to `True`.

Set `log_errors=True` to log background errors: `@validate(rules, kwds={'log_errors': True})`

Set `group_errors=False` to return a flat error list instead of grouped by field.

---

## Return Value

A `SimpleNamespace` with:

- `result.ok` — `True` if all validation passed
- `result.errors` — list of errors (grouped by field by default)
- `result.data` — transformed data, only present when `mutate=True`

```python
result = validate_data(...)

if result.ok:
    pass
else:
    for error_group in result.errors:
        print(error_group)
```

---

## Types

### Basic types

| Type | Description |
|------|-------------|
| `bool` | Boolean |
| `color` | Color in any format. Use `format` key to specify: `hex`, `rgb`, `hsl`, `named` |
| `date` | Date or datetime string |
| `email` | Email address |
| `even` | Even integer |
| `float` | Float |
| `int` | Integer |
| `ip` | IPv4 or IPv6 address |
| `odd` | Odd integer |
| `phone` | Phone number. E.164 built-in. Extended formats require `pip install phonenumbers` |
| `prime` | Prime number |
| `semver` | Semantic version e.g. `1.0.0`, `2.1.0-alpha.1` |
| `slug` | URL-friendly string e.g. `my-blog-post` |
| `str` | String |
| `url` | URL with protocol e.g. `https://example.com` |
| `uuid` | UUID string |

### Extended types

`dict`, `list`, `object`, `regex`, `set`, `tuple`

---

## Rules

| Rule | Type | Description |
|------|------|-------------|
| `contains` | str or tuple | values expected to be present |
| `depends_on` | dict | validate only when a sibling field meets a condition |
| `endswith` | object | value the data must end with |
| `excludes` | str or tuple | values not permitted |
| `expression` | str | regular expression the data must match |
| `fields` | dict | rules for nested dict fields |
| `items` | dict | rule applied to each item in a list or tuple |
| `length` | int | exact expected length |
| `nullable` | bool | allow `None` as a valid value. Default `False` |
| `options` | tuple | permitted values |
| `range` | tuple | permitted range. Use `'any'` for an open bound |
| `startswith` | object | value the data must start with |
| `strict` | bool | skip type casting. Default `False` |
| `transform` | callable or dict | function applied to the value before validation |
| `type` | str | type expected. Always required |
| `unique` | bool | list or tuple must contain no duplicates |

---

## Custom Error Messages

Add a `{rule}-message` key to override any default error:

```python
rules = [{
    'type': 'int',
    'range': (18, 'any'),
    'range-message': 'you must be at least 18 years old'
}, {
    'type': 'str',
    'range': (3, 32),
    'range-message': 'username must be between 3 and 32 characters'
}, {
    'type': 'email',
    'message': 'please enter a valid email address'
}]
```

---

## Shorthand Rule Strings

For common cases rules can be expressed as compact strings:

```python
'str'               # string
'str:20'            # string of exactly 20 characters
'int:10'            # int of length 10
'email'             # email address
'email:msg:invalid email address'   # email with custom message
'int:1:to:100'      # int in range 1 to 100
'regex:[A-Z]{3}'    # must match regex
```

Mixed shorthand and dict rules in the same list:

```python
rules = [
    {'type': 'str', 'expression': r'^[^\d\W_]+[\w\d_-]{2,31}$', 'expression-message': 'invalid username'},
    'email:msg:invalid email',
    {'type': 'str', 'length': 8, 'message': 'password must be 8 characters'}
]
```

---

## Range Rule

The `'any'` keyword is used as an open bound:

```python
{'type': 'int', 'range': (1, 'any')}               # >= 1, no upper limit
{'type': 'int', 'range': ('any', 100)}              # no lower limit, <= 100
{'type': 'int', 'range': (1, 100)}                  # >= 1 and <= 100
{'type': 'date', 'range': ('01-Jan-2021', 'any')}   # from Jan 2021 onwards
{'type': 'date', 'range': ('any', '31-Dec-2025')}   # up to Dec 2025

# on str — checks string length
{'type': 'str', 'range': (3, 32)}    # len(s) >= 3 and len(s) <= 32

# on list/tuple — checks number of elements
{'type': 'list', 'range': (1, 10)}  # between 1 and 10 items
```

---

## Examples

### Color validation

```python
# accept any color format
{'type': 'color'}

# specific formats
{'type': 'color', 'format': 'hex'}    # #ff0000 or #fff
{'type': 'color', 'format': 'rgb'}    # rgb(255, 0, 0)
{'type': 'color', 'format': 'hsl'}    # hsl(0, 100%, 50%)
{'type': 'color', 'format': 'named'}  # red, cornflowerblue, etc.

result = validate_data(
    data={'primary': '#ff0000', 'background': 'white'},
    rule={'keys': {
        'primary': {'type': 'color', 'format': 'hex'},
        'background': {'type': 'color', 'format': 'named'}
    }}
)
```

### Phone validation

```python
# E.164 format — built-in, no extra install
{'type': 'phone'}                          # +14155552671
{'type': 'phone', 'format': 'e164'}        # same

# extended formats — requires: pip install phonenumbers
{'type': 'phone', 'format': 'national'}       # (415) 555-2671
{'type': 'phone', 'format': 'international'}  # +1 415-555-2671
{'type': 'phone', 'region': 'GB'}             # region-specific validation
```

### New types

```python
# url
validate_data(['https://example.com'], [{'type': 'url'}])

# ip — accepts both IPv4 and IPv6
validate_data(['192.168.1.1'], [{'type': 'ip'}])
validate_data(['2001:db8::1'], [{'type': 'ip'}])

# uuid
validate_data(['550e8400-e29b-41d4-a716-446655440000'], [{'type': 'uuid'}])

# slug
validate_data(['my-blog-post'], [{'type': 'slug'}])

# semver
validate_data(['1.2.3'], [{'type': 'semver'}])
validate_data(['2.0.0-alpha.1'], [{'type': 'semver'}])

# prime
validate_data([7], [{'type': 'prime'}])

# even and odd
validate_data([4], [{'type': 'even'}])
validate_data([3], [{'type': 'odd'}])
```

### Nullable fields

```python
rules = {'keys': {
    'name': {'type': 'str'},
    'middle_name': {'type': 'str', 'nullable': True},  # optional
    'age': {'type': 'int'}
}}

validate_data({'name': 'Alice', 'middle_name': None, 'age': 30}, rules).ok  # True
validate_data({'name': 'Alice', 'middle_name': 'Jane', 'age': 30}, rules).ok  # True
```

### Unique collections

```python
rules = [{'type': 'list', 'unique': True}]

validate_data([[1, 2, 3]], rules).ok  # True
validate_data([[1, 2, 2]], rules).ok  # False — duplicates
```

### Transform

Simple — pass a callable:

```python
rules = [{'type': 'str', 'transform': str.strip, 'length': 5}]
validate_data(['  hello  '], rules).ok  # True — stripped before length check
```

Complex — access sibling fields:

```python
rules = {'keys': {
    'role': {'type': 'str'},
    'username': {
        'type': 'str',
        'transform': {
            'func': lambda value, data: value.upper() if data.get('role') == 'admin' else value,
            'pass_data': True
        }
    }
}}
```

With `mutate=True` — get back the transformed values:

```python
result = validate_data(
    data=['  alice  ', '  bob  '],
    rule=[
        {'type': 'str', 'transform': str.strip},
        {'type': 'str', 'transform': str.strip}
    ],
    mutate=True
)

result.ok    # True
result.data  # ['alice', 'bob']
```

Using `mutate=True` with the decorator passes transformed values into the function:

```python
@validate(rules, mutate=True)
def save_user(username):
    # username arrives already stripped
    db.save(username)
```

### Conditional validation with depends_on

Validate a field only when a sibling field meets a condition:

```python
# simple equality check
rules = {'keys': {
    'role': {'type': 'str'},
    'permissions': {
        'type': 'str',
        'depends_on': {'field': 'role', 'value': 'admin'},
        'options': ('full', 'read', 'none')
    }
}}

# permissions only validated when role is 'admin'
validate_data({'role': 'user', 'permissions': 'anything'}, rules).ok   # True
validate_data({'role': 'admin', 'permissions': 'full'}, rules).ok       # True
validate_data({'role': 'admin', 'permissions': 'anything'}, rules).ok   # False
```

Callable condition for complex logic:

```python
rules = {'keys': {
    'age': {'type': 'int'},
    'guardian_name': {
        'type': 'str',
        'depends_on': {
            'field': 'age',
            'condition': lambda age: age < 18
        },
        'message': 'guardian name required for users under 18'
    }
}}
```

### Custom object types

```python
class Address:
    pass

rules = [{'type': 'object', 'object': Address, 'message': 'Address object expected'}]

address = Address()
validate_data([address], rules).ok  # True
validate_data(['not an address'], rules).ok  # False
```

### Nested data structures

When rules contain `fields` or `items`, errors are automatically returned as path-prefixed flat strings instead of the default grouped format.

**Nested dict:**

```python
rules = {'keys': {
    'user': {
        'type': 'dict',
        'fields': {
            'username': {'type': 'str', 'range': (3, 32)},
            'email': {'type': 'email'},
            'age': {'type': 'int', 'range': (18, 'any')}
        }
    }
}}

result = validate_data(
    data={'user': {'username': 'al', 'email': 'not-an-email', 'age': 25}},
    rule=rules
)

result.ok      # False
result.errors  # ['user.username: invalid string length', 'user.email: invalid email']
```

**Deeply nested:**

```python
rules = {'keys': {
    'company': {
        'type': 'dict',
        'fields': {
            'name': {'type': 'str'},
            'address': {
                'type': 'dict',
                'fields': {
                    'street': {'type': 'str'},
                    'city': {'type': 'str'},
                    'postcode': {'type': 'str', 'length': 6}
                }
            }
        }
    }
}}

result = validate_data(
    data={'company': {'name': 'Acme', 'address': {'street': '1 Main St', 'city': 'Lagos', 'postcode': '123'}}},
    rule=rules
)

result.errors  # ['company.address.postcode: value is not of required length']
```

**List of typed items:**

```python
rules = [{'type': 'list', 'items': {'type': 'int', 'range': (1, 100)}}]

result = validate_data([[10, 50, 200, 5]], rules)
result.errors  # ['[0][2]: number out of range']
```

**List of dicts:**

```python
rules = [{'type': 'list', 'items': {
    'type': 'dict',
    'fields': {
        'name': {'type': 'str'},
        'score': {'type': 'int', 'range': (0, 100)}
    }
}}]

result = validate_data(
    data=[[
        {'name': 'Alice', 'score': 95},
        {'name': 'Bob', 'score': 150},   # invalid
    ]],
    rule=rules
)

result.errors  # ['[0][1].score: number out of range']
```

### raise_exceptions

```python
from validatedata import validate, ValidationError

rules = [{'type': 'email', 'message': 'invalid email'}]

@validate(rules, raise_exceptions=True)
def send_email(address):
    ...

try:
    send_email('not-an-email')
except ValidationError as e:
    print(e)  # invalid email
```

### contains, excludes, options

```python
# contains — value must include these
{'type': 'str', 'contains': '@'}
{'type': 'list', 'contains': ('admin', 'user')}

# excludes — value must not include these
{'type': 'str', 'excludes': ('forbidden', 'banned')}

# options — value must be one of these (equal to)
{'type': 'str', 'options': ('active', 'inactive', 'pending')}

# not equal to — achieved with excludes
{'type': 'str', 'excludes': ('deleted',)}
```

### startswith and endswith

```python
# strings
{'type': 'str', 'startswith': 'https'}
{'type': 'str', 'endswith': '.pdf'}

# lists
{'type': 'list', 'startswith': 'header'}
{'type': 'list', 'endswith': 'footer'}
```

### strict mode

By default validatedata casts values before checking type (`strict=False`), so `"42"` passes as an `int`. Set `strict=True` to require exact types:

```python
{'type': 'int', 'strict': True}   # "42" will fail, only 42 passes
{'type': 'str', 'strict': True}   # 42 will fail, only "42" passes
```

---

## Real-World Example: API Request Validation

```python
from validatedata import validate, validate_data

# validate a product creation request
product_rules = {'keys': {
    'name': {'type': 'str', 'range': (2, 100)},
    'slug': {'type': 'slug', 'message': 'slug must be lowercase with hyphens only'},
    'price': {'type': 'float', 'range': (0, 'any'), 'range-message': 'price must be positive'},
    'version': {'type': 'semver'},
    'homepage': {'type': 'url', 'nullable': True},
    'tags': {'type': 'list', 'unique': True, 'nullable': True},
    'variants': {
        'type': 'list',
        'items': {
            'type': 'dict',
            'fields': {
                'sku': {'type': 'uuid'},
                'color': {'type': 'color'},
                'stock': {'type': 'int', 'range': (0, 'any')}
            }
        }
    }
}}

result = validate_data(data=request_body, rule=product_rules)

if not result.ok:
    return {'status': 400, 'errors': result.errors}
```

---

## Additional Notes

- `depends_on` only works when `data` is a dict since it needs access to sibling fields
- Nested data (`fields`, `items`) automatically switches error format to path-prefixed strings
- The current version does not support `depends_on` across nested levels
- `transform` runs before type checking, so the transformed value is what gets validated

---

## License

MIT

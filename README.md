# Validatedata
![build workflow](https://github.com/Edward-K1/validatedata/actions/workflows/test.yml/badge.svg)
[![PyPI version](https://badge.fury.io/py/validatedata.svg)](https://badge.fury.io/py/validatedata)

Lightning-fast validation in python.

**Seven validation modes – one simple syntax.**

1. **`validator()`** – One word: speed. Ideal for high‑throughput streaming. msgspec, handwritten code, and this function will compete for first place.
2. **`FastModel`** – declarative, typed models with compiled validation, rich error messages, serialization, and one-line bridging from Pydantic, msgspec, or dataclasses.
3. **`V`** – fast validation using simple inline checks for both types and constraints (e.g., V.int(5), V.between(1, 10, 5)). Returns bool by default but user can enable exceptions.
4. **`validate_data()`** / **`validate_data_fast()`** – general‑purpose validation with detailed errors, nested structures, and optional mutation.
5. **`@validate`** – decorator for function argument validation.
6. **`@validate_types`** – decorator that uses Python type annotations.
7. **`autovalidate` / `autovalidate_package`** – automatically apply `@validate_types` to entire modules or packages.

Validatedata gives you expressive, inline validation rules without defining model classes. It fits naturally into any Python workflow – from lightweight scripts to high‑volume data processing.

**New in v0.7:**
- **`FastModel.bridge()`** – turn an existing Pydantic model, msgspec `Struct`, or dataclass into a `FastModel` subclass in one line, carrying over field constraints (`min_length`, `ge`/`le`, `pattern`, `Literal` choices, and more) so you get FastModel's compiled validation and serialization without rewriting the model.
- **`V`** – single-line type checks (`V.int(x)`, `V.email(x)`) for when a full `Rule` or `FastModel` is more than you need.
- **Zero hard dependencies** – `python-dateutil` is no longer required. Core install is dependency-free; date validation uses strict ISO-8601 by default (`datetime.fromisoformat`). For the previous flexible parsing (e.g. `"23-Oct-2000"`), install the optional extra:
  ```bash
  pip install validatedata[dates]
  ```


### Benchmark (1 million repetitions)
| Test | validatedata (validator) | msgspec | pydantic | fastjsonschema |
|------|---------------------|-------------|---------|----------|
| Dict  (valid) | 1.1373s | 1.2550s | 4.2318s |  4.6816s|
| Dict (invalid) | 0.2359s | 1.1655s | 4.6230s | 3.0652s |

> [benchmark](https://github.com/Edward-K1/validatedata/blob/main/benchmark.py)


## Fast validation with `validator()`

When you only need a **boolean pass/fail** result (no error messages), use `validator()`. It compiles a rule into a callable that returns `True` or `False` with minimal overhead. Its faster than Pydantic v2 and msgspec on invalid data dicts.


```python
from validatedata import validator

# Single value – pipe syntax
is_valid_username = validator('str|min:3|max:32')
is_valid_username('alice')      # True
is_valid_username('a')          # False

# Multiple fields – flat dict rule
validate_user = validator({
    'username': 'str|min:3|max:32',
    'email':    'email',
    'age':      'int|min:18'
})

if validate_user({'username': 'bob', 'email': 'bob@example.com', 'age': 25}):
    do()


# Parameterized containers
is_str_or_int_list = validator('list[str,int]')
is_str_or_int_list(['a', 1, 'c'])   # True

# Nested dicts. Mirror structure
v = validator({
    'owner': 'str|min:2',
    'address': {'street': 'str', 'city': 'str'},
})

v({
    'owner': 'Alice',
    'address': {'street': '1 Main St', 'city': 'Springfield'},
})


```

## Declarative models with `FastModel`
 
For structured data that you reuse across your application, `FastModel` gives you a declarative, typed model with compiled validation, rich error messages, and built‑in serialization.
 
```python
from validatedata import FastModel, Rule, ValidationError
 
class Address(FastModel):
    street: str = Rule(type="str", min=3, max=64)
    city: str = Rule("str|re:^[A-Za-z ]+$")   # pipe syntax works too
 
class User(FastModel):
    id: int = Rule(type="int")
    username: str = Rule(type="str", min=3, max=32, pattern=r'^[a-z0-9_]+$')
    role: str = Rule(type="str", choices=["admin", "member", "guest"])
    email: str = Rule("email")
    tags: list[str] = Rule(type="list[str]", default=[], init_new=True, max=20)
    address: Address   # nested FastModel field
 
    def model_check(self, data: dict):
        # cross‑field validation
        if data["id"] < 0:
            raise ValidationError({"id": ["ID must be positive"]})
 
# Instantiate – validates on creation
user = User(
    id=1, username="alice", role="admin", email="alice@example.com",
    address=Address(street="1 Main St", city="Springfield"),
)
 
# Serialise to dict
data = user.to_dict()   # {'id': 1, 'username': 'alice', ...}
 
# from_dict recursively converts nested dicts (e.g. "address") into their
# FastModel type. Returns None if data is invalid; set validate=True to raise instead.
# this is the prefered method for performance-conscious users
user2 = User.from_dict(data)
```
See the [FastModel reference](docs/fastmodel.rst) for a full walkthrough of every `Rule` option (transforms, custom messages, `default_factory`, nullable fields, and more).
 
### Hot loops / high‑throughput endpoints: `get_validator()` and `get_rules()`
 
Constructing a `User(**kwargs)` instance runs full validation *and* builds an object every call which is more than you need when you're just checking millions of dicts in a tight loop. Get the compiled boolean validator once via get_validator and reuse it:
 
```python
# Compiled once, cached on the class — subsequent calls return the same function
validate_user = User.get_validator()
 
for payload in incoming_requests:
    if not validate_user(payload):
        reject(payload)
        continue
    process(payload)
```
 
`get_validator()` is the same callable used internally by `is_valid_data` and the default `from_dict(..., validate="check")` path. grab it directly when you want to skip instance construction entirely and just get a `True`/`False` per dict.
 
`get_rules()` returns the canonical rule dict `get_validator()` was compiled from (pipe strings, or nested dicts for `FastModel` fields). Useful for logging, introspection, or feeding the same rules into another `validator()` call:
 
```python
User.get_rules()
# {'id': 'int', 'username': 'str|min:3|max:32|re:^[a-z0-9_]+$', 'role': 'str|in:admin,member,guest',
#  'email': 'email', 'tags': 'list[str]|max:20|nullable', 'address': {'street': 'str|min:3|max:64', 'city': 'str|re:^[A-Za-z ]+$'}}
```
`openapi_schema()` returns the openapi 3.0 json schema. You can get version 3.1 by supplying the version parameter, i.e `User.openapi_schema(version="3.1")`

### Bridging from Pydantic, msgspec, or dataclasses

Already have models defined with another library? `FastModel.bridge()` builds an equivalent `FastModel` subclass from them, so you get compiled validation, serialization, and `openapi_schema()` without rewriting anything.

```python
from pydantic import BaseModel, Field
from validatedata import FastModel

class PyUser(BaseModel):
    username: str = Field(min_length=3, max_length=32, pattern=r'^[a-z0-9_]+$')
    age: int = Field(ge=18)

FastUser = FastModel.bridge(PyUser)

FastUser(username="alice", age=25)     # works
FastUser(username="al", age=25)        # raises ValidationError (min_length)
```

The same call works on a msgspec `Struct` or a plain `@dataclass` — `bridge()` detects which one it was given. Field constraints carry over automatically:

| Source | Mapped to FastModel |
|--------|---------------------|
| `min_length` / `max_length` (Pydantic, msgspec) | `min` / `max` |
| `ge` / `le` (Pydantic, msgspec) | `min` / `max` |
| `pattern` (Pydantic, msgspec) | `pattern` |
| `Literal[...]` (any source) | `choices` |
| default / `default_factory` | `default` / `default_factory` |
| nested model fields | recursively bridged, once per type |

Constraints with no equivalent in validatedata's engine — msgspec's `tz` — raise a clear `ValueError` at bridge time rather than being silently dropped or loosened. 

Other options, using the original `PyUser` (with `ge=18`) from above:

```python
FastModel.bridge(
    PyUser,
    field_overrides={"username": Rule(min=5, max=10)},  # replace a field's rule entirely
    model_check=my_cross_field_check,                    # attach cross-field validation
)

# Bridge an instance directly instead of the class — returns a populated FastModel instance
existing_user = PyUser(username="alice", age=25)
bridged_user = FastModel.bridge(existing_user)
```

## Single‑line checks with `V`

Sometimes you don't want a `Rule`, a `FastModel`, or a rule dict — you just want to ask one question about a type or constraint, inline:

```python
from validatedata import V

if V.int(5):
    ...
if V.between(1, 10, 5):
    ...
if not V.email(user_input):
    raise ValueError("bad email")
```

`V` covers both base types (int, str, float, bool, list, dict, tuple, set, decimal, path, date, datetime, semantic checks like email, url, uuid, ip, phone, slug, semver, color, even, odd, prime) and inline constraints with the config first and value last:

Ranges & Comparisons: `V.between(min, max, value)`, `V.gt(bound, value)`, `V.ge(bound, value)`, `V.lt(bound, value)`, `V.le(bound, value)`

String & Iterable Checks: `V.length(n, value)`, `V.min_length(n, value)`, `V.max_length(n, value)`, `V.contains(item, value)`, `V.excludes(item, value)`, `V.starts_with(prefix, value)`, `V.ends_with(suffix, value)`

Advanced Constraints: `V.multiple_of(step, value)`, `V.regex(pattern, value)` (cached), `V.unique(value)`, `V.one_of(choices, value)`, `V.none_of(choices, value)`

By default a failed check just returns `False`. Call `V.raise_on_fail(True)` to switch every check to a raising variant that throws `TypeError` naming the expected and actual types, instead of returning `False`:

```python
V.raise_on_fail(True)
V.int("not an int")
# TypeError: expected int, got str

V.raise_on_fail(False)   # back to bool-returning
V.int("not an int")      # False
```

For a type that isn't one of `V`'s predeclared attributes — a type you registered with `register_type`, or a plain Python/stdlib type — use `V.check(name, value)`:

```python
V.check("MyRegisteredType", obj)
```

`V` deliberately doesn't do rules, pipe strings, or `Rule` composition — constraint logic (`min`, `max`, `pattern`, `nullable`, ...) is `Rule`/`FastModel`'s job. `V` only ever answers "is this value this type," optionally loudly.

## Installation

```
pip install validatedata
```

For extended phone number validation (national, international, and region-specific formats):

```
pip install phonenumbers
```

---
📖 **[Read the full documentation](https://validatedata.readthedocs.io)**

## Quick Start

```python
from validatedata import validate_data

# with shorthand
rule={
    'username': 'str|min:3|max:32',
    'email': 'email',
    'age': 'int|min:18',
}


result = validate_data(
    data={'username': 'alice', 'email': 'alice@example.com', 'age': 25},
    rule=rule
)

if result.ok:
    print('valid!')
else:
    print(result.errors)
```


---

## Function & Data Validation, In Detail

`FastModel`, `V`, and `FastModel.bridge()` each have their own section above. The six patterns below cover the rest: direct calls and decorators for validating raw data and function arguments.

### 1. `validator()` – for high performance (boolean only)
 ```python
 from validatedata import validator
 
 is_valid_username = validator('str|min:3|max:32')
 if is_valid_username('alice'):
     do_xyz()
 
 ```
### 2. `validate_data_fast()` – compiled speed + error messages (experimental)

 ```python
 from validatedata import validate_data_fast
 
 result = validate_data_fast({'name': 'alice'}, {'name': 'str|min:3'})
 if not result.ok:
     print(result.errors)   # ['name: string too short (minimum length: 3)']
```


### 3. validate_types decorator

Validates function arguments against their Python type annotations.

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

### 4. validate decorator

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

Async functions are supported. Both `validate` and `validate_types` decorators behaves identically:


Class methods:

```python
class User:
    @classmethod
    @validate(rule=['str', 'str'], is_class=True)
    def format_name(cls, firstname, lastname):
        return f'{firstname} {lastname}'
```

### 5. validate_data function

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

>The keys format is for when you need to add top level config options in a future release

### 6. Automatic validation
Yes, that's right.
```python

from decimal import Decimal
from validatedata import autovalidate

# custom type checker for decimals
def is_decimal(v): return isinstance(v, Decimal)

# add at the bottom of a file you want to auto-validate
autovalidate(
    module="my_project.my_module",
    type_checkers={Decimal: is_decimal},   # custom checkers
    raise_exceptions=True,                 # raise on failure
    enforce_hints=False,                   # require type hints on all functions
    # decorator=my_custom_decorator,       # optional: use your own decorator
)
```

You can also auto-validate an entire package. Add the code below to the root package *__init__.py* and watch magic

```python
from validatedata import autovalidate_package

report = autovalidate_package(
    package="my_project",
    include=[ "my_project.*" ],   # only modules under my_project
    exclude=[ "my_project.tests.*" ],  # skip tests
    # dry_run=True,
)

# Uncomment dry_run=True plus the print below to see what would be auto-validated.
# print(report["decorated"])

```

### Parameters:

`module` – module object or name (defaults to caller’s module)

`ignore` – list of strings/regex to skip (fully qualified names)

`type_checkers` – extra custom type checkers

`raise_exceptions` – whether to raise ValidationError (default True)

`dry_run` – if True, only return names that would be decorated

`decorator` – custom decorator to use instead of validate_types (ignores type_checkers & raise_exceptions)

`enforce_hints` – if True, raise TypeError for any function without type annotations

## Mirror‑structure rules

Instead of writing explicit {'type': 'dict', 'fields': {...}} for nested data, you can write a rule that mirrors the shape of your data. This is supported by validator, validate_data and validate. 

```python
from validatedata import validate_data

data = {
    'app': {
        'name':    'QuickScript',
        'version': '1.0.0',
    }
}


# mirror structure (no 'type', 'fields', or 'items' keys)
rule = {
    'app': {
        'name':    'str|min:3',
        'version': 'semver',
    }
}

result = validate_data(data, rule)
print(result.ok)   # True
```
---

## Custom type registration
You can register your own type checkers for any Python class or string name.
```python
from validatedata import register_type, validate_data

def is_decimal(v):
    from decimal import Decimal
    return isinstance(v, Decimal)

register_type(Decimal, is_decimal)

rule = {'price': 'decimal|min:0'}   # use the class name as type
result = validate_data({'price': Decimal('19.99')}, rule)
result.ok  # True
```
Introspection and removal:

```python
from validatedata import unregister_type, export_registered_checkers

unregister_type(Decimal)                     # remove by class
unregister_type('positive_int')              # remove by name

checkers = export_registered_checkers()      # dict of {name: checker}
```

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

Rules can be expressed as compact strings instead of dicts. There are two syntaxes: the original **colon syntax** (deprecated) for simple cases, and the newer **pipe syntax** for anything more expressive.

---

### Pipe syntax

The pipe syntax uses `|` to chain modifiers onto a type. It supports the full set of validation rules, optional transforms, and custom messages — all in one readable string.

**General shape:**

```
type [| transform ...] [| modifier ...] [| msg:message]
```

Transforms must come before validators. `msg:` must always be last.

#### Type

Any supported type name is valid as the first token:

```python
'str|...'
'int|...'
'email|...'
'url|...'
'uuid|...'
# ...any type from the Types section
```

#### Flags

```python
'int|strict'                             # no type coercion — value must already be the right type
'email|nullable'                         # None is accepted as a valid value
'int|strict|nullable'                    # both
```

#### Range

```python
'int|min:18'                             # >= 18, no upper limit
'int|max:100'                            # no lower limit, <= 100
'int|min:0|max:100'                      # between 0 and 100 inclusive
'int|between:0,100'                      # shorthand for the above
'str|min:3|max:32'                       # string length between 3 and 32
'float|min:0.5|max:9.9'                  # float range
'list|min:1|max:10'                      # list must have between 1 and 10 items
```

`min` and `max` can be used independently for open bounds. `between` is a convenience alias for `min` + `max` together — they cannot be combined.

> **Note:** `validatedata` does not impose a maximum size on lists or tuples. If you are validating untrusted input in a web API or other public-facing context, always set an explicit upper bound to prevent memory exhaustion from unexpectedly large payloads.

#### Enums and exclusions

```python
'str|in:admin,user,guest'                # value must be one of these
'str|not_in:root,superuser'              # value must not be any of these
```

#### String constraints

```python
'str|starts_with:https'                  # must start with this prefix
'str|ends_with:.pdf'                     # must end with this suffix
'str|contains:@'                         # must contain this substring
'list|unique'                            # no duplicate values
```

Values can safely contain `|` — the parser only splits on `|` when followed by a recognised keyword:

```python
'str|starts_with:image/png|min:3'        # 'image/png' is treated as one value
```

#### Format

For types that support format variants:

```python
'color|format:hex'                       # #fff or #ffffff
'color|format:rgb'                       # rgb(255, 0, 0)
'color|format:hsl'                       # hsl(0, 100%, 50%)
'color|format:named'                     # red, cornflowerblue, etc.
'phone|format:national'                  # (415) 555-2671  — requires: pip install phonenumbers
'phone|format:e164'                      # +14155552671  — built-in
```

#### Transforms

Named transforms are applied to the value **before** validation runs. They are the only modifiers that must come before validators.

```python
'str|strip|min:3|max:32'                 # strip whitespace, then check length
'str|lower|in:admin,user,guest'          # lowercase, then check options
'str|strip|lower|min:3|max:32'           # chain as many as needed
```

Available named transforms: `strip`, `lstrip`, `rstrip`, `lower`, `upper`, `title`.

To get the transformed value back, pass `mutate=True` to `validate_data` or `@validate`:

```python
result = validate_data(['  Alice  '], ['str|strip|lower'], mutate=True)
result.data  # ['alice']
```

#### Regex

```python
'str|re:[A-Z]{3}'                        # must match pattern
'str|min:8|re:(?=.*[A-Z])(?=.*\d).+'    # combined with other modifiers
```

The pattern is everything after `re:` up to the next recognised modifier or end of string. Patterns can safely contain `:` and `|`:

```python
'str|re:https?://\S+'                    # colons in pattern are safe
'str|re:(?=.*[A-Z]|.*\d).+'             # pipes in pattern are safe
```

#### Custom error message

`msg:` must be the last modifier. The message text can contain any characters including `|`:

```python
'str|min:3|max:32|msg:must be 3 to 32 characters'
'int|min:18|msg:you must be 18 or older'
'str|re:[A-Z]+|msg:uppercase letters only'
'int|min:0|msg:must be positive | or zero'   # | inside message is fine
```

---

### Mixing syntaxes

Colon shorthand, pipe shorthand, and dict rules can all coexist in the same rule list:

```python
rules = [
    {'type': 'str', 'expression': r'^[\w-]{3,32}$', 'expression-message': 'invalid username'},
    'email|nullable|msg:invalid email',
    'str|min:8|re:(?=.*[A-Z])(?=.*\d).+|msg:password too weak',
]
```

---

### Reference table

| Modifier | Example | Description |
|---|---|---|
| `strict` | `int\|strict` | No type coercion |
| `nullable` | `email\|nullable` | Allow `None` |
| `unique` | `list\|unique` | No duplicate values |
| `min:N` | `int\|min:18` | Minimum value or length |
| `max:N` | `int\|max:100` | Maximum value or length |
| `between:N,M` | `int\|between:0,100` | Range shorthand |
| `in:a,b,c` | `str\|in:admin,user` | Allowed values |
| `not_in:a,b` | `str\|not_in:root` | Excluded values |
| `starts_with:x` | `str\|starts_with:https` | Required prefix |
| `ends_with:x` | `str\|ends_with:.pdf` | Required suffix |
| `contains:x` | `str\|contains:@` | Required substring |
| `format:x` | `color\|format:hex` | Format variant |
| `strip` | `str\|strip\|min:3` | Remove surrounding whitespace |
| `lstrip` | `str\|lstrip\|min:3` | Remove leading whitespace |
| `rstrip` | `str\|rstrip\|min:3` | Remove trailing whitespace |
| `lower` | `str\|lower\|in:yes,no` | Lowercase before validating |
| `upper` | `str\|upper\|starts_with:ADM` | Uppercase before validating |
| `title` | `str\|title\|min:3` | Title case before validating |
| `re:pattern` | `str\|re:[A-Z]{3}` | Regex pattern |
| `msg:text` | `str\|min:3\|msg:too short` | Custom error message — must be last |

---

### Real-world examples

```python
# user signup fields
rules = [
    'str|strip|min:3|max:32|msg:username must be 3 to 32 characters',
    'email|nullable|msg:invalid email address',
    'str|min:8|re:(?=.*[A-Z])(?=.*\d).+|msg:password must contain uppercase and a number',
]

# role with enum
'str|in:admin,editor,viewer|msg:invalid role'

# optional hex colour
'color|format:hex|nullable'

# URL that must use HTTPS
'url|starts_with:https|msg:must be a secure URL'

# slugified identifier
'slug|min:3|max:64|msg:invalid slug'

# age gate
'int|strict|min:18|max:120|msg:invalid age'

# phone — any format, optional
'phone|nullable'

# deduplicated tag list
'list|unique|min:1|max:10'

# transform then validate
'str|strip|lower|in:yes,no,maybe|msg:invalid response'
```

---

## Range Rule

The `'any'` keyword is used as an open bound:

> **Note:** `validatedata` does not impose a maximum size on lists or tuples. If you are validating untrusted input in a web API or other public-facing context, always set an explicit upper bound to prevent memory exhaustion from unexpectedly large payloads.

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

**Mirror-structure shorthand (0.4.0+):**

Instead of wrapping every nested dict in `{'type': 'dict', 'fields': {...}}`, you can write a rule that mirrors the shape of your data:
```python
data = {
    'app': {
        'name':    'QuickScript',
        'version': '1.0.0',
    }
}

# before — explicit form
rule = {'keys': {
    'app': {
        'type': 'dict',
        'fields': {
            'name':    {'type': 'str', 'range': (3, 'any')},
            'version': {'type': 'semver'},
        }
    }
}}

# after — rule mirrors the data
rule = {
    'app': {
        'name':    'str|min:3',
        'version': 'semver',
    }
}
```

Error paths are identical in both forms. Nesting can go up to **100 levels** deep — exceeding this raises a `ValueError`. See the [mirror-rules guide](https://validatedata.readthedocs.io/en/latest/mirror-rules.html) for the full reference.
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
- If you need to disable performance optimisations added by code generation on validator, set codegen to False. e.g `is_valid = validator(..., codegen=False)` It will still be fast but you'll not some slight performance hit when procession millions of dicts

---

## Contributing

Contributions are welcome!

**Before starting work on a new feature or non-trivial change, please open an issue first.**


### Getting Started

1. Open an issue describing what you'd like to add or change
2. You'll be informed if there's someone working on it to avoid duplicate work and to ensure its the right call.
2. Fork the repository and create a branch off `main`
```
   git checkout -b feature/your-feature-name
```
3. Make your changes and add tests where appropriate
4. Open a pull request referencing the issue

For bug fixes and small improvements, feel free to skip the issue and go straight to a PR.

---

## License

MIT

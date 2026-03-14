Rules Reference
===============

Rules tell validatedata what to check. A rule can be a string (shorthand) or
a dict (explicit form). Both work side by side in the same rule list or field
map.

----

Types
-----

Every rule — string or dict — must specify a type. The type is always the
first token.

Basic types
~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 20 80

   * - Type
     - Description
   * - ``bool``
     - Boolean
   * - ``color``
     - Colour in any CSS format. Use ``format`` to restrict: ``hex``, ``rgb``, ``hsl``, ``named``
   * - ``date``
     - Date or datetime string (parsed with ``python-dateutil``)
   * - ``email``
     - Email address
   * - ``even``
     - Even integer
   * - ``float``
     - Floating-point number
   * - ``int``
     - Integer
   * - ``ip``
     - IPv4 or IPv6 address
   * - ``odd``
     - Odd integer
   * - ``phone``
     - Phone number. E.164 built-in. Extended formats require ``pip install phonenumbers``
   * - ``prime``
     - Prime number
   * - ``semver``
     - Semantic version string e.g. ``1.0.0``, ``2.1.0-alpha.1``
   * - ``slug``
     - URL-friendly string e.g. ``my-blog-post``
   * - ``str``
     - String
   * - ``url``
     - URL with protocol e.g. ``https://example.com``
   * - ``uuid``
     - UUID string

Extended types
~~~~~~~~~~~~~~

``dict``, ``list``, ``object``, ``regex``, ``set``, ``tuple``

Use ``dict`` and ``list`` with ``fields`` and ``items`` for nested validation
— see :ref:`nested-rules` below.

----

Dict rule form
--------------

The explicit form gives you the full rule API as a Python dict:

.. code-block:: python

   {
       'type': 'str',
       'range': (3, 32),
       'nullable': True,
       'message': 'username must be 3 to 32 characters',
   }

Valid rule keys
~~~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 25 20 55

   * - Key
     - Type
     - Description
   * - ``type``
     - str
     - Type name. Always required
   * - ``range``
     - tuple
     - Permitted range. Use ``'any'`` for an open bound: ``(18, 'any')``, ``('any', 100)``, ``(1, 100)``
   * - ``length``
     - int
     - Exact expected length
   * - ``options``
     - tuple
     - Permitted values — value must equal one of these
   * - ``excludes``
     - str or tuple
     - Values not permitted
   * - ``contains``
     - str or tuple
     - Values that must be present
   * - ``startswith``
     - object
     - Value the data must start with
   * - ``endswith``
     - object
     - Value the data must end with
   * - ``expression``
     - str
     - Regular expression the data must match
   * - ``unique``
     - bool
     - List or tuple must contain no duplicates
   * - ``strict``
     - bool
     - Skip type casting. Default ``False``
   * - ``nullable``
     - bool
     - Allow ``None`` as a valid value. Default ``False``
   * - ``format``
     - str
     - Format variant for ``color`` and ``phone`` types
   * - ``region``
     - str
     - Region code for ``phone`` type (requires ``phonenumbers``)
   * - ``transform``
     - callable or dict
     - Function applied to the value before validation runs
   * - ``depends_on``
     - dict
     - Validate only when a sibling field meets a condition
   * - ``fields``
     - dict
     - Rules for nested dict fields. See :ref:`nested-rules`
   * - ``items``
     - dict
     - Rule applied to each item in a list or tuple. See :ref:`nested-rules`
   * - ``object``
     - type
     - Python class to check against when ``type`` is ``object``
   * - ``message``
     - str
     - Override the default error message for type failures
   * - ``<rule>-message``
     - str
     - Override the error for a specific rule e.g. ``range-message``, ``expression-message``

----

Shorthand rule strings
----------------------

Rules can be written as compact strings rather than dicts. There are two
syntaxes: the original colon syntax for simple cases, and the pipe syntax for
anything more expressive. Both work side by side.

Colon syntax
~~~~~~~~~~~~

.. code-block:: python

   'str'                              # string
   'str:20'                           # string of exactly 20 characters
   'int:10'                           # int of exactly 10 digits
   'email'                            # email address
   'email:msg:invalid email address'  # with custom error message
   'int:1:to:100'                     # int in range 1 to 100
   'regex:[A-Z]{3}'                   # must match regex

Pipe syntax
~~~~~~~~~~~

Chain modifiers onto a type with ``|``. The general shape is:

.. code-block:: text

   type [| transform ...] [| modifier ...] [| msg:message]

Transforms must come before validators. ``msg:`` must always be last.

**Flags**

.. code-block:: python

   'int|strict'            # no type coercion
   'email|nullable'        # None is a valid value
   'int|strict|nullable'   # both

**Range**

.. code-block:: python

   'int|min:18'            # >= 18
   'int|max:100'           # <= 100
   'int|min:0|max:100'     # between 0 and 100 inclusive
   'int|between:0,100'     # shorthand for the above
   'str|min:3|max:32'      # string length range
   'list|min:1|max:10'     # list item count range

**Enums and exclusions**

.. code-block:: python

   'str|in:admin,user,guest'    # must be one of these
   'str|not_in:root,superuser'  # must not be any of these

**String constraints**

.. code-block:: python

   'str|starts_with:https'      # required prefix
   'str|ends_with:.pdf'         # required suffix
   'str|contains:@'             # required substring
   'list|unique'                # no duplicate values

**Format variants**

.. code-block:: python

   'color|format:hex'               # #fff or #ffffff
   'color|format:rgb'               # rgb(255, 0, 0)
   'phone|format:national'          # (415) 555-2671  — requires phonenumbers
   'phone|format:e164'              # +14155552671    — built-in

**Transforms**

Named transforms run before validation. Chain as many as needed:

.. code-block:: python

   'str|strip|min:3|max:32'         # strip whitespace, then check length
   'str|lower|in:admin,user,guest'  # lowercase, then check options
   'str|strip|lower|min:3'          # chained

Available named transforms: ``strip``, ``lstrip``, ``rstrip``, ``lower``,
``upper``, ``title``.

**Regex**

.. code-block:: python

   'str|re:[A-Z]{3}'
   'str|min:8|re:(?=.*[A-Z])(?=.*\d).+'

The pattern is everything after ``re:`` up to the next recognised modifier.
Patterns can safely contain ``:`` and ``|``.

**Custom error message**

``msg:`` must be the last modifier:

.. code-block:: python

   'str|min:3|max:32|msg:must be 3 to 32 characters'
   'int|min:18|msg:you must be 18 or older'
   'str|re:[A-Z]+|msg:uppercase letters only'

**Mixing syntaxes**

Colon shorthand, pipe shorthand, and dict rules can coexist in the same list:

.. code-block:: python

   rules = [
       {'type': 'str', 'expression': r'^[\w-]{3,32}$', 'expression-message': 'invalid username'},
       'email|nullable|msg:invalid email',
       'str|min:8|re:(?=.*[A-Z])(?=.*\d).+|msg:password too weak',
   ]

Pipe modifier reference
~~~~~~~~~~~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 30 35 35

   * - Modifier
     - Example
     - Description
   * - ``strict``
     - ``int|strict``
     - No type coercion
   * - ``nullable``
     - ``email|nullable``
     - Allow ``None``
   * - ``unique``
     - ``list|unique``
     - No duplicate values
   * - ``min:N``
     - ``int|min:18``
     - Minimum value or length
   * - ``max:N``
     - ``int|max:100``
     - Maximum value or length
   * - ``between:N,M``
     - ``int|between:0,100``
     - Range shorthand
   * - ``in:a,b,c``
     - ``str|in:admin,user``
     - Allowed values
   * - ``not_in:a,b``
     - ``str|not_in:root``
     - Excluded values
   * - ``starts_with:x``
     - ``str|starts_with:https``
     - Required prefix
   * - ``ends_with:x``
     - ``str|ends_with:.pdf``
     - Required suffix
   * - ``contains:x``
     - ``str|contains:@``
     - Required substring
   * - ``format:x``
     - ``color|format:hex``
     - Format variant
   * - ``strip``
     - ``str|strip|min:3``
     - Remove surrounding whitespace (transform)
   * - ``lstrip``
     - ``str|lstrip|min:3``
     - Remove leading whitespace (transform)
   * - ``rstrip``
     - ``str|rstrip|min:3``
     - Remove trailing whitespace (transform)
   * - ``lower``
     - ``str|lower|in:yes,no``
     - Lowercase (transform)
   * - ``upper``
     - ``str|upper|starts_with:ADM``
     - Uppercase (transform)
   * - ``title``
     - ``str|title|min:3``
     - Title case (transform)
   * - ``re:pattern``
     - ``str|re:[A-Z]{3}``
     - Regex pattern
   * - ``msg:text``
     - ``str|min:3|msg:too short``
     - Custom error — must be last

----

.. _nested-rules:

Nested rules
------------

Use ``fields`` to validate dict contents, and ``items`` to validate each
element of a list or tuple. Errors on nested fields are returned as
dotted-path strings: ``user.email: invalid email``.

Nested dict
~~~~~~~~~~~

.. code-block:: python

   rules = {'keys': {
       'user': {
           'type': 'dict',
           'fields': {
               'username': {'type': 'str', 'range': (3, 32)},
               'email':    {'type': 'email'},
               'age':      {'type': 'int', 'range': (18, 'any')},
           }
       }
   }}

   result = validate_data(
       data={'user': {'username': 'al', 'email': 'not-an-email', 'age': 25}},
       rule=rules,
   )

   result.errors  # ['user.username: invalid string length', 'user.email: invalid email']

.. tip::

   For deeply nested data, the :doc:`mirror-rules` shorthand lets you write
   rules that match the exact shape of your data without the ``type``/``fields``
   boilerplate.

List of typed items
~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   rules = [{'type': 'list', 'items': {'type': 'int', 'range': (1, 100)}}]

   result = validate_data([[10, 50, 200, 5]], rules)
   result.errors  # ['[0][2]: number out of range']

List of dicts
~~~~~~~~~~~~~

.. code-block:: python

   rules = [{'type': 'list', 'items': {
       'type': 'dict',
       'fields': {
           'name':  {'type': 'str'},
           'score': {'type': 'int', 'range': (0, 100)},
       }
   }}]

   result = validate_data(
       data=[[
           {'name': 'Alice', 'score': 95},
           {'name': 'Bob',   'score': 150},   # invalid
       ]],
       rule=rules,
   )

   result.errors  # ['[0][1].score: number out of range']

----

Transforms
----------

A ``transform`` is applied to a value **before** any validation runs. The
transformed value is what gets checked — and what is returned in
``result.data`` when ``mutate=True``.

Simple callable
~~~~~~~~~~~~~~~

.. code-block:: python

   rules = [{'type': 'str', 'transform': str.strip, 'length': 5}]
   validate_data(['  hello  '], rules).ok  # True — stripped then checked

Lambda
~~~~~~

.. code-block:: python

   rules = [{'type': 'int', 'transform': lambda v: v * 2}]
   result = validate_data([5], rules, mutate=True)
   result.data  # [10]

Accessing sibling fields
~~~~~~~~~~~~~~~~~~~~~~~~

Pass a dict with ``func`` and ``pass_data=True`` to receive the full sibling
data dict as a second argument:

.. code-block:: python

   rules = {'keys': {
       'role': {'type': 'str'},
       'username': {
           'type': 'str',
           'transform': {
               'func': lambda value, data: value.upper() if data.get('role') == 'admin' else value,
               'pass_data': True,
           }
       }
   }}

----

Conditional validation
-----------------------

Use ``depends_on`` to validate a field only when a sibling meets a condition.

Value match
~~~~~~~~~~~

.. code-block:: python

   rules = {'keys': {
       'role':        {'type': 'str'},
       'permissions': {
           'type': 'str',
           'depends_on': {'field': 'role', 'value': 'admin'},
           'options': ('full', 'read', 'none'),
       }
   }}

   validate_data({'role': 'user',  'permissions': 'anything'}, rules).ok  # True  — skipped
   validate_data({'role': 'admin', 'permissions': 'full'},     rules).ok  # True
   validate_data({'role': 'admin', 'permissions': 'anything'}, rules).ok  # False

Callable condition
~~~~~~~~~~~~~~~~~~

.. code-block:: python

   rules = {'keys': {
       'age': {'type': 'int'},
       'guardian_name': {
           'type': 'str',
           'depends_on': {
               'field':     'age',
               'condition': lambda age: age < 18,
           },
           'message': 'guardian name required for users under 18',
       }
   }}

.. note::

   ``depends_on`` requires dict input and only works across top-level sibling
   fields. Cross-nested references are not currently supported.

----

Custom error messages
---------------------

Override any default error with a ``{rule}-message`` key:

.. code-block:: python

   rules = [
       {'type': 'int', 'range': (18, 'any'),  'range-message': 'you must be at least 18'},
       {'type': 'str', 'range': (3, 32),      'range-message': 'username must be 3–32 characters'},
       {'type': 'email',                       'message':       'please enter a valid email address'},
       {'type': 'str', 'expression': r'...',  'expression-message': 'invalid format'},
   ]

Use ``message`` for type-level errors and ``<rule>-message`` for
constraint-level errors (``range-message``, ``expression-message``,
``length-message``, etc.).

----

Validating rule dicts
---------------------

If you write a rule dict with an unrecognised key, validatedata raises a
``ValueError`` immediately — before any data is touched — with a suggestion
for what you might have meant:

.. code-block:: python

   validate_data(['hello'], [{'type': 'str', 'nulable': True}])
   # ValueError: Unknown rule key 'nulable' in rule. Did you mean 'nullable'?

You can also call ``check_rule`` directly to validate a rule dict in isolation:

.. code-block:: python

   from validatedata import check_rule

   check_rule({'type': 'str', 'nulable': True})
   # ValueError: Unknown rule key 'nulable' in rule. Did you mean 'nullable'?

   check_rule({'type': 'str', 'nullable': True})   # passes silently

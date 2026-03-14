Decorators
==========

Validatedata provides two decorators for validating function arguments at call
time: ``@validate`` for explicit rules and ``@validate_types`` for annotation-
based validation.

----

@validate
---------

Wraps a function and runs validation against its arguments before the body
executes. The rule argument follows the same format as :func:`validate_data`.

Basic usage
~~~~~~~~~~~

.. code-block:: python

   from validatedata import validate

   @validate(['str|min:3', 'email'])
   def create_user(username, email):
       return f'created {username}'

   create_user('al', 'alice@example.com')
   # returns {'errors': [['invalid string length'], []]}

   create_user('alice', 'alice@example.com')
   # returns 'created alice'

On failure the decorator returns ``{'errors': result.errors}`` by default
instead of calling the function.

Dict rules
~~~~~~~~~~

Pass a dict rule to validate named arguments:

.. code-block:: python

   signup_rules = {'keys': {
       'username': 'str|min:3|max:32',
       'email':    'email',
       'password': 'str|min:8|re:(?=.*[A-Z])(?=.*\d).+',
   }}

   @validate(signup_rules, raise_exceptions=True)
   def signup(username, email, password):
       return 'Account Created'

   signup('alice_99', 'alice@example.com', 'Secure@123')  # works
   signup('alice_99', 'not-an-email',      'weak')         # raises ValidationError

raise_exceptions
~~~~~~~~~~~~~~~~

Set ``raise_exceptions=True`` to raise ``ValidationError`` instead of
returning the error dict:

.. code-block:: python

   from validatedata import validate, ValidationError

   @validate(['email'], raise_exceptions=True)
   def send_email(address):
       ...

   try:
       send_email('not-an-email')
   except ValidationError as e:
       print(e)

mutate
~~~~~~

Set ``mutate=True`` to apply transforms before calling the function. The
function receives the transformed values:

.. code-block:: python

   @validate(['str|strip|lower'], mutate=True)
   def find_user(username):
       # username arrives already stripped and lowercased
       return db.get(username)

   find_user('  Alice  ')   # finds 'alice' in the database

Class methods
~~~~~~~~~~~~~

For regular instance methods, no extra configuration is needed — the decorator
detects ``self`` automatically:

.. code-block:: python

   class User:
       @validate(['str|min:3', 'email'], raise_exceptions=True)
       def signup(self, username, email):
           return 'Account Created'

For ``@classmethod``, pass ``is_class=True``:

.. code-block:: python

   class User:
       @classmethod
       @validate(rule=['str', 'str'], is_class=True)
       def format_name(cls, firstname, lastname):
           return f'{firstname} {lastname}'

Async functions
~~~~~~~~~~~~~~~

The decorator works identically with async functions:

.. code-block:: python

   @validate(signup_rules, raise_exceptions=True)
   async def signup(username, email, password):
       await db.save(username, email, password)
       return 'Account Created'

   # call as normal — validation runs before the coroutine body
   await signup('alice', 'alice@example.com', 'Secure@123')

----

@validate_types
---------------

Validates function arguments against their Python type annotations. No rule
argument is needed — the decorator reads the annotations automatically.

Basic usage
~~~~~~~~~~~

.. code-block:: python

   from validatedata import validate_types

   @validate_types
   def add(a: int, b: int) -> int:
       return a + b

   add(1, 2)       # 3
   add(1, 'two')   # raises ValidationError

The decorator can be used with or without brackets:

.. code-block:: python

   @validate_types                        # no brackets
   def create_user(username: str, age: int):
       ...

   @validate_types()                      # empty brackets — identical
   def create_user(username: str, age: int):
       ...

   @validate_types(raise_exceptions=False)  # with options — brackets required
   def create_user(username: str, age: int):
       ...

.. note::

   ``raise_exceptions`` defaults to ``True`` for ``@validate_types``, unlike
   ``@validate`` and ``validate_data`` where it defaults to ``False``.

Return annotations are ignored. Only parameter annotations are validated.

Async support
~~~~~~~~~~~~~

Works identically with async functions:

.. code-block:: python

   @validate_types
   async def fetch_user(user_id: int) -> dict:
       return await db.get(user_id)

Class methods
~~~~~~~~~~~~~

The ``self`` parameter is ignored automatically for instance methods. For
``@classmethod``, pass ``is_class=True``:

.. code-block:: python

   class Calculator:
       @validate_types(is_class=True)
       @classmethod
       def multiply(cls, a: int, b: int) -> int:
           return a * b

----

Parameters (both decorators)
-----------------------------

.. list-table::
   :header-rows: 1
   :widths: 25 15 15 45

   * - Parameter
     - Type
     - Default
     - Description
   * - ``raise_exceptions``
     - bool
     - ``False`` (``True`` for ``@validate_types``)
     - Raise ``ValidationError`` on failure instead of returning ``{'errors': [...]}``
   * - ``is_class``
     - bool
     - ``False``
     - Set ``True`` for ``@classmethod`` without ``self``
   * - ``mutate``
     - bool
     - ``False``
     - Apply transforms before calling the function. Transformed values are passed as arguments
   * - ``log_errors``
     - bool
     - ``False``
     - Log background errors
   * - ``group_errors``
     - bool
     - ``True``
     - Return errors grouped by field. Set ``False`` for a flat list

----

Return values
-------------

When validation passes, the original function is called and its return value
is returned normally.

When validation fails and ``raise_exceptions=False`` (the default for
``@validate``), the decorator returns:

.. code-block:: python

   {'errors': result.errors}

When ``raise_exceptions=True``, a ``ValidationError`` is raised instead.

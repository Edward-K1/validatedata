Quick Start
===========

Installation
------------

.. code-block:: bash

   pip install validatedata

For extended phone number validation (national, international, and
region-specific formats):

.. code-block:: bash

   pip install phonenumbers

----

Your first validation
---------------------

.. code-block:: python

   from validatedata import validate_data

   rule = {
       'username': 'str|min:3|max:32',
       'email': 'email',
       'age': 'int|min:18',
   }

   result = validate_data(
       data={'username': 'alice', 'email': 'alice@example.com', 'age': 25},
       rule=rule,
   )

   if result.ok:
       print('valid!')
   else:
       print(result.errors)

Rules are plain strings or dicts — no classes to define, no schema objects to
import. The rule above uses :doc:`pipe-syntax shorthand <rules>` — each field
is a type name followed by modifiers chained with ``|``.

For stricter or more complex rules the dict form is always available alongside
the shorthand:

.. code-block:: python

   rule = {
       'username': {'type': 'str', 'range': (3, 32)},
       'email':    {'type': 'email', 'message': 'please enter a valid email'},
       'age':      {'type': 'int', 'range': (18, 'any'), 'range-message': 'must be 18 or older'},
   }

----

The ``keys`` wrapper
--------------------

For simple field maps the bare dict form (shown above) is fine. When you need
to pair field rules with top-level options — or when you prefer an explicit
marker — wrap the field map in ``{'keys': {...}}``:

.. code-block:: python

   rule = {'keys': {
       'username': 'str|min:3|max:32',
       'email': 'email',
       'age': 'int|min:18',
   }}

Both forms behave identically today.

----

Reading the result
------------------

:func:`validate_data` always returns a result object with three attributes:

.. list-table::
   :header-rows: 1
   :widths: 20 80

   * - Attribute
     - Description
   * - ``result.ok``
     - ``True`` if all fields passed, ``False`` otherwise
   * - ``result.errors``
     - List of error messages, grouped by field by default
   * - ``result.data``
     - Transformed values — only present when ``mutate=True`` is passed.
       The shape mirrors the input: a ``dict`` input returns a ``dict`` keyed
       by field name; a ``list`` or ``tuple`` input returns a ``list`` indexed
       by position

.. code-block:: python

   result = validate_data(data, rule)

   if result.ok:
       # proceed
       pass
   else:
       for group in result.errors:
           print(group)

----

Three ways to validate
-----------------------

Validatedata offers three entry points depending on where and how you want
validation to run.

validate_data
~~~~~~~~~~~~~

The core function. Pass data and a rule, get a result back.

.. code-block:: python

   result = validate_data(data={'name': 'alice', 'age': 25}, rule={
       'name': 'str|min:3',
       'age': 'int|min:18',
   })

@validate decorator
~~~~~~~~~~~~~~~~~~~

Wraps a function and validates its arguments before the body runs. On failure
it returns ``{'errors': [...]}`` instead of calling the function (or raises
``ValidationError`` if ``raise_exceptions=True``).

.. code-block:: python

   from validatedata import validate

   @validate(['str|min:3', 'email'], raise_exceptions=True)
   def create_user(username, email):
       return f'created {username}'

See :doc:`decorators` for the full decorator reference.

@validate_types decorator
~~~~~~~~~~~~~~~~~~~~~~~~~

Validates arguments against their Python type annotations automatically — no
rule argument needed.

.. code-block:: python

   from validatedata import validate_types

   @validate_types
   def add(a: int, b: int) -> int:
       return a + b

   add(1, 2)      # fine
   add(1, 'two')  # raises ValidationError

----

Parameters
----------

All three entry points share most parameters:

.. list-table::
   :header-rows: 1
   :widths: 25 15 15 45

   * - Parameter
     - Type
     - Default
     - Description
   * - ``rule``
     - str / list / dict
     - required
     - Validation rules — see :doc:`rules`
   * - ``raise_exceptions``
     - bool
     - ``False``
     - Raise ``ValidationError`` on failure instead of returning errors. Default is ``True`` for ``@validate_types``
   * - ``is_class``
     - bool
     - ``False``
     - Set ``True`` for ``@classmethod`` without ``self``
   * - ``mutate``
     - bool
     - ``False``
     - Apply transforms and return the modified values in ``result.data``
   * - ``log_errors``
     - bool
     - ``False``
     - Log background validation errors (pass via ``kwds``)
   * - ``group_errors``
     - bool
     - ``True``
     - Return errors grouped by field. Set ``False`` for a flat list

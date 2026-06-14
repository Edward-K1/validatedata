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
import.

----

Six ways to validate
--------------------

Validatedata offers six entry points, from ultra‑fast boolean checks to automatic
package‑wide validation.

1. **`validator()`** – fastest, boolean only
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from validatedata import validator

   is_valid_username = validator('str|min:3|max:32')
   if is_valid_username('alice'):
       print('ok')

2. **`validate_data_fast()`** – compiled speed + error messages (experimental)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from validatedata import validate_data_fast

   result = validate_data_fast({'name': 'alice'}, {'name': 'str|min:3'})
   if not result.ok:
       print(result.errors)   # full error messages

   # This is a preview of the next‑generation engine and will eventually
   # replace validate_data.

3. **`validate_data()`** – general purpose
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   result = validate_data(data, rule, mutate=False)

4. **`@validate` decorator**
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from validatedata import validate

   @validate(['str|min:3', 'email'])
   def create_user(username, email):
       return f'created {username}'

5. **`@validate_types` decorator**
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from validatedata import validate_types

   @validate_types
   def add(a: int, b: int) -> int:
       return a + b

6. **Auto‑validation of modules / packages**
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from validatedata import autovalidate

   # Place this at the bottom of a module
   autovalidate(module=__name__, raise_exceptions=True)

   # Or validate an entire package
   from validatedata import autovalidate_package
   autovalidate_package('my_package', include=['my_package.*'], dry_run=False)

See :doc:`autovalidate` and :doc:`fast-validator` for details.

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

:func:`validate_data` and :func:`validate_data_fast` return a result object with:

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
       The shape mirrors the input.

.. code-block:: python

   result = validate_data(data, rule)

   if result.ok:
       # proceed
       pass
   else:
       for group in result.errors:
           print(group)

----

Parameters
----------

All entry points share most parameters:

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
     - ``False`` (``True`` for ``@validate_types``)
     - Raise ``ValidationError`` on failure instead of returning errors
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
     - Log background validation errors
   * - ``group_errors``
     - bool
     - ``True``
     - Return errors grouped by field. Set ``False`` for a flat list
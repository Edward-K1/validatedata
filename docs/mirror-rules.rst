Mirror-Structure Rules
======================

.. versionadded:: 0.4.0

Mirror-structure rules let you write validation rules whose shape matches the
shape of your data. Instead of wrapping every nested dict in explicit
``{'type': 'dict', 'fields': {...}}`` boilerplate, you can write a rule dict
that looks like the data dict.

----

The problem with explicit nested rules
--------------------------------------

The canonical way to validate a nested dict requires repeating structural
keywords at every level:

.. code-block:: python

   # data
   data = {
       'app': {
           'name': 'QuickScript',
           'version': '1.0.0',
       },
       'database': {
           'host': '127.0.0.1',
           'port': 5432,
       },
   }

   # canonical rule — verbose
   rule = {'keys': {
       'app': {
           'type': 'dict',
           'fields': {
               'name':    {'type': 'str',    'range': (3, 'any')},
               'version': {'type': 'semver'},
           }
       },
       'database': {
           'type': 'dict',
           'fields': {
               'host': {'type': 'ip'},
               'port': {'type': 'int', 'range': (1, 65535)},
           }
       },
   }}

Every nested dict adds two layers (``type`` and ``fields``) that carry no
information beyond "this is a dict with these fields" — which the data already
shows.

----

Mirror-structure shorthand
---------------------------

With mirror-structure rules, the rule mirrors the data exactly. Any dict that
has no ``type``, ``fields``, or ``items`` key is treated as a field map and
expanded automatically:

.. code-block:: python

   # data
   data = {
       'app': {
           'name': 'QuickScript',
           'version': '1.0.0',
       },
       'database': {
           'host': '127.0.0.1',
           'port': 5432,
       },
   }

   # mirror rule — matches the shape of the data
   rule = {
       'app': {
           'name':    'str|min:3',
           'version': 'semver',
       },
       'database': {
           'host': 'ip',
           'port': 'int|between:1,65535',
       },
   }

   result = validate_data(data=data, rule=rule)
   result.ok  # True

The rule is structurally identical to the data. Field names appear once and
each leaf value is the rule for that field.

----

Error paths
-----------

Errors are reported with the full dotted path to the failing field, the same
as canonical nested rules:

.. code-block:: python

   result = validate_data(
       data={'app': {'name': 'ab', 'version': '1.0.0'}},
       rule={'app': {'name': 'str|min:3', 'version': 'semver'}},
   )

   result.ok      # False
   result.errors  # ['app.name: invalid string length']

----

Multi-level nesting
-------------------

The shorthand recurses to any depth. Each level of the rule just mirrors the
corresponding level of the data:

.. code-block:: python

   data = {
       'company': {
           'address': {
               'postcode': 'AB1 2CD',
           }
       }
   }

   rule = {
       'company': {
           'address': {
               'postcode': 'str|min:6',
           }
       }
   }

   result = validate_data(data=data, rule=rule)
   result.ok  # True

If a field at a deeply nested path fails, the full path appears in the error:

.. code-block:: python

   result = validate_data(
       data={'company': {'address': {'postcode': '123'}}},
       rule={'company': {'address': {'postcode': 'str|min:6'}}},
   )

   result.errors  # ['company.address.postcode: invalid string length']

----

Mixing flat and nested rules
-----------------------------

Top-level fields can freely mix flat shorthand rules and mirror-structure
nested dicts:

.. code-block:: python

   data = {
       'owner': 'alice',
       'company': {
           'address': {
               'postcode': 'AB1 2CD',
           }
       }
   }

   rule = {
       'owner':   'str|min:3',           # flat rule for a scalar field
       'company': {                       # mirror structure for a nested dict
           'address': {
               'postcode': 'str|min:6',
           }
       }
   }

   validate_data(data=data, rule=rule).ok  # True

----

Using the ``keys`` wrapper
---------------------------

The bare field map and the ``keys`` wrapper both support mirror-structure
rules and behave identically:

.. code-block:: python

   # bare field map
   rule = {
       'app': {'name': 'str|min:3', 'version': 'semver'},
   }

   # keys wrapper — equivalent
   rule = {'keys': {
       'app': {'name': 'str|min:3', 'version': 'semver'},
   }}

----

Transforms on nested fields
----------------------------

Pipe-syntax transforms work inside mirror rules at any depth. When
``mutate=True`` is passed, transformed values are reflected in the
reconstructed output:

.. code-block:: python

   result = validate_data(
       data={'user': {'profile': {'name': '  alice  '}}},
       rule={'user': {'profile': {'name': 'str|strip|min:3'}}},
       mutate=True,
   )

   result.ok               # True
   result.data[0]          # {'profile': {'name': 'alice'}}  — whitespace stripped

----

Mutate and data reconstruction
-------------------------------

When ``mutate=True`` is passed, ``result.data`` contains the validated
(and transformed) values. For mirror-structure rules the structure is
preserved — ``result.data`` is a list of dicts, not a flat list of leaf
values:

.. code-block:: python

   result = validate_data(
       data={
           'app':      {'name': 'QuickScript', 'version': '1.0.0'},
           'database': {'host': '127.0.0.1',   'port': 5432},
       },
       rule={
           'app':      {'name': 'str|min:3', 'version': 'semver'},
           'database': {'host': 'ip', 'port': 'int|between:1,65535'},
       },
       mutate=True,
   )

   result.ok    # True
   result.data  # [{'name': 'QuickScript', 'version': '1.0.0'}, {'host': '127.0.0.1', 'port': 5432}]

----

Depth limit
-----------

Mirror-structure rules can nest up to **100 levels** deep. Exceeding this
limit raises a ``ValueError`` with the path of the offending node:

.. code-block:: python

   # 101 levels — raises ValueError
   # ValueError: Maximum nesting depth of 100 exceeded at 'x.x.x. ... .x'

This limit exists to prevent runaway recursion from untrusted or
machine-generated rule dicts. In practice, real-world data rarely exceeds
five or six levels.

----

Mixing with explicit dict rules
---------------------------------

You can use explicit ``{'type': 'dict', 'fields': {...}}`` rules alongside
mirror-structure shorthand at any level — they are fully compatible:

.. code-block:: python

   rule = {'keys': {
       'user': {
           # explicit form — use when you need dict-level options (e.g. nullable)
           'type': 'dict',
           'nullable': True,
           'fields': {
               'name': 'str|min:3',
               'role': 'str|in:admin,user,guest',
           }
       },
       'config': {
           # mirror shorthand — no boilerplate
           'theme': 'str|in:light,dark',
           'locale': 'str|length:2',
       }
   }}

Use the explicit form when you need dict-level options such as ``nullable`` or
a custom ``message``. Use the mirror shorthand when the dict structure itself
needs no configuration.

----

Reference: how expansion works
-------------------------------

The mirror shorthand is purely a syntactic convenience. Before validation
runs, the shorthand is expanded into the canonical ``{'type': 'dict', 'fields':
{...}}`` form by ``_expand_shorthand_rule``. The expansion happens
recursively and is transparent — errors, error paths, and ``result.data``
behave identically to manually written canonical rules.

A bare dict like:

.. code-block:: python

   {'app': {'name': 'str|min:3', 'version': 'semver'}}

is expanded to:

.. code-block:: python

   {
       'fields': {
           'app': {
               'fields': {
                   'name':    {'type': 'str', 'range': (3, 'any')},
                   'version': {'type': 'semver', 'message': ''},
               }
           }
       }
   }

before being passed to the validator.

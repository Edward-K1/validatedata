V – Single-Line Type & Constraint Checks
========================================

.. versionadded:: 0.7.0
.. versionchanged:: 0.7.3
   Added a full set of constraint helpers (``between``, ``gt``/``ge``/``lt``/``le``,
   length variants, ``multiple_of``, ``regex``, ``unique``, ``one_of``/``none_of``,
   and string/iterable helpers). ``raise_on_fail`` now covers both type and
   constraint checks.

``V`` answers one question about one value, inline — no ``Rule``, no
``FastModel``, no rule dict.

.. code-block:: python

   from validatedata import V

   if V.int(5):
       ...
   if not V.email(user_input):
       raise ValueError("bad email")

   if V.between(0, 100, score):
       ...
   if V.regex(r"^[A-Z]{3}[0-9]{4}$", code):
       ...

Two families of attributes
--------------------------

- **Type checks** take exactly one argument (the value):
  ``V.int(x)``, ``V.email(x)``, ``V.list(x)``, etc.
- **Constraint checks** take configuration first and the value last:
  ``V.between(lo, hi, value)``, ``V.regex(pattern, value)``,
  ``V.multiple_of(step, value)``.

This consistent shape makes the helpers easy to partially-apply:

.. code-block:: python

   from functools import partial
   is_pct = partial(V.between, 0, 100)
   is_pct(150)   # False

Type checks
-----------

``V`` covers the same base types used elsewhere in the library, plus a few
convenience parsers:

- Scalars / containers: ``bool``, ``int``, ``float``, ``str``, ``list``,
  ``dict``, ``tuple``, ``set``
- Formats / semantics: ``email``, ``url``, ``uuid``, ``ip``, ``phone``,
  ``slug``, ``semver``, ``color``, ``even``, ``odd``, ``prime``
- Special: ``date`` (accepts ``date``/``datetime`` instances or parseable
  strings), ``datetime`` (instances only), ``decimal`` (``Decimal`` or
  cleanly convertible ``str``/``int`` — floats are deliberately rejected),
  ``path`` (``pathlib.Path``, ``str``, or ``os.PathLike``)

Constraint checks
-----------------

All of the following return ``bool`` by default:

**Ranges & comparisons**

- ``V.between(lo, hi, value)`` — numeric range, or length range for
  strings/lists/tuples/sets/dicts
- ``V.gt(bound, value)``, ``V.ge(bound, value)``
- ``V.lt(bound, value)``, ``V.le(bound, value)``

**Length**

- ``V.length(n, value)``
- ``V.min_length(n, value)``
- ``V.max_length(n, value)``

**Membership & content**

- ``V.contains(item, value)``, ``V.excludes(item, value)``
- ``V.starts_with(prefix, value)``, ``V.ends_with(suffix, value)``
- ``V.one_of(options, value)``, ``V.none_of(options, value)``
- ``V.unique(value)`` — every element distinct (works with unhashable items)

**Other**

- ``V.multiple_of(step, value)``
- ``V.regex(pattern, value, flags=0)`` — anchored match (``re.match``),
  patterns are cached

Raising instead of returning ``False``
--------------------------------------

By default a failed check returns ``False``. Call ``V.raise_on_fail(True)``
to switch every predeclared attribute (both type and constraint checks) to a
raising variant:

.. code-block:: python

   V.raise_on_fail(True)
   V.int("not an int")
   # TypeError: expected int, got str

   V.between(0, 100, 150)
   # ValueError: 150 failed constraint between(0, 100)

   V.raise_on_fail(False)   # back to bool-returning
   V.int("not an int")      # False

This is global to the ``V`` class. If you need both behaviours concurrently,
use ``V.check(...)`` with your own ``try``/``except`` instead of toggling
the flag.

Types not predeclared on ``V``
------------------------------

For a type that isn't one of ``V``'s base-type attributes — one you
registered via :func:`register_type`, or a plain Python/stdlib type — use
``V.check()``:

.. code-block:: python

   V.check("datetime", some_dt)
   V.check("MyRegisteredType", obj)

``V.check()`` always returns a bool and does not honour ``raise_on_fail()``.

What ``V`` deliberately doesn't do
----------------------------------

No rule composition, no nesting, no models, no defaults, no nullability
flags. Each attribute answers exactly one question about exactly one value.
For anything that needs multiple constraints combined, defaults,
nullability, or nested models, use ``Rule`` / ``FastModel`` instead.
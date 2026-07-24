V – Single-Line Type Checks
============================

.. versionadded:: 0.7.0

``V`` answers one question about one value, inline — no ``Rule``, no
``FastModel``, no rule dict.

.. code-block:: python

   from validatedata import V

   if V.int(5):
       ...
   if not V.email(user_input):
       raise ValueError("bad email")

``V`` covers the same base types as ``validator()`` — ``int``, ``str``,
``float``, ``bool``, ``list``, ``dict``, ``tuple``, ``set`` — plus format
checks like ``email``, ``url``, ``uuid``, ``date``, ``ip``, ``phone``,
``slug``, ``semver``, ``color``, ``even``, ``odd``, ``prime``, ``decimal``,
``path``. Each is a plain function on the class — nothing to instantiate or
compile.

----

Raising instead of returning ``False``
----------------------------------------

By default a failed check returns ``False``. Call ``V.raise_on_fail(True)`` to
switch every check to a raising variant that throws ``TypeError`` naming the
expected and actual types:

.. code-block:: python

   V.raise_on_fail(True)
   V.int("not an int")
   # TypeError: expected int, got str

   V.raise_on_fail(False)   # back to bool-returning
   V.int("not an int")      # False

This is global to the ``V`` class, not per-call. If you need both behaviors
concurrently, use ``V.check(...)`` with your own ``try``/``except`` instead of
toggling this.

----

Types not predeclared on ``V``
---------------------------------

For a type that isn't one of ``V``'s base-type attributes — one you registered
via :func:`register_type`, or a plain Python/stdlib type — use ``V.check()``:

.. code-block:: python

   V.check("datetime", some_dt)
   V.check("MyRegisteredType", obj)

``V.check()`` always returns a bool and does not honor ``raise_on_fail()``.

----

What ``V`` deliberately doesn't do
--------------------------------------

No rules, no pipe strings, no ``Rule`` composition. Constraint logic (``min``,
``max``, ``pattern``, ``nullable``, ...) belongs to ``Rule``/``FastModel`` —
``V`` only ever answers "is this value this type," optionally loudly.

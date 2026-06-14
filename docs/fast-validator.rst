Fast validation with error messages – ``validate_data_fast``
============================================================

.. versionadded:: 0.6.0 (experimental)

``validate_data_fast`` is a preview of the next‑generation validation engine.
It provides the **the closest speed** to compiled rules **plus full
error messages** and support for nested dicts.

In a future release, ``validate_data_fast`` will
become the default implementation of ``validate_data``, keeping the exact same
API but with dramatically better performance.

Use it today to speed up existing code with minimal changes.

----

Basic usage
-----------

.. code-block:: python

   from validatedata import validate_data_fast

   result = validate_data_fast(
       data={'username': 'al', 'email': 'alice@example.com'},
       rule={
           'username': 'str|min:3|max:32',
           'email': 'email',
       },
   )

   if not result.ok:
       print(result.errors)   # ['username: string too short (minimum length: 3)']

   # It returns the same `ValidationResult` as `validate_data`.

Differences from ``validate_data``
----------------------------------

- **Faster** – uses compiled function calls, no per‑call recursion overhead.
- **No ``defaults`` parameter** (yet) – but you can use `mutate` and `raise_exceptions`.
- **No ``keys`` wrapper** – only bare dict rules (mirror‑structure) are supported.
- **No ``depends_on``** – conditional validation is not yet implemented in the fast path.
- **No custom transforms** – only pipe‑syntax transforms (``strip``, ``lower``, etc.) work.

All other features (pipe syntax, mirror‑structure, ``nullable``, ``range``,
``options``, regex, custom error messages, and nested dicts) are fully supported.

----

Performance comparison
----------------------

For a dict with 5 fields, ``validate_data_fast`` is typically **5–10x faster**
than ``validate_data`` and within 10% of the boolean‑only ``validator()``,
while still returning descriptive error messages.

.. code-block:: python

   # Instead of
   result = validate_data(data, rule)

   # Just change the function name
   result = validate_data_fast(data, rule)

   # Everything else stays the same

----

Current limitations (will be removed before merging)
-----------------------------------------------------

- No support for ``depends_on``.
- No support for custom callable transforms (only named pipe transforms).
- No support for the ``{'keys': {...}}`` wrapper – use bare dicts.
- No support for validating tuple/list of dicts with per‑position rules (but you
  can wrap the list in a dict or use a loop).

These limitations exist because the fast engine is still under development.
They will be resolved before ``validate_data_fast`` replaces ``validate_data``.

----

When to use
-----------

- **Existing projects** – try replacing ``validate_data`` with
  ``validate_data_fast``. If you don't use the unsupported features, you get a
  free performance boost.
- **New projects** – start with ``validate_data_fast`` and switch to
  ``validate_data`` only if you need ``depends_on`` or custom callable
  transforms.
- **High‑throughput APIs** – use ``validator()`` for boolean checks, or
  ``validate_data_fast`` when you need error messages.

----

Feedback
--------

This is an experimental feature. Please report any discrepancies between
``validate_data`` and ``validate_data_fast`` on the issue tracker – they help
us ensure a smooth eventual merge.
Auto‑validation
===============

.. versionadded:: in 0.6.0

Validatedata can automatically apply ``@validate_types`` to every callable with
type hints in a module or an entire package. This removes the need to manually
decorate each function.

----

``autovalidate()`` – single module
----------------------------------

Place this call at the bottom of the module you want to validate:

.. code-block:: python

   # mymodule.py
   from decimal import Decimal
   from validatedata import autovalidate

   def calculate_price(price: Decimal, tax_rate: float) -> Decimal:
       return price * (1 + tax_rate)

   def get_user(user_id: int) -> dict:
       ...

   # Auto‑validate this module
   autovalidate(module=__name__, raise_exceptions=True, type_checkers={Decimal: <your-decimal-checker>})

Now every function with type hints will be validated at call time.

Parameters
~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 25 15 60

   * - Parameter
     - Default
     - Description
   * - ``module``
     - ``None`` (caller's module)
     - Module object or name
   * - ``ignore``
     - ``None``
     - List of strings or regex patterns to skip (fully qualified names)
   * - ``type_checkers``
     - ``None``
     - Additional custom type checkers
   * - ``raise_exceptions``
     - ``True``
     - Whether to raise ``ValidationError`` on failure
   * - ``dry_run``
     - ``False``
     - If ``True``, return list of names that would be decorated without modifying anything

Returns
~~~~~~~

A list of fully qualified names that were decorated.

----

``autovalidate_package()`` – entire package
--------------------------------------------

Walk a package and apply ``@validate_types`` to all matching modules.

.. code-block:: python

   from validatedata import autovalidate_package

   report = autovalidate_package(
       package="my_project",
       include=["my_project.*"],          # glob patterns or regex
       exclude=["my_project.tests.*"],
       raise_exceptions=True,
       dry_run=False,                     # set True to preview
   )

   print(report["decorated"])      # list of decorated callables
   print(report["skipped"])        # (name, reason)
   print(report["import_errors"])  # modules that failed to import

Advanced: auto‑register types from naming conventions
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Set ``auto_register_types=True`` to automatically register any class whose name
matches patterns (e.g. ``*Model``, ``*Entity``) as a custom type. A simple
``isinstance`` check is added, and if the class has a ``validate`` method, it
will be called after the instance check.

.. code-block:: python

   autovalidate_package(
       package="my_project",
       auto_register_types=True,
       custom_type_patterns=["*DTO", "*ValueObject"],
       post_type_validate=True,   # call .validate() on the instance
   )

See the :doc:`rules` section on custom types for more details.
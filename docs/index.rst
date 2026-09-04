validatedata
============

.. image:: https://github.com/Edward-K1/validatedata/actions/workflows/test.yml/badge.svg
   :target: https://github.com/Edward-K1/validatedata/actions
   :alt: Build status

.. image:: https://badge.fury.io/py/validatedata.svg
   :target: https://badge.fury.io/py/validatedata
   :alt: PyPI version

Lightning-fast validation in python.

**Seven validation modes – one simple syntax.**

 1. **`validator()`** – One word: speed. Ideal for high‑throughput streaming. msgspec, handwritten code, and this function will compete for first place.
 2. **`FastModel`** – declarative, typed models with compiled validation, rich error messages, serialization, and one-line bridging from Pydantic, msgspec, or dataclasses.
 3. **`V`** – fast single-line checks for both types and constraints(e.g. ``V.int(5)``, ``V.between(1, 10, 5)``). Returns ``bool`` by default. Call ``V.raise_on_fail(True)`` to raise instead. 
 4. **`validate_data()`** / **`validate_data_fast()`** – general‑purpose validation with detailed errors, nested structures, and optional mutation.
 5. **`@validate`** – decorator for function argument validation.
 6. **`@validate_types`** – decorator that uses Python type annotations.
 7. **`autovalidate` / `autovalidate_package`** – automatically apply `@validate_types` to entire modules or packages.

Validatedata gives you expressive rules and fits naturally into any Python workflow. It can be used by everything from lightweight scripts to high‑volume data processing.

**New in v0.7:**
- **`FastModel.bridge()`** – turn an existing Pydantic model, msgspec `Struct`, or dataclass into a `FastModel` subclass in one line, carrying over field constraints (`min_length`, `ge`/`le`, `pattern`, `Literal` choices, and more) so you get FastModel's compiled validation and serialization without rewriting the model.
- **`V`** – single-line type checks (`V.int(x)`, `V.email(x)`) for when a full `Rule` or `FastModel` is more than you need.
- **Zero hard dependencies** – `python-dateutil` is no longer required. Core install is dependency-free; date validation uses strict ISO-8601 by default (`datetime.fromisoformat`). For the previous flexible parsing (e.g. `"23-Oct-2000"`), install the optional extra:
  ```bash
  pip install validatedata[dates]
  ```

Benchmarks (1 million repetitions)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 28 13 11 13 11 12 12

   * - Test
     - validatedata
     - manual
     - pydantic v2
     - msgspec
     - beartype
     - fastjsonschema
   * - Scalar: type (int)
     - 0.0968s
     - 0.0779s
     - 0.3878s
     - 0.0947s
     - 0.3384s
     - 0.1444s
   * - Scalar: type + range
     - 0.1160s
     - 0.1267s
     - 0.1249s
     - 0.1276s
     - 0.3628s
     - 0.1447s
   * - Dict (valid)
     - 0.8388s
     - 0.8943s
     - 2.5218s
     - 1.2571s
     - 
     - 3.8539s
   * - Dict (invalid)
     - 0.2005s
     - 0.1830s
     - 2.5063s
     - 0.7378s
     - 
     - 3.1960s

.. note::
   The “manual” column represents hand‑written `if` statements – fastest but not reusable or composable. Validatedata’s small overhead buys you maintainability and expressiveness.

**Key features**

- Compact pipe-syntax shorthand: ``'str|strip|min:3|max:32'``
- Mirror-structure rules that match the shape of your data
- Rich built-in types: ``email``, ``url``, ``ip``, ``uuid``, ``semver``, ``slug``, ``color``, ``phone``, and more
- Function and method decorators with async support
- Conditional validation, transforms, and custom error messages
- Auto‑validation of entire packages
- Register your own custom types

----

.. toctree::
   :maxdepth: 2
   :caption: Getting started

   quickstart

.. toctree::
   :maxdepth: 2
   :caption: Guides

   rules
   mirror-rules
   decorators
   autovalidate
   fast-validator
   fastmodel
   v
   examples

.. toctree::
   :maxdepth: 1
   :caption: Project

   changelog
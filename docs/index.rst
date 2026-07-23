validatedata
============

.. image:: https://github.com/Edward-K1/validatedata/actions/workflows/test.yml/badge.svg
   :target: https://github.com/Edward-K1/validatedata/actions
   :alt: Build status

.. image:: https://badge.fury.io/py/validatedata.svg
   :target: https://badge.fury.io/py/validatedata
   :alt: PyPI version

An easier way to validate data in python.

**Seven validation modes – one simple syntax.**

 1. **`validator()`** – One word: speed. Ideal for high‑throughput streaming. msgspec, handwritten code, and this function will compete for first place.
 2. **`FastModel`** – declarative, typed models with compiled validation, rich error messages, and serialization.
 3. **`V`** – fast validation using simple inline checks, e.g if V.int(5), V.email("not"). Returns bool by default but user can enable exceptions
 4. **`validate_data()`** / **`validate_data_fast()`** – general‑purpose validation with detailed errors, nested structures, and optional mutation.
 4. **`@validate`** – decorator for function argument validation.
 5. **`@validate_types`** – decorator that uses Python type annotations.
 6. **`FastModel`** – declarative, typed models with compiled validation, rich error messages, and serialization.
 7. **`autovalidate` / `autovalidate_package`** – automatically apply `@validate_types` to entire modules or packages.

Validatedata gives you expressive rules and fits naturally into any Python workflow. It can be used in lightweight scripts, Web APIs, and high‑volume data processing.

**New in v0.6:**
- **`FastModel`** – declarative models with compiled validation, cross‑field checks, and zero‑overhead serialization.
- **`validate_data_fast`** – the speed of `validator()` combined with rich error messages. This is an **experimental** fast path that will eventually replace `validate_data` once the API stabilises.
- **`autovalidate` & `autovalidate_package`** – automatically apply `@validate_types` to whole modules or packages.
- **Custom type registration** – add your own type checkers with `register_type` / `unregister_type`.
- **`check_rule`** – validate rule dicts before using them.
- **`VALID_RULE_KEYS`** – introspection of all recognised rule keys.

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
   examples

.. toctree::
   :maxdepth: 1
   :caption: Project

   changelog
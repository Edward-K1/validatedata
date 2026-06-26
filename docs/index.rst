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
 2. **`validate_data_fast()`** – same compiled speed but with **full error messages** (preview of the next‑gen engine).
 3. **`validate_data()`** – general‑purpose validation with detailed errors, nested structures, and optional mutation.
 4. **`@validate`** – decorator for function argument validation.
 5. **`@validate_types`** – decorator that uses Python type annotations.
 6. **`FastModel`** – declarative, typed models with compiled validation, rich error messages, and serialization.
 7. **`autovalidate` / `autovalidate_package`** – automatically apply `@validate_types` to entire modules or packages.

Validatedata gives you expressive, inline validation rules without defining model classes. It fits naturally into any Python workflow – from lightweight scripts to high‑volume data processing.

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
     - 0.1109s
     - 0.0842s
     - 0.4254s
     - 0.0793s
     - 0.3594s
     - 0.1478s
   * - Scalar: type + range
     - 0.1508s
     - 0.1286s
     - 0.1314s
     - 0.1353s
     - 0.3841s
     - 0.1493s
   * - Dict (valid)
     - 1.9438s
     - 1.1996s
     - 1.8246s
     - 1.2350s
     - 3.8948s
     - 2.8658s
   * - Dict (invalid)
     - 0.2644s
     - 0.5856s
     - 2.1661s
     - 1.1895s
     - 2.0818s
     - 2.7938s

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
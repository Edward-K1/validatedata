validatedata
============

.. image:: https://github.com/Edward-K1/validatedata/actions/workflows/test.yml/badge.svg
   :target: https://github.com/Edward-K1/validatedata/actions
   :alt: Build status

.. image:: https://badge.fury.io/py/validatedata.svg
   :target: https://badge.fury.io/py/validatedata
   :alt: PyPI version

An easier way to validate data in python.

**Two validation modes, one simple syntax.**

- **High‑performance mode** – use `validator()` to compile rules into fast boolean callables. Ideal for data streams, and anywhere you need maximum throughput.  

- **General‑purpose mode** – use `validate_data` or decorators (`@validate`, `@validate_types`) to get detailed error messages, nested validation, and optional mutation. Perfect for light APIs, CLI tools, scripts, and forms.

Validatedata gives you expressive, inline validation rules without defining model classes. It fits naturally into any Python workflow – from lightweight scripts to high‑volume data processing.

**New in v0.5:** The validator() fast path for dramatic performance gains (see benchmarks below).

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


**Key features**

- Compact pipe-syntax shorthand: ``'str|strip|min:3|max:32'``
- Mirror-structure rules that match the shape of your data
- Rich built-in types: ``email``, ``url``, ``ip``, ``uuid``, ``semver``, ``slug``, ``color``, ``phone``, and more
- Function and method decorators with async support
- Conditional validation, transforms, and custom error messages

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
   examples

.. toctree::
   :maxdepth: 1
   :caption: Project

   changelog
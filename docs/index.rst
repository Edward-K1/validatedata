validatedata
============

.. image:: https://github.com/Edward-K1/validatedata/actions/workflows/test.yml/badge.svg
   :target: https://github.com/Edward-K1/validatedata/actions
   :alt: Build status

.. image:: https://badge.fury.io/py/validatedata.svg
   :target: https://badge.fury.io/py/validatedata
   :alt: PyPI version

An easier way to validate data in Python.

Validatedata is for when you want expressive, inline validation rules without
defining model classes. It is not a Pydantic alternative — it is a different
tool for a different workflow: scripts, lightweight APIs, CLI tools, and
anywhere defining a full model class feels like overkill.

**Key features**

- Compact pipe-syntax shorthand: ``'str|min:3|max:32|strip'``
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

Changelog
=========

----

0.4.0 (upcoming)
-----------------

Added
~~~~~

- **Mirror-structure rules** — rule dicts now mirror the shape of the data.
  Any dict without a ``type``, ``fields``, or ``items`` key is treated as a
  nested field map and expanded automatically. See :doc:`mirror-rules` for
  the full guide.

  .. code-block:: python

     # before (canonical form)
     rule = {'keys': {
         'app': {
             'type': 'dict',
             'fields': {
                 'name':    {'type': 'str', 'range': (3, 'any')},
                 'version': {'type': 'semver'},
             }
         }
     }}

     # after (mirror shorthand)
     rule = {
         'app': {
             'name':    'str|min:3',
             'version': 'semver',
         }
     }

- **Unknown rule key detection** — passing an unrecognised key in a rule dict
  now raises a ``ValueError`` immediately with a did-you-mean suggestion:

  .. code-block:: python

     validate_data(['hello'], [{'type': 'str', 'nulable': True}])
     # ValueError: Unknown rule key 'nulable' in rule. Did you mean 'nullable'?

  This catches misspellings at rule-definition time, not buried in a
  validation result.

- **``check_rule``** — new public function that validates a rule dict in
  isolation, useful for testing rules before wiring them into application code:

  .. code-block:: python

     from validatedata import check_rule

     check_rule({'type': 'str', 'nulable': True})    # raises ValueError
     check_rule({'type': 'str', 'nullable': True})   # passes

- **``VALID_RULE_KEYS``** — exported frozenset of all recognised rule dict
  keys, available for introspection.

----

Fixed
~~~~~

- **``nullable`` now short-circuits fully** — previously, ``nullable: True``
  only bypassed the type check. Transforms and constraint rules (``length``,
  ``range``, etc.) would still run on ``None`` values, causing errors.
  ``None`` on a nullable field now skips the entire validation pipeline.

0.3.x
-----

Added
~~~~~

- ``nullable`` rule key — allow ``None`` as a valid value for any field
- ``depends_on`` rule key — validate a field conditionally based on the value
  of a sibling field. Supports both equality checks and callable conditions
- ``transform`` rule key — apply a callable to a value before validation runs.
  Supports simple callables, lambdas, and ``{'func': ..., 'pass_data': True}``
  for transforms that need access to sibling fields
- ``mutate`` parameter on ``validate_data`` and ``@validate`` — apply
  transforms and return the modified values in ``result.data``
- ``unique`` rule key — list or tuple must contain no duplicate values
- ``{rule}-message`` keys — override the error message for a specific rule
  (e.g. ``range-message``, ``expression-message``) independently of the
  top-level ``message`` key
- Pipe-syntax shorthand — compact ``type|modifier|modifier`` rule strings as
  an alternative to dict rules and the original colon syntax. Supports
  ``strict``, ``nullable``, ``unique``, ``min``, ``max``, ``between``, ``in``,
  ``not_in``, ``starts_with``, ``ends_with``, ``contains``, ``format``,
  ``re``, named transforms (``strip``, ``lstrip``, ``rstrip``, ``lower``,
  ``upper``, ``title``), and ``msg``
- Async support for ``@validate`` and ``@validate_types``
- New built-in types: ``url``, ``ip``, ``uuid``, ``semver``, ``slug``,
  ``color``, ``prime``, ``even``, ``odd``
- ``color`` type with ``format`` variants: ``hex``, ``rgb``, ``hsl``,
  ``named``
- ``phone`` type with extended format support via optional ``phonenumbers``
  dependency

----

0.2.x
------

- dropped python 3.6 support
- added nested dict validation

----

0.1.x
------

- Initial release
- ``validate_data`` function
- Basic types: ``str``, ``int``, ``float``, ``bool``, ``date``, ``email``,
  ``phone`` (E.164)
- Dict input via ``{'keys': {...}}`` wrapper
- Colon-syntax shorthand rule strings
- ``range``, ``length``, ``options``, ``excludes``, ``contains``,
  ``startswith``, ``endswith``, ``expression`` rule keys
- ``strict`` and ``message`` rule keys

Examples
========

These are self-contained examples showing validatedata solving real problems.
Each one reflects a workflow you might actually have — no boilerplate, no
contrived data.

----

User registration
-----------------

A typical sign-up form: username, email, password with strength requirements,
and an optional phone number.

.. code-block:: python

   from validatedata import validate_data

   rule = {
       'username': 'str|strip|min:3|max:32|re:^[\\w.-]+$|msg:username must be 3–32 characters, letters, digits, dots, or hyphens only',
       'email':    'email|msg:please enter a valid email address',
       'password': 'str|min:8|re:(?=.*[A-Z])(?=.*\\d).+|msg:password must be at least 8 characters with one uppercase letter and one digit',
       'phone':    'phone|nullable',
   }

   result = validate_data(
       data={
           'username': 'alice_99',
           'email':    'alice@example.com',
           'password': 'Secure123',
           'phone':    None,
       },
       rule=rule,
   )

   if result.ok:
       print('registration accepted')
   else:
       # errors are grouped per field — easy to map back to form inputs
       for group in result.errors:
           if group:
               print(group[0])

The ``phone`` field is ``nullable`` so submitting the form without it passes.
Everything else is required and validated in a single call.

----

Flask route with the decorator
-------------------------------

Validate incoming JSON before your route body runs. On failure the decorator
returns the error dict directly — you just need to check for it.

.. code-block:: python

   from flask import Flask, request, jsonify
   from validatedata import validate, ValidationError

   app = Flask(__name__)

   signup_rule = {
       'username': 'str|strip|min:3|max:32',
       'email':    'email',
       'password': 'str|min:8|re:(?=.*[A-Z])(?=.*\\d).+',
   }

   @app.route('/signup', methods=['POST'])
   def signup():
       body = request.get_json()

       result = validate_data(body, signup_rule)
       if not result.ok:
           return jsonify({'errors': result.errors}), 422

       # body is clean — proceed
       user = create_user(body['username'], body['email'], body['password'])
       return jsonify({'id': user.id}), 201

Or register a Flask error handler and use ``raise_exceptions=True`` to keep
the route body completely free of validation logic:

.. code-block:: python

   from validatedata import ValidationError

   @app.errorhandler(ValidationError)
   def handle_validation_error(e):
       return jsonify({'errors': str(e)}), 422

   @app.route('/signup', methods=['POST'])
   @validate(signup_rule, raise_exceptions=True)
   def signup(username, email, password):
       user = create_user(username, email, password)
       return jsonify({'id': user.id}), 201

----

Application config file
-----------------------

Validate a config dict loaded from YAML, TOML, or environment variables before
your app starts. Mirror-structure rules match the shape of the config exactly —
no structural boilerplate required.

.. code-block:: python

   import yaml
   from validatedata import validate_data

   with open('config.yaml') as f:
       config = yaml.safe_load(f)

   # config.yaml looks like:
   #
   # app:
   #   name: MyService
   #   version: 1.4.0
   #   debug: false
   #
   # database:
   #   host: 127.0.0.1
   #   port: 5432
   #   name: mydb
   #
   # server:
   #   host: 0.0.0.0
   #   port: 8080

   rule = {
       'app': {
           'name':    'str|min:1',
           'version': 'semver',
           'debug':   'bool',
       },
       'database': {
           'host': 'ip',
           'port': 'int|between:1,65535',
           'name': 'str|min:1',
       },
       'server': {
           'host': 'ip',
           'port': 'int|between:1024,65535',
       },
   }

   result = validate_data(data=config, rule=rule)

   if not result.ok:
       for error in result.errors:
           print(f'Config error: {error}')
       raise SystemExit('Invalid configuration — aborting startup')

Bad config fails loudly at startup with a clear field path
(e.g. ``database.port: invalid integer``) rather than surfacing as a
cryptic runtime error later.

----

Bulk data import
----------------

Validate rows before writing them to a database. Collect all errors up front
so you can report the bad rows without stopping at the first failure.

.. code-block:: python

   from validatedata import validate_data

   row_rule = [
       'str|strip|min:1|max:128',    # name
       'email',                       # email
       'int|min:0',                   # age
       'str|in:active,inactive',      # status
   ]

   rows = [
       ['Alice',  'alice@example.com',  30, 'active'],
       ['',       'bob@example.com',    25, 'active'],    # blank name
       ['Carol',  'not-an-email',       28, 'active'],    # bad email
       ['Dave',   'dave@example.com',  -1,  'pending'],   # bad age, bad status
   ]

   bad_rows = []

   for i, row in enumerate(rows):
       result = validate_data(row, row_rule)
       if not result.ok:
           bad_rows.append({'row': i + 1, 'errors': result.errors})

   if bad_rows:
       for entry in bad_rows:
           print(f"Row {entry['row']}: {entry['errors']}")
   else:
       write_to_database(rows)

Running through all rows before writing means you can return a full report
to the user — not just the first bad row.

----

Conditional fields on a checkout form
--------------------------------------

Delivery method determines which fields are required. ``depends_on`` skips
validation on a field entirely when the condition isn't met.

.. code-block:: python

   from collections import OrderedDict
   from validatedata import validate_data

   rule = {
       'delivery_method': 'str|in:pickup,delivery',
       'address': {
           'type':       'str',
           'range':      (10, 'any'),
           'depends_on': {'field': 'delivery_method', 'value': 'delivery'},
           'message':    'a delivery address is required',
       },
       'promo_code': {
           'type':     'str',
           'length':   8,
           'nullable': True,
           'message':  'promo code must be exactly 8 characters',
       },
   }

   # pickup — address is skipped, promo code is optional
   result = validate_data(
       data=OrderedDict([
           ('delivery_method', 'pickup'),
           ('address',         None),
           ('promo_code',      None),
       ]),
       rule=rule,
   )
   result.ok  # True

   # delivery without address — fails
   result = validate_data(
       data=OrderedDict([
           ('delivery_method', 'delivery'),
           ('address',         None),
           ('promo_code',      None),
       ]),
       rule=rule,
   )
   result.ok     # False
   result.errors # [[], ['a delivery address is required', 'a delivery address is required'], []]

----

Normalising data before saving
-------------------------------

Use transforms with ``mutate=True`` to clean user input in the same pass as
validation. The function receives the cleaned values — no separate sanitisation
step needed.

.. code-block:: python

   from validatedata import validate

   @validate(
       rule={
           'username': 'str|strip|lower|min:3|max:32',
           'bio':      'str|strip|max:280|nullable',
           'website':  'url|nullable',
       },
       mutate=True,
   )
   def update_profile(username, bio, website):
       # username is already stripped and lowercased
       # bio is stripped, website is validated
       db.update(username=username, bio=bio, website=website)
       return 'profile updated'

   update_profile(
       username='  Alice_99  ',
       bio='  Building things.  ',
       website='https://alice.dev',
   )
   # saves username='alice_99', bio='Building things.'  — whitespace stripped

Input arrives messy, your function receives it clean. No intermediate
variables, no separate call to ``.strip()`` or ``.lower()``.

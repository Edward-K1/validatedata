FastModel – Declarative Models
==============================

.. versionadded:: 0.6.0

`FastModel` is a declarative validation model built on validatedata's compiled core. It combines the speed of `validator()` with the convenience of typed, reusable models – ideal for API schemas, configuration objects, and domain entities.

----

Basic usage
-----------

Define a model by subclassing `FastModel` and annotating fields with types. Use `Rule` to add validation constraints.

.. code-block:: python

   from validatedata import FastModel, Rule

   class User(FastModel):
       id: int
       username: str = Rule(min=3, max=32, pattern=r'^[a-z0-9_]+$')
       email: str = Rule("email")          # pipe syntax works too
       tags: list[str] = Rule(default=[], init_new=True, max_items=20)

   # Instantiate – validates on creation
   user = User(id=1, username="alice", email="alice@example.com")

   # Invalid data raises ValidationError
   try:
       bad = User(id=1, username="a", email="not-an-email")
   except ValidationError as e:
       print(e.errors)   # {'username': [...], 'email': [...]}

----

Cross‑field validation
----------------------

Implement a `model_check` method to run cross‑field logic. It receives a dict of all field values and can mutate them by returning a dict.

.. code-block:: python

   class Order(FastModel):
       start: int
       end: int

       def model_check(self, data: dict):
           if data["end"] <= data["start"]:
               raise ValidationError({"end": ["end must be greater than start"]})
           # Optionally mutate
           return {"end": data["end"] + 1}   # add one day

----

Serialisation / Deserialisation
-------------------------------

Models can be converted to dicts and reconstructed.

.. code-block:: python

   # to dict
   data = user.to_dict()   # {'id': 1, 'username': 'alice', ...}

   # recommeded if you want speed. its the same as from_dict(data, validate="check")
   user2 = User.from_dict(data)

   # from dict – full validation (raises on invalid)
   user3 = User.from_dict(data, validate=True)

   # from dict – check only, returns None on invalid
   user4 = User.from_dict(data, validate="check")
   
   # never use unless you validated the data earlier and you trust it
   user5 = User.from_dict(data, validate=False)

Nested models are automatically handled:

.. code-block:: python

   class Address(FastModel):
       street: str
       city: str

   class User(FastModel):
       name: str
       address: Address

   data = {"name": "Alice", "address": {"street": "123 Main St", "city": "Springfield"}}
   user = User.from_dict(data)   # address is automatically converted to Address instance

----

Partial validation (no instantiation)
--------------------------------------

Use `check` to validate a dict without creating an instance.

.. code-block:: python

   ok, errors = User.check({"username": "alice", "email": "alice@example.com"})
   if not ok:
       print(errors)

----

Fast boolean checks
-------------------

Use `is_valid` on an instance or `is_valid_data` on a class for a fast boolean check.

.. code-block:: python

   if user.is_valid():        # whole model
       ...

   if user.is_valid(field="username"):   # single field
       ...

   if User.is_valid_data({"username": "alice"}):   # class‑level, dict only
       ...

----

Schema introspection
--------------------

`schema()` returns a lightweight description of the model fields – useful for documentation or API generation.

.. code-block:: python

   User.schema()
   # {
   #   "model": "User",
   #   "fields": {
   #     "username": {"rule": "str|min:3|max:32|re:...", "required": True},
   #     "email":    {"rule": "email", "required": True},
   #     "tags":     {"rule": None, "required": False, "default": []},
   #   }
   # }


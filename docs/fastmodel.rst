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
       id: int = Rule(type="int")
       username: str = Rule(min=3, max=32, pattern=r'^[a-z0-9_]+$')
       email: str = Rule("email")          # pipe syntax works too
       tags: list[str] = Rule(default=[], init_new=True, max=20)

   # Instantiate – validates on creation
   user = User(id=1, username="alice", email="alice@example.com")

   # Invalid data raises ValidationError
   try:
       bad = User(id=1, username="a", email="not-an-email")
   except ValidationError as e:
       print(e.errors)   # {'username': [...], 'email': [...]}

----

Full example — most `Rule` options at once
--------------------------------------------

The example below is deliberately dense: it exercises nearly every `Rule`
option and shows the two syntaxes side by side. Keyword form with an
explicit ``type=`` is preferred for non-``str`` types and for anything past
a bare type check; pipe strings remain fully supported and are shown here
both as a fallback and for cases the keyword shortcuts don't cover.

.. code-block:: python

   from validatedata import FastModel, Rule, ValidationError


   class Address(FastModel):
       """Nested model — used as a field type on Order below."""

       # Keyword form with an explicit type=, since "str" needs no extra
       # constraints here beyond a length range.
       street: str = Rule(type="str", min=3, max=64)

       # Pipe-string form (fallback / shortform) — identical result to
       # Rule(type="str", pattern=r'^[A-Za-z ]+$'), just written as one string.
       city: str = Rule("str|re:^[A-Za-z ]+$")

       # pattern kwarg -> compiled to |re: internally. Also shows nullable=True
       # as an explicit keyword instead of appending "|nullable" by hand.
       postal_code: str = Rule(type="str", pattern=r'^[0-9]{4,10}$', nullable=True)


   class Order(FastModel):
       """
       Exercises keyword constraints with explicit type=, pipe-string
       fallback, choices, regex patterns, transforms, custom messages,
       nullable fields, mutable defaults via init_new, a default_factory,
       a nested FastModel field, and cross-field validation via model_check.
       """

       # --- required scalar fields, keyword form with explicit type= ---
       order_id: str = Rule(type="str", pattern=r'^ORD-[0-9]{6}$')

       # int with min/max and a custom failure message
       priority: int = Rule(type="int", min=1, max=5, msg="priority must be 1-5")

       # choices -> compiled to "in:pending,paid,shipped,cancelled"
       status: str = Rule(type="str", choices=["pending", "paid", "shipped", "cancelled"])

       # transforms kwarg: strip + lower BEFORE the pattern check runs
       customer_email: str = Rule(type="email", transforms="strip|lower")

       # Pipe-string-only fallback showing the exact same transform pipeline
       # written by hand, for cases where the shortform keywords don't fit.
       coupon_code: str = Rule("str|strip|upper|min:4|max:12|nullable")

       # --- floats / numeric edge types ---
       discount_rate: float = Rule(type="float", min=0.0, max=1.0, msg="discount_rate must be between 0 and 1")

       # --- nullable without touching the pipe string directly ---
       gift_message: str = Rule(type="str", max=200, nullable=True)

       # --- mutable defaults ---
       # init_new=True gives every Order instance its own fresh list, instead
       # of sharing one mutable default across instances.
       tags: list[str] = Rule("list[str]", default=[], init_new=True, max=20)  # item type enforced
       # default_factory is the explicit-callable equivalent of init_new for
       # cases where the container needs custom construction logic.
       metadata: dict = Rule(type="dict", default_factory=dict)

       # --- nested FastModel field ---
       # A dict passed for this field is converted into an Address instance
       # (recursively validated) when built via from_dict — see below.
       shipping_address: Address

       # Plain list field (count constraints only — a single Rule can't
       # express a per-item schema; use validate_data()'s dict-rule 'items'
       # key for that instead).
       items: list = Rule(type="list", min=1)

       def model_check(self, data: dict):
           """Cross-field logic that can't live on a single Rule."""
           if data["status"] == "cancelled" and data["discount_rate"] > 0:
               raise ValidationError(
                   {"discount_rate": ["cancelled orders cannot carry a discount"]}
               )
           # Returning a dict mutates fields after validation passes.
           item_count = len(data["items"])
           return {"metadata": {**data["metadata"], "item_count": item_count}}


   # from_dict recursively builds nested FastModel fields (a dict passed for
   # shipping_address is converted into an Address instance automatically).
   # validate=True runs the full __init__ path and raises ValidationError on
   # bad data. Direct Order(...) construction also works, but nested fields
   # must then be passed as already-built model instances (Address(...)),
   # not raw dicts.
   order = Order.from_dict(
       {
           "order_id": "ORD-004821",
           "priority": 3,
           "status": "pending",
           "customer_email": "  Alice@Example.com  ",   # -> stripped + lowercased
           "coupon_code": "save10",                      # -> "SAVE10"
           "discount_rate": 0.1,
           "gift_message": None,
           "shipping_address": {"street": "1 Main St", "city": "Springfield", "postal_code": None},
           "items": [
               {"sku": "ABC-1234", "quantity": 2, "unit_price": 9.99},
               {"sku": "XYZ-0007", "quantity": 1, "unit_price": 24.50},
           ],
       },
       validate=True,
   )

   print(order.customer_email)      # alice@example.com
   print(order.coupon_code)         # SAVE10
   print(order.shipping_address)    # Address(street='1 Main St', city='Springfield', postal_code=None)
   print(order.metadata)            # {'item_count': 2}

.. note::

   ``Rule`` fields are field-scoped only — cross-field logic like the
   cancelled/discount check above always belongs in ``model_check``, never
   on a ``Rule``.

.. tip::

   Every keyword shortcut compiles down to a pipe string internally. If a
   constraint has no dedicated keyword, drop to the pipe string directly —
   both forms can be mixed freely across fields in the same model, as shown
   with ``coupon_code`` above.

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

----

Rule dict and compiled validator access
----------------------------------------

`get_rules()` returns the canonical rule dictionary used at class-creation
time — each value is a pipe string, or a nested rule dict for fields whose
type is a `FastModel` subclass.

.. code-block:: python

   Order.get_rules()["shipping_address"]
   # {'street': 'str|min:3|max:64', 'city': 'str|re:^[A-Za-z ]+$', 'postal_code': 'str|re:^[0-9]{4,10}$|nullable'}

`get_validator()` returns the compiled boolean validator callable for the
whole model — the same function used internally by `is_valid_data` and the
`"check"` branch of `from_dict`.

.. code-block:: python

   validate = User.get_validator()
   validate({"username": "alice", "email": "alice@example.com"})   # True / False
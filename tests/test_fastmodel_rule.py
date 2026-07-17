# tests/test_fastmodel.py
"""
Tests for FastModel declarative validation models.

Covers:
- Basic field validation (int, str, email, etc.)
- Rule with default, init_new, nullable, transforms, custom messages
- Parameterized types (list[str], etc.)
- to_dict and from_dict (recursive serialisation/deserialisation)
- Inheritance (field merging)
- model_check cross-field validation
- Copy method
- Schema method
- Classmethod check (partial validation)
- Error messages (ValidationError)
"""
from __future__ import annotations

import unittest
from datetime import datetime

from validatedata.fastmodel import FastModel
from validatedata.rule import Rule
from validatedata.engine import ValidationError


# ---------------------------------------------------------------------------
# Basic models for testing
# ---------------------------------------------------------------------------

class User(FastModel):
    id: int
    username: str = Rule(min=3, max=32, pattern=r'^[a-z0-9_]+$')
    email: str = Rule("email")
    tags: list[str] = Rule([], init_new=True)
    bio: str = Rule("str|nullable")
    score: float = Rule(type="float", default=0.0)


class Address(FastModel):
    street: str = Rule(min=3)
    city: str = Rule(min=2)
    zipcode: str = Rule(pattern=r'^\d{5}$')


class Person(FastModel):
    name: str
    address: Address


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestFastModelBasic(unittest.TestCase):

    def test_valid_construction(self):
        user = User(
            id=1,
            username="alice_99",
            email="alice@example.com",
            tags=["dev", "ops"],
            bio="I like coding",
            score=95.5
        )
        self.assertEqual(user.id, 1)
        self.assertEqual(user.username, "alice_99")
        self.assertEqual(user.email, "alice@example.com")
        self.assertEqual(user.tags, ["dev", "ops"])
        self.assertEqual(user.bio, "I like coding")
        self.assertEqual(user.score, 95.5)

    def test_missing_required_field_raises(self):

        class Required(FastModel):
            name: str
        with self.assertRaises(ValidationError):
            Required()  # missing 'name'

    def test_nullable_field_accepts_none(self):
        user = User(
            id=1,
            username="alice_99",
            email="alice@example.com",
            bio=None
        )
        self.assertIsNone(user.bio)

    def test_nullable_field_validation_applies_when_not_none(self):
        # bio must be string; if not None, must be str
        with self.assertRaises(ValidationError):
            User(
                id=1,
                username="alice_99",
                email="alice@example.com",
                bio=123  # not None and not str
            )

    def test_default_value(self):
        user = User(id=1, username="alice_99", email="alice@example.com")
        self.assertEqual(user.score, 0.0)

    def test_init_new_creates_fresh_list_per_instance(self):
        u1 = User(id=1, username="alice_99", email="alice@example.com")
        u2 = User(id=2, username="bob_99", email="bob@example.com")
        u1.tags.append("new")
        self.assertEqual(u1.tags, ["new"])
        self.assertEqual(u2.tags, [])

    def test_validation_fails_on_bad_email(self):
        with self.assertRaises(ValidationError):
            User(id=1, username="alice_99", email="not-an-email")

    def test_validation_fails_on_username_too_short(self):
        with self.assertRaises(ValidationError):
            User(id=1, username="a", email="a@b.com")

    def test_validation_fails_on_username_invalid_chars(self):
        with self.assertRaises(ValidationError):
            User(id=1, username="Alice!", email="a@b.com")

    def test_validation_fails_on_score_type(self):
        with self.assertRaises(ValidationError):
            User(id=1, username="alice_99", email="a@b.com", score="not a float")
            


class TestFastModelTransforms(unittest.TestCase):

    class TransformModel(FastModel):
        name: str = Rule("str|strip|lower")

    def test_transform_applied(self):
        m = self.TransformModel(name="  ALICE  ")
        self.assertEqual(m.name, "alice")

    def test_transform_with_validation_after(self):
        class Model(FastModel):
            name: str = Rule("str|strip|lower|min:3")
        # "  Al  " → strip+lower → "al" (len 2) → fails min:3.
        # The bare assignment on the original line was a copy-paste error:
        # both calls use identical input so only one assertRaises block is needed.
        with self.assertRaises(ValidationError):
            Model(name="  Al  ")


class TestFastModelCustomMessage(unittest.TestCase):

    class CustomMsgModel(FastModel):
        age: int = Rule(min=18, msg="You must be at least 18 years old")

    def test_custom_message_on_failure(self):
        with self.assertRaises(ValidationError) as ctx:
            self.CustomMsgModel(age=16)
        self.assertIn("You must be at least 18 years old", str(ctx.exception))


class TestFastModelParameterizedTypes(unittest.TestCase):

    class ListModel(FastModel):
        ids: list[int] = Rule("list[int]")
        tags: list[str] = Rule("list[str]|unique")

    def test_valid_list_int(self):
        m = self.ListModel(ids=[1, 2, 3], tags=["a", "b"])
        self.assertEqual(m.ids, [1, 2, 3])

    def test_invalid_list_int_element(self):
        with self.assertRaises(ValidationError):
            self.ListModel(ids=[1, "two", 3], tags=[])

    def test_unique_validator_on_list(self):
        with self.assertRaises(ValidationError):
            self.ListModel(ids=[1, 2], tags=["a", "a"])

    def test_tuple_parameterized(self):
        class TupleModel(FastModel):
            point: tuple[int, int] = Rule("tuple[int,int]")
        m = TupleModel(point=(10, 20))
        self.assertEqual(m.point, (10, 20))
        with self.assertRaises(ValidationError):
            TupleModel(point=(10, "20"))


class TestFastModelNestedSerialisation(unittest.TestCase):

    def test_nested_to_dict_recursive(self):
        addr = Address(street="123 Main St", city="Springfield", zipcode="12345")
        person = Person(name="Alice", address=addr)
        d = person.to_dict(recursive=True)
        self.assertEqual(d, {
            "name": "Alice",
            "address": {
                "street": "123 Main St",
                "city": "Springfield",
                "zipcode": "12345"
            }
        })

    def test_nested_to_dict_non_recursive(self):
        addr = Address(street="123 Main St", city="Springfield", zipcode="12345")
        person = Person(name="Alice", address=addr)
        d = person.to_dict(recursive=False)
        self.assertEqual(d["name"], "Alice")
        self.assertIsInstance(d["address"], Address)  # not converted

    def test_from_dict_constructs_nested(self):
        data = {
            "name": "Alice",
            "address": {
                "street": "123 Main St",
                "city": "Springfield",
                "zipcode": "12345"
            }
        }
        person = Person.from_dict(data)
        self.assertEqual(person.name, "Alice")
        self.assertIsInstance(person.address, Address)
        self.assertEqual(person.address.street, "123 Main St")
        self.assertEqual(person.address.city, "Springfield")
        self.assertEqual(person.address.zipcode, "12345")

    def test_from_dict_validation_applies_to_nested(self):
        data = {
            "name": "Alice",
            "address": {
                "street": "12",  # too short (min 3)
                "city": "Springfield",
                "zipcode": "12345"
            }
        }
        with self.assertRaises(ValidationError):
            Person.from_dict(data, validate=True)

    def test_to_dict_roundtrip(self):
        original = Person(
            name="Bob",
            address=Address(street="456 Oak Ave", city="Metropolis", zipcode="67890")
        )
        data = original.to_dict(recursive=True)
        reconstructed = Person.from_dict(data)
        self.assertEqual(original.name, reconstructed.name)
        self.assertEqual(original.address.street, reconstructed.address.street)
        self.assertEqual(original.address.city, reconstructed.address.city)
        self.assertEqual(original.address.zipcode, reconstructed.address.zipcode)


class OptionalAddress(FastModel):
    street: str = Rule(min=3, nullable=True)


class Owner(FastModel):
    name: str
    address: OptionalAddress = Rule(nullable=True)


class Inventory(FastModel):
    item: str
    address: Address

    def model_check(self, data):
        # Simulate an implementer re-raising structured errors sourced
        # from elsewhere (e.g. an external lookup), rather than raising
        # a plain string.
        raise ValidationError({"address": {"city": ["city is on a blocklist"]}})


class Inner(FastModel):
    code: str = Rule(pattern=r'^\d{3}$')


class Middle(FastModel):
    inner: Inner


class Outer(FastModel):
    middle: Middle


class TestFastModelNestedErrors(unittest.TestCase):
    """
    Regression tests for nested FastModel error reporting.

    Historically, ``FastModel.__init__`` and ``FastModel.check`` treated
    nested-model fields as plain scalars: a bad nested dict was either
    silently accepted unvalidated (stored as a raw dict, see
    ``test_init_previously_silently_accepted_invalid_nested_dict`` for the
    documented pre-fix behaviour) or reported as a single opaque
    "expected dict" message, with no indication of which sub-field failed.
    """

    def test_check_reports_nested_field_errors(self):
        ok, errors = Person.check({
            "name": "Alice",
            "address": {"street": "ok st", "city": "A", "zipcode": "bad"},
        })
        self.assertFalse(ok)
        self.assertIn("address", errors)
        self.assertIsInstance(errors["address"], dict)
        self.assertIn("city", errors["address"])
        self.assertIn("zipcode", errors["address"])
        self.assertNotIn("street", errors["address"])  # street was valid

    def test_check_nested_field_valid_produces_no_error(self):
        ok, errors = Person.check({
            "name": "Alice",
            "address": {"street": "123 Main St", "city": "Springfield", "zipcode": "12345"},
        })
        self.assertTrue(ok)
        self.assertEqual(errors, {})

    def test_check_nested_field_wrong_type(self):
        ok, errors = Person.check({"name": "Alice", "address": "not-a-dict"})
        self.assertFalse(ok)
        self.assertEqual(errors["address"], ["expected dict for nested model"])

    def test_check_nested_field_none_when_nullable(self):
        ok, errors = Owner.check({"name": "Alice", "address": None})
        self.assertTrue(ok)
        self.assertEqual(errors, {})

    def test_init_raises_with_nested_error_dict(self):
        with self.assertRaises(ValidationError) as ctx:
            Person(
                name="Alice",
                address={"street": "ok st", "city": "A", "zipcode": "bad"},
            )
        errors = ctx.exception.errors
        self.assertIn("address", errors)
        self.assertIsInstance(errors["address"], dict)
        self.assertIn("city", errors["address"])
        self.assertIn("zipcode", errors["address"])
        self.assertNotIn("street", errors["address"])  # street was valid

    def test_init_nested_errors_stringify_with_dotted_paths(self):
        # ValidationError.errors nests, but str(exc) still flattens to a
        # readable, dotted, line-per-message representation.
        with self.assertRaises(ValidationError) as ctx:
            Person(
                name="Alice",
                address={"street": "ok st", "city": "A", "zipcode": "bad"},
            )
        message = str(ctx.exception)
        self.assertIn("address.city:", message)
        self.assertIn("address.zipcode:", message)
        self.assertNotIn("address.street:", message)

    def test_init_succeeds_with_valid_nested_dict(self):
        person = Person(
            name="Alice",
            address={"street": "123 Main St", "city": "Springfield", "zipcode": "12345"},
        )
        self.assertIsInstance(person.address, Address)
        self.assertEqual(person.address.city, "Springfield")

    def test_init_accepts_existing_nested_instance(self):
        addr = Address(street="456 Oak Ave", city="Metropolis", zipcode="67890")
        person = Person(name="Bob", address=addr)
        self.assertIs(person.address, addr)

    def test_init_nested_field_wrong_type(self):
        with self.assertRaises(ValidationError) as ctx:
            Person(name="Alice", address="not-a-dict")
        self.assertEqual(
            ctx.exception.errors["address"], ["expected dict for nested model"]
        )

    def test_init_multiple_top_level_and_nested_errors_coexist(self):
        with self.assertRaises(ValidationError) as ctx:
            # 'name' omitted entirely -> required-field error at top level.
            Person(address={"street": "x", "city": "y", "zipcode": "bad"})
        errors = ctx.exception.errors
        # Top-level field error still reported as a flat list...
        self.assertIn("name", errors)
        self.assertEqual(errors["name"], ["field is required"])
        # ...alongside nested field errors, as a nested dict.
        self.assertIsInstance(errors["address"], dict)
        self.assertIn("street", errors["address"])
        self.assertIn("zipcode", errors["address"])

    def test_deeply_nested_check_returns_nested_dicts_at_each_level(self):
        ok, errors = Outer.check({"middle": {"inner": {"code": "bad"}}})
        self.assertFalse(ok)
        self.assertEqual(
            errors, {"middle": {"inner": {"code": ["value does not match required pattern"]}}}
        )

    def test_init_previously_silently_accepted_invalid_nested_dict(self):
        """
        Documents the bug this test class guards against: before the fix,
        constructing a model with an invalid nested dict neither raised nor
        coerced the value into the nested model type -- it silently stored
        the raw, unvalidated dict. This test locks in the corrected
        behaviour: an invalid nested dict must now raise.
        """
        with self.assertRaises(ValidationError):
            Person(name="Alice", address={"street": "x", "city": "y", "zipcode": "bad"})

    def test_flat_errors_unaffected_by_nested_support(self):
        # A plain (non-nested-model) validation failure must still produce
        # a flat dict[str, list[str]] and stringify exactly as before --
        # nested-dict support in ValidationError must not change behaviour
        # for models with no nested fields.
        with self.assertRaises(ValidationError) as ctx:
            User(id=1, username="a", email="not-an-email")
        errors = ctx.exception.errors
        for msgs in errors.values():
            self.assertIsInstance(msgs, list)
        message = str(ctx.exception)
        self.assertIn("username:", message)
        self.assertIn("email:", message)

    def test_model_check_raising_nested_dict_error_is_preserved(self):
        # model_check implementers may re-raise a caught nested
        # ValidationError with a nested-dict payload; that shape must be
        # preserved (not corrupted by list-based error merging).
        with self.assertRaises(ValidationError) as ctx:
            Inventory(
                item="widget",
                address={"street": "123 Main St", "city": "Springfield", "zipcode": "12345"},
            )
        errors = ctx.exception.errors
        self.assertIsInstance(errors["address"], dict)
        self.assertEqual(errors["address"]["city"], ["city is on a blocklist"])
        self.assertIn("address.city:", str(ctx.exception))


class TestFastModelInheritance(unittest.TestCase):

    class Base(FastModel):

        id: int

    class Derived(Base):
        name: str

    def test_inheritance_merges_fields(self):
        self.assertIn("id", self.Derived.__validated_fields__)
        self.assertIn("name", self.Derived.__validated_fields__)

    def test_inheritance_instantiation(self):
        obj = self.Derived(id=1, name="Alice")
        self.assertEqual(obj.id, 1)
        self.assertEqual(obj.name, "Alice")

    def test_subclass_overrides_rule(self):
        class Base(FastModel):
            field: str = Rule(min=2)

        class Derived(Base):
            field: str = Rule(min=5)  # stronger constraint

        with self.assertRaises(ValidationError):
            Derived(field="ab")  # len=2 <5
        # Base would accept "ab", but Derived should not


class TestFastModelModelCheck(unittest.TestCase):

    class Order(FastModel):
        start: int
        end: int

        def model_check(self, data):
            if data["end"] <= data["start"]:
                raise ValidationError("end must be greater than start")
            # optionally mutate
            return {"end": data["end"] + 1}

    def test_model_check_passes(self):
        order = self.Order(start=1, end=5)
        self.assertEqual(order.end, 6)  # mutated by model_check

    def test_model_check_fails(self):
        with self.assertRaises(ValidationError) as ctx:
            self.Order(start=5, end=3)
        exc = ctx.exception
        # String form still works for logging/assertIn
        self.assertIn("end must be greater than start", str(exc))
        # Structured form: model-level errors live under __model__
        self.assertIn("__model__", exc.errors)
        self.assertIn("end must be greater than start", exc.errors["__model__"])


class TestFastModelCopy(unittest.TestCase):

    class Person(FastModel):
        name: str
        age: int = Rule(default=0)

    def test_copy_with_overrides(self):
        original = self.Person(name="Alice", age=30)
        copied = original.copy(age=31)
        self.assertEqual(copied.name, "Alice")
        self.assertEqual(copied.age, 31)
        self.assertEqual(original.age, 30)  # unchanged

    def test_copy_no_overrides(self):
        original = self.Person(name="Alice", age=30)
        copied = original.copy()
        self.assertEqual(copied.name, "Alice")
        self.assertEqual(copied.age, 30)
        self.assertIsNot(copied, original)


class TestFastModelSchema(unittest.TestCase):

    class User(FastModel):
        name: str = Rule(min=3, max=32)
        age: int = Rule(default=0, nullable=True)

    def test_schema_returns_description(self):
        schema = self.User.schema()
        self.assertEqual(schema["model"], "User")
        fields = schema["fields"]
        self.assertIn("name", fields)
        self.assertIn("age", fields)
        self.assertEqual(fields["name"]["required"], True)
        self.assertEqual(fields["age"]["required"], False)
        self.assertEqual(fields["age"]["nullable"], True)
        self.assertEqual(fields["age"]["default"], 0)

    def test_schema_includes_rule_string(self):
        class WithRule(FastModel):
            email: str = Rule("email")
        schema = WithRule.schema()
        self.assertEqual(schema["fields"]["email"]["rule"], "email")


class TestFastModelCheckClassmethod(unittest.TestCase):

    class User(FastModel):
        username: str = Rule(min=3)
        email: str = Rule("email")

    def test_check_valid_partial_data(self):
        ok, errors = self.User.check({"username": "alice"})
        self.assertTrue(ok)
        self.assertEqual(errors, {})

    def test_check_invalid_partial_data(self):
        ok, errors = self.User.check({"username": "a"})
        self.assertFalse(ok)
        self.assertIn("username", errors)
        self.assertTrue(any("too short" in msg for msg in errors["username"]))

    def test_check_unknown_field(self):
        ok, errors = self.User.check({"unknown": "value"})
        self.assertFalse(ok)
        self.assertIn("unknown", errors)

    def test_check_missing_field_ok(self):
        # missing email is fine in partial validation
        ok, errors = self.User.check({"username": "alice"})
        self.assertTrue(ok)


class TestFastModelReprAndEq(unittest.TestCase):

    class Point(FastModel):
        x: int
        y: int

    def test_repr(self):
        p = self.Point(x=10, y=20)
        self.assertEqual(repr(p), "Point(x=10, y=20)")

    def test_eq_same_values(self):
        p1 = self.Point(x=10, y=20)
        p2 = self.Point(x=10, y=20)
        self.assertEqual(p1, p2)

    def test_eq_different_values(self):
        p1 = self.Point(x=10, y=20)
        p2 = self.Point(x=10, y=21)
        self.assertNotEqual(p1, p2)

    def test_eq_different_type(self):
        p = self.Point(x=10, y=20)
        self.assertNotEqual(p, (10, 20))
        
class TestFastModelChoicesKwarg(unittest.TestCase):
    """Tests for the 'choices' kwarg (safe replacement for reserved 'in' keyword)."""

    class ChoicesModel(FastModel):
        # List of choices
        role: str = Rule(choices=["admin", "user", "guest"])
        
        # Comma-separated string of choices
        status: str = Rule("str", choices="active,pending,archived")
        
        # Choices combined with other standard kwargs
        letter: str = Rule(choices=["a", "b", "c"], min=1, max=1)

    def test_choices_accepts_valid_list_value(self):
        m = self.ChoicesModel(role="admin", status="active", letter="a")
        self.assertEqual(m.role, "admin")

    def test_choices_accepts_valid_string_value(self):
        m = self.ChoicesModel(role="user", status="pending", letter="b")
        self.assertEqual(m.status, "pending")

    def test_choices_rejects_invalid_value(self):
        with self.assertRaises(ValidationError):
            self.ChoicesModel(role="hacker", status="active", letter="a")

    def test_choices_rejects_invalid_string_parsed_value(self):
        with self.assertRaises(ValidationError):
            self.ChoicesModel(role="admin", status="deleted", letter="a")

    def test_choices_validates_alongside_other_kwargs(self):
        # 'letter' must be in choices AND have exactly length 1
        self.ChoicesModel(role="admin", status="active", letter="c")  # Passes
        
        with self.assertRaises(ValidationError):
            self.ChoicesModel(role="admin", status="active", letter="ab")  # Fails max:1


class TestFastModelTransformsKwarg(unittest.TestCase):
    """Tests for the 'transforms' kwarg (solves the transform ordering trap)."""

    class TransformsListModel(FastModel):
        name: str = Rule(transforms=["strip", "lower"], min=3, max=10)

    class TransformsStringModel(FastModel):
        name: str = Rule(transforms="strip|lower", min=3)

    class TransformsTupleModel(FastModel):
        name: str = Rule(transforms=("strip", "lower"), min=3)

    def test_transforms_applied_from_list(self):
        m = self.TransformsListModel(name="  ALICE  ")
        self.assertEqual(m.name, "alice")

    def test_transforms_applied_from_string(self):
        m = self.TransformsStringModel(name="  BOB  ")
        self.assertEqual(m.name, "bob")

    def test_transforms_applied_from_tuple(self):
        m = self.TransformsTupleModel(name="  CHARLIE  ")
        self.assertEqual(m.name, "charlie")

    def test_transforms_solve_ordering_trap(self):
        """The primary purpose of the kwarg: min/max can safely come BEFORE transforms."""
        class OrderedModel(FastModel):
            name: str = Rule(min=3, max=10, transforms=["strip", "lower"])
            
        # This would previously raise ValueError at runtime!
        m = OrderedModel(name="  DAVE  ")
        self.assertEqual(m.name, "dave")

    def test_transforms_run_before_validation(self):
        """Ensure transforms alter the value before min/max checks evaluate it."""
        with self.assertRaises(ValidationError):
            self.TransformsListModel(name="  A  ")  # stripped/lowered to "a" -> fails min:3

    def test_transforms_deduplicate_with_pipe_string(self):
        """If a pipe string and transforms kwarg both specify 'strip', it shouldn't run twice."""
        class DedupeModel(FastModel):
            name: str = Rule("str|strip", transforms=["lower"])
            
        m = DedupeModel(name="  ALICE  ")
        self.assertEqual(m.name, "alice")

    def test_transforms_rejects_unknown_transform(self):
        """Invalid transform strings should raise ValueError at compile time."""
        with self.assertRaises(ValueError) as ctx:
            class BadTransformModel(FastModel):
                name: str = Rule(transforms=["strip", "nonexistent_transform"])
                
        self.assertIn("Unknown transform", str(ctx.exception))
        self.assertIn("nonexistent_transform", str(ctx.exception))


class TestFastModelMixingKwargsAndPipe(unittest.TestCase):
    """Tests ensuring new kwargs integrate cleanly with existing pipe syntax."""

    class MixedModel(FastModel):
        # Pipe string + choices kwarg
        status: str = Rule("str|lower", choices=["active", "pending"])
        
        # Transforms kwarg + pattern kwarg
        code: str = Rule(transforms="strip", pattern=r"^[A-Z]{3}$")

    def test_pipe_and_choices_work_together(self):
        m = self.MixedModel(status="ACTIVE", code="  ABC  ")
        self.assertEqual(m.status, "active")
        self.assertEqual(m.code, "ABC")

    def test_pipe_and_choices_reject_invalid(self):
        with self.assertRaises(ValidationError):
            self.MixedModel(status="ACTIVE", code="abc")  # fails pattern

    def test_pipe_transform_and_kwarg_transform_dont_duplicate(self):
        class DoubleStripModel(FastModel):
            name: str = Rule("str|strip", transforms=["strip", "lower"])
            
        # "  ALICE  " -> strip (pipe) -> "ALICE" -> strip (kwarg, ignored) -> lower -> "alice"
        m = DoubleStripModel(name="  ALICE  ")
        self.assertEqual(m.name, "alice")
        
        
class TestFastModelOpenAPISchema(unittest.TestCase):
    """Tests for OpenAPI schema generation, types, constraints, and versions."""

    def test_basic_types_and_formats(self):
        class APIUser(FastModel):
            id: int
            email: str = Rule("email")
            is_active: bool = Rule(default=True)

        schema = APIUser.openapi_schema()
        
        self.assertEqual(schema["type"], "object")
        self.assertEqual(schema["title"], "APIUser")
        
        # 'is_active' has a default, so it shouldn't be required
        self.assertEqual(schema["required"], ["id", "email"])
        
        props = schema["properties"]
        self.assertEqual(props["id"]["type"], "integer")
        self.assertEqual(props["email"]["type"], "string")
        self.assertEqual(props["email"]["format"], "email")
        self.assertEqual(props["is_active"]["type"], "boolean")
        self.assertEqual(props["is_active"]["default"], True)

    def test_constraints_mapping(self):
        class Product(FastModel):
            name: str = Rule(min=3, max=50, pattern="^[A-Z]")
            price: float = Rule(min=0.01)
            # Must explicitly pass "list[str]" so inner type logic extracts "string"
            tags: list[str] = Rule("list[str]", min=1, max=5)
            status: str = Rule(choices=["active", "archived"])
            code: int = Rule(choices=[100, 200])

        schema = Product.openapi_schema()
        props = schema["properties"]
        
        self.assertEqual(props["name"]["minLength"], 3)
        self.assertEqual(props["name"]["maxLength"], 50)
        self.assertEqual(props["name"]["pattern"], "^[A-Z]")
        
        self.assertEqual(props["price"]["type"], "number")
        self.assertEqual(props["price"]["minimum"], 0.01)

        self.assertEqual(props["tags"]["type"], "array")
        self.assertEqual(props["tags"]["items"]["type"], "string")
        self.assertEqual(props["tags"]["minItems"], 1)
        self.assertEqual(props["tags"]["maxItems"], 5)

        self.assertEqual(props["status"]["enum"], ["active", "archived"])
        self.assertEqual(props["code"]["enum"], [100, 200])

    def test_nested_model_schema(self):
        class Coordinate(FastModel):
            lat: float
            lng: float
            
        class Location(FastModel):
            name: str
            coord: Coordinate
            
        schema = Location.openapi_schema()
        props = schema["properties"]
        
        self.assertIn("coord", props)
        self.assertEqual(props["coord"]["type"], "object")
        self.assertEqual(props["coord"]["properties"]["lat"]["type"], "number")
        self.assertEqual(props["coord"]["required"], ["lat", "lng"])

    def test_openapi_versions_nullability_and_enums(self):
        class Profile(FastModel):
            bio: str = Rule(nullable=True)
            status: str = Rule(choices=["online", "offline"], nullable=True)
            
        # OpenAPI 3.0 Behavior
        schema_30 = Profile.openapi_schema(version="3.0")
        self.assertEqual(schema_30["properties"]["bio"]["type"], "string")
        self.assertTrue(schema_30["properties"]["bio"]["nullable"])
        self.assertEqual(schema_30["properties"]["status"]["enum"], ["online", "offline"])

        # OpenAPI 3.1 Behavior
        schema_31 = Profile.openapi_schema(version="3.1")
        self.assertEqual(schema_31["properties"]["bio"]["type"], ["string", "null"])
        self.assertNotIn("nullable", schema_31["properties"]["bio"])
        # In 3.1, nullable enums MUST inject None to remain valid according to JSON Schema
        self.assertEqual(schema_31["properties"]["status"]["enum"], ["online", "offline", None])

    def test_invalid_openapi_version_raises(self):
        class Dummy(FastModel):
            x: int
            
        with self.assertRaises(ValueError):
            Dummy.openapi_schema(version="2.0")


if __name__ == "__main__":
    unittest.main()
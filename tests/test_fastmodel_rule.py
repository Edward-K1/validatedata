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


if __name__ == "__main__":
    unittest.main()
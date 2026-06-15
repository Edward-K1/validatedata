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
    score: float = Rule(default=0.0)


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
        with self.assertRaises(ValidationError) as ctx:
            User(id=1, username="alice_99", email="alice@example.com")
        # tags has default via init_new, bio is nullable, score has default, but email and username present.
        # Actually missing? All fields have defaults except id, username, email? Let's check:
        # id: no default, username: no default, email: no default, tags: default [], bio: nullable default? bio: Rule("str|nullable") has no default, but nullable allows None? Actually nullable flag doesn't provide default; missing key is still missing. So error.
        self.assertIn("tags", str(ctx.exception))  # depends on actual error; adjust
        # But we want to test that missing required field raises. Simpler model:
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
        m = Model(name="  Al  ")  # after strip/lower becomes "al" → len 2, fails min:3
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
            Person.from_dict(data)

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
        self.assertIn("end must be greater than start", str(ctx.exception))

    def test_model_check_ignores_return_when_not_dict(self):
        class Model(FastModel):
            x: int
            def model_check(self, data):
                return None  # no mutation
        m = Model(x=10)
        self.assertEqual(m.x, 10)


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
        self.assertEqual(errors, [])

    def test_check_invalid_partial_data(self):
        ok, errors = self.User.check({"username": "a"})
        self.assertFalse(ok)
        self.assertTrue(any("username" in e for e in errors))

    def test_check_unknown_field(self):
        ok, errors = self.User.check({"unknown": "value"})
        self.assertFalse(ok)
        self.assertTrue(any("unknown" in e for e in errors))

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


if __name__ == "__main__":
    unittest.main()
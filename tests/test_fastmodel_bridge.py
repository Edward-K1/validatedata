# tests/test_fastmodel_bridge.py
"""
Tests for FastModel interoperability bridging.

Covers:
- Bridging standard Python dataclasses
- Bridging Pydantic models (if installed)
- Bridging msgspec Structs (if installed)
- Preserving field constraints (min_length, ge, etc.)
- Overriding constraints via extra_rules
- Passing custom model_check callables
- Bridging nested models recursively
- Directly bridging model instances
"""
from __future__ import annotations

import sys
import unittest
import dataclasses
from typing import List, Optional

from validatedata.fastmodel import FastModel
from validatedata.rule import Rule
from validatedata.engine import ValidationError

if sys.version_info >= (3, 9):
    from typing import Annotated
else:
    try:
        from typing_extensions import Annotated
    except ImportError:
        Annotated = None

# Optional dependencies
try:
    import pydantic
    from pydantic import BaseModel, Field
    HAS_PYDANTIC = True
except ImportError:
    HAS_PYDANTIC = False

try:
    import msgspec
    HAS_MSGSPEC = True
except ImportError:
    HAS_MSGSPEC = False


# ---------------------------------------------------------------------------
# Test Fixtures: Dataclasses
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class DCAddress:
    street: str
    zipcode: str

@dataclasses.dataclass
class DCUser:
    id: int
    username: str
    tags: List[str] = dataclasses.field(default_factory=list)
    address: Optional[DCAddress] = None


# ---------------------------------------------------------------------------
# Tests: Dataclasses
# ---------------------------------------------------------------------------

class TestBridgeDataclass(unittest.TestCase):

    def test_bridge_dataclass_basic(self):
        FastUser = FastModel.bridge(DCUser)
        
        # Valid construction
        user = FastUser(id=1, username="alice")
        self.assertEqual(user.id, 1)
        self.assertEqual(user.username, "alice")
        self.assertEqual(user.tags, [])  # default_factory preserved
        self.assertIsNone(user.address)  # optional field defaults to None

    def test_bridge_dataclass_enforces_types(self):
        FastUser = FastModel.bridge(DCUser)
        
        with self.assertRaises(ValidationError) as ctx:
            FastUser(id="not-an-int", username="alice")
            
        self.assertIn("id", ctx.exception.errors)

    def test_bridge_dataclass_nested(self):
        FastUser = FastModel.bridge(DCUser)
        
        # Construct with nested dict
        user = FastUser(
            id=1, 
            username="alice", 
            address={"street": "123 Main", "zipcode": "12345"}
        )
        
        # Ensure it recursively bridged the nested class
        self.assertIsInstance(user.address, FastModel)
        self.assertEqual(user.address.street, "123 Main")

    def test_bridge_instance_directly(self):
        dc_inst = DCUser(id=99, username="bob")
        
        # Bridge the instance directly
        fast_inst = FastModel.bridge(dc_inst)
        
        self.assertIsInstance(fast_inst, FastModel)
        self.assertEqual(fast_inst.id, 99)
        self.assertEqual(fast_inst.username, "bob")


# ---------------------------------------------------------------------------
# Tests: Extra Rules & Model Checks
# ---------------------------------------------------------------------------

class TestBridgeFeatures(unittest.TestCase):

    def test_bridge_with_extra_rules(self):
        # Override the username rule to require min length of 5
        FastUser = FastModel.bridge(
            DCUser,
            extra_rules={"username": "str|min:5"}
        )
        
        # Passes
        FastUser(id=1, username="alice")
        
        # Fails (length 3 < 5)
        with self.assertRaises(ValidationError):
            FastUser(id=1, username="bob")

    def test_bridge_with_extra_rules_as_rule_object(self):
        FastUser = FastModel.bridge(
            DCUser,
            extra_rules={"username": Rule(min=5, max=10)}
        )
        
        with self.assertRaises(ValidationError):
            FastUser(id=1, username="bob")

    def test_bridge_with_model_check(self):
        def custom_check(self, data):
            if data["username"] == "admin" and data["id"] > 1:
                raise ValidationError({"username": ["Admin must have ID 1"]})

        FastAdmin = FastModel.bridge(
            DCUser,
            model_check=custom_check
        )
        
        # Passes
        FastAdmin(id=1, username="admin")
        
        # Fails model_check
        with self.assertRaises(ValidationError) as ctx:
            FastAdmin(id=2, username="admin")
            
        self.assertIn("Admin must have ID 1", str(ctx.exception))


# ---------------------------------------------------------------------------
# Tests: Pydantic V2
# ---------------------------------------------------------------------------

@unittest.skipUnless(HAS_PYDANTIC, "Pydantic is not installed")
class TestBridgePydantic(unittest.TestCase):

    def test_pydantic_constraints_mapped(self):
        class PyUser(BaseModel):
            username: str = Field(min_length=4, max_length=12, pattern=r"^[a-z]+$")
            age: int = Field(ge=18)
            score: float = Field(default=0.0)

        FastPyUser = FastModel.bridge(PyUser)

        # Passes
        user = FastPyUser(username="alice", age=25)
        self.assertEqual(user.score, 0.0)  # default preserved

        # Fails min_length
        with self.assertRaises(ValidationError):
            FastPyUser(username="bob", age=25)

        # Fails pattern
        with self.assertRaises(ValidationError):
            FastPyUser(username="alice123", age=25)

        # Fails ge (greater than or equal to)
        with self.assertRaises(ValidationError):
            FastPyUser(username="alice", age=17)

    def test_pydantic_instance_bridging(self):
        class PyItem(BaseModel):
            name: str
            price: float

        py_inst = PyItem(name="Widget", price=19.99)
        fast_inst = FastModel.bridge(py_inst)

        self.assertEqual(fast_inst.name, "Widget")
        self.assertEqual(fast_inst.price, 19.99)


# ---------------------------------------------------------------------------
# Tests: Msgspec
# ---------------------------------------------------------------------------

@unittest.skipUnless(HAS_MSGSPEC and Annotated is not None, "Msgspec or Annotated not available")
class TestBridgeMsgspec(unittest.TestCase):

    def test_msgspec_constraints_mapped(self):
        class MsgUser(msgspec.Struct):
            username: Annotated[str, msgspec.Meta(min_length=4, pattern=r"^[a-z]+$")]
            age: Annotated[int, msgspec.Meta(ge=18)]
            status: str = "active"

        FastMsgUser = FastModel.bridge(MsgUser)

        # Passes
        user = FastMsgUser(username="alice", age=25)
        self.assertEqual(user.status, "active")

        # Fails min_length
        with self.assertRaises(ValidationError):
            FastMsgUser(username="bob", age=25)

        # Fails ge
        with self.assertRaises(ValidationError):
            FastMsgUser(username="alice", age=17)

    def test_msgspec_instance_bridging(self):
        class MsgItem(msgspec.Struct):
            name: str
            price: float

        msg_inst = MsgItem(name="Gadget", price=29.99)
        fast_inst = FastModel.bridge(msg_inst)

        self.assertEqual(fast_inst.name, "Gadget")
        self.assertEqual(fast_inst.price, 29.99)


class TestBridgeNullableRegressions(unittest.TestCase):
    """
    Regression tests for two bridging bugs:

    1. A field that merely has a default (but isn't Optional/Union[..., None])
       was incorrectly reported/validated as nullable, e.g. a Literal field
       with a default such as `role: Literal["admin", "member"] = "member"`.
    2. Passing a pipe-string via extra_rules (e.g. "int|min:18|max:120") for a
       field that also had constraints extracted from the source model (e.g.
       Pydantic's Field(ge=18)) duplicated those constraints in the final
       rule string (e.g. "int|min:18|max:120|min:18").
    """

    def test_default_only_field_is_not_nullable(self):
        @dataclasses.dataclass
        class DCUser:
            username: str
            age: int = 18
            address: Optional[DCAddress] = None

        FastDC = FastModel.bridge(DCUser)
        rules = FastDC.get_rules()

        self.assertEqual(rules["age"], "int")
        self.assertNotIn("nullable", rules["age"].split("|"))

        # The nested model's own defaulted, non-optional field must not pick
        # up nullable either.
        self.assertEqual(rules["address"]["zipcode"], "str")

        # A genuinely-optional nested model field should remain nullable at
        # construction time even though get_rules() no longer tags scalar
        # fields as nullable just for having a default.
        user = FastDC(username="alice")
        self.assertIsNone(user.address)

    @unittest.skipUnless(HAS_PYDANTIC, "Pydantic not installed")
    def test_literal_field_with_default_is_not_nullable(self):
        from typing import Literal

        class PyUser(BaseModel):
            username: str = Field(min_length=3, max_length=32)
            age: int = Field(ge=18)
            role: Literal["admin", "member", "guest"] = "member"

        FastUser = FastModel.bridge(PyUser)
        rules = FastUser.get_rules()

        self.assertEqual(rules["role"], "str|in:admin,member,guest")
        self.assertNotIn("nullable", rules["role"].split("|"))

    @unittest.skipUnless(HAS_PYDANTIC, "Pydantic not installed")
    def test_extra_rules_pipe_string_does_not_duplicate_constraints(self):
        class PyUser(BaseModel):
            username: str = Field(min_length=3, max_length=32)
            age: int = Field(ge=18)

        FastUser = FastModel.bridge(
            PyUser,
            extra_rules={"age": "int|min:18|max:120"},
        )
        rules = FastUser.get_rules()

        self.assertEqual(rules["age"], "int|min:18|max:120")
        # 'min:18' must appear exactly once, not duplicated.
        self.assertEqual(rules["age"].split("|").count("min:18"), 1)

    @unittest.skipUnless(HAS_PYDANTIC, "Pydantic not installed")
    def test_extra_rules_pipe_string_preserves_default(self):
        class PyUser(BaseModel):
            age: int = Field(default=21, ge=18)

        FastUser = FastModel.bridge(
            PyUser,
            extra_rules={"age": "int|min:18|max:120"},
        )
        # No key supplied -> falls back to the source model's default.
        user = FastUser()
        self.assertEqual(user.age, 21)


if __name__ == "__main__":
    unittest.main()
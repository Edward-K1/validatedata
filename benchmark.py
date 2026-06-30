"""
benchmark.py - 
"""

import sys
import time
import json
import re
from typing import Any, Dict

import argparse

# Libraries
import pydantic
from pydantic import BaseModel, ValidationError, field_validator
import fastjsonschema
import msgspec
import validatedata as vd

print(f"Pydantic version: {pydantic.VERSION}")
print(f"validatedata version: {getattr(vd, '__version__', 'unknown')}\n")

# -----------------------------
# Config
# -----------------------------
def get_reps_warmup():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--reps", "-r", type=int, default=10_000_00,
                        help="Number of repetitions")
    parser.add_argument("--warmup", type=int, default=5_000,
                        help="Warmup iterations")

    if any(x in sys.modules for x in ["ipykernel", "google.colab"]):
        args, _ = parser.parse_known_args()
    else:
        args = parser.parse_args()
    return args.reps, args.warmup


REPS, WARMUP = get_reps_warmup()
print(f"Running with REPS = {REPS:,} | WARMUP = {WARMUP:,}\n")

# -----------------------------
# Test payloads
# -----------------------------
nested_valid = {
    "user": {
        "id": 123,
        "name": "Alice",
        "profile": {
            "email": "alice@example.com",
            "age": 30,
            "address": {
                "street": "Main St",
                "city": "Metropolis",
                "zip": "12345"
            }
        }
    }
}

nested_invalid = {
    "user": {
        "id": "oops",
        "name": "Alice",
        "profile": {
            "email": "not-an-email",
            "age": "thirty",
            "address": {
                "street": "Main St",
                "city": 999,
                "zip": "ABCDE"
            }
        }
    }
}

# -----------------------------
# Email regex for fair manual validation
# -----------------------------
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")


# -----------------------------
# Manual (pure Python baseline)
# -----------------------------
def manual_validate(data: Dict[str, Any]) -> bool:
    try:
        # Top level
        if not isinstance(data, dict) or "user" not in data:
            return False
        user = data["user"]
        if not isinstance(user, dict):
            return False
        
        # User fields
        if not isinstance(user.get("id"), int):
            return False
        name = user.get("name")
        if not isinstance(name, str) or len(name) < 1:
            return False
        
        # Profile
        profile = user.get("profile")
        if not isinstance(profile, dict):
            return False
        
        email = profile.get("email")
        if not isinstance(email, str) or not EMAIL_REGEX.match(email):
            return False
        age = profile.get("age")
        if not isinstance(age, int) or age < 0 or age > 120:
            return False
        
        # Address
        address = profile.get("address")
        if not isinstance(address, dict):
            return False
        street = address.get("street")
        if not isinstance(street, str) or len(street) < 1:
            return False
        city = address.get("city")
        if not isinstance(city, str) or len(city) < 1:
            return False
        zip_code = address.get("zip")
        if not isinstance(zip_code, str) or len(zip_code) != 5:
            return False
        
        return True
    except Exception:
        return False
        
        
# -----------------------------
# Validatedata
# -----------------------------
vd_rules = {
    "user": {
        "id": "int",
        "name": "str|min:1",
        "profile": {
            "email": "email",
            "age": "int|min:0|max:120",
            "address": {
                "street": "str|min:1",
                "city": "str|min:1",
                "zip": "str|length:5"
            }
        }
    }
}
vd_validator = vd.validator(vd_rules)

def validatedata_validate(data: Dict[str, Any]) -> bool:
    try:
        return bool(vd_validator(data))
    except Exception:
        return False

# -----------------------------
# FastModel
# -----------------------------
from validatedata import FastModel, Rule

class AddressFM(FastModel):
    street: str = Rule(min=1)
    city: str = Rule(min=1)
    zip: str = Rule(length=5)

class ProfileFM(FastModel):
    email: str = Rule("email")
    age: int = Rule(min=0, max=120)
    address: AddressFM

class UserFM(FastModel):
    id: int
    name: str = Rule(type ="str", min=1)
    profile: ProfileFM
    
class NestedFM(FastModel):
    user: UserFM


def fastmodel_validate(data):
    try:
        return NestedFM.from_dict(data)
    except Exception:
        return False
        
        
        
# -----------------------------
# Pydantic v2
# -----------------------------
class Address(BaseModel):
    street: str
    city: str
    zip: str

    @field_validator("zip")
    @classmethod
    def zip_len(cls, v: str) -> str:
        if len(v) != 5:
            raise ValueError("must be 5 chars")
        return v


class Profile(BaseModel):
    email: str
    age: int
    address: Address

    @field_validator("email")
    @classmethod
    def email_has_at(cls, v: str) -> str:
        if not EMAIL_REGEX.match(v):
            raise ValueError("invalid email")
        return v


class User(BaseModel):
    id: int
    name: str
    profile: Profile


class NestedModel(BaseModel):
    user: User


def pydantic_validate(data: Dict[str, Any]) -> bool:
    try:
        NestedModel.model_validate(data)
        return True
    except ValidationError:
        return False


# -----------------------------
# fastjsonschema
# -----------------------------
json_schema = {
    "type": "object",
    "properties": {
        "user": {
            "type": "object",
            "properties": {
                "id": {"type": "integer"},
                "name": {"type": "string", "minLength": 1},
                "profile": {
                    "type": "object",
                    "properties": {
                        "email": {"type": "string", "format": "email"},
                        "age": {"type": "integer", "minimum": 0, "maximum": 120},
                        "address": {
                            "type": "object",
                            "properties": {
                                "street": {"type": "string", "minLength": 1},
                                "city": {"type": "string", "minLength": 1},
                                "zip": {"type": "string", "minLength": 5, "maxLength": 5}
                            },
                            "required": ["street", "city", "zip"]
                        }
                    },
                    "required": ["email", "age", "address"]
                }
            },
            "required": ["id", "name", "profile"]
        }
    },
    "required": ["user"]
}

fastjson_validate = fastjsonschema.compile(json_schema)

def fastjsonschema_validate(data: Dict[str, Any]) -> bool:
    try:
        fastjson_validate(data)
        return True
    except Exception:
        return False


# -----------------------------
# Msgspec - OPTIMIZED (no json.dumps)
# -----------------------------
class AddressStruct(msgspec.Struct):
    street: str
    city: str
    zip: str

class ProfileStruct(msgspec.Struct):
    email: str
    age: int
    address: AddressStruct

class UserStruct(msgspec.Struct):
    id: int
    name: str
    profile: ProfileStruct

class NestedStruct(msgspec.Struct):
    user: UserStruct


def msgspec_validate(data: Dict[str, Any]) -> bool:
    try:
        # Structural + type validation
        obj = msgspec.convert(data, type=NestedStruct)

        # Additional rules
        if not EMAIL_REGEX.match(obj.user.profile.email):
            return False
        if len(obj.user.profile.address.zip) != 5:
            return False
        if len(obj.user.name) < 1:
            return False

        return True
    except Exception:
        return False


# -----------------------------
# Benchmark
# -----------------------------
def run_once(fn, data, reps: int):
    # Warmup
    for _ in range(min(WARMUP, max(100, reps // 10))):
        try:
            fn(data)
        except:
            pass

    start = time.perf_counter()
    ok = sum(1 for _ in range(reps) if fn(data))
    end = time.perf_counter()

    total = end - start
    ops = reps / total if total > 0 else float("inf")
    return total, ops, ok


def bench_all(data, reps: int):
    size = len(json.dumps(data))
    print(f"\n=== Running {reps:,} reps (~{size} bytes) ===")

    for label, fn in [
        ("manual", manual_validate),
        ("validatedata_validator", validatedata_validate),
        ("fastmodel", fastmodel_validate),
        ("pydantic_v2", pydantic_validate),
        ("fastjsonschema", fastjsonschema_validate),
        ("msgspec", msgspec_validate),
    ]:
        total, ops, ok = run_once(fn, data, reps)
        print(f"{label:22s} {total:7.4f}s {ops:10,.0f} ops/s   ok: {ok:,}")


if __name__ == "__main__":
    print("=== VALID ===")
    bench_all(nested_valid, REPS)

    print("\n=== INVALID ===")
    bench_all(nested_invalid, REPS)
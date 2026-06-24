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
    parser.add_argument("--reps", "-r", type=int, default=3_000_000,
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

# ==================== DIAGNOSTIC BLOCK START ====================
print("\n=== FastModel Diagnostic ===")
print(f"AddressFM.__rule_dict__: {AddressFM.__rule_dict__}")
print(f"ProfileFM.__rule_dict__: {ProfileFM.__rule_dict__}")
print(f"UserFM.__rule_dict__: {UserFM.__rule_dict__}")
print(f"NestedFM.__rule_dict__: {NestedFM.__rule_dict__}")
print(f"NestedFM.__fast_validator__ is None? {NestedFM.__fast_validator__ is None}")

test_valid = nested_valid
print(f"\nTesting is_valid_data on valid payload: {NestedFM.is_valid_data(test_valid)}")

if not NestedFM.is_valid_data(test_valid):
    # Get detailed errors using check()
    ok, errors = NestedFM.check(test_valid)
    print(f"check() returned ok={ok}, errors={errors}")
else:
    print("is_valid_data returned True (as expected)")

# Also test a direct validator call if it exists
if NestedFM.__fast_validator__ is not None:
    try:
        direct_result = NestedFM.__fast_validator__(test_valid)
        print(f"Direct __fast_validator__ call: {direct_result}")
    except Exception as e:
        print(f"Direct validator call raised: {e}")
else:
    print("No __fast_validator__ (None) - using fallback slow path")

# Optionally test from_dict with check mode
try:
    from_dict_result = NestedFM.from_dict(test_valid, validate="check")
    print(f"from_dict(validate='check') returned: {from_dict_result is not None}")
except Exception as e:
    print(f"from_dict(validate='check') raised: {e}")

print("=== End Diagnostic ===\n")
# ==================== DIAGNOSTIC BLOCK END ====================

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
        msgspec.convert(data, type=NestedStruct)
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
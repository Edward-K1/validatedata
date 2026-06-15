# validatedata/fastmodel.py
"""
FastModel — declarative validation models built on validatedata's compiled core.

Design goals
------------
* Fast path uses compiled.py bool callables — zero overhead on valid data.
* Error path routes through fast._validate_value_with_messages for rich,
  human-readable messages without any extra work from the caller.
* ``model_check`` for cross-field logic — one clear contract: raise
  ``ValidationError`` to fail, return ``dict`` to mutate, return ``None`` to pass.
* ``Rule`` doubles as both the field descriptor and the compilation unit.
  ``_MISSING`` sentinel keeps "no default" distinct from ``None``.

Serialisation / deserialisation
-------------------------------
- ``to_dict(recursive=True)`` converts the model (and any nested FastModel fields)
  to a plain dictionary.
- ``from_dict(cls, data)`` reconstructs a model from a dictionary, recursively
  building nested models where the field annotation is a FastModel subclass.
"""
from __future__ import annotations

import copy
import inspect
from typing import Any, Callable, ClassVar, Dict, List, Optional, Tuple, Type, get_type_hints

from .rule import Rule, _MISSING
from . import fast as _fast
from .engine import ValidationError


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _make_trivial_compiled_rule() -> _fast._CompiledRule:
    """Fallback compiled rule that accepts any value."""
    return _fast._CompiledRule(
        fast_validator=lambda v: True,
        checks=[],
        nullable=True,
        type_name="any",
        transform=None,
        validator_names=[],
        validator_args=[],
    )


def _compiled_rule_for(rule_obj: Rule) -> _fast._CompiledRule:
    """
    Convert a Rule into a _CompiledRule.

    Fast path: rule_obj.rule is a str → _fast._get_compiled_rule (LRU cached).
    Fallback: compile() then wrap in a trivial struct that holds at least
    the fast_validator and nullable flag so the __init__ loop stays uniform.
    """
    # Preferred: pipe string → fully cached _CompiledRule with message support
    if isinstance(rule_obj.rule, str):
        try:
            return _fast._get_compiled_rule(rule_obj.rule)
        except Exception:
            pass

    # Compile the rule to get the bool callable and optional struct
    try:
        compiled_fn, compiled_struct = rule_obj.compile()
    except Exception:
        return _make_trivial_compiled_rule()

    # If fast.py already gave us a proper _CompiledRule, use it directly
    if isinstance(compiled_struct, _fast._CompiledRule):
        return compiled_struct

    # Build a minimal wrapper so the hot-path loop needs no isinstance checks
    nullable = getattr(compiled_struct, "nullable", False) if compiled_struct else False
    transform = getattr(compiled_struct, "transform", None) if compiled_struct else None
    return _fast._CompiledRule(
        fast_validator=compiled_fn,
        checks=[compiled_fn],          # one opaque check — message will be generic
        nullable=nullable,
        type_name="any",
        transform=transform,
        validator_names=["type"],
        validator_args=[None],
    )


# ---------------------------------------------------------------------------
# Metaclass — runs once at class definition, not per-instance
# ---------------------------------------------------------------------------

class _FastModelMeta(type):
    """
    Collect annotated fields and Rule instances at class creation time.

    What happens here:
    1. Merge annotations from all bases (MRO order, so subclass wins).
    2. For each annotated field, resolve a Rule object (or create a default one).
    3. Pre-compile every Rule into a _CompiledRule and cache it on the class.

    Nothing dynamic happens at __init__ time beyond looking up these
    pre-built structures and running the already-compiled callables.
    """
    def __new__(mcls, name: str, bases: tuple, namespace: dict, **kwargs):
        cls = super().__new__(mcls, name, bases, dict(namespace))

        # --- Collect annotations (bases → subclass so subclass overrides) ---
        annotations: Dict[str, Any] = {}
        for base in reversed(bases):
            annotations.update(getattr(base, "__annotations__", {}) or {})
        annotations.update(namespace.get("__annotations__", {}) or {})

        # Strip ClassVar and other non-field annotations
        field_annotations: Dict[str, Any] = {
            k: v for k, v in annotations.items()
            if not (isinstance(v, str) and v.startswith("ClassVar"))
            and not (hasattr(v, "__origin__") and v.__origin__ is ClassVar)
        }

        # These three dicts are the class-level "schema"
        cls.__validated_fields__: Dict[str, Any] = {}   # field → annotation
        cls.__field_rules__: Dict[str, Rule] = {}        # field → Rule
        cls.__compiled_fields__: Dict[str, _fast._CompiledRule] = {}  # field → compiled

        for field_name, annot in field_annotations.items():
            raw = namespace.get(field_name, _MISSING)

            if isinstance(raw, Rule):
                rule_obj = raw
            elif raw is not _MISSING:
                # Plain default value with no Rule — wrap it
                rule_obj = Rule(default=raw)
            else:
                # No default, no Rule — accept any value, require presence
                rule_obj = Rule()

            cls.__validated_fields__[field_name] = annot
            cls.__field_rules__[field_name] = rule_obj
            cls.__compiled_fields__[field_name] = _compiled_rule_for(rule_obj)

        return cls


# ---------------------------------------------------------------------------
# Public base class
# ---------------------------------------------------------------------------

class FastModel(metaclass=_FastModelMeta):
    """
    Declarative validation model.

    Basic usage::

        from validatedata import FastModel, Rule

        class User(FastModel):
            id: int
            username: str = Rule(min=3, max=32, pattern=r'^[a-z0-9_]+$')
            email: str = Rule("email")        # pipe syntax
            tags: list = Rule([], init_new=True, max_items=20)
            bio: str = Rule("str|nullable")

        user = User(id=1, username="alice", email="alice@example.com")
        print(user.to_dict())   # {'id': 1, 'username': 'alice', ...}

    Cross-field validation::

        class Order(FastModel):
            start: int
            end: int

            def model_check(self, data: dict):
                if data["end"] <= data["start"]:
                    raise ValidationError("end must be greater than start")
                # Optionally return a dict of mutations
                # return {"end": data["end"] + 1}

    Partial validation (no instantiation)::

        ok, errors = User.check({"username": "x"})

    Serialisation / deserialisation::

        data = user.to_dict()
        user2 = User.from_dict(data)
    """

    # ------------------------------------------------------------------
    # Construction — the hot path
    # ------------------------------------------------------------------

    def __init__(self, **kwargs):
        cls = self.__class__
        errors: List[str] = []

        # Phase 1: resolve values (kwargs > default)
        data: Dict[str, Any] = {}
        for fname in cls.__validated_fields__:
            if fname in kwargs:
                data[fname] = kwargs[fname]
            else:
                default = cls.__field_rules__[fname].get_default()
                data[fname] = None if default is _MISSING else default

        # Phase 2: validate each field
        for fname, val in data.items():
            cr: _fast._CompiledRule = cls.__compiled_fields__[fname]

            if val is not _MISSING and cr.fast_validator(val):
                # fast_validator already includes transform; val is already correct.
                object.__setattr__(self, fname, val)
                continue

            if val is None and cr.nullable:
                object.__setattr__(self, fname, None)
                continue

            ok, errs, transformed_val = _fast._validate_value_with_messages(val, cr, field_name=fname)

            if not ok:
                errors.extend(errs)
            else:
                # transformed_val already has transform applied (if any)
                object.__setattr__(self, fname, transformed_val)

        # Phase 3: cross-field hook
        if not errors and hasattr(self, "model_check") and callable(self.model_check):
            try:
                result = self.model_check(
                    {k: getattr(self, k, None) for k in cls.__validated_fields__}
                )
                if isinstance(result, dict):
                    for k, v in result.items():
                        if k in cls.__validated_fields__:
                            object.__setattr__(self, k, v)
            except ValidationError as exc:
                errors.append(str(exc))
            except Exception as exc:
                errors.append(f"model_check: {exc}")

        if errors:
            raise ValidationError("\n".join(errors))

    # ------------------------------------------------------------------
    # Serialisation / deserialisation
    # ------------------------------------------------------------------

    def to_dict(self, recursive: bool = True) -> Dict[str, Any]:
        """
        Convert the model to a dictionary.

        Args:
            recursive: If True, any field that is itself a FastModel instance
                       will be converted to a dict recursively. If False,
                       nested models are kept as objects.

        Returns:
            A dictionary mapping field names to their values.
        """
        result = {}
        cls = self.__class__
        for fname in cls.__validated_fields__:
            value = getattr(self, fname, None)
            if recursive and isinstance(value, FastModel):
                result[fname] = value.to_dict(recursive=True)
            else:
                result[fname] = value
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FastModel":
        """
        Construct a model instance from a dictionary, recursively building nested models.

        Args:
            data: A dictionary mapping field names to values. For fields whose
                  annotation is a subclass of FastModel, if the corresponding value
                  is a dict, it will be converted to that nested model automatically.

        Returns:
            An instance of the model.

        Example::

            class Address(FastModel):
                street: str
                city: str

            class User(FastModel):
                name: str
                address: Address

            user = User.from_dict({
                "name": "Alice",
                "address": {"street": "123 Main St", "city": "Springfield"}
            })
        """
        field_types = cls.__validated_fields__
        processed = {}

        for fname, value in data.items():
            if fname not in field_types:
                # Ignore unknown fields – you could also raise, but skipping is more forgiving.
                continue

            annot = field_types[fname]

            # Resolve forward references if necessary (simplistic: check if it's a string)
            if isinstance(annot, str):
                # Attempt to resolve the string to an actual class (optional)
                # For simplicity, we skip recursion for forward refs.
                processed[fname] = value
                continue

            # Check if the annotation is a FastModel subclass
            if isinstance(annot, type) and issubclass(annot, FastModel):
                if isinstance(value, dict):
                    processed[fname] = annot.from_dict(value)
                else:
                    # If the value is already an instance, use it directly
                    processed[fname] = value
            else:
                processed[fname] = value

        # Instantiate the model – this runs all validation rules
        return cls(**processed)

    # ------------------------------------------------------------------
    # Convenience methods
    # ------------------------------------------------------------------

    def copy(self, **overrides) -> "FastModel":
        """Return a new instance with optionally overridden fields."""
        base = self.to_dict(recursive=False)  # shallow copy of values
        base.update(overrides)
        return self.__class__(**base)

    def __repr__(self) -> str:
        cls_name = self.__class__.__name__
        # Use the shallow dict for representation (avoid recursion depth issues)
        parts = []
        for k in self.__class__.__validated_fields__:
            v = getattr(self, k, None)
            parts.append(f"{k}={v!r}")
        return f"{cls_name}({', '.join(parts)})"

    def __eq__(self, other: object) -> bool:
        if type(other) is not type(self):
            return NotImplemented
        # Compare using the shallow dictionary – fast and sufficient
        return self.to_dict(recursive=False) == other.to_dict(recursive=False)

    # ------------------------------------------------------------------
    # Class-level validation (no instantiation)
    # ------------------------------------------------------------------

    @classmethod
    def check(cls, data: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """
        Validate a mapping of field→value without constructing an instance.

        Only validates the fields present in *data* — unknown keys produce
        an error, missing keys are silently skipped (partial validation).

        Returns ``(ok, errors)`` — never raises.

        Example::

            ok, errors = User.check({"username": "x"})
            # ok=False, errors=["username: string too short"]
        """
        errors: List[str] = []
        for fname, val in data.items():
            if fname not in cls.__validated_fields__:
                errors.append(f"{fname}: unknown field")
                continue
            cr = cls.__compiled_fields__[fname]
            ok, errs, _ = _fast._validate_value_with_messages(val, cr, field_name=fname)
            if not ok:
                errors.extend(errs)
        return len(errors) == 0, errors

    @classmethod
    def schema(cls) -> Dict[str, Any]:
        """
        Return a lightweight schema description of all fields.

        Useful for documentation, introspection, and generating forms or
        API specs without a heavy dependency on JSON Schema.

        Example::

            User.schema()
            # {
            #   "model": "User",
            #   "fields": {
            #     "username": {"rule": "str|min:3|max:32", "required": True},
            #     "email":    {"rule": "email",            "required": True},
            #     "tags":     {"rule": None, "required": False, "default": []},
            #   }
            # }
        """
        fields: Dict[str, Any] = {}
        for fname, rule_obj in cls.__field_rules__.items():
            has_default = rule_obj.default is not _MISSING
            fields[fname] = {
                "annotation": cls.__validated_fields__[fname],
                "rule": rule_obj.rule,
                "required": not has_default,
                "default": None if not has_default else (
                    "<factory>" if rule_obj.init_new else rule_obj.default
                ),
                "nullable": cls.__compiled_fields__[fname].nullable,
            }
        return {"model": cls.__name__, "fields": fields}
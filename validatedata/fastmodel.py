# validatedata/fastmodel.py
"""
FastModel — declarative validation models built on validatedata's compiled core.

Design goals
------------
* Fast path uses compiled.py bool callables — zero overhead on valid data.
* Error path routes exclusively through diagnose.diagnose for rich, precomputed,
  human-readable messages. diagnose owns the full error lifecycle: transform,
  nullable check, per-constraint failure messages and custom_msg.
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

from typing import Annotated, Any, Callable, ClassVar, Dict, List, Optional, Tuple, Type, get_args, get_origin, get_type_hints, Mapping

from .rule import Rule, _MISSING
from . import fast as _fast
from .engine import ValidationError
from .compiled import validator
from . import diagnose as _diagnose


def _diag_to_field_messages(diag: dict) -> tuple[bool, list[str]]:
    """Extract bare message strings from a diagnose() result.

    Returns (ok, [message, ...]) — field name is intentionally excluded
    because callers always know the field name and store it as the dict key.
    """
    if diag.get("valid", True):
        return True, []
    if "failures" in diag:
        return False, [f["message"] for f in diag["failures"]]
    # single failure (mode="first")
    return False, [diag.get("message", "validation failed")]


def _diagnose_to_errors(value: Any, cr: _fast._CompiledRule, field_name: Optional[str]) -> tuple[bool, list[str], Any | None]:
    """
    Returns (ok, [bare_message, ...], transformed_value_or_None).

    Messages are bare strings with no field prefix — the caller owns the
    field name and stores it as the dict key in the error structure.
    """
    rule_str = getattr(cr, "rule_str", None)
    if rule_str is None:
        return False, ["validation failed"], None

    diag = _diagnose.diagnose(value, rule_str, mode="first", aggressive=False)
    ok, msgs = _diag_to_field_messages(diag)

    if not ok:
        custom_msg = getattr(cr, "custom_msg", None)
        if custom_msg:
            msgs = [custom_msg]
        return False, msgs, None

    if cr.transform is not None:
        try:
            transformed = cr.transform(value)
        except Exception:
            return False, ["transform failed"], None
    else:
        transformed = value

    return True, [], transformed



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
        rule_str=resolved_rs,
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
            cr = _fast._get_compiled_rule(rule_obj.rule)
            # Ensure rule_str is set on the compiled rule for diagnostics
            if getattr(cr, "rule_str", None) is None:
                cr.rule_str = rule_obj.rule
            return cr
        except Exception:
            pass

    # Compile the rule to get the bool callable and optional struct
    try:
        compiled_fn, compiled_struct = rule_obj.compile()
    except Exception:
        return _make_trivial_compiled_rule()

    # If fast.py already gave us a proper _CompiledRule, use it directly.
    # Resolve and stamp rule_str now — rule_obj.rule is None for kwargs-based
    # Rules, so we must call _resolve_rule_string() to get the actual pipe
    # string that was compiled.  Without this, _diagnose_to_errors sees
    # rule_str=None and can't reach diagnose or honour custom_msg.
    if isinstance(compiled_struct, _fast._CompiledRule):
        if getattr(compiled_struct, "rule_str", None) is None:
            try:
                compiled_struct.rule_str = rule_obj._resolve_rule_string()
            except Exception:
                compiled_struct.rule_str = getattr(rule_obj, "rule", None)
        return compiled_struct

    # Build a minimal wrapper so the hot-path loop needs no isinstance checks
    nullable = getattr(compiled_struct, "nullable", False) if compiled_struct else False
    # Also honour the Rule-level nullable flag even when there is no compiled struct
    nullable = nullable or rule_obj.nullable
    transform = getattr(compiled_struct, "transform", None) if compiled_struct else None
    try:
        resolved_rule_str = rule_obj._resolve_rule_string()
    except Exception:
        resolved_rule_str = getattr(rule_obj, "rule", None)
        
    return _fast._CompiledRule(
        fast_validator=compiled_fn,
        checks=[compiled_fn],          # one opaque check — message will be generic
        nullable=nullable,
        type_name="any",
        transform=transform,
        validator_names=["type"],
        validator_args=[None],
        rule_str=resolved_rule_str,
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

            # Unwrap Annotated[T, Rule(...)] — the declared type stays T,
            # the Rule rides as the first Rule-typed metadata argument.
            rule_from_annotation: Rule | None = None
            if get_origin(annot) is Annotated:
                args = get_args(annot)
                annot = args[0]  # the real type (str, int, …)
                for meta in args[1:]:
                    if isinstance(meta, Rule):
                        rule_from_annotation = meta
                        break

            if rule_from_annotation is not None:
                rule_obj = rule_from_annotation
                
            elif isinstance(raw, Rule):
                rule_obj = raw
            elif raw is not _MISSING:
                # Plain default value with no Rule — wrap it
                rule_obj = Rule(default=raw)
            else:
                # No default, no Rule — accept any value, require presence
                rule_obj = Rule()

            cls.__validated_fields__[field_name] = annot
            cls.__field_rules__[field_name] = rule_obj

            # If a kwargs-only Rule has no explicit type, inject the annotation
            # type now — this is the only place both the Rule and its annotation
            # are visible together. Without this, _resolve_rule_string() defaults
            # to "str" regardless of the field annotation, so Rule(min=18) on an
            # int field compiles as "str|min:18" and produces string range errors
            # instead of number range errors.
            if rule_obj.rule is None and rule_obj.kwargs and "type" not in rule_obj.kwargs:
                origin = get_origin(annot)
                bare = origin if origin is not None else annot
                if bare in (int, float, bool, str, list, tuple, set, dict):
                    rule_obj.kwargs["type"] = bare.__name__

            cls.__compiled_fields__[field_name] = _compiled_rule_for(rule_obj)

        # Cache resolved type hints once at class-definition time so from_dict
        # never pays the get_type_hints() cost at call time.
        try:
            cls.__resolved_hints__: Dict[str, Any] = get_type_hints(cls)
        except Exception:
            cls.__resolved_hints__ = dict(cls.__validated_fields__)

        # Pre-compute the set of field names that are FastModel subclasses so
        # from_dict can skip the isinstance check for the common case.
        cls.__nested_model_fields__: Dict[str, type] = {
            fname: hint
            for fname, hint in cls.__resolved_hints__.items()
            if fname in cls.__validated_fields__
            and isinstance(hint, type)
            and issubclass(hint, FastModel)
            and hint is not FastModel
        }

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
        errors: Dict[str, List[str]] = {}
        
        def _add_error(field: str, messages: list[str]) -> None:
            errors.setdefault(field, []).extend(messages)
    
        # Phase 1: resolve values (kwargs > default)
        data: Dict[str, Any] = {}
        for fname in cls.__validated_fields__:
            if fname in kwargs:
                data[fname] = kwargs[fname]
            else:
                default = cls.__field_rules__[fname].get_default()
                if default is _MISSING and cls.__compiled_fields__[fname].nullable:
                    # A nullable field with no explicit default implicitly accepts
                    # omission as None (the field can legally hold None, so None
                    # is the natural "absent" value).
                    default = None
                data[fname] = default  # stays _MISSING only for truly required fields
    
        # Phase 2: validate each field
        for fname, val in data.items():
            cr: _fast._CompiledRule = cls.__compiled_fields__[fname]

            if val is _MISSING:
                _add_error(fname, ["field is required"])
                continue

            if val is None and cr.nullable:
                object.__setattr__(self, fname, None)
                continue

            if cr.fast_validator(val):
                if cr.transform is not None:
                    try:
                        transformed_val = cr.transform(val)
                    except Exception:
                        transformed_val = val
                else:
                    transformed_val = val
                object.__setattr__(self, fname, transformed_val)
                continue

            ok, msgs, diag_transformed = _diagnose_to_errors(val, cr, field_name=fname)

            if not ok:
                _add_error(fname, msgs)
            else:
                object.__setattr__(self, fname, diag_transformed)
    
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
                # Re-raised ValidationError from model_check may itself carry a
                # structured dict (if raised by a nested FastModel) or a plain
                # string (if raised manually as in the Order example).
                if exc.errors:
                    for field, msgs in exc.errors.items():
                        _add_error(field, msgs)
                else:
                    _add_error("__model__", [str(exc)])
            except Exception as exc:
                _add_error("__model__", [f"model_check: {exc}"])

        if errors:
            raise ValidationError(errors)
    

    def is_valid(self, *, field: Optional[str] = None, apply_transforms: bool = False) -> bool:
        cls = self.__class__
    
        def _get_callable_and_value(cr, val):
            # Prefer the compiled fast callable if present
            fn = getattr(cr, "fast_validator", None)
            if fn is None:
                rule_str = getattr(cr, "rule_str", None)
                if rule_str is None:
                    return None, val
                fn = validator(rule_str)
            return fn, val
    
        # Single-field check
        if field is not None:
            if field not in cls.__validated_fields__:
                return False
            cr = cls.__compiled_fields__[field]
            val = getattr(self, field, _MISSING)
            if val is _MISSING:
                return False
    
            # Optionally apply transform (do not mutate stored attribute)
            if apply_transforms and getattr(cr, "transform", None) is not None:
                try:
                    v = cr.transform(val)
                except Exception:
                    return False
            else:
                v = val
    
            fn, _ = _get_callable_and_value(cr, v)
            if fn is None:
                return False
            return bool(fn(v))
    
        # Whole-model check: short-circuit on first failing field
        for fname in cls.__validated_fields__:
            cr = cls.__compiled_fields__[fname]
            val = getattr(self, fname, _MISSING)
            if val is _MISSING:
                return False
    
            if apply_transforms and getattr(cr, "transform", None) is not None:
                try:
                    v = cr.transform(val)
                except Exception:
                    return False
            else:
                v = val
    
            fn, _ = _get_callable_and_value(cr, v)
            if fn is None or not fn(v):
                return False
    
        return True
        
    @classmethod
    def is_valid_data(cls, data: Mapping[str, Any], *, apply_transforms: bool = False) -> bool:
        """
        Fast boolean check for a dict of field->value without instantiating.
        - apply_transforms False: do not run transforms (fastest).
        - apply_transforms True: run per-field transform before boolean check.
        Returns True if all provided fields pass; unknown fields cause False.
        """
        for fname, val in data.items():
            # unknown field -> treat as invalid
            if fname not in cls.__validated_fields__:
                return False
    
            cr = cls.__compiled_fields__[fname]
    
            # missing sentinel check (if caller uses _MISSING)
            if val is _MISSING:
                return False
    
            # optionally apply transform (do not mutate caller's dict)
            if apply_transforms and getattr(cr, "transform", None) is not None:
                try:
                    v = cr.transform(val)
                except Exception:
                    return False
            else:
                v = val
    
            # prefer already-compiled fast callable; fall back to compiled.validator
            fn = getattr(cr, "fast_validator", None)
            if fn is None:
                rule_str = getattr(cr, "rule_str", None)
                if rule_str is None:
                    return False
                fn = validator(rule_str)
    
            if not fn(v):
                return False
    
        # All provided fields passed
        return True

    # ------------------------------------------------------------------
    # Serialisation / deserialisation
    # ------------------------------------------------------------------
    # 
    # 
    

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
        if not recursive:
            return self.__dict__.copy()
            
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
    def from_dict(
        cls,
        data: Dict[str, Any],
        validate: "bool | str" = "check",
    ) -> "Optional[FastModel]":
        """
        Construct a model instance from a dictionary, recursively building nested models.

        Args:
            data: A dictionary mapping field names to values. For fields whose
                  annotation is a subclass of FastModel, if the corresponding value
                  is a dict, it will be converted to that nested model automatically.
            validate:
                Controls how (or whether) the data is validated before the instance
                is built.

                ``False``
                    No validation.  Attributes are set directly via
                    ``object.__setattr__``, bypassing ``__init__`` entirely.
                    Use this when the data is already known-good (e.g. a
                    round-trip through ``to_dict``).  Fastest path.

                ``True``
                    Full validation.  Delegates to ``cls(**data)``, which runs
                    every compiled field rule plus ``model_check``.  Raises
                    ``ValidationError`` on bad data, identical to constructing
                    the model normally.

                ``"check"`` (default)
                    Non-raising pre-flight.  Runs ``cls.is_valid_data(data)``
                    (fast boolean short-circuit, no error list allocation) and
                    returns ``None`` if the data is invalid; otherwise builds
                    and returns the instance via the fast bypass path.

        Returns:
            A model instance, or ``None`` when ``validate="check"`` and the
            data fails validation.

        Example::

            class Address(FastModel):
                street: str
                city: str

            class User(FastModel):
                name: str
                address: Address

            # Trusted data — no validation overhead
            user = User.from_dict({"name": "Alice", "address": {"street": "123 Main St", "city": "Springfield"}})

            # Full validation — raises ValidationError on bad data
            user = User.from_dict(data, validate=True)

            # Silent check — returns None instead of raising
            user = User.from_dict(data, validate="check")
            if user is None:
                ...  # data was invalid
        """

        # --- validate=True: full __init__ path, raises on bad data ----------
        if validate is True:
            # Recurse into nested FastModel fields first so __init__ receives
            # proper model instances (which it can validate) rather than raw
            # dicts (which it would accept unchecked).
            nested_fields = cls.__nested_model_fields__
            if nested_fields:
                data = {
                    k: nested_fields[k].from_dict(v, validate=True)
                    if k in nested_fields and isinstance(v, dict) else v
                    for k, v in data.items()
                }
            return cls(**data)

        # --- validate="check": fast boolean guard, then bypass path ---------
        if validate == "check":
            # is_valid_data is flat — it can't descend into nested dicts.
            # Recursively check each nested model field first; if any returns
            # None (invalid), propagate None immediately.
            nested_fields = cls.__nested_model_fields__
            if nested_fields:
                for fname, nested_cls in nested_fields.items():
                    value = data.get(fname)
                    if isinstance(value, dict):
                        if nested_cls.from_dict(value, validate="check") is None:
                            return None
            if not cls.is_valid_data(data):
                return None
            # Fall through to the bypass path below with already-confirmed data

        # --- bypass path (validate=False or post-check) ---------------------
        field_types = cls.__validated_fields__
        nested_fields = cls.__nested_model_fields__          # pre-computed at class time
        field_rules = cls.__field_rules__

        instance = object.__new__(cls)

        for fname in field_types:
            if fname in data:
                value = data[fname]
                # Recurse into nested FastModel fields
                if fname in nested_fields and isinstance(value, dict):
                    value = nested_fields[fname].from_dict(value)
            else:
                # Apply default exactly as __init__ does
                value = field_rules[fname].get_default()
                if value is _MISSING:
                    cr = cls.__compiled_fields__[fname]
                    value = None if cr.nullable else _MISSING

            object.__setattr__(instance, fname, value)

        return instance

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
    def check(cls, data: Dict[str, Any]) -> Tuple[bool, Dict[str, List[str]]]:
        """
        ...
        Returns ``(ok, errors)`` — never raises.

        Example::

            ok, errors = User.check({"username": "x"})
            # ok=False, errors={"username": ["value is too short (minimum length: 3)"]}
        """
        errors: Dict[str, List[str]] = {}
        for fname, val in data.items():
            if fname not in cls.__validated_fields__:
                errors.setdefault(fname, []).append("unknown field")
                continue
            cr = cls.__compiled_fields__[fname]
            if val is None and cr.nullable:
                continue
            if cr.fast_validator(val):
                continue
            ok, msgs, _ = _diagnose_to_errors(val, cr, field_name=fname)
            if not ok:
                errors.setdefault(fname, []).extend(msgs)
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
            has_default = rule_obj.has_default  # covers both .default and ._default_factory
            
            try:
                resolved_rule = rule_obj._resolve_rule_string()
            except Exception:
                resolved_rule = rule_obj.rule
                
            fields[fname] = {
                "annotation": cls.__validated_fields__[fname],
                "rule": resolved_rule,
                "required": not has_default,
                "default": None if not has_default else (
                    "<factory>" if rule_obj.init_new else rule_obj.default
                ),
                "nullable": cls.__compiled_fields__[fname].nullable,
            }
        return {"model": cls.__name__, "fields": fields}
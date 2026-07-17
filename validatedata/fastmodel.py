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

import sys
from typing import Any, Callable,ClassVar, Dict, List, Optional, Tuple, Type, get_args, get_origin, get_type_hints, Mapping

from .rule import Rule, _MISSING
from . import fast as _fast
from .engine import ValidationError
from .compiled import validator
from . import diagnose as _diagnose

if sys.version_info >= (3, 9):
    from typing import Annotated
else:
    from typing_extensions import Annotated

# ---------------------------------------------------------------------------
# Codegen flag
# Set FASTMODEL_CODEGEN = True to replace the construction loop with a 
# per-class unrolled function that eliminates tuple unpacking and attribute 
# lookups.
# ---------------------------------------------------------------------------
FASTMODEL_CODEGEN: bool = False


def _fast_construct(cls, data: dict) -> "FastModel":
    """Construct an instance from already-validated data without re-validating.

    Called only after __fast_validator__ has returned True, so every field is
    guaranteed to be present and type-correct.  The loop applies defaults for
    missing-but-defaulted fields and recurses into nested FastModel fields.
    Transforms are applied here so the stored value always matches what
    __init__ would store.

    This is the loop version — always correct, readable, produces real
    tracebacks.  When FASTMODEL_CODEGEN is True, each class gets a compiled
    replacement bound to cls.__fast_construct__ instead.
    """
    instance = object.__new__(cls)
    sa = object.__setattr__
    MISSING = _MISSING
    
    # Localize attribute lookups to avoid per-iteration dict lookups
    field_meta = cls.__field_meta__
    compiled_fields = cls.__compiled_fields__
    
    for fname, is_nested, nested_cls, default_getter, nullable in field_meta:
        value = data.get(fname, MISSING)
        if value is MISSING:
            value = default_getter()  # Only called when value is actually missing
            if value is MISSING:
                value = None if nullable else MISSING
        elif is_nested and isinstance(value, dict):
            # Delegate to the nested class's own construct
            value = nested_cls.__fast_construct__(data=value)
        else:
            # Apply transform if present
            cr = compiled_fields[fname]
            tf = cr.transform
            if tf is not None:
                value = tf(value)
        sa(instance, fname, value)
    return instance


def _build_fast_construct(cls) -> Callable:
    """Compile a class-specific construction function for cls.

    The compiled function has the same contract as _fast_construct:
    called only after __fast_validator__ has returned True.

    Falls back to a closure over _fast_construct if exec fails (e.g. in a
    restricted environment).
    """
    field_meta = cls.__field_meta__       # tuple of (fname, is_nested, nested_cls, dg, nullable)
    compiled   = cls.__compiled_fields__  # fname -> _CompiledRule

    ns: dict[str, Any] = {
        "__new__":        object.__new__,
        "MISSING":        _MISSING,
        "cls":            cls,
    }

    lines: list[str] = [
        "def _fast_construct_compiled(data):",
        "    inst = __new__(cls)",
        "    _d = inst.__dict__",
    ]

    for idx, (fname, is_nested, nested_cls, default_getter, nullable) in enumerate(field_meta):
        cr = compiled[fname]
        has_default = nullable or cls.__field_rules__[fname].has_default
        has_transform = cr.transform is not None

        ns[f"_f{idx}"] = fname

        if is_nested:
            ns[f"_nvc{idx}"] = nested_cls.__fast_construct__
            if has_default:
                ns[f"_dg{idx}"] = default_getter
                lines.append(f"    try: _v{idx} = data[_f{idx}]")
                lines.append(f"    except KeyError:")
                lines.append(f"        _v{idx} = _dg{idx}()")
                if nullable:
                    lines.append(f"        if _v{idx} is MISSING: _v{idx} = None")
                else:
                    lines.append(f"        if _v{idx} is MISSING: _v{idx} = MISSING")
            else:
                lines.append(f"    try: _v{idx} = data[_f{idx}]")
                lines.append(f"    except KeyError: _v{idx} = MISSING")
            lines.append(f"    if isinstance(_v{idx}, dict):")
            lines.append(f"        _v{idx} = _nvc{idx}(data=_v{idx})")
            lines.append(f"    _d[_f{idx}] = _v{idx}")

        elif has_default:
            # Field with default/nullable: use try/except, apply transform on non-default values
            ns[f"_dg{idx}"] = default_getter
            if has_transform:
                ns[f"_tf{idx}"] = cr.transform
            lines.append(f"    try: _v{idx} = data[_f{idx}]")
            lines.append(f"    except KeyError:")
            lines.append(f"        _v{idx} = _dg{idx}()")
            if nullable:
                lines.append(f"        if _v{idx} is MISSING: _v{idx} = None")
            else:
                lines.append(f"        if _v{idx} is MISSING: _v{idx} = MISSING")
            lines.append(f"    else:")
            if has_transform:
                lines.append(f"        _v{idx} = _tf{idx}(_v{idx})")
            lines.append(f"    _d[_f{idx}] = _v{idx}")

        else:
            # FAST PATH: required field, no default, not nested
            # Happy path: lookup → assign (no branches, no MISSING check)
            if has_transform:
                ns[f"_tf{idx}"] = cr.transform
            lines.append(f"    try: _v{idx} = data[_f{idx}]")
            lines.append(f"    except KeyError: _v{idx} = MISSING")
            if has_transform:
                lines.append(f"    if _v{idx} is not MISSING: _v{idx} = _tf{idx}(_v{idx})")
            lines.append(f"    _d[_f{idx}] = _v{idx}")

    lines.append("    return inst")

    try:
        code = "\n".join(lines)
        exec(compile(code, f"<fast_construct_{cls.__name__}>", "exec"), ns)  # noqa: S102
        return ns["_fast_construct_compiled"]
    except Exception:
        # Restricted environment or exec failure — fall back to the generic loop.
        def _fallback(data: dict) -> "FastModel":
            return _fast_construct(cls, data)
        return _fallback


# ---------------------------------------------------------------------------
# Fused single-pass validate + construct
# ---------------------------------------------------------------------------

def _fused_vc_loop(cls, data: dict):
    """Loop-based fallback for fused validate+construct."""
    if not isinstance(data, dict):
        return None
    instance = object.__new__(cls)
    sa = object.__setattr__
    MISSING = _MISSING
    
    for fname, is_nested, nested_cls, default_getter, nullable in cls.__field_meta__:
        value = data.get(fname, MISSING)
        if value is MISSING:
            value = default_getter()
            if value is MISSING:
                if nullable:
                    value = None
                else:
                    return None
        
        if is_nested:
            if isinstance(value, dict):
                value = nested_cls.__fast_vc__(value)
                if value is None:
                    return None
            sa(instance, fname, value)
        else:
            cr = cls.__compiled_fields__[fname]
            if not cr.fast_validator(value):
                return None
            if cr.transform is not None:
                value = cr.transform(value)
            sa(instance, fname, value)
            
    return instance


def _build_fused_validate_construct(cls) -> Callable:
    """Compile a single-pass validate-and-construct function for cls.
    
    Walks the data dict exactly once: for each field it validates inline
    and, on success, sets the attribute immediately. On any failure it
    returns None (the partial instance is discarded).
    
    For nested FastModel fields, it calls the nested class's own
    __fast_vc__ directly — no double-walk, no separate __fast_validator__.
    
    Contract: returns (instance | None).
    """
    field_meta = cls.__field_meta__
    compiled   = cls.__compiled_fields__
    
    ns: dict[str, Any] = {
        "__new__":  object.__new__,
        "MISSING":  _MISSING,
        "cls":      cls,
    }
    
    lines: list[str] = [
        "def _vc(data):",
        "    if not isinstance(data, dict): return None",
        "    inst = __new__(cls)",
        "    _d = inst.__dict__",
    ]
    
    for idx, (fname, is_nested, nested_cls, default_getter, nullable) in enumerate(field_meta):
        cr = compiled[fname]
        has_default = nullable or cls.__field_rules__[fname].has_default
        has_transform = cr.transform is not None
        
        ns[f"_f{idx}"] = fname
        
        if is_nested:
            # Nested FastModel field — call nested __fast_vc__ directly
            ns[f"_nvc{idx}"] = nested_cls.__fast_vc__
            if has_default:
                ns[f"_dg{idx}"] = default_getter
                lines.append(f"    try: _v{idx} = data[_f{idx}]")
                lines.append(f"    except KeyError:")
                lines.append(f"        _v{idx} = _dg{idx}()")
                if nullable:
                    lines.append(f"        if _v{idx} is MISSING: _v{idx} = None")
                else:
                    lines.append(f"        if _v{idx} is MISSING: return None")
            else:
                lines.append(f"    try: _v{idx} = data[_f{idx}]")
                lines.append(f"    except KeyError: return None")
            lines.append(f"    if isinstance(_v{idx}, dict):")
            lines.append(f"        _v{idx} = _nvc{idx}(_v{idx})")
            lines.append(f"        if _v{idx} is None: return None")
            lines.append(f"    _d[_f{idx}] = _v{idx}")
            
        elif has_default:
            # Field with default/nullable: use try/except, skip validation for defaults
            ns[f"_dg{idx}"] = default_getter
            ns[f"_fv{idx}"] = cr.fast_validator
            if has_transform:
                ns[f"_tf{idx}"] = cr.transform
            lines.append(f"    try: _v{idx} = data[_f{idx}]")
            lines.append(f"    except KeyError:")
            lines.append(f"        _v{idx} = _dg{idx}()")
            if nullable:
                lines.append(f"        if _v{idx} is MISSING: _v{idx} = None")
            else:
                lines.append(f"        if _v{idx} is MISSING: return None")
            lines.append(f"    else:")
            lines.append(f"        if not _fv{idx}(_v{idx}): return None")
            if has_transform:
                lines.append(f"        _v{idx} = _tf{idx}(_v{idx})")
            lines.append(f"    _d[_f{idx}] = _v{idx}")
            
        else:
            # FAST PATH: required field, no default, not nested
            # Happy path: lookup → validate → assign (no branches, no MISSING check)
            ns[f"_fv{idx}"] = cr.fast_validator
            if has_transform:
                ns[f"_tf{idx}"] = cr.transform
            lines.append(f"    try: _v{idx} = data[_f{idx}]")
            lines.append(f"    except KeyError: return None")
            lines.append(f"    if not _fv{idx}(_v{idx}): return None")
            if has_transform:
                lines.append(f"    _v{idx} = _tf{idx}(_v{idx})")
            lines.append(f"    _d[_f{idx}] = _v{idx}")
    
    lines.append("    return inst")
    
    try:
        code = "\n".join(lines)
        exec(compile(code, f"<fast_vc_{cls.__name__}>", "exec"), ns)
        return ns["_vc"]
    except Exception:
        # Fallback to loop-based fused path if exec is restricted
        return lambda data, _c=cls: _fused_vc_loop(_c, data)


def _diagnose_to_field_messages(diag: dict) -> tuple[bool, list[str]]:
    """Extract bare message strings from a diagnose() result.

    Returns (ok, [message, ...]) — field name is intentionally excluded
    because callers always know the field name and store it as the dict key.
    """
    if diag.get("valid", True):
        return True, []
    if "failures" in diag:
        return False, [f["message"] for f in diag["failures"]]
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
    ok, msgs = _diagnose_to_field_messages(diag)

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
# Internal helpers for compiled rule caching
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
        rule_str=None,
    )


def _compiled_rule_for(rule_obj: Rule) -> _fast._CompiledRule:
    """
    Convert a Rule into a _CompiledRule.

    Always resolves the full pipe string via _resolve_rule_string() so that
    kwargs (choices, min, max, pattern, transforms, msg, etc.) are included
    regardless of whether the Rule was built from a raw string or keyword args.
    Falls back to compile() and then to a trivial pass-through on error.
    """
    # Resolve the canonical pipe string (idempotent, returns None for unconstrained).
    try:
        resolved = rule_obj._resolve_rule_string()
    except ValueError:
        # Unknown transform or other author error — re-raise so the class body
        # sees it immediately rather than silently producing a broken model.
        raise
    except Exception:
        resolved = None

    # Preferred: resolved pipe string → fully cached _CompiledRule with
    # message support, transforms, custom_msg, etc.
    if resolved is not None:
        try:
            cr = _fast._get_compiled_rule(resolved)
            if getattr(cr, "rule_str", None) is None:
                cr.rule_str = resolved
            return cr
        except Exception:
            pass

    # Fallback: compile() (uses the same resolved string internally).
    try:
        compiled_fn, compiled_struct = rule_obj.compile()
    except Exception:
        return _make_trivial_compiled_rule()

    # If fast.py already gave us a proper _CompiledRule, use it directly.
    if isinstance(compiled_struct, _fast._CompiledRule):
        if getattr(compiled_struct, "rule_str", None) is None:
            compiled_struct.rule_str = resolved
        return compiled_struct

    # Build a minimal wrapper so the hot-path loop needs no isinstance checks.
    nullable = getattr(compiled_struct, "nullable", False) if compiled_struct else False
    nullable = nullable or rule_obj.nullable
    transform = getattr(compiled_struct, "transform", None) if compiled_struct else None

    return _fast._CompiledRule(
        fast_validator=compiled_fn,
        checks=[compiled_fn],
        nullable=nullable,
        type_name="any",
        transform=transform,
        validator_names=["type"],
        validator_args=[None],
        rule_str=resolved,
    )


# ---------------------------------------------------------------------------
# Metaclass — builds schema and compiled validator
# ---------------------------------------------------------------------------

class _FastModelMeta(type):
    """
    Collect annotated fields and Rule instances at class creation time.
    """
    def __new__(mcls, name: str, bases: tuple, namespace: dict, **kwargs):
        cls = super().__new__(mcls, name, bases, dict(namespace))

        # --- Collect annotations ---
        annotations: Dict[str, Any] = {}
        for base in reversed(bases):
            annotations.update(getattr(base, "__annotations__", {}) or {})
        annotations.update(namespace.get("__annotations__", {}) or {})

        field_annotations = {
            k: v for k, v in annotations.items()
            if not (isinstance(v, str) and v.startswith("ClassVar"))
            and not (hasattr(v, "__origin__") and v.__origin__ is ClassVar)
        }

        # Storage
        cls.__validated_fields__: Dict[str, Any] = {}
        cls.__field_rules__: Dict[str, Rule] = {}
        cls.__compiled_fields__: Dict[str, _fast._CompiledRule] = {}
        
        # Populate fields
        for field_name, annot in field_annotations.items():
            raw = namespace.get(field_name, _MISSING)

            rule_from_annotation: Rule | None = None
            if get_origin(annot) is Annotated:
                args = get_args(annot)
                annot = args[0]
                for meta in args[1:]:
                    if isinstance(meta, Rule):
                        rule_from_annotation = meta
                        break

            if rule_from_annotation is not None:
                rule_obj = rule_from_annotation
            elif isinstance(raw, Rule):
                rule_obj = raw
            elif raw is not _MISSING:
                rule_obj = Rule(default=raw)
            else:
                rule_obj = Rule()

            cls.__validated_fields__[field_name] = annot
            cls.__field_rules__[field_name] = rule_obj

            if rule_obj.rule is None and "type" not in rule_obj.kwargs:
                origin = get_origin(annot) or annot
                if origin in (int, float, bool, str, list, tuple, set, dict):
                    rule_obj.kwargs["type"] = origin.__name__

            cls.__compiled_fields__[field_name] = _compiled_rule_for(rule_obj)

        # Resolve nested models
        try:
            cls.__resolved_hints__ = get_type_hints(cls)
        except Exception:
            cls.__resolved_hints__ = dict(cls.__validated_fields__)

        cls.__nested_model_fields__ = {
            fname: hint
            for fname, hint in cls.__resolved_hints__.items()
            if fname in cls.__validated_fields__
            and isinstance(hint, type)
            and issubclass(hint, FastModel)
            and hint is not FastModel
        }

        # --- Build __field_meta__ for fast construction ---
        cls.__field_meta__ = tuple(
            (
                fname,
                fname in cls.__nested_model_fields__,
                cls.__nested_model_fields__.get(fname),
                cls.__field_rules__[fname].get_default,
                cls.__compiled_fields__[fname].nullable,
            )
            for fname in cls.__validated_fields__
        )

        # --- Build rule dict and compile validator ---
        def _build_rule_dict(cls) -> Dict[str, Any]:
            rule_dict = {}
            for fname, rule_obj in cls.__field_rules__.items():
                if fname in cls.__nested_model_fields__:
                    nested_cls = cls.__nested_model_fields__[fname]
                    rule_dict[fname] = nested_cls.__rule_dict__
                else:
                    cr = cls.__compiled_fields__[fname]
                    rule_str = getattr(cr, "rule_str", None)
                    if rule_str is None:
                        kwargs_copy = rule_obj.kwargs.copy()
                        t = kwargs_copy.pop("type", "any")
                        parts = [str(t)]
                        for k, v in kwargs_copy.items():
                            if v is True or v is None:
                                parts.append(k)
                            else:
                                parts.append(f"{k}:{v}")
                        rule_str = "|".join(parts)
                    
                    # Fields with defaults are effectively optional for dict validation
                    if rule_obj.has_default and "nullable" not in rule_str.split("|"):
                        rule_str = rule_str + "|nullable"
                    
                    rule_dict[fname] = rule_str
            return rule_dict

        cls.__rule_dict__ = _build_rule_dict(cls)

        try:
            cls.__fast_validator__ = validator(cls.__rule_dict__)
        except Exception as e:
            print(f"⚠️ FastModel validator compilation failed for {name}: {e}")
            cls.__fast_validator__ = None

        # Build __fast_construct__
        if FASTMODEL_CODEGEN:
            cls.__fast_construct__ = _build_fast_construct(cls)
        else:
            _cls = cls
            cls.__fast_construct__ = lambda data, _c=_cls: _fast_construct(_c, data)

        # Build fused single-pass validate+construct
        cls.__fast_vc__ = _build_fused_validate_construct(cls)
        if cls.__fast_vc__ is None:
            def _fallback_vc(data, _c=cls):
                if _c.__fast_validator__ is not None and _c.__fast_validator__(data):
                    return _c.__fast_construct__(data=data)
                return None
            cls.__fast_vc__ = _fallback_vc

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
    
    __fast_validator__ = None
    __fast_construct__ = None
    __fast_vc__ = None

    # ------------------------------------------------------------------
    # Construction — the hot path
    # ------------------------------------------------------------------

    def __init__(self, **kwargs):
        cls = self.__class__
        errors: Dict[str, List[str]] = {}

        def _add_error(field: str, messages: list[str]) -> None:
            errors.setdefault(field, []).extend(messages)

        # Resolve values
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
                data[fname] = default

        # Validate each field
        for fname, val in data.items():
            cr = cls.__compiled_fields__[fname]

            if val is _MISSING:
                _add_error(fname, ["field is required"])
                continue

            if val is None and cr.nullable:
                object.__setattr__(self, fname, None)
                continue

            # === Nested FastModel handling ===
            # Recurse into the nested model's own __init__ so its errors are
            # produced by the same rich diagnostic path. The nested
            # ValidationError.errors dict is attached as-is (not flattened)
            # under the field name, matching the shape check() already
            # produces, since ValidationError now knows how to stringify
            # nested dicts.
            if fname in cls.__nested_model_fields__:
                nested_cls = cls.__nested_model_fields__[fname]
                if isinstance(val, nested_cls):
                    object.__setattr__(self, fname, val)
                elif isinstance(val, dict):
                    try:
                        nested_instance = nested_cls(**val)
                        object.__setattr__(self, fname, nested_instance)
                    except ValidationError as nested_exc:
                        if nested_exc.errors:
                            errors[fname] = nested_exc.errors
                        else:
                            _add_error(fname, [str(nested_exc)])
                    except Exception as e:
                        _add_error(fname, [f"nested model error: {e}"])
                else:
                    _add_error(fname, ["expected dict for nested model"])
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

        # model_check
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
                if exc.errors:
                    for field, msgs in exc.errors.items():
                        if isinstance(msgs, dict):
                            errors[field] = msgs
                        else:
                            _add_error(field, msgs)
                else:
                    _add_error("__model__", [str(exc)])
            except Exception as exc:
                _add_error("__model__", [f"model_check: {exc}"])

        if errors:
            raise ValidationError(errors)

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def is_valid(self, *, field: Optional[str] = None, apply_transforms: bool = False) -> bool:
        cls = self.__class__

        def _get_callable_and_value(cr, val):
            fn = getattr(cr, "fast_validator", None)
            if fn is None:
                rule_str = getattr(cr, "rule_str", None)
                if rule_str is None:
                    return None, val
                fn = validator(rule_str)
            return fn, val

        if field is not None:
            if field not in cls.__validated_fields__:
                return False
            cr = cls.__compiled_fields__[field]
            val = getattr(self, field, _MISSING)
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
            if fn is None:
                return False
            return bool(fn(v))

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
        if not apply_transforms and cls.__fast_validator__ is not None:
            return cls.__fast_validator__(data)

        # Fallback slow path
        for fname, val in data.items():
            if fname not in cls.__validated_fields__:
                return False

            cr = cls.__compiled_fields__[fname]
            if val is _MISSING:
                return False

            if apply_transforms and getattr(cr, "transform", None) is not None:
                try:
                    v = cr.transform(val)
                except Exception:
                    return False
            else:
                v = val

            fn = getattr(cr, "fast_validator", None)
            if fn is None:
                rule_str = getattr(cr, "rule_str", None)
                if rule_str is None:
                    return False
                fn = validator(rule_str)

            if not fn(v):
                return False

        return True

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self, recursive: bool = True) -> Dict[str, Any]:
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

        if validate == "check":
            # Single-pass fused validate+construct
            if cls.__fast_vc__ is not None:
                return cls.__fast_vc__(data)
            # Fallback two-pass path
            if cls.__fast_validator__ is None or not cls.__fast_validator__(data):
                return None
            return cls.__fast_construct__(data=data)

        # --- validate=False: fast bypass using __field_meta__ ---
        instance = object.__new__(cls)
        _d = instance.__dict__
        data_get = data.get
        MISSING = _MISSING

        for fname, is_nested, nested_cls, default_getter, nullable in cls.__field_meta__:
            value = data_get(fname, MISSING)
            if value is MISSING:
                value = default_getter()
                if value is MISSING:
                    value = None if nullable else MISSING
            else:
                if is_nested and isinstance(value, dict):
                    value = nested_cls.from_dict(value, validate=False)
            _d[fname] = value

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
    def check(cls, data: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """
        Partial validation without instantiation.

        Returns ``(ok, errors)`` — never raises.  Nested FastModel fields are
        recursively validated; their errors are returned as a nested dict
        (``{"address": {"zipcode": ["..."]}}``) rather than a flat list.

        Example::

            ok, errors = User.check({"username": "x"})
            # ok=False, errors={"username": ["value is too short (minimum length: 3)"]}

            ok, errors = Person.check({"name": "Alice", "address": {"zipcode": "bad"}})
            # ok=False, errors={"address": {"zipcode": ["..."]}}
        """
        errors: Dict[str, Any] = {}
        for fname, val in data.items():
            if fname not in cls.__validated_fields__:
                errors.setdefault(fname, []).append("unknown field")
                continue

            # === Nested FastModel handling ===
            # Recurse into the nested model's own `check` so its errors come
            # back as a nested dict (field -> {subfield -> [msgs]}) instead
            # of a single generic "expected dict"-style message.
            if fname in cls.__nested_model_fields__:
                nested_cls = cls.__nested_model_fields__[fname]
                cr = cls.__compiled_fields__[fname]
                if isinstance(val, dict):
                    nested_ok, nested_errors = nested_cls.check(val)
                    if not nested_ok:
                        errors[fname] = nested_errors
                elif val is None and cr.nullable:
                    continue
                else:
                    errors.setdefault(fname, []).append("expected dict for nested model")
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
            has_default = rule_obj.has_default
            
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
        
        
    @classmethod
    def openapi_schema(cls, version: str = "3.0") -> Dict[str, Any]:
        """
        Generate an OpenAPI compatible schema object for this FastModel.
        
        Args:
            version: Target OpenAPI version, either "3.0" or "3.1". Defaults to "3.0".
        """
        from .rule import _MISSING
        
        if version not in ("3.0", "3.1"):
            raise ValueError("openapi_schema version must be '3.0' or '3.1'")
            
        schema: Dict[str, Any] = {
            "type": "object",
            "title": cls.__name__,
            "properties": {},
        }
        required: List[str] = []

        for fname, rule_obj in cls.__field_rules__.items():
            cr = cls.__compiled_fields__.get(fname)
            field_schema: Dict[str, Any] = {"title": fname}

            # Required, Default, Nullable
            is_nullable = cr.nullable if cr else rule_obj.nullable
            if not rule_obj.has_default and not is_nullable:
                required.append(fname)
            elif rule_obj.default is not _MISSING and not callable(rule_obj.default):
                field_schema["default"] = rule_obj.default

            if is_nullable and version == "3.0":
                field_schema["nullable"] = True

            # Extract description (from kwargs['msg'] or cr.custom_msg)
            description = rule_obj.kwargs.get("msg")
            if cr and not description:
                description = getattr(cr, "custom_msg", None)
            if description:
                field_schema["description"] = str(description)

            # Nested Models
            if fname in getattr(cls, '__nested_model_fields__', {}):
                nested_cls = cls.__nested_model_fields__[fname]
                nested_schema = nested_cls.openapi_schema(version=version)
                
                # Merge nested schema while preserving field-level metadata (like description)
                for k, v in nested_schema.items():
                    if k not in field_schema:
                        field_schema[k] = v
                        
                # Handle OpenAPI 3.1 nullability for nested objects
                if is_nullable and version == "3.1":
                    if "type" in field_schema and isinstance(field_schema["type"], str):
                        field_schema["type"] = [field_schema["type"], "null"]
                        
                schema["properties"][fname] = field_schema
                continue

            # Determine base type and map to OpenAPI type + format
            base_type = cls._get_base_type(rule_obj, cr)
            openapi_type, openapi_format = cls._map_type_to_openapi(base_type)
            
            if openapi_type:
                # OpenAPI 3.1 uses JSON Schema type arrays for nullability
                if is_nullable and version == "3.1":
                    field_schema["type"] = [openapi_type, "null"]
                else:
                    field_schema["type"] = openapi_type
                    
            if openapi_format:
                field_schema["format"] = openapi_format

            # Array items
            if openapi_type == "array":
                items_schema = cls._get_array_items_schema(rule_obj, cr)
                if items_schema:
                    field_schema["items"] = items_schema

            # Constraints
            cls._add_constraints_to_schema(
                field_schema, rule_obj, cr, openapi_type, 
                version=version, is_nullable=is_nullable
            )

            schema["properties"][fname] = field_schema

        if required:
            schema["required"] = required

        return schema

    @classmethod
    def _get_base_type(cls, rule_obj, cr) -> str:
        """Extract base type preferring compiled metadata, then kwargs, then rule string."""
        if cr and getattr(cr, "type_name", None):
            return cr.type_name.lower()
            
        if "type" in rule_obj.kwargs:
            return str(rule_obj.kwargs["type"]).lower()

        try:
            rule_str = rule_obj._resolve_rule_string() or getattr(rule_obj, 'rule', '')
            if rule_str:
                token = str(rule_str).split("|")[0].strip()
                raw = token.split(":")[0].split("[")[0]
                return raw.lower()
        except Exception:
            pass

        return "string"

    @classmethod
    def _map_type_to_openapi(cls, base_type: str) -> tuple[Optional[str], Optional[str]]:
        """Map FastModel types to OpenAPI types and formats."""
        type_map = {
            "int": ("integer", None),
            "float": ("number", None),
            "number": ("number", None),
            "bool": ("boolean", None),
            "boolean": ("boolean", None),
            "list": ("array", None),
            "tuple": ("array", None),
            "set": ("array", None),
            "dict": ("object", None),
            "object": ("object", None),
            "email": ("string", "email"),
            "url": ("string", "uri"),
            "uuid": ("string", "uuid"),
            "date": ("string", "date"),
            "datetime": ("string", "date-time"),
            "ip": ("string", "ipv4"),
            "ipv4": ("string", "ipv4"),
            "ipv6": ("string", "ipv6"),
        }
        return type_map.get(base_type, ("string", None))

    @classmethod
    def _get_array_items_schema(cls, rule_obj, cr) -> Optional[Dict[str, Any]]:
        """Extract items schema for list[T] style declarations."""
        try:
            rule_str = getattr(cr, "rule_str", None) or rule_obj._resolve_rule_string()
            if not rule_str:
                return None
                
            first_token = rule_str.split("|")[0].strip()
            if "[" not in first_token or not first_token.endswith("]"):
                return None

            inner = first_token.split("[", 1)[1].rsplit("]", 1)[0].strip()
            if not inner:
                return {}

            inner_type, inner_format = cls._map_type_to_openapi(inner.lower())
            items: Dict[str, Any] = {}
            if inner_type:
                items["type"] = inner_type
            if inner_format:
                items["format"] = inner_format
            return items
        except Exception:
            return None

    @classmethod
    def _add_constraints_to_schema(
        cls,
        field_schema: Dict[str, Any],
        rule_obj,
        cr,
        openapi_type: Optional[str],
        version: str = "3.0",
        is_nullable: bool = False
    ):
        """Add constraints extracting from both kwargs and compiled metadata."""
        compiled_constraints = {}
        if cr and hasattr(cr, "validator_names") and hasattr(cr, "validator_args"):
            for name, arg in zip(cr.validator_names, cr.validator_args):
                compiled_constraints[name] = arg

        # Resolve Min / Max Bounds (including 'between' ranges)
        min_val = rule_obj.kwargs.get("min")
        max_val = rule_obj.kwargs.get("max")
        
        if min_val is None and "min" in compiled_constraints:
            min_val = compiled_constraints["min"]
        if max_val is None and "max" in compiled_constraints:
            max_val = compiled_constraints["max"]
            
        between_val = rule_obj.kwargs.get("between")
        if between_val is not None:
            if isinstance(between_val, (list, tuple)) and len(between_val) == 2:
                if min_val is None: min_val = between_val[0]
                if max_val is None: max_val = between_val[1]
        elif "between" in compiled_constraints:
            parts = str(compiled_constraints["between"]).split(",", 1)
            if len(parts) == 2:
                if min_val is None: min_val = parts[0].strip()
                if max_val is None: max_val = parts[1].strip()

        # Apply resolved Min / Max based on OpenAPI Type
        if openapi_type in ("integer", "number"):
            coercer = int if openapi_type == "integer" else float
            if min_val is not None:
                try:
                    field_schema["minimum"] = coercer(min_val)
                except (ValueError, TypeError):
                    pass
            if max_val is not None:
                try:
                    field_schema["maximum"] = coercer(max_val)
                except (ValueError, TypeError):
                    pass
        elif openapi_type == "string":
            if min_val is not None:
                try:
                    field_schema["minLength"] = int(min_val)
                except (ValueError, TypeError):
                    pass
            if max_val is not None:
                try:
                    field_schema["maxLength"] = int(max_val)
                except (ValueError, TypeError):
                    pass
        elif openapi_type == "array":
            if min_val is not None:
                try:
                    field_schema["minItems"] = int(min_val)
                except (ValueError, TypeError):
                    pass
            if max_val is not None:
                try:
                    field_schema["maxItems"] = int(max_val)
                except (ValueError, TypeError):
                    pass

        # Resolve Length Constraints
        length_val = rule_obj.kwargs.get("length")
        if length_val is None and "length" in compiled_constraints:
            length_val = compiled_constraints["length"]

        if length_val is not None:
            try:
                length_int = int(length_val)
                if openapi_type == "string":
                    field_schema["minLength"] = field_schema["maxLength"] = length_int
                elif openapi_type == "array":
                    field_schema["minItems"] = field_schema["maxItems"] = length_int
            except (ValueError, TypeError):
                pass

        # Resolve Enum / Choices
        choices = rule_obj.kwargs.get("choices")
        if choices is None and "in" in compiled_constraints:
            raw_in = compiled_constraints["in"]
            choices = [c.strip() for c in str(raw_in).split(",")]

        if choices is not None:
            if not isinstance(choices, (list, tuple, set)):
                choices = [choices]
            else:
                choices = list(choices)
            
            # Coerce enums dynamically so swagger UI sends correct JSON types
            if openapi_type == "integer":
                choices = [int(x) for x in choices if str(x).lstrip('-').isdigit()]
            elif openapi_type == "number":
                choices = [float(x) for x in choices if str(x).replace('.', '', 1).lstrip('-').isdigit()]
            else:
                choices = [str(x) for x in choices]
                
            # If 3.1 and nullable, enum MUST explicitly permit None (null)
            if version == "3.1" and is_nullable and None not in choices:
                choices.append(None)
                
            if choices:
                field_schema["enum"] = choices

        # Resolve Regex Patterns
        pattern = rule_obj.kwargs.get("pattern")
        if pattern is None and "re" in compiled_constraints:
            pattern = compiled_constraints["re"]

        if pattern is not None:
            field_schema["pattern"] = str(pattern)
            
    @classmethod
    def get_rules(cls) -> Dict[str, Any]:
        """
        Return the canonical rule dictionary for this model.

        Each key is a field name.  Each value is either:
        * a pipe string (``"str|min:3|max:32"``) for scalar fields, or
        * a nested rule dict for fields whose type is a FastModel subclass.

        This is the same structure passed to ``compiled.validator`` at
        class-creation time, so it can be inspected, serialised, or fed
        directly into another validator.

        Example::

            User.get_rules()
            # {
            #   "username": "str|min:3|max:32|nullable",
            #   "email":    "email",
            #   "address":  {"street": "str", "city": "str"},
            # }
        """
        return cls.__rule_dict__

    @classmethod
    def get_validator(cls) -> Callable[[Dict[str, Any]], bool]:
        """
        Return the compiled fast-path validator callable for this model.

        The callable accepts a single ``dict`` argument and returns ``True``
        when the data passes all field rules, ``False`` otherwise.  It is
        the same function stored on ``__fast_validator__`` and used internally
        by ``is_valid_data`` and ``from_dict``.

        If the cached ``__fast_validator__`` is ``None``, a fresh validator
        is compiled from the model's rule dictionary and cached for future calls.

        Example::

            validate = User.get_validator()
            if validate({"username": "alice", "email": "alice@example.com"}):
                ...
        """
        if cls.__fast_validator__ is not None:
            return cls.__fast_validator__
        
        v = validator(cls.__rule_dict__)
        cls.__fast_validator__ = v
        return v
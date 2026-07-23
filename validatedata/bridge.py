# validatedata/bridge.py
import sys
import types
from typing import Any, Callable, Dict, Optional, Type,Union, get_args, get_origin, get_type_hints

from .rule import Rule, _MISSING

def _is_external_model(t):
    return isinstance(t, type) and (
        hasattr(t, "model_fields") or 
        hasattr(t, "__struct_fields__") or 
        hasattr(t, "__dataclass_fields__")
    )

def _extract_external_model(t):
    """Find an external model in a type annotation, unwrapping Optional if needed."""
    if _is_external_model(t):
        return t
    origin = get_origin(t)
    is_union = origin is Union or (hasattr(types, "UnionType") and origin is types.UnionType)
    if is_union:
        args = get_args(t)
        for arg in args:
            if _is_external_model(arg):
                return arg
    return None

def build_bridged_model(
    fastmodel_base: Type[Any],
    source_model: Any,
    field_overrides: Optional[Dict[str, Any]] = None,
    model_check: Optional[Callable] = None,
    extra_rules: Optional[Dict[str, Any]] = None,
) -> Any:
    """
    Core implementation for bridging external models to FastModel.
    If an instance is passed, returns a populated FastModel instance.
    """
    is_instance = not isinstance(source_model, type)
    instance_data = None

    if is_instance:
        instance = source_model
        source_model = type(instance)
        
        if hasattr(instance, "model_dump"):
            instance_data = instance.model_dump()
        elif hasattr(instance, "__dataclass_fields__"):
            import dataclasses
            instance_data = dataclasses.asdict(instance)
        elif hasattr(instance, "__struct_fields__"):
            import msgspec
            instance_data = {f.name: getattr(instance, f.name) for f in msgspec.structs.fields(instance)}
        else:
            instance_data = instance.__dict__

    namespace: Dict[str, Any] = {}
    annotations: Dict[str, Any] = {}
    overrides = field_overrides or {}
    extra = extra_rules or {}

    # 1. Pydantic (v2) Integration
    if hasattr(source_model, "model_fields"):
        for name, field in source_model.model_fields.items():
            if name in overrides:
                namespace[name] = overrides[name]
                annotations[name] = field.annotation
                continue

            annotations[name] = field.annotation
            kwargs = {}
            
            for meta in field.metadata:
                if hasattr(meta, "min_length") and meta.min_length is not None: kwargs["min"] = meta.min_length
                if hasattr(meta, "max_length") and meta.max_length is not None: kwargs["max"] = meta.max_length
                if hasattr(meta, "ge") and meta.ge is not None: kwargs["min"] = meta.ge
                if hasattr(meta, "le") and meta.le is not None: kwargs["max"] = meta.le
                if hasattr(meta, "pattern") and meta.pattern is not None: kwargs["pattern"] = meta.pattern
                
            if not field.is_required():
                if field.default_factory is not None:
                    kwargs["default_factory"] = field.default_factory
                else:
                    kwargs["default"] = field.default

            ext_model = _extract_external_model(field.annotation)
            if ext_model:
                bridged = build_bridged_model(fastmodel_base, ext_model)
                if field.annotation is ext_model:
                    annotations[name] = bridged
                else:
                    annotations[name] = Optional[bridged]
                    # Optional implies nullable
                    kwargs["nullable"] = True
                
                if "default" in kwargs:
                    namespace[name] = Rule(default=kwargs["default"], nullable=kwargs.get("nullable", False))
                elif "default_factory" in kwargs:
                    namespace[name] = Rule(default_factory=kwargs["default_factory"], nullable=kwargs.get("nullable", False))
                else:
                    namespace[name] = Rule(nullable=kwargs.get("nullable", False))
            elif name in extra:
                e_rule = extra[name]
                if isinstance(e_rule, Rule):
                    namespace[name] = e_rule
                elif isinstance(e_rule, dict):
                    namespace[name] = Rule(**kwargs, **e_rule)
                else:
                    namespace[name] = Rule(rule=e_rule, **kwargs)
            else:
                namespace[name] = Rule(**kwargs) if kwargs else _MISSING

    # 2. Msgspec Integration
    elif hasattr(source_model, "__struct_fields__"):
        import msgspec
        try:
            hints = get_type_hints(source_model, include_extras=True)
        except TypeError:
            try:
                hints = get_type_hints(source_model)
            except Exception:
                hints = {}
        except Exception:
            hints = {}
            
        for field in msgspec.structs.fields(source_model):
            name = field.name
            if name in overrides:
                namespace[name] = overrides[name]
                annotations[name] = field.type
                continue
            
            t = hints.get(name, field.type)
            annotations[name] = t
            kwargs = {}
            
            if hasattr(t, "__metadata__"):
                for arg in t.__metadata__:
                    if isinstance(arg, msgspec.Meta):
                        if arg.min_length is not None: kwargs["min"] = arg.min_length
                        if arg.max_length is not None: kwargs["max"] = arg.max_length
                        if arg.ge is not None: kwargs["min"] = arg.ge
                        if arg.le is not None: kwargs["max"] = arg.le
                        if arg.pattern is not None: kwargs["pattern"] = arg.pattern
            
            if field.default is not msgspec.NODEFAULT: kwargs["default"] = field.default
            if field.default_factory is not msgspec.NODEFAULT: kwargs["default_factory"] = field.default_factory

            ext_model = _extract_external_model(t)
            if ext_model:
                bridged = build_bridged_model(fastmodel_base, ext_model)
                if t is ext_model:
                    annotations[name] = bridged
                else:
                    annotations[name] = Optional[bridged]
                    # Optional implies nullable
                    kwargs["nullable"] = True
                
                if "default" in kwargs:
                    namespace[name] = Rule(default=kwargs["default"], nullable=kwargs.get("nullable", False))
                elif "default_factory" in kwargs:
                    namespace[name] = Rule(default_factory=kwargs["default_factory"], nullable=kwargs.get("nullable", False))
                else:
                    namespace[name] = Rule(nullable=kwargs.get("nullable", False))
            elif name in extra:
                e_rule = extra[name]
                if isinstance(e_rule, Rule):
                    namespace[name] = e_rule
                elif isinstance(e_rule, dict):
                    namespace[name] = Rule(**kwargs, **e_rule)
                else:
                    namespace[name] = Rule(rule=e_rule, **kwargs)
            else:
                namespace[name] = Rule(**kwargs) if kwargs else _MISSING

    # 3. Dataclasses Integration
    elif hasattr(source_model, "__dataclass_fields__"):
        import dataclasses
        try:
            hints = get_type_hints(source_model, include_extras=True)
        except TypeError:
            try:
                hints = get_type_hints(source_model)
            except Exception:
                hints = {}
        except Exception:
            hints = {}
            
        for field in dataclasses.fields(source_model):
            name = field.name
            if name in overrides:
                namespace[name] = overrides[name]
                annotations[name] = field.type
                continue

            t = hints.get(name, field.type)
            annotations[name] = t
            kwargs = {}
            
            if field.default is not dataclasses.MISSING: kwargs["default"] = field.default
            elif field.default_factory is not dataclasses.MISSING: kwargs["default_factory"] = field.default_factory

            ext_model = _extract_external_model(t)
            if ext_model:
                bridged = build_bridged_model(fastmodel_base, ext_model)
                if t is ext_model:
                    annotations[name] = bridged
                else:
                    annotations[name] = Optional[bridged]
                    # Optional implies nullable
                    kwargs["nullable"] = True
                
                if "default" in kwargs:
                    namespace[name] = Rule(default=kwargs["default"], nullable=kwargs.get("nullable", False))
                elif "default_factory" in kwargs:
                    namespace[name] = Rule(default_factory=kwargs["default_factory"], nullable=kwargs.get("nullable", False))
                else:
                    namespace[name] = Rule(nullable=kwargs.get("nullable", False))
            elif name in extra:
                e_rule = extra[name]
                if isinstance(e_rule, Rule):
                    namespace[name] = e_rule
                elif isinstance(e_rule, dict):
                    namespace[name] = Rule(**kwargs, **e_rule)
                else:
                    namespace[name] = Rule(rule=e_rule, **kwargs)
            else:
                namespace[name] = Rule(**kwargs) if kwargs else _MISSING

    else:
        raise TypeError(f"Cannot bridge {source_model}: unsupported model type. Supported: Pydantic, msgspec, dataclasses.")

    # Final Assembly
    namespace["__annotations__"] = annotations
    if model_check:
        namespace["model_check"] = model_check

    NewModel = type(source_model.__name__, (fastmodel_base,), namespace)

    if is_instance:
        return NewModel(**instance_data)

    return NewModel
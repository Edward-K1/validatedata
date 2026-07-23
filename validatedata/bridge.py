# validatedata/bridge.py
import sys
import types
from typing import Any, Callable, Dict, Optional, Type, Union, get_args, get_origin, get_type_hints

from .rule import Rule, _MISSING


def _is_external_model(t: Any) -> bool:
    """Check if a type is a supported external model class."""
    return isinstance(t, type) and (
        hasattr(t, "model_fields") or 
        hasattr(t, "__struct_fields__") or 
        hasattr(t, "__dataclass_fields__")
    )


def _extract_external_model(t: Any) -> Optional[type]:
    """Find an external model in a type annotation, unwrapping Optional if needed."""
    if _is_external_model(t):
        return t
    origin = get_origin(t)
    is_union = origin is Union or (hasattr(types, "UnionType") and origin is types.UnionType)
    if is_union:
        for arg in get_args(t):
            if _is_external_model(arg):
                return arg
    return None


def _get_type_hints(source_model: type) -> Dict[str, Any]:
    """Safely get type hints, falling back gracefully on older Python versions."""
    try:
        return get_type_hints(source_model, include_extras=True)
    except TypeError:
        try:
            return get_type_hints(source_model)
        except Exception:
            return {}
    except Exception:
        return {}


def _extract_instance_data(instance: Any) -> Dict[str, Any]:
    """Extract a dictionary of fields from a model instance."""
    if hasattr(instance, "model_dump"):
        return instance.model_dump()
    if hasattr(instance, "__dataclass_fields__"):
        import dataclasses
        return dataclasses.asdict(instance)
    if hasattr(instance, "__struct_fields__"):
        import msgspec
        return {f.name: getattr(instance, f.name) for f in msgspec.structs.fields(instance)}
    return instance.__dict__


def _process_field(
    name: str,
    annotation: Any,
    kwargs: Dict[str, Any],
    overrides: Dict[str, Any],
    extra: Dict[str, Any],
    namespace: Dict[str, Any],
    annotations: Dict[str, Any],
    fastmodel_base: Type[Any],
) -> None:
    """Process a single field, resolving its annotation and assigning its Rule."""
    if name in overrides:
        namespace[name] = overrides[name]
        annotations[name] = annotation
        return

    annotations[name] = annotation
    ext_model = _extract_external_model(annotation)
    
    if ext_model:
        bridged = build_bridged_model(fastmodel_base, ext_model)
        if annotation is ext_model:
            annotations[name] = bridged
        else:
            annotations[name] = Optional[bridged]
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
        instance_data = _extract_instance_data(instance)

    namespace: Dict[str, Any] = {}
    annotations: Dict[str, Any] = {}
    overrides = field_overrides or {}
    extra = extra_rules or {}

    # 1. Pydantic (v2) Integration
    if hasattr(source_model, "model_fields"):
        for name, field in source_model.model_fields.items():
            kwargs: Dict[str, Any] = {}
            
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

            _process_field(name, field.annotation, kwargs, overrides, extra, namespace, annotations, fastmodel_base)

    # 2. Msgspec Integration
    elif hasattr(source_model, "__struct_fields__"):
        import msgspec
        hints = _get_type_hints(source_model)
            
        for field in msgspec.structs.fields(source_model):
            name = field.name
            t = hints.get(name, field.type)
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

            _process_field(name, t, kwargs, overrides, extra, namespace, annotations, fastmodel_base)

    # 3. Dataclasses Integration
    elif hasattr(source_model, "__dataclass_fields__"):
        import dataclasses
        hints = _get_type_hints(source_model)
            
        for field in dataclasses.fields(source_model):
            name = field.name
            t = hints.get(name, field.type)
            kwargs = {}
            
            if field.default is not dataclasses.MISSING: kwargs["default"] = field.default
            elif field.default_factory is not dataclasses.MISSING: kwargs["default_factory"] = field.default_factory

            _process_field(name, t, kwargs, overrides, extra, namespace, annotations, fastmodel_base)

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
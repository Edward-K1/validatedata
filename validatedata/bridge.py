# validatedata/bridge.py
import sys
import types
from typing import Any, Callable, Dict, Optional, Type, Union, get_args, get_origin, get_type_hints

from .rule import Rule, _MISSING

try:
    from typing import Literal
except ImportError:  # pragma: no cover
    Literal = None


def _literal_choices(t: Any) -> Optional[list]:
    """Return the list of allowed values if `t` is a Literal[...] annotation, else None."""
    if Literal is not None and get_origin(t) is Literal:
        return list(get_args(t))
    return None


def _extract_annotated_types_constraints(t: Any, name: str) -> Dict[str, Any]:
    """
    Scan an Annotated[...] type for annotated_types constraint markers
    (Gt, Lt, MultipleOf) and translate them into Rule kwargs.

    This is the only source of gt/lt/multiple_of for plain dataclasses,
    since the stdlib dataclasses module has no constraint metadata of its
    own — authors express these constraints via
    `Annotated[int, annotated_types.Gt(0)]` instead. It also serves as a
    fallback for Pydantic/msgspec fields that use annotated_types markers
    directly rather than Field(...)/Meta(...).

    `annotated_types` is an optional dependency: if the annotation carries
    no recognizable constraint markers, this function never needs it and
    returns {}. It's only imported (and required) once a marker-shaped
    object is actually found on the annotation.
    """
    metadata = getattr(t, "__metadata__", None)
    if not metadata:
        return {}

    kwargs: Dict[str, Any] = {}
    for arg in metadata:
        type_name = type(arg).__name__
        if type_name not in ("Gt", "Lt", "Ge", "Le", "MultipleOf"):
            continue

        try:
            import annotated_types as at
        except ImportError:
            raise ImportError(
                f"Field '{name}' uses an annotated_types constraint "
                f"({type_name}), but the 'annotated_types' package is not "
                f"installed, so it can't be verified as a real annotated_types "
                f"marker (vs. an unrelated same-named class). Install it with: "
                f"pip install annotated_types"
            )

        if isinstance(arg, at.Gt):
            kwargs["gt"] = arg.gt
        elif isinstance(arg, at.Lt):
            kwargs["lt"] = arg.lt
        elif isinstance(arg, at.Ge):
            kwargs["min"] = arg.ge
        elif isinstance(arg, at.Le):
            kwargs["max"] = arg.le
        elif isinstance(arg, at.MultipleOf):
            kwargs["multiple_of"] = arg.multiple_of

    return kwargs


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
        try:
            import msgspec
        except ImportError:
            raise ImportError(
                f"Bridging a msgspec Struct instance of '{type(instance).__name__}' "
                f"requires the 'msgspec' package, which is not installed. Install it "
                f"with: pip install msgspec"
            )
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
    _cache: Dict[type, Any],
    _in_progress: set,
) -> None:
    """Process a single field, resolving its annotation and assigning its Rule."""
    if name in overrides:
        namespace[name] = overrides[name]
        annotations[name] = annotation
        return

    annotations[name] = annotation
    ext_model = _extract_external_model(annotation)

    # Pick up annotated_types markers (Gt/Lt/Ge/Le/MultipleOf) directly from
    # the annotation. This is the only path for plain dataclasses, and a
    # fallback for Pydantic/msgspec fields that didn't already set these via
    # Field(...)/Meta(...). Never overrides a constraint the model-specific
    # branch already resolved, and never overrides explicit overrides/extra.
    if name not in overrides and name not in extra:
        at_kwargs = _extract_annotated_types_constraints(annotation, name)
        for k, v in at_kwargs.items():
            kwargs.setdefault(k, v)

    # Literal[...] annotations map to a `choices` constraint. This is checked
    # before the external-model branch since Literal is never an external model.
    literal_vals = _literal_choices(annotation)
    if literal_vals is not None and name not in overrides and name not in extra:
        kwargs.setdefault("choices", literal_vals)

    if ext_model:
        if ext_model in _in_progress:
            raise TypeError(
                f"Cannot bridge '{ext_model.__name__}': it references itself "
                f"(directly or through another model), and FastModel.bridge does "
                f"not support self-referential / circular model graphs."
            )
        if ext_model in _cache:
            bridged = _cache[ext_model]
        else:
            bridged = build_bridged_model(
                fastmodel_base, ext_model, _cache=_cache, _in_progress=_in_progress
            )
            _cache[ext_model] = bridged
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
    _cache: Optional[Dict[type, Any]] = None,
    _in_progress: Optional[set] = None,
) -> Any:
    """
    Core implementation for bridging external models to FastModel.
    If an instance is passed, returns a populated FastModel instance.

    _cache and _in_progress are internal bookkeeping for a single top-level
    bridge() call (not exposed publicly): _cache memoizes already-bridged
    nested model classes so a type referenced from multiple fields/models is
    only bridged once (both for correctness — repeated bridging previously
    produced *distinct* FastModel subclasses for the same source type, so
    isinstance checks across them would fail — and for avoiding wasted work).
    _in_progress detects self-referential / circular model graphs, which
    memoization alone can't handle, and raises a clear error instead of
    recursing until the stack overflows.
    """
    is_instance = not isinstance(source_model, type)
    instance_data = None

    if is_instance:
        instance = source_model
        source_model = type(instance)
        instance_data = _extract_instance_data(instance)

    if _cache is None:
        _cache = {}
    if _in_progress is None:
        _in_progress = set()
    _in_progress = _in_progress | {source_model}

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
                gt = getattr(meta, "gt", None)
                lt = getattr(meta, "lt", None)
                if gt is not None and name not in overrides and name not in extra:
                    kwargs["gt"] = gt
                if lt is not None and name not in overrides and name not in extra:
                    kwargs["lt"] = lt
                if hasattr(meta, "pattern") and meta.pattern is not None: kwargs["pattern"] = meta.pattern
                if getattr(meta, "multiple_of", None) is not None and name not in overrides and name not in extra:
                    kwargs["multiple_of"] = meta.multiple_of
                
            if not field.is_required():
                if field.default_factory is not None:
                    kwargs["default_factory"] = field.default_factory
                else:
                    kwargs["default"] = field.default

            _process_field(name, field.annotation, kwargs, overrides, extra, namespace, annotations, fastmodel_base, _cache, _in_progress)

    # 2. Msgspec Integration
    elif hasattr(source_model, "__struct_fields__"):
        try:
            import msgspec
        except ImportError:
            raise ImportError(
                f"Bridging msgspec Struct '{source_model.__name__}' requires the "
                f"'msgspec' package, which is not installed. Install it with: "
                f"pip install msgspec"
            )
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
                        gt = getattr(arg, "gt", None)
                        lt = getattr(arg, "lt", None)
                        if gt is not None and name not in overrides and name not in extra:
                            kwargs["gt"] = gt
                        if lt is not None and name not in overrides and name not in extra:
                            kwargs["lt"] = lt
                        if arg.pattern is not None: kwargs["pattern"] = arg.pattern
                        if getattr(arg, "multiple_of", None) is not None and name not in overrides and name not in extra:
                            kwargs["multiple_of"] = arg.multiple_of
                        if getattr(arg, "tz", None) is not None and name not in overrides and name not in extra:
                            raise ValueError(
                                f"msgspec field '{name}' uses tz={arg.tz!r} (timezone-awareness "
                                f"constraint), which has no equivalent in the validation engine. "
                                f"Bridging would silently drop this constraint, so it's rejected "
                                f"instead — pass an explicit override via extra_rules for "
                                f"'{name}' if you want to bridge this field anyway."
                            )
            
            if field.default is not msgspec.NODEFAULT: kwargs["default"] = field.default
            if field.default_factory is not msgspec.NODEFAULT: kwargs["default_factory"] = field.default_factory

            _process_field(name, t, kwargs, overrides, extra, namespace, annotations, fastmodel_base, _cache, _in_progress)

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

            _process_field(name, t, kwargs, overrides, extra, namespace, annotations, fastmodel_base, _cache, _in_progress)

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
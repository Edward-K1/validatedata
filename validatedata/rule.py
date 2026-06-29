# validatedata/rule.py
"""
Rule — field descriptor for FastModel.

A Rule carries three concerns in one object:

  1. The validation spec (pipe string, dict, or kwargs).
  2. The default value / factory for the field.
  3. A lazily-compiled pair (bool callable, _CompiledRule struct) that is
     cached after the first compile() call and reused on every instance.

Pipe string syntax examples
----------------------------------------------------------------------------------
  Rule("email")                       # type constraint only
  Rule("str|min:3|max:32")            # bounds
  Rule("str|min:3|max:32|nullable")   # optional field
  Rule("str|re:^[a-z0-9_]+$")        # regex

Kwargs syntax (convenience — converted to a pipe string at compile time)
------------------------------------------------------------------------
  Rule(min=3, max=32)                 # infers "str" type
  Rule(type="int", min=0)
  Rule(type="email")

Mutable-default ergonomics
--------------------------
  Rule([], init_new=True)             # fresh list per instance
  Rule({}, init_new=True)             # fresh dict per instance
  Rule(default_factory=list)          # explicit factory callable

Cross-field / model-level validation
-------------------------------------
  Model-level logic lives in ``model_check``, not on the Rule.  Rule is
  intentionally field-scoped only.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

# Lazy imports so startup cost is paid only on first validation
_compiled_validator = None
_fast_get_compiled_rule = None


def _get_compiled_modules():
    global _compiled_validator, _fast_get_compiled_rule
    if _compiled_validator is None:
        from . import compiled as _c
        from . import fast as _f
        _compiled_validator = _c.validator
        _fast_get_compiled_rule = _f._get_compiled_rule
    return _compiled_validator, _fast_get_compiled_rule


_MISSING = object()   # sentinel — "no value provided"
_VALID_TRANSFORMS = frozenset({"strip", "lstrip", "rstrip", "lower", "upper", "title"})

class Rule:
    """
    Field descriptor for FastModel.

    Positional first argument is the rule spec (pipe string or dict).
    Exception: a bare mutable container ([], {}, set()) with no other kwargs
    is treated as the default value (enables ``Rule([], init_new=True)``).

    Parameters
    ----------
    rule:
        Pipe string (``"str|min:3"``), or ``None`` for unconstrained.
    default:
        Static default value. Copied via ``copy.deepcopy`` on each instantiation.
    default_factory:
        Zero-argument callable that produces a fresh default each time.
        Takes precedence over *default* when both are provided.
    init_new:
        When ``True`` and *default* is a mutable container, a fresh empty
        instance of the same type is created for each model instance.
        Equivalent to ``default_factory=list`` / ``default_factory=dict``.
    nullable:
        When ``True``, the rule string ``|nullable`` is appended automatically
        so ``None`` is always accepted without separate handling.
    **kwargs:
        Shorthand constraint kwargs (``min``, ``max``, ``pattern``, ``type``,
        etc.) converted to a pipe string at compile time.
    """

    __slots__ = (
        "rule", "default", "_default_factory", "init_new", "nullable",
        "kwargs", "_compiled", "_compiled_struct","transforms",
    )

    def __init__(
        self,
        rule: Any = None,
        *,
        default: Any = _MISSING,
        default_factory: Optional[Callable] = None,
        init_new: bool = False,
        nullable: bool = False,
        transforms: Any = None,
        **kwargs,
    ):
        # Bare mutable container as first positional → treat as default
        if (
            default is _MISSING
            and default_factory is None
            and not kwargs
            and isinstance(rule, (list, dict, set, tuple))
        ):
            self.rule = None
            self.default = rule
        else:
            self.rule = rule
            self.default = default

        self.nullable = nullable
        self.init_new = init_new
        self.kwargs = dict(kwargs)
        self._compiled = None
        self._compiled_struct = None
        self.transforms = transforms


        # Resolve default factory
        if default_factory is not None:
            # Explicit factory always wins
            self._default_factory: Optional[Callable] = default_factory
        elif self.default is not _MISSING and init_new:
            if callable(self.default):
                self._default_factory = self.default
            else:
                _d = self.default
                self._default_factory = lambda d=_d: type(d)()
        else:
            self._default_factory = None

    # ------------------------------------------------------------------
    # Default resolution
    # ------------------------------------------------------------------

    def get_default(self) -> Any:
        """Return a fresh default value, or _MISSING if none was configured."""
        if self._default_factory is not None:
            return self._default_factory()
        if self.default is _MISSING:
            return _MISSING
        try:
            return copy.deepcopy(self.default)
        except Exception:
            return self.default

    @property
    def has_default(self) -> bool:
        return self.default is not _MISSING or self._default_factory is not None

    # ------------------------------------------------------------------
    # Compilation
    # ------------------------------------------------------------------

    def _resolve_rule_string(self) -> Optional[str]:
        """Convert whatever was passed to a canonical pipe string, or None."""
        base = self.rule

        if isinstance(base, dict):
            raise ValueError(
                "Dict rules must use Rule(fields={...}), not Rule({...}). "
                "Bare dicts are treated as default values."
            )

        # Work on a copy of kwargs so this method is pure / idempotent.
        kwargs = dict(self.kwargs)

        # -------------------------------------------------------------
        # 1. RESOLVE TRANSFORMS (Collect them, but don't place them yet)
        # -------------------------------------------------------------
        tf_parts = []
        if self.transforms:
            if isinstance(self.transforms, str):
                tf_parts = [t.strip() for t in self.transforms.split("|") if t.strip()]
            elif isinstance(self.transforms, (list, tuple)):
                tf_parts = list(self.transforms)

            for tf in tf_parts:
                if tf not in _VALID_TRANSFORMS:
                    raise ValueError(
                        f"Unknown transform '{tf}'. "
                        f"Supported: {sorted(_VALID_TRANSFORMS)}"
                    )

        # -------------------------------------------------------------
        # 2. RESOLVE TYPE AND BASE PIPE STRING
        # -------------------------------------------------------------
        parts = []
        if isinstance(base, str):
            tokens = base.split("|")
            parts.append(tokens[0])  # Type token MUST be first

            # Append other tokens, deduplicating against transforms kwarg
            for tok in tokens[1:]:
                if tok in _VALID_TRANSFORMS and tok in tf_parts:
                    # Transform already in the pipe string — keep it at its
                    # current pipe-string position and remove from tf_parts so
                    # it isn't injected a second time in step 4.
                    tf_parts.remove(tok)
                parts.append(tok)

        elif kwargs:
            # Pop 'type' so it isn't repeated in the kwargs loop below
            t = kwargs.pop("type", None)
            parts.append(str(t) if t else "str")
        else:
            return None   # no constraint — trivial validator

        # -------------------------------------------------------------
        # 3. RESOLVE KWARGS (Map 'choices' -> 'in:', 'pattern' -> 're:')
        # -------------------------------------------------------------
        if kwargs:
            # Handle 'choices' -> 'in:'
            choices = kwargs.pop("choices", None)
            if choices is not None:
                if isinstance(choices, (list, tuple, set)):
                    parts.append(f"in:{','.join(str(c) for c in choices)}")
                else:
                    parts.append(f"in:{choices}")

            # Handle 'pattern' -> 're:'
            pattern = kwargs.pop("pattern", None)

            # Handle remaining standard kwargs
            for k, v in kwargs.items():
                if v is True or v is None:
                    parts.append(k)
                else:
                    parts.append(f"{k}:{v}")

            if pattern:
                parts.append(f"re:{pattern}")

        # -------------------------------------------------------------
        # 4. ASSEMBLE FINAL STRING
        # -------------------------------------------------------------
        if not parts:
            return None

        # Reconstruct with transforms correctly ordered:
        # type | <pipe-string transforms> | <new transforms from kwarg> | <validators>
        type_token = parts[0]
        rest = parts[1:]  # everything after the type from the pipe string

        if isinstance(base, str) and tf_parts:
            # Separate the rest into pipe-string transforms and validators.
            # Pipe transforms must come before the new kwarg transforms, which
            # must come before any validators.
            pipe_transforms = [t for t in rest if t in _VALID_TRANSFORMS]
            validators = [t for t in rest if t not in _VALID_TRANSFORMS]
            final_parts = [type_token] + pipe_transforms + tf_parts + validators
        else:
            # kwargs-only path: type | transforms | validators (original order)
            final_parts = [type_token] + tf_parts + rest

        rule_str = "|".join(final_parts)

        if self.nullable and "nullable" not in rule_str.split("|"):
            rule_str = rule_str + "|nullable"

        return rule_str

    def compile(self):
        """
        Lazily compile to (bool_callable, _CompiledRule | None).

        The bool callable is the fast path used by compiled.validator.
        The struct carries message metadata used by fast._validate_value_with_messages.
        Both are cached on the Rule instance after the first call.
        """
        if self._compiled is not None:
            return self._compiled, self._compiled_struct

        compiled_validator, fast_get_compiled_rule = _get_compiled_modules()
        rule_str = self._resolve_rule_string()

        if rule_str is None:
            # Unconstrained field — accept anything
            self._compiled = lambda v: True
            self._compiled_struct = None
            return self._compiled, self._compiled_struct

        # Primary path: pipe string → LRU-cached _CompiledRule
        try:
            cr = fast_get_compiled_rule(rule_str)
            self._compiled = cr.fast_validator
            self._compiled_struct = cr
            return self._compiled, self._compiled_struct
        except Exception:
            pass

        # Fallback: compiled.validator only (no message struct)
        try:
            fn = compiled_validator(rule_str)
            self._compiled = fn
            self._compiled_struct = None
            return self._compiled, self._compiled_struct
        except Exception:
            self._compiled = lambda v: True
            self._compiled_struct = None
            return self._compiled, self._compiled_struct

    def validate(self, value: Any) -> bool:
        """Validate a single value. Returns True/False."""
        fn, _ = self.compile()
        try:
            return bool(fn(value))
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Repr
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        parts = []
        if self.rule is not None:
            parts.append(repr(self.rule))
        if self.default is not _MISSING:
            parts.append(f"default={self.default!r}")
        if self._default_factory is not None:
            parts.append(f"default_factory={self._default_factory!r}")
        if self.nullable:
            parts.append("nullable=True")
        if self.init_new:
            parts.append("init_new=True")
        if self.kwargs:
            parts.extend(f"{k}={v!r}" for k, v in self.kwargs.items())
        return f"Rule({', '.join(parts)})"
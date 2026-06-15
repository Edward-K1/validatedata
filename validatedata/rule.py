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


class Rule:
    """
    Field descriptor for FastModel.

    Positional first argument is the rule spec (pipe string or dict).
    Exception: a bare mutable container ([], {}, set()) with no other kwargs
    is treated as the default value (enables ``Rule([], init_new=True)``).

    Parameters
    ----------
    rule:
        Pipe string (``"str|min:3"``), dict schema, or ``None`` for unconstrained.
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
        "kwargs", "_compiled", "_compiled_struct",
    )

    def __init__(
        self,
        rule: Any = None,
        *,
        default: Any = _MISSING,
        default_factory: Optional[Callable] = None,
        init_new: bool = False,
        nullable: bool = False,
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
        """
        Convert whatever was passed to a canonical pipe string, or None
        for the fully-unconstrained (accept-anything) case.
        """
        base = self.rule

        # Already a pipe string
        if isinstance(base, str):
            rule_str = base
        # Dict schema — serialise to JSON so compiled.validator can consume it
        elif isinstance(base, dict):
            import json
            rule_str = json.dumps(base, sort_keys=True)
        # kwargs-only shorthand
        elif self.kwargs:
            parts = []
            t = self.kwargs.pop("type", None) if "type" in self.kwargs else None
            # pattern kwarg → re: token
            pattern = self.kwargs.pop("pattern", None)
            parts.append(str(t) if t else "str")
            for k, v in self.kwargs.items():
                if v is True or v is None:
                    parts.append(k)
                else:
                    parts.append(f"{k}:{v}")
            if pattern:
                parts.append(f"re:{pattern}")
            rule_str = "|".join(parts)
        else:
            return None   # no constraint — trivial validator

        # Append |nullable if requested and not already present
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
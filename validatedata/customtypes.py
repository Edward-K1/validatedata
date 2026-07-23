# validatedata/types.py

from typing import Any, Callable, Dict, Optional

_BY_OBJ: Dict[object, Callable[[Any], bool]] = {}
_BY_NAME: Dict[str, Callable[[Any], bool]] = {}

def _fq_name(obj: object) -> Optional[str]:
    try:
        return f"{obj.__module__}.{obj.__qualname__}"
    except Exception:
        return None

def register_type(key: object, checker: Callable[[Any], bool],
                  *, register_names: bool = True, override: bool = False) -> None:
    if isinstance(key, str):
        if not override and key in _BY_NAME:
            raise KeyError(f"Name '{key}' already registered")
        _BY_NAME[key] = checker
        return

    # object key
    if key in _BY_OBJ and not override:
        raise KeyError(f"Object {key} already registered")
    _BY_OBJ[key] = checker

    if register_names:
        short = getattr(key, "__name__", None)
        fq = _fq_name(key)
        if short and (override or short not in _BY_NAME):
            _BY_NAME[short] = checker
        if fq and (override or fq not in _BY_NAME):
            _BY_NAME[fq] = checker

def unregister_type(key: object) -> None:
    if isinstance(key, str):
        _BY_NAME.pop(key, None)
        return
    _BY_OBJ.pop(key, None)
    short = getattr(key, "__name__", None)
    fq = _fq_name(key)
    if short:
        _BY_NAME.pop(short, None)
    if fq:
        _BY_NAME.pop(fq, None)

def get_registered_checker(annot: Any) -> Optional[Callable[[Any], bool]]:
    # 1. exact object match
    if annot in _BY_OBJ:
        return _BY_OBJ[annot]
    # 2. object name / fq name
    name = getattr(annot, "__name__", None)
    if name and name in _BY_NAME:
        return _BY_NAME[name]
    fq = _fq_name(annot)
    if fq and fq in _BY_NAME:
        return _BY_NAME[fq]
    # 3. forward-ref string
    if isinstance(annot, str) and annot in _BY_NAME:
        return _BY_NAME[annot]
    return None

def export_registered_checkers() -> Dict[Any, Callable[[Any], bool]]:
    """
    Return a shallow copy of the registered checkers merged into a single dict.

    Keys may be objects (class objects) or names (str). This provides a stable
    public API so callers can merge registry checkers into their own type_checkers.
    """
    out: Dict[Any, Callable[[Any], bool]] = {}
    # object-keyed checkers
    out.update(_BY_OBJ)
    # name-keyed checkers
    out.update(_BY_NAME)
    return out

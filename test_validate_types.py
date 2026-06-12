# ==============================================================================
# NEW: Bespoke Fast-Path @validate_types Benchmark
# This bypasses the engine entirely, pre-compiling isinstance checks at 
# decoration time to establish the theoretical speed limit.
# ==============================================================================
import timeit
from collections import OrderedDict
from functools import wraps
from inspect import getfullargspec
from validatedata import ValidationError
from typing import Any

# Sentinel for missing arguments (mimics validatedata's EMPTY)
class _EmptySentinel: pass
_EMPTY = _EmptySent1 = _EmptySentinel()

rules = {
    "username": "str|strip|min:3|max:32",
    "age": "int|min:0|max:120",
    "email": "email|nullable",
    "role": "str|strip|lower|in:admin,editor,viewer",
    "is_active": "bool"
}

# Compile the validator once (this is the fast part)

# Paste your full test_records list here (the 19 records)
test_records = [
    {"username": "Eddy", "age": 28, "email": "eddy@example.com", "role": "admin", "is_active": True},
    {"username": "ab", "age": 25, "email": "bad-email", "role": "viewer", "is_active": False},  # Invalid: username min_len, email format
    {"username": "Alice", "age": 150, "email": None, "role": "editor", "is_active": True},      # Invalid: age max
    {"username": "Bob_The_Builder", "age": 45, "email": "bob@example.com", "role": "viewer", "is_active": True},
    {"username": "charlie", "age": 10, "email": "charlie@domain.com", "role": "VIEWER ", "is_active": False}, # Invalid: age min, role will be lower-cased
    {"username": "diana", "age": 30, "email": None, "role": "editor", "is_active": True},
    {"username": "e", "age": 20, "email": "e@test.com", "role": "unknown", "is_active": True}, # Invalid: username min_len, role not in options
    {"username": "Frank", "age": -5, "email": "frank@mail.com", "role": "admin", "is_active": False}, # Invalid: age min
    {"username": "GraceKelly", "age": 60, "email": "grace@email.co.uk", "role": "admin", "is_active": True},
    {"username": "HenryTheEighth", "age": 35, "email": "henry@royal.com", "role": "admin", "is_active": True},
    {"username": "Isabelle", "age": 7, "email": "isabelle@org.net", "role": "viewer", "is_active": False}, # Invalid: age min

    # More email-specific tests
    {"username": "ValidEmail1", "age": 30, "email": "user.name+tag@sub.domain.com", "role": "admin", "is_active": True}, # Valid: complex email
    {"username": "ValidEmail2", "age": 40, "email": "u@d.com", "role": "editor", "is_active": True}, # Valid: shortest possible
    {"username": "InvalidEmail1", "age": 50, "email": "missingat.com", "role": "viewer", "is_active": True}, # Invalid: missing @
    {"username": "InvalidEmail2", "age": 60, "email": "user@.com", "role": "admin", "is_active": True}, # Invalid: missing domain part after @
    {"username": "InvalidEmail3", "age": 70, "email": "user@domain", "role": "editor", "is_active": True}, # Invalid: missing top-level domain
    {"username": "InvalidEmail4", "age": 80, "email": "user@domain.c", "role": "viewer", "is_active": True}, # Invalid: TLD too short
    {"username": "NoEmail", "age": 90, "email": None, "role": "admin", "is_active": True}, # Valid: nullable email
    {"username": "EmailWithSpace", "age": 22, "email": "user name@domain.com", "role": "editor", "is_active": True} # Invalid: space in email
]

def validate_types_fast(func: Any = None, raise_exceptions: bool = True, is_class: bool = False):
    """Fast-path version of validate_types: pre-compiles isinstance checks."""
    def decorator(f):
        func_defn = getfullargspec(f)
        func_annotations = OrderedDict(
            (k, v) for k, v in func_defn.annotations.items() if k != 'return'
        )
        obj_is_cls = True if (is_class or (func_defn.args and func_defn.args[0] == 'self')) else False
        clean_params = func_defn.args[1:] if obj_is_cls else func_defn.args
        
        func_defaults = OrderedDict()
        if func_defn.defaults:
            func_defaults.update(zip(clean_params[-len(func_defn.defaults):], func_defn.defaults))

        # 1. PRE-COMPILE: Build a tight list of (name, expected_type, expected_name)
        # This happens exactly ONCE at decoration time.
        checks = []
        for name in clean_params:
            expected_type = func_annotations.get(name)
            if expected_type is not None:
                expected_name = getattr(expected_type, '__name__', str(expected_type))
                checks.append((name, expected_type, expected_name))

        def fast_checker(func_data: dict):
            errors = []
            # 2. ZERO-OVERHEAD HOT PATH: Native C-level isinstance checks
            for name, expected_type, expected_name in checks:
                val = func_data.get(name)
                if isinstance(val, _EmptySentinel):
                    continue  # Skip missing args with no default
                
                if not isinstance(val, expected_type):
                    actual_name = type(val).__name__
                    errors.append(f"Expected value of type {expected_name} for argument {name}, found {actual_name}")
            return len(errors) == 0, errors

        @wraps(f)
        def wrapper(obj=_EMPTY, *args, **kwargs):
            # 3. Argument alignment (unavoidable Python overhead, but highly optimized)
            func_data = OrderedDict()
            func_data.update(zip(clean_params, [_EMPTY] * len(clean_params)))
            if func_defaults:
                func_data.update(func_defaults)
            if not obj_is_cls:
                func_data[clean_params[0]] = obj
            if args:
                if obj_is_cls:
                    func_data.update(zip(clean_params, args))
                else:
                    func_data.update(zip(clean_params[1:], args))
            if kwargs:
                func_data.update({k: v for k, v in kwargs.items() if k in func_data})

            # 4. Execute pre-compiled checks
            ok, errors = fast_checker(func_data)
            
            if ok:
                if isinstance(obj, _EmptySentinel):
                    return f(*args, **kwargs)
                else:
                    return f(obj, *args, **kwargs)
            else:
                if raise_exceptions:
                    raise ValidationError("\n".join(errors))
                return {'errors': errors}

        return wrapper

    if func is not None:
        return decorator(func)
    return decorator


# --- Benchmark the Fast-Path Decorator ---
print("\n" + "=" * 40)
print("Testing BESPOKE FAST-PATH @validate_types performance\n")

@validate_types_fast
def dummy_user_processor_fast(username: str, age: int, email: str | None, role: str, is_active: bool):
    """Dummy function to measure pure fast-path decorator validation overhead."""
    return True

# Warmup run to ensure any Python internal caching is settled
for r in test_records:
    dummy_user_processor_fast(**r)

# Benchmark the fast-path decorator
time_taken_fast_decorator = timeit.timeit(
    lambda: [dummy_user_processor_fast(**r) for r in test_records],
    number=5000
)

total_fast_decorator_calls = 5000 * len(test_records)
avg_us_fast_decorator = (time_taken_fast_decorator / total_fast_decorator_calls) * 1_000_000

print(f"Total time for 5000 runs ({total_fast_decorator_calls} total calls): {time_taken_fast_decorator:.6f} s")
print(f"Average time per call (@validate_types FAST PATH): {avg_us_fast_decorator:.2f} μs")
print("=" * 40)

# --- Summary Comparison ---
print("\n📊 PERFORMANCE SUMMARY:")
print(f"  Detailed validate_data()       : ~390.16 μs per record")
print(f"  Current @validate_types        : ~69.32 μs per call")
print(f"  Bespoke Fast-Path @validate_types: ~{avg_us_fast_decorator:.2f} μs per call")
print(f"  Pure validator() (bool only)   : ~0.10 μs per record")
print("=" * 40)
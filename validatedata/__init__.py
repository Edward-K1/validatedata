from .validatedata import validate, validate_data, validate_types, ValidationResult, _check_rule_dict, VALID_RULE_KEYS
from .validator import ValidationError

__version__ = '0.4.0'

__all__ = [
    'validate',
    'validate_data',
    'validate_types',
    'ValidationResult',
    'ValidationError',
    'VALID_RULE_KEYS',
    'check_rule',
]

# Public alias — underscore-free name for user-facing use
check_rule = _check_rule_dict

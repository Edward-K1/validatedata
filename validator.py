class Validator:
  def __init__(self, basic_types, extended_types, raise_exceptions):
      self.basic_types = basic_types
      self.extended_types = extended_types
      self.raise_exceptions = raise_exceptions

  def validate_string(self, data, rule, message):
    pass

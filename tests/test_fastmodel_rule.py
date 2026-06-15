# tests/test_fastmodel_rule.py
import pytest
from validatedata.fastmodel import FastModel
from validatedata.rule import Rule
from validatedata.engine import ValidationError

class User(FastModel):
    id: int
    tags: list[str] = Rule([], init_new=True)
    email: str = Rule("email")

def test_init_new_creates_fresh_lists():
    u1 = User(id=1, email="a@b.com")
    u2 = User(id=2, email="c@d.com")
    u1.tags.append("x")
    assert u2.tags == []

def test_validation_fails_on_bad_email():
    with pytest.raises(ValidationError):
        User(id=1, email="not-an-email")

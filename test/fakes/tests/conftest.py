"""pytest fixtures for the fakes tests; helpers live in fakes_support (unique module name)."""
import pytest
from fakes_support import request


@pytest.fixture()
def req():
    return request

import pytest
from .provider import Provider, configure


@pytest.fixture
def provider(settings):
    with Provider() as provider:
        configure(settings, provider)
        yield provider


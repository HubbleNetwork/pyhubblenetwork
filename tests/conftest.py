"""Shared pytest fixtures for integration tests."""

import pytest

from hubblenetwork import termcaps


@pytest.fixture(autouse=True)
def _reset_terminal_overrides():
    """Keep a --ascii/--no-color invocation from leaking into the next test.

    termcaps holds the only mutable module state in the package; without this,
    test ordering becomes load-bearing.
    """
    termcaps.reset()
    yield
    termcaps.reset()

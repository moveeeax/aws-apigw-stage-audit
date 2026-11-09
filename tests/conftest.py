import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


def load(name):
    with open(FIXTURES / name, encoding="utf-8") as handle:
        return json.load(handle)


@pytest.fixture
def fixtures_dir():
    return FIXTURES


@pytest.fixture
def clean():
    return load("clean.json")


@pytest.fixture
def messy():
    return load("messy.json")


@pytest.fixture
def warn_only():
    return load("warn_only.json")

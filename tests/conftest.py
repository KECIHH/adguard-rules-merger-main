from __future__ import annotations

import shutil
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest


@pytest.fixture
def workspace_tmp_path(request: pytest.FixtureRequest) -> Iterator[Path]:
    root = Path(__file__).resolve().parent / ".tmp"
    path = root / uuid.uuid4().hex
    path.mkdir(parents=True, exist_ok=False)
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)

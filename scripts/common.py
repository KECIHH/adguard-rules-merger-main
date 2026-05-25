#!/usr/bin/env python3
"""Shared helpers for configuration, paths, and logging."""

from __future__ import annotations

import copy
import logging
import os
import sys
from pathlib import Path
from typing import Any

import yaml

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
CONFIG_PATH = REPO_ROOT / "config.yml"
LOGS_DIR = REPO_ROOT / "logs"

DEFAULT_CONFIG: dict[str, Any] = {
    "download": {
        "timeout": 30,
        "connect_timeout": 10,
        "read_timeout": 30,
        "retries": 3,
        "min_success_rate": 0.8,
    },
    "workers": {
        "threads": min(16, (os.cpu_count() or 2) * 2),
    },
    "optimization": {
        "enable": True,
        "level": 2,
        "target_rules": 150000,
        "min_rules": 100000,
        "max_rules": 200000,
    },
}


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def load_config() -> dict[str, Any]:
    config = copy.deepcopy(DEFAULT_CONFIG)
    if not CONFIG_PATH.exists():
        return config

    with open(CONFIG_PATH, "r", encoding="utf-8") as file:
        loaded = yaml.safe_load(file) or {}

    if not isinstance(loaded, dict):
        raise ValueError("config.yml must contain a YAML mapping at the top level")

    return _deep_merge(config, loaded)


def repo_path(*parts: str) -> Path:
    return REPO_ROOT.joinpath(*parts)


def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def setup_logging(log_name: str) -> logging.Logger:
    ensure_dir(LOGS_DIR)

    logger = logging.getLogger(log_name)
    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)
    logger.propagate = False

    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)

    file_handler = logging.FileHandler(LOGS_DIR / f"{log_name}.log", encoding="utf-8")
    file_handler.setFormatter(formatter)

    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

    return logger

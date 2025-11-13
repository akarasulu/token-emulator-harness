"""Configuration helpers for the emulator harness."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import yaml

DEFAULT_CONFIG_PATH = Path("config/emulator_config.yaml")


def load_config(path: Path | None = None) -> Dict[str, Any]:
    """Load YAML configuration for the harness."""
    config_path = path or DEFAULT_CONFIG_PATH
    data: Dict[str, Any] = {}
    if config_path.exists():
        with config_path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
    return data

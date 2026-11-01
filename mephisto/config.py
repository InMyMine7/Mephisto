"""Configuration loading and path resolution.

All paths in ``config.json`` may be relative; they are resolved against the
project root (the directory that contains ``config.json``) so the tool behaves
the same no matter which working directory it is launched from.
"""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
CONFIG_FILE = ROOT_DIR / "config.json"

VERSION = "0.2"

# Keys that must always be absolute after load.
_PATH_KEYS = ("FILES_DIR", "RESULT_DIR")

DEFAULT_CONFIG = {
    "TIMEOUT": 10,
    "UPLOAD_TIMEOUT": 15,
    "FILES_DIR": "assets/payloads",
    "REQUIRED_FILES": ["inmymine-shell.jpg", "mem.zip"],
    "RESULT_DIR": "Result",
    "SHELLS_FILE": "Shells.txt",
    "PASSWORDS_FILE": "password_change.txt",
    "ADMINS_FILE": "wp-admin.txt",
    "REGISTER_FILE": "wp-register.txt",
    "PROXIES": [],
    "DISABLED_EXPLOITS": [],
    "UPDATE_REPO": "InMyMine7/Mephisto",
    "UPDATE_CHECK": True,
    "SKIPPED_VERSION": "",
    "SUPPORT_URL": ["https://buymeacoffee.com/inmymine72"],
    "EMAIL": "default@example.com",
}


def _resolve_path(value: str) -> str:
    path = Path(value)
    if not path.is_absolute():
        path = ROOT_DIR / path
    return str(path)


class Config(dict):
    """Dict of settings with absolute paths already resolved."""

    @property
    def files_dir(self) -> str:
        return self["FILES_DIR"]

    @property
    def result_dir(self) -> str:
        return self["RESULT_DIR"]

    def payload_path(self, filename: str) -> str:
        return os.path.join(self.files_dir, filename)

    def result_path(self, filename: str) -> str:
        return os.path.join(self.result_dir, filename)


def load() -> Config:
    """Load ``config.json``, creating it from defaults when absent."""
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as handle:
                raw = json.load(handle)
        except (OSError, ValueError):
            raw = None
    else:
        raw = None

    if raw is None:
        config = Config(copy.deepcopy(DEFAULT_CONFIG))
        save(config)
    else:
        merged = copy.deepcopy(DEFAULT_CONFIG)
        merged.update(raw)
        config = Config(merged)

    for key in _PATH_KEYS:
        config[key] = _resolve_path(config[key])
    return config


def save(config: Config) -> None:
    """Persist configuration, storing path keys in their portable relative form."""
    data = {key: value for key, value in config.items() if not str(key).startswith("_")}
    for key in _PATH_KEYS:
        path = Path(data[key])
        if path.is_absolute():
            try:
                data[key] = path.relative_to(ROOT_DIR).as_posix()
            except ValueError:
                data[key] = path.as_posix()
    with open(CONFIG_FILE, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=4)

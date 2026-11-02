"""Per-installation runtime state kept outside version control.

``config.json`` holds settings a user may want to share or commit; this file
holds machine-local state such as "which release did I ask to stop being
reminded about". It lives next to ``config.json`` and is gitignored.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

STATE_FILE_NAME = ".mephisto-state.json"


def state_path() -> Path:
    """Resolved lazily so tests can relocate the project root."""
    from . import config as config_module

    return Path(config_module.ROOT_DIR) / STATE_FILE_NAME


def load() -> dict:
    try:
        raw = state_path().read_text(encoding="utf-8")
    except (OSError, ValueError):
        return {}
    try:
        data = json.loads(raw)
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def save(data: dict) -> None:
    """Write atomically so a crash cannot leave a half-written state file."""
    path = state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=str(path.parent), prefix=path.name, delete=False
    )
    try:
        with handle:
            json.dump(data, handle, indent=4)
            handle.write("\n")
        os.replace(handle.name, path)
    except OSError:
        try:
            os.unlink(handle.name)
        except OSError:
            pass
        raise


def get(key: str, default=None):
    return load().get(key, default)


def set(key: str, value) -> None:
    data = load()
    data[key] = value
    save(data)


def clear(key: str) -> None:
    data = load()
    if key in data:
        data.pop(key)
        save(data)

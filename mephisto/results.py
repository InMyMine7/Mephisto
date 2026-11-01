"""Result file bookkeeping.

Exploit modules append their findings straight to the files named in
``config.json``. This module only measures those files so the runner can report
which artifact each exploit produced, and provides safe directory setup.
"""

from __future__ import annotations

import os


class ResultStore:
    def __init__(self, config):
        self._config = config
        self._tracked = {
            "shell": config["SHELLS_FILE"],
            "password": config["PASSWORDS_FILE"],
            "admin": config["ADMINS_FILE"],
            "register": config["REGISTER_FILE"],
        }

    def ensure_dir(self):
        os.makedirs(self._config["RESULT_DIR"], exist_ok=True)

    def _path(self, filename):
        return os.path.join(self._config["RESULT_DIR"], filename)

    def snapshot(self):
        """Return {kind: line_count} for every tracked result file."""
        counts = {}
        for kind, filename in self._tracked.items():
            path = self._path(filename)
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as handle:
                    counts[kind] = sum(1 for _ in handle)
            except FileNotFoundError:
                counts[kind] = 0
        return counts

    def diff(self, before, after):
        """Return how many rows each artifact gained (delta, not the total)."""
        return {
            kind: after[kind] - before.get(kind, 0)
            for kind in after
            if after.get(kind, 0) > before.get(kind, 0)
        }

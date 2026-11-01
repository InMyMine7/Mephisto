#!/usr/bin/env python3
"""Mephisto entry point.

The implementation lives in the ``mephisto`` package; this file only forwards
to the terminal UI so ``python main.py`` keeps working.
"""

from mephisto.cli import run

if __name__ == "__main__":
    raise SystemExit(run())


"""Exploit discovery and registration.

Modules live in the top-level ``exploits`` package. Any ``cve_*.py`` file that
exports a single-argument ``exploit_*`` callable is picked up automatically, so
adding a CVE means dropping in one file -- no central registry to edit.

A module may optionally declare metadata used by the UI::

    META = {
        "cve": "CVE-2025-1234",      # defaults to the filename
        "title": "Unauthenticated file upload",
        "type": "Arbitrary File Upload",
        "component": "plugin-slug",
        "year": 2025,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2025-1234"],
    }
    EXPLOIT_ENTRY = "exploit_cve_2025_1234"   # optional explicit entry point
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil
import re
from dataclasses import dataclass, field

EXPLOITS_PACKAGE = "exploits"

_FILENAME_CVE = re.compile(r"cve_?(\d{4})_(\d{1,7})", re.IGNORECASE)


@dataclass(frozen=True)
class ExploitSpec:
    cve: str
    module: str
    entry_point: str
    title: str = ""
    vuln_type: str = ""
    component: str = ""
    year: int = 0
    references: tuple = field(default_factory=tuple)

    @property
    def label(self) -> str:
        return self.cve

    @property
    def summary(self) -> str:
        details = " - ".join(part for part in (self.vuln_type, self.title) if part)
        return f"{self.cve}: {details}" if details else self.cve


def _cve_from_filename(name: str) -> str:
    match = _FILENAME_CVE.search(name)
    if not match:
        raise ValueError(f"cannot derive a CVE id from {name!r}")
    year, number = match.groups()
    return f"CVE-{year}-{number}"


def _year_from_cve(cve: str) -> int:
    match = re.search(r"CVE-(\d{4})-", cve, re.IGNORECASE)
    return int(match.group(1)) if match else 0


def _resolve_entry_point(module) -> str:
    """Find the callable that exploits the target."""
    declared = getattr(module, "EXPLOIT_ENTRY", None)
    if declared:
        if not callable(getattr(module, declared, None)):
            raise AttributeError(f"{module.__name__} declares missing entry point {declared!r}")
        return declared

    candidates = [
        name
        for name, value in vars(module).items()
        if name.startswith("exploit")
        and inspect.isfunction(value)
        and value.__module__ == module.__name__
    ]
    if len(candidates) == 1:
        return candidates[0]
    if not candidates:
        raise AttributeError(f"{module.__name__} exports no exploit_* function")

    # Several exploit_* helpers: prefer the one carrying CVE digits, then the
    # one whose signature takes exactly the target instance.
    def rank(name):
        takes_one = len(inspect.signature(getattr(module, name)).parameters) == 1
        return (bool(re.search(r"\d{4}", name)), takes_one)

    return max(candidates, key=rank)


def _build_spec(module, module_name: str) -> ExploitSpec:
    short_name = module_name.rsplit(".", 1)[-1]
    meta = dict(getattr(module, "META", {}) or {})
    cve = meta.get("cve") or _cve_from_filename(short_name)
    return ExploitSpec(
        cve=cve.upper(),
        module=module_name,
        entry_point=_resolve_entry_point(module),
        title=meta.get("title", ""),
        vuln_type=meta.get("type", ""),
        component=meta.get("component", ""),
        year=int(meta.get("year") or _year_from_cve(cve)),
        references=tuple(meta.get("references", ())),
    )


def discover(disabled=()) -> list:
    """Import every exploit module and return specs sorted by CVE id."""
    package = importlib.import_module(EXPLOITS_PACKAGE)
    disabled = {item.upper() for item in disabled}
    specs = []
    for info in pkgutil.iter_modules(package.__path__):
        if info.ispkg or not info.name.startswith("cve_"):
            continue
        module_name = f"{EXPLOITS_PACKAGE}.{info.name}"
        module = importlib.import_module(module_name)
        spec = _build_spec(module, module_name)
        if spec.cve in disabled:
            continue
        specs.append(spec)
    return sorted(specs, key=lambda spec: (spec.year, spec.cve))


def load_function(spec: ExploitSpec):
    """Return the callable for a spec, importing its module on demand."""
    module = importlib.import_module(spec.module)
    return getattr(module, spec.entry_point)


def by_cve(specs) -> dict:
    return {spec.cve.lower(): spec for spec in specs}

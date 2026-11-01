"""Version discovery and self-update against the upstream GitHub repository.

Version information comes straight from ``github.com/<UPDATE_REPO>``, tried in
order of reliability:

1. the latest GitHub release (``/releases/latest``)
2. the highest semver tag (``/tags``)
3. the ``VERSION`` constant committed in ``mephisto/config.py`` on the default
   branch

Updating prefers ``git pull`` when the checkout is a git working tree, and falls
back to downloading the release archive. Either way ``config.json`` and the
``Result/`` directory are preserved.
"""

from __future__ import annotations

import io
import os
import re
import shutil
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path

import requests

DEFAULT_REPO = "InMyMine7/Mephisto"
API_ROOT = "https://api.github.com/repos"
CODELOAD_ROOT = "https://codeload.github.com"
HEADERS = {"User-Agent": "mephisto-updater", "Accept": "application/vnd.github+json"}
TIMEOUT = 4

# Never overwritten by the archive-based update path.
PROTECTED = {"config.json", "Result", ".git", "__pycache__", ".venv", "venv"}

_VERSION_EXPR = re.compile(r"VERSION\s*=\s*[\"']([^\"']+)[\"']")


@dataclass(frozen=True)
class ReleaseInfo:
    version: str
    tag: str
    url: str
    source: str
    notes: str = ""

    @property
    def label(self) -> str:
        return self.tag or f"v{self.version}"


def parse_version(value) -> tuple:
    """``v0.2.1`` -> ``(0, 2, 1)``; unparsable input yields ``()``."""
    match = re.search(r"(\d+(?:\.\d+)*)", str(value or ""))
    if not match:
        return ()
    return tuple(int(part) for part in match.group(1).split("."))


def is_newer(remote: str, local: str) -> bool:
    remote_parts, local_parts = parse_version(remote), parse_version(local)
    if not remote_parts or not local_parts:
        return False
    width = max(len(remote_parts), len(local_parts))
    pad = lambda parts: parts + (0,) * (width - len(parts))
    return pad(remote_parts) > pad(local_parts)


def repo_of(config) -> str:
    return (config.get("UPDATE_REPO") or DEFAULT_REPO).strip("/")


def _get(url: str, timeout: int = TIMEOUT):
    return requests.get(url, headers=HEADERS, timeout=timeout)


def _from_release(repo: str):
    try:
        response = _get(f"{API_ROOT}/{repo}/releases/latest")
    except requests.RequestException:
        return None
    if response.status_code != 200:
        return None
    try:
        payload = response.json()
    except ValueError:
        return None
    tag = payload.get("tag_name") or ""
    version = ".".join(str(part) for part in parse_version(tag))
    if not version:
        return None
    return ReleaseInfo(
        version=version,
        tag=tag,
        url=payload.get("html_url") or f"https://github.com/{repo}/releases",
        source="release",
        notes=(payload.get("body") or "").strip(),
    )


def _from_tags(repo: str):
    try:
        response = _get(f"{API_ROOT}/{repo}/tags?per_page=100")
    except requests.RequestException:
        return None
    if response.status_code != 200:
        return None
    try:
        tags = response.json()
    except ValueError:
        return None
    best = None
    for entry in tags if isinstance(tags, list) else []:
        name = entry.get("name") or ""
        version = ".".join(str(part) for part in parse_version(name))
        if not version:
            continue
        if best is None or is_newer(version, best.version):
            best = ReleaseInfo(
                version=version,
                tag=name,
                url=f"https://github.com/{repo}/releases/tag/{name}",
                source="tag",
            )
    return best


def _from_source(repo: str, branch: str = "main"):
    url = f"https://raw.githubusercontent.com/{repo}/{branch}/mephisto/config.py"
    try:
        response = _get(url)
    except requests.RequestException:
        return None
    if response.status_code != 200:
        return None
    match = _VERSION_EXPR.search(response.text)
    if not match:
        return None
    version = match.group(1)
    return ReleaseInfo(
        version=".".join(str(part) for part in parse_version(version)),
        tag=f"v{version}",
        url=f"https://github.com/{repo}",
        source="source",
    )


def latest(config, local_version: str | None = None) -> ReleaseInfo | None:
    """Highest version advertised by the upstream repository."""
    from . import config as config_module

    local_version = local_version or config_module.VERSION
    repo = repo_of(config)

    candidates = [
        candidate
        for candidate in (_from_release(repo), _from_tags(repo), _from_source(repo))
        if candidate and candidate.version
    ]
    if not candidates:
        return None

    best = candidates[0]
    for candidate in candidates[1:]:
        if is_newer(candidate.version, best.version):
            best = candidate
    return best


def available(config, local_version: str | None = None) -> ReleaseInfo | None:
    """Return the upstream release when it is strictly newer than ours."""
    from . import config as config_module

    local_version = local_version or config_module.VERSION
    info = latest(config, local_version)
    if info and is_newer(info.version, local_version):
        return info
    return None


# --------------------------------------------------------------------------- #
# Updating
# --------------------------------------------------------------------------- #


def project_root() -> Path:
    from . import config as config_module

    return Path(config_module.ROOT_DIR)


def _run_git(root: Path, *args) -> subprocess.CompletedProcess:
    creation = 0x08000000 if os.name == "nt" else 0
    return subprocess.run(
        ["git", *args],
        cwd=str(root),
        capture_output=True,
        text=True,
        timeout=120,
        creationflags=creation,
    )


def _installed_version(root: Path) -> str:
    source = root / "mephisto" / "config.py"
    try:
        text = source.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    match = _VERSION_EXPR.search(text)
    return match.group(1) if match else ""


def _update_git(root: Path, info: ReleaseInfo, dry_run: bool):
    if not (root / ".git").exists() or shutil.which("git") is None:
        return False, "not a git checkout"

    fetch = _run_git(root, "fetch", "--tags", "--quiet")
    if fetch.returncode != 0:
        return False, (fetch.stderr or "git fetch failed").strip()

    if not dry_run:
        pull = _run_git(root, "pull", "--ff-only", "--quiet")
        if pull.returncode == 0:
            installed = _installed_version(root)
            if not installed or is_newer(installed, info.version) or parse_version(installed) == parse_version(info.version):
                return True, f"updated to {installed or info.version} with git pull"

        # A detached or diverged checkout cannot fast-forward: use the archive.
        return False, "git pull did not fast-forward"
    return True, f"git fetch ok ({info.label})"


def _safe_extract(archive: Path, destination: Path):
    with zipfile.ZipFile(archive) as bundle:
        target = destination.resolve()
        for member in bundle.infolist():
            resolved = (destination / member.filename).resolve()
            if not str(resolved).startswith(str(target)):
                raise ValueError(f"unsafe path in archive: {member.filename}")
        bundle.extractall(destination)


def _copy_tree(source: Path, root: Path):
    copied = []
    for item in sorted(source.rglob("*")):
        if not item.is_file():
            continue
        relative = item.relative_to(source)
        parts = relative.parts
        if any(part in PROTECTED for part in parts) or parts[0] in PROTECTED:
            continue
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(item, destination)
        copied.append(str(relative))
    return copied


def update(config, info: ReleaseInfo | None = None, dry_run: bool = False):
    """Install ``info`` (or the newest release) into the project directory.

    Returns ``(ok, message)``. ``config.json`` and ``Result/`` are preserved.
    """
    from . import config as config_module

    root = project_root()
    info = info or available(config)
    if info is None:
        return False, "already up to date"

    ok, message = _update_git(root, info, dry_run)
    if ok:
        return ok, message

    return _download_and_install(config, info, root, dry_run)


def _download_and_install(config, info: ReleaseInfo, root: Path, dry_run: bool):
    repo = repo_of(config)
    archive_url = f"{CODELOAD_ROOT}/{repo}/zip/refs/tags/{info.tag}"
    try:
        response = _get(archive_url, timeout=30)
    except requests.RequestException as exc:
        return False, f"download failed ({type(exc).__name__})"
    if response.status_code != 200 or not response.content:
        return False, f"download failed (HTTP {response.status_code})"

    if dry_run:
        return True, f"archive available for {info.label}"

    with tempfile.TemporaryDirectory() as workspace:
        archive = Path(workspace) / "release.zip"
        archive.write_bytes(response.content)
        extracted = Path(workspace) / "tree"
        try:
            _safe_extract(archive, extracted)
        except (zipfile.BadZipFile, ValueError) as exc:
            return False, f"cannot unpack archive ({exc})"

        roots = [path for path in extracted.iterdir() if path.is_dir()]
        source = roots[0] if len(roots) == 1 else extracted
        copied = _copy_tree(source, root)

    if not copied:
        return False, "archive contained no files to install"
    installed = _installed_version(root)
    return True, f"installed {installed or info.version} ({len(copied)} files updated)"


# --------------------------------------------------------------------------- #
# User preference
# --------------------------------------------------------------------------- #


def should_notify(config, info: ReleaseInfo | None, local_version: str | None = None) -> bool:
    """Respect a version the user asked to skip.

    A skip only suppresses that exact version; a newer release still notifies.
    """
    if info is None:
        return False
    skipped = str(config.get("SKIPPED_VERSION") or "").strip()
    if not skipped:
        return True
    return is_newer(info.version, skipped)


def skip_version(config, version: str):
    from . import config as config_module

    config["SKIPPED_VERSION"] = version
    try:
        config_module.save(config)
    except OSError:
        pass


def clear_skip(config):
    from . import config as config_module

    if config.pop("SKIPPED_VERSION", None) is not None:
        try:
            config_module.save(config)
        except OSError:
            pass

"""Terminal UI for Mephisto."""

from __future__ import annotations

import os
import sys
import time

import requests
from colorama import Fore, Style, init

from . import config as config_module
from . import ui
from .engine import ERROR, SUCCESS, TIMEOUT, Listener, run_target, run_targets
from .registry import discover
from .results import ResultStore

init(autoreset=True)


class LiveScanView(Listener):
    """Draws one line per exploit as the scan progresses."""

    def __init__(self, quiet=False):
        self.quiet = quiet
        self.started = 0.0
        self.hits = 0

    def target_start(self, report, total_exploits):
        self.started = time.time()
        self.hits = 0
        print()
        print(
            f"  {ui.paint(ui.GLYPH.arrow, ui.ACCENT)} "
            f"{ui.paint(report.url, Style.BRIGHT + Fore.WHITE)}  "
            f"{ui.paint(str(total_exploits) + ' exploits', ui.FAINT)}"
        )
        print(ui.paint("  " + ui.GLYPH.h * (ui.term_width() - 2), ui.FAINT))

    def exploit_done(self, report, outcome, index, total):
        if self.quiet:
            return
        if outcome.status == SUCCESS:
            self.hits += 1
        label, colour = ui.badge(outcome.status)
        bar_colour = ui.ACCENT if self.hits else ui.FAINT
        print(
            f"  {ui.paint(str(index).rjust(2) + '/' + str(total), ui.FAINT)}  "
            f"{ui.paint(outcome.cve.ljust(16), ui.MUTED)}  "
            f"{ui.paint(label.ljust(8), colour)}  "
            f"{ui.metric_bar(index, total, 12, bar_colour)}  "
            f"{ui.paint(f'{outcome.duration:5.2f}s', ui.FAINT)}"
        )

    def target_done(self, report):
        if self.quiet:
            return
        print(ui.paint("  " + ui.GLYPH.h * (ui.term_width() - 2), ui.FAINT))


def confirm_assets(config):
    """Return the payload status shown in the banner and warn when incomplete."""
    payload_dir = config["FILES_DIR"]
    missing = [
        name for name in config["REQUIRED_FILES"] if not os.path.exists(os.path.join(payload_dir, name))
    ]
    present = len(config["REQUIRED_FILES"]) - len(missing)
    return present, missing


def print_banner(config, specs):
    present, missing = confirm_assets(config)
    total = len(config["REQUIRED_FILES"])
    notice = ""
    if missing:
        notice = f"missing payload: {', '.join(missing)}"
    ui.banner(
        config_module.VERSION,
        {
            "exploits": len(specs),
            "payloads": f"{present}/{total}",
            "notice": notice,
        },
    )
    if missing:
        ui.notice(
            f"payload folder {ui.paint(config['FILES_DIR'], ui.MUTED)} is incomplete - "
            f"exploits needing {', '.join(missing)} will skip",
            "warn",
        )


def print_menu(config, specs):
    rows = [
        ("1", "Start exploit", "single target or a target list"),
        ("2", "List exploits", f"{len(specs)} CVE modules registered"),
        ("3", "Support developer", "keep the project alive"),
        ("0", "Exit", ""),
    ]
    print()
    for key, label, hint in rows:
        number = ui.paint(f"[{key}]", ui.ACCENT)
        print(f"  {number} {ui.paint(label.ljust(20), ui.MUTED)} {ui.paint(hint, ui.FAINT)}")
    print()


def list_exploits(specs):
    print()
    ui.rule(f"{len(specs)} registered exploits")
    rows = []
    for index, spec in enumerate(specs, 1):
        kind = spec.vuln_type or "-"
        component = spec.component if spec.component else ("-", ui.FAINT)
        rows.append(
            [
                (str(index), ui.FAINT),
                spec.cve,
                kind,
                component,
            ]
        )
    ui.table(["#", "CVE", "TYPE", "COMPONENT"], rows, aligns=["right", "left", "left", "left"])
    print()
    ui.notice("every module runs automatically against each target", "info")
    if any(spec.references for spec in specs):
        ui.notice("modules with references expose them in their META block", "info")


def support_developer(config):
    print()
    ui.rule("support the project")
    for url in config["SUPPORT_URL"]:
        print(f"  {ui.paint(ui.GLYPH.arrow, ui.ACCENT)} {ui.paint(url, ui.INFO)}")
    print()
    ui.notice("github.com/InMyMine7  ·  t.me/InMyMineee", "info")


def check_updates(config):
    """Report version status once per session; the menu redraws often."""
    if config.get("_update_checked"):
        return
    config["_update_checked"] = True

    url = config.get("UPDATE_URL") or ""
    if not url:
        return

    try:
        response = requests.get(url, timeout=min(config["TIMEOUT"], 3))
        body = response.text.strip()
    except requests.RequestException as exc:
        ui.notice(f"update check skipped ({type(exc).__name__})", "warn")
        return

    if response.status_code != 200 or not body:
        ui.notice("update check unavailable", "warn")
        return

    if config_module.VERSION in body:
        ui.notice("you are on the latest version", "ok")
    elif body.lower().startswith("<") or "not found" in body.lower():
        ui.notice("update check returned no data", "warn")
    else:
        ui.notice(body.splitlines()[0][:80], "warn")


def ask_threads():
    raw = ui.prompt("threads", default="10")
    try:
        return max(1, int(raw)) if raw else 10
    except ValueError:
        ui.notice("invalid thread count, using 10", "warn")
        return 10


def read_targets():
    path = ui.prompt("target list path")
    if not path:
        ui.notice("no path given", "error")
        return []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            targets = [line.strip() for line in handle if line.strip() and not line.startswith("#")]
        if not targets:
            ui.notice("target list is empty", "warn")
        return targets
    except FileNotFoundError:
        ui.notice(f"file not found: {path}", "error")
        return []
    except OSError as exc:
        ui.notice(f"cannot read {path}: {exc}", "error")
        return []


PLURAL = {
    "shell": "shell",
    "admin": "admin",
    "password": "password",
    "register": "user",
}


def _artifact_summary(outcome):
    """'1 shell, 2 admins' for the rows this exploit added."""
    parts = [
        f"{count} {PLURAL.get(kind, kind)}{'s' if count > 1 else ''}"
        for kind, count in outcome.artifacts.items()
    ]
    return (", ".join(parts) or "-", ui.INFO)


def summarize(reports, config):
    """Print the verdict table plus where findings were written."""
    print()
    ui.rule("scan summary")

    rows = []
    totals = {"targets": len(reports), "vuln": 0, "clean": 0, "error": 0, "timeout": 0}
    for report in reports:
        if report.error:
            totals["error"] += 1
            rows.append([report.url, ("unreachable", ui.WARN), "-", "-", "-"])
            continue

        vuln = len(report.vulnerable)
        clean = sum(1 for o in report.outcomes if o.status == "NO")
        errored = len(report.failures)
        timed = len(report.timed_out)

        totals["vuln"] += vuln
        totals["clean"] += clean
        totals["error"] += errored
        totals["timeout"] += timed

        verdict = ("VULN", ui.ACCENT) if vuln else ("clean", ui.FAINT + Fore.WHITE)
        rows.append(
            [
                report.url,
                verdict,
                (str(vuln), ui.ACCENT if vuln else ui.FAINT),
                (str(errored) if errored else "-", ui.WARN if errored else ui.FAINT),
                (f"{report.duration:.1f}s", ui.FAINT),
            ]
        )

    ui.table(
        ["TARGET", "VERDICT", "VULN", "ERR", "TIME"],
        rows,
        aligns=["left", "left", "right", "right", "right"],
    )

    findings = [
        (report, outcome)
        for report in reports
        for outcome in report.vulnerable
    ]
    if findings:
        print()
        ui.rule("findings", color=ui.ACCENT)
        detail = [
            [outcome.cve, report.url, _artifact_summary(outcome)]
            for report, outcome in findings
        ]
        ui.table(["CVE", "TARGET", "RECORDED"], detail, aligns=["left", "left", "left"])

    problems = [
        (report, outcome)
        for report in reports
        for outcome in report.failures + report.timed_out
    ]
    if problems:
        print()
        ui.rule("problems", color=ui.WARN)
        for report, outcome in problems:
            ui.notice(f"{report.url}  {outcome.cve}  {outcome.detail or outcome.status}", "warn")

    print()
    result_dir = config["RESULT_DIR"]
    ui.key_value(
        [
            ("targets", ui.paint(str(totals["targets"]), ui.MUTED)),
            ("vulnerable", ui.paint(str(totals["vuln"]), ui.ACCENT if totals["vuln"] else ui.FAINT)),
            ("clean", ui.paint(str(totals["clean"]), ui.FAINT)),
            ("errors", ui.paint(str(totals["error"]), ui.WARN if totals["error"] else ui.FAINT)),
            ("results", ui.paint(result_dir, ui.FAINT)),
        ]
    )
    print()


def scan_single(config, specs):
    url = ui.prompt("target url")
    if not url:
        ui.notice("target url cannot be empty", "error")
        return

    deadline = prompt_deadline()
    ResultStore(config).ensure_dir()
    report = scan_with_abort(
        run_target, url, specs, config, deadline=deadline, listener=LiveScanView()
    )
    if report is None:
        return
    summarize([report], config)


def scan_mass(config, specs):
    targets = read_targets()
    if not targets:
        return
    threads = ask_threads()
    deadline = prompt_deadline()
    ResultStore(config).ensure_dir()

    ui.notice(f"scanning {len(targets)} targets with {threads} threads", "info")
    reports = scan_with_abort(
        run_targets,
        targets,
        specs,
        config,
        threads=threads,
        deadline=deadline,
        listener=LiveScanView(quiet=len(targets) > 1) if threads > 1 else LiveScanView(),
    )
    if reports is None:
        return
    summarize(reports, config)


def prompt_deadline():
    raw = ui.prompt("per-exploit deadline in seconds (blank = none)")
    if not raw:
        return None
    try:
        value = float(raw)
        return value if value > 0 else None
    except ValueError:
        ui.notice("invalid deadline, running without a limit", "warn")
        return None


def scan_with_abort(func, *args, **kwargs):
    """Run a scan; Ctrl+C stops the scan and returns to the menu."""
    try:
        return func(*args, **kwargs)
    except KeyboardInterrupt:
        print()
        ui.notice("scan stopped", "warn")
        return None


def run_scan(config, specs):
    print()
    ui.rule("start exploit")
    print()
    print(f"  {ui.paint('[1]', ui.ACCENT)} {ui.paint('single target', ui.MUTED)}")
    print(f"  {ui.paint('[2]', ui.ACCENT)} {ui.paint('target list', ui.MUTED)}   {ui.paint('one url per line', ui.FAINT)}")
    print()
    mode = ui.prompt("mode", default="1")
    if mode == "2":
        scan_mass(config, specs)
    elif mode in ("", "1"):
        scan_single(config, specs)
    else:
        ui.notice("invalid option", "error")


def main_menu():
    config = config_module.load()
    try:
        specs = discover(config.get("DISABLED_EXPLOITS", ()))
    except Exception as exc:
        print(f"  {ui.paint('x', ui.DANGER)} failed to load exploit modules: {exc}")
        return 1

    while True:
        os.system("cls" if os.name == "nt" else "clear")
        check_updates(config)
        print_banner(config, specs)
        print_menu(config, specs)

        choice = ui.prompt("choice")
        if choice in ("0", "q", "exit", "quit"):
            ui.notice("bye", "info")
            return 0
        if choice == "1":
            print()
            run_scan(config, specs)
            ui.pause()
        elif choice == "2":
            list_exploits(specs)
            ui.pause()
        elif choice == "3":
            support_developer(config)
            ui.pause()
        elif choice == "":
            continue
        else:
            ui.notice("invalid option", "error")
            time.sleep(0.8)


def run(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)

    if "-v" in argv or "--verbose" in argv:
        ui.set_verbose(True)

    targets = [arg for arg in argv if not arg.startswith("-")]
    if targets:
        return run_headless(targets)

    try:
        return main_menu()
    except KeyboardInterrupt:
        print()
        ui.notice("cancelled", "warn")
        return 1


def run_headless(targets):
    """Non-interactive scan: ``python main.py <url|list> [more...]``."""
    config = config_module.load()
    try:
        specs = discover(config.get("DISABLED_EXPLOITS", ()))
    except Exception as exc:
        print(f"  {ui.paint('x', ui.DANGER)} failed to load exploit modules: {exc}")
        return 1

    expanded = []
    for target in targets:
        if os.path.isfile(target):
            with open(target, "r", encoding="utf-8", errors="replace") as handle:
                expanded.extend(
                    line.strip() for line in handle if line.strip() and not line.startswith("#")
                )
        else:
            expanded.append(target)

    if not expanded:
        ui.notice("no targets to scan", "error")
        return 1

    ResultStore(config).ensure_dir()
    print()
    ui.rule(f"scanning {len(expanded)} target(s)")
    reports = run_targets(
        expanded,
        specs,
        config,
        threads=min(10, len(expanded)),
        listener=LiveScanView(quiet=len(expanded) > 1),
    )
    summarize(reports, config)
    return 0

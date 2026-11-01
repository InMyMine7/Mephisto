"""Target orchestration: run selected exploits against one or many targets."""

from __future__ import annotations

import random
import threading
import time
from dataclasses import dataclass, field
from multiprocessing.dummy import Pool
from typing import Callable, Optional

from .client import Exploit
from .registry import load_function
from .results import ResultStore

SUCCESS = "VULN"
CLEAN = "NO"
ERROR = "ERROR"
TIMEOUT = "TIMEOUT"


@dataclass
class ExploitOutcome:
    cve: str
    status: str
    artifacts: dict = field(default_factory=dict)
    detail: str = ""
    duration: float = 0.0


@dataclass
class TargetReport:
    url: str
    outcomes: list = field(default_factory=list)
    error: str = ""
    duration: float = 0.0

    @property
    def vulnerable(self):
        return [outcome for outcome in self.outcomes if outcome.status == SUCCESS]

    @property
    def failures(self):
        return [outcome for outcome in self.outcomes if outcome.status == ERROR]

    @property
    def timed_out(self):
        return [outcome for outcome in self.outcomes if outcome.status == TIMEOUT]


class Listener:
    """No-op observer; the CLI subclasses this to draw progress."""

    def target_start(self, report, total_exploits):
        pass

    def exploit_done(self, report, outcome, index, total):
        pass

    def target_done(self, report):
        pass


def _call_with_deadline(func, exploit, deadline):
    """Call ``func``, returning whether it finished before ``deadline`` seconds.

    Without a deadline the call runs inline so exceptions propagate naturally.
    With one it runs in a helper thread; a raised exception is re-raised in the
    caller once the thread reports back.
    """
    if not deadline:
        func(exploit)
        return True

    result = {}

    def runner():
        try:
            func(exploit)
        except BaseException as exc:
            result["error"] = exc
        finally:
            result["done"] = True

    worker = threading.Thread(target=runner, daemon=True)
    worker.start()
    worker.join(deadline)

    if not result.get("done"):
        return False
    error = result.get("error")
    if error is not None:
        raise error
    return True


def run_exploit(exploit, spec, store, deadline=None):
    """Run one module, deriving the verdict from what it recorded."""
    started = time.time()
    before = store.snapshot()
    try:
        finished = _call_with_deadline(load_function(spec), exploit, deadline)
        artifacts = store.diff(before, store.snapshot())
        elapsed = time.time() - started
        if not finished:
            return ExploitOutcome(spec.cve, TIMEOUT, artifacts, f"exceeded {deadline}s", elapsed)
        status = SUCCESS if artifacts else CLEAN
        return ExploitOutcome(spec.cve, status, artifacts, "", elapsed)
    except BaseException as exc:
        detail = f"{type(exc).__name__}: {exc}"
        return ExploitOutcome(spec.cve, ERROR, {}, detail, time.time() - started)


def _pause(pause):
    low, high = pause
    return random.uniform(low, high) if high > low else low


def run_target(url, specs, config, deadline=None, pause=(0.5, 1.5), listener: Optional[Listener] = None):
    """Run every spec against one target and return a :class:`TargetReport`."""
    listener = listener or Listener()
    store = ResultStore(config)
    store.ensure_dir()
    try:
        exploit = Exploit(url, config)
    except Exception as exc:
        return TargetReport(url=str(url), error=str(exc))

    started = time.time()
    report = TargetReport(url=exploit.url)
    total = len(specs)
    listener.target_start(report, total)

    for index, spec in enumerate(specs, 1):
        outcome = run_exploit(exploit, spec, store, deadline)
        report.outcomes.append(outcome)
        listener.exploit_done(report, outcome, index, total)
        time.sleep(_pause(pause))

    report.duration = time.time() - started
    listener.target_done(report)
    return report


def run_targets(targets, specs, config, threads=10, deadline=None, pause=(0.5, 1.5), listener=None):
    """Scan many targets concurrently; returns one report per target."""
    if not targets:
        return []
    if threads <= 1 or len(targets) == 1:
        return [run_target(url, specs, config, deadline, pause, listener) for url in targets]

    jobs = [(url, specs, config, deadline, pause, listener) for url in targets]
    with Pool(threads) as pool:
        return pool.starmap(run_target, jobs)

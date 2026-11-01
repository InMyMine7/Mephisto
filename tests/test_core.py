"""Self-checks for the Mephisto package.

Run with ``python -m unittest discover -s tests -t .`` (or ``python tests/test_core.py``).
No network access and no real target are required.
"""

import os
import io
import sys
import tempfile
import time
import unittest
import zipfile
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests

from mephisto import config as config_module
from mephisto import ui, updater
from mephisto.client import Exploit
from mephisto.engine import ERROR, SUCCESS, TIMEOUT, run_target, run_targets
from mephisto.registry import ExploitSpec, _cve_from_filename, discover, load_function
from mephisto.results import ResultStore


def make_config(tmpdir, **overrides):
    config = config_module.Config(config_module.DEFAULT_CONFIG.copy())
    config["FILES_DIR"] = os.path.join(tmpdir, "payloads")
    config["RESULT_DIR"] = os.path.join(tmpdir, "Result")
    os.makedirs(config["FILES_DIR"], exist_ok=True)
    config.update(overrides)
    return config


class RegistryTests(unittest.TestCase):
    def test_cve_from_filename(self):
        self.assertEqual(_cve_from_filename("cve_2025_7852"), "CVE-2025-7852")
        self.assertEqual(_cve_from_filename("CVE_2021_25094"), "CVE-2021-25094")
        with self.assertRaises(ValueError):
            _cve_from_filename("not_an_exploit")

    def test_every_module_is_discovered_with_a_callable_entry_point(self):
        specs = discover()
        self.assertGreaterEqual(len(specs), 22)
        for spec in specs:
            self.assertIsInstance(spec, ExploitSpec)
            self.assertRegex(spec.cve, r"^CVE-\d{4}-\d+$")
            self.assertTrue(spec.module.startswith("exploits."))
            self.assertTrue(callable(load_function(spec)), spec.cve)

    def test_specs_are_sorted_and_unique(self):
        specs = discover()
        cves = [spec.cve for spec in specs]
        self.assertEqual(cves, sorted(cves, key=lambda c: (int(c.split("-")[1]), c)))
        self.assertEqual(len(cves), len(set(cves)))

    def test_disabled_list_is_honoured(self):
        specs = discover(disabled=["CVE-2024-2667"])
        self.assertNotIn("CVE-2024-2667", [spec.cve for spec in specs])

    def test_multi_candidate_modules_resolve_to_the_cve_entry_point(self):
        specs = {spec.cve: spec for spec in discover()}
        self.assertEqual(specs["CVE-2025-15403"].entry_point, "exploit_cve_2025_15403")
        self.assertEqual(specs["CVE-2026-0920"].entry_point, "exploit_cve_2026_0920")


class ClientTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.config = make_config(self.tmpdir.name)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_url_is_normalised(self):
        self.assertEqual(Exploit("example.com", self.config).url, "https://example.com/")
        self.assertEqual(Exploit("http://example.com/wp/", self.config).url, "http://example.com/wp/")

    def test_helpers_have_the_expected_shape(self):
        exploit = Exploit("example.com", self.config)
        self.assertRegex(exploit.random_email(), r"^[a-z0-9]{10}@(gmail|yahoo|hotmail|outlook)\.com$")
        self.assertRegex(exploit.random_filename("php"), r"^[a-z0-9]{8}\.php$")
        self.assertTrue(exploit.random_password().startswith("mine"))
        self.assertRegex(exploit.random_username(), r"^nx_\d{4}_[a-z]{6}$")
        self.assertEqual(len(exploit.random_cookie(32)), 32)
        self.assertIn("User-Agent", exploit.headers)

    def test_obfuscate_shell_preserves_bytes(self):
        exploit = Exploit("example.com", self.config)
        payload = b"\xff\xd8\xff<?php echo 'InMyMine7'; ?>"
        self.assertEqual(exploit.obfuscate_shell(payload), payload)
        self.assertEqual(exploit.obfuscate_shell("abc"), b"abc")

    def test_record_appends_to_the_configured_file(self):
        exploit = Exploit("example.com", self.config)
        exploit.record("shell", "https://example.com/x.php")
        exploit.record("admin", "example.com | a:b")
        with open(exploit.result_path(self.config["SHELLS_FILE"]), encoding="utf-8") as handle:
            self.assertEqual(handle.read(), "https://example.com/x.php\n")
        with open(exploit.result_path(self.config["ADMINS_FILE"]), encoding="utf-8") as handle:
            self.assertEqual(handle.read(), "example.com | a:b\n")

    def test_record_rejects_unknown_kind(self):
        exploit = Exploit("example.com", self.config)
        with self.assertRaises(ValueError):
            exploit.record("nope", "x")

    def test_check_file_reports_missing_payload(self):
        exploit = Exploit("example.com", self.config)
        self.assertFalse(exploit.check_file("missing.jpg"))
        with open(exploit.payload_path("present.jpg"), "wb") as handle:
            handle.write(b"x")
        self.assertTrue(exploit.check_file("present.jpg"))


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.config = make_config(self.tmpdir.name)

    def tearDown(self):
        self.tmpdir.cleanup()

    def _spec(self, func, name="CVE-2025-0001"):
        return ExploitSpec(cve=name, module="fake.module", entry_point=func)

    def test_successful_exploit_is_reported_as_vulnerable(self):
        def fake(exploit):
            exploit.record("shell", f"{exploit.url}shell.php")

        with mock.patch("mephisto.engine.load_function", return_value=fake):
            report = run_target("example.com", [self._spec(fake)], self.config, pause=(0, 0))

        self.assertEqual(len(report.outcomes), 1)
        self.assertEqual(report.outcomes[0].status, SUCCESS)
        self.assertEqual(report.outcomes[0].artifacts, {"shell": 1})
        self.assertEqual(len(report.vulnerable), 1)
        self.assertEqual(report.failures, [])

    def test_exploit_without_artifacts_is_not_vulnerable(self):
        def fake(exploit):
            exploit.log_message("nothing found")

        with mock.patch("mephisto.engine.load_function", return_value=fake):
            report = run_target("example.com", [self._spec(fake)], self.config, pause=(0, 0))

        self.assertEqual(report.outcomes[0].status, "NO")
        self.assertEqual(report.vulnerable, [])

    def test_module_errors_do_not_abort_the_target_and_are_not_findings(self):
        def boom(exploit):
            raise RuntimeError("kaboom")

        def ok(exploit):
            exploit.record("admin", "example.com | a:b")

        specs = [self._spec(boom, "CVE-2025-0001"), self._spec(ok, "CVE-2025-0002")]
        with mock.patch("mephisto.engine.load_function", side_effect=[boom, ok]):
            report = run_target("example.com", specs, self.config, pause=(0, 0))

        self.assertEqual([o.status for o in report.outcomes], [ERROR, SUCCESS])
        self.assertEqual(len(report.failures), 1)
        self.assertIn("kaboom", report.failures[0].detail)
        self.assertEqual(len(report.vulnerable), 1)

    def test_network_errors_are_recorded_as_errors(self):
        def boom(exploit):
            raise requests.ConnectionError("no route")

        with mock.patch("mephisto.engine.load_function", return_value=boom):
            report = run_target("example.com", [self._spec(boom)], self.config, pause=(0, 0))
        self.assertEqual(report.outcomes[0].status, ERROR)

    def test_artifacts_are_counted_per_exploit_not_cumulatively(self):
        def first(exploit):
            exploit.record("shell", f"{exploit.url}a.php")

        def second(exploit):
            exploit.record("shell", f"{exploit.url}b.php")

        specs = [self._spec(first, "CVE-2025-0001"), self._spec(second, "CVE-2025-0002")]
        with mock.patch("mephisto.engine.load_function", side_effect=[first, second]):
            report = run_target("example.com", specs, self.config, pause=(0, 0))

        self.assertEqual(report.outcomes[0].artifacts, {"shell": 1})
        self.assertEqual(report.outcomes[1].artifacts, {"shell": 1})

    def test_deadline_marks_slow_exploits_as_timed_out(self):
        def slow(exploit):
            time.sleep(2)
            exploit.record("shell", "late")

        specs = [self._spec(slow)]
        with mock.patch("mephisto.engine.load_function", return_value=slow):
            report = run_target("example.com", specs, self.config, pause=(0, 0), deadline=0.2)

        self.assertEqual(report.outcomes[0].status, TIMEOUT)
        self.assertEqual(report.vulnerable, [])
        self.assertEqual([o.cve for o in report.timed_out], ["CVE-2025-0001"])

    def test_deadline_still_reports_exceptions(self):
        def boom(exploit):
            raise ValueError("bad module")

        with mock.patch("mephisto.engine.load_function", return_value=boom):
            report = run_target("example.com", [self._spec(boom)], self.config, pause=(0, 0), deadline=5)

        self.assertEqual(report.outcomes[0].status, ERROR)
        self.assertIn("ValueError", report.outcomes[0].detail)

    def test_multiple_targets_run_concurrently(self):
        def found(exploit):
            exploit.record("shell", f"{exploit.url}s.php")

        targets = ["a.example", "b.example", "c.example"]
        with mock.patch("mephisto.engine.load_function", return_value=found):
            reports = run_targets(targets, [self._spec(found)], self.config, threads=3, pause=(0, 0))

        self.assertEqual(len(reports), 3)
        self.assertTrue(all(len(report.vulnerable) == 1 for report in reports))
        self.assertEqual(len({report.url for report in reports}), 3)

    def test_empty_target_list_returns_no_reports(self):
        self.assertEqual(run_targets([], [self._spec(lambda e: None)], self.config), [])


class ResultStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.config = make_config(self.tmpdir.name)
        self.store = ResultStore(self.config)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_snapshot_counts_lines_and_handles_missing_files(self):
        self.assertEqual(self.store.snapshot(), {"shell": 0, "password": 0, "admin": 0, "register": 0})
        self.store.ensure_dir()
        exploit = Exploit("example.com", self.config)
        exploit.record("shell", "a")
        exploit.record("shell", "b")
        self.assertEqual(self.store.snapshot()["shell"], 2)

    def test_diff_returns_growth_per_artifact(self):
        self.store.ensure_dir()
        exploit = Exploit("example.com", self.config)
        exploit.record("admin", "a")
        before = self.store.snapshot()
        exploit.record("admin", "b")
        exploit.record("shell", "c")
        after = self.store.snapshot()
        self.assertEqual(self.store.diff(before, after), {"admin": 1, "shell": 1})


class RenderTests(unittest.TestCase):
    """The UI layer must stay width-safe and never leak ANSI into widths."""

    def _capture(self, func, *args, **kwargs):
        buffer = io.StringIO()
        with mock.patch("sys.stdout", buffer):
            func(*args, **kwargs)
        return buffer.getvalue().splitlines()

    def test_truncate_uses_ellipsis_only_when_needed(self):
        self.assertEqual(ui.truncate("short", 10), "short")
        self.assertEqual(ui.truncate("x" * 20, 10), "x" * 9 + ui.GLYPH.ellipsis)
        self.assertEqual(ui.truncate("abc", 0), "")

    def test_table_cells_align_despite_ansi_codes(self):
        ui.GLYPH = ui._Glyphs(False)
        rows = [[("styled", ui.ACCENT), "plain"], ["a", "b"]]
        lines = self._capture(ui.table, ["LEFT", "RIGHT"], rows)
        widths = {len(ui._strip_ansi(line)) for line in lines}
        self.assertEqual(len(widths), 1, lines)

    def test_table_truncates_to_terminal_width(self):
        ui.GLYPH = ui._Glyphs(False)
        rows = [["x" * 200, "y" * 200] for _ in range(3)]
        lines = self._capture(ui.table, ["A", "B"], rows, width=70)
        for line in lines:
            self.assertLessEqual(len(ui._strip_ansi(line)), 70)

    def test_badge_maps_every_engine_status(self):
        for status in (SUCCESS, "NO", ERROR, TIMEOUT):
            label, colour = ui.badge(status)
            self.assertTrue(label)
            self.assertIsInstance(colour, str)

    def test_metric_bar_is_proportional(self):
        half = ui._strip_ansi(ui.metric_bar(5, 10, 10))
        full = ui._strip_ansi(ui.metric_bar(10, 10, 10))
        empty = ui._strip_ansi(ui.metric_bar(0, 10, 10))
        self.assertEqual(len(half), 10)
        self.assertEqual(len(full), 10)
        self.assertEqual(half.count(ui.GLYPH.bar_full), 5)
        self.assertEqual(full.count(ui.GLYPH.bar_full), 10)
        self.assertEqual(empty.count(ui.GLYPH.bar_full), 0)

    def test_verbose_flag_controls_module_logging(self):
        tmpdir = tempfile.TemporaryDirectory()
        try:
            config = make_config(tmpdir.name)
            exploit = Exploit("example.com", config)
            ui.set_verbose(False)
            self.assertEqual(self._capture(exploit.log_message, "quiet"), [])
            ui.set_verbose(True)
            self.assertEqual(len(self._capture(exploit.log_message, "loud")), 1)
        finally:
            ui.set_verbose(False)
            tmpdir.cleanup()


class UpdaterTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.config = make_config(self.tmpdir.name)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_version_parsing_handles_prefixes_and_junk(self):
        self.assertEqual(updater.parse_version("v0.2.1"), (0, 2, 1))
        self.assertEqual(updater.parse_version("0.1"), (0, 1))
        self.assertEqual(updater.parse_version("release-1.2.3"), (1, 2, 3))
        self.assertEqual(updater.parse_version(""), ())
        self.assertEqual(updater.parse_version(None), ())

    def test_newer_comparison_pads_missing_segments(self):
        self.assertTrue(updater.is_newer("0.2", "0.1"))
        self.assertTrue(updater.is_newer("0.1.1", "0.1"))
        self.assertTrue(updater.is_newer("1.0", "0.9.9"))
        self.assertFalse(updater.is_newer("0.1", "0.1"))
        self.assertFalse(updater.is_newer("0.1", "0.1.0"))
        self.assertFalse(updater.is_newer("0.1", "0.2"))
        self.assertFalse(updater.is_newer("junk", "0.1"))

    def test_repo_defaults_to_the_project_repository(self):
        self.assertEqual(updater.repo_of({}), "InMyMine7/Mephisto")
        self.assertEqual(updater.repo_of({"UPDATE_REPO": "owner/repo/"}), "owner/repo")

    def test_available_ignores_equal_or_older_remote(self):
        same = updater.ReleaseInfo(version="0.1", tag="v0.1", url="u", source="release")
        with mock.patch.object(updater, "latest", return_value=same):
            self.assertIsNone(updater.available(self.config, local_version="0.1"))
        newer = updater.ReleaseInfo(version="0.2", tag="v0.2", url="u", source="release")
        with mock.patch.object(updater, "latest", return_value=newer):
            self.assertIs(updater.available(self.config, local_version="0.1"), newer)

    def test_latest_prefers_the_highest_candidate(self):
        release = updater.ReleaseInfo(version="0.1", tag="v0.1", url="u", source="release")
        tag = updater.ReleaseInfo(version="0.3", tag="v0.3", url="u", source="tag")
        source = updater.ReleaseInfo(version="0.2", tag="v0.2", url="u", source="source")
        with mock.patch.object(updater, "_from_release", return_value=release), \
             mock.patch.object(updater, "_from_tags", return_value=tag), \
             mock.patch.object(updater, "_from_source", return_value=source):
            self.assertEqual(updater.latest(self.config).version, "0.3")

    def test_latest_returns_none_when_github_is_unreachable(self):
        with mock.patch.object(updater, "_from_release", return_value=None), \
             mock.patch.object(updater, "_from_tags", return_value=None), \
             mock.patch.object(updater, "_from_source", return_value=None):
            self.assertIsNone(updater.latest(self.config))

    def test_skipping_a_version_silences_only_that_version(self):
        info = updater.ReleaseInfo(version="0.2", tag="v0.2", url="u", source="release")
        self.assertTrue(updater.should_notify(self.config, None) is False)
        self.assertTrue(updater.should_notify(self.config, info))

        self.config["SKIPPED_VERSION"] = "0.2"
        self.assertFalse(updater.should_notify(self.config, info))

        later = updater.ReleaseInfo(version="0.3", tag="v0.3", url="u", source="release")
        self.assertTrue(updater.should_notify(self.config, later))

    def test_skip_preference_persists_through_config_save(self):
        info = updater.ReleaseInfo(version="0.2", tag="v0.2", url="u", source="release")
        path = os.path.join(self.tmpdir.name, "config.json")
        with mock.patch.object(config_module, "CONFIG_FILE", __import__("pathlib").Path(path)):
            updater.skip_version(self.config, info.version)
            reloaded = config_module.load()
        self.assertEqual(reloaded["SKIPPED_VERSION"], "0.2")

    def test_private_session_keys_never_reach_config_json(self):
        path = os.path.join(self.tmpdir.name, "config.json")
        self.config["_latest"] = "transient"
        with mock.patch.object(config_module, "CONFIG_FILE", __import__("pathlib").Path(path)):
            config_module.save(self.config)
            reloaded = config_module.load()
        self.assertNotIn("_latest", reloaded)

    def test_safe_extract_rejects_paths_outside_the_target(self):
        bundle = os.path.join(self.tmpdir.name, "evil.zip")
        with zipfile.ZipFile(bundle, "w") as archive:
            archive.writestr("../escaped.txt", "nope")
        with self.assertRaises(ValueError):
            updater._safe_extract(__import__("pathlib").Path(bundle), __import__("pathlib").Path(self.tmpdir.name) / "out")

    def test_archive_update_preserves_config_and_results(self):
        root = __import__("pathlib").Path(self.tmpdir.name) / "install"
        (root / "mephisto").mkdir(parents=True)
        (root / "mephisto" / "config.py").write_text('VERSION = "0.1"\n', encoding="utf-8")
        (root / "config.json").write_text('{"EMAIL": "keep@me"}\n', encoding="utf-8")
        (root / "Result").mkdir()
        (root / "Result" / "Shells.txt").write_text("mine\n", encoding="utf-8")

        staging = __import__("pathlib").Path(self.tmpdir.name) / "stage" / "Mephisto-0.2"
        (staging / "mephisto").mkdir(parents=True)
        (staging / "mephisto" / "config.py").write_text('VERSION = "0.2"\n', encoding="utf-8")
        (staging / "config.json").write_text('{"EMAIL": "remote"}\n', encoding="utf-8")
        (staging / "Result").mkdir()
        (staging / "Result" / "Shells.txt").write_text("junk\n", encoding="utf-8")
        (staging / "newfile.txt").write_text("hi\n", encoding="utf-8")

        bundle = os.path.join(self.tmpdir.name, "release.zip")
        with zipfile.ZipFile(bundle, "w") as archive:
            base = staging.parent
            for item in sorted(base.rglob("*")):
                if item.is_file():
                    archive.write(item, item.relative_to(base).as_posix())

        class FakeResponse:
            status_code = 200
            content = open(bundle, "rb").read()

        info = updater.ReleaseInfo(version="0.2", tag="v0.2", url="u", source="release")
        with mock.patch.object(config_module, "ROOT_DIR", root), \
             mock.patch.object(updater, "_get", return_value=FakeResponse()):
            ok, message = updater.update(self.config, info)

        self.assertTrue(ok, message)
        self.assertEqual((root / "mephisto" / "config.py").read_text().strip(), 'VERSION = "0.2"')
        self.assertTrue((root / "newfile.txt").exists())
        self.assertEqual((root / "config.json").read_text().strip(), '{"EMAIL": "keep@me"}')
        self.assertEqual((root / "Result" / "Shells.txt").read_text().strip(), "mine")


class ConfigTests(unittest.TestCase):
    def test_paths_resolve_against_the_project_root(self):
        config = config_module.load()
        self.assertTrue(os.path.isabs(config["FILES_DIR"]))
        self.assertTrue(os.path.isabs(config["RESULT_DIR"]))
        self.assertTrue(config["FILES_DIR"].endswith(os.path.join("assets", "payloads")))

    def test_defaults_survive_a_partial_config_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "config.json")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write('{"TIMEOUT": 5}')
            with mock.patch.object(config_module, "CONFIG_FILE", __import__("pathlib").Path(path)):
                config = config_module.load()
            self.assertEqual(config["TIMEOUT"], 5)
            self.assertIn("SHELLS_FILE", config)
            self.assertIn("PROXIES", config)


if __name__ == "__main__":
    unittest.main(verbosity=2)

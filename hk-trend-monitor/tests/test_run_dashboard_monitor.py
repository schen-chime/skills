import contextlib
import hashlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from types import SimpleNamespace
from unittest.mock import patch

# Standalone work-folder tests use the unchanged packaged legacy scripts.
# In the assembled package all four modules live together in scripts/.
SCRIPT_DIR = Path(__file__).resolve().parent
LEGACY_DIR = SCRIPT_DIR.parent / "package/scripts"
if LEGACY_DIR.is_dir():
    sys.path.insert(0, str(LEGACY_DIR))

from datetime import datetime
from test_login_volume_report import fixture as login_fixture
import run_dashboard_monitor as monitor


CUTOFF = "2026-10-21T15:00:00Z"


def record(kind, payload):
    return {"RECORD_TYPE": kind, "PAYLOAD": payload}


def primary(new_ids=()):
    rows = [
        record("COVERAGE", {"key": "extraction_complete", "value": True}),
        record("COVERAGE", {"key": "current_registry_available", "value": True}),
        record("COVERAGE", {"key": "campaign_activity_alerts_available", "value": True}),
        record("COVERAGE", {"key": "cutoff", "value": CUTOFF}),
        record("MEMBER", {"user_id": "42", "membership_kind": "recorded", "first_qualified_at": "2026-07-02T00:00:00Z"}),
        record("COHORT_USER", {"user_id": "42", "cohort": "campaign"}),
    ]
    for uid in new_ids:
        rows.extend([
            record("MEMBER", {"user_id": uid, "membership_kind": "candidate", "first_qualified_at": "2026-10-21T14:00:00Z", "evidence_event_at": "2026-10-21T14:00:00Z"}),
            record("COHORT_USER", {"user_id": uid, "cohort": "campaign"}),
        ])
    return {"data": [rows]}


def cohort():
    return [record("COHORT_COVERAGE", {"cutoff": CUTOFF, "chart_start": "2026-10-14T15:00:00Z", "extraction_complete": True,
            "emitted_device_rows": 1, "full_eligible_campaign_devices": 1, "sampled_baseline_devices": 0,
            "group_metrics": [{"cohort": "campaign", "emitted_device_rows": 1, "eligible_devices": 1,
                "excluded_devices": 0, "devices_with_valid_callbacks": 1, "app_access_fully_evaluated_devices": 1,
                "unknown_controlling_evaluated_devices": 1, "unknown_controlling_positive_devices": 1,
                "known_controlling_evaluated_devices": 1, "known_controlling_positive_devices": 0,
                "known_only_controlling_evaluated_devices": 1, "known_only_controlling_positive_devices": 0,
                "any_controlling_evaluated_devices": 1, "any_controlling_positive_devices": 1}]}),
            record("COHORT_DEVICE", {"device_id": "device-42", "user_id": "42", "cohort": "campaign", "eligible": True, "unknown_controlling": True, "known_controlling": False, "valid_callbacks": 1, "latest_observed_at": "2026-10-21T14:00:00Z", "app_access_evaluated": True})] + login_fixture(cutoff=datetime.fromisoformat(CUTOFF.replace("Z","+00:00")))


def risk(new_ids):
    rows = [record("COVERAGE", {"user_id": uid, "cutoff": CUTOFF, "valid_pi_callbacks": 1}) for uid in new_ids]
    if new_ids:
        rows.append(record("RISK", {"user_id": new_ids[0], "device_id": "new-device", "signal": "unknown_controlling", "scope": "direct_device", "majority_eligible": True, "risky": True, "observed_at": "2026-10-21T14:00:00Z"}))
    return rows


class WrapperTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.package = self.base / "skill"
        (self.package / "queries").mkdir(parents=True)
        (self.package / "queries/cohort_play_integrity.sql").write_text("WITH cohort AS ({{COHORT_USERS}}) SELECT {{BASELINE_LIMIT}} baseline_limit;")
        (self.package / "queries/play_integrity.sql").write_text("WITH new_users AS ({{NEW_USERS}}) SELECT * FROM new_users;")
        self.export = self.base / "input.hex.yaml"
        self.export.write_text("private synthetic exported dashboard source\n")
        self.out = self.base / "out"
        self.source = SimpleNamespace(metadata={"project_id": "synthetic-project", "source_version_id": "synthetic-version", "success_semantics": "dashboard_policy_allowed"})
        self.root_patch = patch.object(monitor, "ROOT", self.package)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)
        self.load_patch = patch.object(monitor, "load_dashboard_source", return_value=self.source)
        self.load = self.load_patch.start()
        self.addCleanup(self.load_patch.stop)
        self.main_patch = patch.object(monitor, "build_main_sql", return_value="SELECT 'synthetic primary query';")
        self.build_main = self.main_patch.start()
        self.addCleanup(self.main_patch.stop)
        self.cohort_input_patch = patch.object(monitor, "build_cohort_user_sql", return_value="SELECT 42::NUMBER user_id\nUNION SELECT 123::NUMBER user_id")
        self.build_cohort_input = self.cohort_input_patch.start()
        self.addCleanup(self.cohort_input_patch.stop)

    def args(self, *extra, supplied=True):
        values = ["--as-of", CUTOFF[:16] + "Z", "--out-dir", str(self.out)]
        if supplied:
            values.extend(["--dashboard-export", str(self.export)])
        return values + list(extra)

    def invoke(self, *extra, supplied=True):
        with contextlib.redirect_stdout(io.StringIO()) as captured:
            result = monitor.main(self.args(*extra, supplied=supplied))
        return result, captured.getvalue()

    @staticmethod
    def snow_mock(results, calls):
        def run(sql_path, output_path, connection):
            calls.append((sql_path.name, connection, sql_path.read_text()))
            result = results[len(calls) - 1]
            if isinstance(result, Exception):
                output_path.write_text("")
                output_path.with_suffix(".err").write_text(str(result))
                raise result
            output_path.write_text(json.dumps(result))
            output_path.with_suffix(".err").write_text("")
            return result
        return run

    def test_prepare_only_local_export_never_starts_either_cli(self):
        with patch.object(monitor, "run_snow") as snow, patch.object(monitor.subprocess, "run") as process:
            code, stdout = self.invoke("--prepare-only", "--baseline-limit", "10000")
        self.assertEqual(code, 0)
        snow.assert_not_called()
        process.assert_not_called()
        manifest = json.loads((self.out / "manifest.json").read_text())
        self.assertEqual(manifest["status"], "PREPARED_NO_QUERY")
        self.assertEqual(manifest["dashboard_source_sha256"], hashlib.sha256(self.export.read_bytes()).hexdigest())
        self.assertEqual((self.out / "dashboard_source.hex.yaml").read_bytes(), self.export.read_bytes())
        prepared = (self.out / "cohort_play_integrity.sql").read_text()
        self.assertNotIn("{{COHORT_USERS}}", prepared)
        self.assertIn("UNION SELECT 123::NUMBER user_id", prepared)
        self.assertIn("10000 baseline_limit", prepared)
        self.assertFalse((self.out / "results.json").exists())
        self.assertLess(len(stdout), 1000)

    def test_prepare_only_default_export_fetches_latest_once(self):
        def export(argv, stdout, stderr, check):
            self.assertEqual(argv[:6], ["hex", "project", "export", monitor.PROJECT_ID, "--hex-version", "latest"])
            Path(argv[argv.index("-o") + 1]).write_text(self.export.read_text())
            stdout.write('{"success":true}')
            return SimpleNamespace(returncode=0)
        with patch.object(monitor.subprocess, "run", side_effect=export) as process, patch.object(monitor, "run_snow") as snow:
            self.invoke("--prepare-only", supplied=False)
        self.assertEqual(process.call_count, 1)
        snow.assert_not_called()
        manifest = json.loads((self.out / "manifest.json").read_text())
        self.assertEqual(manifest["dashboard_export_returncode"], 0)
        self.assertIn("dashboard_export.err", manifest["artifact_sha256"])

    def test_hex_failure_attempts_once_and_never_attempts_snow(self):
        def fail(argv, stdout, stderr, check):
            stderr.write("synthetic authentication failure")
            return SimpleNamespace(returncode=7)
        with patch.object(monitor.subprocess, "run", side_effect=fail) as process, patch.object(monitor, "run_snow") as snow:
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as stopped:
                self.invoke(supplied=False)
        self.assertEqual(stopped.exception.code, 1)
        self.assertEqual(process.call_count, 1)
        snow.assert_not_called()
        self.assertEqual((self.out / "dashboard_export.err").read_text(), "synthetic authentication failure")
        manifest = json.loads((self.out / "manifest.json").read_text())
        self.assertEqual(manifest["status"], "FAILED")
        self.assertEqual(manifest["dashboard_export_returncode"], 7)

    def test_no_new_users_still_runs_full_cohort_and_filters_extension_rows(self):
        calls = []
        with patch.object(monitor, "run_snow", side_effect=self.snow_mock([primary(), cohort()], calls)), patch.object(monitor.subprocess, "run") as process:
            _, stdout = self.invoke()
        self.assertEqual([r[0] for r in calls], ["main.sql", "cohort_play_integrity.sql"])
        self.assertIn("VALUES (42)", calls[1][2])
        process.assert_not_called()
        summary = json.loads((self.out / "summary.json").read_text())
        self.assertEqual(summary["counts"]["new_users"], 0)
        self.assertEqual(summary["cohort_monitor"]["unique_devices"], 1)
        self.assertEqual(summary["status"], "OK")
        self.assertFalse(any("Unrecognized result record type" in w for w in summary["warnings"]))
        self.assertEqual(summary["risk_signals"][0]["status"], "NOT_APPLICABLE")
        self.assertEqual(summary["coverage"]["risk_query_available"], "not_applicable_no_additions")
        self.assertIn("Dashboard success = policy allowed", (self.out / "report.html").read_text())
        self.assertLess(len(stdout), 1000)
        self.assertNotIn("device-42", stdout)

    def test_empty_campaign_cohort_is_a_typed_empty_input_and_still_queries(self):
        calls = []
        data = primary()
        data["data"][0] = [r for r in data["data"][0] if r["RECORD_TYPE"] != "COHORT_USER"]
        with patch.object(monitor, "run_snow", side_effect=self.snow_mock([data, [cohort()[0]]], calls)):
            self.invoke()
        self.assertEqual(len(calls), 2)
        self.assertIn("SELECT NULL::NUMBER(38,0) user_id WHERE FALSE", calls[1][2])

    def test_new_user_legacy_risk_runs_after_cohort_and_uses_separate_denominator(self):
        calls = []
        with patch.object(monitor, "run_snow", side_effect=self.snow_mock([primary(("123", "124")), cohort(), risk(("123", "124"))], calls)):
            self.invoke()
        self.assertEqual([r[0] for r in calls], ["main.sql", "cohort_play_integrity.sql", "play_integrity.sql"])
        self.assertIn("VALUES (42),(123),(124)", calls[1][2])
        summary = json.loads((self.out / "summary.json").read_text())
        self.assertEqual(summary["counts"]["new_users"], 2)
        tracker = next(r for r in summary["risk_signals"] if r["signal"] == "unknown_controlling")
        self.assertEqual((tracker["triggered_users"], tracker["new_users"]), (1, 2))
        self.assertFalse(tracker["majority_of_new_users"])
        self.assertTrue(summary["coverage"]["risk_query_available"])
        self.assertFalse(any("risk telemetry for proposed additions is incomplete" in w for w in summary["warnings"]))

    def test_cohort_snow_failure_preserves_primary_and_prevents_later_auth_attempt(self):
        calls = []
        with patch.object(monitor, "run_snow", side_effect=self.snow_mock([primary(("123",)), RuntimeError("Snowflake CLI authentication failed; no retry")], calls)):
            code, stdout = self.invoke()
        self.assertEqual(code, 0)
        self.assertEqual(len(calls), 2)
        summary = json.loads((self.out / "summary.json").read_text())
        manifest = json.loads((self.out / "manifest.json").read_text())
        self.assertEqual(summary["counts"]["prior_users"], 1)
        self.assertEqual(summary["counts"]["new_users"], 1)
        self.assertEqual(summary["status"], "PARTIAL")
        self.assertEqual(summary["cohort_monitor"]["status"], "PARTIAL")
        self.assertFalse(summary["coverage"]["risk_query_available"])
        self.assertTrue(manifest["cohort_cli_failed_no_more_snow_attempts"])
        self.assertEqual(manifest["phases"]["new_user_risk"], "skipped_after_cohort_cli_failure")
        self.assertTrue((self.out / "main.json").exists())
        self.assertTrue((self.out / "cohort_play_integrity.err").exists())
        self.assertIn('"status": "PARTIAL"', stdout)

    def test_cohort_result_validation_error_preserves_raw_and_can_run_legacy(self):
        calls = []
        malformed = [cohort()[0], record("COHORT_DEVICE", {"device_id": "d", "cohort": "unsupported"})]
        with patch.object(monitor, "run_snow", side_effect=self.snow_mock([primary(("123",)), malformed, risk(("123",))], calls)):
            self.invoke()
        self.assertEqual(len(calls), 3)
        summary = json.loads((self.out / "summary.json").read_text())
        raw = json.loads((self.out / "raw_results.json").read_text())
        self.assertEqual(raw["cohort"], malformed)
        self.assertEqual(summary["status"], "PARTIAL")
        self.assertTrue(summary["coverage"]["risk_query_available"])
        self.assertEqual(summary["counts"]["new_users"], 1)

    def test_primary_failure_stops_once_without_optional_queries(self):
        calls = []
        with patch.object(monitor, "run_snow", side_effect=self.snow_mock([RuntimeError("primary auth failure")], calls)):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                self.invoke()
        self.assertEqual(len(calls), 1)
        self.assertEqual(json.loads((self.out / "manifest.json").read_text())["status"], "FAILED")

    def test_missing_optional_template_cannot_discard_primary(self):
        (self.package / "queries/cohort_play_integrity.sql").unlink()
        calls = []
        with patch.object(monitor, "run_snow", side_effect=self.snow_mock([primary()], calls)):
            self.invoke()
        self.assertEqual([call[0] for call in calls], ["main.sql"])
        summary = json.loads((self.out / "summary.json").read_text())
        self.assertEqual(summary["status"], "PARTIAL")
        self.assertEqual(summary["counts"]["prior_users"], 1)
        self.assertEqual(summary["counts"]["new_users"], 0)

    def test_legacy_failure_keeps_primary_and_successful_cohort(self):
        calls = []
        with patch.object(monitor, "run_snow", side_effect=self.snow_mock([primary(("123",)), cohort(), RuntimeError("legacy CLI failure")], calls)):
            self.invoke()
        self.assertEqual(len(calls), 3)
        summary = json.loads((self.out / "summary.json").read_text())
        self.assertEqual(summary["cohort_monitor"]["status"], "AVAILABLE")
        self.assertEqual(summary["counts"]["new_users"], 1)
        self.assertEqual(summary["status"], "PARTIAL")
        self.assertFalse(summary["coverage"]["risk_query_available"])

    def test_legacy_result_cannot_inject_new_members(self):
        calls = []
        poisoned = risk(("123",)) + [record("MEMBER", {"user_id": "999", "membership_kind": "candidate", "first_qualified_at": "2026-10-21T14:00:00Z", "evidence_event_at": "2026-10-21T14:00:00Z"})]
        with patch.object(monitor, "run_snow", side_effect=self.snow_mock([primary(("123",)), cohort(), poisoned], calls)):
            self.invoke()
        summary = json.loads((self.out / "summary.json").read_text())
        self.assertEqual(summary["counts"]["new_users"], 1)
        self.assertEqual(summary["new_users"][0]["user_id"], "123")
        self.assertFalse(summary["coverage"]["risk_query_available"])

    def test_invalid_inputs_fail_before_source_reads_or_any_cli(self):
        for extra in (("--baseline-limit", "0"), ("--baseline-limit", "10001"), ("--baseline-limit", "1 OR 1"), ("--role", "ANALYST;DROP"), ("--campaign-start", "2026-10-21"), ("--connection", "--bad")):
            with self.subTest(extra=extra), patch.object(monitor, "run_snow") as snow, patch.object(monitor.subprocess, "run") as process:
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    self.invoke(*extra)
                snow.assert_not_called()
                process.assert_not_called()
                self.load.assert_not_called()
                self.build_cohort_input.assert_not_called()
                self.assertFalse(self.out.exists())

    def test_source_filter_and_safe_cohort_values(self):
        document = [primary(), record("COHORT_USER", {"user_id": "7", "cohort": "campaign"}), record("COHORT_USER", {"user_id": "42", "cohort": "campaign"})]
        self.assertTrue(all(r["RECORD_TYPE"] in monitor.RECOGNIZED_TYPES for r in monitor.renderer_rows(document)))
        values, ids = monitor.cohort_user_values(document)
        self.assertEqual(ids, ["7", "42"])
        self.assertIn("VALUES (7),(42)", values)
        for invalid in ("0", "-1", "1.1", "1); DROP TABLE x;--", None, True):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                monitor.cohort_user_values([record("COHORT_USER", {"user_id": invalid})])

    def test_multiline_cohort_input_is_never_expanded_in_sql_comment(self):
        result = monitor._render_template("-- {{COHORT_USERS}} is a typed SELECT\nWITH cohort AS ({{COHORT_USERS}}) SELECT {{BASELINE_LIMIT}};", {"COHORT_USERS": "SELECT 1 user_id\nUNION SELECT 2 user_id", "BASELINE_LIMIT": "5000"}, "test")
        self.assertEqual(result.count("UNION SELECT 2 user_id"), 1)
        self.assertTrue(result.startswith("-- COHORT_USERS input is a typed SELECT\n"))
        self.assertNotIn("{{", result)


if __name__ == "__main__":
    unittest.main()

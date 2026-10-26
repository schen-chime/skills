"""Synthetic runner checks. No test may execute snow or access the network."""

import contextlib
import hashlib
import io
import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import run_monitor as runner


AS_OF = "2026-10-20 12:30"


def result(kind, **payload):
    return {"RECORD_TYPE": kind, "PAYLOAD": payload}


def primary_results(with_addition=True, user_id="12345678"):
    rows = [
        result("COVERAGE", key="extraction_complete", value=True),
        result("COVERAGE", key="current_registry_available", value=True),
        result("COVERAGE", key="cutoff", value="2026-10-20T17:30:00Z"),
    ]
    if with_addition:
        rows.append(result("MEMBER", user_id=user_id, membership_kind="candidate",
                           first_qualified_at="2026-10-20T08:00:00Z",
                           evidence_event_at="2026-10-20T08:01:00Z",
                           reasons=["synthetic campaign evidence"]))
    return rows


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hk-runner-test-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.package = self.base / "fixture-package"
        queries = self.package / "queries"
        queries.mkdir(parents=True)
        (queries / "monitor.sql").write_text("-- synthetic main query fixture\nSELECT 1;\n")
        (queries / "play_integrity.sql").write_text("WITH new_users AS ({{NEW_USERS}}) SELECT * FROM new_users;\n")
        root_patch = mock.patch.object(runner, "ROOT", self.package)
        root_patch.start()
        self.addCleanup(root_patch.stop)
        # Defense in depth: an accidental unmocked command fails the test
        # before any Snowflake/authentication process can be started.
        command_patch = mock.patch.object(runner.subprocess, "run", side_effect=AssertionError("External commands are forbidden in synthetic tests"))
        command_patch.start()
        self.addCleanup(command_patch.stop)
        self.output = self.base / "report"

    def arguments(self, *extra, out_dir=None):
        return ["--as-of", AS_OF, "--out-dir", str(out_dir or self.output), *extra]

    def invoke(self, args):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return runner.main(args)

    def summary(self):
        return json.loads((self.output / "summary.json").read_text())

    def test_prepare_only_validates_time_and_writes_reproducible_sql_without_query(self):
        with mock.patch.object(runner, "run_snow") as snow:
            self.assertEqual(self.invoke(self.arguments("--prepare-only")), 0)
            snow.assert_not_called()
        sql = (self.output / "main.sql").read_text()
        manifest = json.loads((self.output / "manifest.json").read_text())
        self.assertIn("SET cutoff=TO_TIMESTAMP_TZ('2026-10-20T17:30:00Z')", sql)
        self.assertIn("SET day_start=TO_TIMESTAMP_TZ('2026-10-20T05:00:00Z')", sql)
        self.assertIn("SET chart_start=TO_TIMESTAMP_TZ('2026-10-13T17:30:00Z')", sql)
        self.assertEqual(manifest["main_sql_sha256"], hashlib.sha256(sql.encode()).hexdigest())
        self.assertEqual(manifest["chart_hours"], 168)
        self.assertTrue(manifest["read_only"])
        self.assertFalse((self.output / "main.json").exists())
        self.assertFalse((self.output / "play_integrity.sql").exists())
        self.assertFalse((self.output / "report.html").exists())

    def test_invalid_dates_zone_history_and_identifiers_stop_before_any_query(self):
        cases = [
            ["--as-of", "2026-10-20"],
            ["--as-of", "2026-10-20 24:00"],
            ["--as-of", "2999-01-01 12:30"],
            ["--timezone", "Not/A_Real_Zone"],
            ["--campaign-start", "2026-02-30"],
            ["--campaign-start", "2026-10-19"],
            ["--campaign-start", "07/01/2026"],
            ["--role", "ANALYST;DROP TABLE X"],
            ["--warehouse", "A B"],
        ]
        with mock.patch.object(runner, "run_snow") as snow:
            for index, extra in enumerate(cases):
                output = self.base / f"invalid-{index}"
                with self.subTest(extra=extra), self.assertRaises(SystemExit) as stopped:
                    self.invoke(self.arguments("--prepare-only", *extra, out_dir=output))
                self.assertEqual(stopped.exception.code, 1)
                self.assertFalse((output / "main.sql").exists())
            snow.assert_not_called()

    def test_as_of_is_required(self):
        with mock.patch.object(runner, "run_snow") as snow:
            with self.assertRaises(SystemExit) as stopped:
                self.invoke(["--out-dir", str(self.output), "--prepare-only"])
            self.assertEqual(stopped.exception.code, 2)
            snow.assert_not_called()

    def test_no_additions_skips_integrity_preparation_and_query(self):
        with mock.patch.object(runner, "run_snow", return_value=primary_results(False)) as snow:
            self.assertEqual(self.invoke(self.arguments()), 0)
            self.assertEqual(snow.call_count, 1)
        self.assertFalse((self.output / "play_integrity.sql").exists())
        self.assertTrue((self.output / "report.html").is_file())
        summary = self.summary()
        self.assertEqual(summary["counts"]["new_users"], 0)
        self.assertEqual(summary["coverage"]["risk_query_available"], "not_applicable_no_additions")
        self.assertFalse(summary["has_alerts"])

    def test_integrity_query_failure_preserves_primary_report_as_partial(self):
        with mock.patch.object(runner, "run_snow", side_effect=[primary_results(), RuntimeError("synthetic network policy failure")]) as snow:
            self.assertEqual(self.invoke(self.arguments()), 0)
            self.assertEqual(snow.call_count, 2)
        summary = self.summary()
        self.assertEqual(summary["status"], "PARTIAL")
        self.assertFalse(summary["coverage"]["risk_query_available"])
        self.assertEqual(summary["counts"]["new_users"], 1)
        self.assertIn("12345678", (self.output / "new_users.csv").read_text())
        self.assertTrue((self.output / "report.html").is_file())
        self.assertTrue(any("synthetic network policy failure" in text for risk in summary["risk_signals"] for text in risk["missing_reasons"]))

    def test_integrity_preparation_failure_preserves_primary_report(self):
        (self.package / "queries/play_integrity.sql").unlink()
        with mock.patch.object(runner, "run_snow", return_value=primary_results()) as snow:
            self.assertEqual(self.invoke(self.arguments()), 0)
            self.assertEqual(snow.call_count, 1)
        self.assertEqual(self.summary()["status"], "PARTIAL")
        self.assertFalse(self.summary()["coverage"]["risk_query_available"])

    def test_malformed_integrity_payload_preserves_primary_report(self):
        malformed = [result("RISK", user_id="12345678", signal="play_integrity:test",
                            scope="pi_independent", majority_eligible=True,
                            risky=True, observed_at="not a timestamp")]
        with mock.patch.object(runner, "run_snow", side_effect=[primary_results(), malformed]) as snow:
            self.assertEqual(self.invoke(self.arguments()), 0)
            self.assertEqual(snow.call_count, 2)
        self.assertEqual(self.summary()["status"], "PARTIAL")
        self.assertEqual(self.summary()["counts"]["new_users"], 1)
        self.assertFalse(self.summary()["coverage"]["risk_query_available"])

    def test_mismatched_integrity_cutoff_preserves_primary_report(self):
        wrong_cutoff = [result("COVERAGE", scope="run", cutoff="2026-10-20T18:30:00Z")]
        with mock.patch.object(runner, "run_snow", side_effect=[primary_results(), wrong_cutoff]):
            self.assertEqual(self.invoke(self.arguments()), 0)
        self.assertEqual(self.summary()["status"], "PARTIAL")
        self.assertFalse(self.summary()["coverage"]["risk_query_available"])

    def test_successful_integrity_results_are_combined_and_can_alert(self):
        integrity = [result("RISK", user_id="12345678", signal="play_integrity:app_access_controlling",
                            risky=True, observed_at="2026-10-20T09:00:00Z",
                            scope="pi_independent", majority_eligible=True),
                     result("COVERAGE", user_id="12345678", cutoff="2026-10-20T17:30:00Z",
                            valid_pi_callbacks=1)]
        with mock.patch.object(runner, "run_snow", side_effect=[primary_results(), integrity]) as snow:
            self.assertEqual(self.invoke(self.arguments()), 0)
            self.assertEqual(snow.call_count, 2)
        summary = self.summary()
        self.assertTrue(summary["coverage"]["risk_query_available"])
        self.assertTrue(any(alert["kind"] == "common_risky_signal" for alert in summary["alerts"]))
        self.assertIn("(12345678,'2026-10-20T08:01:00Z')", (self.output / "play_integrity.sql").read_text())

    def test_empty_integrity_result_is_partial_not_clean(self):
        with mock.patch.object(runner, "run_snow", side_effect=[primary_results(), []]):
            self.assertEqual(self.invoke(self.arguments()), 0)
        self.assertEqual(self.summary()["status"], "PARTIAL")
        self.assertFalse(self.summary()["coverage"]["risk_query_available"])
        self.assertEqual(self.summary()["counts"]["new_users"], 1)

    def test_primary_query_failure_stops_once_without_optional_query_or_false_report(self):
        with mock.patch.object(runner, "run_snow", side_effect=RuntimeError("synthetic authentication failure")) as snow:
            with self.assertRaises(SystemExit) as stopped:
                self.invoke(self.arguments())
            self.assertEqual(stopped.exception.code, 1)
            self.assertEqual(snow.call_count, 1)
        self.assertFalse((self.output / "report.html").exists())

    def test_run_snow_failure_runs_subprocess_once_without_authentication_retry(self):
        sql = self.base / "synthetic.sql"
        sql.write_text("SELECT 1")
        output = self.base / "synthetic.json"

        def failed_process(command, **kwargs):
            kwargs["stdout"].write("[]")
            kwargs["stderr"].write("synthetic authentication failure")
            return SimpleNamespace(returncode=7)

        with mock.patch.object(runner.subprocess, "run", side_effect=failed_process) as process:
            with self.assertRaisesRegex(RuntimeError, "No authentication retry"):
                runner.run_snow(sql, output, "env")
            process.assert_called_once()
            self.assertEqual(process.call_args.args[0], ["snow", "sql", "-c", "env", "-f", str(sql), "--format", "JSON"])
            self.assertFalse(process.call_args.kwargs["check"])
        self.assertIn("authentication", output.with_suffix(".err").read_text())


class UserValuesTests(unittest.TestCase):
    def test_empty_user_list_is_typed_and_bounded(self):
        self.assertEqual(runner.new_user_values([]), "SELECT NULL::NUMBER user_id,NULL::TIMESTAMP_TZ first_qualified_at WHERE FALSE")

    def test_values_are_deduplicated_sorted_and_normalized_to_utc(self):
        values = runner.new_user_values([
            {"user_id": "10", "evidence_event_at": "2026-10-20T09:00:00-05:00"},
            {"user_id": "2", "evidence_event_at": "2026-10-20T13:00:00Z"},
            {"user_id": "10", "evidence_event_at": "2026-10-20T13:30:00Z"},
        ])
        self.assertTrue(values.endswith("(2,'2026-10-20T13:00:00Z'),(10,'2026-10-20T13:30:00Z')"))
        self.assertEqual(values.count("(10,"), 1)

    def test_invalid_ids_and_missing_naive_or_injected_timestamps_are_rejected(self):
        cases = [
            {"user_id": "0", "evidence_event_at": "2026-10-20T13:00:00Z"},
            {"user_id": "-1", "evidence_event_at": "2026-10-20T13:00:00Z"},
            {"user_id": "1);SELECT 1--", "evidence_event_at": "2026-10-20T13:00:00Z"},
            {"user_id": "0001", "evidence_event_at": "2026-10-20T13:00:00Z"},
            {"user_id": "12345678901", "evidence_event_at": "2026-10-20T13:00:00Z"},
            {"user_id": "1"},
            {"user_id": "1", "evidence_event_at": None},
            {"user_id": "1", "evidence_event_at": "2026-10-20T13:00:00"},
            {"user_id": "1", "evidence_event_at": "2026-10-20T13:00:00Z');SELECT 1--"},
            None,
        ]
        for value in cases:
            with self.subTest(value=value), self.assertRaises(ValueError):
                runner.new_user_values([value])


if __name__ == "__main__":
    unittest.main()

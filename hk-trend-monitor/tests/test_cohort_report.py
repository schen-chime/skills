import copy
import csv
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))

from cohort_report import (
    append_cohort_report, configure_dashboard_labels, historical_benchmark,
    summarize_cohort,
)


CUTOFF = datetime(2026, 10, 26, 15, tzinfo=timezone.utc)


def record(kind, payload):
    return {"RECORD_TYPE": kind, "PAYLOAD": payload}


def device(device_id="d1", **kwargs):
    row = {
        "device_id": device_id, "user_id": "u1", "cohort": "campaign", "eligible": True,
        "exclusion_reason": "", "unknown_controlling": True, "known_controlling": False,
        "latest_observed_at": "2026-10-26T14:00:00Z", "first_positive_at": "2026-10-26T14:00:00Z",
        "last_positive_at": "2026-10-26T14:00:00Z", "valid_callbacks": 1,
        "missing_reason": "", "app_access_evaluated": True,
    }
    row.update(kwargs)
    return record("COHORT_DEVICE", row)


def coverage(rows=None, **kwargs):
    rows = [device()] if rows is None else rows
    devices = {row["PAYLOAD"]["device_id"]: row["PAYLOAD"] for row in rows}
    groups = []
    for cohort in ("campaign", "baseline", "ambiguous"):
        selected = [row for row in devices.values() if row["cohort"] == cohort]
        if not selected:
            continue
        eligible = [row for row in selected if row["eligible"]]
        group = {"cohort": cohort, "emitted_device_rows": len(selected), "eligible_devices": len(eligible),
                 "excluded_devices": len(selected) - len(eligible),
                 "devices_with_valid_callbacks": sum(row["valid_callbacks"] > 0 for row in eligible),
                 "app_access_fully_evaluated_devices": sum(row["app_access_evaluated"] is True for row in eligible)}
        values = []
        for row in eligible:
            u, k = row.get("unknown_controlling"), row.get("known_controlling")
            values.append({"unknown_controlling": u, "known_controlling": k,
                           "known_only_controlling": row.get("known_only_controlling", False if u is True or k is False else True if k is True and u is False else None),
                           "any_controlling": row.get("any_controlling", True if u is True or k is True else False if u is False and k is False else None)})
        for signal in ("unknown_controlling", "known_controlling", "known_only_controlling", "any_controlling"):
            group[signal + "_evaluated_devices"] = sum(row[signal] is not None for row in values)
            group[signal + "_positive_devices"] = sum(row[signal] is True for row in values)
        groups.append(group)
    return record("COHORT_COVERAGE", {"extraction_complete": True, "cohort_query_available": True,
        "cutoff": "2026-10-26T15:00:00Z", "emitted_device_rows": len(devices),
        "full_eligible_campaign_devices": sum(row["eligible"] and row["cohort"] == "campaign" for row in devices.values()),
        "sampled_baseline_devices": sum(row["eligible"] and row["cohort"] == "baseline" for row in devices.values()),
        "group_metrics": groups, **kwargs})


def metric(summary, signal="unknown_controlling", cohort="campaign"):
    return next(r for r in summary["metrics"] if r["signal"] == signal and r["cohort"] == cohort)


class CohortAggregationTests(unittest.TestCase):
    def test_nested_wrappers_and_exact_duplicate_count_once(self):
        row = device(extra_provenance={"source": "direct"})
        row_string = {"record_type": "COHORT_DEVICE", "payload": json.dumps(row["PAYLOAD"])}
        result = summarize_cohort({"data": [[coverage(), row], {"rows": [row_string]}]}, CUTOFF)
        self.assertEqual(result["unique_devices"], 1)
        self.assertEqual(result["deduplicated_exact_rows"], 1)
        self.assertEqual(metric(result)["positive_devices"], 1)
        self.assertEqual(result["devices"][0]["extra_provenance"], {"source": "direct"})

    def test_conflicting_identity_is_quarantined(self):
        result = summarize_cohort([coverage(), device(), device(user_id="u2", cohort="baseline")], CUTOFF)
        self.assertEqual(result["unique_devices"], 1)
        self.assertFalse(result["devices"][0]["eligible"])
        self.assertEqual(result["devices"][0]["cohort"], "ambiguous")
        self.assertEqual(metric(result)["all_eligible_devices"], 0)
        self.assertEqual(metric(result, cohort="baseline")["all_eligible_devices"], 0)

    def test_conflicting_same_time_signal_is_quarantined(self):
        result = summarize_cohort([coverage(), device(), device(unknown_controlling=False)], CUTOFF)
        self.assertFalse(result["devices"][0]["eligible"])
        self.assertIn("unknown_controlling", result["devices"][0]["conflicting_fields"])

    def test_latest_negative_wins_over_prior_positive(self):
        result = summarize_cohort([coverage(), device(latest_observed_at="2026-10-25T14:00:00Z"), device(unknown_controlling=False, first_positive_at=None, last_positive_at=None)], CUTOFF)
        self.assertEqual(metric(result)["positive_devices"], 0)
        self.assertEqual(metric(result)["observed_devices"], 1)
        self.assertEqual(result["devices"][0]["distinct_source_row_count"], 2)

    def test_missing_telemetry_stays_in_all_eligible_denominator(self):
        rows = [device(), device("missing", user_id=None, unknown_controlling=None, known_controlling=None, latest_observed_at=None, first_positive_at=None, last_positive_at=None, valid_callbacks=0, app_access_evaluated=False, missing_reason="no callback")]
        result = summarize_cohort([coverage(rows), *rows], CUTOFF)
        row = metric(result)
        self.assertEqual((row["positive_devices"], row["all_eligible_devices"], row["observed_devices"], row["unknown_devices"]), (1, 2, 1, 1))
        self.assertEqual(row["positive_share_all_eligible"], 0.5)
        self.assertEqual(row["positive_share_observed"], 1)
        self.assertEqual(row["negative_devices"], 0)

    def test_zero_new_users_does_not_disable_cohort_monitor(self):
        result = summarize_cohort([coverage(), record("COVERAGE", {"key": "new_users", "value": 0}), device()], CUTOFF)
        self.assertTrue(result["independent_of_new_users"])
        self.assertEqual(metric(result)["positive_devices"], 1)
        self.assertEqual(result["status"], "AVAILABLE")

    def test_window_is_half_open_and_cannot_use_future(self):
        rows = [coverage(), device("start", latest_observed_at="2026-10-19T15:00:00Z"), device("old", latest_observed_at="2026-10-19T14:59:59Z"), device("at-cutoff", latest_observed_at="2026-10-26T15:00:00Z")]
        result = summarize_cohort(rows, CUTOFF)
        self.assertEqual(metric(result)["all_eligible_devices"], 3)
        self.assertEqual(metric(result)["positive_devices"], 1)
        self.assertEqual(metric(result)["unknown_devices"], 2)

    def test_each_signal_has_its_own_observed_denominator(self):
        result = summarize_cohort([coverage(), device(known_controlling=None, app_access_evaluated=False)], CUTOFF)
        self.assertEqual(metric(result)["positive_devices"], 1)
        self.assertEqual(metric(result)["observed_devices"], 1)
        self.assertEqual(metric(result, "known_controlling")["observed_devices"], 0)
        self.assertEqual(metric(result, "known_only_controlling")["negative_devices"], 1)
        self.assertEqual(metric(result, "any_controlling")["positive_devices"], 1)
        self.assertEqual(result["populations"][0]["fully_evaluated_devices"], 0)

    def test_unknown_known_and_both_are_not_exclusive(self):
        result = summarize_cohort([coverage(), device("unknown"), device("known", unknown_controlling=False, known_controlling=True), device("both", unknown_controlling=True, known_controlling=True), device("neither", unknown_controlling=False, known_controlling=False)], CUTOFF)
        self.assertEqual(metric(result)["positive_devices"], 2)
        self.assertEqual(metric(result, "known_controlling")["positive_devices"], 2)
        self.assertEqual(metric(result, "known_only_controlling")["positive_devices"], 1)
        self.assertEqual(metric(result, "any_controlling")["positive_devices"], 3)

    def test_explicit_inconsistent_derived_verdict_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "inconsistent known_only_controlling"):
            summarize_cohort([coverage(), device(known_only_controlling=True)], CUTOFF)

    def test_invalid_eligible_and_count_are_not_silently_truthy(self):
        with self.assertRaises(ValueError):
            summarize_cohort([coverage(), device(eligible="yes")], CUTOFF)
        with self.assertRaises(ValueError):
            summarize_cohort([coverage(), device(valid_callbacks=-1)], CUTOFF)

    def test_historical_context_is_fixed_and_separate_from_live_zero(self):
        result = summarize_cohort([coverage(), device(unknown_controlling=False, known_controlling=False)], CUTOFF)
        self.assertEqual(metric(result)["positive_devices"], 0)
        historical = result["historical_benchmark"]
        self.assertEqual(historical["original_population"], {"campaign": 1259, "baseline": 5893})
        row = historical["rows"][0]
        self.assertEqual((row["campaign_positive"], row["baseline_positive"]), (145, 39))
        self.assertAlmostEqual(row["campaign_rate"], 145 / 908)
        self.assertAlmostEqual(row["baseline_rate"], 39 / 4165)
        self.assertAlmostEqual(row["rate_ratio"], (145 / 908) / (39 / 4165))
        self.assertEqual(historical["selected_takeover_observations"]["examined"], 9)
        self.assertEqual(historical["selected_takeover_observations"]["signal"], "unknown_controlling")
        self.assertEqual(historical["selected_takeover_observations"]["first_positive_after_phone_change"], 4)
        self.assertIn("does not establish pre-action detection", historical["selected_takeover_observations"]["description"])
        self.assertEqual(historical_benchmark()["rows"][1]["campaign_positive"], 61)

    def test_coverage_absent_false_and_cutoff_mismatch(self):
        self.assertEqual(summarize_cohort([device()], CUTOFF)["status"], "UNAVAILABLE")
        self.assertEqual(summarize_cohort([coverage(extraction_complete=False)], CUTOFF)["status"], "PARTIAL")
        self.assertEqual(summarize_cohort([coverage(seven_day_window_valid=False)], CUTOFF)["status"], "PARTIAL")
        self.assertEqual(summarize_cohort([coverage(chart_start="2026-10-18T15:00:00Z")], CUTOFF)["status"], "PARTIAL")
        with self.assertRaisesRegex(ValueError, "cutoff differs"):
            summarize_cohort([coverage(cutoff="2026-10-26T16:00:00Z")], CUTOFF)

    def test_empty_successful_extraction_retains_unknown_rates(self):
        result = summarize_cohort([coverage([])], CUTOFF)
        self.assertEqual(result["status"], "AVAILABLE")
        self.assertIsNone(metric(result)["positive_share_all_eligible"])
        self.assertEqual(result["hourly"]["status"], "NOT_AVAILABLE_FROM_DEVICE_SNAPSHOTS")

    def test_truncated_snapshot_is_partial_and_cannot_publish_rates(self):
        expected = [device(), device("d2", unknown_controlling=False)]
        result = summarize_cohort([coverage(expected), expected[0]], CUTOFF)
        self.assertEqual(result["status"], "PARTIAL")
        self.assertFalse(result["count_reconciliation"]["verified"])
        self.assertIn("declared 2, received 1", result["count_reconciliation"]["error"])
        self.assertIsNone(metric(result)["positive_share_all_eligible"])
        self.assertIsNone(metric(result)["positive_share_observed"])
        self.assertTrue(all(row["rate_ratio_observed"] is None for row in result["live_comparisons"]))

    def test_missing_or_conflicting_count_metadata_is_not_available(self):
        missing = record("COHORT_COVERAGE", {"cutoff": "2026-10-26T15:00:00Z"})
        self.assertEqual(summarize_cohort([missing, device()], CUTOFF)["status"], "PARTIAL")
        result = summarize_cohort([coverage(), coverage(emitted_device_rows=2), device()], CUTOFF)
        self.assertEqual(result["status"], "PARTIAL")
        self.assertIn("Conflicting", result["count_reconciliation"]["error"])

    def test_group_denominator_and_signal_counts_are_reconciled(self):
        for field in ("eligible_devices", "unknown_controlling_evaluated_devices", "unknown_controlling_positive_devices"):
            metadata = coverage()
            metadata["PAYLOAD"]["group_metrics"][0][field] += 1
            with self.subTest(field=field):
                result = summarize_cohort([metadata, device()], CUTOFF)
                self.assertEqual(result["status"], "PARTIAL")
                self.assertIn(field, result["count_reconciliation"]["error"])

    def test_valid_campaign_baseline_counts_allow_rates_and_exact_duplicates(self):
        rows = [device(), device("b1", cohort="baseline", user_id="u2", unknown_controlling=False)]
        result = summarize_cohort([coverage(rows), *rows, rows[0]], CUTOFF)
        self.assertEqual(result["status"], "AVAILABLE")
        self.assertTrue(result["count_reconciliation"]["verified"])
        self.assertEqual(metric(result)["positive_share_all_eligible"], 1)
        self.assertEqual(metric(result, cohort="baseline")["positive_share_all_eligible"], 0)


class CohortArtifactTests(unittest.TestCase):
    def test_append_preserves_core_counts_and_majority_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            core = {"status": "OK", "counts": {"new_users": 0, "prior_users": 42}, "risk_signals": [{"majority_of_new_users": False}], "warnings": [], "alerts": [{"message": "New IP: 7 persisted successes"}], "ips": [{"persisted_successes": None}]}
            original = copy.deepcopy(core)
            (directory / "summary.json").write_text(json.dumps(core))
            (directory / "summary.md").write_text("HK trend monitor — OK\n\nSuccesses are persisted completions; policy allowed is a separate series.\nNew IP: 7 persisted successes\n")
            (directory / "report.html").write_text('<html><body><main><h1>HK trend monitor <span class="badge">OK</span></h1><select><option value="successes">Persisted successes</option></select><p>New IP: 7 persisted successes</p></main></body></html>')
            for _ in range(2):
                append_cohort_report(directory, [device()], CUTOFF, dashboard_success_policy_allowed=True)
            updated = json.loads((directory / "summary.json").read_text())
            self.assertEqual(updated["counts"], original["counts"])
            self.assertEqual(updated["risk_signals"], original["risk_signals"])
            self.assertEqual(updated["status"], "PARTIAL")
            self.assertEqual(updated["dashboard_success_semantics"], "policy_allowed")
            self.assertEqual(updated["alerts"][0]["message"], "New IP: 7 dashboard successes (policy allowed)")
            self.assertIsNone(updated["ips"][0]["persisted_successes"])
            text = (directory / "report.html").read_text()
            self.assertEqual(text.count('id="play-integrity-cohorts"'), 1)
            self.assertIn('badge">PARTIAL', text)
            self.assertIn("Dashboard success = policy allowed", text)
            self.assertNotIn("Persisted successes</option>", text)
            self.assertNotIn("7 persisted successes", text)
            self.assertIn("7 dashboard successes (policy allowed)", text)
            self.assertEqual((directory / "summary.md").read_text().count("Play Integrity device cohorts —"), 1)
            self.assertIn("UNKNOWN and KNOWN can coexist", (directory / "cohort_report.html").read_text())
            with (directory / "cohort_metrics.csv").open(newline="") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(len(rows), 12)
            self.assertIn("positive_share_observed", rows[0])

    def test_label_hook_does_not_modify_counts(self):
        report = {"counts": {"successes": 4}}
        configure_dashboard_labels(report)
        self.assertEqual(report["counts"], {"successes": 4})


if __name__ == "__main__":
    unittest.main()

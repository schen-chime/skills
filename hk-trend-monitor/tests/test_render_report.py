"""Focused contract checks using synthetic data only; stdlib unittest."""

import csv
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import render_report as monitor


UTC = timezone.utc
NOW = datetime(2026, 12, 1, tzinfo=UTC)
AS_OF = "2026-10-26 12:30"
CUTOFF = datetime(2026, 10, 26, 17, 30, tzinfo=UTC)
DAY_START = datetime(2026, 10, 26, 5, tzinfo=UTC)


def row(kind, **payload):
    if kind == "RISK":
        payload.setdefault("scope", "pi_independent")
        payload.setdefault("majority_eligible", True)
    return {"RECORD_TYPE": kind, "PAYLOAD": payload}


def coverage(complete=True, registry=True):
    return [
        row("COVERAGE", key="extraction_complete", value=complete),
        row("COVERAGE", key="current_registry_available", value=registry),
    ]


def member(user, kind="candidate", first="2026-10-26T07:00:00Z", evidence="2026-10-26T08:00:00Z", **extra):
    return row("MEMBER", user_id=str(user), membership_kind=kind,
               first_qualified_at=first, evidence_event_at=evidence, **extra)


def hourly(at, value=1, **extra):
    metrics = {metric: value for metric in monitor.METRICS}
    return row("HOURLY", bucket_start=at, **{**metrics, **extra})


def report(extra=(), complete=True, registry=True, as_of=AS_OF):
    return monitor.build_report(coverage(complete, registry) + list(extra), as_of, now=NOW)


class InputAndClockTests(unittest.TestCase):
    def test_nested_snow_multi_statement_results_and_json_payload(self):
        data = [[{"status": "Statement executed successfully."}], [
            {"record_type": "COVERAGE", "payload": '{"key":"extraction_complete","value":true}'},
            row("COVERAGE", key="current_registry_available", value=True),
        ], {"data": [member("7")]}]
        output = monitor.build_report(data, AS_OF, now=NOW)
        self.assertEqual(output["new_users"][0]["user_id"], "7")
        self.assertEqual(output["bucket_count"], 168)

    def test_invalid_time_and_future_rejected(self):
        for value in ("2026-10-26", "2026-10-26 24:00", "2026-10-26 12:30:01", "10/26/2026 12:30"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                monitor.parse_cutoff(value, now=NOW)
        with self.assertRaisesRegex(ValueError, "future"):
            monitor.parse_cutoff("2026-12-02 00:00", now=NOW)

    def test_dst_fold_requires_offset_and_gap_rejected(self):
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            monitor.parse_cutoff("2026-11-01 01:30", now=NOW)
        with self.assertRaisesRegex(ValueError, "does not exist"):
            monitor.parse_cutoff("2026-03-08 02:30", now=NOW)
        early, _ = monitor.parse_cutoff("2026-11-01T01:30-05:00", now=NOW)
        late, _ = monitor.parse_cutoff("2026-11-01T01:30-06:00", now=NOW)
        self.assertEqual(late - early, timedelta(hours=1))

    def test_malformed_payload_and_empty_results_rejected(self):
        with self.assertRaises(ValueError):
            monitor.build_report([{"RECORD_TYPE": "MEMBER", "PAYLOAD": "bad JSON"}], AS_OF, now=NOW)
        with self.assertRaises(ValueError):
            monitor.build_report([{"status": "SQL failed"}], AS_OF, now=NOW)

    def test_source_cutoff_must_match_selected_cutoff(self):
        for payload in (
            {"key": "cutoff", "value": "2026-10-26T18:30:00Z"},
            {"scope": "run", "cutoff": "2026-10-26T18:30:00Z"},
        ):
            with self.subTest(payload=payload), self.assertRaisesRegex(ValueError, "cutoff differs"):
                report([row("COVERAGE", **payload)])
        output = report([row("COVERAGE", key="cutoff", value="2026-10-26 17:30:00")])
        self.assertEqual(output["as_of_utc"], "2026-10-26T17:30:00Z")


class MembershipTests(unittest.TestCase):
    def test_recorded_prior_and_today_candidates_are_disjoint_with_half_open_boundaries(self):
        data = [
            member("1", "recorded", "2026-10-26T04:59:59.999999Z"),
            member("2", "recorded", "2026-10-26T05:00:00Z"),
            member("1"),  # already known before day; do not add again
            member("2"),  # today's annotation is visible and flagged
            member("3", first="2026-10-20T05:00:00Z"),  # older unrecorded eligibility, fresh evidence
            member("4", first="2026-10-26T05:00:00Z", evidence="2026-10-26T05:00:00Z"),
            member("5", first="2026-10-26T17:30:00Z", evidence="2026-10-26T17:30:00Z"),
            member("6", evidence="2026-10-26T17:30:00Z"),
        ]
        output = report(data)
        self.assertEqual({r["user_id"] for r in output["prior_users"]}, {"1"})
        self.assertEqual({r["user_id"] for r in output["new_users"]}, {"2", "3", "4"})
        self.assertEqual({r["user_id"] for r in output["recorded_today"]}, {"2"})
        self.assertEqual({r["user_id"] for r in output["all_users"]}, {"1", "2", "3", "4"})
        candidate = next(r for r in output["new_users"] if r["user_id"] == "2")
        self.assertTrue(candidate["annotated_today"])
        self.assertIn("already annotated", candidate["status"])
        self.assertEqual(output["counts"]["prior_users"], 1)
        self.assertTrue(any("Excluded 2 MEMBER" in w for w in output["warnings"]))

    def test_duplicate_users_stable_and_registry_timestamp_wins_union(self):
        data = [member("9", reasons=["rule_b"]), member("9", reasons=["rule_a"]),
                member("9", "recorded", first="2026-10-26T09:00:00Z")]
        output = report(data)
        reversed_output = report(reversed(data))
        self.assertEqual(output["new_users"], reversed_output["new_users"])
        self.assertEqual(output["new_users"][0]["reasons"], "rule_a; rule_b")
        self.assertEqual(len(output["all_users"]), 1)
        self.assertEqual(output["all_users"][0]["membership_kind"], "recorded")

    def test_registry_unavailable_is_unknown_and_provisional(self):
        output = report([member("8")], registry=False)
        self.assertIsNone(output["counts"]["prior_users"])
        self.assertIsNone(output["counts"]["all_users"])
        self.assertEqual(output["counts"]["new_users"], 1)
        self.assertIn("provisional", output["new_users"][0]["registry_diff_status"])
        self.assertEqual(output["status"], "PARTIAL")
        self.assertIn("unknown", monitor.summary_markdown(output))
        self.assertIn("unknown", monitor.report_html(output))

    def test_missing_kind_is_rejected_rather_than_inferred(self):
        with self.assertRaisesRegex(ValueError, "membership_kind"):
            report([row("MEMBER", user_id="1", first_qualified_at="2026-10-25T00:00:00Z")])

    def test_midnight_has_no_same_day_candidates(self):
        output = report([
            member("1", "recorded", "2026-10-26T04:59:59Z", "2026-10-26T04:00:00Z"),
            member("2", first="2026-10-26T05:00:00Z", evidence="2026-10-26T05:00:00Z"),
        ], as_of="2026-10-26 00:00")
        self.assertEqual(output["counts"]["prior_users"], 1)
        self.assertEqual(output["new_users"], [])


class HourlyTests(unittest.TestCase):
    def test_complete_empty_extraction_zero_fills_exactly_168_elapsed_hours(self):
        output = report()
        self.assertEqual(len(output["hourly"]), 168)
        self.assertTrue(all(r["hk_attempts"] == 0 for r in output["hourly"]))
        self.assertEqual(output["hourly"][0]["bucket_start"], "2026-10-19T17:30:00Z")
        self.assertEqual(output["hourly"][-1]["bucket_end"], "2026-10-26T17:30:00Z")

    def test_partial_missing_hours_remain_unknown(self):
        output = report([hourly("2026-10-26T16:30:00Z", value=3)], complete=False)
        self.assertIsNone(output["hourly"][0]["hk_attempts"])
        self.assertEqual(output["hourly"][-1]["hk_attempts"], 3)
        self.assertEqual(output["status"], "PARTIAL")

    def test_unknown_completion_is_never_filled_from_allow(self):
        output = report([hourly("2026-10-26T16:30:00Z", value=3, hk_successes=None)])
        self.assertEqual(output["hourly"][-1]["hk_allowed"], 3)
        self.assertIsNone(output["hourly"][-1]["hk_successes"])
        self.assertEqual(output["status"], "PARTIAL")

    def test_unaligned_conflicting_negative_and_overcounted_buckets_rejected(self):
        for data in (
            [hourly("2026-10-26T16:00:00Z")],
            [hourly("2026-10-26T16:30:00Z", 1), hourly("2026-10-26T16:30:00Z", 2)],
            [hourly("2026-10-26T16:30:00Z", -1)],
            [hourly("2026-10-26T16:30:00Z", 1, hk_successes=2)],
        ):
            with self.subTest(data=data), self.assertRaises(ValueError):
                report(data)

    def test_exact_duplicates_not_summed_and_future_bucket_excluded(self):
        data = [hourly("2026-10-26T16:30:00Z", 2)] * 2 + [hourly("2026-10-26T17:30:00Z", 100)]
        output = report(data)
        self.assertEqual(sum(r["hk_attempts"] for r in output["hourly"]), 2)

    def test_dst_transition_still_has_168_unique_offset_aware_columns(self):
        output = report(as_of="2026-11-02 12:30")
        labels = [r["hour_local"] for r in output["hourly"]]
        self.assertEqual(len(labels), 168)
        self.assertEqual(len(set(labels)), 168)
        self.assertIn("2026-11-01T01:30-05:00", labels)
        self.assertIn("2026-11-01T01:30-06:00", labels)


class IPAndRiskTests(unittest.TestCase):
    def test_event_country_alerts_override_ip_qualification_proxy(self):
        output = report([
            row('COVERAGE', key='campaign_activity_alerts_available', value=True),
            row('IP', ip='198.51.100.20', country='HK',
                first_seen='2026-10-26T07:00:00Z',
                first_qualified_at='2026-10-26T08:00:00Z'),
            row('ALERT', key='new_campaign_country', country='SG',
                first_seen='2026-10-26T09:00:00Z', accounts=2),
        ])
        self.assertEqual(output['new_countries'], ['SG'])
        self.assertFalse(any(a['kind']=='new_campaign_country' for a in output['alerts']))
        self.assertIn('New country in campaign activity: SG', output['alerts'][0]['message'])

    def test_sql_source_alerts_retain_event_level_evidence_without_ip_qualification(self):
        ip_payload = {"key": "new_campaign_ip", "ip": "192.0.2.9",
                      "first_seen": "2026-10-26T07:00:00Z", "attempts": 2, "successes": 1}
        country_payload = {"key": "new_campaign_country", "country": "SG",
                           "first_seen": "2026-10-26T07:00:00Z", "accounts": 1}
        output = report([
            row("IP", ip="192.0.2.9", country="SG", first_seen="2026-10-26T07:00:00Z",
                first_qualified_at=None),
            row("ALERT", **ip_payload), row("ALERT", **country_payload),
        ])
        self.assertEqual(output["new_ips"], [])
        self.assertEqual(output["new_countries"], [])
        source_alerts = [r for r in output["alerts"] if r["kind"] == "source_alert"]
        self.assertEqual([r["evidence"] for r in source_alerts], [ip_payload, country_payload])
        markdown = monitor.summary_markdown(output)
        rendered = monitor.report_html(output)
        for value in ("192.0.2.9", "SG", "2026-10-26T07:00:00Z"):
            self.assertIn(value, markdown)
            self.assertIn(value, rendered)
        with tempfile.TemporaryDirectory() as temp:
            monitor.write_report(output, temp)
            saved = json.loads((Path(temp) / "summary.json").read_text())
        self.assertEqual(saved["alerts"][1]["evidence"]["accounts"], 1)

    def test_ip_evidence_metadata_survives_json_and_csv_exports(self):
        output = report([row("IP", ip="192.0.2.1", country="HK", countries=["SG", "HK", "HK"],
                             campaign_first_known_at="2026-10-25T09:00:00+00:00",
                             first_qualified_at="2026-10-26T06:00:00Z", missing_geo=2,
                             country_variants=2, geo_observed_at="2026-10-26T08:00:00Z",
                             qualification_accounts=15, qualification_outlook_accounts=12,
                             qualification_outlook_share=0.8)])
        ip = output["ips"][0]
        self.assertEqual(ip["countries"], ["HK", "SG"])
        self.assertEqual(ip["campaign_first_known_at"], "2026-10-25T09:00:00Z")
        self.assertEqual(ip["missing_geo"], 2)
        self.assertEqual(ip["country_variants"], 2)
        self.assertEqual(ip["geo_observed_at"], "2026-10-26T08:00:00Z")
        self.assertEqual(ip["qualification_accounts"], 15)
        self.assertEqual(ip["qualification_outlook_accounts"], 12)
        self.assertEqual(ip["qualification_outlook_share"], 0.8)
        with tempfile.TemporaryDirectory() as temp:
            monitor.write_report(output, temp)
            with (Path(temp) / "ips.csv").open(newline="") as handle:
                exported = next(csv.DictReader(handle))
            saved = json.loads((Path(temp) / "summary.json").read_text())
        for field in ("countries", "campaign_first_known_at", "missing_geo", "country_variants", "geo_observed_at",
                      "qualification_accounts", "qualification_outlook_accounts", "qualification_outlook_share"):
            self.assertIn(field, exported)
            self.assertEqual(saved["ips"][0][field], ip[field])
        self.assertEqual(exported["missing_geo"], "2")

    def test_invalid_qualification_evidence_counts_and_share_rejected(self):
        for extra in ({"qualification_accounts": -1}, {"qualification_outlook_accounts": 1.5},
                      {"qualification_outlook_share": 1.1}, {"qualification_outlook_share": float("nan")}):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                report([row("IP", ip="192.0.2.1", **extra)])

    def test_risk_query_unavailable_or_unverified_marks_additions_partial(self):
        for availability in (False, None):
            data = [member("1")]
            if availability is not None:
                data.append(row("COVERAGE", key="risk_query_available", value=availability))
            with self.subTest(availability=availability):
                output = report(data)
                self.assertEqual(output["status"], "PARTIAL")
                self.assertTrue(any("Play Integrity/unlock query" in w for w in output["warnings"]))
        output = report([member("1"), row("COVERAGE", key="risk_query_available", value=True)])
        self.assertFalse(any("Play Integrity/unlock query" in w for w in output["warnings"]))
        no_additions = report()
        self.assertNotEqual(no_additions["status"], "PARTIAL")
        self.assertEqual(no_additions["risk_signals"][0]["status"], "NOT_APPLICABLE")

    def test_new_ip_and_country_compare_with_pre_day_baseline(self):
        data = [
            row("IP", ip="192.0.2.1", country="HK", first_qualified_at="2026-10-25T05:00:00Z"),
            row("IP", ip="192.0.2.2", country="SG", first_qualified_at="2026-10-26T06:00:00Z"),
            row("IP", ip="192.0.2.3", country=None, first_qualified_at="2026-10-26T07:00:00Z"),
            row("IP", ip="192.0.2.4", country="US", first_qualified_at="2026-10-26T17:30:00Z"),
        ]
        output = report(data)
        self.assertEqual([r["ip"] for r in output["new_ips"]], ["192.0.2.2", "192.0.2.3"])
        self.assertEqual(output["new_countries"], ["SG"])
        self.assertNotIn("US", output["new_countries"])
        self.assertEqual(output["ips"][-1]["country"], "UNKNOWN")

    def test_conflicting_ip_aggregates_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "Conflicting IP"):
            report([row("IP", ip="192.0.2.1", attempts=1), row("IP", ip="192.0.2.1", attempts=2)])

    def test_majority_uses_all_new_users_and_distinct_users(self):
        data = [member(i) for i in range(100)]
        data += [row("RISK", user_id=str(i), signal="play_integrity_unlock", risky=i < 6,
                     observed_at="2026-10-26T08:00:00Z") for i in range(8)]
        data += [data[-1], row("RISK", user_id="not-in-campaign", signal="play_integrity_unlock", risky=True,
                              observed_at="2026-10-26T08:00:00Z")]
        signal = report(data)["risk_signals"][0]
        self.assertEqual((signal["triggered_users"], signal["observable_users"], signal["new_users"]), (6, 8, 100))
        self.assertEqual(signal["share_of_observed_users"], 0.75)
        self.assertFalse(signal["majority_of_new_users"])
        self.assertEqual(signal["distinct_usable_events"], 8)

    def test_strict_majority_50_vs_51_percent_and_future_risk_excluded(self):
        members = [member(i) for i in range(100)]
        risk = [row("RISK", user_id=str(i), signal="play_integrity_unlock", risky=True,
                    observed_at="2026-10-26T09:00:00Z") for i in range(50)]
        self.assertFalse(report(members + risk)["risk_signals"][0]["majority_of_new_users"])
        at_cutoff = row("RISK", user_id="50", signal="play_integrity_unlock", risky=True, observed_at="2026-10-26T17:30:00Z")
        self.assertFalse(report(members + risk + [at_cutoff])["risk_signals"][0]["majority_of_new_users"])
        within = row("RISK", user_id="50", signal="play_integrity_unlock", risky=True, observed_at="2026-10-26T17:29:59Z")
        output = report(members + risk + [within])
        self.assertTrue(output["risk_signals"][0]["majority_of_new_users"])
        self.assertTrue(any(a["kind"] == "common_risky_signal" for a in output["alerts"]))

    def test_no_additions_not_applicable_missing_source_unavailable(self):
        output = report()
        self.assertEqual(output["risk_signals"][0]["status"], "NOT_APPLICABLE")
        self.assertIsNone(output["risk_signals"][0]["share_of_all_new_users"])
        output = report([member("1")])
        self.assertEqual(output["risk_signals"][0]["status"], "UNAVAILABLE")
        self.assertEqual(output["risk_signals"][0]["observable_users"], 0)
        self.assertFalse(output["risk_signals"][0]["majority_of_new_users"])

    def test_risk_window_relative_to_fresh_candidate_evidence_and_risk_does_not_add_users(self):
        data = [member("1", first="2026-08-01T00:00:00Z"),
                row("RISK", user_id="1", signal="play_integrity_unlock", risky=True, observed_at="2026-10-19T08:00:00Z"),
                row("RISK", user_id="2", signal="play_integrity_unlock", risky=True, observed_at="2026-10-26T08:00:00Z")]
        output = report(data)
        self.assertEqual(output["counts"]["new_users"], 1)
        self.assertEqual(output["risk_signals"][0]["triggered_users"], 1)

    def test_100_percent_provisional_risk_is_visible_but_cannot_alert(self):
        output = report([member("1"), member("2")] + [
            row("RISK", user_id=str(i), signal="play_integrity:app_access_controlling",
                risky=True, observed_at="2026-10-26T09:00:00Z",
                scope="unlock_association_provisional", majority_eligible=False,
                device_link="namespace_unvalidated", coverage="provisional")
            for i in (1, 2)
        ])
        signal = output["risk_signals"][0]
        self.assertEqual(signal["share_of_all_new_users"], 1.0)
        self.assertFalse(signal["majority_eligible"])
        self.assertFalse(signal["majority_of_new_users"])
        self.assertEqual(signal["device_links"], ["namespace_unvalidated"])
        self.assertEqual(signal["coverage_labels"], ["provisional"])
        self.assertFalse(any(a["kind"] == "common_risky_signal" for a in output["alerts"]))
        self.assertEqual(len(output["risk_signals"]), 1)  # standard prefix recognized

    def test_contradictory_scopes_never_merge(self):
        data = [member("1"),
                row("RISK", user_id="1", signal="play_integrity:app_access_controlling", risky=False,
                    observed_at="2026-10-26T09:00:00Z", scope="pi_independent", majority_eligible=True),
                row("RISK", user_id="1", signal="play_integrity:app_access_controlling", risky=True,
                    observed_at="2026-10-26T10:00:00Z", scope="unlock_association_provisional", majority_eligible=False)]
        output = report(data)
        self.assertEqual(len(output["risk_signals"]), 2)
        independent = next(r for r in output["risk_signals"] if r["scope"] == "pi_independent")
        provisional = next(r for r in output["risk_signals"] if r["scope"] == "unlock_association_provisional")
        self.assertEqual(independent["triggered_users"], 0)
        self.assertEqual(provisional["triggered_users"], 1)
        self.assertFalse(any(r["majority_of_new_users"] for r in output["risk_signals"]))

    def test_missing_majority_eligibility_cannot_alert(self):
        risk = row("RISK", user_id="1", signal="play_integrity:raw_label", risky=True,
                   observed_at="2026-10-26T09:00:00Z")
        risk["PAYLOAD"].pop("majority_eligible")
        output = report([member("1"), risk])
        self.assertFalse(output["risk_signals"][0]["majority_eligible"])
        self.assertFalse(output["risk_signals"][0]["majority_of_new_users"])

    def test_per_user_coverage_rollups_preserve_parse_errors_and_run_metadata(self):
        data = [member("1"), member("2"),
                row("COVERAGE", user_id="1", valid_pi_callbacks=2, invalid_json_callbacks=3,
                    http_error_or_unknown_callbacks=4, apps_detected_array_callbacks=2,
                    unlock_events=1, confirmed_unlock_pi_links=0, provisional_unlock_pi_links=1),
                row("COVERAGE", user_id="2", valid_pi_callbacks=0, invalid_json_callbacks=1,
                    http_error_or_unknown_callbacks=0, unlock_events=0),
                row("COVERAGE", user_id="not-a-new-user", invalid_json_callbacks=100),
                row("COVERAGE", scope="run", all_new_users=2, unlock_device_namespace_validated=False)]
        output = report(data)
        telemetry = output["telemetry_coverage"]
        self.assertEqual(telemetry["new_users_with_coverage_rows"], 2)
        self.assertEqual(telemetry["users_with_valid_pi_callbacks"], 1)
        self.assertEqual(telemetry["event_totals"]["invalid_json_callbacks"], 4)
        self.assertEqual(telemetry["event_totals"]["http_error_or_unknown_callbacks"], 4)
        self.assertEqual(telemetry["users_with_provisional_unlock_pi_links"], 1)
        self.assertEqual(telemetry["users_with_confirmed_unlock_pi_links"], 0)
        self.assertEqual(telemetry["run_metadata"][0]["scope"], "run")
        self.assertIn('"invalid_json_callbacks": 4', monitor.summary_markdown(output))

    def test_conflicting_per_user_coverage_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Conflicting per-user COVERAGE"):
            report([member("1"), row("COVERAGE", user_id="1", valid_pi_callbacks=1),
                    row("COVERAGE", user_id="1", valid_pi_callbacks=2)])


class OutputTests(unittest.TestCase):
    def test_all_required_files_and_168_hour_csv_columns(self):
        output = report([member("1"), row("IP", ip="192.0.2.1", country="HK")])
        with tempfile.TemporaryDirectory() as temp:
            artifact = monitor.write_report(output, temp)
            directory = Path(temp)
            self.assertTrue(artifact.is_file())
            expected = {"report.html", "summary.md", "summary.json", "prior_users.csv", "new_users.csv", "recorded_today.csv", "all_users.csv", "ips.csv", "hourly.csv", "hourly_168_columns.csv", "risk_signals.csv", "telemetry_coverage.csv"}
            self.assertEqual({p.name for p in directory.iterdir()}, expected)
            with (directory / "hourly.csv").open(newline="") as handle:
                self.assertEqual(len(list(csv.DictReader(handle))), 168)
            with (directory / "hourly_168_columns.csv").open(newline="") as handle:
                wide = list(csv.reader(handle))
            self.assertEqual(len(wide[0]) - 1, 168)
            self.assertTrue(all(len(r) == 169 for r in wide))
            self.assertEqual(json.loads((directory / "summary.json").read_text())["counts"]["new_users"], 1)

    def test_html_escapes_untrusted_payload_and_stays_offline(self):
        output = report([member("1", reasons=['</script><img src=x onerror="evil()">'])])
        rendered = monitor.report_html(output)
        self.assertNotIn('</script><img src=x onerror="evil()">', rendered)
        self.assertNotIn("https://", rendered)
        self.assertIn("&lt;/script&gt;", rendered)
        self.assertIn('id="chart"', rendered)


if __name__ == "__main__":
    unittest.main()

"""Synthetic tests; no database, network, or private export is required."""
import hashlib
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))

import dashboard_adapter as adapter


def generated_export(hk_sql=None, app_sql=None):
    header = ("schemaVersion: 3\nmeta:\n"
              f"  sourceVersionId: 00000000-0000-0000-0000-000000000001 # generated\n"
              f"  projectId: {adapter.PROJECT_ID} # generated\ncells:\n")
    cells = []
    for key, sql in (("hk", hk_sql or HK_SQL), ("app_web", app_sql or APP_WEB_SQL)):
        cid, label = adapter.EXPECTED_CELLS[key]
        cells.append(f"  - cellType: SQL\n    cellId: {cid} # generated\n    cellLabel: {label}\n    config:\n      source: |-\n"
                     + "".join("        " + line + "\n" for line in sql.splitlines())
                     + "      dataFrameCell: false\n")
    return header + "".join(cells) + "appLayout:\n  blocks: []\n"


class DashboardAdapterTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="dashboard-adapter-")
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "dashboard.hex.yaml"
        self.cutoff = datetime(2026, 10, 26, 18, 17, tzinfo=timezone.utc)
        self.chart_start = self.cutoff - timedelta(hours=168)

    def load(self, text=None):
        self.path.write_text(text or generated_export())
        return adapter.load_dashboard_source(self.path)

    def test_extracts_literal_cells_and_provenance_without_private_seed_metadata(self):
        source = self.load()
        self.assertEqual(source.known_ips, ("192.0.2.1", "198.51.100.2"))
        self.assertEqual(source.metadata["export_sha256"], hashlib.sha256(self.path.read_bytes()).hexdigest())
        self.assertEqual(source.metadata["source_version_id"], "00000000-0000-0000-0000-000000000001")
        self.assertEqual(source.metadata["success_semantics"], "dashboard_policy_allowed")
        self.assertNotIn("192.0.2.1", repr(source.metadata))
        self.assertEqual(set(source.metadata["source_cells"]), {"hk", "app_web"})

    def test_rejects_changed_schema_project_identity_label_or_source_structure(self):
        text = generated_export()
        variants = [
            text.replace("schemaVersion: 3", "schemaVersion: 4"),
            text.replace(adapter.PROJECT_ID, "00000000-0000-0000-0000-000000000002"),
            text.replace(adapter.EXPECTED_CELLS["hk"][0], "00000000-0000-0000-0000-000000000003"),
            text.replace("cellLabel: Hong Kong clicks by hour", "cellLabel: Changed dashboard"),
            text.replace("source: |-", "source: >-", 1),
            text.replace("  - cellType: SQL", "  - cellType: PYTHON", 1),
            text.replace("schemaVersion: 3", "schemaVersion: 3\nschemaVersion: 3"),
        ]
        for variant in variants:
            with self.subTest(variant=variant[:120]), self.assertRaises(ValueError):
                self.load(variant)

    def test_filter_changes_fail_closed_but_runtime_seed_updates_are_supported(self):
        with self.assertRaisesRegex(ValueError, "SQL changed"):
            self.load(generated_export(hk_sql=HK_SQL.replace("and pii_type = 'email'", "and pii_type = 'phone'", 1)))
        text = generated_export().replace("192.0.2.1", "203.0.113.9")
        self.assertIn("203.0.113.9", self.load(text).known_ips)

    def test_seed_values_must_be_distinct_valid_literal_ips_and_agree_between_cells(self):
        variants = [
            HK_SQL.replace("192.0.2.1", "999.0.0.1"),
            HK_SQL.replace("198.51.100.2", "192.0.2.1"),
            HK_SQL.replace("('192.0.2.1')", "(CURRENT_USER())"),
            HK_SQL.replace("192.0.2.1", "203.0.113.9"),
        ]
        for sql in variants:
            with self.subTest(sql=sql[:80]), self.assertRaises(ValueError):
                self.load(generated_export(hk_sql=sql))

    def test_duplicate_and_missing_required_cells_are_rejected(self):
        text = generated_export()
        hk_block = text[text.index("  - cellType: SQL"):text.index("  - cellType: SQL", text.index("  - cellType: SQL") + 1)]
        with self.assertRaises(ValueError):
            self.load(text.replace("appLayout:", hk_block + "appLayout:"))
        with self.assertRaises(ValueError):
            self.load(text.replace(hk_block, ""))

    def test_adapts_exclusive_cutoff_and_utc_minute_bins_preserving_source_filters(self):
        source = self.load()
        hk, app = adapter.adapt_dashboard_sql(source, self.cutoff, self.chart_start)
        end = "TO_TIMESTAMP_TZ('2026-10-26T18:17:00Z')"
        chart = "TO_TIMESTAMP_TZ('2026-10-19T18:17:00Z')"
        self.assertNotIn("current_timestamp()", hk + app)
        self.assertNotIn("convert_timezone(", hk + app)
        self.assertIn("original_timestamp < " + end, hk)
        self.assertIn("_creation_timestamp < " + end, app)
        self.assertIn("dateadd('day', -60, " + end + ")", hk)
        self.assertIn("dateadd('day', -15, dateadd('day', -60, " + end + "))", hk)
        self.assertIn("dateadd('day', -15, dateadd('day', -14, " + end + "))", app)
        self.assertIn("DATEDIFF('second', " + chart + ", k.ts)", hk)
        self.assertIn("g.country = 'HK' or k.ip in (select ip from known_ips)", hk)
        self.assertIn("mode(geo_ip_data_country)", hk)
        self.assertIn("original_timestamp >= '2026-07-01'::timestamp_tz", hk)
        self.assertIn("count_if(is_hk and outcome = 'allow') hk_successes", hk)
        self.assertIn("partition by user_id, new_email order by ts", app)
        self.assertIn("i.user_id = v.user_id", app)
        self.assertIn("i.new_email = v.new_email", app)
        self.assertIn("i.ts between dateadd('minute', -35, v.ts) and v.ts", app)
        self.assertIn("evaluation_target::string = 'general'", app)
        self.assertIn("h.hr bucket_start", hk)
        self.assertIn("hr bucket_start", app)

    def test_main_query_wraps_all_metrics_and_keeps_supplemental_membership_explicit(self):
        source = self.load()
        sql = adapter.build_main_sql(source, self.cutoff, self.cutoff.replace(hour=5, minute=0),
                                     self.chart_start, datetime(2026, 7, 1, tzinfo=timezone.utc))
        for metric in ("hk_attempts", "hk_successes", "hk_allowed", "bad_device_attempts",
                       "bad_device_successes", "bad_device_allowed", "app_to_web_attempts",
                       "app_to_web_successes", "app_to_web_allowed"):
            self.assertIn("'" + metric + "'", sql)
        self.assertIn("GENERATOR(ROWCOUNT=>168)", sql)
        self.assertIn("'hk_allowed',COALESCE(h.hk_successes,0)", sql)
        self.assertIn("'app_to_web_allowed',COALESCE(a.app_to_web_success,0)", sql)
        self.assertIn("'COHORT_USER'", sql)
        self.assertIn("first_recorded_at IS NULL OR first_recorded_at>=", sql)
        self.assertIn("outcome='allow' AND campaign_linked", sql)
        self.assertIn("LOWER(resource_type)='user'", sql)
        self.assertIn("'persisted_successes',NULL", sql)
        self.assertIn("'success_semantics','value','dashboard_policy_allowed'", sql)
        self.assertNotIn("15 AND", sql)
        self.assertNotIn("outlook.com", sql)
        self.assertNotIn("versions_pivot", sql)
        # CTE references must follow their definitions in Snowflake.
        self.assertLess(sql.index("dashboard_known_ips AS ("), sql.index("classified_history AS ("))
        self.assertLess(sql.index("supplemental_geo AS ("), sql.index("classified_history AS ("))

    def test_bounds_require_aware_minute_precision_and_exactly_168_elapsed_hours(self):
        source = self.load()
        cases = [
            (self.cutoff.replace(tzinfo=None), self.chart_start),
            (self.cutoff, self.chart_start + timedelta(minutes=1)),
            (self.cutoff + timedelta(seconds=1), self.chart_start + timedelta(seconds=1)),
        ]
        for cutoff, chart_start in cases:
            with self.subTest(cutoff=cutoff), self.assertRaises(ValueError):
                adapter.adapt_dashboard_sql(source, cutoff, chart_start)

    def test_standalone_cohort_select_matches_main_membership_rules_and_private_runtime_seeds(self):
        source = self.load()
        history = datetime(2026, 7, 1, tzinfo=timezone.utc)
        sql = adapter.build_cohort_user_sql(source, self.cutoff, history)
        bad_dev = sql.split(", bad_dev AS (", 1)[1].split("), registry AS (", 1)[0]
        linked = sql.split("linked_users AS (", 1)[1]
        self.assertIn("('192.0.2.1'),('198.51.100.2')", sql)
        self.assertIn("original_timestamp >= '2026-07-01'::timestamp_tz", bad_dev)
        self.assertNotIn("pii_type", bad_dev)
        self.assertNotIn("decision_outcome", bad_dev)
        self.assertIn("device_ip_address in (select ip from known_ips)", bad_dev)
        self.assertIn("original_timestamp < TO_TIMESTAMP_TZ('2026-10-26T18:17:00Z')", bad_dev)
        self.assertIn("AND NOT is_shadow_mode", linked)
        self.assertIn("pii_type='email'", linked)
        self.assertIn("decision_outcome='allow'", linked)
        self.assertIn("OR device_id IN (SELECT dev FROM bad_dev)", linked)
        self.assertIn("LOWER(resource_type)='user'", sql)
        self.assertIn("SELECT user_id FROM registry\nUNION\nSELECT user_id FROM linked_users", sql)
        self.assertNotIn("COHORT_USER", sql)
        self.assertNotIn("current_timestamp()", sql)
        with self.assertRaises(ValueError):
            adapter.build_cohort_user_sql(source, self.cutoff, self.cutoff)

    def test_provider_metadata_is_supplemental_and_primary_queries_remain_exact(self):
        source = self.load()
        hk, app = adapter.adapt_dashboard_sql(source, self.cutoff, self.chart_start)
        sql = adapter.build_main_sql(source, self.cutoff, self.cutoff.replace(hour=5, minute=0),
                                     self.chart_start, datetime(2026, 7, 1, tzinfo=timezone.utc))
        self.assertNotIn("connection_data_isp", hk + app)
        self.assertIn(hk.rstrip(), sql)
        self.assertIn(app.rstrip(), sql)
        self.assertIn("MODE(connection_data_isp) isp", sql)
        self.assertIn("MODE(isp) isp", sql)
        self.assertIn("'isp',isp", sql)


if __name__ == "__main__":
    unittest.main()

HK_SQL = "-- HK email monitor: Hong Kong clicks, known bad browsers and in-app requests by Pacific hour, rolling 60 days.\n-- hk_*: email-change confirmation clicks from an IP in Hong Kong or one of the campaign's known HK IPs (successes = allowed).\n-- hk_new_ip_*: the same from HK IPs not on the known list. baddev_*: clicks from any browser that has confirmed an email\n-- change from the known HK IPs since Jul 1; baddev_non_hk_* = those browsers clicking from outside Hong Kong.\n-- app_req: live in-app email-change requests. all_web_clicks: every live confirmation click.\nwith known_ips as (\n  select column1 ip from values ('192.0.2.1'),('198.51.100.2')\n),\nclk as (\n  select try_to_number(user_id) user_id, original_timestamp ts, device_ip_address ip, device_id dev, decision_outcome outcome\n  from chime.decision_platform.user_service\n  where original_timestamp >= dateadd('day', -60, date_trunc('hour', current_timestamp())) and original_timestamp < date_trunc('hour', current_timestamp()) and not is_shadow_mode\n    and pii_type = 'email' and update_context = 'email_verification_email_change'\n),\nreq as (   -- live in-app requests, counted once per decision\n  select original_timestamp ts, decision_id\n  from chime.decision_platform.user_service\n  where original_timestamp >= dateadd('day', -60, date_trunc('hour', current_timestamp())) and original_timestamp < date_trunc('hour', current_timestamp()) and not is_shadow_mode\n    and pii_type = 'email' and update_context = 'in_app_email_verification_check'\n),\nbad_dev as (\n  select distinct device_id dev\n  from chime.decision_platform.user_service\n  where original_timestamp >= '2026-07-01'::timestamp_tz and original_timestamp < date_trunc('hour', current_timestamp()) and not is_shadow_mode\n    and update_context = 'email_verification_email_change' and device_id is not null\n    and device_ip_address in (select ip from known_ips)\n),\ngeo as (\n  select connection_data_ip_address ip, mode(geo_ip_data_country) country, mode(connection_data_connection_type) ctype\n  from chime.decision_platform.device_intelligence\n  where original_timestamp >= dateadd('day', -15, dateadd('day', -60, date_trunc('hour', current_timestamp()))) and original_timestamp < date_trunc('hour', current_timestamp())\n    and connection_data_ip_address in (select ip from clk)\n  group by 1\n),\nc as (\n  select k.*, date_trunc('hour', convert_timezone('America/Los_Angeles', k.ts))::timestamp_ntz hr,\n    (g.country = 'HK' or k.ip in (select ip from known_ips)) is_hk,\n    (g.country = 'HK' and k.ip not in (select ip from known_ips)) is_hk_new_ip,\n    (k.dev in (select dev from bad_dev)) is_bad_dev,\n    (g.country is not null and g.country <> 'US') is_foreign,\n    (g.ctype = 'Data Center') is_dc\n  from clk k left join geo g on g.ip = k.ip\n),\nhc as (\n  select hr,\n    count_if(is_hk) hk_attempts, count_if(is_hk and outcome = 'allow') hk_successes, count(distinct iff(is_hk, user_id, null)) hk_accounts,\n    count_if(is_hk_new_ip) hk_new_ip_attempts, count_if(is_hk_new_ip and outcome = 'allow') hk_new_ip_successes,\n    count_if(is_bad_dev) baddev_attempts, count_if(is_bad_dev and outcome = 'allow') baddev_successes,\n    count_if(is_bad_dev and not is_hk) baddev_non_hk_attempts, count_if(is_bad_dev and not is_hk and outcome = 'allow') baddev_non_hk_successes,\n    count(*) all_web_clicks\n  from c group by hr\n),\nhreq as (\n  select date_trunc('hour', convert_timezone('America/Los_Angeles', ts))::timestamp_ntz hr, count(distinct decision_id) app_req\n  from req group by 1\n),\nhrs as (select hr from hc union select hr from hreq)\nselect to_char(h.hr, 'YYYY-MM-DD HH24:MI:SS') hour_pt,  -- Pacific hour as text so every tool reads it the same way\n \n  coalesce(hk_attempts, 0) hk_attempts, coalesce(hk_successes, 0) hk_successes, coalesce(hk_accounts, 0) hk_accounts,\n  coalesce(hk_new_ip_attempts, 0) hk_new_ip_attempts, coalesce(hk_new_ip_successes, 0) hk_new_ip_successes,\n  coalesce(baddev_attempts, 0) baddev_attempts, coalesce(baddev_successes, 0) baddev_successes,\n  coalesce(baddev_non_hk_attempts, 0) baddev_non_hk_attempts, coalesce(baddev_non_hk_successes, 0) baddev_non_hk_successes,\n  coalesce(app_req, 0) app_req, coalesce(all_web_clicks, 0) all_web_clicks\nfrom hrs h left join hc on hc.hr = h.hr left join hreq on hreq.hr = h.hr\norder by 1\n"
APP_WEB_SQL = "-- HK email monitor: email changes started in the app and finished on the web, by Pacific hour of the web click, rolling 14 days.\n-- Counted once per requested email: the first web click on that email's link, matched to an in-app request for the\n-- same email in the 35 minutes before. Live decisions only (evaluation_target = 'general').\n-- app_to_web_success = went through; _foreign / _datacenter / _hk = where the web click came from.\nwith known_ips as (\n  select column1 ip from values ('192.0.2.1'),('198.51.100.2')\n),\ndlg as (   -- both steps from the live decision log, which carries the requested email\n  select _creation_timestamp ts, user_id,\n    request:user_update:update_context::string ctx,\n    decision:outcome:outcome::string outcome,\n    lower(request:user_update:user_changes:email::string) new_email,\n    request:user_update:device:device_ip_address::string ip\n  from streaming_platform.segment_and_hawker_production.realtimedecisioning_v1_risk_decision_log\n  where _creation_timestamp >= dateadd('minute', -35, dateadd('day', -14, date_trunc('hour', current_timestamp()))) and _creation_timestamp < date_trunc('hour', current_timestamp())\n    and event_name = 'user_update'\n    and request:user_update:update_context::string in ('in_app_email_verification_check', 'email_verification_email_change')\n    and request:decision_context:evaluation_target::string = 'general'\n),\nver as (   -- first web click per member and requested email\n  select * from dlg where ctx = 'email_verification_email_change'\n  qualify row_number() over (partition by user_id, new_email order by ts) = 1\n),\npair as (  -- ... that has an in-app request for the same email in the 35 minutes before\n  select v.ts, v.ip, v.outcome, date_trunc('hour', convert_timezone('America/Los_Angeles', v.ts))::timestamp_ntz hr\n  from ver v\n  where v.ts >= dateadd('day', -14, date_trunc('hour', current_timestamp()))\n    and exists (select 1 from dlg i where i.ctx = 'in_app_email_verification_check' and i.user_id = v.user_id\n                and i.new_email = v.new_email and i.ts between dateadd('minute', -35, v.ts) and v.ts)\n),\ngeo as (\n  select connection_data_ip_address ip, mode(geo_ip_data_country) country, mode(connection_data_connection_type) ctype\n  from chime.decision_platform.device_intelligence\n  where original_timestamp >= dateadd('day', -15, dateadd('day', -14, date_trunc('hour', current_timestamp()))) and original_timestamp < date_trunc('hour', current_timestamp())\n    and connection_data_ip_address in (select ip from pair)\n  group by 1\n),\nhp as (\n  select p.hr, count(*) app_to_web, count_if(p.outcome = 'allow') app_to_web_success,\n    count_if(g.country is not null and g.country <> 'US') app_to_web_foreign,\n    count_if(g.ctype = 'Data Center') app_to_web_datacenter,\n    count_if(g.country = 'HK' or p.ip in (select ip from known_ips)) app_to_web_hk\n  from pair p left join geo g on g.ip = p.ip\n  group by 1\n)\nselect to_char(hr, 'YYYY-MM-DD HH24:MI:SS') hour_pt,  -- Pacific hour as text\n  app_to_web, app_to_web_success, app_to_web_foreign, app_to_web_datacenter, app_to_web_hk\nfrom hp\norder by 1\n"

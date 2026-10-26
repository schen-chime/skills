"""Adapt the two approved Hex dashboard SQL cells without changing their rules.

The generated Hex YAML is deliberately parsed as a narrow, fail-closed export
format, not as arbitrary YAML. Private infrastructure values are read only from
the runtime export; this module contains no campaign IP list.
"""
import hashlib
import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path


PROJECT_ID = "01a17982-c6c9-7161-8f2a-92113bceb68a"
EXPECTED_CELLS = {
    "hk": ("01a17982-c9b5-748a-8dd9-dae8392ca323", "Hong Kong clicks by hour"),
    "app_web": ("01a17982-ce74-72d5-b056-4b9e5de775d9", "App email changes finished on the web by hour"),
}
# Fingerprints exclude only the runtime VALUES block. Any other source change
# needs an explicit adapter review; changing a version ID alone is insufficient.
APPROVED_SQL_SHA256 = {
    "hk": "6cc30ae265e9b3597c34721a11211c7fad94e089d0efeaad10bac3c02b5f60f7",
    "app_web": "9b0fbc0c50809f05b6e16914eb9cbfcc3d871fd190a331434156a1057ee212b5",
}
UUID = r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}"
KNOWN_IPS = re.compile(
    r"(?P<prefix>with known_ips as \(\s*select column1 ip from values )"
    r"(?P<values>[^\n]+)(?P<suffix>\s*\),)", re.IGNORECASE)


def _sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _one(pattern, text, name):
    matches = re.findall(pattern, text, re.MULTILINE)
    if len(matches) != 1:
        raise ValueError(f"Expected exactly one {name} in generated Hex YAML")
    return matches[0]


def _known_ips(sql):
    matches = list(KNOWN_IPS.finditer(sql))
    if len(matches) != 1:
        raise ValueError("Expected one literal known_ips VALUES block")
    block = matches[0].group("values").strip()
    tokens = re.findall(r"\('([^']+)'\)", block)
    if not tokens or re.sub(r"\('([^']+)'\)", "", block).replace(",", "").strip():
        raise ValueError("known_ips must contain only single-column literal IP tuples")
    try:
        addresses = tuple(str(ipaddress.ip_address(value)) for value in tokens)
    except ValueError as exc:
        raise ValueError("known_ips contains an invalid IP literal") from exc
    if tuple(tokens) != addresses or len(set(addresses)) != len(addresses):
        raise ValueError("known_ips must contain distinct canonical IP literals")
    normalized = sql[:matches[0].start("values")] + "{{PRIVATE_KNOWN_IP_VALUES}}" + sql[matches[0].end("values"):]
    return addresses, normalized


@dataclass(frozen=True)
class DashboardSource:
    hk_sql: str
    app_web_sql: str
    known_ips: tuple
    metadata: dict


def load_dashboard_source(path):
    """Load a private Hex export and verify the reviewed SQL cell contracts."""
    raw = Path(path).read_bytes()
    text = raw.decode("utf-8")
    if "\t" in text or "\r" in text:
        raise ValueError("Unsupported generated Hex YAML whitespace")
    if _one(r"^schemaVersion: (\d+)$", text, "schemaVersion") != "3":
        raise ValueError("Only generatedHexYAML schemaVersion 3 is supported")
    project_id = _one(rf"^  projectId: ({UUID})(?: #.*)?$", text, "projectId")
    version_id = _one(rf"^  sourceVersionId: ({UUID})(?: #.*)?$", text, "sourceVersionId")
    if project_id != PROJECT_ID:
        raise ValueError("Hex export belongs to a different project")
    cells_section = _one(r"^cells:\n((?:[ \n].*\n?)*)", text, "cells section")
    starts = list(re.finditer(r"^  - cellType: ([A-Z_]+)$", cells_section, re.MULTILINE))
    selected = {}
    seen_ids, seen_labels = set(), set()
    for index, start in enumerate(starts):
        block = cells_section[start.start():starts[index + 1].start() if index + 1 < len(starts) else len(cells_section)]
        ids = re.findall(rf"^    cellId: ({UUID})(?: #.*)?$", block, re.MULTILINE)
        if len(ids) != 1:
            raise ValueError("Each generated cell requires one literal cellId")
        labels = re.findall(r"^    cellLabel: (.*)$", block, re.MULTILINE)
        label = labels[0] if len(labels) == 1 else None
        if ids[0] in seen_ids:
            raise ValueError("Duplicate Hex cellId")
        seen_ids.add(ids[0])
        for key, (expected_id, expected_label) in EXPECTED_CELLS.items():
            if ids[0] != expected_id and label != expected_label:
                continue
            if key in selected or ids[0] != expected_id or label != expected_label or start.group(1) != "SQL":
                raise ValueError("Dashboard SQL cell identity, label, or type changed")
            if label in seen_labels:
                raise ValueError("Duplicate dashboard SQL label")
            seen_labels.add(label)
            # Generated source is exactly an indented literal scalar. Do not
            # interpret folded scalars, anchors, aliases, tags, or escaped YAML.
            source = _one(r"^      source: \|-\n((?:        .*\n|\n)*)", block, f"literal source for {key}")
            if len(re.findall(r"^      source:", block, re.MULTILINE)) != 1 or not source:
                raise ValueError("Unsupported or duplicate source scalar")
            sql = "\n".join(line[8:] if line.startswith("        ") else "" for line in source.splitlines()).rstrip() + "\n"
            addresses, normalized = _known_ips(sql)
            if _sha(normalized) != APPROVED_SQL_SHA256[key]:
                raise ValueError(f"Dashboard {key} SQL changed; review its logic before updating the adapter")
            selected[key] = (sql, addresses, normalized)
    if set(selected) != set(EXPECTED_CELLS):
        raise ValueError("Required dashboard SQL cells are missing")
    if selected["hk"][1] != selected["app_web"][1]:
        raise ValueError("Dashboard SQL cells disagree on known_ips")
    metadata = {
        "project_id": project_id, "source_version_id": version_id,
        "export_sha256": hashlib.sha256(raw).hexdigest(), "schema_version": 3,
        "source_cells": {
            key: {"cell_id": EXPECTED_CELLS[key][0], "cell_label": EXPECTED_CELLS[key][1],
                  "sql_sha256": _sha(item[0]), "rule_sha256": _sha(item[2])}
            for key, item in selected.items()
        },
        "known_ip_count": len(selected["hk"][1]),
        "authority": "published Hex dashboard export; source filters preserved",
        "success_semantics": "dashboard_policy_allowed",
        "historical_warehouse_availability_verified": False,
    }
    return DashboardSource(selected["hk"][0], selected["app_web"][0], selected["hk"][1], metadata)


def _replace_once(text, old, new, label):
    if text.count(old) != 1:
        raise ValueError(f"Dashboard adapter expected exactly one {label}")
    return text.replace(old, new, 1)


def _instant(value):
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Dashboard bounds must be timezone-aware datetimes")
    return value.astimezone(timezone.utc)


def _literal(value):
    return "TO_TIMESTAMP_TZ('" + _instant(value).isoformat().replace("+00:00", "Z") + "')"


def adapt_dashboard_sql(source, cutoff, chart_start):
    """Return the original two queries with only cutoff and hourly bins adapted."""
    cutoff = _instant(cutoff)
    chart_start = _instant(chart_start)
    if cutoff - chart_start != timedelta(hours=168):
        raise ValueError("The dashboard export requires exactly 168 elapsed-hour bins")
    if cutoff.second or cutoff.microsecond:
        raise ValueError("Cutoff must have minute precision")
    end, beginning = _literal(cutoff), _literal(chart_start)

    def bins(column):
        return f"DATEADD('hour', FLOOR(DATEDIFF('second', {beginning}, {column})/3600), {beginning})"

    hk = source.hk_sql.replace("date_trunc('hour', current_timestamp())", end)
    app = source.app_web_sql.replace("date_trunc('hour', current_timestamp())", end)
    hk = _replace_once(hk, "date_trunc('hour', convert_timezone('America/Los_Angeles', k.ts))::timestamp_ntz", bins("k.ts"), "HK UTC bin")
    hk = _replace_once(hk, "date_trunc('hour', convert_timezone('America/Los_Angeles', ts))::timestamp_ntz", bins("ts"), "request UTC bin")
    app = _replace_once(app, "date_trunc('hour', convert_timezone('America/Los_Angeles', v.ts))::timestamp_ntz", bins("v.ts"), "app/web UTC bin")
    hk = _replace_once(hk, "to_char(h.hr, 'YYYY-MM-DD HH24:MI:SS') hour_pt", "h.hr bucket_start", "HK output timestamp")
    app = _replace_once(app, "to_char(hr, 'YYYY-MM-DD HH24:MI:SS') hour_pt", "hr bucket_start", "app/web output timestamp")
    if "current_timestamp()" in hk + app or "convert_timezone(" in hk + app:
        raise ValueError("Unsupported remaining dynamic timestamp or timezone conversion")
    return hk, app


def build_cohort_user_sql(source, cutoff, history_start):
    """Return a pure SQL SELECT of the main report's campaign cohort user IDs.

    This is a source-derived membership query, not a cached result list. Its
    whole-window browser set intentionally follows the dashboard exactly.
    """
    cutoff, history_start = map(_instant, (cutoff, history_start))
    if history_start >= cutoff:
        raise ValueError("Cohort history must begin before the exclusive cutoff")
    end, history = _literal(cutoff), _literal(history_start)
    matches = list(re.finditer(r"^bad_dev as \(\n(?P<body>.*?)^\),\ngeo as \(", source.hk_sql,
                               re.MULTILINE | re.DOTALL))
    if len(matches) != 1:
        raise ValueError("Dashboard bad_dev CTE structure changed")
    bad_device_body = matches[0].group("body").replace("date_trunc('hour', current_timestamp())", end)
    if "current_timestamp()" in bad_device_body:
        raise ValueError("Unadapted dynamic timestamp in dashboard bad_dev")
    values = ",".join("('" + ip + "')" for ip in source.known_ips)
    return f"""WITH known_ips AS (
  SELECT column1::STRING ip FROM VALUES {values}
), bad_dev AS (
{bad_device_body.rstrip()}
), registry AS (
  SELECT DISTINCT TRY_TO_NUMBER(resource_id) user_id
  FROM postgres_db.penny.notes
  WHERE created_at < {end} AND content ILIKE '%gambling_app_compromise%'
    AND LOWER(resource_type)='user' AND TRY_TO_NUMBER(resource_id)>0
), linked_users AS (
  SELECT DISTINCT TRY_TO_NUMBER(user_id) user_id
  FROM chime.decision_platform.user_service
  WHERE original_timestamp >= {history} AND original_timestamp < {end} AND NOT is_shadow_mode
    AND pii_type='email' AND update_context='email_verification_email_change'
    AND decision_outcome='allow' AND TRY_TO_NUMBER(user_id)>0
    AND (device_ip_address IN (SELECT ip FROM known_ips) OR device_id IN (SELECT dev FROM bad_dev))
)
SELECT user_id FROM registry
UNION
SELECT user_id FROM linked_users
"""


def build_main_sql(source, cutoff, day_start, chart_start, history_start):
    """Build one read-only result set: dashboard hours, members, IPs and coverage.

    Supplemental membership is explicitly a review proposal: an allowed click
    on a dashboard known IP or dashboard bad browser. This does not broaden the
    dashboard hourly definitions or infer a persisted email transition.
    """
    cutoff, day_start, chart_start, history_start = map(_instant, (cutoff, day_start, chart_start, history_start))
    if not history_start <= chart_start < cutoff or not history_start <= day_start <= cutoff:
        raise ValueError("Invalid dashboard history/day/chart bounds")
    hk, app = adapt_dashboard_sql(source, cutoff, chart_start)
    end, day, beginning, history = map(_literal, (cutoff, day_start, chart_start, history_start))
    # Reuse reviewed source CTEs for supplemental history. The two authoritative
    # hourly queries above retain their original 60-day/14-day source horizons.
    before_hc = hk.split("hc as (", 1)
    if len(before_hc) != 2:
        raise ValueError("Dashboard HK CTE structure changed")
    clk_part, req_part = before_hc[0].split("req as (", 1)
    history_ctes = _replace_once(clk_part, f"original_timestamp >= dateadd('day', -60, {end})", f"original_timestamp >= {history}", "supplemental history start") + "req as (" + req_part
    return _assemble(source, hk, app, history_ctes, end, day, beginning, history)


def _assemble(source, hk, app, history_ctes, end, day, beginning, history):
    # history_ctes ends in a comma, ready for a supplemental SELECT CTE.
    return f"""-- Read-only adaptation of Hex {source.metadata['project_id']} version {source.metadata['source_version_id']}.
-- Dashboard successes are policy allows; historical MODE geography and whole-window bad browsers are intentional.
WITH dashboard_hk AS (
{hk.rstrip()}
), dashboard_app_web AS (
{app.rstrip()}
), history_events AS (
{history_ctes.rstrip()}
selected_history AS (SELECT * FROM c)
SELECT * FROM selected_history
), registry AS (
  SELECT TRY_TO_NUMBER(resource_id) user_id, MIN(created_at) first_recorded_at
  FROM postgres_db.penny.notes
  WHERE created_at < {end} AND content ILIKE '%gambling_app_compromise%'
    AND LOWER(resource_type)='user' AND TRY_TO_NUMBER(resource_id)>0 GROUP BY 1
), dashboard_known_ips AS (
  SELECT column1::STRING ip FROM VALUES {','.join("('" + ip + "')" for ip in source.known_ips)}
), supplemental_geo AS (
  SELECT connection_data_ip_address ip, MODE(geo_ip_data_country) country,
    MODE(connection_data_connection_type) ctype,MODE(connection_data_isp) isp
  FROM chime.decision_platform.device_intelligence
  WHERE original_timestamp>=DATEADD('day',-15,DATEADD('day',-60,{end})) AND original_timestamp<{end}
    AND connection_data_ip_address IN (SELECT ip FROM history_events) GROUP BY 1
), classified_history AS (
  SELECT e.*,r.first_recorded_at,
    (e.ip IN (SELECT ip FROM dashboard_known_ips) OR e.is_bad_dev) campaign_linked,
    g.country,g.ctype,g.isp
  FROM history_events e LEFT JOIN registry r ON r.user_id=e.user_id
  LEFT JOIN supplemental_geo g ON g.ip=e.ip
), candidates AS (
  SELECT user_id,MIN(ts) first_qualified_at,MIN(ts) evidence_event_at,
    ARRAY_AGG(DISTINCT IFF(ip IN (SELECT ip FROM dashboard_known_ips),
      'dashboard_allowed_on_known_ip','dashboard_allowed_on_whole_window_bad_browser')) reasons
  FROM classified_history
  WHERE ts>={day} AND ts<{end} AND outcome='allow' AND campaign_linked AND user_id>0
    AND (first_recorded_at IS NULL OR first_recorded_at>={day}) GROUP BY 1
), cohort AS (
  SELECT user_id,MIN(first_qualified_at) first_qualified_at
  FROM (
    SELECT user_id,first_recorded_at first_qualified_at FROM registry
    UNION ALL SELECT user_id,MIN(ts) FROM classified_history
      WHERE outcome='allow' AND campaign_linked AND user_id>0 GROUP BY 1
  ) GROUP BY 1
), campaign_activity AS (
  SELECT * FROM classified_history
  WHERE campaign_linked OR first_recorded_at<=ts
), ip_counts AS (
  SELECT ip,COUNT(*) attempts,COALESCE(COUNT_IF(outcome='allow'),0) allowed,
    COUNT(DISTINCT user_id) accounts,MIN(ts) first_seen,MAX(ts) last_seen,
    MODE(country) country,MODE(ctype) ctype,MODE(isp) isp,COUNT_IF(country IS NULL) missing_geo,
    COUNT(DISTINCT country) country_variants
  FROM campaign_activity WHERE ip IS NOT NULL GROUP BY 1
), new_ips AS (
  SELECT ip,MIN(ts) first_seen,COUNT(*) attempts,COALESCE(COUNT_IF(outcome='allow'),0) successes
  FROM campaign_activity WHERE ip IS NOT NULL GROUP BY 1 HAVING MIN(ts)>={day}
), new_countries AS (
  SELECT country,MIN(ts) first_seen,COUNT(DISTINCT user_id) accounts
  FROM campaign_activity WHERE country IS NOT NULL GROUP BY 1 HAVING MIN(ts)>={day}
), hour_grid AS (
  SELECT DATEADD('hour',ROW_NUMBER() OVER(ORDER BY SEQ4())-1,{beginning}) bucket_start
  FROM TABLE(GENERATOR(ROWCOUNT=>168))
)
SELECT 'HOURLY' record_type,OBJECT_CONSTRUCT_KEEP_NULL(
  'bucket_start',g.bucket_start,
  'hk_attempts',COALESCE(h.hk_attempts,0),'hk_successes',COALESCE(h.hk_successes,0),'hk_allowed',COALESCE(h.hk_successes,0),
  'bad_device_attempts',COALESCE(h.baddev_attempts,0),'bad_device_successes',COALESCE(h.baddev_successes,0),'bad_device_allowed',COALESCE(h.baddev_successes,0),
  'app_to_web_attempts',COALESCE(a.app_to_web,0),'app_to_web_successes',COALESCE(a.app_to_web_success,0),'app_to_web_allowed',COALESCE(a.app_to_web_success,0),
  'app_initiations',COALESCE(h.app_req,0)) payload
FROM hour_grid g LEFT JOIN dashboard_hk h ON h.bucket_start=g.bucket_start
  LEFT JOIN dashboard_app_web a ON a.bucket_start=g.bucket_start
UNION ALL SELECT 'MEMBER',OBJECT_CONSTRUCT_KEEP_NULL('user_id',TO_VARCHAR(user_id),'membership_kind','recorded',
  'first_qualified_at',first_recorded_at,'evidence_event_at',first_recorded_at,'reasons',ARRAY_CONSTRUCT('recorded_campaign_annotation')) FROM registry
UNION ALL SELECT 'MEMBER',OBJECT_CONSTRUCT_KEEP_NULL('user_id',TO_VARCHAR(user_id),'membership_kind','candidate',
  'first_qualified_at',first_qualified_at,'evidence_event_at',evidence_event_at,'reasons',reasons) FROM candidates
UNION ALL SELECT 'COHORT_USER',OBJECT_CONSTRUCT_KEEP_NULL('user_id',TO_VARCHAR(user_id),'cohort','campaign',
  'first_qualified_at',first_qualified_at,'cohort_basis','recorded_annotation_or_dashboard_linked_allowed_since_history_start') FROM cohort
UNION ALL SELECT 'IP',OBJECT_CONSTRUCT_KEEP_NULL('ip',ip,'country',country,'connection_type',ctype,'isp',isp,
  'attempts',attempts,'allowed',allowed,'persisted_successes',NULL,'accounts',accounts,
  'outlook_accounts',NULL,'outlook_share',NULL,'first_seen',first_seen,'last_seen',last_seen,
  'missing_geo',missing_geo,'country_variants',country_variants,'success_semantics','dashboard_policy_allowed') FROM ip_counts
UNION ALL SELECT 'ALERT',OBJECT_CONSTRUCT_KEEP_NULL('key','new_campaign_ip','ip',ip,'first_seen',first_seen,
  'attempts',attempts,'successes',successes,'success_semantics','dashboard_policy_allowed') FROM new_ips
UNION ALL SELECT 'ALERT',OBJECT_CONSTRUCT_KEEP_NULL('key','new_campaign_country','country',country,
  'first_seen',first_seen,'accounts',accounts,'geography_semantics','dashboard_whole_window_mode') FROM new_countries
UNION ALL SELECT 'COVERAGE',OBJECT_CONSTRUCT('key','extraction_complete','value',TRUE)
UNION ALL SELECT 'COVERAGE',OBJECT_CONSTRUCT('key','current_registry_available','value',TRUE)
UNION ALL SELECT 'COVERAGE',OBJECT_CONSTRUCT('key','campaign_activity_alerts_available','value',TRUE)
UNION ALL SELECT 'COVERAGE',OBJECT_CONSTRUCT('key','cutoff','value',{end})
UNION ALL SELECT 'COVERAGE',OBJECT_CONSTRUCT('key','history_start','value',{history})
UNION ALL SELECT 'COVERAGE',OBJECT_CONSTRUCT('key','success_semantics','value','dashboard_policy_allowed')
UNION ALL SELECT 'COVERAGE',OBJECT_CONSTRUCT('key','dashboard_source_version_id','value','{source.metadata['source_version_id']}')
UNION ALL SELECT 'COVERAGE',OBJECT_CONSTRUCT('key','knowledge_basis','value','dashboard_event_time_reconstruction_MODE_geo_whole_window_browser_list; no historical ingestion assertion');
"""

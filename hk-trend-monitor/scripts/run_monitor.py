#!/usr/bin/env python3
"""Run the read-only, date-selected HK monitor through the existing snow CLI."""
import argparse
import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfoNotFoundError

from render_report import build_report, iso_utc, parse_cutoff, summary_markdown, write_report

UTC = timezone.utc
ROOT = Path(__file__).resolve().parents[1]


def sql_params(cutoff, zone, history_start, role, warehouse):
    for value in (role, warehouse):
        if value and not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_$]*", value):
            raise ValueError("Role and warehouse must be plain Snowflake identifiers")
    local_midnight = cutoff.astimezone(zone).replace(hour=0, minute=0, second=0, microsecond=0).astimezone(UTC)
    lines = []
    if role:
        lines.append(f"USE ROLE {role};")
    if warehouse:
        lines.append(f"USE WAREHOUSE {warehouse};")
    # Session-only formatting keeps VARIANT timestamps unambiguous for the renderer.
    lines.append("ALTER SESSION SET TIMEZONE='UTC', TIMESTAMP_LTZ_OUTPUT_FORMAT='YYYY-MM-DD\"T\"HH24:MI:SS.FF6TZH:TZM', TIMESTAMP_TZ_OUTPUT_FORMAT='YYYY-MM-DD\"T\"HH24:MI:SS.FF6TZH:TZM';")
    for key, value in (("cutoff", cutoff), ("day_start", local_midnight),
                       ("chart_start", cutoff - timedelta(hours=168)), ("history_start", history_start)):
        lines.append(f"SET {key}=TO_TIMESTAMP_TZ('{iso_utc(value)}');")
    return "\n".join(lines) + "\n"


def new_user_values(users):
    selected = {}
    for row in users:
        if not isinstance(row, dict):
            raise ValueError("New campaign users must be objects with user_id and evidence_event_at")
        uid = str(row.get("user_id", ""))
        if not re.fullmatch(r"[1-9][0-9]{0,9}", uid):
            raise ValueError(f"Invalid positive member ID in source results: {uid!r}")
        # The risk window is relative to the selected day's observed qualifying activity.
        evidence = row.get("evidence_event_at")
        if not isinstance(evidence, str) or not evidence:
            raise ValueError(f"Member {uid} requires an ISO evidence_event_at with a UTC offset")
        try:
            instant = datetime.fromisoformat(evidence.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(f"Invalid evidence_event_at for member {uid}") from exc
        if instant.tzinfo is None or instant.utcoffset() is None:
            raise ValueError(f"Member {uid} evidence_event_at must include a UTC offset")
        instant = instant.astimezone(UTC)
        selected[uid] = min(instant, selected.get(uid, instant))
    # Defensively keep one row per member even if a caller supplies duplicate
    # source rows. Otherwise the follow-on risk joins could multiply callbacks.
    values = [f"({uid},'{iso_utc(selected[uid])}')" for uid in sorted(selected, key=int)]
    if not values:
        return "SELECT NULL::NUMBER user_id,NULL::TIMESTAMP_TZ first_qualified_at WHERE FALSE"
    return "SELECT column1::NUMBER user_id,column2::TIMESTAMP_TZ first_qualified_at FROM VALUES " + ",".join(values)


def run_snow(sql_path, output_path, connection):
    err_path = output_path.with_suffix(".err")
    with output_path.open("w", encoding="utf-8") as out, err_path.open("w", encoding="utf-8") as err:
        proc = subprocess.run(["snow", "sql", "-c", connection, "-f", str(sql_path), "--format", "JSON"],
                              stdout=out, stderr=err, check=False)
    if proc.returncode:
        raise RuntimeError(f"Snowflake CLI failed ({proc.returncode}); see {err_path} and {output_path}. No authentication retry was attempted.")
    return json.loads(output_path.read_text(encoding="utf-8"))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--as-of", required=True, help="YYYY-MM-DD HH:MM, 24-hour time; optional explicit ISO offset")
    parser.add_argument("--timezone", default="America/Chicago")
    parser.add_argument("--campaign-start", default="2026-07-01", help="Inclusive history start in UTC; must cover all campaign evidence")
    parser.add_argument("--connection", default="env")
    parser.add_argument("--role", default="SNOWFLAKE_PROD_ANALYST_OKTA", help="Session role; empty string preserves configured role")
    parser.add_argument("--warehouse", default="ANALYTICS_WH", help="Session warehouse; empty string preserves configured warehouse")
    parser.add_argument("--out-dir", required=True, type=Path)
    parser.add_argument("--prepare-only", action="store_true", help="Write teammate-runnable main.sql and manifest without querying")
    args = parser.parse_args(argv)
    try:
        cutoff, zone = parse_cutoff(args.as_of, args.timezone)
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", args.campaign_start):
            raise ValueError("--campaign-start must be YYYY-MM-DD")
        history_start = datetime.fromisoformat(args.campaign_start).replace(tzinfo=UTC)
        if history_start > cutoff - timedelta(hours=168):
            raise ValueError("Campaign history must begin at or before the 168-hour chart start")
        args.out_dir.mkdir(parents=True, exist_ok=True)
        prefix = sql_params(cutoff, zone, history_start, args.role, args.warehouse)
        sql = prefix + (ROOT / "queries/monitor.sql").read_text(encoding="utf-8")
        main_path = args.out_dir / "main.sql"
        main_path.write_text(sql, encoding="utf-8")
        manifest = {"as_of_input": args.as_of, "timezone": args.timezone, "cutoff_utc": iso_utc(cutoff),
                    "history_start_utc": iso_utc(history_start), "chart_hours": 168,
                    "prepared_at_utc": iso_utc(datetime.now(UTC)), "connection": args.connection,
                    "main_sql_sha256": hashlib.sha256(sql.encode()).hexdigest(),
                    "read_only": True, "public_result_upload": False,
                    "historical_warehouse_availability_verified": False}
        (args.out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        if args.prepare_only:
            print(f"Prepared {main_path.resolve()} (includes the reproducible IP-list result). No query executed.")
            return 0
        primary = run_snow(main_path, args.out_dir / "main.json", args.connection)
        first_report = build_report(primary, args.as_of, args.timezone)
        combined = [primary]
        if first_report["new_users"]:
            try:
                template = (ROOT / "queries/play_integrity.sql").read_text(encoding="utf-8")
                if "{{NEW_USERS}}" not in template:
                    raise ValueError("Play Integrity SQL is missing its bounded NEW_USERS placeholder")
                integrity = prefix + template.replace("{{NEW_USERS}}", new_user_values(first_report["new_users"]))
                integrity_path = args.out_dir / "play_integrity.sql"
                integrity_path.write_text(integrity, encoding="utf-8")
                integrity_result = run_snow(integrity_path, args.out_dir / "play_integrity.json", args.connection)
                verified = [primary, integrity_result,
                            {"RECORD_TYPE":"COVERAGE", "PAYLOAD":{"key":"risk_query_available", "value":True}}]
                # A syntactically valid JSON file can still contain malformed
                # or mismatched-as-of telemetry. Validate inside the optional
                # phase so that it cannot discard the completed primary work.
                verified_report = build_report(verified, args.as_of, args.timezone)
                if verified_report['telemetry_coverage']['new_users_with_coverage_rows'] != len(first_report['new_users']):
                    raise ValueError('Play Integrity query did not return coverage for every proposed addition')
                combined = verified
            except (ValueError, RuntimeError, json.JSONDecodeError, OSError) as exc:
                # Preserve completed primary work; missing risk telemetry is never clean.
                combined.append({"RECORD_TYPE":"COVERAGE", "PAYLOAD":{"key":"risk_query_available", "value":False}})
                for row in first_report["new_users"]:
                    combined.append({"RECORD_TYPE":"RISK", "PAYLOAD":{"user_id":row["user_id"],
                      "signal":"play_integrity:unavailable", "risky":None, "majority_eligible":False,
                      "scope":"source_unavailable", "missing_reason":str(exc)}})
        else:
            combined.append({"RECORD_TYPE":"COVERAGE", "PAYLOAD":{"key":"risk_query_available", "value":"not_applicable_no_additions"}})
        (args.out_dir / "results.json").write_text(json.dumps(combined), encoding="utf-8")
        report = build_report(combined, args.as_of, args.timezone)
        write_report(report, args.out_dir)
        print(summary_markdown(report))
        print(f"Report: {(args.out_dir / 'report.html').resolve()}")
        return 0
    except (ValueError, RuntimeError, OSError, json.JSONDecodeError, ZoneInfoNotFoundError) as exc:
        parser.exit(1, f"Monitor stopped: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())

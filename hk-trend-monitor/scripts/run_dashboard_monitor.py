#!/usr/bin/env python3
"""Run the read-only dashboard-aligned HK monitor and PI device cohorts.

Uses the existing configured snow CLI; optional phases never retry CLI failures.
Private exports, SQL, results, and errors stay in the selected local output folder.
"""

import argparse
import hashlib
import json
import re
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfoNotFoundError

from login_volume_report import append_login_volume_report
from dashboard_adapter import PROJECT_ID, build_cohort_user_sql, build_main_sql, load_dashboard_source
from cohort_report import (
    append_cohort_report, configure_dashboard_labels, normalize_dashboard_html_labels,
    normalize_dashboard_markdown_labels, summarize_cohort,
)
from render_report import (
    RECOGNIZED_TYPES, build_report, iso_utc, parse_cutoff,
    records_from_json, write_report,
)
from run_monitor import new_user_values, run_snow, sql_params

UTC = timezone.utc
ROOT = Path(__file__).resolve().parents[1]
RECOVERABLE = (ValueError, RuntimeError, OSError, json.JSONDecodeError)


def _sha(data):
    return hashlib.sha256(data if isinstance(data, bytes) else data.encode("utf-8")).hexdigest()


def _json(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False) + "\n", encoding="utf-8")


def baseline_limit(value):
    if not re.fullmatch(r"[0-9]+", str(value)) or not 1 <= int(value) <= 10000:
        raise argparse.ArgumentTypeError("--baseline-limit must be an integer from 1 through 10000")
    return int(value)


def renderer_rows(document):
    """Filter extension rows before invoking the unchanged original renderer."""
    return [{"RECORD_TYPE": kind, "PAYLOAD": payload}
            for kind, payload in records_from_json(document) if kind in RECOGNIZED_TYPES]


def cohort_user_values(document):
    """Make a typed SQL input from distinct positive numeric COHORT_USER IDs."""
    identifiers = set()
    for kind, payload in records_from_json(document):
        if kind != "COHORT_USER":
            continue
        value = str(payload.get("user_id") or "")
        if not re.fullmatch(r"[1-9][0-9]{0,37}", value):
            raise ValueError(f"Invalid positive integer COHORT_USER ID: {value!r}")
        if payload.get("cohort", "campaign") != "campaign":
            raise ValueError("COHORT_USER input must contain only the campaign cohort")
        identifiers.add(value)
    ordered = sorted(identifiers, key=int)
    if not ordered:
        return "SELECT NULL::NUMBER(38,0) user_id WHERE FALSE", []
    return "SELECT column1::NUMBER(38,0) user_id FROM VALUES " + ",".join(f"({uid})" for uid in ordered), ordered


def _risk_status(document, value):
    # Replace, rather than conflict with, a source's provisional availability.
    rows = [row for row in renderer_rows(document)
            if not (row["RECORD_TYPE"] == "COVERAGE" and str(row["PAYLOAD"].get("key", "")).lower() == "risk_query_available")]
    rows.append({"RECORD_TYPE": "COVERAGE", "PAYLOAD": {"key": "risk_query_available", "value": value}})
    return rows


def _missing_new_user_risk(users, error):
    return [{"RECORD_TYPE": "RISK", "PAYLOAD": {
        "user_id": row["user_id"], "signal": "play_integrity:unavailable",
        "risky": None, "majority_eligible": False, "scope": "source_unavailable",
        "missing_reason": str(error),
    }} for row in users]


def _new_user_rows(document):
    rows = []
    for kind, payload in records_from_json(document):
        if kind not in {"RISK", "COVERAGE"}:
            raise ValueError(f"New-user PI returned unexpected {kind} rows")
        rows.append({"RECORD_TYPE": kind, "PAYLOAD": payload})
    return rows


def _write_dashboard_report(report, out_dir):
    write_report(configure_dashboard_labels(report), out_dir)
    # The legacy renderer has literal labels as well as definitions. Correct
    # these in the preserved primary report before optional extraction starts.
    for name, convert in (("report.html", normalize_dashboard_html_labels), ("summary.md", normalize_dashboard_markdown_labels)):
        path = out_dir / name
        path.write_text(convert(path.read_text(encoding="utf-8")), encoding="utf-8")


def _unavailable_cohort(error, cutoff, chart_start):
    return [{"RECORD_TYPE": "COHORT_COVERAGE", "PAYLOAD": {
        "available": False, "complete": False, "extraction_complete": False,
        "error": str(error), "cutoff": iso_utc(cutoff),
        "chart_start": iso_utc(chart_start), "seven_day_window_valid": True,
        "window_days": 7, "missing_semantics": "Unavailable is unknown, never clean",
    }}]


def _render_template(template, replacements, label):
    lines = template.splitlines(keepends=True)
    for name, value in replacements.items():
        token = "{{" + name + "}}"
        if not any(token in line for line in lines if not line.lstrip().startswith("--")):
            raise ValueError(f"{label} SQL is missing its bounded {name} placeholder")
        # Expanding multiline relational SQL inside a comment would turn its
        # second line into executable SQL. Comments retain a plain label only.
        lines = [line.replace(token, name + " input") if line.lstrip().startswith("--")
                 else line.replace(token, value) for line in lines]
    template = "".join(lines)
    if re.search(r"\{\{[A-Z_]+\}\}", template):
        raise ValueError(f"{label} SQL contains an unresolved placeholder")
    return template


def export_dashboard(out_dir, manifest):
    """One Hex export attempt. CLI output/error files are retained verbatim."""
    target = out_dir / "dashboard_source.hex.yaml"
    argv = ["hex", "project", "export", PROJECT_ID, "--hex-version", "latest", "-o", str(target), "--json"]
    manifest["dashboard_export_command"] = argv
    output = out_dir / "dashboard_export_cli.json"
    error = out_dir / "dashboard_export.err"
    with output.open("w", encoding="utf-8") as stdout, error.open("w", encoding="utf-8") as stderr:
        proc = subprocess.run(argv, stdout=stdout, stderr=stderr, check=False)
    manifest["dashboard_export_returncode"] = proc.returncode
    if proc.returncode:
        raise RuntimeError(f"Hex CLI export failed ({proc.returncode}); see {error}. No authentication retry was attempted.")
    if not target.is_file():
        raise ValueError("Hex CLI reported success without creating the requested export file")
    return target


def _manifest_write(out_dir, manifest):
    # The manifest cannot hash itself. All other saved top-level artifacts are
    # hashed so that private SQL/source/result provenance is reproducible.
    manifest["artifact_sha256"] = {
        path.name: _sha(path.read_bytes()) for path in sorted(out_dir.iterdir())
        if path.is_file() and path.name != "manifest.json"
    }
    _json(out_dir / "manifest.json", manifest)


def _validate(args):
    """Validate all user-controlled SQL bounds before any filesystem reads."""
    cutoff, zone = parse_cutoff(args.as_of, args.timezone)
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", args.campaign_start):
        raise ValueError("--campaign-start must be YYYY-MM-DD")
    history_start = datetime.fromisoformat(args.campaign_start).replace(tzinfo=UTC)
    chart_start = cutoff - timedelta(hours=168)
    if history_start > chart_start:
        raise ValueError("Campaign history must begin at or before the 168-hour chart start")
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", args.connection):
        raise ValueError("--connection must name an existing configured Snowflake connection")
    # sql_params also validates role/warehouse identifiers; it does no I/O.
    prefix = sql_params(cutoff, zone, history_start, args.role, args.warehouse)
    baseline_limit(args.baseline_limit)
    return cutoff, zone, history_start, chart_start, prefix


def run(args):
    """Execute a parsed/validated run; return a compact machine-readable result."""
    cutoff, zone, history_start, chart_start, prefix = _validate(args)
    out_dir = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "as_of_input": args.as_of, "timezone": args.timezone,
        "cutoff_utc": iso_utc(cutoff), "chart_start_utc": iso_utc(chart_start),
        "history_start_utc": iso_utc(history_start), "chart_hours": 168,
        "prepared_at_utc": iso_utc(datetime.now(UTC)),
        "connection": args.connection, "baseline_limit": args.baseline_limit,
        "read_only": True, "public_result_upload": False,
        "historical_warehouse_availability_verified": False,
        "dashboard_success_semantics": "dashboard_policy_allowed",
        "phases": {}, "phase_errors": {},
    }
    try:
        if args.dashboard_export is not None:
            manifest["phases"]["dashboard_export"] = "supplied_local_export"
            source_path = args.dashboard_export
        else:
            manifest["phases"]["dashboard_export"] = "started"
            _manifest_write(out_dir, manifest)
            source_path = export_dashboard(out_dir, manifest)
            manifest["phases"]["dashboard_export"] = "complete"
        # Keep the exact private input beside generated SQL, including supplied
        # local exports; source.metadata includes reviewed source fingerprints.
        raw_source = source_path.read_bytes()
        source_copy = out_dir / "dashboard_source.hex.yaml"
        if source_path.resolve() != source_copy.resolve():
            source_copy.write_bytes(raw_source)
        manifest["dashboard_source_sha256"] = _sha(raw_source)
        manifest["dashboard_source_path"] = str(source_copy.resolve())
        source = load_dashboard_source(source_copy)
        manifest["dashboard_source"] = dict(source.metadata)
        day_start = cutoff.astimezone(zone).replace(hour=0, minute=0, second=0, microsecond=0).astimezone(UTC)
        main_sql = prefix + build_main_sql(source, cutoff, day_start, chart_start, history_start)
        main_path = out_dir / "main.sql"
        main_path.write_text(main_sql, encoding="utf-8")
        manifest["main_sql_sha256"] = _sha(main_sql)
        manifest["phases"]["primary"] = "prepared"
        # Prepare a fully runnable source-derived cohort SELECT for teammates.
        # A normal run later replaces this with the exact validated main IDs.
        cohort_template, cohort_template_error = None, None
        try:
            cohort_template = (ROOT / "queries/cohort_play_integrity.sql").read_text(encoding="utf-8")
            if "{{COHORT_USERS}}" not in cohort_template or "{{BASELINE_LIMIT}}" not in cohort_template:
                raise ValueError("Cohort SQL must contain bounded COHORT_USERS and BASELINE_LIMIT placeholders")
            prepared_cohort = prefix + _render_template(cohort_template, {
                "COHORT_USERS": build_cohort_user_sql(source, cutoff, history_start),
                "BASELINE_LIMIT": str(args.baseline_limit),
            }, "Cohort Play Integrity")
            (out_dir / "cohort_play_integrity.sql").write_text(prepared_cohort, encoding="utf-8")
            manifest["cohort_template_source_sha256"] = _sha(cohort_template)
            manifest["cohort_prepared_sql_sha256"] = _sha(prepared_cohort)
            manifest["cohort_prepared_input"] = "dashboard_source_relational_membership"
            manifest["phases"]["cohort"] = "prepared_source_derived_membership"
        except RECOVERABLE as exc:
            cohort_template_error = str(exc)
            manifest["phase_errors"]["cohort"] = cohort_template_error
            manifest["phases"]["cohort"] = "preparation_failed"
        _manifest_write(out_dir, manifest)
        if args.prepare_only:
            manifest["status"] = "PREPARED_PARTIAL_NO_QUERY" if cohort_template_error else "PREPARED_NO_QUERY"
            _manifest_write(out_dir, manifest)
            return {"status": manifest["status"], "main_sql": str(main_path.resolve()), "manifest": str((out_dir / "manifest.json").resolve())}

        primary = run_snow(main_path, out_dir / "main.json", args.connection)
        manifest["phases"]["primary"] = "complete"
        primary_rows = renderer_rows(primary)
        first_report = build_report(primary_rows, args.as_of, args.timezone)
        # Write completed primary work before any optional extraction. A later
        # optional failure cannot remove the main activity/member/IP results.
        _write_dashboard_report(first_report, out_dir)
        _manifest_write(out_dir, manifest)

        raw_results = {"primary": primary}
        cohort_document = []
        cohort_cli_failed = False
        try:
            if cohort_template_error:
                raise ValueError(cohort_template_error)
            cohort_values, cohort_ids = cohort_user_values(primary)
            manifest["cohort_user_count"] = len(cohort_ids)
            cohort_sql = prefix + _render_template(cohort_template, {
                "COHORT_USERS": cohort_values, "BASELINE_LIMIT": str(args.baseline_limit),
            }, "Cohort Play Integrity")
            cohort_path = out_dir / "cohort_play_integrity.sql"
            cohort_path.write_text(cohort_sql, encoding="utf-8")
            manifest["cohort_sql_sha256"] = _sha(cohort_sql)
            manifest["phases"]["cohort"] = "query_started"
            _manifest_write(out_dir, manifest)
            try:
                cohort_result = run_snow(cohort_path, out_dir / "cohort_play_integrity.json", args.connection)
            except RECOVERABLE:
                cohort_cli_failed = True
                raise
            raw_results["cohort"] = cohort_result
            validated = summarize_cohort(cohort_result, cutoff)
            cohort_document = cohort_result
            manifest["phases"]["cohort"] = validated["status"].lower()
        except RECOVERABLE as exc:
            error = str(exc)
            manifest["phases"]["cohort"] = "failed"
            manifest["phase_errors"]["cohort"] = error
            (out_dir / "cohort_phase.err").write_text(error + "\n", encoding="utf-8")
            cohort_document = _unavailable_cohort(error, cutoff, chart_start)
        manifest["cohort_cli_failed_no_more_snow_attempts"] = cohort_cli_failed
        _manifest_write(out_dir, manifest)

        risk_result = []
        risk_status = "not_applicable_no_additions"
        if not first_report["new_users"]:
            manifest["phases"]["new_user_risk"] = "not_applicable_no_additions"
        elif cohort_cli_failed:
            error = "New-user PI query skipped after cohort Snowflake CLI failure; no additional authentication attempt was made"
            manifest["phases"]["new_user_risk"] = "skipped_after_cohort_cli_failure"
            manifest["phase_errors"]["new_user_risk"] = error
            risk_status = False
            risk_result = _missing_new_user_risk(first_report["new_users"], error)
        else:
            try:
                template = (ROOT / "queries/play_integrity.sql").read_text(encoding="utf-8")
                risk_sql = prefix + _render_template(template, {"NEW_USERS": new_user_values(first_report["new_users"])}, "New-user Play Integrity")
                risk_path = out_dir / "play_integrity.sql"
                risk_path.write_text(risk_sql, encoding="utf-8")
                manifest["new_user_risk_sql_sha256"] = _sha(risk_sql)
                manifest["phases"]["new_user_risk"] = "query_started"
                _manifest_write(out_dir, manifest)
                extracted = run_snow(risk_path, out_dir / "play_integrity.json", args.connection)
                raw_results["new_user_risk"] = extracted
                extracted_rows = _new_user_rows(extracted)
                verified = _risk_status([primary_rows, extracted_rows], True)
                verified_report = build_report(verified, args.as_of, args.timezone)
                if verified_report["telemetry_coverage"]["new_users_with_coverage_rows"] != len(first_report["new_users"]):
                    raise ValueError("New-user PI query did not return coverage for every proposed addition")
                risk_result = extracted_rows
                risk_status = True
                manifest["phases"]["new_user_risk"] = "complete"
            except RECOVERABLE as exc:
                error = str(exc)
                manifest["phases"]["new_user_risk"] = "failed"
                manifest["phase_errors"]["new_user_risk"] = error
                (out_dir / "new_user_risk_phase.err").write_text(error + "\n", encoding="utf-8")
                risk_result = _missing_new_user_risk(first_report["new_users"], error)
                risk_status = False

        status_row = {"RECORD_TYPE": "COVERAGE", "PAYLOAD": {"key": "risk_query_available", "value": risk_status}}
        combined = [primary, cohort_document, risk_result, status_row]
        _json(out_dir / "raw_results.json", raw_results)
        _json(out_dir / "results.json", combined)
        final_rows = _risk_status([primary_rows, risk_result], risk_status)
        report = configure_dashboard_labels(build_report(final_rows, args.as_of, args.timezone))
        _write_dashboard_report(report, out_dir)
        cohort_summary = append_cohort_report(out_dir, combined, cutoff, dashboard_success_policy_allowed=True)
        try:
            login_summary = append_login_volume_report(out_dir, combined, cutoff, timezone=args.timezone)
        except RECOVERABLE as exc:
            manifest["phase_errors"]["login_volume"] = str(exc)
            login_summary = append_login_volume_report(out_dir, [], cutoff, timezone=args.timezone)
        manifest["phases"]["login_volume"] = login_summary["status"].lower()
        final_status = "PARTIAL" if cohort_summary["status"] != "AVAILABLE" or login_summary["status"] != "AVAILABLE" else report["status"]
        manifest["status"] = final_status
        manifest["completed_at_utc"] = iso_utc(datetime.now(UTC))
        _manifest_write(out_dir, manifest)
        return {
            "status": final_status, "as_of_utc": iso_utc(cutoff),
            "new_users": report["counts"]["new_users"],
            "cohort_status": cohort_summary["status"],
            "login_volume_status": login_summary["status"],
            "report": str((out_dir / "report.html").resolve()),
            "manifest": str((out_dir / "manifest.json").resolve()),
        }
    except RECOVERABLE as exc:
        manifest["status"] = "FAILED"
        manifest["error"] = str(exc)
        (out_dir / "monitor.err").write_text(str(exc) + "\n", encoding="utf-8")
        _manifest_write(out_dir, manifest)
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--as-of", required=True, help="YYYY-MM-DD HH:MM, 24-hour time; optional explicit ISO offset")
    parser.add_argument("--timezone", default="America/Chicago")
    parser.add_argument("--campaign-start", default="2026-07-01")
    parser.add_argument("--connection", default="env")
    parser.add_argument("--role", default="SNOWFLAKE_PROD_ANALYST_OKTA", help="Empty preserves configured role")
    parser.add_argument("--warehouse", default="ANALYTICS_WH", help="Empty preserves configured warehouse")
    parser.add_argument("--out-dir", required=True, type=Path)
    parser.add_argument("--dashboard-export", type=Path, help="Use this private local Hex YAML without a Hex CLI request")
    parser.add_argument("--prepare-only", action="store_true")
    parser.add_argument("--baseline-limit", type=baseline_limit, default=5000)
    args = parser.parse_args(argv)
    try:
        result = run(args)
    except (*RECOVERABLE, ZoneInfoNotFoundError) as exc:
        parser.exit(1, f"Monitor stopped: {exc}\n")
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

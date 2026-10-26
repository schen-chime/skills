#!/usr/bin/env python3
"""Work-only, offline Play Integrity cohort extension for the HK monitor.

Input: nested Snow CLI RECORD_TYPE/PAYLOAD results. COHORT_DEVICE rows are
device snapshots, not callback events; COHORT_COVERAGE rows carry provenance.
No database, network, registry, installation, or messaging operations occur.
"""

import argparse
import csv
import html
import json
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

UTC = timezone.utc
SIGNALS = ("unknown_controlling", "known_controlling", "known_only_controlling", "any_controlling")
LABELS = {
    "unknown_controlling": "UNKNOWN_CONTROLLING (non-Play recognized control)",
    "known_controlling": "KNOWN_CONTROLLING (Play/system recognized control; may overlap UNKNOWN)",
    "known_only_controlling": "KNOWN_CONTROLLING only (without UNKNOWN_CONTROLLING)",
    "any_controlling": "Any controlling verdict (KNOWN or UNKNOWN)",
}
COHORTS = ("campaign", "baseline", "ambiguous")
MARKER_START = "<!-- HK_PI_COHORT_EXTENSION_START -->"
MARKER_END = "<!-- HK_PI_COHORT_EXTENSION_END -->"
MISSING_SEMANTICS = "Missing, invalid, unmapped, unevaluated, or out-of-window telemetry is unknown; it is never a clean verdict."


def _time(value, field="timestamp"):
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        instant = value
    elif isinstance(value, str):
        try:
            instant = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(f"Invalid {field}: {value!r}") from exc
    else:
        raise ValueError(f"{field} must be an ISO timestamp or datetime")
    if instant.tzinfo is None:
        instant = instant.replace(tzinfo=UTC)
    return instant.astimezone(UTC)


def _iso(value):
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z") if value else None


def _bool(value, field):
    if value is None or value == "":
        return None
    if value is True or value == 1 or (isinstance(value, str) and value.lower() == "true"):
        return True
    if value is False or value == 0 or (isinstance(value, str) and value.lower() == "false"):
        return False
    raise ValueError(f"{field} must be boolean or null")


def _count(value, field):
    if value is None or value == "":
        return 0
    if isinstance(value, bool):
        raise ValueError(f"{field} must be a nonnegative integer")
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be a nonnegative integer") from exc
    if str(number) != str(value) and not isinstance(value, int):
        raise ValueError(f"{field} must be a nonnegative integer")
    if number < 0:
        raise ValueError(f"{field} must be a nonnegative integer")
    return number


def records_from_json(document):
    """Flatten nested Snow CLI results, accepting JSON-string payloads."""
    if isinstance(document, list):
        for item in document:
            yield from records_from_json(item)
    elif isinstance(document, dict):
        row = {str(key).lower(): value for key, value in document.items()}
        if "record_type" in row:
            kind = str(row["record_type"]).upper()
            # Unrelated monitor rows are deliberately not validated here.
            if kind not in {"COHORT_DEVICE", "COHORT_COVERAGE"}:
                return
            payload = row.get("payload")
            if isinstance(payload, str):
                payload = json.loads(payload)
            if not isinstance(payload, dict):
                raise ValueError(f"{kind} PAYLOAD must be an object")
            yield kind, {str(key).lower(): value for key, value in payload.items()}
        else:
            for value in document.values():
                if isinstance(value, (list, dict)):
                    yield from records_from_json(value)


def historical_benchmark():
    """Fixed historical context; never inputs to live snapshot calculations."""
    rows = []
    for signal, campaign, baseline in (("unknown_controlling", 145, 39), ("known_only_controlling", 61, 283)):
        campaign_rate, baseline_rate = campaign / 908, baseline / 4165
        rows.append({
            "signal": signal,
            "campaign_positive": campaign, "campaign_environment_details": 908,
            "baseline_positive": baseline, "baseline_environment_details": 4165,
            "campaign_rate": campaign_rate, "baseline_rate": baseline_rate,
            "rate_ratio": campaign_rate / baseline_rate,
            "rate_difference_percentage_points": (campaign_rate - baseline_rate) * 100,
        })
    return {
        "status": "FIXED_HISTORICAL_CONTEXT",
        "original_population": {"campaign": 1259, "baseline": 5893},
        "rows": rows,
        "method": "Latest callback before a preselected phone change; denominator required any environmentDetails, with no callback-age cap. Median callback age: campaign 16 days; baseline 3 days.",
        "selected_takeover_observations": {
            "signal": "unknown_controlling", "positive": 9, "examined": 9,
            "first_positive_after_phone_change": 4,
            "description": "UNKNOWN_CONTROLLING was observed around takeover for all nine selected case accounts. In four, the first positive observation was after the phone change, with observation gaps; this does not establish pre-action detection. These selected cases are not a random sample or a population prevalence estimate.",
        },
        "comparability": "The historical benchmark and live seven-day latest-callback snapshot have different selection rules and denominators. Neither is a verified-legitimate control population; do not treat the live baseline as a replication of the historical method.",
        "interpretation": "A lure/downloader explanation is a hypothesis, not proof. UNKNOWN_CONTROLLING is Google's recognition category and can include cross-profile Play apps; it does not identify a specific app, installation source, remote-control action, or takeover causality.",
    }


def _normalize(row):
    result = dict(row)  # Retain source provenance and future fields.
    device = str(row.get("device_id") or "").strip()
    if not device:
        raise ValueError("COHORT_DEVICE requires a nonempty device_id")
    cohort = str(row.get("cohort") or "").lower()
    if cohort not in COHORTS:
        raise ValueError(f"COHORT_DEVICE {device} requires cohort campaign/baseline/ambiguous")
    result.update(device_id=device, cohort=cohort,
                  user_id=str(row["user_id"]).strip() if row.get("user_id") is not None else None)
    result["eligible"] = _bool(row.get("eligible"), "eligible") is True
    result["app_access_evaluated"] = _bool(row.get("app_access_evaluated"), "app_access_evaluated")
    result["valid_callbacks"] = _count(row.get("valid_callbacks"), "valid_callbacks")
    for field in SIGNALS:
        result[field] = _bool(row.get(field), field)
    u, k = result["unknown_controlling"], result["known_controlling"]
    derived = {
        "any_controlling": True if u is True or k is True else (False if u is False and k is False else None),
        "known_only_controlling": False if u is True or k is False else (True if k is True and u is False else None),
    }
    for field, expected in derived.items():
        if result[field] is None:
            result[field] = expected
        elif expected is not None and result[field] != expected:
            raise ValueError(f"COHORT_DEVICE {device} has inconsistent {field}")
    for field in ("latest_observed_at", "first_positive_at", "last_positive_at"):
        result[field] = _iso(_time(row.get(field), field))
    result["exclusion_reason"] = str(row.get("exclusion_reason") or "")
    result["missing_reason"] = str(row.get("missing_reason") or "")
    return result


def _unique_rows(rows):
    unique = {}
    for row in rows:
        unique[json.dumps(row, sort_keys=True, ensure_ascii=False, default=str)] = row
    return [unique[key] for key in sorted(unique)]


def _dedupe(rows, cutoff, warnings):
    grouped = defaultdict(list)
    for row in rows:
        grouped[row["device_id"]].append(row)
    output = []
    duplicate_rows = 0
    for device_id, raw in sorted(grouped.items()):
        unique = _unique_rows(raw)
        duplicate_rows += len(raw) - len(unique)
        # Prefer latest strictly pre-cutoff observation, never an older positive
        # over a newer negative or missing callback.
        past = [r for r in unique if _time(r["latest_observed_at"]) is not None and _time(r["latest_observed_at"]) < cutoff]
        candidates = past if past else unique
        latest = max((_time(r["latest_observed_at"]) or datetime.min.replace(tzinfo=UTC)) for r in candidates)
        selected = [r for r in candidates if (_time(r["latest_observed_at"]) or datetime.min.replace(tzinfo=UTC)) == latest]
        result = dict(selected[0])
        identity_fields = ("user_id", "cohort", "eligible")
        identity_conflicts = [field for field in identity_fields if len({json.dumps(r.get(field), sort_keys=True) for r in unique}) > 1]
        signal_conflicts = [field for field in (*SIGNALS, "valid_callbacks", "app_access_evaluated") if len({json.dumps(r.get(field), sort_keys=True) for r in selected}) > 1]
        conflicts = identity_conflicts + signal_conflicts
        result["source_row_count"] = len(raw)
        result["distinct_source_row_count"] = len(unique)
        result["conflicting_fields"] = conflicts
        if len(unique) > 1:
            result["source_records"] = unique
        if conflicts:
            # Conflicting identifiers cannot establish a validated device link.
            result.update(eligible=False, cohort="ambiguous", exclusion_reason="conflicting device records: " + ", ".join(conflicts))
            warnings.append(f"Quarantined device {device_id}: conflicting records")
        elif result["cohort"] == "ambiguous":
            result["eligible"] = False
            result["exclusion_reason"] = result["exclusion_reason"] or "ambiguous device linkage"
        if not result["eligible"] and not result["exclusion_reason"]:
            result["exclusion_reason"] = "source did not establish eligibility"
        output.append(result)
    return output, duplicate_rows


def _coverage_status(metadata, cutoff, warnings):
    if not metadata:
        warnings.append("COHORT_COVERAGE metadata is absent; cohort extraction availability and completeness are unverified")
        return "UNAVAILABLE"
    incomplete = False
    for row in metadata:
        # Support both key/value coverage contracts and descriptive payloads.
        values = {str(row["key"]).lower(): row.get("value")} if "key" in row else row
        for key, value in values.items():
            if key in {"cutoff", "as_of_utc", "snapshot_end_utc"} and value is not None:
                if _time(value, key) != cutoff:
                    raise ValueError("Cohort source cutoff differs from requested cutoff")
            if key in {"extraction_complete", "cohort_query_available", "query_available", "available", "coverage_complete", "seven_day_window_valid"}:
                if _bool(value, key) is not True:
                    incomplete = True
                    warnings.append(f"Cohort metadata {key} is false or unknown")
            if key == "chart_start" and value is not None and _time(value, key) != cutoff - timedelta(days=7):
                incomplete = True
                warnings.append("Cohort source chart_start is not exactly seven days before cutoff")
            if key == "window_days" and value is not None and float(value) != 7:
                incomplete = True
                warnings.append("Cohort source window_days is not seven")
            if key == "status" and str(value).upper() in {"PARTIAL", "UNAVAILABLE", "ERROR", "FAILED"}:
                incomplete = True
                warnings.append(f"Cohort source status is {value}")
    return "PARTIAL" if incomplete else "AVAILABLE"


def assert_cohort_counts(devices, metadata):
    """Reject missing/truncated snapshots before publishing population rates."""
    declared = {}
    for row in metadata:
        values = {str(row["key"]).lower(): row.get("value")} if "key" in row else row
        for key, value in values.items():
            if key in declared and declared[key] != value:
                raise ValueError(f"Conflicting cohort coverage {key}")
            declared[key] = value

    def check(values, key, actual, label):
        if key not in values or values[key] is None:
            raise ValueError(f"Missing cohort count {label}.{key}")
        expected = _count(values[key], f"{label}.{key}")
        if expected != actual:
            raise ValueError(f"Cohort count mismatch {label}.{key}: declared {expected}, received {actual}")

    identifiers = [row["device_id"] for row in devices]
    if len(set(identifiers)) != len(identifiers):
        raise ValueError("Duplicate device IDs in cohort snapshot")
    check(declared, "emitted_device_rows", len(devices), "run")
    check(declared, "full_eligible_campaign_devices", sum(r["eligible"] and r["cohort"] == "campaign" for r in devices), "run")
    check(declared, "sampled_baseline_devices", sum(r["eligible"] and r["cohort"] == "baseline" for r in devices), "run")
    if "emitted_excluded_devices" in declared:
        check(declared, "emitted_excluded_devices", sum(not r["eligible"] for r in devices), "run")
    groups = declared.get("group_metrics")
    if not isinstance(groups, list):
        raise ValueError("Missing or invalid cohort count run.group_metrics")
    by_cohort = {}
    for group in groups:
        if not isinstance(group, dict) or group.get("cohort") not in COHORTS or group["cohort"] in by_cohort:
            raise ValueError("Invalid or duplicate cohort in group_metrics")
        by_cohort[group["cohort"]] = group
    for cohort in COHORTS:
        selected = [r for r in devices if r["cohort"] == cohort]
        eligible = [r for r in selected if r["eligible"]]
        if not selected and cohort not in by_cohort:
            continue
        if cohort not in by_cohort:
            raise ValueError(f"Missing cohort count group_metrics.{cohort}")
        group = by_cohort[cohort]
        expected = {"emitted_device_rows": len(selected), "eligible_devices": len(eligible),
                    "excluded_devices": len(selected) - len(eligible),
                    "devices_with_valid_callbacks": sum(r["valid_callbacks"] > 0 for r in eligible),
                    "app_access_fully_evaluated_devices": sum(r["app_access_evaluated"] is True for r in eligible)}
        for signal in SIGNALS:
            expected[signal + "_evaluated_devices"] = sum(r[signal] is not None for r in eligible)
            expected[signal + "_positive_devices"] = sum(r[signal] is True for r in eligible)
        for key, actual in expected.items():
            check(group, key, actual, cohort)
    return True


def summarize_cohort(document, cutoff):
    """Aggregate one validated device once, with per-signal missingness.

    All-eligible rates retain unobserved devices in their denominator. Each
    signal has its own observed denominator; a known positive remains usable
    when another verdict is unknown or app_access_evaluated is false.
    """
    cutoff = _time(cutoff, "cutoff")
    if cutoff is None:
        raise ValueError("cutoff is required")
    start = cutoff - timedelta(days=7)
    source_devices, metadata = [], []
    for kind, row in records_from_json(document):
        (source_devices if kind == "COHORT_DEVICE" else metadata).append(row)
    warnings = []
    availability = _coverage_status(metadata, cutoff, warnings)
    devices, duplicates = _dedupe([_normalize(row) for row in source_devices], cutoff, warnings)
    count_error = None
    try:
        assert_cohort_counts(devices, metadata)
    except ValueError as exc:
        count_error = str(exc)
        warnings.append(count_error + "; live prevalence rates suppressed")
        if availability != "UNAVAILABLE":
            availability = "PARTIAL"
    counts_verified = count_error is None
    for row in devices:
        latest = _time(row["latest_observed_at"])
        reasons = []
        if latest is None:
            reasons.append("no latest valid callback timestamp")
        elif latest >= cutoff:
            reasons.append("callback at or after cutoff")
        elif latest < start:
            reasons.append("latest callback outside seven-day window")
        if row["valid_callbacks"] == 0:
            reasons.append("no valid callbacks")
        if any(_time(row[field]) is not None and _time(row[field]) >= cutoff for field in ("first_positive_at", "last_positive_at")):
            reasons.append("positive timestamp at or after cutoff")
        row["callback_usable"] = not reasons
        row["device_fully_evaluated"] = row["callback_usable"] and row["app_access_evaluated"] is True and all(row[s] is not None for s in SIGNALS)
        row["computed_missing_reason"] = "; ".join(filter(None, [row["missing_reason"], *reasons]))
        for signal in SIGNALS:
            row[signal + "_observed"] = row["callback_usable"] and row[signal] is not None
    metrics, populations = [], []
    for cohort in COHORTS:
        selected = [r for r in devices if r["cohort"] == cohort]
        eligible = [r for r in selected if r["eligible"]]
        populations.append({
            "cohort": cohort, "distinct_devices": len(selected), "eligible_devices": len(eligible),
            "excluded_devices": len(selected) - len(eligible),
            "devices_with_usable_callback": sum(r["callback_usable"] for r in eligible),
            "fully_evaluated_devices": sum(r["device_fully_evaluated"] for r in eligible),
        })
        for signal in SIGNALS:
            observed = [r for r in eligible if r[signal + "_observed"]]
            positive = sum(r[signal] is True for r in observed)
            missing_reasons = Counter(r["computed_missing_reason"] or "signal verdict unknown" for r in eligible if not r[signal + "_observed"])
            metrics.append({
                "cohort": cohort, "signal": signal, "label": LABELS[signal],
                "all_eligible_devices": len(eligible), "observed_devices": len(observed),
                "positive_devices": positive, "negative_devices": len(observed) - positive,
                "unknown_devices": len(eligible) - len(observed),
                "positive_share_all_eligible": positive / len(eligible) if eligible and counts_verified else None,
                "positive_share_observed": positive / len(observed) if observed and counts_verified else None,
                "coverage_share": len(observed) / len(eligible) if eligible and counts_verified else None,
                "denominator_verified": counts_verified,
                "missing_reasons": dict(sorted(missing_reasons.items())),
            })
    comparisons = []
    for signal in SIGNALS:
        a = next(r for r in metrics if r["cohort"] == "campaign" and r["signal"] == signal)
        b = next(r for r in metrics if r["cohort"] == "baseline" and r["signal"] == signal)
        ar, br = a["positive_share_observed"], b["positive_share_observed"]
        comparisons.append({"signal": signal, "campaign_rate_observed": ar, "baseline_rate_observed": br,
                            "rate_ratio_observed": ar / br if ar is not None and br else None,
                            "rate_difference_percentage_points_observed": (ar - br) * 100 if ar is not None and br is not None else None})
    return {
        "status": availability, "as_of_utc": _iso(cutoff), "window_start_utc": _iso(start),
        "method": "Common [T−7 days,T) window; each device's latest callback strictly before T; per-signal known verdicts define observed denominators. Devices count once and UNKNOWN/KNOWN can overlap.",
        "baseline_method": "Deterministic sample of at most 5,000 active Android devices outside the campaign cohort. This is a noncohort comparison sample, not verified legitimate devices or the historical selection method.",
        "independent_of_new_users": True,
        "majority_alert_semantics": "This device-cohort comparison does not modify the existing strictly-greater-than-50% test over all same-day candidate users; it does not add members or confirm ATO.",
        "missing_semantics": MISSING_SEMANTICS,
        "coverage_metadata": metadata, "populations": populations, "metrics": metrics,
        "count_reconciliation": {"verified": counts_verified, "error": count_error},
        "live_comparisons": comparisons, "devices": devices,
        "source_device_rows": len(source_devices), "deduplicated_exact_rows": duplicates,
        "unique_devices": len(devices), "warnings": sorted(set(warnings)),
        "historical_benchmark": historical_benchmark(),
        "hourly": {"status": "NOT_AVAILABLE_FROM_DEVICE_SNAPSHOTS", "description": "Only latest-callback device snapshots are supplied; hourly signal counts are not reconstructed from first/last timestamps or invented as zeros."},
    }


def _percent(value):
    return "unknown / no denominator" if value is None else f"{value:.3%}"


def _table(rows, fields):
    esc = lambda value: html.escape("" if value is None else str(value))
    return "<table><thead><tr>" + "".join(f"<th>{esc(f)}</th>" for f in fields) + "</tr></thead><tbody>" + "".join("<tr>" + "".join(f"<td>{esc(row.get(f))}</td>" for f in fields) + "</tr>" for row in rows) + "</tbody></table>"


def cohort_markdown(summary):
    lines = ["Play Integrity device cohorts — " + summary["status"], "", f"As of {summary['as_of_utc']}; seven-day window begins {summary['window_start_utc']}.", summary["method"], summary["baseline_method"], "", "| Cohort | Signal | Positive / eligible | Positive / observed | Unknown |", "|---|---|---:|---:|---:|"]
    for row in summary["metrics"]:
        if row["cohort"] == "ambiguous":
            continue
        lines.append(f"| {row['cohort']} | {row['signal']} | {row['positive_devices']}/{row['all_eligible_devices']} ({_percent(row['positive_share_all_eligible'])}) | {row['positive_devices']}/{row['observed_devices']} ({_percent(row['positive_share_observed'])}) | {row['unknown_devices']} |")
    historical = summary["historical_benchmark"]
    lines.extend(["", summary["missing_semantics"], summary["majority_alert_semantics"], "", "Fixed historical context (separate from live results):"])
    for row in historical["rows"]:
        lines.append(f"- {row['signal']}: campaign {row['campaign_positive']}/908 ({_percent(row['campaign_rate'])}); historical comparison {row['baseline_positive']}/4165 ({_percent(row['baseline_rate'])}); {row['rate_ratio']:.3f}×.")
    lines.extend([historical["method"], "Original populations: campaign 1,259; historical comparison 5,893.", "9/9: " + historical["selected_takeover_observations"]["description"], historical["comparability"], historical["interpretation"], "", summary["hourly"]["description"]])
    if summary["warnings"]:
        lines.extend(["", "Data limitations:", *["- " + warning for warning in summary["warnings"]]])
    lines.extend(["", "Downloads: cohort_devices.csv, cohort_metrics.csv, cohort_summary.json, cohort_report.html."])
    return "\n".join(lines) + "\n"


def cohort_html_section(summary):
    esc = html.escape
    rows = [{"cohort": r["cohort"], "signal": r["signal"], "positive / all eligible": f"{r['positive_devices']}/{r['all_eligible_devices']} ({_percent(r['positive_share_all_eligible'])})", "positive / observed": f"{r['positive_devices']}/{r['observed_devices']} ({_percent(r['positive_share_observed'])})", "observed / eligible": f"{r['observed_devices']}/{r['all_eligible_devices']}", "unknown": r["unknown_devices"]} for r in summary["metrics"] if r["cohort"] != "ambiguous"]
    historical = summary["historical_benchmark"]
    old = [{"signal": r["signal"], "campaign": f"{r['campaign_positive']}/908 ({_percent(r['campaign_rate'])})", "historical comparison": f"{r['baseline_positive']}/4165 ({_percent(r['baseline_rate'])})", "ratio": f"{r['rate_ratio']:.3f}×"} for r in historical["rows"]]
    warnings = "".join(f"<li>{esc(w)}</li>" for w in summary["warnings"])
    return f'''<section class="card" id="play-integrity-cohorts"><h2>Play Integrity device cohorts <span class="badge">{esc(summary['status'])}</span></h2>
<p>Latest callback snapshot as of <strong>{esc(summary['as_of_utc'])}</strong>, common seven-day window starting {esc(summary['window_start_utc'])}. This tracker runs even when there are zero same-day candidate additions.</p>
<p>{esc(summary['method'])}</p><p>{esc(summary['baseline_method'])}</p>
<div class="table-scroll">{_table(rows, ('cohort', 'signal', 'positive / all eligible', 'positive / observed', 'observed / eligible', 'unknown'))}</div>
<p><strong>UNKNOWN and KNOWN can coexist.</strong> UNKNOWN_CONTROLLING is the non-Play recognized control category; KNOWN_CONTROLLING is Play/system recognized control. KNOWN only excludes UNKNOWN. Each signal has its own observed denominator.</p>
<p>{esc(summary['missing_semantics'])}</p><p>{esc(summary['majority_alert_semantics'])}</p>
<p><a href="cohort_devices.csv" download>Device data and exclusions</a> · <a href="cohort_metrics.csv" download>Live metric CSV</a> · <a href="cohort_summary.json" download>Full provenance JSON</a> · <a href="cohort_report.html">Standalone cohort report</a></p>
<h3>Fixed historical context — different selection method</h3>
<div class="table-scroll">{_table(old, ('signal', 'campaign', 'historical comparison', 'ratio'))}</div>
<p>Original populations: campaign 1,259; historical comparison 5,893. {esc(historical['method'])}</p>
<p><strong>Selected case observations: 9/9.</strong> {esc(historical['selected_takeover_observations']['description'])}</p>
<p>{esc(historical['comparability'])}</p><p>{esc(historical['interpretation'])}</p>
<p class="muted">{esc(summary['hourly']['description'])}</p>
{'<div class="limit"><strong>Cohort data limitations</strong><ul>' + warnings + '</ul></div>' if warnings else ''}
<details><summary>Cohort populations, exclusions, and source coverage</summary><div class="table-scroll">{_table(summary['populations'], ('cohort', 'distinct_devices', 'eligible_devices', 'excluded_devices', 'devices_with_usable_callback', 'fully_evaluated_devices'))}</div><pre>{esc(json.dumps(summary['coverage_metadata'], indent=2, ensure_ascii=False))}</pre></details></section>'''


def standalone_html(summary):
    return '''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>HK Play Integrity cohort monitor</title><style>body{margin:0;background:#f4f7fb;color:#172b4d;font:15px/1.5 system-ui,sans-serif}main{max-width:1280px;margin:30px auto;padding:0 20px}.card{background:white;border:1px solid #dce5ee;border-radius:12px;padding:22px}.badge{background:#e9eef7;padding:3px 9px;border-radius:6px;font-size:14px}.table-scroll{overflow:auto}table{border-collapse:collapse;width:100%;font-size:13px}th,td{text-align:left;padding:9px;border-bottom:1px solid #dce5ee}th{background:#f5f8fc}.muted{color:#50647c}.limit{border-left:4px solid #c67d16;padding-left:14px}pre{white-space:pre-wrap;font-size:12px}a{color:#1768ac}</style></head><body><main>''' + cohort_html_section(summary) + "</main></body></html>"


def configure_dashboard_labels(report):
    """Explicit integration hook; does not change counts or field names."""
    report["dashboard_success_semantics"] = "policy_allowed"
    report.setdefault("definitions", {})["successes"] = "Dashboard success = policy allowed (policy response status allow); this does not establish persisted email updates."
    for alert in report.get("alerts", []):
        if isinstance(alert.get("message"), str):
            alert["message"] = _dashboard_success_words(alert["message"])
    return report


def _dashboard_success_words(text):
    return text.replace("Persisted successes", "Dashboard successes (policy allowed)").replace("persisted successes", "dashboard successes (policy allowed)")


def normalize_dashboard_html_labels(text):
    """Normalize only the known dashboard wording, retaining source evidence."""
    replacements = {
        '<option value="successes">Persisted successes</option>': '<option value="successes">Dashboard success = policy allowed</option>',
        "Policy allowed decisions and persisted completions are separate. The source query must establish persistence and app-to-web linkage; this renderer never infers completion from an allow decision.": "Dashboard success = policy allowed (policy response status allow). It does not establish a persisted email update; app-to-web confirmation linkage is supplied by the source query.",
    }
    for old, new in replacements.items():
        text = text.replace(old, new)
    return _dashboard_success_words(text)


def normalize_dashboard_markdown_labels(text):
    return _dashboard_success_words(text.replace("Successes are persisted completions; policy allowed is a separate series.", "Dashboard success = policy allowed (policy response status allow); it does not establish a persisted email update."))


def _csv(path, rows, preferred):
    fields = list(preferred) + sorted({key for row in rows for key in row} - set(preferred))
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({key: json.dumps(value, ensure_ascii=False, sort_keys=True) if isinstance(value, (dict, list)) else value for key, value in row.items()})


def _replace_section(text, section):
    if MARKER_START in text and MARKER_END in text:
        before, tail = text.split(MARKER_START, 1)
        _, after = tail.split(MARKER_END, 1)
        return before + MARKER_START + "\n" + section + "\n" + MARKER_END + after
    block = MARKER_START + "\n" + section + "\n" + MARKER_END + "\n"
    return text.replace("</main>", block + "</main>", 1) if "</main>" in text else text + "\n" + block


def append_cohort_report(out_dir, document, asofutc, dashboard_success_policy_allowed=False):
    """Write extension artifacts and idempotently append to an existing report.

    Existing core counts and risk-majority logic are untouched. The main status
    becomes PARTIAL when cohort coverage is unavailable or explicitly partial.
    Set dashboard_success_policy_allowed=True only for a policy-allow source.
    """
    directory = Path(out_dir)
    directory.mkdir(parents=True, exist_ok=True)
    summary = summarize_cohort(document, asofutc)
    _csv(directory / "cohort_devices.csv", summary["devices"], ("device_id", "user_id", "cohort", "eligible", "exclusion_reason", *SIGNALS, "latest_observed_at", "first_positive_at", "last_positive_at", "valid_callbacks", "app_access_evaluated", "missing_reason"))
    _csv(directory / "cohort_metrics.csv", summary["metrics"], ("cohort", "signal", "all_eligible_devices", "observed_devices", "positive_devices", "negative_devices", "unknown_devices", "positive_share_all_eligible", "positive_share_observed", "coverage_share"))
    (directory / "cohort_summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False, allow_nan=False) + "\n", encoding="utf-8")
    (directory / "cohort_summary.md").write_text(cohort_markdown(summary), encoding="utf-8")
    (directory / "cohort_report.html").write_text(standalone_html(summary), encoding="utf-8")
    main_json = directory / "summary.json"
    if main_json.exists():
        report = json.loads(main_json.read_text(encoding="utf-8"))
        report["cohort_monitor"] = summary
        if summary["status"] != "AVAILABLE":
            report["status"] = "PARTIAL"
            warning = "Play Integrity device-cohort extraction is unavailable or partial; see cohort coverage metadata"
            report["warnings"] = sorted(set(report.get("warnings", []) + [warning]))
        if dashboard_success_policy_allowed:
            configure_dashboard_labels(report)
        main_json.write_text(json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False) + "\n", encoding="utf-8")
    main_html = directory / "report.html"
    if main_html.exists():
        text = main_html.read_text(encoding="utf-8")
        if dashboard_success_policy_allowed:
            text = normalize_dashboard_html_labels(text)
        if summary["status"] != "AVAILABLE":
            for old_status in ("OK", "ALERT"):
                text = text.replace(f'<h1>HK trend monitor <span class="badge">{old_status}</span>', '<h1>HK trend monitor <span class="badge">PARTIAL</span>', 1)
        main_html.write_text(_replace_section(text, cohort_html_section(summary)), encoding="utf-8")
    main_md = directory / "summary.md"
    if main_md.exists():
        text = main_md.read_text(encoding="utf-8")
        if dashboard_success_policy_allowed:
            text = normalize_dashboard_markdown_labels(text)
        if summary["status"] != "AVAILABLE":
            for old_status in ("OK", "ALERT"):
                text = text.replace("HK trend monitor — " + old_status, "HK trend monitor — PARTIAL", 1)
        main_md.write_text(_replace_section(text, cohort_markdown(summary)), encoding="utf-8")
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--as-of", required=True, help="ISO UTC or offset timestamp")
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--dashboard-success-policy-allowed", action="store_true")
    args = parser.parse_args(argv)
    document = json.loads(args.input.read_text(encoding="utf-8"))
    summary = append_cohort_report(args.out_dir, document, args.as_of, args.dashboard_success_policy_allowed)
    print(json.dumps({"status": summary["status"], "unique_devices": summary["unique_devices"], "report": str(args.out_dir / "cohort_report.html")}))


if __name__ == "__main__":
    main()

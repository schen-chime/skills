#!/usr/bin/env python3
"""Render an as-of HK campaign report from read-only Snowflake JSON results.

Input rows have RECORD_TYPE and PAYLOAD (an object or JSON object string).
Statement result lists may be nested. Recognized types: MEMBER, IP, HOURLY,
COVERAGE, ALERT, RISK. Payload keys are case-insensitive. Source timestamps
must be ISO 8601; naive source timestamps are explicitly interpreted as UTC.
The user cutoff is a local YYYY-MM-DD HH:MM or ISO datetime with an offset.

No database, network, scheduling, or message-sending functions are used.
"""

import argparse
import csv
import html
import ipaddress
import json
import math
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

UTC = timezone.utc
HOURS = 168
STREAMS = {
    "hk": "Email confirmations from Hong Kong",
    "bad_device": "Email confirmations from campaign device IDs",
    "app_to_web": "App-initiated updates with web confirmations",
}
METRICS = tuple(
    f"{stream}_{metric}"
    for stream in STREAMS
    for metric in ("attempts", "successes", "allowed")
) + ("app_initiations",)
MEMBER_FIELDS = (
    "user_id", "membership_kind", "first_qualified_at", "evidence_event_at",
    "reasons", "annotated_today", "registry_diff_status", "status"
)
IP_FIELDS = (
    "ip", "country", "countries", "connection_type", "isp", "attempts", "allowed",
    "persisted_successes", "accounts", "outlook_accounts", "outlook_share",
    "qualification_accounts", "qualification_outlook_accounts", "qualification_outlook_share",
    "first_seen", "last_seen", "first_qualified_at", "campaign_first_known_at",
    "missing_geo", "country_variants", "geo_observed_at", "seeded_optional",
)
RECOGNIZED_TYPES = {"MEMBER", "IP", "HOURLY", "COVERAGE", "ALERT", "RISK"}


def iso_utc(value):
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def source_time(value, field="timestamp"):
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise ValueError(f"{field} must be an ISO timestamp string")
    try:
        instant = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"Invalid {field}: {value!r}") from exc
    # Snowflake TIMESTAMP_NTZ result values are UTC only when the producer
    # follows the documented contract. Never interpret them in host local time.
    if instant.tzinfo is None:
        instant = instant.replace(tzinfo=UTC)
    return instant.astimezone(UTC)


def parse_cutoff(value, timezone_name="America/Chicago", now=None):
    """Validate minute precision, local DST, and a nonfuture selected instant."""
    zone = ZoneInfo(timezone_name)
    if not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?:Z|[+-]\d{2}:\d{2})?", value
    ):
        raise ValueError("--as-of must be YYYY-MM-DD HH:MM (24-hour) or include an ISO UTC offset")
    try:
        instant = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"Invalid --as-of value: {value!r}") from exc
    if instant.tzinfo is None:
        candidates = []
        for fold in (0, 1):
            candidate = instant.replace(tzinfo=zone, fold=fold)
            back = candidate.astimezone(UTC).astimezone(zone)
            if back.replace(tzinfo=None) == instant:
                if all(candidate.utcoffset() != c.utcoffset() for c in candidates):
                    candidates.append(candidate)
        if not candidates:
            raise ValueError("Selected local time does not exist during the DST transition")
        if len(candidates) > 1:
            raise ValueError("Selected local time is ambiguous; include an explicit UTC offset")
        instant = candidates[0]
    instant = instant.astimezone(UTC)
    now = now or datetime.now(UTC)
    if now.tzinfo is None:
        raise ValueError("The comparison clock must have a UTC offset")
    if instant > now.astimezone(UTC):
        raise ValueError("Selected cutoff is in the future")
    return instant, zone


def _lower_keys(value):
    return {str(k).lower(): v for k, v in value.items()}


def records_from_json(document):
    """Flatten Snow CLI's nested multi-statement lists without counting twice."""
    if isinstance(document, list):
        for item in document:
            yield from records_from_json(item)
    elif isinstance(document, dict):
        keys = _lower_keys(document)
        if "record_type" in keys:
            kind = str(keys["record_type"]).upper()
            payload = keys.get("payload")
            if isinstance(payload, str):
                try:
                    payload = json.loads(payload)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"{kind} PAYLOAD is not valid JSON") from exc
            if not isinstance(payload, dict):
                raise ValueError(f"{kind} PAYLOAD must be a JSON object")
            yield kind, _lower_keys(payload)
        else:
            # Accommodate {data: [...]}, {rows: [...]}, and structured result
            # wrappers. Ordinary metadata scalars cannot be mistaken for rows.
            for value in document.values():
                if isinstance(value, (list, dict)):
                    yield from records_from_json(value)


def _as_bool(value):
    if value is True or value == 1 or (isinstance(value, str) and value.lower() == "true"):
        return True
    if value is False or value == 0 or (isinstance(value, str) and value.lower() == "false"):
        return False
    return None


def _count(value, field):
    if value is None:
        return None
    if isinstance(value, bool):
        raise ValueError(f"{field} must be a nonnegative integer, not boolean")
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be a nonnegative integer") from exc
    if not math.isfinite(number) or number < 0 or not number.is_integer():
        raise ValueError(f"{field} must be a nonnegative integer")
    return int(number)


def _reasons(value):
    if value is None:
        return set()
    if isinstance(value, list):
        return {str(v) for v in value if v is not None and str(v)}
    return {str(value)} if str(value) else set()


def _member_sort(row):
    return (source_time(row["first_qualified_at"]), len(row["user_id"]), row["user_id"])


def _normalize_members(rows, cutoff, day_start, registry_available, warnings):
    recorded, candidates = {}, {}
    excluded = 0
    for row in rows:
        user_id = str(row.get("user_id", "")).strip()
        if not user_id or user_id.lower() == "none":
            raise ValueError("MEMBER requires user_id")
        kind = str(row.get("membership_kind") or "").lower()
        if kind not in {"recorded", "candidate"}:
            raise ValueError("MEMBER requires membership_kind='recorded' or 'candidate'")
        first = source_time(row.get("first_qualified_at"), "first_qualified_at")
        evidence = source_time(row.get("evidence_event_at"), "evidence_event_at")
        if first is None:
            raise ValueError(f"MEMBER {user_id} requires first_qualified_at")
        if kind == "candidate" and evidence is None:
            raise ValueError(f"Candidate MEMBER {user_id} requires evidence_event_at")
        if first >= cutoff or (evidence is not None and evidence >= cutoff):
            excluded += 1
            continue
        normalized = {
            "user_id": user_id,
            "membership_kind": kind,
            "first_qualified_at": iso_utc(first),
            "evidence_event_at": iso_utc(evidence) if evidence else "",
            "reasons": _reasons(row.get("reasons")),
            "annotated_today": False,
            "registry_diff_status": "verified" if registry_available else "provisional: registry unavailable",
            "status": str(row.get("status") or ("recorded campaign annotation" if kind == "recorded" else "proposed campaign addition")),
        }
        members = recorded if kind == "recorded" else candidates
        # Candidate additions concern fresh same-day evidence, irrespective of
        # whether that user had an earlier unrecorded qualifying observation.
        if kind == "candidate" and evidence < day_start:
            continue
        old = members.get(user_id)
        if old is None:
            members[user_id] = normalized
        else:
            combined = old["reasons"] | normalized["reasons"]
            # Earliest qualifying evidence controls membership; stable ties
            # avoid dependence on Snowflake result ordering.
            choose = min(
                (old, normalized),
                key=lambda x: (
                    source_time(x["first_qualified_at"] if kind == "recorded" else x["evidence_event_at"]),
                    source_time(x["first_qualified_at"]), source_time(x["evidence_event_at"]) or datetime.min.replace(tzinfo=UTC), x["status"],
                ),
            )
            choose["reasons"] = combined
            members[user_id] = choose
    if excluded:
        warnings.append(f"Excluded {excluded} MEMBER records with evidence at or after the cutoff")
    for row in list(recorded.values()) + list(candidates.values()):
        row["reasons"] = "; ".join(sorted(row["reasons"]))
    prior = sorted((r for r in recorded.values() if source_time(r["first_qualified_at"]) < day_start), key=_member_sort)
    today = sorted((r for r in recorded.values() if source_time(r["first_qualified_at"]) >= day_start), key=_member_sort)
    prior_ids = {r["user_id"] for r in prior}
    today_ids = {r["user_id"] for r in today}
    new = sorted((r for r in candidates.values() if r["user_id"] not in prior_ids), key=_member_sort)
    for row in today:
        row["annotated_today"] = True
    for row in new:
        if row["user_id"] in today_ids:
            row["annotated_today"] = True
            row["status"] = "already annotated on selected day"
    # Registry records win in the union; their first_qualified_at is the
    # annotation timestamp, whereas candidate timestamps describe eligibility.
    union = {r["user_id"]: r for r in new}
    union.update(recorded)
    ordered = sorted(union.values(), key=_member_sort)
    return ordered, prior, new, today


def _normalize_ips(rows, cutoff, day_start, warnings):
    ips = {}
    excluded = 0
    for row in rows:
        value = row.get("ip")
        if value is None or value == "":
            warnings.append("An IP record had no IP address and was omitted")
            continue
        try:
            address = str(ipaddress.ip_address(str(value).strip()))
        except ValueError as exc:
            raise ValueError(f"Invalid IP result value: {value!r}") from exc
        normalized = {field: row.get(field) for field in IP_FIELDS}
        normalized["ip"] = address
        country = str(row.get("country") or "UNKNOWN").strip().upper()
        normalized["country"] = country if country not in {"", "NULL", "NONE"} else "UNKNOWN"
        normalized["countries"] = sorted({value.strip().upper() for value in _reasons(row.get("countries")) if value.strip()})
        times = {}
        for field in ("first_seen", "last_seen", "first_qualified_at", "campaign_first_known_at", "geo_observed_at"):
            instant = source_time(row.get(field), field)
            times[field] = instant
            normalized[field] = iso_utc(instant) if instant else ""
        if any(v is not None and v >= cutoff for v in times.values()):
            excluded += 1
            continue
        for field in ("attempts", "allowed", "persisted_successes", "accounts", "outlook_accounts",
                      "qualification_accounts", "qualification_outlook_accounts", "missing_geo", "country_variants"):
            normalized[field] = _count(row.get(field), field)
        for field in ("outlook_share", "qualification_outlook_share"):
            if row.get(field) is not None:
                share = float(row[field])
                if not math.isfinite(share) or not 0 <= share <= 1:
                    raise ValueError(f"{field} must be between 0 and 1")
                normalized[field] = share
        normalized["seeded_optional"] = _as_bool(row.get("seeded_optional"))
        old = ips.get(address)
        if old is not None and old != normalized:
            # Aggregate results must already be one row per IP. Summing here
            # could double-count overlapping statement outputs.
            raise ValueError(f"Conflicting IP aggregates for {address}")
        ips[address] = normalized
    if excluded:
        warnings.append(f"Excluded {excluded} IP aggregates containing timestamps at or after the cutoff")
    ordered = sorted(ips.values(), key=lambda x: (ipaddress.ip_address(x["ip"]).version, int(ipaddress.ip_address(x["ip"]))))
    prior_countries = {
        r["country"] for r in ordered
        if r["country"] != "UNKNOWN" and r["first_qualified_at"]
        and source_time(r["first_qualified_at"]) < day_start
    }
    new_ips = [r for r in ordered if r["first_qualified_at"] and day_start <= source_time(r["first_qualified_at"]) < cutoff]
    new_countries = sorted({r["country"] for r in new_ips if r["country"] != "UNKNOWN"} - prior_countries)
    return ordered, new_ips, new_countries


def _normalize_hourly(rows, cutoff, zone, complete, warnings):
    start = cutoff - timedelta(hours=HOURS)
    buckets = {}
    excluded = 0
    for row in rows:
        instant = source_time(row.get("bucket_start"), "bucket_start")
        if instant is None:
            raise ValueError("HOURLY requires bucket_start")
        if instant >= cutoff:
            excluded += 1
            continue
        if instant < start:
            continue
        hours = (instant - start).total_seconds() / 3600
        if not hours.is_integer():
            raise ValueError("HOURLY bucket_start must align to the selected cutoff's elapsed-hour grid")
        index = int(hours)
        normalized = {metric: _count(row.get(metric), metric) for metric in METRICS}
        # A result cannot have more allowed/completed events than attempts.
        for stream in STREAMS:
            attempts = normalized[f"{stream}_attempts"]
            for metric in ("successes", "allowed"):
                count = normalized[f"{stream}_{metric}"]
                if attempts is not None and count is not None and count > attempts:
                    raise ValueError(f"{stream}_{metric} exceeds {stream}_attempts")
        old = buckets.get(index)
        if old is not None and old != normalized:
            raise ValueError(f"Conflicting HOURLY aggregates for {iso_utc(instant)}")
        buckets[index] = normalized
    if excluded:
        warnings.append(f"Excluded {excluded} HOURLY records at or after the cutoff")
    output = []
    missing = 0
    for index in range(HOURS):
        instant = start + timedelta(hours=index)
        present = index in buckets
        if not present:
            missing += 1
        values = buckets.get(index, {metric: 0 if complete else None for metric in METRICS})
        output.append({
            "bucket_start": iso_utc(instant),
            "bucket_end": iso_utc(instant + timedelta(hours=1)),
            "hour_local": instant.astimezone(zone).isoformat(timespec="minutes"),
            "source_row_present": present,
            **values,
        })
    if not complete and missing:
        warnings.append(f"{missing}/168 hours have no source row and remain unknown because extraction_complete is not true")
    unknown_metrics = [metric for metric in METRICS if metric != "app_initiations" and any(row[metric] is None for row in output)]
    if unknown_metrics:
        warnings.append("Some hourly values are unknown: " + ", ".join(unknown_metrics))
    return output


def _risk_summary(rows, new_users, cutoff, warnings):
    new = {r["user_id"]: source_time(r["evidence_event_at"] or r["first_qualified_at"]) for r in new_users}
    groups = defaultdict(lambda: {
        "observed": set(), "triggered": set(), "missing_reasons": set(),
        "events": set(), "eligibility": set(), "sources": set(),
        "device_links": set(), "coverage_labels": set(), "risk_mappings": set(),
    })
    for row in rows:
        signal = str(row.get("signal") or "unspecified_signal")
        scope = str(row.get("scope") or "unspecified_scope")
        group = groups[(signal, scope)]
        user_id = str(row.get("user_id", "")).strip()
        if user_id not in new:
            continue
        # A risky provisional association is visible, but cannot establish a
        # common-risk alert. Missing eligibility is deliberately not permission
        # to promote a raw label or unvalidated device association.
        group["eligibility"].add(_as_bool(row.get("majority_eligible")) is True)
        for field, target in (("source", "sources"), ("device_link", "device_links"),
                              ("coverage", "coverage_labels"), ("risk_mapping", "risk_mappings")):
            if row.get(field) is not None:
                group[target].add(str(row[field]))
        if row.get("missing_reason"):
            group["missing_reasons"].add(str(row["missing_reason"]))
        at = source_time(row.get("observed_at"), "observed_at")
        # Seven-day lookback relative to each join, always censored at T.
        if at is None or not (new[user_id] - timedelta(days=7) <= at < cutoff):
            continue
        risky = _as_bool(row.get("risky"))
        if risky is None:
            continue
        group["observed"].add(user_id)
        if risky:
            group["triggered"].add(user_id)
        group["events"].add((user_id, str(row.get("device_id") or ""), iso_utc(at), risky))
    # Always retain the requested tracker, even when its source is absent.
    if not any(
        "playintegrity" in re.sub(r"[^a-z]", "", signal.lower()) or "unlock" in scope.lower()
        for signal, scope in groups
    ):
        groups[("play_integrity_unlock", "unavailable_unlock_tracker")]["missing_reasons"].add("No Play Integrity unlock RISK records supplied")
    denominator = len(new)
    output = []
    for signal, scope in sorted(groups):
        group = groups[(signal, scope)]
        observed = len(group["observed"])
        triggered = len(group["triggered"])
        status = "NOT_APPLICABLE" if denominator == 0 else ("AVAILABLE" if observed else "UNAVAILABLE")
        eligible = group["eligibility"] == {True}
        output.append({
            "signal": signal, "scope": scope, "new_users": denominator,
            "observable_users": observed, "triggered_users": triggered,
            "unobservable_users": denominator - observed,
            "share_of_all_new_users": triggered / denominator if denominator else None,
            "coverage_share": observed / denominator if denominator else None,
            "share_of_observed_users": triggered / observed if observed else None,
            "majority_eligible": eligible,
            "majority_of_new_users": eligible and denominator > 0 and triggered * 2 > denominator,
            "status": status, "distinct_usable_events": len(group["events"]),
            "missing_reasons": sorted(group["missing_reasons"]),
            **{field: sorted(group[field]) for field in ("sources", "device_links", "coverage_labels", "risk_mappings")},
            "observation_window": "[same-day candidate evidence - 7 days, selected cutoff); source query may narrow this window",
        })
    return output


TELEMETRY_COUNT_FIELDS = (
    "authn_registrations", "authn_devices", "usable_registrations", "ambiguous_registrations",
    "mapped_vendor_callbacks", "unmapped_vendor_callbacks", "http_error_or_unknown_callbacks",
    "invalid_json_callbacks", "missing_token_payload_callbacks", "vendor_user_conflict_callbacks",
    "callbacks_with_stable_id_variants", "valid_pi_callbacks", "apps_detected_array_callbacks",
    "device_verdict_array_callbacks", "pi_devices", "unlock_events", "android_unlock_events",
    "direct_device_prior_pi_unlocks", "unlocks_without_mapped_prior_pi", "confirmed_unlock_pi_links",
    "provisional_unlock_pi_links",
)


def _telemetry_summary(rows, new_users, cutoff, warnings):
    """Keep per-user and run-level PI coverage, including error denominators."""
    new_ids = {r["user_id"] for r in new_users}
    users, run_metadata = {}, []
    for row in rows:
        if row.get("user_id") is None:
            if row not in run_metadata:
                run_metadata.append(row)
            continue
        user_id = str(row["user_id"])
        if user_id not in new_ids:
            continue
        normalized = dict(row, user_id=user_id)
        # A cutoff field may equal T. Actual observation timestamps cannot.
        if any(source_time(row.get(field), field) is not None and source_time(row.get(field), field) >= cutoff
               for field in ("first_vendor_observed_at", "last_vendor_observed_at", "last_unlock_observed_at")):
            warnings.append(f"Excluded future-contaminated telemetry coverage for user {user_id}")
            continue
        for field in TELEMETRY_COUNT_FIELDS:
            if field in normalized:
                normalized[field] = _count(normalized[field], field)
        if user_id in users and users[user_id] != normalized:
            raise ValueError(f"Conflicting per-user COVERAGE aggregates for {user_id}")
        users[user_id] = normalized
    counts = {
        field: sum(row.get(field) or 0 for row in users.values())
        for field in TELEMETRY_COUNT_FIELDS
        if any(field in row for row in users.values())
    }
    observed = lambda field: sum((row.get(field) or 0) > 0 for row in users.values())
    return {
        "all_new_users": len(new_ids), "new_users_with_coverage_rows": len(users),
        "new_users_without_coverage_rows": len(new_ids) - len(users),
        "users_with_valid_pi_callbacks": observed("valid_pi_callbacks"),
        "users_with_app_access_array": observed("apps_detected_array_callbacks"),
        "users_with_unlock_events": observed("unlock_events"),
        "users_with_confirmed_unlock_pi_links": observed("confirmed_unlock_pi_links"),
        "users_with_provisional_unlock_pi_links": observed("provisional_unlock_pi_links"),
        "event_totals": counts,
        "per_user": sorted(users.values(), key=lambda x: (len(x["user_id"]), x["user_id"])),
        "run_metadata": run_metadata,
        "absence_semantics": "Missing, malformed, HTTP-error, or unmapped telemetry is unknown; it is never a clean verdict",
    }


def build_report(document, as_of, timezone_name="America/Chicago", now=None):
    cutoff, zone = parse_cutoff(as_of, timezone_name, now=now)
    local = cutoff.astimezone(zone)
    day_start = local.replace(hour=0, minute=0, second=0, microsecond=0).astimezone(UTC)
    by_type = defaultdict(list)
    warnings = []
    for kind, payload in records_from_json(document):
        if kind not in RECOGNIZED_TYPES:
            warnings.append(f"Unrecognized result record type {kind!r} was ignored")
        else:
            by_type[kind].append(payload)
    if not any(by_type.values()):
        raise ValueError("Input contains no recognized RECORD_TYPE/PAYLOAD result rows")
    coverage, telemetry_rows = {}, []
    for row in by_type["COVERAGE"]:
        if "key" not in row:
            telemetry_rows.append(row)
            continue
        key = str(row["key"])
        if key in coverage and coverage[key] != row.get("value"):
            raise ValueError(f"Conflicting COVERAGE values for {key}")
        coverage[key] = row.get("value")
    declared_cutoffs = [coverage["cutoff"]] if coverage.get("cutoff") else []
    declared_cutoffs.extend(row["cutoff"] for row in telemetry_rows if row.get("cutoff"))
    if any(source_time(value, "source cutoff") != cutoff for value in declared_cutoffs):
        raise ValueError("Source query cutoff differs from --as-of; rerun or select the matching cutoff")
    complete = _as_bool(coverage.get("extraction_complete")) is True
    if not complete:
        warnings.append("Source extraction is partial or unverified; missing data is not evidence of zero activity")
    registry_available = _as_bool(coverage.get("current_registry_available")) is True
    if not registry_available:
        warnings.append("Campaign annotation registry is unavailable or unverified; the prior list is unknown and candidate differences are provisional")
    members, prior, new, recorded_today = _normalize_members(by_type["MEMBER"], cutoff, day_start, registry_available, warnings)
    if new and _as_bool(coverage.get("risk_query_available")) is not True:
        warnings.append("Play Integrity/unlock query is unavailable or unverified; risk telemetry for proposed additions is incomplete")
    ips, new_ips, new_countries = _normalize_ips(by_type["IP"], cutoff, day_start, warnings)
    event_alerts_available = _as_bool(coverage.get('campaign_activity_alerts_available')) is True
    if event_alerts_available:
        # Event-level country history is authoritative. An IP's latest country
        # at cutoff cannot establish when that country first joined a campaign.
        new_countries = sorted({str(r['country']).upper() for r in by_type['ALERT']
                                if r.get('key') == 'new_campaign_country' and r.get('country')})
    hourly = _normalize_hourly(by_type["HOURLY"], cutoff, zone, complete, warnings)
    risk = _risk_summary(by_type["RISK"], new, cutoff, warnings)
    telemetry = _telemetry_summary(telemetry_rows, new, cutoff, warnings)
    alerts = []
    if new_ips and not event_alerts_available:
        alerts.append({
            "kind": "new_campaign_ip", "message": f"{len(new_ips)} campaign IPs first qualified on the selected day before the cutoff",
            "ips": [r["ip"] for r in new_ips],
        })
    if new_countries and not event_alerts_available:
        alerts.append({
            "kind": "new_campaign_country", "message": "New countries in IP qualification results: " + ", ".join(new_countries),
            "countries": new_countries,
            "basis": "Countries of IPs first qualified on the selected day, compared with IP countries qualified before the selected day; event-level source alerts may add detail",
        })
    for row in risk:
        if row["majority_of_new_users"]:
            alerts.append({
                "kind": "common_risky_signal", "signal": row["signal"],
                "scope": row["scope"],
                "message": f"{row['signal']} [{row['scope']}]: {row['triggered_users']}/{row['new_users']} new users triggered the risky signal; telemetry usable for {row['observable_users']}/{row['new_users']}",
            })
    for row in by_type["ALERT"]:
        # SQL alerts carry their evidence beside the key, rather than in a
        # generic value field. Preserve the complete payload, including future
        # evidence fields, and surface it in the human-readable report too.
        evidence = {key: value for key, value in row.items() if key != "key"}
        if row.get('key') == 'new_campaign_ip':
            message = f"New IP in campaign activity: {row.get('ip')}; {row.get('attempts')} attempts, {row.get('successes')} persisted successes; first seen {row.get('first_seen')}."
        elif row.get('key') == 'new_campaign_country':
            message = f"New country in campaign activity: {row.get('country')}; {row.get('accounts')} users; first seen {row.get('first_seen')}."
        elif row.get('key') == 'new_candidate_hk_ip':
            message = f"Newly qualified HK/datacenter IP: {row.get('ip')}; {row.get('qualification_outlook_accounts')}/{row.get('qualification_accounts')} users with persisted Outlook changes; qualified {row.get('first_qualified_at')}."
        else:
            message = str(row.get('key', 'source alert')) + ': ' + json.dumps(evidence, ensure_ascii=False, sort_keys=True)
        alerts.append({"kind": "source_alert", "key": row.get("key"), "evidence": dict(row),
                       "message": message})
    # Extract-level missingness affects every component, while individual
    # unavailable risk sources are made visible in their own output section.
    status = "PARTIAL" if not complete or warnings else ("ALERT" if alerts else "OK")
    return {
        "status": status, "has_alerts": bool(alerts),
        "as_of_utc": iso_utc(cutoff), "as_of_local": local.isoformat(timespec="minutes"),
        "timezone": timezone_name, "selected_day_start_utc": iso_utc(day_start),
        "hourly_start_utc": iso_utc(cutoff - timedelta(hours=HOURS)),
        "bucket_count": HOURS, "extraction_complete": complete,
        "current_registry_available": registry_available,
        "counts": {"prior_users": len(prior) if registry_available else None, "new_users": len(new), "all_users": len(members) if registry_available else None, "recorded_today": len(recorded_today) if registry_available else None, "ips": len(ips)},
        "prior_users": prior, "new_users": new, "all_users": members,
        "recorded_today": recorded_today,
        "ips": ips, "new_ips": new_ips, "new_countries": new_countries,
        "hourly": hourly, "risk_signals": risk, "alerts": alerts,
        "coverage": coverage, "telemetry_coverage": telemetry, "warnings": sorted(set(warnings)),
        "definitions": {
            "prior_users": "Recorded campaign annotations strictly before selected-day local midnight; unknown when registry unavailable",
            "new_users": "Candidate evidence at/after selected-day local midnight and strictly before cutoff, excluding users annotated before the selected day; already-annotated-today users are flagged",
            "recorded_today": "First recorded campaign annotation on the selected day before cutoff",
            "all_users": "Recorded campaign annotations as of cutoff union proposed same-day candidates, with membership kind retained; no registry is modified",
            "histogram": "168 elapsed-hour bins ending at selected cutoff; UTC arithmetic; labels include local UTC offset",
            "successes": "Persisted email-update completions supplied by source query; never inferred from policy allow",
            "allowed": "Policy allowed decisions; not proof of email update persistence",
            "risk_majority": "Within one signal and scope explicitly majority_eligible=true: strictly more than 50% of all same-day new campaign users; unknown telemetry does not reduce denominator; provisional associations cannot alert",
            "source_timestamps": "ISO source timestamps without offsets are interpreted as UTC under the producer contract",
            "historical_replay": "Event-time reconstruction; historical availability is proven only if the source query supplies ingestion/snapshot provenance",
            "campaign_membership": "Recorded campaign annotations and evidence-based proposed additions are separate; risk-tracker rows never add campaign users",
        },
    }


def _csv(path, fields, rows):
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def _percent(value):
    return "not applicable" if value is None else f"{value:.1%}"


def _number(value):
    return "unknown" if value is None else f"{value:,}"


def summary_markdown(report):
    lines = [
        f"HK trend monitor — {report['status']}", "",
        f"Selected cutoff: **{report['as_of_local']} ({report['timezone']})**; UTC {report['as_of_utc']}.",
        f"Recorded campaign users before the selected day: **{_number(report['counts']['prior_users'])}**.",
        f"Candidate users to add on the selected day before cutoff: **{_number(report['counts']['new_users'])}** (provisional if registry unavailable; annotated-today users are flagged).",
        f"First recorded annotations on the selected day: **{_number(report['counts']['recorded_today'])}**.",
        f"Recorded users plus proposed additions as of cutoff: **{_number(report['counts']['all_users'])}**.", "",
        "The histogram contains exactly 168 elapsed-hour positions ending at the cutoff. Successes are persisted completions; policy allowed is a separate series.", "",
    ]
    if report["alerts"]:
        lines.append("Alerts:")
        lines.extend(f"- {row['message']}" for row in report["alerts"])
    else:
        lines.append("No configured campaign-change or majority-risk alerts were produced from the supplied results.")
    lines.extend(["", "Risk trackers (provisional scopes cannot trigger majority alerts):", "", "| Signal / scope | Triggered / all new users | Telemetry coverage | Among observed | Majority eligible | Status |", "|---|---:|---:|---:|---|---|"])
    for row in report["risk_signals"]:
        lines.append(f"| {row['signal'].replace('|', '/')} / {row['scope'].replace('|', '/')} | {row['triggered_users']}/{row['new_users']} ({_percent(row['share_of_all_new_users'])}) | {row['observable_users']}/{row['new_users']} | {_percent(row['share_of_observed_users'])} | {row['majority_eligible']} | {row['status']} |")
    telemetry = report["telemetry_coverage"]
    lines.extend([
        "", f"Play Integrity/unlock coverage: {telemetry['new_users_with_coverage_rows']}/{telemetry['all_new_users']} new users have coverage rows; {telemetry['users_with_valid_pi_callbacks']} have valid PI callbacks; {telemetry['users_with_unlock_events']} have unlock events; {telemetry['users_with_confirmed_unlock_pi_links']} have confirmed PI/unlock device links; {telemetry['users_with_provisional_unlock_pi_links']} have provisional links.",
        "Telemetry event/error totals: " + json.dumps(telemetry["event_totals"], sort_keys=True) + ".",
        telemetry["absence_semantics"] + ".",
    ])
    if report["warnings"]:
        lines.extend(["", "Data limitations:"])
        lines.extend("- " + warning for warning in report["warnings"])
    lines.extend([
        "", "Files: report.html, prior_users.csv, new_users.csv, recorded_today.csv, all_users.csv, ips.csv, hourly.csv, hourly_168_columns.csv, risk_signals.csv, telemetry_coverage.csv, summary.json.",
        "", "Recorded annotations and proposed additions are separate; no campaign registry is modified. Proposed additions are not ATO confirmations. Risk signals do not create campaign membership.",
        "Historical results are event-time reconstructions unless source ingestion/snapshot provenance establishes historical availability.",
    ])
    return "\n".join(lines) + "\n"


def _html_table(rows, fields, limit=200):
    esc = lambda x: html.escape("" if x is None else str(x))
    table = "<table><thead><tr>" + "".join(f"<th>{esc(field)}</th>" for field in fields) + "</tr></thead><tbody>"
    for row in rows[:limit]:
        table += "<tr>" + "".join(f"<td>{esc(row.get(field))}</td>" for field in fields) + "</tr>"
    table += "</tbody></table>"
    if len(rows) > limit:
        table += f"<p>Showing the first {limit} of {len(rows)} rows. Download the CSV for the full list.</p>"
    if not rows:
        table += "<p>No rows in this result.</p>"
    return table


def report_html(report):
    esc = html.escape
    payload = json.dumps({"hourly": report["hourly"], "streams": STREAMS}, ensure_ascii=False).replace("<", "\\u003c")
    alert_items = "".join(f"<li>{esc(r['message'])}</li>" for r in report["alerts"])
    warning_items = "".join(f"<li>{esc(w)}</li>" for w in report["warnings"])
    risks = []
    for row in report["risk_signals"]:
        risks.append({
            "signal": row["signal"], "scope": row["scope"], "triggered / all new": f"{row['triggered_users']}/{row['new_users']} ({_percent(row['share_of_all_new_users'])})",
            "telemetry coverage": f"{row['observable_users']}/{row['new_users']}",
            "among observed": _percent(row["share_of_observed_users"]), "status": row["status"],
            "majority eligible": row["majority_eligible"], "majority": "YES" if row["majority_of_new_users"] else "", "missing reason": "; ".join(row["missing_reasons"]),
            "device links": "; ".join(row["device_links"]),
            "coverage labels": "; ".join(row["coverage_labels"]),
        })
    coverage = json.dumps({"extraction": report["coverage"], "telemetry": report["telemetry_coverage"]}, indent=2, ensure_ascii=False)
    prior_table = _html_table(report["prior_users"], MEMBER_FIELDS)
    new_table = _html_table(report["new_users"], MEMBER_FIELDS)
    recorded_today_table = _html_table(report["recorded_today"], MEMBER_FIELDS)
    ip_table = _html_table(report["ips"], IP_FIELDS)
    risk_table = _html_table(risks, ("signal", "scope", "triggered / all new", "telemetry coverage", "among observed", "majority eligible", "status", "majority", "device links", "coverage labels", "missing reason"))
    telemetry = report["telemetry_coverage"]
    options = "".join(f'<option value="{key}">{esc(value)}</option>' for key, value in STREAMS.items())
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>HK trend monitor — {esc(report['as_of_local'])}</title>
<style>
:root{{color-scheme:light;--ink:#172b4d;--muted:#50647c;--line:#dce5ee;--blue:#1768ac}}*{{box-sizing:border-box}}body{{margin:0;background:#f4f7fb;color:var(--ink);font:15px/1.5 system-ui,sans-serif}}main{{max-width:1280px;margin:32px auto;padding:0 24px 48px}}h1{{font-size:28px;margin-bottom:6px}}h2{{font-size:20px}}.muted{{color:var(--muted)}}.card{{background:white;border:1px solid var(--line);border-radius:12px;padding:20px;margin:18px 0}}.kpis{{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px}}.kpi{{background:white;border:1px solid var(--line);border-radius:10px;padding:18px}}.kpi strong{{display:block;font-size:32px}}.badge{{display:inline-block;border-radius:6px;background:#e9eef7;padding:3px 9px;font-size:14px}}.chart-scroll{{overflow:auto;border:1px solid var(--line);border-radius:8px}}#chart{{display:block;min-width:1100px;width:100%;height:320px}}select{{max-width:100%;font:inherit;padding:7px;border:1px solid #9badbf;border-radius:5px;margin:4px 12px 12px 0}}table{{border-collapse:collapse;width:100%;font-size:12px}}th,td{{text-align:left;vertical-align:top;border-bottom:1px solid var(--line);padding:8px;overflow-wrap:anywhere}}th{{background:#f5f8fc}}.table-scroll{{overflow:auto}}summary{{cursor:pointer;font-weight:650}}a{{color:var(--blue)}}pre{{white-space:pre-wrap;font-size:12px}}.limit{{border-left:4px solid #c67d16;padding-left:14px}}@media(max-width:650px){{.kpis{{grid-template-columns:1fr}}main{{padding:0 12px}}select{{display:block;margin-right:0}}}}
</style></head><body><main>
<h1>HK trend monitor <span class="badge">{esc(report['status'])}</span></h1>
<p class="muted">Selected cutoff: {esc(report['as_of_local'])} · {esc(report['timezone'])}<br>UTC cutoff: {esc(report['as_of_utc'])}. All intervals exclude the cutoff.</p>
<div class="kpis"><div class="kpi">Recorded users before selected day<strong>{_number(report['counts']['prior_users'])}</strong><a href="prior_users.csv" download>Download list</a></div><div class="kpi">Candidate additions on selected day<strong>{_number(report['counts']['new_users'])}</strong><a href="new_users.csv" download>Download candidates</a></div><div class="kpi">Recorded users plus proposed additions<strong>{_number(report['counts']['all_users'])}</strong><a href="all_users.csv" download>Download union</a></div></div>
<section class="card"><h2>Campaign changes and alerts</h2>{'<ul>' + alert_items + '</ul>' if alert_items else '<p>No configured campaign-change or majority-risk alerts were produced.</p>'}
{'<div class="limit"><strong>Data limitations</strong><ul>' + warning_items + '</ul></div>' if warning_items else ''}</section>
<section class="card"><h2>Hourly volume — 168 columns</h2>
<p class="muted">Seven elapsed days ending at the selected cutoff. Each bar spans one hour; local labels include the UTC offset. A minute cutoff anchors minute-offset bins. Gray gaps mean unknown; known zero hours have no height.</p>
<label for="stream">Stream </label><select id="stream">{options}</select><label for="metric">Measure </label><select id="metric"><option value="attempts">Attempts</option><option value="successes">Persisted successes</option><option value="allowed">Policy allowed</option></select>
<div class="chart-scroll"><svg id="chart" role="img" aria-label="168 hourly volume columns"></svg></div><p id="chart-note" class="muted"></p>
<p><a href="hourly.csv" download>Hourly data (168 rows)</a> · <a href="hourly_168_columns.csv" download>Wide data (168 hour columns)</a></p>
<p class="muted">Policy allowed decisions and persisted completions are separate. The source query must establish persistence and app-to-web linkage; this renderer never infers completion from an allow decision.</p></section>
<section class="card"><h2>Common risky signals among new additions</h2><p>Highlight threshold: strictly more than 50% of all new users, within one signal and scope explicitly eligible for majority alerts. Provisional associations and raw labels cannot trigger an alert. Missing telemetry remains in the denominator. Risk observations use [candidate evidence − 7 days, cutoff), subject to a narrower source query.</p><div class="table-scroll">{risk_table}</div>
<p>Telemetry coverage rows: {telemetry['new_users_with_coverage_rows']}/{telemetry['all_new_users']} new users. Valid PI callbacks: {telemetry['users_with_valid_pi_callbacks']} users. Unlock events: {telemetry['users_with_unlock_events']} users. Confirmed PI/unlock links: {telemetry['users_with_confirmed_unlock_pi_links']} users; provisional links: {telemetry['users_with_provisional_unlock_pi_links']} users.</p><p><a href="telemetry_coverage.csv" download>Per-user telemetry coverage and errors</a></p><pre>{esc(json.dumps(telemetry['event_totals'], indent=2))}</pre><p class="muted">{esc(telemetry['absence_semantics'])}.</p></section>
<section class="card"><h2>IP query results</h2><p><a href="ips.csv" download>Download full IP list</a>. New-country alerts use event-level campaign activity when supplied; IP qualification and observation history are retained separately.</p><div class="table-scroll">{ip_table}</div></section>
<details class="card"><summary>Users to add on the selected day ({len(report['new_users']):,})</summary><div class="table-scroll">{new_table}</div></details>
<details class="card"><summary>Recorded users before the selected day ({_number(report['counts']['prior_users'])})</summary><div class="table-scroll">{prior_table}</div></details>
<details class="card"><summary>First annotations on the selected day ({_number(report['counts']['recorded_today'])})</summary><p><a href="recorded_today.csv" download>Download annotation list</a>. Candidate rows already annotated today are flagged, so they do not need another annotation.</p><div class="table-scroll">{recorded_today_table}</div></details>
<details class="card"><summary>Source coverage and provenance</summary><pre>{esc(coverage)}</pre><p>Recorded annotations and proposed additions are separate; no campaign registry is modified. Candidate additions are not ATO confirmations. Risk-tracker records do not add campaign users. Historical results are event-time reconstructions unless ingestion/snapshot provenance establishes historical availability. Naive source timestamps are interpreted as UTC.</p></details>
<p class="muted">Local report. No messages, recurring jobs, or database writes are performed.</p>
</main><script id="report-data" type="application/json">{payload}</script><script>
"use strict";
const data=JSON.parse(document.getElementById("report-data").textContent);
const svg=document.getElementById("chart"), NS="http://www.w3.org/2000/svg";
function node(tag,attrs,text){{const el=document.createElementNS(NS,tag);for(const[k,v]of Object.entries(attrs))el.setAttribute(k,String(v));if(text!==undefined)el.textContent=text;return el;}}
function render(){{
 const stream=document.getElementById("stream").value,metric=document.getElementById("metric").value,key=stream+"_"+metric;
 const values=data.hourly.map(row=>row[key]),known=values.filter(v=>v!==null),peak=Math.max(1,...known),width=Math.max(1100,svg.parentElement.clientWidth),height=320,left=30,bottom=250,step=(width-left-10)/168;
 svg.replaceChildren();svg.setAttribute("viewBox",`0 0 ${{width}} ${{height}}`);
 for(let j=0;j<=4;j++){{const y=bottom-j*50;svg.append(node("line",{{x1:left,y1:y,x2:width,y2:y,stroke:"#e1e7ef"}}));svg.append(node("text",{{x:2,y:y+4,"font-size":10,fill:"#50647c"}},Math.round(peak*j/4)));}}
 data.hourly.forEach((row,i)=>{{const value=values[i],h=value===null?3:(value/peak)*200;
 const rect=node("rect",{{x:left+i*step+1,y:bottom-h,width:Math.max(1,step-2),height:h,fill:value===null?"#aebbc9":"#1768ac","data-hour":i}});
 rect.append(node("title",{{}},`${{row.hour_local}} | ${{key}}: ${{value===null?"UNKNOWN":value}}`));svg.append(rect);
 if(i%(width<2000?24:12)===0||i===167)svg.append(node("text",{{x:left+i*step+4,y:bottom+14,transform:`rotate(35 ${{left+i*step+4}} ${{bottom+14}})`,"font-size":10,fill:"#50647c"}},row.hour_local));
 }});
 const unknown=168-known.length,total=known.reduce((a,b)=>a+b,0);
 document.getElementById("chart-note").textContent=`${{data.streams[stream]}} · ${{metric}} · ${{total}} in observed bins · ${{unknown}}/168 unknown hours. Hover over a column for its exact hour and value.`;
}}
document.getElementById("stream").addEventListener("change",render);document.getElementById("metric").addEventListener("change",render);window.addEventListener("resize",render);render();
</script></body></html>"""


def write_report(report, out_dir):
    directory = Path(out_dir)
    directory.mkdir(parents=True, exist_ok=True)
    for key in ("prior_users", "new_users", "recorded_today", "all_users"):
        _csv(directory / f"{key}.csv", MEMBER_FIELDS, report[key])
    _csv(directory / "ips.csv", IP_FIELDS, report["ips"])
    _csv(directory / "hourly.csv", ("bucket_start", "bucket_end", "hour_local", "source_row_present") + METRICS, report["hourly"])
    # Metric rows plus exactly 168 hour columns; the label column is separate.
    hours = [row["hour_local"] for row in report["hourly"]]
    wide = [{"metric": metric, **{row["hour_local"]: row[metric] for row in report["hourly"]}} for metric in METRICS]
    _csv(directory / "hourly_168_columns.csv", ("metric", *hours), wide)
    risk_fields = ("signal", "scope", "new_users", "observable_users", "triggered_users", "unobservable_users", "share_of_all_new_users", "coverage_share", "share_of_observed_users", "majority_eligible", "majority_of_new_users", "status", "distinct_usable_events", "missing_reasons", "sources", "device_links", "coverage_labels", "risk_mappings", "observation_window")
    risks = [{**row, **{field: "; ".join(row[field]) for field in ("missing_reasons", "sources", "device_links", "coverage_labels", "risk_mappings")}} for row in report["risk_signals"]]
    _csv(directory / "risk_signals.csv", risk_fields, risks)
    telemetry_rows = report["telemetry_coverage"]["per_user"]
    telemetry_fields = ["user_id"] + sorted({field for row in telemetry_rows for field in row} - {"user_id"})
    _csv(directory / "telemetry_coverage.csv", telemetry_fields, telemetry_rows)
    (directory / "summary.json").write_text(json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False) + "\n", encoding="utf-8")
    (directory / "summary.md").write_text(summary_markdown(report), encoding="utf-8")
    (directory / "report.html").write_text(report_html(report), encoding="utf-8")
    return directory / "report.html"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path, help="Snow CLI JSON result file")
    parser.add_argument("--as-of", required=True, help="Selected date and 24-hour time, YYYY-MM-DD HH:MM")
    parser.add_argument("--timezone", default="America/Chicago", help="IANA timezone for naive cutoff and display")
    parser.add_argument("--out-dir", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        document = json.loads(args.input.read_text(encoding="utf-8"))
        report = build_report(document, args.as_of, args.timezone)
        output = write_report(report, args.out_dir)
    except (ValueError, OSError, KeyError) as exc:
        parser.error(str(exc))
    print(summary_markdown(report))
    print(f"Report: {output.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

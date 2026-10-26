---
name: hk-trend-monitor
description: Monitor the HK email-change campaign at a selected date and 24-hour time. Return the prior recorded campaign members, same-day proposed additions, 168 hourly volume buckets, reproducible IP results, infrastructure alerts, and Play Integrity/unlock risk trackers.
---

# HK trend monitor

Read-only investigation and reporting. Run when asked to check the HK trend, refresh campaign membership, examine HK/known-browser email changes, or compare app initiation with web completion. This skill does not schedule itself, send Slack messages, change account controls, or write campaign annotations.

## Input and time contract

Required: a date and 24-hour time, `YYYY-MM-DD HH:MM`. Default timezone: `America/Chicago`; honor an explicitly supplied IANA timezone or UTC offset. Example:

```text
$hk-trend-monitor 2026-10-26 14:00 America/Chicago
```

The selected instant is **T, the exclusive as-of cutoff**, not the start of a future observation window. Let **D** be midnight at the start of the selected date in the reporting timezone.

- **Current campaign list before the selected date:** members whose first recorded campaign annotation is before D.
- **Users proposed for addition on the selected date:** qualifying observed email-change activity in `[D,T)`, excluding members annotated before D. Flag candidates already annotated during `[D,T)`; also return `recorded_today.csv` so they are not actioned twice.
- **Hourly graph:** exactly 168 consecutive elapsed-hour buckets in `[T−168 hours,T)`, oldest to newest. A cutoff at 14:30 produces 168 full 60-minute buckets ending at 14:30. UTC arithmetic and local labels with offsets prevent DST duplicate/missing-hour errors. `hourly_168_columns.csv` has one metric-label column plus exactly 168 hour columns.
- Events at T are excluded. Reject future cutoffs and nonexistent local times; require an explicit offset for an ambiguous DST time.

The campaign history starts at `2026-07-01 00:00 UTC` by default, matching the existing HK monitor's searched campaign period. Set `--campaign-start` earlier when needed. It must cover the entire chart window and intended campaign history. Display the searched bounds; absence outside them is unknown.

## Execute

Use the existing official Snowflake CLI and configured `env` connection. Never call, enable, or start Snowflake MCP, alter connection/authentication configuration, or repeatedly retry authentication. The runner uses the existing read role and warehouse as session settings; override `--role`/`--warehouse` only when the caller's environment requires it. Empty values preserve the configured session settings.

Use Python 3.9+ with standard library `zoneinfo` and installed timezone data. The package has no Python package-install step. From the installed skill directory, run:

```bash
python3 scripts/run_monitor.py --as-of "2026-10-26 14:00" --timezone America/Chicago --out-dir /tmp/hk-trend-20261026-1400
```

Resolve `scripts/` and `queries/` relative to this `SKILL.md`; use absolute paths when invoking from another directory. Choose a private writable output directory. Each run retains generated SQL, raw CLI JSON/error files, a cutoff/SQL-hash manifest, and derived results. No results are uploaded.

To give a teammate a runnable query, generate SQL without connecting:

```bash
python3 scripts/run_monitor.py --as-of "2026-10-26 14:00" --timezone America/Chicago --out-dir /tmp/hk-trend-query --prepare-only
snow sql -c env -f /tmp/hk-trend-query/main.sql --format JSON > /tmp/hk-trend-query/main.json
python3 scripts/render_report.py --input /tmp/hk-trend-query/main.json --as-of "2026-10-26 14:00" --timezone America/Chicago --out-dir /tmp/hk-trend-query
```

The main query returns the actual IP list as `RECORD_TYPE='IP'` rows. The renderer writes `ips.csv`; **show that query result**, including IP, country, provider, attempts, allows, persisted successes, account count, Outlook numerator/share, first/last observation, and qualification timestamp. Export the first-threshold `qualification_accounts`, `qualification_outlook_accounts`, and `qualification_outlook_share` separately from the all-history IP aggregates. An empty IP result is a valid finding, not a reason to skip the remaining trackers. A main-only teammate run explicitly lacks the risk query; use the full runner for Play Integrity/unlock results.

### Resources

- [Runner](scripts/run_monitor.py): validates input, prepares parameters, calls `snow`, runs the lower-priority risk query for proposed additions, and renders results.
- [Main SQL](queries/monitor.sql): campaign registry, dynamic IP discovery, hourly metrics, candidate additions, and infrastructure alerts.
- [Play Integrity SQL](queries/play_integrity.sql): same-device/registration PI signals, actual unlock events, and missing-source diagnostics.
- [Renderer](scripts/render_report.py): standalone interactive HTML, full CSV lists, 168-column export, and strict majority alerts.

## Definitions that must stay distinct

| Output | Definition and limitation |
|---|---|
| Attempt | One production email-verification-link decision, deduplicated by member and non-null decision ID, with a composite fallback. Policy rows are not separate attempts; a shared request ID is not a cross-member deduplication key. |
| Allowed | An unconflicted observed `allow` outcome. Keep it separate from persisted success. |
| Success | A real email audit transition uniquely associated with a click in both directions within ±10 seconds. This is strong user/time correlation, not an exact workflow-key join. Ambiguous/unmatched audit pairs stay unknown, not successful. |
| HK email updates | Web confirmation context `email_verification_email_change` whose preceding IP GeoIP observation reports `HK`. Device timezone alone never establishes country. A known campaign IP without current geo coverage is not automatically HK. |
| Known-bad-device tracker | Campaign-linked browser IDs supported by persisted HK/datacenter/Outlook activity on an annotated campaign member. Freeze qualification before D and require the indicator's evidence timestamp no later than each counted event. These are reported browser identifiers, not attested hardware/person identities. |
| App → web | Web click with the latest same-user app `in_app_email_verification_check` in the preceding 30 minutes. Count each click once and preserve candidate multiplicity. It is a temporal association unless a common workflow key is independently verified. This path is normal for many members and alone does not add them to the campaign. |
| Current campaign member | Recorded Penny annotation on a user resource matching the existing campaign marker. Do not return note content. The first annotation time is not compromise time. Current note text may have been edited; no historical warehouse/annotation-version availability is asserted. |
| Proposed addition | Persisted activity on a pre-day campaign-linked device; persisted Outlook change on a pre-day campaign IP; or persisted Outlook change from newly qualified HK/datacenter infrastructure. These are review candidates, not confirmed ATOs or automatic annotation writes. |

Never silently substitute policy allows for successes. Do not filter out real consumer web confirmations because `DEVICE_PLATFORM` is `invalid`; the producer context identifies this flow. The three hourly streams overlap and should not be summed as unique total events.

## Infrastructure discovery and alert evidence

The reproducible discovery rule requires at least **15 distinct confirmation users** and an **80% Outlook share** for HK/datacenter event observations. The denominator includes all observed users, including those without uniquely attributable persisted Outlook changes, so the share is conservative. Qualification occurs only when cumulative evidence crosses the threshold; later evidence cannot backdate an indicator. This is a discovery heuristic, not a fraud verdict.

Return campaign-linked IPs and candidate IPs separately through their evidence fields. GeoIP uses the latest same-IP observation at or before each event, no older than 45 days; same-time conflicts, staleness and missing countries remain unknown. Avoid a full-window modal country that would use future observations for earlier events.

Report:

- New IPs or countries first seen in the selected-day campaign activity, including activity on existing campaign users or known browsers outside HK. Explain whether the observation could be recovery/legitimate activity; geography does not identify an actor.
- Newly threshold-qualified HK/datacenter IPs and their evidence counts; do not silently declare them confirmed bad infrastructure.
- Missing/stale/conflicting GeoIP, ambiguous audit matches, conflicting decision attributes, and multiple potential app initiations.
- Material hourly spikes/drops visible in the 168-hour graph, with explicit comparison periods and denominators. Do not invent a production alert threshold or call an empty/inaccessible source zero activity.

## Play Integrity and unlock risk tracker

Include this lower-priority tracker by default for the proposed additions. It does not create campaign membership. Read the query's mapping comments before changing signal classification.

- Join production AUTHN's exact member/device/registration evidence to `VENDOR_PLAY_INTEGRITY` callbacks. Preserve anonymous vendor user 0 through the validated registration association; quarantine shared/conflicting registrations, conflicting callback variants, and failed/unparseable callbacks.
- Show six nullable standardized signals: controlling, capturing, overlays, harmful Play Protect verdict, unrecognized app, and device integrity below this monitor's documented threshold. Report raw verdicts as metadata. `INSTALLED` alone and absence of optional strong-integrity attestation are not risk triggers. Empty/unevaluated fields remain unknown.
- Use actual `ACCESS_TYPE_UNLOCKED` events. A device's biometry/security capability does not establish the method used for an unlock. Link only same-user/same-verified-device PI before the unlock, with a seven-day freshness bound. The current direct-string namespace association is **provisional**; it is visible but excluded from confirmed unlock-linked majority alerts until a source bridge is validated.
- Standard PI risks remain reportable independently of unlock linkage. Label the observation scope and time relative to the campaign activity; an earlier detection is not proof of malicious control during that activity. The query does not verify token request binding or historical ingestion availability.
- **If a risky signal affects more than 50% of all newly proposed users, mention it prominently in the final output.** Use distinct users, not callbacks or unlock counts. Show `triggered / all additions`, telemetry coverage, observed-only prevalence, and unknowns. Exactly 50% is not a majority. Missing telemetry never shrinks the all-additions denominator. Raw metadata and provisional associations cannot trigger this alert.

Signal semantics: [Android integrity verdicts](https://developer.android.com/google/play/integrity/verdicts) and [app access risk remediation](https://developer.android.com/google/play/integrity/remediation). These describe risk capabilities, not proof of ATO, malware, or member consent.

## Deliverables and failure handling

Return the cutoff/timezone and source bounds, followed by:

1. The current user-ID list before the selected date (`prior_users.csv`) and count.
2. Proposed new user IDs for the selected day up to T (`new_users.csv`), evidence reasons, and same-day annotations (`recorded_today.csv`). The union (`all_users.csv`) labels recorded versus proposed membership.
3. An interactive histogram with exactly 168 columns and selectable HK / known-device / app-to-web streams and attempts / persisted successes / allowed views. Include both `hourly.csv` and `hourly_168_columns.csv`.
4. The actual IP query results (`ips.csv`) and all infrastructure/country/volume alerts with dates and evidence.
5. Play Integrity and unlock tracker results, highlighting any majority risky signal, with coverage and limitations. Include `risk_signals.csv`, telemetry coverage, `summary.json`, `summary.md`, and `report.html`.

User-ID and infrastructure lists stay in private local run artifacts. Public skill/PR contents contain queries and synthetic tests, not production result lists, IP/device seed lists, notes, or contact PII. Do not send a Slack draft/message or schedule recurring runs merely because the skill is named a monitor.

On main-query/authentication/network failure, preserve the error and stop without repeated sign-in attempts. On a lower-priority PI query failure, preserve the primary report and mark risk telemetry unavailable/partial. If the campaign registry is inaccessible, do not fabricate an empty current list: a separately authorized rerun may use a supplied private registry snapshot, or a typed empty registry CTE **with** `current_registry_available=false`; candidate differences remain provisional. No row caps are permitted on exported member/IP lists.

Validate actual run counts, the prior/new split, the 168-hour grid, and the success/attempt invariant before delivery. Keep recorded annotations, candidate signals, prior ATO contact labels, and adjudicated fraud separate. A historical run is an event-time reconstruction unless source availability/version history independently proves point-in-time knowledge.

## Package checks

Run `python3 -m unittest discover -s tests -v` from this skill directory. The tests use synthetic data and never invoke Snowflake. `tests/pi_truth_table.sql` is an optional read-only VALUES query for verifying nullable integrity semantics through an existing Snowflake session; it reads no production tables.

---
name: hk-trend-monitor
description: Run the HK email monitor using the existing Hex dashboard logic at a selected date and 24-hour time. Return campaign lists, 168 hourly columns, IP results, and four hourly Google Play Integrity signal volumes on qualified campaign login attempts, with baseline comparison notes.
---

# HK trend monitor

Use the published [HK Email Monitor](https://chime.hex.tech/global/app/HK-Email-Monitor-034ml6ptI5Uj50iMHuMDD0/latest) as the authority for the email-monitor logic. Add Play Integrity tracking for the whole monitored cohort even when there are zero new additions. Analysis is read-only; do not send messages, schedule runs, change controls, or annotate accounts.

## Input and execution

Required input: `YYYY-MM-DD HH:MM` in 24-hour time. Default reporting timezone: `America/Chicago`; honor an explicit timezone or offset. T is the exclusive cutoff and D is local midnight of that date. Reject future/nonexistent times; ambiguous DST times need an explicit offset. The graph has exactly 168 elapsed-hour buckets in `[T−168h,T)`, including minute-aligned cutoffs.

From the installed skill directory, run:

```bash
python3 scripts/run_dashboard_monitor.py --as-of "2026-10-26 10:00" --timezone America/Chicago --out-dir /tmp/hk-trend-20261026-1000
```

Resolve resources relative to this file. Use a private writable output directory. Use the existing official Snowflake CLI `env` connection; never enable Snowflake MCP, alter authentication configuration, or retry failed authentication. Use the existing Hex CLI login to export the latest published project. If browser access is needed for dashboard edits, use the Hex skill and preserve the existing base queries.

`--dashboard-export /private/path/dashboard.hex.yaml` uses an already exported private source instead of contacting Hex. `--prepare-only` writes teammate-runnable SQL without querying Snowflake. `--campaign-start` defaults to `2026-07-01` UTC and must cover the entire chart/history window. `--baseline-limit` defaults to 5,000 (validated range 1–10,000).

The runner records dashboard project/version IDs, SQL/export hashes, bounds and query artifacts. The [dashboard adapter](scripts/dashboard_adapter.py) validates the reviewed source-cell identities and fingerprints; changed filters or flow logic require review rather than silently falling back to the old monitor. Runtime known-IP values are read from the dashboard and never stored in public skill code.

## Dashboard definitions

Preserve these rules when adapting the cutoff and display timezone:

- HK: non-shadow USER_SERVICE email-confirmation rows whose modal GeoIP is HK **or** whose IP is in the dashboard's configured known list. Attempts retain the dashboard's row grain.
- Known browsers: any browser seen confirming from a configured known IP since July 1 through T. This is the dashboard's whole-window retrospective browser set; do not substitute annotation-gated or frozen-before-day membership.
- App → web: live risk-decision-log records (`evaluation_target='general'`), first web confirmation per member/requested email in the source window, with an app request for that same email/member in the preceding 35 minutes. Never return requested email addresses.
- **Dashboard success means policy allowed.** Label it “Dashboard success (policy allowed)”; it does not prove a persisted email change. Do not mix these counts with the previous audit-linked completion metric.
- Preserve the dashboard's 60-day and 14-day source horizons and modal geography windows, while exporting exactly the selected 168 hours. Modal geography and whole-window browser membership are retrospective definitions, not point-in-time knowledge.

The previous standalone `run_monitor.py` / `queries/monitor.sql` implement different audit-persistence/discovery rules and are retained as legacy resources. They are not the default for this skill.

## Campaign and IP outputs

Return full CSVs, without row caps:

1. `prior_users.csv`: recorded Penny user-resource campaign annotations before D.
2. `new_users.csv`: allowed selected-day confirmations on dashboard known IPs/browsers, excluding pre-day recorded members. These are review proposals; preserve same-day annotation flags and `recorded_today.csv`. `all_users.csv` keeps recorded/proposed membership distinct.
3. `report.html`, `hourly.csv` (168 rows), and `hourly_168_columns.csv` (168 hour columns plus metric label).
4. The **actual IP query result** in `ips.csv`, including IP, country/provider, attempts/allows, accounts and first/last observations. Unsupported persistence/Outlook fields stay unknown. Include `main.sql` so teammates can reproduce the list with their own authorized connection.
5. New campaign IP/country observations relative to the searched pre-day history, plus factual volume comparisons with explicit periods. Geography may reflect legitimate recovery/member activity; it does not identify an actor.

The PI cohort is the union of recorded campaign members and users with allowed dashboard-linked confirmations since the searched history start. Keep this operational membership separate from adjudicated ATO labels. Source annotation edit/ingestion history is not asserted.

## Google Play Integrity tracking

Run [cohort_play_integrity.sql](queries/cohort_play_integrity.sql) for the full cohort independently of additions. The primary PI output is **four hourly campaign login-attempt volume graphs**, each with exactly 168 elapsed-hour buckets:

1. UNKNOWN_CONTROLLING: non-Play/other-profile controlling.
2. KNOWN_CONTROLLING: Play/system-known controlling.
3. Known-only controlling: KNOWN present and UNKNOWN absent.
4. Any controlling: either signal.

A qualified login is a production Android AUTHN `atom_event` / `member_logins` attempt, with a real `ACCOUNT_ACCESS_ATTEMPT_ID`, one positive member, one SDK device and one live decision. Exclude `atom_model` inference-only rows, deduplicate policy/stage rows by attempt ID, and anchor at the earliest live evaluation. Count attempts irrespective of allow/success. The first login row must carry the member and SDK device. The four signals overlap; never sum their totals.

For each attempt use the latest valid HTTP-2xx/object PI callback on its **exact registration/member/SDK device**, observed at or before login and no more than **24 hours old**. The attempt registration must already be present at its first evaluation, and mapping evidence must exist by login. A missing/ambiguous registration stays unknown. Scan PI and mapping evidence 24 hours before the chart start to avoid losing early-window observations. Later callbacks and later-only registrations cannot qualify an earlier login. This is a recent PI-state association, not verified attestation-request binding or proof the login itself generated the callback.

Keep the latest unevaluated verdict unknown instead of substituting an older positive. Quarantine conflicting same-time verdicts, stable-ID variants and observed ownership conflicts. Exact enum positives remain usable with future enum values; negative classification requires a nonempty fully recognized array. Missing, malformed, unmapped and stale telemetry stays unknown. Zero positive volume is distinct from zero telemetry coverage.

Use the existing unique ownership/device safeguards and Android app-open registration bridge. Whole-window device/registration ownership checks can conservatively exclude attempts using later conflict evidence; label that retrospective exclusion. They cannot create a positive from future PI or mapping evidence. Operational campaign membership is also retrospective and is not an adjudicated ATO label.

For comparison use the same-window deterministic bounded sample of other active Android devices, excluding campaign owners. Count their qualified login attempts using the identical attempt and PI rules. **Baseline belongs in notes, not the volume graph series.** If a signal's campaign positive/evaluated-attempt rate exceeds baseline, report counts, rates, denominators and coverage as a descriptive note, not a significance or causal claim. Do not compare raw campaign/baseline volumes across differently sized populations.

Export `login_pi_hourly.csv`, `login_pi_summary.json`, and four volume graphs in `report.html`. Validate 1,344 cohort/hour/signal rows, unique keys, triggered≤evaluated≤qualified, unknown=qualified−evaluated, and group/overall coverage totals before plotting. Missing extraction or buckets produce visible gaps/unavailable status. Device-snapshot CSVs and the cohort prevalence section remain secondary diagnostics, not a substitute for login-attempt volume. The separate strictly-more-than-50%-of-all-new-users alert and unlock tracker still apply to additions.

### Historical context to retain separately

The original investigation found UNKNOWN_CONTROLLING on **145/908 = 16.0%**, versus **39/4,165 = 0.9%** in sampled other Android phone changers (about 17×). Its grain was one selected phone-change request per member, using the latest prior AUTHN-mapped verdict with environment details, without a freshness cap; original populations were 1,259 and 5,893, with median verdict ages 16 and 3 days. These are fixed historical measurements, not current live rates or the same device-snapshot method.

Known-only controlling showed little difference: **61/908 = 6.7% versus 283/4,165 = 6.8%**. Those known-only figures exclude verdicts also containing UNKNOWN; do not relabel them as all KNOWN_CONTROLLING.

UNKNOWN_CONTROLLING was observed **around takeover in 9/9 selected end-to-end reviews**. This was not a random sample or nine positive pre-action checks: four first-positive observations followed the change amid observation gaps. Keep this selected-case evidence separate from population prevalence and live alert denominators.

A Play Store app acting as a lure/downloader for a separate controller is a hypothesis. PI does not identify the app, prove malware/ATO, or establish who controlled the phone. KNOWN includes system-preloaded apps, and apps in another device profile may receive UNKNOWN regardless of install source. See [Google's verdict definitions](https://developer.android.com/google/play/integrity/verdicts).

## Validation and failures

Validate source provenance, prior/new disjointness, 168 buckets, allow≤attempt invariants, unique-device aggregation and per-signal denominators before delivery. Report missing data and searched bounds. A completed extraction does not prove source ingestion freshness.

Stop on primary Hex/Snowflake access/authentication failure, preserving errors. If lower-priority cohort/new-user telemetry fails, retain primary outputs and show unavailable/partial risk coverage; do not repeat sign-in or return a clean verdict. Keep historical context visible without substituting it for live measurements.

Public skill/PR contents contain implementation and synthetic tests, not production result lists, IP/device seeds, note content or contact PII. Local exports/results remain private. Run `python3 -m unittest discover -s tests -v` from the installed package for offline checks.

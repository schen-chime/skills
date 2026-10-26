---
name: hk-trend-monitor
description: Monitor the HK email-change campaign at a selected date and 24-hour time, with prior members, proposed additions, 168 hourly buckets, reproducible IP results, infrastructure alerts, and Play Integrity/unlock risk trackers.
---

# HK trend monitor

The installable skill is [hk-trend-monitor/SKILL.md](hk-trend-monitor/SKILL.md). Read it before running; its bundled queries and scripts are required. This entry supersedes `hk-email-monitor`.

Copy the **entire `hk-trend-monitor/` folder**, including `scripts/`, `queries/`, and `agents/`, into `~/.codex/skills/hk-trend-monitor/` (or `~/.claude/skills/hk-trend-monitor/`). Do not install this entry file alone.

## Input

Supply `YYYY-MM-DD HH:MM` in 24-hour time. The default timezone is `America/Chicago`; provide an explicit timezone or UTC offset when needed.

```text
$hk-trend-monitor 2026-10-26 14:00 America/Chicago
```

The selected instant **T** is an exclusive cutoff; **D** is midnight at the start of its local date. The histogram covers `[T − 168 hours, T)`, so a historical input anchors the report to that historical instant. Future cutoffs and invalid local times are rejected; ambiguous DST times require an explicit offset.

## Output

1. Recorded campaign user IDs before D, with a full CSV list.
2. Users proposed for addition during `[D,T)`, evidence reasons, and flags for users already annotated that day. Recorded and proposed membership remain separate.
3. An interactive histogram with exactly **168 hourly columns** and CSV exports for HK, known campaign device IDs, and app-initiated/web-completed email updates. Each stream exposes attempts, persisted successes, and policy allows separately.
4. The actual query-generated IP list with country, provider, counts, Outlook-share denominators, observation times, and qualification times; alerts for new IPs/countries in campaign activity and newly qualified infrastructure.
5. Play Integrity and actual unlock risk trackers for proposed additions, including missing-telemetry coverage. A risky signal affecting **more than 50% of all proposed additions** is highlighted. Raw metadata and provisional unlock/device associations cannot trigger a confirmed majority alert.

## Run

Requires Python 3.9+ and the existing official Snowflake CLI connection. From the cloned repository:

```bash
python3 hk-trend-monitor/scripts/run_monitor.py --as-of "2026-10-26 14:00" --timezone America/Chicago --out-dir /tmp/hk-trend-20261026-1400
```

Use `--prepare-only` to create a teammate-runnable `main.sql` without querying. It returns the actual IP list as `RECORD_TYPE='IP'` rows. The full runner additionally executes the lower-priority Play Integrity/unlock query for proposed additions and writes standalone HTML plus full CSV/JSON results.

Read [the canonical skill](hk-trend-monitor/SKILL.md) for membership/discovery rules, source limits, exact success/app-to-web definitions, risk mappings, error handling, and tests. Queries reconstruct event-time history; historical source availability and annotation edit history are not asserted. Proposed additions require review and do not modify the campaign.

Read-only analysis: no messages, recurring jobs, control changes, authentication retries, or Snowflake MCP. Production query results and member/IP/device seed lists remain in private local run artifacts.

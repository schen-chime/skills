---
name: hk-email-monitor
description: Run the HK email-change monitor for the ddw / Hong Kong ATO campaign. Every run reports the latest 72 hours up to now against the 7 days before: email-change confirmations from Hong Kong (attempts and allowed, including new HK IPs), confirmations from known bad browsers (including outside Hong Kong), and in-app email requests finished on web. Use when asked to check, monitor or refresh the HK email trend.
---

# HK email-change monitor

Read-only monitor for the ddw / Hong Kong email-change campaign. Each run covers the latest 72 hours up to the moment it runs and compares them with the 7 days before. It never sends a message.

The runnable version (query, runner, summary script and full field notes) lives in the private repo `schen-chime/projects` under `.claude/commands/hk-email-monitor/`. Ask Siyu Chen for access. This file is the shareable overview.

## Run

```
~/.claude/commands/hk-email-monitor/run.sh
```

- Runs one read-only Snowflake query through the `snow` CLI. Never call, enable or re-enable a Snowflake MCP tool.
- Sets the analyst role itself, because a fresh sign-in can come up with the wrong role.
- Saves `hourly.json` and `summary.md` under `~/hk_email_monitor/runs/<date_time PT>/`.
- If Snowflake asks for a sign-in or errors, retry at most once, then report the error and stop.

## What the report shows

For the latest 72 hours, the last 24 hours, and the per-day rate against the 7 days before:
- Email-change confirmations from Hong Kong, attempted and allowed, and how many came from Hong Kong IPs not seen before in the campaign.
- Confirmations from browsers already tied to the campaign, and how many of those came from outside Hong Kong.
- In-app email requests that were finished on web, split by where the web click came from (outside the US, a datacenter, Hong Kong). Finishing on web is normal for many members, so the splits are what matter.

A by-day table follows. The first line of the output is `STATUS: OK`, `STATUS: ALERT` (with the alert lines) or `STATUS: SNOWFLAKE_ERROR`.

## Reporting

- `STATUS: OK`: show the summary and say nothing tripped.
- `STATUS: ALERT`: show the summary and alert lines. If a Slack note is wanted, create a draft in the user's own DM only and send it only after the user approves the exact text.
- Keep reports free of member IDs, phone numbers and email addresses.

Not covered: unlocks with a Play Integrity signal.

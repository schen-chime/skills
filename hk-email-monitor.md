---
name: hk-email-monitor
description: Run the HK email-change monitor for the ddw / Hong Kong ATO campaign. Every run reports the latest 72 hours up to now against the 7 days before - email-change confirmations from Hong Kong (attempts and allowed, including new HK IPs), confirmations from known bad browsers (including outside Hong Kong), and in-app email requests finished on web (split by outside-US, datacenter and Hong Kong clicks). Use when asked to check, monitor or refresh the HK email trend.
---

# HK Email-Change Monitor

Read-only monitor for the ddw / Hong Kong email-change campaign. Each run covers the latest 72 hours up to the moment it runs and compares them with the 7 days before. It never sends a message.

## Input

None. Every run uses the latest 72 hours. Step 1 finds the campaign's HK IPs from the data, so there is nothing to set up.

## Requirements

- The `snow` CLI with a connection named `env`, run through Bash. Never call, enable or re-enable a Snowflake MCP tool.
- Access to the `SNOWFLAKE_PROD_ANALYST_OKTA` role and the `ANALYTICS_WH` warehouse.
- Python 3.

---

## Step 1 — Find the campaign's HK IPs

The campaign confirms its email changes from a few Hong Kong datacenter IPs, and almost every new email it sets is an outlook.com address. Run this query to list them. It looks at email-change confirmation clicks over the last 120 days and keeps IPs that geolocate to Hong Kong, are datacenter connections, confirmed email changes for 15 or more accounts, and set outlook.com on at least 80% of them. That last check keeps out other Hong Kong operations that don't use Outlook.

Write it to a temp file (for example `/tmp/hk_ips.sql`) and run `snow sql -c env -f /tmp/hk_ips.sql --format json`:

```sql
use role SNOWFLAKE_PROD_ANALYST_OKTA; use warehouse ANALYTICS_WH;
with clk as (
  select try_to_number(u.user_id) user_id, u.original_timestamp ts, u.device_ip_address ip
  from chime.decision_platform.user_service u
  where u.original_timestamp >= dateadd('day', -120, current_timestamp()) and u.original_timestamp < current_timestamp()
    and not u.is_shadow_mode and u.update_context = 'email_verification_email_change' and u.device_ip_address is not null
),
busy as (select ip, count(distinct user_id) accts, min(ts) first_seen, max(ts) last_seen from clk group by ip having count(distinct user_id) >= 15),
geo as (
  select connection_data_ip_address ip, mode(geo_ip_data_country) country, mode(connection_data_connection_type) ctype, mode(connection_data_isp) isp
  from chime.decision_platform.device_intelligence
  where original_timestamp >= dateadd('day', -120, current_timestamp()) and connection_data_ip_address in (select ip from busy)
  group by 1
),
em as (   -- new email domain saved with each click (audit row within 10 seconds)
  select c.ip, c.user_id, max(iff(split_part(lower(trim(v.change_to)), '@', -1) = 'outlook.com', 1, 0)) to_outlook
  from clk c join busy b on b.ip = c.ip
  join analytics.looker.versions_pivot v on v.item_id = c.user_id and v.item_type = 'User' and v.object = 'email'
    and v.created_at between dateadd('second', -10, c.ts) and dateadd('second', 10, c.ts)
  group by 1, 2
)
select b.ip, b.accts as accounts, g.isp, round(avg(e.to_outlook), 3) as outlook_share,
       convert_timezone('America/Los_Angeles', b.first_seen)::date as first_seen_pt,
       convert_timezone('America/Los_Angeles', b.last_seen)::date as last_seen_pt
from busy b join geo g on g.ip = b.ip left join em e on e.ip = b.ip
where g.country = 'HK' and g.ctype = 'Data Center'
group by b.ip, b.accts, g.isp, b.first_seen, b.last_seen
having avg(e.to_outlook) >= 0.8
order by b.accts desc;
```

Show the user the IP list it returns (IP, accounts, provider, Outlook share, first and last seen). If it returns no rows, say so and stop: the campaign may have moved off Hong Kong datacenters.

Optional: if `~/.claude/hk-email-monitor/known_ips.txt` exists (one IP per line; lines starting with `#` are comments), add its IPs to the list. Check every line is a plain IPv4 or IPv6 address first.

Turn the list into a SQL values list: `('ip1'),('ip2'),...`

## Step 2 — Build and run the query

Write this file to a temp path (for example `/tmp/hk_email_monitor.sql`), replacing `{{KNOWN_HK_IPS}}` with the values list from Step 1. The first two lines set the role (a fresh sign-in can come up as PUBLIC) and the window: the latest 72 hours plus the 168 hours before them as the baseline.

```sql
use role SNOWFLAKE_PROD_ANALYST_OKTA; use warehouse ANALYTICS_WH;
set (win_start, win_end) = (dateadd('hour', -240, current_timestamp()), current_timestamp());
with known_ips as (
  select column1 ip from values {{KNOWN_HK_IPS}}
),
clk as (
  select try_to_number(user_id) user_id, original_timestamp ts, device_ip_address ip, device_id dev, decision_outcome outcome
  from chime.decision_platform.user_service
  where original_timestamp >= $win_start and original_timestamp < $win_end and not is_shadow_mode
    and pii_type = 'email' and update_context = 'email_verification_email_change'
),
req as (
  select try_to_number(user_id) user_id, original_timestamp ts, device_ip_address ip
  from chime.decision_platform.user_service
  where original_timestamp >= dateadd('minute', -30, $win_start) and original_timestamp < $win_end and not is_shadow_mode
    and pii_type = 'email' and update_context = 'in_app_email_verification_check'
),
bad_dev as (
  select distinct device_id dev
  from chime.decision_platform.user_service
  where original_timestamp >= '2026-07-01'::timestamp_tz and original_timestamp < $win_end and not is_shadow_mode
    and update_context = 'email_verification_email_change' and device_id is not null
    and device_ip_address in (select ip from known_ips)
),
geo as (
  select connection_data_ip_address ip, mode(geo_ip_data_country) country, mode(connection_data_connection_type) ctype
  from chime.decision_platform.device_intelligence
  where original_timestamp >= dateadd('day', -45, $win_end) and original_timestamp < $win_end
    and connection_data_ip_address in (select ip from clk union select ip from req)
  group by 1
),
c as (
  select k.*, date_trunc('hour', convert_timezone('America/Los_Angeles', k.ts))::timestamp_ntz hr,
    (g.country = 'HK' or k.ip in (select ip from known_ips)) is_hk,
    (g.country = 'HK' and k.ip not in (select ip from known_ips)) is_hk_new_ip,
    (k.dev in (select dev from bad_dev)) is_bad_dev,
    (g.country is not null and g.country <> 'US') is_foreign,
    (g.ctype = 'Data Center') is_dc
  from clk k left join geo g on g.ip = k.ip
),
pair as (   -- in-app request -> web confirmation click by the same member within 30 minutes
  select r.user_id, r.ts req_ts, date_trunc('hour', convert_timezone('America/Los_Angeles', r.ts))::timestamp_ntz hr,
    max(iff(c.user_id is not null, 1, 0)) web_done,
    max(iff(c.outcome = 'allow', 1, 0)) web_success,
    max(iff(c.is_foreign, 1, 0)) web_foreign,
    max(iff(c.is_dc, 1, 0)) web_dc,
    max(iff(c.is_hk, 1, 0)) web_hk
  from req r left join c on c.user_id = r.user_id and c.ts between r.ts and dateadd('minute', 30, r.ts)
  where r.ts >= $win_start
  group by 1, 2, 3
),
hc as (
  select hr,
    count_if(is_hk) hk_attempts, count_if(is_hk and outcome = 'allow') hk_successes, count(distinct iff(is_hk, user_id, null)) hk_accounts,
    count_if(is_hk_new_ip) hk_new_ip_attempts, count_if(is_hk_new_ip and outcome = 'allow') hk_new_ip_successes,
    count_if(is_bad_dev) baddev_attempts, count_if(is_bad_dev and outcome = 'allow') baddev_successes,
    count_if(is_bad_dev and not is_hk) baddev_non_hk_attempts, count_if(is_bad_dev and not is_hk and outcome = 'allow') baddev_non_hk_successes,
    count(*) all_web_clicks
  from c group by hr
),
hp as (
  select hr, count(*) app_req, sum(web_done) app_to_web, sum(web_success) app_to_web_success,
    sum(web_foreign) app_to_web_foreign, sum(web_dc) app_to_web_datacenter, sum(web_hk) app_to_web_hk
  from pair group by hr
)
select coalesce(hc.hr, hp.hr) hour_pt,
  coalesce(hk_attempts, 0) hk_attempts, coalesce(hk_successes, 0) hk_successes, coalesce(hk_accounts, 0) hk_accounts,
  coalesce(hk_new_ip_attempts, 0) hk_new_ip_attempts, coalesce(hk_new_ip_successes, 0) hk_new_ip_successes,
  coalesce(baddev_attempts, 0) baddev_attempts, coalesce(baddev_successes, 0) baddev_successes,
  coalesce(baddev_non_hk_attempts, 0) baddev_non_hk_attempts, coalesce(baddev_non_hk_successes, 0) baddev_non_hk_successes,
  coalesce(app_req, 0) app_req, coalesce(app_to_web, 0) app_to_web, coalesce(app_to_web_success, 0) app_to_web_success,
  coalesce(app_to_web_foreign, 0) app_to_web_foreign, coalesce(app_to_web_datacenter, 0) app_to_web_datacenter, coalesce(app_to_web_hk, 0) app_to_web_hk,
  coalesce(all_web_clicks, 0) all_web_clicks
from hc full outer join hp on hp.hr = hc.hr
order by 1;
```

Run it and keep the JSON:

```
snow sql -c env -f /tmp/hk_email_monitor.sql --format json > /tmp/hk_email_monitor.json
```

If Snowflake asks for a sign-in or returns an error, retry at most once, then report the error and stop.

## Step 3 — Summarize

Save this script (for example `/tmp/hk_summarize.py`) and run it with the JSON and the current Pacific time:

```
python3 /tmp/hk_summarize.py /tmp/hk_email_monitor.json "$(TZ=America/Los_Angeles date +%Y-%m-%dT%H:%M:%S)"
```

```python
# Summarize the HK email monitor: latest 72 hours up to now vs the 7 days (168 hours) before.
# Usage: summarize.py hourly.json NOW_PT   (NOW_PT like 2026-10-23T18:05:00, Pacific time)
import json, sys
from collections import defaultdict
from datetime import datetime, timedelta
path, now_s = sys.argv[1], sys.argv[2]
now = datetime.fromisoformat(now_s)
d = json.load(open(path)); d = d[-1] if d and isinstance(d[0], list) else d
cols = ['HK_ATTEMPTS','HK_SUCCESSES','HK_ACCOUNTS','HK_NEW_IP_ATTEMPTS','HK_NEW_IP_SUCCESSES','BADDEV_ATTEMPTS','BADDEV_SUCCESSES',
        'BADDEV_NON_HK_ATTEMPTS','BADDEV_NON_HK_SUCCESSES','APP_REQ','APP_TO_WEB','APP_TO_WEB_SUCCESS','APP_TO_WEB_FOREIGN','APP_TO_WEB_DATACENTER','APP_TO_WEB_HK']
w_start = now - timedelta(hours=72)
b_start = w_start - timedelta(hours=168)
last24 = now - timedelta(hours=24)
win, base, l24 = defaultdict(int), defaultdict(int), defaultdict(int)
per_day = defaultdict(lambda: defaultdict(int))
for r in d:
    h = datetime.fromisoformat(r['HOUR_PT'][:19])
    if h >= w_start:
        for c in cols: win[c] += r.get(c) or 0; per_day[h.date().isoformat()][c] += r.get(c) or 0
        if h >= last24:
            for c in cols: l24[c] += r.get(c) or 0
    elif h >= b_start:
        for c in cols: base[c] += r.get(c) or 0
b_day = {c: base[c] / 7 for c in cols}      # baseline per-day average
w_day = {c: win[c] / 3 for c in cols}       # 72-hour per-day average
alerts = []
if win['HK_NEW_IP_ATTEMPTS'] > 0: alerts.append(f"HK confirmations from new IPs not on the known list: {win['HK_NEW_IP_ATTEMPTS']} ({win['HK_NEW_IP_SUCCESSES']} allowed)")
if win['BADDEV_NON_HK_ATTEMPTS'] > 0: alerts.append(f"Known bad browsers confirming from outside Hong Kong: {win['BADDEV_NON_HK_ATTEMPTS']} ({win['BADDEV_NON_HK_SUCCESSES']} allowed)")
if b_day['HK_ATTEMPTS'] >= 5 and w_day['HK_ATTEMPTS'] >= 1.5 * b_day['HK_ATTEMPTS']: alerts.append(f"HK confirmations up: {w_day['HK_ATTEMPTS']:.0f}/day vs {b_day['HK_ATTEMPTS']:.0f}/day before")
if b_day['HK_ATTEMPTS'] >= 5 and l24['HK_ATTEMPTS'] == 0: alerts.append(f"No HK confirmations in the last 24 hours (was {b_day['HK_ATTEMPTS']:.0f}/day): paused or moved")
print(f"STATUS: {'ALERT' if alerts else 'OK'}")
print(f"HK email monitor: last 72 hours, {w_start:%b %d %H:%M} to {now:%b %d %H:%M} PT, compared with the 7 days before")
for a in alerts: print(f"- ALERT: {a}")
print()
def row(label, c, ok=None):
    s = f"- {label}: {win[c]}" + (f" ({win[ok]} allowed)" if ok else "") + f" | last 24 h {l24[c]} | {w_day[c]:.0f}/day vs {b_day[c]:.0f}/day before"
    print(s)
row('Email confirmations from Hong Kong', 'HK_ATTEMPTS', 'HK_SUCCESSES')
row('  of which from new HK IPs', 'HK_NEW_IP_ATTEMPTS', 'HK_NEW_IP_SUCCESSES')
row('Confirmations from known bad browsers', 'BADDEV_ATTEMPTS', 'BADDEV_SUCCESSES')
row('  of which outside Hong Kong', 'BADDEV_NON_HK_ATTEMPTS', 'BADDEV_NON_HK_SUCCESSES')
row('In-app email requests', 'APP_REQ')
row('  finished on web within 30 min', 'APP_TO_WEB', 'APP_TO_WEB_SUCCESS')
row('  web click from outside the US', 'APP_TO_WEB_FOREIGN')
row('  web click from a datacenter', 'APP_TO_WEB_DATACENTER')
row('  web click from Hong Kong', 'APP_TO_WEB_HK')
print()
print("By PT day (partial days at the edges):")
print("| Day | HK clicks (allowed) | new HK IPs | bad browsers (outside HK) | app req | finished on web | non-US | datacenter |")
print("|---|---|---|---|---|---|---|---|")
for k in sorted(per_day):
    x = per_day[k]
    print(f"| {k} | {x['HK_ATTEMPTS']} ({x['HK_SUCCESSES']}) | {x['HK_NEW_IP_ATTEMPTS']} | {x['BADDEV_ATTEMPTS']} ({x['BADDEV_NON_HK_ATTEMPTS']}) | {x['APP_REQ']} | {x['APP_TO_WEB']} | {x['APP_TO_WEB_FOREIGN']} | {x['APP_TO_WEB_DATACENTER']} |")
```

The first line of the output is `STATUS: OK` or `STATUS: ALERT`.

---

## What the columns mean (per PT hour)

| Column | Meaning |
|---|---|
| `hk_attempts` / `hk_successes` | Email-change confirmation clicks (the emailed link, `user_service.update_context = 'email_verification_email_change'`) from an IP in Hong Kong or on the known list. Successes = `decision_outcome = 'allow'`. |
| `hk_new_ip_*` | The same, from HK IPs not on the known list (possible IP rotation). |
| `baddev_*` | Clicks from known bad browsers: any device that ever confirmed an email change from the known IPs since Jul 1. The list grows by itself. |
| `baddev_non_hk_*` | Those browsers clicking from outside Hong Kong (moved infrastructure). |
| `app_req` | In-app email-change requests (`in_app_email_verification_check`). |
| `app_to_web*` | Requests finished by a web confirmation click within 30 minutes, split by click from outside the US, a datacenter, or Hong Kong. Finishing on web is normal for many members, so watch the splits. |

IP country and connection type come from `chime.decision_platform.device_intelligence`, looked up over the trailing 45 days.

## Alert rules

`STATUS: ALERT` when any of these hold for the latest 72 hours:
- any HK confirmation from a new IP;
- any known-bad-browser confirmation from outside Hong Kong;
- HK confirmations per day at 1.5x the daily average of the 7 days before, or more (when that average is at least 5);
- no HK confirmations in the last 24 hours (when the earlier daily average is at least 5).

## Reporting

- Show the summary: 72-hour totals, last 24 hours, per-day rate against the 7 days before, and the by-day table.
- `STATUS: OK`: say nothing tripped.
- `STATUS: ALERT`: show the alert lines. If a Slack note is wanted, create a draft in the user's own DM only, and send it only after the user approves the exact text.
- Keep reports free of member IDs, phone numbers and email addresses.

Not covered: unlocks with a Play Integrity signal.

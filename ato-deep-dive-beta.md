# ATO Session Brief — Beta

Cross-team-ready ATO case summary. Pulls the same data sources as `ato-deep-dive`; omits monetization flow; adds an attack clock bar and a per-session ML score vs. policy threshold comparison. Frames findings around controls that engaged, not gaps. Suitable for sharing outside the authentication team.

## Input

`$ARGUMENTS` — one of:
- **User ID** — numeric, 7–9 digits (e.g. `33224462`)
- **Device ID** — UUID or uppercase hex block (e.g. `447AAD3B-FA61-419B-AB58-B28EE94052DA`)
- **Dispute Claim ID** — value from `USER_DISPUTE_CLAIM_ID` column

---

## Step 1 — Resolve to user_id

Detect input type by format:
- All digits → **user_id**, use directly
- Contains `-` or uppercase hex ≥ 16 chars → **device_id**, resolve via:

```sql
SELECT DISTINCT USER_ID, COUNT(*) AS sessions,
       MIN(ORIGINAL_TIMESTAMP) AS first_seen, MAX(ORIGINAL_TIMESTAMP) AS last_seen
FROM CHIME.DECISION_PLATFORM.AUTHN
WHERE DEVICE_ID = '$ARGUMENTS'
  AND ORIGINAL_TIMESTAMP >= DATEADD('day', -90, CURRENT_DATE)
GROUP BY 1 ORDER BY sessions DESC LIMIT 5;
```

- Neither → **dispute claim ID**, resolve via:

```sql
SELECT DISTINCT USER_ID FROM risk.prod.disputed_transactions
WHERE USER_DISPUTE_CLAIM_ID = '$ARGUMENTS';
```

Take the user_id with the most sessions. If multiple users share the device, note ring linkage and investigate all.

---

## ATOM Score Threshold Reference

Source: ATOM v204 production policy configuration (effective May 2026). All thresholds apply to `ML_INFERENCE_MODEL_SCORE` in AUTHN.

| Band | Score Range | Default Outcome | Example Policy Name |
|---|---|---|---|
| Step-Down | ATOM < 0.03 (v183) / < 0.07 (v204) | `step_down` → OTP issued | `login___atom_v3_stepdown_0_07_threshold` |
| Pass | 0.07 – 0.70 | `default` (password + OTP required — both must pass) | standard flow |
| Step-Up OTP | 0.70 – 0.98 | `step_up_otp` | bounded by adjacent rules |
| Scan ID | > 0.98 | `scan_id` / `document_upload` | `login_v1_2___atom_v3__0_98` |
| Hard Block | N/A — deterministic | `hard_block` | device/attribute rules, not score-based |

**`default` outcome = password + OTP:** `DECISION_OUTCOME = 'default'` in AUTHN is **not** a no-challenge pass — it is the standard two-factor login requiring the member to enter their password and confirm an OTP sent to the phone on file. To verify whether the OTP was issued and confirmed, join AUTHN with STEP_UP_PLATFORM by user_id and timestamp proximity: `USER_DECISION = true` = OTP confirmed; `USER_DECISION = false` = OTP failed; `USER_DECISION = null` = OTP issued (`create_step_up` event) but not resolved (expired or completion captured elsewhere). If the phone number was changed before the fraud date, a `default` session with `USER_DECISION = true` on a fraud device means the OTP was routed to and confirmed by the fraudster. **Critical:** when an `allow_list` fires in the same request as `default` (within ~275ms), NO OTP is issued — verify by checking STEP_UP_PLATFORM for absence of any `create_step_up` near that timestamp. IVR `step_up_otp` outcomes in `PHONE_RISK_ASSESSMENT_EVENT` correspond to `create_step_up` events in STEP_UP_PLATFORM ~15–30 seconds later.

**Key distinction:** Velocity, geo, and PII-update rules can trigger challenges (`scan_id`, `last4`, `step_down`) at any ML score. Always separate ML-triggered from rule-triggered outcomes when presenting to an external audience.

---

## Queries

Run queries A–H in parallel. `USER_ID` in AUTHN, STEP_UP_PLATFORM, and USER_SERVICE is **TEXT (VARCHAR)** — always quote it as `'<USER_ID_STR>'`. The ATOM table uses a numeric `_USER_ID` — no quotes. `disputed_transactions` and `patty_ato_contact_new_dev` use `TO_VARCHAR` casts.

> **Snowflake LISTAGG**: `LISTAGG(DISTINCT col, sep) WITHIN GROUP (ORDER BY col)` is **invalid** when `DISTINCT` is present. Use `LISTAGG(DISTINCT col, sep)` with no `WITHIN GROUP` clause.

> **AUTHN column names**: no `CITY` or `STATE` columns — use `ARKOSE_RESPONSE_CITY` and `ARKOSE_RESPONSE_REGION`.

### Query A — AUTHN device matrix (90 days)
```sql
SELECT
    a.DEVICE_ID,
    a.PLATFORM,
    MIN(a.ORIGINAL_TIMESTAMP)                 AS first_seen,
    MAX(a.ORIGINAL_TIMESTAMP)                 AS last_seen,
    COUNT(*)                                  AS total_events,
    MAX(a.ML_INFERENCE_MODEL_SCORE)           AS max_ml_score,
    ROUND(AVG(a.ML_INFERENCE_MODEL_SCORE),4)  AS avg_ml_score,
    MAX(a.ARKOSE_RESPONSE_IS_VPN::INT)        AS ever_vpn,
    MAX(a.ARKOSE_RESPONSE_IS_PROXY::INT)      AS ever_proxy,
    COUNT(DISTINCT a.IP_ADDRESS)              AS distinct_ips,
    COUNT(DISTINCT a.ARKOSE_RESPONSE_CITY)    AS distinct_cities,
    LISTAGG(DISTINCT a.DECISION_OUTCOME, ' | ')        AS outcomes,
    LISTAGG(DISTINCT a.ARKOSE_RESPONSE_CITY, ' | ')    AS city_list,
    LISTAGG(DISTINCT a.ARKOSE_RESPONSE_REGION, ' | ')  AS region_list,
    LISTAGG(DISTINCT a.IP_ADDRESS, ' | ')              AS ip_list
FROM CHIME.DECISION_PLATFORM.AUTHN a
WHERE a.USER_ID = '<USER_ID_STR>'
  AND a.ORIGINAL_TIMESTAMP >= DATEADD('day', -90, CURRENT_DATE)
GROUP BY 1, 2
ORDER BY first_seen;
```

### Query B — STEP_UP challenge timeline
```sql
SELECT
    s.ORIGINAL_TIMESTAMP,
    s.STEP_UP_CHALLENGE_TYPE,
    s.USER_DECISION,
    a.DEVICE_ID,
    a.IP_ADDRESS,
    a.ARKOSE_RESPONSE_CITY,
    a.ML_INFERENCE_MODEL_SCORE,
    a.DECISION_OUTCOME
FROM CHIME.DECISION_PLATFORM.STEP_UP_PLATFORM s
LEFT JOIN CHIME.DECISION_PLATFORM.AUTHN a
    ON  s.USER_ID = a.USER_ID
    AND ABS(DATEDIFF('second', s.ORIGINAL_TIMESTAMP, a.ORIGINAL_TIMESTAMP)) <= 300
WHERE s.USER_ID = '<USER_ID_STR>'
  AND s.ORIGINAL_TIMESTAMP >= DATEADD('day', -90, CURRENT_DATE)
ORDER BY s.ORIGINAL_TIMESTAMP;
```

**USER_DECISION type: BOOLEAN** (`USER_DECISION` is not VARCHAR — do not filter with string literals): `true` = OTP/in-app challenge confirmed; `false` = challenge failed/denied; `null` = challenge issued (`create_step_up` event) but not resolved here — expired or completion captured elsewhere. Multiple `false` → `true` on the same fraud device = fraudster retrying OTP until they received the code (e.g., after a Phase 1 phone change rerouted OTP to their number). A `null` does not mean "no challenge was issued" — check for a `create_step_up` event at that timestamp to confirm issuance.

### Query C — Disputed transactions (full detail)
```sql
SELECT
    d.USER_DISPUTE_CLAIM_ID,
    d.DISPUTE_CREATED_AT,
    d.TRANSACTION_TIMESTAMP,
    d.DISPUTE_TYPE,
    d.REASON,
    d.RESOLUTION_CODE,
    d.RESOLUTION_DATE,
    ABS(COALESCE(d.UPDATED_TRANSACTION_AMOUNT, d.TRANSACTION_AMOUNT)) AS amount,
    d.SOURCE_MERCHANT_NAME,
    d.MERCHANT_NAME,
    d.MERCHANT_CATEGORY_CODE,
    d.ENTRY_TYPE,
    d.CARD_PRESENT,
    d.ISSUER,
    d.PROCESSOR
FROM risk.prod.disputed_transactions d
WHERE TO_VARCHAR(d.USER_ID) = '<USER_ID_STR>'
  AND d.DISPUTE_CREATED_AT >= DATEADD('day', -90, CURRENT_DATE)
ORDER BY d.TRANSACTION_TIMESTAMP;
```

### Query D — ATO label lookup
```sql
SELECT
    TO_VARCHAR(member_id)               AS user_id,
    MIN(interaction_chain_occurred_at)  AS ato_contact_date,
    MAX(ato_confirmed)                  AS ato_confirmed,
    MAX(new_dev_last_30d)               AS new_dev_last_30d
FROM risk.test.patty_ato_contact_new_dev
WHERE TO_VARCHAR(member_id) = '<USER_ID_STR>'
  AND interaction_chain_occurred_at >= DATEADD('day', -90, CURRENT_DATE)
GROUP BY 1;
```

### Query E — Raw AUTHN event log (200-row cap)
```sql
SELECT
    a.ORIGINAL_TIMESTAMP,
    a.DEVICE_ID,
    a.PLATFORM,
    a.DECISION_OUTCOME,
    a.ML_INFERENCE_MODEL_SCORE,
    a.ARKOSE_RESPONSE_IS_VPN,
    a.ARKOSE_RESPONSE_IS_PROXY,
    a.IP_ADDRESS,
    a.ARKOSE_RESPONSE_CITY,
    a.ARKOSE_RESPONSE_REGION
FROM CHIME.DECISION_PLATFORM.AUTHN a
WHERE a.USER_ID = '<USER_ID_STR>'
  AND a.ORIGINAL_TIMESTAMP >= DATEADD('day', -90, CURRENT_DATE)
ORDER BY a.ORIGINAL_TIMESTAMP
LIMIT 200;
```

### Query F — ATOM model scores
`_USER_ID` is **NUMBER** — no quotes.

*Device grain (for §3 device matrix):*
```sql
SELECT
    DEVICE_ID,
    COUNT(*)                    AS atom_predictions,
    MAX(SCORE)                  AS max_atom_score,
    AVG(SCORE)                  AS avg_atom_score,
    MAX(PERCENTILE)             AS max_atom_percentile,
    MIN(SNAPSHOT_TIMESTAMP)     AS first_prediction,
    MAX(SNAPSHOT_TIMESTAMP)     AS last_prediction,
    MAX(MODEL_VERSION)          AS model_version,
    MAX(MODEL_NAME)             AS model_name
FROM streaming_platform.segment_and_hawker_production.dsml_events_predictions_segment_v2_atom_model_v3
WHERE _USER_ID = <USER_ID_NUM>
  AND SNAPSHOT_TIMESTAMP >= DATEADD('day', -90, CURRENT_DATE)
GROUP BY 1
ORDER BY max_atom_score DESC;
```

*Raw events (for §4 timeline, 200-row cap):*
```sql
SELECT
    SNAPSHOT_TIMESTAMP,
    DEVICE_ID,
    IP,
    SCORE           AS atom_score,
    RAW_SCORE       AS atom_raw_score,
    PERCENTILE      AS atom_percentile,
    MODEL_VERSION,
    INFERENCE_ID,
    ACCOUNT_ACCESS_ATTEMPT_ID
FROM streaming_platform.segment_and_hawker_production.dsml_events_predictions_segment_v2_atom_model_v3
WHERE _USER_ID = <USER_ID_NUM>
  AND SNAPSHOT_TIMESTAMP >= DATEADD('day', -90, CURRENT_DATE)
ORDER BY SNAPSHOT_TIMESTAMP
LIMIT 200;
```

### Query G — USER_SERVICE identity change events (full 90-day window)
Captures every PII change attempt — phone, email, address, name — both successful and blocked, along with which system initiated them.

> **Column name corrections**: The correct columns are `EVENT_NAME` (not `EVENT_TYPE`), `DECISION_OUTCOME` (not `POLICY_DECISION`), `DEVICE_IP_ADDRESS` (not `IP_ADDRESS`). There are no `NEW_PHONE_NUMBER` or `NEW_EMAIL` columns — the PII type being changed is in `PII_TYPE`.

```sql
SELECT
    ORIGINAL_TIMESTAMP,
    EVENT_NAME,
    SUB_EVENT_NAME,
    PII_TYPE,
    DECISION_OUTCOME,
    POLICY_NAME,
    POLICY_ACTIONS,
    ORIGINATING_CLIENT,
    IS_USER_CHANGE_REQUEST,
    UPDATE_CONTEXT,
    DEVICE_ID,
    DEVICE_PLATFORM,
    DEVICE_MANUFACTURER,
    DEVICE_MODEL,
    DEVICE_NETWORK_CARRIER,
    DEVICE_IP_ADDRESS,
    REMOTE_CONTROLLED_APPS,
    ML_INFERENCE_MODEL_SCORE,
    ML_PREDICTION_MODEL_SCORE,
    SOCURE_REASON_CODES,
    NAMED_LIST,
    NAMED_LIST_RESULT
FROM CHIME.DECISION_PLATFORM.USER_SERVICE
WHERE USER_ID = '<USER_ID_STR>'
  AND ORIGINAL_TIMESTAMP >= DATEADD('day', -90, CURRENT_DATE)
ORDER BY ORIGINAL_TIMESTAMP;
```

Key signals:
- `ORIGINATING_CLIENT = 'penny'` — support-tool change; bypasses all self-serve velocity, SCAN_ID, and challenge controls
- `DECISION_OUTCOME = 'document_upload'` — SCAN_ID triggered; fraudster was challenged
- `DECISION_OUTCOME = 'deny'` on a VICTIM DEVICE post-fraud — victim lockout
- `DECISION_OUTCOME = 'allow'` on `phone` or `email` **before** fraud date — likely entry point
- `REMOTE_CONTROLLED_APPS` not null — remote access app active; strong social engineering signal

### Query H — Phone risk assessment (agent-assisted and self-serve phone changes)

Run whenever Query G shows a phone number change, or if you suspect agent social engineering. This event covers both self-serve app changes and agent-assisted CX calls (`AGENT_INTENT = 'INTENT_PHONE_UPDATE'`).

```sql
SELECT
    ORIGINAL_TIMESTAMP,
    SUB_EVENT,
    AGENT_INTENT,
    POLICY_NAME,
    POLICY_DECISION,
    CALLING_NUMBER_ANI,
    ANI_MATCH,
    DEVICE_ID,
    IP_ADDRESS,
    TRUST_INDICATOR,
    HIGHLY_PROBABLE_FALSIFIED,
    VOIP,
    REASSIGNED_INDICATOR,
    PREPAID
FROM CHIME.DECISION_PLATFORM.PHONE_RISK_ASSESSMENT_EVENT
WHERE USER_ID = '<USER_ID_STR>'
  AND ORIGINAL_TIMESTAMP >= DATEADD('day', -90, CURRENT_DATE)
ORDER BY ORIGINAL_TIMESTAMP;
```

If the column set is unknown, run `DESCRIBE TABLE CHIME.DECISION_PLATFORM.PHONE_RISK_ASSESSMENT_EVENT` first.

**Policy outcomes to surface:**
- `step_up_otp` — OTP challenge issued before the phone change is allowed; check whether the OTP was confirmed on a fraud device
- `no_checks_needed` — change allowed without further challenge; flag as a gap if combined with VoIP, ANI mismatch, or low trust indicator
- `refer_to_scan_id` — document verification required; triggered for synthetic identity risk or suspended-for-fraud accounts

**Key signals:** `AGENT_INTENT = 'INTENT_PHONE_UPDATE'` = agent-assisted CX call (not self-serve); `ANI_MATCH = false` = caller's number does not match number on file (social engineering indicator); `VOIP = true` = disposable VoIP number; `TRUST_INDICATOR < 300` = high-risk number. A successful phone change with VoIP + ANI mismatch + `POLICY_DECISION = 'no_checks_needed'` is a policy gap worth noting in §5.

### Query E-fraud — Event-level AUTHN for fraud day only

```sql
SELECT
    ORIGINAL_TIMESTAMP,
    DEVICE_ID,
    PLATFORM,
    DECISION_OUTCOME,
    ML_INFERENCE_MODEL_SCORE,
    IP_ADDRESS,
    ARKOSE_RESPONSE_CITY,
    ARKOSE_RESPONSE_IS_VPN
FROM CHIME.DECISION_PLATFORM.AUTHN
WHERE USER_ID = '<USER_ID_STR>'
  AND DATE(ORIGINAL_TIMESTAMP) = '<FRAUD_DATE>'
ORDER BY ORIGINAL_TIMESTAMP;
```

Use this (not the 200-row cap Query E) to populate §4 Score vs. Threshold — you need every event, not a sample.

### Query I — Device Ring Cross-User Linkage

Run for every device classified SUSPECT or FRAUD RING. A `linked_members` count > 1 means the device was shared across multiple accounts — strong ring signal. Compare `first_seen_global` against the earliest session you tracked: if the device appeared earlier on a different member, the fraud tool was in use before reaching this victim.

```sql
SELECT
    DEVICE_ID,
    COUNT(DISTINCT USER_ID)    AS linked_members,
    COUNT(DISTINCT IP_ADDRESS) AS distinct_ips,
    MIN(ORIGINAL_TIMESTAMP)    AS first_seen_global,
    MAX(ORIGINAL_TIMESTAMP)    AS last_seen_global
FROM CHIME.DECISION_PLATFORM.AUTHN
WHERE DEVICE_ID IN (<comma-separated UUID list>)
  AND ORIGINAL_TIMESTAMP >= DATEADD('day', -90, CURRENT_DATE)
GROUP BY 1
ORDER BY linked_members DESC;
```

**Interpretation:**
- `linked_members = 1` — single-user device in the 90-day window; no ring signal from this device alone
- `linked_members > 1` — shared device; pull the other USER_IDs and check if they also have active ATO cases
- `first_seen_global` < your tracked session start — device was already active against another account; note the gap in the timeline event detail

### Full UUID Requirement

Always surface complete device UUIDs in the artifact (36-char UUID, not a truncated prefix). Truncated IDs prevent cross-team lookup, Snowflake joins, and Jira cross-referencing. If you are working from a data pull that only returned 8-char prefixes, run Query A (90-day AUTHN device matrix) and join on the prefix to recover the full ID.

### Dispute Filing History — Interpreting Query C

`risk.prod.disputed_transactions` stores one row per transaction per dispute filing. The same claim ID appears multiple times if the member refiled. To reconstruct the full claim history:

1. **Distinct transactions**: deduplicate on `TRANSACTION_TIMESTAMP` (or `TRANSACTION_AMOUNT` + timestamp) — these are the actual fraud events.
2. **Filing rounds**: group by `DISPUTE_CREATED_AT` — each distinct filing date is one round.
3. **Resolution timeline**: for each filing, note `RESOLUTION_CODE` (approve / deny) and `RESOLUTION_DATE`. Count days from first filing to first approval — this is the victim's recovery wait.
4. **Multiple claims**: a member may have a separate claim ID for a different product (e.g., a MyPay advance disputed separately from debit card transactions). Surface each claim separately with its own resolution history.

---

## Output — HTML Artifact

Write a self-contained HTML file to the scratchpad, then publish it as an artifact titled `"ATO Session Brief · User <USER_ID>"`.

### CSS Token System

Use this exact token system — do not substitute different variable names or a dark-first palette. This preserves visual consistency across all beta briefs.

```css
:root {
  --bg:#F0F3FA; --surface:#FFFFFF; --card:#FFFFFF;
  --border:#D2DBF0; --faint:#E8EDF7;
  --tx1:#0B1223; --tx2:#3A4F7A; --tx3:#7B90BC;
  --c-ato:#C6350D;    /* confirmed fraud events */
  --c-legit:#0A8A60;  /* victim / recovery / approved */
  --c-warn:#B8720A;   /* probe / login attempts / Penny override */
  --c-info:#2550D4;   /* controls / challenges engaged */
  --c-neutral:#6B80AA;/* blocked / default outcomes */
  --c-txn:#7B3DAD;    /* ring / cross-account signal */
  --shadow:0 1px 4px rgba(11,18,35,.08),0 4px 16px rgba(11,18,35,.05);
  --r:8px;
  --mono:'SF Mono','Cascadia Code','Menlo',monospace;
  --sans:system-ui,-apple-system,sans-serif;
}
@media(prefers-color-scheme:dark){:root{
  --bg:#07101E; --surface:#0C1627; --card:#111E34;
  --border:#1C2D4A; --faint:#152036;
  --tx1:#D8E3F8; --tx2:#8AA4D5; --tx3:#445E90;
  --c-ato:#F06040; --c-legit:#25D49A; --c-warn:#F5A32A;
  --c-info:#6898F8; --c-neutral:#8098C0; --c-txn:#C07AEE;
  --shadow:0 1px 4px rgba(0,0,0,.4),0 4px 16px rgba(0,0,0,.3);
}}
:root[data-theme="light"]{--bg:#F0F3FA;--surface:#FFFFFF;--card:#FFFFFF;--border:#D2DBF0;--faint:#E8EDF7;--tx1:#0B1223;--tx2:#3A4F7A;--tx3:#7B90BC;}
:root[data-theme="dark"]{--bg:#07101E;--surface:#0C1627;--card:#111E34;--border:#1C2D4A;--faint:#152036;--tx1:#D8E3F8;--tx2:#8AA4D5;--tx3:#445E90;}
```

Tint semantic colors with `color-mix()` rather than hardcoded hex so they adapt to both themes:
```css
/* example: ATO badge */
background: color-mix(in srgb, var(--c-ato) 15%, transparent);
color: var(--c-ato);
border: 1px solid color-mix(in srgb, var(--c-ato) 35%, transparent);
```

**Chip shape** — use pill chips (`border-radius:99px`) for nav and KPI badges, square badges (`border-radius:4px`) only for table cell tags.

**Nav bar chips** — use `chip-neutral` or `chip-info` classes only. Do not use `chip-ato` or `chip-warn` in the header.

**Clock bar colors** — `--c-warn` (amber) for probe/login entries, `--c-ato` (red) for fraud transactions, `--c-info` (blue) for challenges/controls, `--c-legit` (green) for victim sessions, `--c-txn` (purple) for Penny overrides.

### §1 — Case Summary

**Victim Profile card (render first, above the KPI grid)**

Before the KPI cards, render a compact victim profile card. Style: `border-left: 3px solid var(--c-info)` on a `.card` surface; a small `VICTIM PROFILE` label in `--c-info` mono uppercase; a two-column CSS grid (`140px 1fr`) with uppercase labels in `--tx3` and mono values in `--tx1`. If a field is unavailable, omit that row — do not show "N/A".

Fields, in order:

| Field | Source | Notes |
|---|---|---|
| User ID | input | Display in full |
| Home location | Query A — victim device city/region | City/region from victim-classified devices (low ML, no VPN, home IP) |
| Victim devices | Query A | All UUIDs classified VICTIM DEVICE; show platform and first/last seen as sub-text in `--tx3` |
| ATO confirmed | Query D `ato_confirmed` | Yes / No / Not in label table |
| ATO contact date | Query D `ato_contact_date` | Date victim called support |
| Lag: fraud → contact | Computed | Days between first fraud transaction and ATO contact |
| Total disputed | Query C | SUM of amounts across all claims |
| Amount recovered | Query C | SUM of amounts with RESOLUTION_CODE = 'approve'; color in `--c-legit` |
| Amount unrecovered | Computed | Total minus recovered; color in `--c-ato`; omit row if $0 |

**KPI grid (below Victim Profile)**

6-card grid (`repeat(auto-fill, minmax(155px, 1fr))`). KPI value: mono 22px, bold. Include: total disputed, fraud date + window length, peak ML score + device, distinct attack waves, ATO contact date, victim recovery status.

### §2 — Attack Timeline (Clock Bar + Event Log)

**This section has two parts: (A) a clock bar and (B) a detailed event log below it. Both are required — do not render just the clock bar.**

#### A. Clock Bar

```css
.clock-wrap{background:var(--card);border:1px solid var(--border);border-radius:var(--r);padding:16px 20px;box-shadow:var(--shadow)}
.clock-title{font-family:var(--mono);font-size:10px;letter-spacing:.09em;text-transform:uppercase;color:var(--tx3);margin-bottom:12px}
.clock-bar{position:relative;height:32px;background:var(--faint);border-radius:6px;overflow:hidden;margin-bottom:8px}
.clock-seg{position:absolute;top:0;bottom:0;display:flex;align-items:center;justify-content:center;font-family:var(--mono);font-size:9px;font-weight:700;letter-spacing:.04em;overflow:hidden}
.clock-labels{display:flex;justify-content:space-between;font-family:var(--mono);font-size:10px;color:var(--tx3);margin-top:4px}
```

Steps:
1. **Window**: from the first suspicious AUTHN event (earliest probe/step_up_otp) to the latest of (ATO contact, victim recovery login, last fraud transaction). Include the full arc — overnight gaps are OK and should show as blank space in the bar.
2. **Background tint bands**: before individual segments, lay down lightly tinted background bands covering the pre-entry phase (color-mix warn 12%), active fraud phase (color-mix ato 12%), and recovery phase (color-mix legit 14%). These make the phases readable even when segments are small.
3. **Individual segments**: map every key event to `left` = (minutes_from_start / total_minutes) × 100%. Minimum segment width: 3%.
4. **Five colors** — amber (`--c-warn`) for probes/logins, red (`--c-ato`) for fraud transactions, blue (`--c-info`) for challenges/controls, purple (`--c-txn`) for Penny overrides, green (`--c-legit`) for victim recovery sessions.
5. **Tooltip**: set the `title` attribute on each segment with timestamp + event description — the full clock bar serves as a hover-navigation index.
6. **Labels**: below the bar, show 5 labels — window start, Penny or entry point time, fraud cluster range, any next-day recurrence, window end. Use `justify-content:space-between`.

#### B. Event Log

Below the clock bar, render a chronological event-by-event log inside a `.card`. Every key event from the queries must appear as its own entry — do not group or summarize multiple events into one row. Use date-divider headers (e.g. `Jul 23, 2026`) between days.

**Required CSS:**
```css
.tl2{display:flex;gap:0;padding:7px 0;border-bottom:1px solid var(--faint);cursor:pointer}
.tl2:last-of-type{border-bottom:none}
.tl2:hover{background:var(--faint)}
.tl2-dot{width:22px;display:flex;flex-direction:column;align-items:center;padding-top:4px;flex-shrink:0}
.tl2-d{width:9px;height:9px;border-radius:50%;flex-shrink:0}
.tl2-line{width:1px;flex:1;background:var(--border);margin-top:3px}
.tl2-body{flex:1;padding:0 8px}
.tl2-hdr{display:flex;align-items:baseline;flex-wrap:wrap;gap:8px}
.tl2-ts{font-family:var(--mono);font-size:11px;color:var(--tx3);min-width:52px;flex-shrink:0}
.tl2-lbl{font-size:13px;font-weight:600;color:var(--tx1)}
.tl2-chips{display:flex;flex-wrap:wrap;gap:4px;margin-top:4px}
.tl2-det{display:none;margin-top:8px;font-family:var(--mono);font-size:11px;color:var(--tx2);line-height:1.7;padding:8px 12px;background:var(--faint);border-radius:5px;border-left:2px solid var(--border)}
.tl2-det.open{display:block}
```

**Entry structure** — each row is a `<div class="tl2" onclick="this.querySelector('.tl2-det').classList.toggle('open')">`:
```html
<div class="tl2" onclick="this.querySelector('.tl2-det').classList.toggle('open')">
  <div class="tl2-dot">
    <div class="tl2-d" style="background:var(--c-COLOR)"></div>
    <div class="tl2-line"></div>  <!-- omit on last entry of a day group -->
  </div>
  <div class="tl2-body">
    <div class="tl2-hdr">
      <span class="tl2-ts">HH:MM</span>
      <span class="tl2-lbl">Event label</span>
    </div>
    <div class="tl2-chips"><!-- badge chips --></div>
    <div class="tl2-det"><!-- expanded detail, hidden by default --></div>
  </div>
</div>
```

**Dot color by event type:**
- `--c-warn` (amber) — fraud ring probes, fraud device logins, AUTHN step_up_otp on suspicious devices
- `--c-txn` (purple) — Penny-initiated email/phone change (entry point AND recovery revert)
- `--c-info` (blue) — phone risk assessments (Neustar/Socure), STEP_UP challenges (OTP, IN_APP_CONFIRMATION), SCAN_ID checks
- `--c-ato` (red) — fraud transactions (debit, transfers, P2P)
- `--c-legit` (green) — victim device logins (low ML, home IP), ATO contact confirmed, dispute filings

**Row-level highlight** — Penny entry-point rows and simultaneous challenge+fraud-txn rows get a background tint:
```css
style="background:color-mix(in srgb,var(--c-txn) 6%,transparent)"   /* Penny row */
style="background:color-mix(in srgb,var(--c-ato) 5%,transparent)"   /* fraud device first login */
style="background:color-mix(in srgb,var(--c-ato) 6%,transparent)"   /* challenge+txn simultaneous */
```

**Events to include** (populate from Query A, B, C, E-fraud, G, H, D data):

| Event type | Source | Dot color | Key detail to show in `.tl2-det` |
|---|---|---|---|
| Fraud ring probe | Query A/E — step_up_otp on suspicious web device | warn | full device UUID, IP, Query I ring size and first_seen_global |
| Phone risk assessment | Query H | info | UUID, carrier, VoIP flag, compromised indicator, policies fired |
| STEP_UP challenge (pre-entry) | Query B | info | challenge type, USER_DECISION (or no decision), AUTHN outcome on nearest session |
| Penny email/phone change | Query G — ORIGINATING_CLIENT=penny | txn | policies fired (allow_penny_updates), IP, UPDATE_CONTEXT, bypass explanation |
| Fraud web probe (post-Penny) | Query A/E — step_up_otp, same IP as fraud device | warn | device UUID, IP, Query I linkage |
| Fraud device first login | Query E-fraud — new device, AUTHN default | ato | full UUID, model, carrier, IP, city, all AUTHN events for this device (score progression), ATOM band vs. actual outcome |
| SCAN_ID / eligibility blocks | Query G — document_upload or deny on fraud device | info | PII_TYPE, DECISION_OUTCOME, POLICY_NAME per row; note which PII types were blocked vs. allowed |
| Fraud transaction | Query C per distinct TRANSACTION_TIMESTAMP | ato | claim ID, amount, payee, MCC, entry type, full filing history (all rounds with resolution code + date) |
| Mid-fraud STEP_UP challenge | Query B — challenge between fraud txns | info | challenge type, USER_DECISION, transaction that followed despite the challenge |
| Victim recovery login | Query A/E — victim device, home IP, low ML | legit | AUTHN score, device UUID, outcome |
| Penny recovery revert | Query G — ORIGINATING_CLIENT=penny on victim side | txn | IP, timestamp, policies fired; note velocity counter NOT reset if applicable |
| ATO contact confirmed | Query D | legit | ato_contact_date, ato_confirmed, new_dev_last_30d |

**Key narrative to surface explicitly:**
- If a Penny change preceded the fraud device login by < 15 minutes, mark it as **★ ENTRY POINT** and note "bypassed all self-serve velocity, SCAN_ID, and challenge controls via allow_penny_updates policy"
- If a mid-fraud challenge (OTP or IN_APP_CONFIRMATION) fired with no USER_DECISION and a fraud transaction followed within 5 minutes, note "challenge did not stop the next transaction" in the `.tl2-det`
- If a challenge and fraud transaction are within 60 seconds of each other, describe them as "simultaneous" and highlight with the ato background tint
- If `first_seen_global` on a ring device is before its first appearance on this account, note "device was already active against another member before arriving at this victim"

### §3 — Device Matrix

Identical to standard skill §2, with these additions:

**ML Band column** — given the device's max ML score, which ATOM v204 band does it fall in? Label each row (STEP-DOWN / PASS / STEP-UP / SCAN-ID / NO SCORE).

**Events column** — total AUTHN event count from the 90-day window for that device. Helps distinguish brief probes (2–6 events) from sustained sessions (20+ events).

**Ring column** — results from Query I. Show `N members · M IPs` for SUSPECT/FRAUD RING devices. Show `—` for victim devices. Highlight in a distinct color if `linked_members > 1`. If `first_seen_global` is earlier than the device's first tracked session on this account, note it in the timeline event — the device was active against another member before arriving at this victim.

**Full UUIDs required** — display all 36-char device UUIDs in the matrix and timeline. Add a footnote only if some devices are legitimately missing full UUIDs due to a data gap, and note which query would resolve them. Never truncate silently.

**Victim device classification note** — state explicitly whether each victim device was classified by ML/VPN signals alone, or via IP overlap with another confirmed victim session. The latter is the more reliable signal when ML scores are low and VPN is absent. Note the "first_seen in 90-day window ≠ first_seen ever" caveat if the device may predate the query window.

### §4 — Score vs. Threshold

**Include this section only when at least one fraud-day session has an ML score that crossed a band boundary or sits within 0.02 of one.** If all fraud-day sessions fall solidly in the PASS band (0.07–0.70) with no boundary crossings, the spectrum bar adds no information for a cross-team audience — omit the section and instead note in §5 Controls Applied that "all fraud-day sessions scored in the PASS band; controls that engaged were velocity- and rule-triggered, not ML-triggered."

When included, two parts:

**A. Spectrum bar** — a horizontal bar spanning 0–1.0 with labeled threshold markers at 0.03 (v183 step_down), 0.07 (v204 step_down), 0.70 (step_up boundary), and 0.98 (scan_id boundary). Color-fill each band. Plot each fraud-day session as a labeled vertical tick on the bar. Mark ML-triggered sessions (where the score crossing a band boundary caused the outcome) with a distinct indicator (e.g., ★ or bold tick).

**B. Per-session table** — columns: Session | Device | ML Score | Band (v204) | Expected Outcome | Actual AUTHN Outcome | Control Source

In the "Control Source" column, state either:
- `ATOM ML score (< 0.03 band)` — score crossed a boundary, ML caused the outcome
- `Velocity rule` — velocity counter fired; ML score irrelevant to this outcome
- `Deterministic rule` — policy rule with no ML dependency

**Near-threshold highlight:** If any score is within 0.02 of a band boundary, add a ★ marker and a note in the table. This helps reviewers understand margin without implying policy failure.

**ML scores only from AUTHN, not ATOM table:** `ML_INFERENCE_MODEL_SCORE` in AUTHN is what policy decisions are made against. ATOM table scores may differ slightly due to model version or inference timing — use AUTHN as the authoritative source for policy outcomes.

### §5 — Controls Applied

List each distinct control that engaged, grouped:

**Group A — ML Score-Triggered**
Controls where the ATOM score crossing a band boundary caused the AUTHN outcome.

For each: control name | device | timestamp | score + band | what happened

**Group B — Velocity / Rule-Triggered**
Controls that fired from velocity counters, geo rules, or deterministic policies. Include the reason the rule fired (e.g., "new device in out-of-state geo," "velocity counter accumulated from N prior attempts") so the reader understands this was not score-driven.

Close with a brief **Follow-up items** list — factual open questions only (e.g., "Victim phone recovery blocked by velocity_deny as of [date]"). Do not frame as policy critique.

### §6 — Identity Changes

Same structure as standard skill §7. Keep all three phases. Trim Phase 1 note if no pre-ATO changes found. In Phase 2, note per-row whether each change was consumer self-serve or Penny-initiated, and whether it was challenged or allowed. In Phase 3, document victim lockout with the policy name.

### §7 — Claims & Dispute Records

Two parts:

**A. Transaction table** — one row per distinct fraud transaction. Columns: Transaction Time | Amount | Payee | MCC | Entry Type | Processor | Dispute Type | Notes. Derive this by deduplicating Query C results on `TRANSACTION_TIMESTAMP`. Include a totals row.

**B. Claim filing history** — one table per claim ID. Columns: Filing # | Dispute Filed | Resolution Code | Resolution Date | Transactions Covered. Derive by grouping Query C on `DISPUTE_CREATED_AT` (each distinct date = one filing round). Note:
- How many filings occurred before the first approval
- Days from fraud date to first approval — this is the victim's recovery wait
- If a claim was filed multiple times with the same resolution code, each filing is a separate row
- Surface separate claim IDs (e.g., a MyPay advance claim vs. a debit card claim) as separate sub-sections

**Zendesk note (if unavailable):** If CX ticket data is not in the current data pull, add a labeled note with the expected ticket themes based on the fraud timeline (e.g., "unauthorized transfer," "phone number change," "support call date"). Do not present expected themes as confirmed.

---

## Tone

- State what happened, not what should have happened
- "ATOM score placed this session in the pass band (0.1334, 0.07–0.70)" not "ML failed to catch this"
- "Velocity rule applied SCAN_ID on new out-of-state device" not "fraudster was blocked"
- "OTP issued and confirmed on the phone number on file at that moment" not "OTP bypass"
- Quantify everything: scores, timestamps, counts, dollar amounts
- Remove modifiers like "clearly", "obviously", "significantly"
- If something is uncertain, either verify it or put it in a clearly labeled appendix

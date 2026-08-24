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
| Pass | 0.07 – 0.70 | `default` (no additional challenge) | standard flow |
| Step-Up OTP | 0.70 – 0.98 | `step_up_otp` | bounded by adjacent rules |
| Scan ID | > 0.98 | `scan_id` / `document_upload` | `login_v1_2___atom_v3__0_98` |
| Hard Block | N/A — deterministic | `hard_block` | device/attribute rules, not score-based |

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

### Query H — Phone risk assessment (Neustar signals on new phone numbers)
Run whenever Query G shows a phone number change.

```sql
SELECT
    ORIGINAL_TIMESTAMP,
    DEVICE_ID,
    POLICY_NAME,
    POLICY_DECISION,
    IP_ADDRESS
FROM CHIME.DECISION_PLATFORM.PHONE_RISK_ASSESSMENT_EVENT
WHERE USER_ID = '<USER_ID_STR>'
  AND ORIGINAL_TIMESTAMP >= DATEADD('day', -90, CURRENT_DATE)
ORDER BY ORIGINAL_TIMESTAMP;
```

If the column set is unknown, run `DESCRIBE TABLE CHIME.DECISION_PLATFORM.PHONE_RISK_ASSESSMENT_EVENT` first. Key signals: VoIP flag, carrier type, ported-recently flag, country mismatch.

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

Same CSS token system as `ato-deep-dive.md`. Design differences for beta:

- Primary accent: `--c-info` (blue) for controls that engaged; `--c-ato` (red) for confirmed fraud transactions only
- Nav bar chips: `chip-neutral` or `chip-info` — no `chip-warn` / `chip-ato` in the header
- Clock bar colors: amber = probe/login entries, red = transactions, blue = controls/challenges, green = victim sessions
- No root-cause policy critique section

### §1 — Case Summary

**Victim Information Summary (render first, above the KPI grid)**

Before the KPI cards, render a compact victim profile card with the following fields derived from Query A (victim device data), Query D (ATO label), and Query C (dispute records):

| Field | Source | Notes |
|---|---|---|
| User ID | input | Display in full |
| Home location | Query A — victim device city/region | Use the city/region from victim-classified devices (low ML, no VPN, home IP) |
| Victim devices | Query A | List all device UUIDs classified VICTIM DEVICE; show platform and first/last seen |
| Account age at fraud | Query C earliest dispute date vs. account open date if available | If account open date unavailable, omit |
| ATO confirmed | Query D `ato_confirmed` | Yes / No / Not in label table |
| ATO contact date | Query D `ato_contact_date` | Date victim called support; derive lag from fraud date |
| Lag: fraud → contact | Computed | Days between first fraud transaction and ATO contact date |
| Total disputed | Query C | SUM of amounts across all claims |
| Amount recovered | Query C | SUM of amounts with RESOLUTION_CODE = 'approve' |
| Amount unrecovered | Computed | Total disputed minus recovered; highlight in red |

Style as a two-column definition list or a bordered card with `--c-info` left accent. Do not use a table with many empty cells — if a field is unavailable, omit that row rather than showing "N/A". Label the card clearly as **Victim Profile** to distinguish it from the KPI summary below.

**KPI grid (below Victim Profile)**

6-card KPI grid. Include: total disputed, fraud date + window length, peak ML score + device, distinct attack waves, ATO contact date, victim recovery status.

### §2 — Attack Timeline (Clock Bar)

Visual compressed timeline of the attack window. Pattern from reference:

```css
.clock-wrap{background:var(--card);border:1px solid var(--border);border-radius:var(--r);padding:16px 20px;box-shadow:var(--shadow)}
.clock-title{font-family:var(--mono);font-size:10px;letter-spacing:.09em;text-transform:uppercase;color:var(--tx3);margin-bottom:12px}
.clock-bar{position:relative;height:32px;background:var(--faint);border-radius:6px;overflow:hidden;margin-bottom:8px}
.clock-seg{position:absolute;top:0;bottom:0;display:flex;align-items:center;justify-content:center;font-family:var(--mono);font-size:9px;font-weight:700;letter-spacing:.04em;overflow:hidden}
.clock-labels{display:flex;justify-content:space-between;font-family:var(--mono);font-size:10px;color:var(--tx3);margin-top:4px}
```

Steps:
1. Determine window start (first suspicious AUTHN event) and end (last fraud event or identity change on fraud day)
2. Map each key event to a % position in that window
3. Render as `clock-seg` divs with `left` and `width` as % of total window
4. Use 4 colors only: amber for probe/login entries, red for transactions, blue for challenges/controls, green for victim sessions
5. Minimum segment width: 3% (for readability)
6. Add time labels below the bar at start, 25%, 50%, 75%, and end positions

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

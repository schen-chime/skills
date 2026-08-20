# ATO Account Deep Dive

Reconstruct the full fraud timeline for any ATO identifier (user ID, device ID, or dispute claim ID). Pulls all data sources, classifies devices, infers monetization pattern, traces pre-ATO identity changes that enabled the takeover, and publishes a self-contained interactive HTML artifact.

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

## Step 2 — Pull all data sources

Run these queries in parallel. `USER_ID` in AUTHN, STEP_UP_PLATFORM, and USER_SERVICE is **TEXT (VARCHAR)** — always quote it as `'<USER_ID_STR>'`. The ATOM table uses a numeric `_USER_ID` — no quotes. `disputed_transactions` and `patty_ato_contact_new_dev` use `TO_VARCHAR` casts.

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
`_USER_ID` is **NUMBER** — no quotes. Pull both device-grain summary and raw events.

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
Captures every PII change attempt — phone, email, address, name — both successful and blocked, along with which system initiated them. Pull the full 90-day window; do not filter to fraud day only. Pre-ATO changes (days or weeks before the fraud) may be the actual entry point.

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

**PII_TYPE values and their fraud risk:**

| PII_TYPE | Risk when changed pre-ATO | Why it matters |
|---|---|---|
| `phone` | **Critical** | OTP-based MFA and forgot-password flows now route to the fraudster's number |
| `email` | **Critical** | Password reset links, notifications, and account recovery now go to the fraudster |
| `address` | **High** | Physical card sent to fraudster's address; intercept new card without victim knowing |
| `name` | **Medium** | Can indicate identity layering; rarely benign when combined with other changes |

**Key signals to read in results:**

- `ORIGINATING_CLIENT = 'penny'` — change made via the internal support/admin tool; bypasses all self-serve velocity, SCAN_ID, and challenge controls entirely
- `ORIGINATING_CLIENT = 'consumer'` with `IS_USER_CHANGE_REQUEST = true` — legitimate self-serve change; lower risk unless combined with other signals
- `IS_USER_CHANGE_REQUEST = false` with `ORIGINATING_CLIENT = 'api'` — system-initiated bulk update (low risk on its own); a single address update of this type right before fraud is still worth noting
- `DECISION_OUTCOME = 'document_upload'` — SCAN_ID triggered on that device; fraudster was challenged
- `DECISION_OUTCOME = 'deny'` — hard-blocked; repeated denies on a VICTIM DEVICE post-fraud = victim lockout
- `DECISION_OUTCOME = 'allow'` on `phone` or `email` **before** the fraud date — this is the likely entry point; the fraudster now owns that MFA or recovery channel
- `REMOTE_CONTROLLED_APPS` not null — a remote access app (AnyDesk, TeamViewer, etc.) was active on the device during the PII change; strong indicator of a real-time social engineering call where the fraudster is watching or controlling the victim's screen
- `SOCURE_REASON_CODES` — Socure identity verification result on the new PII; reason codes flagging identity mismatch, synthetic identity, or address risk should have blocked the change
- `ML_INFERENCE_MODEL_SCORE` / `ML_PREDICTION_MODEL_SCORE` — the model's fraud score on this identity change request; a high score that still resulted in `allow` is a detection gap
- `NAMED_LIST` / `NAMED_LIST_RESULT` — watchlist hit on the new PII value (phone, email, address); a hit that did not block the change is a policy gap

**What USER_SERVICE does NOT capture:**
- **Forgot password / forgot email flows**: these are triggered through the app's auth service and appear as AUTHN outcomes (`password_reset`) or STEP_UP challenges sent to whatever phone/email is currently on file. If the fraudster already changed the phone number, the OTP from a forgot-password flow goes to them — the chain is: `USER_SERVICE phone allow (pre-ATO)` → victim or fraudster triggers forgot-password → OTP routes to fraudster's number → password reset succeeds.
- **New card request**: check `CHIME.DECISION_PLATFORM.MOBILE_WALLET_PROVISIONING_AND_CARD_TOKENIZATION` or spending override tables for card issuance events near the address change date.

### Query H — Phone risk assessment (Neustar signals on new phone numbers)
Evaluates the risk of any new phone number added to the account — whether it is VoIP, a burner, recently ported, or carrier-mismatched. Run whenever Query G shows a phone number change.

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

If the column set is unknown, run `DESCRIBE TABLE CHIME.DECISION_PLATFORM.PHONE_RISK_ASSESSMENT_EVENT` first. Key signals: VoIP flag, carrier type, ported-recently flag, country mismatch. A phone change allowed despite high Neustar risk is a policy gap.

---

## Step 3 — Classify each device

Apply these rules. Use **both** ML/VPN signals (Query A) **and** IP address cross-matching to identify victim devices correctly.

| Classification | Criteria |
|---|---|
| **FRAUD RING** | max_ml_score > 0.8 AND (ever_vpn = 1 OR ever_proxy = 1) AND distinct_cities > 3 |
| **SUSPECT** | max_ml_score > 0.5 OR ever_vpn = 1 OR ever_proxy = 1 (but not FRAUD RING) |
| **VICTIM DEVICE** | ever_vpn = 0 AND ever_proxy = 0 AND distinct_cities ≤ 2 AND avg_ml_score < 0.5 — **or** the device's IP set overlaps with another already-confirmed VICTIM DEVICE |
| **UNKNOWN** | Insufficient data to classify |

**IP cross-match rule:** If a device's IP address also appears on a confirmed VICTIM DEVICE, promote it to VICTIM. This catches web sessions (`platform = 'web'`) at the victim's home or mobile IP that lack an ML score and would otherwise stay UNKNOWN.

**Case B pattern (low-ML, no VPN):** If no devices meet FRAUD RING criteria, classify non-victim devices as SUSPECT and note this explicitly. Make §7 and §8 the primary analytical focus — ML and VPN signals are blind to this pattern; only velocity, identity change, payee, and time-of-day signals can catch it.

**ATOM enrichment:** After classifying from Query A, join Query F results to add `max_atom_score` and `max_atom_percentile` to each device. If a device's ATOM score exceeds 0.7 while its AUTHN ML score is low, flag this pair as a detection gap in §7.

---

## Step 3.5 — Establish fraud date and split identity events into phases

Before building the timeline, determine the **fraud date**: the date of the earliest transaction in Query C (or, if no disputes, the earliest session on a SUSPECT/FRAUD RING device). This date is the dividing line for all identity change analysis.

Split Query G results into three phases:

**Phase 1 — Pre-ATO setup** (before fraud date)
Filter Query G results to `ORIGINAL_TIMESTAMP < fraud_date` and `DECISION_OUTCOME = 'allow'`. For each successful change, assess what it handed the fraudster:

| PII_TYPE changed | What it compromised |
|---|---|
| `phone` | OTP delivery for MFA, forgot-password, and 2FA flows; any `step_up_otp` or `last4` challenge now routes to the fraudster |
| `email` | Password reset links, account alerts, and recovery emails now go to the fraudster |
| `address` | Physical card replacement will be shipped to the fraudster's address |
| `name` | Identity layering; combined with address change, positions fraudster to receive physical mail |

For each successful pre-ATO phone change, run Query H (phone risk) to assess Neustar signals on the new number (VoIP, burner, recently ported, carrier mismatch). A risky number that was allowed through is a gap.

Also check `REMOTE_CONTROLLED_APPS` on any pre-ATO change event — presence of a remote access app indicates the fraudster was watching or driving the change in real time (tech-support or account-help scam).

A successful `phone` or `email` change before the fraud date is often the **root entry point** — not the day transactions occurred. Document it as the entry point in Phase 1 and in the root cause narrative.

**Forgot password / forgot email flows:** These do not appear in USER_SERVICE. They manifest as AUTHN or STEP_UP events (OTP challenge, `step_up_otp` outcome) triggered on whatever phone or email is currently on the account. If the fraudster already owns the phone number from Phase 1, they receive and confirm the OTP — the password reset succeeds silently. Detect this by correlating a `STEP_UP_CHALLENGE_TYPE = 'OTP'` event in Query B with a prior `PII_TYPE = 'phone'` allow in Query G.

**Phase 2 — Day-of-fraud attack** (on or within 24h of fraud date)
All USER_SERVICE events during the active fraud window. Look for:
- Challenge step-down across devices: device A received `DECISION_OUTCOME = 'document_upload'` (SCAN_ID) → fraudster switched to device B and received `allow` with a weaker effective challenge — because SCAN_ID is device-scoped, not account-scoped
- Penny-originated change (`ORIGINATING_CLIENT = 'penny'`) immediately following a blocked self-serve attempt on the same `PII_TYPE` — social engineering of a support agent
- MFA confirmations on a SUSPECT device (possible if fraudster owns the OTP channel from Phase 1)
- Multiple PII types changed in quick succession (phone → email → address within same session = full identity replacement)
- `REMOTE_CONTROLLED_APPS` active during a change = fraudster is live on a call coaching the victim or directly controlling their device

**Phase 3 — Post-fraud victim lockout** (after last fraud transaction)
Filter to `DECISION_OUTCOME = 'deny'` on VICTIM DEVICE(s) after the fraud date. Compute lockout duration: days from fraud date to the most recent deny with no subsequent allow. Also check: was the contact information changed in Phase 1 or 2 still in place? If so, the victim may not even be receiving account recovery communications.

---

## Step 4 — Infer monetization pattern

Identify which apply from Query C and G results. Multiple patterns may co-occur.

- **ACH Pull Exploit** — dispute_type = 'ach_debit', payees are company names, spanning weeks → fraudster enrolled the account number at external ACH initiators; persists after password reset because the external enrollment is not revoked
- **Rapid Cash App Drain** — MCC 4829, high transaction count in < 2 hours, followed by large ACH to fintech (GO2bank, Cash App, etc.) → micro-transfers to mule accounts + single large liquidation
- **Card-Not-Present Ring** — MCC 5816/5999/6012, ORDER pattern, repeated digital goods → account used to purchase resellable items at a mule's direction
- **P2P Drain** — dispute_type = 'pay_friends'/'pay_anyone', individual names as payees → direct P2P to mule accounts
- **Penny Social Engineering** — USER_SERVICE shows `originating_client = 'penny'` for a phone or email change shortly after a blocked self-serve attempt of the same type. Indicates the fraudster called support and convinced an agent to bypass SCAN_ID and velocity controls. Hallmark: two events close in time — self-serve attempt with `scan_id` or `deny` decision, then a Penny-originated change with `allow` decision.

**Undiscovered transactions:** Disputes only capture what the member filed. Mentally cross-reference the fraud time window against all auth events and any available card auth or ACH tables to identify transactions that were never disputed. Report these separately as undiscovered exposure in §2 and §6 — they are not included in the dispute total.

---

## Step 5 — Build merged timeline

Merge events from all queries into one chronological list. Label each event:

| Icon | Type | Source |
|---|---|---|
| ⚠ | `login` | AUTHN session on SUSPECT or FRAUD RING device |
| 🔒 | `challenge` | STEP_UP event (IN_APP_CONFIRMATION, OTP, scan_id, last4) |
| 💸 | `fraud_txn` | TRANSACTION_TIMESTAMP from disputes |
| 🔍 | `undiscovered_txn` | Transaction in fraud window not in any dispute claim |
| 📋 | `dispute_filed` | DISPUTE_CREATED_AT from disputes |
| 📞 | `ato_contact` | Query D ato_contact_date |
| 🛑 | `block` | AUTHN DECISION_OUTCOME = 'hard_block' or USER_SERVICE DECISION_OUTCOME = 'deny' |
| ✅ | `legit_login` | AUTHN session on VICTIM DEVICE |
| 📱 | `phone_change` | USER_SERVICE PII_TYPE = 'phone', DECISION_OUTCOME = 'allow' |
| 📧 | `email_change` | USER_SERVICE PII_TYPE = 'email', DECISION_OUTCOME = 'allow' |
| 🏠 | `address_change` | USER_SERVICE PII_TYPE = 'address', DECISION_OUTCOME = 'allow' |
| 👤 | `name_change` | USER_SERVICE PII_TYPE = 'name', DECISION_OUTCOME = 'allow' |
| 🖥 | `remote_control` | USER_SERVICE REMOTE_CONTROLLED_APPS not null during any PII change |
| 🛠 | `penny_action` | USER_SERVICE ORIGINATING_CLIENT = 'penny' |

Mark three critical inflection points in the timeline:
1. **First fraudster session** — earliest AUTHN event on a SUSPECT/FRAUD RING device
2. **Entry point** — the pre-ATO identity change (if any) that compromised an MFA channel
3. **ATO contact** (if in Query D) or last known fraudster activity

Add labeled day-boundary dividers for **every** date in the dataset. Derive each label from the phase it belongs to (e.g., "Pre-ATO Setup", "Wave 1", "FRAUD DAY", "Victim Denied – Day N") rather than emitting a raw date string.

---

## Step 6 — Generate the artifact

Write a self-contained HTML file to the scratchpad, then publish it as an artifact.

### Required CSS design tokens (embed verbatim in `<style>`):
```css
:root{--bg:#F0F3FA;--surface:#FFFFFF;--card:#FFFFFF;--border:#D2DBF0;--faint:#E8EDF7;--tx1:#0B1223;--tx2:#3A4F7A;--tx3:#7B90BC;--c-ato:#C6350D;--c-legit:#0A8A60;--c-warn:#B8720A;--c-info:#2550D4;--c-neutral:#6B80AA;--c-txn:#7B3DAD;--shadow:0 1px 4px rgba(11,18,35,.08),0 4px 16px rgba(11,18,35,.05);--r:8px;--mono:'SF Mono','Cascadia Code','Menlo',monospace;--sans:system-ui,-apple-system,sans-serif;}
@media(prefers-color-scheme:dark){:root{--bg:#07101E;--surface:#0C1627;--card:#111E34;--border:#1C2D4A;--faint:#152036;--tx1:#D8E3F8;--tx2:#8AA4D5;--tx3:#445E90;--c-ato:#F06040;--c-legit:#25D49A;--c-warn:#F5A32A;--c-info:#6898F8;--c-neutral:#8098C0;--c-txn:#C07AEE;--shadow:0 1px 4px rgba(0,0,0,.4),0 4px 16px rgba(0,0,0,.3);}}
:root[data-theme="light"]{--bg:#F0F3FA;--surface:#FFFFFF;--card:#FFFFFF;--border:#D2DBF0;--faint:#E8EDF7;--tx1:#0B1223;--tx2:#3A4F7A;--tx3:#7B90BC;}
:root[data-theme="dark"]{--bg:#07101E;--surface:#0C1627;--card:#111E34;--border:#1C2D4A;--faint:#152036;--tx1:#D8E3F8;--tx2:#8AA4D5;--tx3:#445E90;}
```

### Eight required sections:

**§0 — Disclaimer banner (always rendered, full-width, top of page, above all other content)**
Render this as the very first element in the page body — above the nav bar and all sections:
```html
<div class="disclaimer-banner">
  ⚠ This report is for investigative reference only. Do not use for decisioning purposes. Work in progress.
</div>
```
Style it as a full-width amber/warning bar with `position: sticky; top: 0; z-index: 9999` so it is always visible. Use `--c-warn` for the background tint and `--tx1` for text. Never omit this banner.

**§1 — Sticky nav bar**
Show: anonymized user ID (`User-XXXXXX`), investigation date, total dispute $, fraud pattern label, light/dark toggle.
Conditional chips (show only when applicable):
- `● ACTIVE FRAUD` (pulsing red) — if `isStillActive` is true
- `⚠ PENNY BYPASS` (amber) — if a Penny-originated change followed a blocked self-serve attempt
- `⚠ PRE-ATO ENTRY` (amber) — if a successful identity change before the fraud date is identified as the root entry point

**§2 — Case header KPI grid**
Always show: Total Dispute $, Dispute Count, Peak ML Score, Peak ATOM Score, Fraud Devices / Total Devices, Days Active.
Show when applicable: Undiscovered Fraud $, ATO Contact Date, Victim Lockout Days, Days Since Pre-ATO Entry (gap between the pre-ATO identity change and the fraud date).

**§3 — Device matrix table**
Columns: Device (first 8 chars + platform), Wave, First Seen, Last Seen, Max ML (with progress bar), Max ATOM Score, Max ATOM Percentile, VPN/Proxy, Distinct IPs, Locations, Key Outcomes, Classification badge.
Row background tint: red-4% for FRAUD RING, green-4% for VICTIM DEVICE, amber-4% for SUSPECT.
**Classification badge and row class must be computed from `d.cls` at render time — never hardcoded.** Use `d.cls.toUpperCase()` for the pill label and `row-${d.cls}` for the row class.

**§4 — Merged event timeline**
Vertical flow list. Each item: icon + timestamp + description + device context + chip badges (ML score, ATOM score, VPN, challenge type, amount).
Day-boundary dividers with descriptive labels for every date. Mark entry-point events with a distinct visual treatment (e.g., a left border accent or `ENTRY POINT` badge).

**§5 — Monetization flow**
Numbered steps covering the full attack chain: credential acquisition → pre-ATO identity manipulation (if any) → account access method → probing → drain → liquidation → persistence after the fact.

**§6 — Dispute intake table**
Columns: Txn Date, Amount, Merchant, MCC, Dispute Type, Dispute Filed, Lag (txn→filed), Resolution.
Footer: totals and avg lag. Add a separate "Undiscovered Exposure" subsection if any transactions in the fraud window were not disputed.

**§7 — Detection gaps**
For each signal that failed to stop the fraud:
- Signal name
- Observed value at fraud time
- Threshold or condition that would have triggered
- Recommended rule

Always check these, regardless of case:
- **AUTHN ML score** — was it below block threshold on SUSPECT devices? (Case B: score < 0.5 throughout)
- **ATOM vs. AUTHN ML** — did ATOM score high when AUTHN ML did not trigger a block? ATOM and AUTHN ML are separate signals; a gap between them = ATOM not connected to auth decision
- **VPN/proxy absence** — Case B blind spot; other signals must carry the load
- **SCAN_ID device-scope bypass** — DECISION_OUTCOME = 'document_upload' on device A → fraudster switches to device B and gets a weaker challenge tier; challenge is tied to the device, not the account
- **Pre-ATO phone change allowed** — USER_SERVICE shows `PII_TYPE = 'phone'` + `DECISION_OUTCOME = 'allow'` before fraud date; OTP/MFA now routed to fraudster. Check: what challenge governed that change? Was Neustar phone risk evaluated?
- **Pre-ATO email change allowed** — `PII_TYPE = 'email'` allowed before fraud date; password reset emails now go to fraudster
- **Pre-ATO address change allowed** — `PII_TYPE = 'address'` allowed before fraud date; physical card replacement will be intercepted
- **Phone risk signal ignored** — Query H shows VoIP/burner/ported-recently on the new phone number but change was allowed
- **Socure reason codes on PII change** — `SOCURE_REASON_CODES` flagged identity risk on a USER_SERVICE event but `DECISION_OUTCOME = 'allow'` regardless
- **ML score on USER_SERVICE ignored** — `ML_INFERENCE_MODEL_SCORE` or `ML_PREDICTION_MODEL_SCORE` elevated on a PII change event that was still allowed
- **Remote controlled apps not actioned** — `REMOTE_CONTROLLED_APPS` was populated during a PII change (real-time social engineering) but was not a blocking signal
- **Penny bypass** — `ORIGINATING_CLIENT = 'penny'` change followed a blocked self-serve attempt; admin tool skips all velocity and challenge controls
- **Velocity block collateral damage** — fraudster's repeated blocked attempts created a deny rule that subsequently locks out the legitimate victim with no self-serve recovery path
- **NAMED_LIST hit not blocking** — `NAMED_LIST_RESULT` flagged the new PII value but the change was allowed

**§8 — Identity Change & Policy Root Cause**
Always include when Query G returns any results. Structured in three phases:

*Phase 1 — Pre-ATO setup changes* (before fraud date)
Show all rows from Query G where `ORIGINAL_TIMESTAMP < fraud_date` and `DECISION_OUTCOME = 'allow'`.
Table columns: Timestamp · PII_TYPE · Policy Name · Decision · Client · Remote Control App · Socure Codes · ML Score · Impact
For each row: state what the successful change handed the fraudster (OTP channel, recovery email, card intercept). Note any Neustar phone risk from Query H. If `REMOTE_CONTROLLED_APPS` is populated, call it out explicitly.
If this table is empty, state explicitly: "No pre-ATO identity changes found — fraudster likely obtained credentials via phishing or credential stuffing without first modifying account contact info."

*Phase 2 — Day-of-fraud attack sequence* (on or within 24h of fraud date)
Show all rows from Query G where `ORIGINAL_TIMESTAMP` falls within the fraud window.
Table columns: Timestamp · PII_TYPE · Event Name · Decision Outcome · Policy Name · Client · Device · Remote Control App · Notes
One row per USER_SERVICE event. Annotate:
- Challenge step-down: `DECISION_OUTCOME = 'document_upload'` on device A → `allow` on device B minutes later (different device_id, same PII_TYPE)
- Penny bypass: `DECISION_OUTCOME = 'deny'` or `'document_upload'` on self-serve → `ORIGINATING_CLIENT = 'penny'` allow shortly after on same PII_TYPE
- MFA compromise: `STEP_UP_CHALLENGE_TYPE = 'OTP'` confirmed on a SUSPECT device (from Query B, correlated by time and device)
- Full identity replacement: multiple PII_TYPE values changed in sequence within a single session

*Phase 3 — Post-fraud victim lockout* (after last fraud transaction)
Show all rows from Query G where `ORIGINAL_TIMESTAMP > last_fraud_date` and `DECISION_OUTCOME = 'deny'` on VICTIM DEVICE(s).
Table columns: Date · PII_TYPE · Policy Name · Decision Outcome · Client · Device · Days Since Fraud
Compute lockout duration from fraud date to the most recent deny. Also note: if the phone or email changed in Phase 1/2 is still in place, the victim may not even receive account recovery communications sent to the original contact details.

*Policy root cause summary*
After the three tables, provide a short structured narrative (3–5 bullets) answering: **why did this ATO succeed?**
Frame each bullet as one of:
- **Entry point** — "Fraudster gained access because [policy X] allowed [identity change Y] with only [challenge Z] on [date], which [compromised channel / handed OTP control / enabled password reset]."
- **Amplifier** — "Impact was amplified because [policy P] allowed [action Q] after the entry point was established."
- **Detection failure** — "The session/transaction was not blocked because [signal S] was [below threshold / not evaluated / device-scoped rather than account-scoped]."
- **Persistence** — "The fraudster maintained access because [no remediation step revoked X]."
- **Collateral damage** — "The victim cannot recover because [residual velocity block / changed contact info / no recovery path]."

### JavaScript data template:
```javascript
const CASE = {
  userId: '<USER_ID>',
  displayId: 'User-' + String('<USER_ID>').slice(-6),
  fraudDate: '<earliest TRANSACTION_TIMESTAMP from Query C, or earliest SUSPECT/FRAUD RING first_seen>',
  totalDisputeUSD: 0,        // SUM(amount) from Query C
  undiscoveredUSD: 0,        // transactions in fraud window not in any dispute; 0 if none found
  disputeCount: 0,           // COUNT(distinct claim_id) from Query C
  peakML: null,              // MAX(max_ml_score) from Query A
  peakATOM: null,            // MAX(max_atom_score) from Query F; null if no ATOM records
  totalDevices: 0,
  fraudDevices: 0,
  suspectDevices: 0,
  victimDevices: 0,
  preAtoEntryDate: null,     // date of the earliest successful pre-ATO identity change, or null
  preAtoEntryType: null,     // 'phone_change' | 'email_change' | 'password_reset' | null
  pennyBypass: false,        // true if Penny-originated change followed a blocked self-serve attempt
  atoContactDate: null,      // from Query D
  firstFraudEvent: null,     // MIN(first_seen) on SUSPECT/FRAUD RING devices
  lastFraudEvent: null,      // MAX(last_seen) on SUSPECT/FRAUD RING devices
  isStillActive: false,      // true if lastFraudEvent within 7 days of today
  fraudPattern: '',          // e.g. 'Rapid Drain + Penny Social Engineering'
  daysActive: 0,
  victimLockoutDays: 0,      // days from fraud date to last deny on victim device; 0 if none
};
const DEVICES = [
  // one object per device, Query A enriched with Query F:
  { id, platform, wave, firstSeen, lastSeen,
    maxML, avgML, vpn, proxy, distinctIPs, ips, cities, outcomes,
    maxATOM, avgATOM, maxATOMPercentile,  // null if no ATOM record for this device
    cls }  // 'fraud' | 'suspect' | 'victim' | 'unknown'
];
const TIMELINE = [
  // merged from B + C + E + F + G, sorted by ts:
  { ts, type, icon, label, detail, deviceId, ml, atomScore, amount, chips: [] }
  // type values: 'login' | 'challenge' | 'fraud_txn' | 'undiscovered_txn' |
  //              'dispute_filed' | 'ato_contact' | 'block' | 'legit_login' |
  //              'phone_change' | 'email_change' | 'password_reset' | 'penny_action'
];
const DISPUTES = [
  { claimId, disputeCreatedAt, txnTimestamp, type, amount,
    merchant, mcc, lagDays, resolution }
];
const IDENTITY_EVENTS = [
  // from Query G — correct column names from actual schema:
  { ts,
    eventName,           // EVENT_NAME (e.g. 'user_update')
    piiType,             // PII_TYPE: 'phone' | 'email' | 'address' | 'name'
    decisionOutcome,     // DECISION_OUTCOME: 'allow' | 'deny' | 'document_upload'
    policyName,          // POLICY_NAME
    originatingClient,   // ORIGINATING_CLIENT: 'api' | 'penny' | 'consumer'
    isUserChangeRequest, // IS_USER_CHANGE_REQUEST boolean
    deviceId,            // DEVICE_ID
    deviceIpAddress,     // DEVICE_IP_ADDRESS
    deviceNetworkCarrier,// DEVICE_NETWORK_CARRIER
    remoteControlledApps,// REMOTE_CONTROLLED_APPS (null or app name)
    mlScore,             // ML_INFERENCE_MODEL_SCORE
    mlPredictionScore,   // ML_PREDICTION_MODEL_SCORE
    socureReasonCodes,   // SOCURE_REASON_CODES
    namedList,           // NAMED_LIST
    namedListResult,     // NAMED_LIST_RESULT
    phase,               // derived: 'pre_ato' | 'attack' | 'lockout'
    notes }              // human-readable annotation of the event's role
];
const PHONE_RISK_EVENTS = [
  // from Query H (run when Query G shows PII_TYPE = 'phone' changes):
  { ts, deviceId, policyName, decisionOutcome, riskSignals }
];
const GAPS = [
  { signal, actual, threshold, recommendation }
];
const ROOT_CAUSE = [
  { type,   // 'entry_point' | 'amplifier' | 'detection_failure' | 'persistence' | 'collateral_damage'
    narrative }  // one sentence
];
```

### File name and artifact metadata:
- File: `ato_deepdive_<USER_ID>.html` in the scratchpad directory
- Title: `ATO Deep Dive — User <USER_ID>`
- Description: `Fraud timeline for <USER_ID> · <totalDisputeUSD> disputed · <fraudPattern> · entry: <preAtoEntryType or 'direct'>`
- Favicon: `🔍`

---

## Edge cases

| Situation | Handling |
|---|---|
| No disputes found | Show AUTHN/STEP_UP/USER_SERVICE data only; label §6 "No disputes in 90-day window — extend lookback?" |
| No AUTHN data | Try 180-day window before failing |
| Multiple users on same device | Investigate all; add a "Shared device ring" note in §5 |
| Case B (low-ML, no VPN) | Classify non-victim devices SUSPECT; lead §7 with identity-change and velocity signal gaps; emphasize §8 root cause |
| Still-active fraud | Pulsing red alert in nav; flag in §2; note in §7 "no remediation has broken the chain" |
| Pre-ATO entry point found | Amber `⚠ PRE-ATO ENTRY` chip in nav; compute days-between-entry-and-fraud for §2; make Phase 1 of §8 the lead finding |
| Penny bypass detected | Amber `⚠ PENNY BYPASS` chip in nav; add Penny Social Engineering to §5; add Penny bypass to §7; annotate in §8 Phase 2 |
| Victim lockout after fraud | Populate §8 Phase 3 table; compute and display lockout days; note whether recovery path exists |
| ATOM absent for some devices | Show `—` in ATOM columns; do not fail; note coverage gap |
| ATOM high, ML low | Add to §7: "ATOM elevated session to X (Pth percentile) but ML did not meet block threshold — ATOM signal not connected to auth decision" |
| Phone risk signals on new number | Surface in §8 Phase 1 and add to §7: "Phone risk [signal] was present on number changed [N days] before fraud — change was allowed" |
| Undiscovered transactions | Add `undiscoveredUSD` to §2 KPI; add 🔍 events to timeline; add "Undiscovered Exposure" subsection to §6 |
| No identity changes in Query G | §8 Phase 1 = "No pre-ATO identity changes found — fraudster likely used stolen credentials directly (phishing/credential stuffing)"; root cause focuses on credential theft and direct account access |
| Address or name change pre-ATO | Add to Phase 1; assess whether physical card was re-issued and shipped to new address; check MOBILE_WALLET_PROVISIONING_AND_CARD_TOKENIZATION for card issuance near the change date |
| REMOTE_CONTROLLED_APPS populated | Flag in §8 Phase 1 or 2 as real-time social engineering; add to §7 as detection gap if it did not block the change |
| Socure reason codes flagged but change allowed | Add to §7 as gap: Socure identified identity risk but USER_SERVICE DECISION_OUTCOME = 'allow' |
| ML score elevated on USER_SERVICE event | Add to §7: identity change ML score elevated but not blocking; note ML_INFERENCE_MODEL_SCORE vs ML_PREDICTION_MODEL_SCORE difference if both present |
| NAMED_LIST hit not blocking | Add to §7; list the named list that was hit and the PII_TYPE affected |
| Forgot password / forgot email | Detect via STEP_UP OTP challenge correlated with prior phone/email change in USER_SERVICE; annotate in timeline as 'challenge' event with note "OTP now routes to fraudster-controlled number" |
| Card request after address change | Cross-reference MOBILE_WALLET_PROVISIONING_AND_CARD_TOKENIZATION for card issuance; if new card shipped to changed address, add to undiscovered exposure |

---

## Output checklist

- [ ] All 8 queries ran using **correct column names** (EVENT_NAME, DECISION_OUTCOME, DEVICE_IP_ADDRESS, PII_TYPE — not EVENT_TYPE/POLICY_DECISION/IP_ADDRESS/NEW_PHONE_NUMBER)
- [ ] Query H run for any case with a pre-ATO phone change in Query G
- [ ] Fraud date established from earliest dispute transaction (or earliest SUSPECT session if no disputes)
- [ ] All identity events split into pre-ATO / attack / lockout phases based on fraud date
- [ ] All PII_TYPE values checked: phone, email, address, name — each assessed for what it compromised
- [ ] REMOTE_CONTROLLED_APPS checked on every USER_SERVICE event; noted in §8 and §7 if populated
- [ ] Socure reason codes and ML scores from USER_SERVICE checked for gap between signal and decision
- [ ] NAMED_LIST / NAMED_LIST_RESULT checked; hits on new PII noted as gap if not blocking
- [ ] Every device classified (no UNKNOWN if avoidable; IP cross-match applied)
- [ ] ATOM score joined to each device in §3; ML vs ATOM disagreements flagged in §7
- [ ] Classification badge and row class computed dynamically from `d.cls` — never hardcoded
- [ ] Timeline covers full 90-day window; labeled day dividers for every date; entry-point events marked distinctly
- [ ] Forgot-password / forgot-email flows detected via STEP_UP OTP correlation with prior phone/email change
- [ ] Monetization pattern named; undiscovered exposure (including possible card intercept) flagged if found
- [ ] §7 covers all applicable gaps from the standard checklist
- [ ] §8 Phase 1: explains each pre-ATO change and what MFA/recovery channel it compromised (or states "none found")
- [ ] §8 Phase 2: annotates challenge step-down, Penny bypass, remote control, and MFA compromise if present
- [ ] §8 Phase 3: shows victim lockout duration and whether the victim's contact info is still the fraudster's
- [ ] §8 root cause bullets answer "why did this ATO succeed" in policy terms — one bullet per causal factor
- [ ] Artifact published, URL shared

# Device Monitor — Login Journey: Underlying Data Validation

**Dashboard:** [Device Monitor — Login Journey](https://chime.hex.tech/global/hex/Device-Monitor-Login-Journey-033vFY3NngaWUznoT1oqaB/draft/logic)  
**Audit date:** 2026-08-18  
**Last updated:** 2026-08-19  
**Method:** Static SQL audit of all 40+ cells + app section bindings; dry-run validation in Snowflake

---

## P0 — Stable Login Session Table (prerequisite for all fixes)

### Problem
`analytics.test.account_access_flows` is not designed for the dashboard's use case and can change without notice. The Q2–Q8 and PI cells all depend on it via a broken user+hour proxy join.

### Solution
`risk.test.siyu_login_sessions` — owned table built from stable DPL sources.

**PRs:**
- [#80910](https://github.com/1debit/chime-tf/pull/80910) — SQL file (`tasks_analyst_sql/siyu_login_sessions.sql`)
- [#80911](https://github.com/1debit/chime-tf/pull/80911) — Terraform task wiring (hourly cron)
- SQL source of truth: [schen-chime/auto_job_sql](https://github.com/schen-chime/auto_job_sql/blob/main/siyu_login_sessions.sql)

**Before first task run:** execute the CREATE TABLE DDL in the SQL file header comment once manually in Snowflake.

### Table design

| Column | Type | Notes |
|---|---|---|
| `login_date_pt` | DATE | America/Los_Angeles |
| `session_id` | VARCHAR | From `fact_account_access_flows` |
| `account_access_attempt_id` | VARCHAR | Dedup key; unique per attempt |
| `user_id` | VARCHAR | |
| `platform` | VARCHAR | ios / android / web / legacy_web |
| `session_event` | VARCHAR | First AUTHN event for this attempt |
| `decision_id` | VARCHAR | **Join key → `device_intelligence`** |
| `registration_id` | VARCHAR | **Join key → Sardine / PI `vendor_response`**; ~4% null |
| `attempt_login_success` | BOOLEAN | This specific attempt succeeded — **dashboard population field** |
| `session_login_success` | BOOLEAN | Session-level success; **NULL** when `has_session_match = FALSE` |
| `has_session_match` | BOOLEAN | FALSE = attempt not yet in `fact_account_access_flows` |
| `is_shadow_mode` | BOOLEAN | Always FALSE in this table (shadow rows excluded) |
| `attempt_started_at` | TIMESTAMP_LTZ | |
| `session_start_at` | TIMESTAMP_LTZ | NULL when `has_session_match = FALSE` |
| `first_login_success_at` | TIMESTAMP_LTZ | NULL when no session success |
| `num_ios_login` | INTEGER | |
| `num_android_login` | INTEGER | |
| `num_web_login` | INTEGER | |
| `num_legacy_web_login` | INTEGER | |

### Source tables and join chain

```
edw_db.account_access.fact_login_attempts       (~12h lag; dw_created_ts window)
  └─ decision_id                                → chime.decision_platform.device_intelligence
  └─ account_access_attempt_id (INNER JOIN)     → chime.decision_platform.authn
       └─ registration_id                       → Sardine / PI vendor_response
       └─ session_event, is_shadow_mode
  └─ session_id (LEFT JOIN)                     → edw_db.account_access.fact_account_access_flows
       └─ session_login_success, user_id, platform counts
```

### Schedule

- Cron: `5 * * * * America/Los_Angeles` (every hour at :05 — captures full prior-hour data)
- Warehouse: `ingestion_l_wh_gen_2_warehouse`
- Lookback: `dw_created_ts >= -3h` on `fact_login_attempts` (accounts for ~12h processing lag)
- AUTHN window: `original_timestamp >= -20h` (12h lag + 3h window + 5h buffer)
- History: `login_started_at >= -120 days` (covers full dashboard window)

### Population alignment with legacy `account_access_flows`

| Property | `account_access_flows` (legacy) | `siyu_login_sessions` (new) |
|---|---|---|
| Source | `analytics.test.login_requests` | `edw_db.account_access.fact_login_attempts` |
| Arkose filter | `pre_pw_checks_arkose = 1` | `pre_pw_checks_arkose = TRUE` ✓ |
| User filter | `user_id IS NOT NULL` | `user_id IS NOT NULL AND user_id <> 0` ✓ |
| Grain | user × PT calendar hour | **attempt** (finer) |
| Success | max success in hour | attempt-level + session-level (separate columns) |
| PW reset / phone update | Included | Not included |
| Timezone | America/Los_Angeles | America/Los_Angeles ✓ |

### Dry-run validation results (2026-08-19)

Test window: 27h `dw_created_ts` (captured ~1.08M attempts across 3 days including a backfill batch).

| Check | Result | Status |
|---|---|---|
| `fan_out_delta` (total rows − distinct attempts) | 0 | ✓ No fan-out |
| `remaining_null_userid` | 0 | ✓ User filter working |
| `shadow_rows` | 0 | ✓ Filter working |
| `distinct_platforms` | 4 (ios/android/web/legacy_web) | ✓ |
| `null_decision_id` | 12 / 1.08M (0.001%) | ✓ |
| `null_registration_id` | ~4% for hourly 3h window; 20.8% in test (backfill batch included 53h-old records outside 20h AUTHN window — expected) | ✓ |
| `null_session_success` | 363K correctly NULL (not FALSE) | ✓ Fix applied |
| `has_session_match = TRUE` | 66% of attempts | Expected — 34% not yet in `fact_account_access_flows` due to lag |

### Code review findings fixed before merge

| Severity | Finding | Fix |
|---|---|---|
| Critical | `SELECT *` inserts values into wrong columns — INSERT and enriched column order differed for `user_id`, `platform`, `session_event`, `decision_id`, `registration_id` | Replaced `SELECT *` with explicit named column list in the exact INSERT order |
| High | Missing `user_id IS NOT NULL AND user_id <> 0` filter | Added to `recent_attempts` CTE |
| High | `COALESCE(f.login_success, FALSE)` classified missing sessions as failed | Changed to `f.login_success` (NULL when no session match); added `has_session_match` flag |
| Medium | Shadow-mode filter documented but not applied | Added `WHERE is_shadow_mode = FALSE` to final SELECT |
| Medium | Daily 48h window missed late-arriving records | Switched to hourly cron + `dw_created_ts >= -3h` window |

---

## P0.1 — Population Field Validation

### Question
Which success field to use as the dashboard population filter: `attempt_login_success` or `session_login_success`?

### Validation method
30-day backfill (2026-07-17 to 2026-08-17) compared against the legacy `analytics.test.account_access_flows` daily distinct-user counts.

### Results

| Field | Agreement with legacy | Notes |
|---|---|---|
| `attempt_login_success = TRUE` | **99.73%** (≈ 3.3M / 3.3M) | **Selected** |
| `session_login_success = TRUE` | 73.35% | 23.58% of attempts have `session_id IS NULL` → classified as failed |

### Why `session_login_success` is wrong for this use case
`session_login_success` comes from `fact_account_access_flows` via a LEFT JOIN. 23.58% of rows in `risk.test.siyu_login_sessions` have `session_id IS NULL` (`has_session_match = FALSE`) because `fact_account_access_flows` lags up to 48 hours and the table's 3h incremental window doesn't wait for it. Those rows are inserted with `session_id = NULL` and `session_login_success = NULL`, which a `WHERE session_login_success = TRUE` filter drops — creating a ~25% undercount.

### Remaining gaps explained (0.27% ≈ 8,900/day)

| Gap component | Volume/day | Decision |
|---|---|---|
| `enrollment_token` attempts (new auth method) | ~8,700–9,300 | **Include** — legitimate silent re-auth; EDW added July 9, 2026 |
| Web password Arkose gap | ~4,400 | **Accept** — structural gap stable since ≥ May 21, 2026 (~0.8% of total) |
| Late-arriving rows not yet in backfill window | ~330 | Expected; captured on next hourly run |

### `enrollment_token` decision
`enrollment_token` = users who re-authenticate silently using a stored device token (no password prompt). These are not bot logins. EDW added this auth method to `fact_login_attempts` with `pre_pw_checks_arkose = TRUE` on July 9, 2026 (visible as a step-change from 0 to ~8,700/day). They are legitimate successful logins and should be included.

### Web password Arkose gap decision
~4,400 web password attempts/day appear in `siyu_login_sessions` but not in the legacy `account_access_flows`. This is a longstanding structural difference (confirmed stable across the full 90-day lookback, May 21 – Aug 18, 2026 at 99.97–100.00% Arkose pass rate). Root cause is likely a filter difference in how the legacy table defines `pre_pw_checks_arkose` for web password attempts. Accepted as a known structural gap; it does not affect fraud signal quality.

### Dashboard population definition (final)
```sql
WHERE attempt_login_success = TRUE
  AND session_id IS NOT NULL
```
Rows with `session_id IS NULL` (`has_session_match = FALSE`) are excluded — they represent attempts not yet matched by `fact_account_access_flows` and cannot be confirmed as complete login sessions.

Volume count (App + Web = total):
```sql
COUNT(DISTINCT session_id)
```
Each session is counted once, regardless of how many attempts it contains.

### Hex cell update status (2026-08-19)

All 16 dashboard cells migrated to `risk.test.siyu_login_sessions` with `attempt_login_success = TRUE AND session_id IS NOT NULL` and `COUNT(DISTINCT session_id)` volume counts.

| Cell ID | Variable | Status |
|---|---|---|
| `019ff756-ef83-710c-8fc3-639dd9e352b7` | `df_login_dod_aligned` | ✓ Updated |
| `019ff756-ef83-710c-8fc3-654142cea404` | `df_logins_by_channel` | ✓ Updated |
| `019ff756-ef83-710c-8fc3-69441bbeb7ca` | `df_volume` | ✓ Updated |
| `019ff756-ef83-710c-8fc3-6fef90c55d43` | `df_connection_type_mix` | ✓ Updated |
| `019ff756-ef83-710c-8fc3-70482470615e` | `df_countries` | ✓ Updated |
| `019ff756-ef83-710c-8fc3-8034cbb644ef` | `df_device_type_daily` | ✓ Updated |
| `019ff756-ef83-710c-8fc3-865593e3a102` | `df_authn_device_models` | ✓ Updated |
| `019ff756-ef83-710c-8fc3-8bb02a2bd3ac` | `df_authn_device_model_increases` | ✓ Updated |
| `019ff756-ef83-710c-8fc3-8eff68c52ff6` | `df_network_rates_daily` | ✓ Updated |
| `019ff756-ef83-710c-8fc3-93b2dc2a663b` | `df_behavioral_daily` | ✓ Updated |
| `019ff756-ef83-710c-8fc3-9bb7d83ecec8` | `df_system_language_monitor` | ✓ Updated |
| `019ff756-ef83-710c-8fc3-a07df0606413` | `coverage_results` | ✓ Updated |
| `019ff756-ef83-710c-8fc3-aa8ea43686df` | `arkose_coverage_results` | ✓ Updated |
| `019ff756-ef83-710c-8fc3-b05529718d28` | `di_coverage_overall` | ✓ Updated |
| `019ff756-ef83-710c-8fc3-bad7b10164ae` | `di_missing_by_platform_method` | ✓ Updated |
| `019ff756-ef83-710c-8fc3-c1779cc6f18f` | `di_arrival_latency` | ⚠ Hex CLI error — manual update needed |

---

## 1. Display Section → Data Cell Map

| App Section | Data Cell(s) | Metric Visualized |
|---|---|---|
| LoginVolume | `df_volume` + `df_login_dod_aligned` | Daily volume trend (Segment distinct users) + DoD KPIs (DI event counts) |
| ChannelVolume | `df_logins_by_channel` | Stacked App / Web |
| PlatformVolume | `df_volume` | Stacked iOS / Android / Browser |
| ConnectionMix | `df_connection_type_mix` | Top 6 connection types (120d) |
| GeoRanking | `df_us_states`, `df_non_us_countries` | Top 15 states/countries + WoW movers |
| DeviceType | `df_device_type_daily` | Top 10 OS versions, client mix |
| DeviceModel | `df_authn_device_models` + `df_authn_device_model_increases` | Top 15 volume; top 15 7v7 increase |
| NetworkVpnRates | `df_network_rates_daily` | VPN % + obfuscation % (Arkose source) |
| RemoteAccessSignals | `df_remote_tz` (Q6) | Remote-software %, IP-TZ mismatch % |
| LocationMismatch | `df_geo` (Q7) | Country-mismatch % |
| Behavioral | `df_behavioral_daily` | On-call %, avg interaction seconds |
| SystemLanguage | `df_system_language_monitor` | Volume, trend, WoW |
| DiCoverage | `di_coverage_overall`, `di_missing_by_platform_method`, `di_arrival_latency` | DI present/missing, missing by platform×method, latency buckets |
| CoverageMonitor | `coverage_results`, `arkose_coverage_results` | Daily Sardine + Arkose coverage % |
| SardineHighRisk | `df_q9_t1_sardine_rate`, `df_q9_t2_sardine_increase` | High-risk rate; Δ pct pts vs prior 30d |
| SardineRules | `sardine_rule_daily`, `sardine_rule_wow`, `sardine_shadow_top10_daily` | Live vs shadow trigger volume |
| PlayIntegrityAndroid | PI coverage, PI daily, PI verdicts | Coverage %, verdict rates, distribution |

### Orphaned cells (computed but never displayed)

| Cell | Output var | Note |
|---|---|---|
| Q0 | `df_success_rate` | Success rate from ACCOUNT_ACCESS_FLOWS |
| Q2 | `df_device_type` | Device type from DI×flows join |
| Q3 | `df_browser_installer` | Browser/installer from DI×flows join |
| Q4 | `df_integrity` | Integrity signals from DI×flows join |
| Q5 | `df_network` | Competing VPN definition vs displayed NetworkVpnRates |
| Q8 | `df_behavioral` | Competing on-call definition vs displayed Behavioral |
| `high_risk_trend` | — | Risk tier trend; tier overlap bugs; orphaned |

---

## 2. Data Cell Inventory

### Overview / DI-based cells

| Cell | Table(s) | Window | Grain | Partial-day included? |
|---|---|---|---|---|
| `df_login_dod_aligned` | `CHIME.DECISION_PLATFORM.DEVICE_INTELLIGENCE` | Today vs yesterday, hour-aligned | 1 row | Yes (today-so-far) |
| `df_connection_type_mix` | DEVICE_INTELLIGENCE | **120d**, no upper bound | day × CONNECTION_DATA_CONNECTION_TYPE | Yes |
| `df_countries` / `df_us_states` / `df_non_us_countries` | DEVICE_INTELLIGENCE | 30d, no upper bound | day × country × state | Yes |
| `df_system_language_monitor` | DEVICE_INTELLIGENCE | **120d**, no upper bound | day × OS_DATA_LANGUAGE | Yes |
| `df_behavioral_daily` | DEVICE_INTELLIGENCE + DEVICE_EVENTS_V1_VENDOR_RESPONSE | **120d** | day (FULL OUTER JOIN) | Yes |
| `df_device_type_daily` | `CHIME.DECISION_PLATFORM.AUTHN` | 30d, no upper bound | day × dimension × value | Yes |
| `df_authn_device_models` | AUTHN | 30d, no upper bound | day × DEVICE_MODEL | Yes |
| `df_authn_device_model_increases` | AUTHN | 14d (7v7) + **unbounded** first_seen scan | model | No (has `< CURRENT_DATE`) |
| `df_network_rates_daily` | AUTHN (ARKOSE_RESPONSE_IS_VPN/PROXY/TOR/PUBLIC_ACCESS_POINT) | **120d**, no upper bound | day | Yes |

### DI × flows join family (currently displayed cells: Q6, Q7, PI — will be replaced with `siyu_login_sessions` join)

| Cell | Window | Success filter | Displayed? |
|---|---|---|---|
| Q2 `df_device_type` | 7d | `LOGIN_SUCCESS >= 1` | No |
| Q3 `df_browser_installer` | 7d | `LOGIN_SUCCESS >= 1` | No |
| Q4 `df_integrity` | 30d | `LOGIN_SUCCESS = 1` | No |
| Q5 `df_network` | 30d | `LOGIN_SUCCESS = 1` | No |
| Q6 `df_remote_tz` | 30d | `LOGIN_SUCCESS = 1` | Yes → **P2 target** |
| Q7 `df_geo` | 30d | `LOGIN_SUCCESS = 1` | Yes → **P2 target** |
| Q8 `df_behavioral` | 30d | `LOGIN_SUCCESS = 1` | No |
| PI coverage / daily / verdicts | 30d | `LOGIN_SUCCESS = 1` AND `NUM_ANDROID_LOGIN > 0` | Yes → **P2 target** |

### Other cells

| Cell | Table(s) | Window | Key filter |
|---|---|---|---|
| `df_volume` (Q1) | `SEGMENT.CHIME_PROD.LOGIN_SUCCESS` | 120d, `< CURRENT_DATE` | `COUNT(DISTINCT USER_ID)`, America/Los_Angeles |
| `df_logins_by_channel` | `ANALYTICS.TEST.ACCOUNT_ACCESS_FLOWS` | 30d, `< CURRENT_DATE` | `LOGIN_SUCCESS = 1` |
| `coverage_results` | DI (30d) LEFT JOIN Sardine on `REGISTRATION_ID` | 30d | — |
| `arkose_coverage_results` | DI → AUTHN (`DECISION_ID`) → Arkose | Capped at Arkose freshness | — |
| `di_coverage_overall` / `di_missing_by_platform_method` / `di_arrival_latency` | AUTHN `*_auth_succeeded` LEFT JOIN DI on `DECISION_ID` | 31d DI / 30d AUTHN | — |
| `df_device_model` (Sardine) | VENDOR_RESPONSE JSON | 31d | **Missing `JOURNEY = 'JOURNEY_LOGIN'`** |
| `sardine_rule_daily` / `_wow` / `_shadow_top10` | VENDOR_RESPONSE ⋈ REGISTRATION_STATUS_UPDATED | 30d | `JOURNEY_LOGIN` |

---

## 3. Cross-Check: Alignment Issues

### CRITICAL — Affects metric accuracy

#### C1: "Successful logins" has three different definitions
| Population | Filter used | Where |
|---|---|---|
| Initiated (not confirmed success) | `SESSION_EVENT = 'username_auth_initiated'` | ConnectionMix, Q9, SystemLanguage, Behavioral, DI DoD |
| Confirmed succeeded | `SESSION_EVENT IN ('*_auth_succeeded')` | DI Coverage cells |
| Session-level success | `ACCOUNT_ACCESS_FLOWS.LOGIN_SUCCESS = 1` | Q2–Q8, PI, ChannelVolume |

**Fix (P1):** Standardize all cells to `siyu_login_sessions WHERE attempt_login_success = TRUE`.

#### C2: Denominator mismatch between LoginVolume and all panels below
- `df_volume` (stated denominator): `COUNT(DISTINCT USER_ID)` from Segment, America/Los_Angeles, users per day
- Every panel below: `COUNT(*)` DI/AUTHN events in UTC
- Within the same KPI card: "Today so far" = DI event counts; "Last complete day" = Segment distinct users

#### C3: DI × flows hour join is a proxy, not a session join
`CAST(di.USER_ID AS TEXT) = f.USER_ID AND DATE_TRUNC('hour', di.ORIGINAL_TIMESTAMP) = DATE_TRUNC('hour', f.EVENT_HOUR)` — fan-out, no success confirmation, timezone ambiguity.

**Fix (P2):** Replace with `di.DECISION_ID = s.decision_id AND s.attempt_login_success = TRUE` joining `siyu_login_sessions`.

#### C4: Inconsistent success predicate within the same join family
- Q2, Q3: `f.LOGIN_SUCCESS >= 1` (includes multi-success hours)
- Q4–Q8, PI: `f.LOGIN_SUCCESS = 1`

#### C5: DI Coverage `di_decisions` CTE has no event filters
No `EVENT_NAME`, `SUB_EVENT_NAME`, `SESSION_EVENT`, or `IS_SHADOW_MODE = FALSE`. Shadow-mode events count as "DI Present" → coverage overstated.

#### C6: Sardine device-model cells missing `JOURNEY = 'JOURNEY_LOGIN'`
`df_device_model` reads all `VENDOR_SARDINE` responses but columns named `login_date` / `logins`.

#### C7: Competing metric definitions (displayed vs orphaned)
| Metric | Displayed (active) | Orphaned (dead code) |
|---|---|---|
| VPN rate | AUTHN `ARKOSE_RESPONSE_IS_VPN` | DI `CONNECTION_DATA_IS_VPN` |
| "Any obfuscation" | VPN + proxy + Tor + **public_access_point** | VPN + proxy + Tor + **datacenter** |
| On-phone-call | `BEHAVIORAL_DATA_CALL_STATUS = 'on_call'` | `BEHAVIORAL_DATA_ON_PHONE_CALL` boolean |
| Remote access | `OS_DATA:is_remote_software` (Sardine, Q6) | `OS_DATA_REMOTE_CONTROL_APPS` (DI, Q4) |

---

### Date range / grain misalignment

#### D1: Five different windows coexist without consistent labeling
| Window | Cells |
|---|---|
| 7d | Q2, Q3 |
| 14d | Device model increases body; unbounded for `first_seen` |
| 30d | Q4–Q8, PI, device type, device model trend, geo, coverage cells |
| 31d | Sardine device model, DI coverage (DI side), high_risk_trend |
| 120d | ConnectionMix, NetworkVpnRates, Behavioral, SystemLanguage, LoginVolume |

**SystemLanguage mislabel:** SQL = 120d, column named `total_30d_logins`, trend label says "30 days".

#### D2: Only 3 cells exclude partial current day
`df_volume`, `df_logins_by_channel`, `df_authn_device_model_increases` use `< CURRENT_DATE`. All others include today's incomplete data.

#### D3: Timezone mixing
Q1 / `df_logins_by_channel`: America/Los_Angeles. All other cells: raw UTC.

---

### Join key inconsistencies

#### J1: Four different session keys across coverage panels
| Coverage panel | Join key |
|---|---|
| DI Coverage | `DECISION_ID` (AUTHN → DI) |
| Sardine Coverage | `REGISTRATION_ID` (DI → Sardine) |
| PI Coverage | `REGISTRATION_ID` (DI → PI) |
| Arkose Coverage | `DECISION_ID` → `ACCOUNT_ACCESS_ATTEMPT_ID` |
| Q2–Q8 panels | `USER_ID` (text cast) + hour bucket |

#### J2: `USER_ID` type inconsistency
Q2–Q8: `CAST(di.USER_ID AS TEXT)`. Latency cell: `TRY_TO_NUMBER(a.USER_ID)` — silently nulls non-numeric IDs.

#### J3: Coverage lookback buffer asymmetry
| Panel | Auth window | Vendor window | Note |
|---|---|---|---|
| DI Coverage | 30d | 31d | Buffer intentional ✓ |
| Sardine Coverage | 30d | 30d | Edge undercount |
| PI Coverage | 30d | 30d | Edge undercount |
| Arkose Coverage | 30d | Capped at freshness | ✓ |

#### J4: DI latency cell measures wrong session
Joins any `JOURNEY_LOGIN` event for the user within 24h — not the specific missing session.

---

### Denominator and null handling

| # | Issue | Cell | Impact |
|---|---|---|---|
| N1 | `REGISTRATION_STATUS_UPDATED` fan-out with no dedupe | Q3, Q6, Sardine rules | Inflated rates |
| N2 | `SUM(bool::INT)` without `COALESCE` | Q4 | Rates are lower bounds |
| N3 | `GEO_IP_DATA_COUNTRY != 'US'` excludes NULLs + misses 'USA'/'UNITED STATES' | Q7 | Non-US rate overstated |
| N4 | Q9 T2 baseline: unweighted daily rate AVG, no volume floor | Sardine high-risk | Baseline skewed by low-traffic days |
| N5 | ChannelVolume priority-ordering — iOS+Web hour = App only | ChannelVolume | Web volume understated |
| N6 | `first_seen_date` scans full unbounded AUTHN history | DeviceModel increases | Expensive + inconsistent with 14d body |

---

## 4. Unverified / Test Tables in Use

| Table | Used by | Risk |
|---|---|---|
| `ANALYTICS.TEST.ACCOUNT_ACCESS_FLOWS` | Q2–Q8, PI, `df_logins_by_channel` | Not designed for this use; may change without notice → **replacing with `siyu_login_sessions`** |
| `risk.test.siyu_sardine_rules` | Sardine rule cells | Owned by Siyu; stable (manual upload) |
| `CHIME.DECISION_PLATFORM.*` (raw events) | Most DI/AUTHN cells | Raw; no Analytics Verified model |
| `STREAMING_PLATFORM.SEGMENT_AND_HAWKER_PRODUCTION.*` | Q1, behavioral, Sardine cells | Raw |

---

## 5. Fix Priority Tracker

| Priority | Fix | Status | PR / Notes |
|---|---|---|---|
| **P0** | Create `risk.test.siyu_login_sessions` stable table | **Done** — DDL run manually; 30-day backfill inserted; hourly task pending PR merge | [#80910](https://github.com/1debit/chime-tf/pull/80910) (SQL), [#80911](https://github.com/1debit/chime-tf/pull/80911) (TF) |
| **P0.1** | Validate population field and align all 16 Hex cells | **Done** — `attempt_login_success = TRUE AND session_id IS NOT NULL`; 15/16 cells updated via CLI; `di_arrival_latency` cell needs manual update | See §P0.1 above |
| **P1** | Pin single "successful login" definition across all cells | In progress | All 16 base cells now use `siyu_login_sessions WHERE attempt_login_success = TRUE AND session_id IS NOT NULL`; remaining orphaned Q-cells (Q2–Q8) to be cleaned up under P13 |
| **P2** | Replace DI×flows user+hour join with `decision_id` join | Pending | Q6, Q7, PI cells: `di.DECISION_ID = s.decision_id AND s.attempt_login_success = TRUE` |
| **P3** | Add `< CURRENT_DATE` upper bound to all cells | Pending | ConnectionMix, Q9, SystemLanguage, Q4–Q8, NetworkVpnRates, Behavioral, DeviceType/Model, coverage cells |
| **P4** | Fix DI Coverage `di_decisions` filters | Pending | Add `EVENT_NAME`, `SUB_EVENT_NAME`, `SESSION_EVENT`, `IS_SHADOW_MODE = FALSE` |
| **P5** | Add `JOURNEY = 'JOURNEY_LOGIN'` to Sardine device-model cell | Pending | One-line fix in `df_device_model` |
| **P6** | Standardize timezones (all to America/Los_Angeles) | Pending | Update `CURRENT_DATE` anchors and `DATE_TRUNC` calls |
| **P7** | Standardize coverage lookback buffers (31d vendor / 30d auth) | Pending | Sardine and PI coverage cells |
| **P8** | Fix Q7 country matching (null + 'USA' variants) | Pending | `NOT IN ('US','USA','UNITED STATES','UNITED STATES OF AMERICA') OR IS NULL` |
| **P9** | Add `COALESCE(..., FALSE)` to Q4 boolean numerators | Pending | Prevents silent lower-bound rates |
| **P10** | Fix SystemLanguage column naming and label (120d not 30d) | Pending | Rename `total_30d_logins` → `total_120d_logins`; fix subtitle |
| **P11** | Deduplicate `REGISTRATION_STATUS_UPDATED` joins in Q6 | Pending | Add `QUALIFY ROW_NUMBER() OVER (PARTITION BY registration_id ORDER BY created_at DESC) = 1` |
| **P12** | Fix ChannelVolume double-counting | Pending | Derive platform from `siyu_login_sessions.platform` |
| **P13** | Delete/fix orphaned cells (Q0, Q2, Q3, Q4, Q5, Q8, `high_risk_trend`) | Pending | Remove dead code |

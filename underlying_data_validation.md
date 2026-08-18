# Device Monitor — Login Journey: Underlying Data Validation

**Dashboard:** [Device Monitor — Login Journey](https://chime.hex.tech/global/hex/Device-Monitor-Login-Journey-033vFY3NngaWUznoT1oqaB/draft/logic)  
**Audit date:** 2026-08-18  
**Method:** Static SQL audit of all 40+ cells + app section bindings (no queries executed)

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
| Q5 | `df_network` | Network obfuscation from DI×flows join (competing def of VPN vs displayed) |
| Q8 | `df_behavioral` | Behavioral from DI×flows join (competing def of on-call vs displayed) |
| `high_risk_trend` | — | Risk tier trend; has tier overlap bugs |

---

## 2. Data Cell Inventory

### Overview / DI-based cells

| Cell | Table(s) | Window | Grain | Partial-day included? |
|---|---|---|---|---|
| `df_login_dod_aligned` | `CHIME.DECISION_PLATFORM.DEVICE_INTELLIGENCE` | Today vs yesterday, hour-aligned | 1 row | Yes (today-so-far) |
| `df_connection_type_mix` | DEVICE_INTELLIGENCE | **120d**, no upper bound | day × CONNECTION_DATA_CONNECTION_TYPE | Yes |
| `df_countries` / `df_us_states` / `df_non_us_countries` | DEVICE_INTELLIGENCE | 30d, no upper bound | day × country × state | Yes |
| `df_system_language_monitor` | DEVICE_INTELLIGENCE | **120d**, no upper bound | day × OS_DATA_LANGUAGE (BROWSER fallback) | Yes |
| `df_behavioral_daily` | DEVICE_INTELLIGENCE + DEVICE_EVENTS_V1_VENDOR_RESPONSE + REGISTRATION_STATUS_UPDATED | **120d** | day (FULL OUTER JOIN on day) | Yes |
| `df_device_type_daily` | `CHIME.DECISION_PLATFORM.AUTHN` | 30d, no upper bound | day × dimension × value | Yes |
| `df_authn_device_models` | AUTHN | 30d, no upper bound | day × DEVICE_MODEL | Yes |
| `df_authn_device_model_increases` | AUTHN | 14d (7v7) + **unbounded** first_seen scan | model | No (has `< CURRENT_DATE`) |
| `df_network_rates_daily` | AUTHN (ARKOSE_RESPONSE_IS_VPN/PROXY/TOR/PUBLIC_ACCESS_POINT) | **120d**, no upper bound | day | Yes |

### DI × flows join family (all join `CAST(di.USER_ID AS TEXT) = f.USER_ID AND DATE_TRUNC('hour', di.ORIGINAL_TIMESTAMP) = DATE_TRUNC('hour', f.EVENT_HOUR)` against `ANALYTICS.TEST.ACCOUNT_ACCESS_FLOWS`)

| Cell | Window | Success filter | Displayed? |
|---|---|---|---|
| Q2 `df_device_type` | 7d | `LOGIN_SUCCESS >= 1` | No |
| Q3 `df_browser_installer` | 7d | `LOGIN_SUCCESS >= 1` | No |
| Q4 `df_integrity` | 30d | `LOGIN_SUCCESS = 1` | No |
| Q5 `df_network` | 30d | `LOGIN_SUCCESS = 1` | No |
| Q6 `df_remote_tz` | 30d | `LOGIN_SUCCESS = 1` | Yes |
| Q7 `df_geo` | 30d | `LOGIN_SUCCESS = 1` | Yes |
| Q8 `df_behavioral` | 30d | `LOGIN_SUCCESS = 1` | No |
| PI coverage / daily / verdicts | 30d | `LOGIN_SUCCESS = 1` AND `NUM_ANDROID_LOGIN > 0` | Yes |

### Other cells

| Cell | Table(s) | Window | Key filter |
|---|---|---|---|
| `df_volume` (Q1) | `SEGMENT.CHIME_PROD.LOGIN_SUCCESS` | 120d, **`< CURRENT_DATE`** | `COUNT(DISTINCT USER_ID)`, America/Los_Angeles |
| `df_logins_by_channel` | `ANALYTICS.TEST.ACCOUNT_ACCESS_FLOWS` | 30d, **`< CURRENT_DATE`** | `LOGIN_SUCCESS = 1` |
| `df_success_rate` (Q0) | ACCOUNT_ACCESS_FLOWS | 30d | `LOGIN_STARTED = 1` denominator |
| `coverage_results` | DI (30d) LEFT JOIN Sardine on **`REGISTRATION_ID`** | 30d | — |
| `arkose_coverage_results` | DI → AUTHN (`DECISION_ID`) → `EDW_DB.BIO.FACT_ARKOSE_CHALLENGE_EVENTS` | Capped at Arkose freshness | — |
| `di_coverage_overall` / `di_missing_by_platform_method` / `di_arrival_latency` | AUTHN `*_auth_succeeded` LEFT JOIN DI on **`DECISION_ID`** | 31d DI / 30d AUTHN (8d latency check) | — |
| `df_device_model` (Sardine) | VENDOR_RESPONSE JSON | 31d | **Missing `JOURNEY = 'JOURNEY_LOGIN'`** |
| `sardine_rule_daily` / `_wow` / `_shadow_top10` | VENDOR_RESPONSE ⋈ REGISTRATION_STATUS_UPDATED | 30d | `JOURNEY_LOGIN` |
| `high_risk_trend` | AUTHN + STEP_UP_PLATFORM (FACE_AUTH) | 31d scan → 30d output | Orphaned |

---

## 3. Cross-Check: Alignment Issues

### CRITICAL — Affects metric accuracy

#### C1: "Successful logins" has three different definitions
| Population | Filter used | Where |
|---|---|---|
| Initiated (not confirmed success) | `SESSION_EVENT = 'username_auth_initiated'` | ConnectionMix, Q9, SystemLanguage, Behavioral, DI DoD |
| Confirmed succeeded | `SESSION_EVENT IN ('*_auth_succeeded')` | DI Coverage cells |
| Session-level success | `ACCOUNT_ACCESS_FLOWS.LOGIN_SUCCESS = 1` | Q2–Q8, PI, ChannelVolume |

The first two sets are **disjoint** on `SESSION_EVENT`. DI Coverage does not measure coverage of the population the overview charts use.

**Fix:** Standardize to `risk.test.siyu_login_sessions` (stable table built from `edw_db.account_access.fact_account_access_flows` + AUTHN; see [PR #80910](https://github.com/1debit/chime-tf/pull/80910) / [PR #80911](https://github.com/1debit/chime-tf/pull/80911)).

#### C2: Denominator mismatch between LoginVolume and all panels below
- `df_volume` (the stated denominator): `COUNT(DISTINCT USER_ID)` from Segment, **America/Los_Angeles**, one per user per day
- Every panel below: `COUNT(*)` DI/AUTHN events in **UTC**
- Different table, grain (users vs events), day boundary timezone
- Within the same KPI card: "Today so far" = DI event counts; "Last complete day" = Segment distinct users

#### C3: DI × flows hour join is a proxy, not a session join
`CAST(di.USER_ID AS TEXT) = f.USER_ID AND DATE_TRUNC('hour', di.ORIGINAL_TIMESTAMP) = DATE_TRUNC('hour', f.EVENT_HOUR)` means:
- A DI event matches any hour a user had *some* success — doesn't confirm the specific event succeeded
- Multiple DI events in one hour all match the same flow row (fan-out, inflates `COUNT(*)`)
- `EVENT_HOUR` is in America/Los_Angeles; `ORIGINAL_TIMESTAMP` is UTC — potential silent row drops

**Fix:** Join on `di.DECISION_ID = siyu_login_sessions.decision_id WHERE session_login_success = TRUE`.

#### C4: Inconsistent success predicate within the same join family
- Q2, Q3: `f.LOGIN_SUCCESS >= 1` (includes multi-success hours)
- Q4–Q8, PI: `f.LOGIN_SUCCESS = 1`

#### C5: DI Coverage has no event filters in `di_decisions` CTE
No `EVENT_NAME`, `SUB_EVENT_NAME`, `SESSION_EVENT`, or `IS_SHADOW_MODE = FALSE` on the DI side. Shadow-mode events count as "DI Present" → coverage overstated.

#### C6: Sardine device-model cells missing `JOURNEY = 'JOURNEY_LOGIN'`
`df_device_model` reads all `VENDOR_SARDINE` responses (enrollment, transactions) but columns are named `login_date` / `logins`. Sardine coverage and rule cells *do* filter to `JOURNEY_LOGIN`.

#### C7: Competing metric definitions (displayed vs orphaned)
| Metric | Displayed (active) | Orphaned (dead code) |
|---|---|---|
| VPN rate | AUTHN `ARKOSE_RESPONSE_IS_VPN` | DI `CONNECTION_DATA_IS_VPN` |
| "Any obfuscation" | VPN + proxy + Tor + **public_access_point** | VPN + proxy + Tor + **datacenter** |
| On-phone-call | `BEHAVIORAL_DATA_CALL_STATUS = 'on_call'` | `BEHAVIORAL_DATA_ON_PHONE_CALL` boolean |
| Remote access | `OS_DATA:is_remote_software` (Sardine, Q6) | `OS_DATA_REMOTE_CONTROL_APPS` (DI, Q4); `REMOTE_CONTROLLED_APPS` (high_risk_trend) |

---

### Date range / grain misalignment

#### D1: Five different windows coexist without consistent labeling
| Window | Cells |
|---|---|
| 7d | Q2, Q3 |
| 14d | Device model increases (body); unbounded for `first_seen` |
| 30d | Q4–Q8, PI, device type, device model trend, geo, coverage cells, Q1 channel |
| 31d | Sardine device model, DI coverage (DI side), high_risk_trend |
| 120d | ConnectionMix, NetworkVpnRates, Behavioral, SystemLanguage, LoginVolume |

**SystemLanguage mislabel:** SQL window = 120d, column named `total_30d_logins`, trend label says "30 days". Top-15 ranking is 120-day, not 30-day.

#### D2: Only 3 cells exclude partial current day (`< CURRENT_DATE`)
- `df_volume`, `df_logins_by_channel`, `df_authn_device_model_increases`
- All others include today's incomplete data; LoginVolume claims "complete days only"

#### D3: Timezone mixing
- Q1 / `df_logins_by_channel`: America/Los_Angeles
- All other cells: UTC `ORIGINAL_TIMESTAMP` bucketed by `CURRENT_DATE` (session timezone)

---

### Join key inconsistencies

#### J1: Four different session keys across coverage panels
| Coverage panel | Join key |
|---|---|
| DI Coverage | `DECISION_ID` (AUTHN → DI) |
| Sardine Coverage | `REGISTRATION_ID` (DI → Sardine) |
| PI Coverage | `REGISTRATION_ID` (DI → PI) |
| Arkose Coverage | `DECISION_ID` → `ACCOUNT_ACCESS_ATTEMPT_ID` (AUTHN → Arkose) |
| Q2–Q8 panels | `USER_ID` (text cast) + hour bucket |

Presented side-by-side as comparable coverage tiles.

#### J2: `USER_ID` type inconsistency
- Q2–Q8: `CAST(di.USER_ID AS TEXT)`
- Latency cell: `TRY_TO_NUMBER(a.USER_ID)` — silently nulls non-numeric IDs, then `WHERE user_id IS NOT NULL` drops them (silent population loss)

#### J3: Coverage lookback buffer asymmetry
| Panel | Auth window | Vendor window | Note |
|---|---|---|---|
| DI Coverage | 30d | 31d | Buffer intentional |
| Sardine Coverage | 30d | 30d | Edge undercount |
| PI Coverage | 30d | 30d | Edge undercount |
| Arkose Coverage | 30d | Capped at freshness date | Correct |

#### J4: DI latency cell measures wrong session
Joins any `JOURNEY_LOGIN` registration event for the user within 24h — not the specific missing session's own DI signal.

---

### Denominator and null handling

| # | Issue | Cell | Impact |
|---|---|---|---|
| N1 | `REGISTRATION_STATUS_UPDATED` fan-out with no dedupe | Q3, Q6, Sardine rule cells | Inflated rates |
| N2 | `SUM(bool::INT)` without `COALESCE` — nulls silently drop from numerator but stay in denominator | Q4 | Rates are lower bounds; material given DI coverage gaps |
| N3 | `GEO_IP_DATA_COUNTRY != 'US'` excludes NULLs + misses 'USA'/'UNITED STATES' variants | Q7 | Non-US rate overstated |
| N4 | Q9 T2 baseline: unweighted daily rate AVG, no volume floor | Sardine high-risk baseline | Low-traffic days drag baseline equally |
| N5 | Q0 `LOGIN_SUCCESS` only counted over `LOGIN_STARTED = 1` rows | Q0 (orphaned) | Biased success rate |
| N6 | ChannelVolume priority-ordering — session with both iOS and Web logins = App only | ChannelVolume | Web volume understated |
| N7 | `first_seen_date` in device-model increases scans full unbounded AUTHN history | DeviceModel increase | Expensive + inconsistent with 14d body |

---

## 4. Unverified / Test Tables in Use

The following tables are in test schemas and are not Analytics Verified models:

| Table | Used by |
|---|---|
| `ANALYTICS.TEST.ACCOUNT_ACCESS_FLOWS` | Q2–Q8, PI, `df_success_rate`, `df_logins_by_channel` |
| `risk.test.siyu_sardine_rules` | Sardine rule cells |
| `CHIME.DECISION_PLATFORM.*` (raw events) | Most DI/AUTHN cells |
| `STREAMING_PLATFORM.SEGMENT_AND_HAWKER_PRODUCTION.*` | Q1, behavioral, sardine cells |

---

## 5. Fix Priority

| Priority | Fix | Status |
|---|---|---|
| P0 | Create `risk.test.siyu_login_sessions` stable table | PRs [#80910](https://github.com/1debit/chime-tf/pull/80910) / [#80911](https://github.com/1debit/chime-tf/pull/80911) created; DDL needs manual run |
| P1 | Pin single "successful login" definition across all cells | Pending |
| P2 | Replace DI×flows user+hour join with `decision_id` join | Pending |
| P3 | Add `< CURRENT_DATE` upper bound to all cells | Pending |
| P4 | Fix DI Coverage cell filters (add `IS_SHADOW_MODE = FALSE`, journey filter) | Pending |
| P5 | Add `JOURNEY = 'JOURNEY_LOGIN'` to Sardine device-model cell | Pending |
| P6 | Standardize timezones (all to America/Los_Angeles) | Pending |
| P7 | Standardize coverage lookback buffers (31d vendor / 30d auth) | Pending |
| P8 | Fix Q7 country matching (null + 'USA' variants) | Pending |
| P9 | Add `COALESCE(..., FALSE)` to Q4 boolean numerators | Pending |
| P10 | Fix SystemLanguage column naming and label (120d not 30d) | Pending |
| P11 | Deduplicate `REGISTRATION_STATUS_UPDATED` joins in Q6 | Pending |
| P12 | Fix ChannelVolume double-counting | Pending |
| P13 | Delete/fix orphaned cells (Q0, Q2, Q3, Q4, Q5, Q8, high_risk_trend) | Pending |

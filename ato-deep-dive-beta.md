# ATO Session Brief — Beta

Cross-team-ready ATO case summary. Pulls the same data sources as `ato-deep-dive`; omits monetization flow; adds an attack clock bar and a per-session ML score vs. policy threshold comparison. Frames findings around controls that engaged, not gaps. Suitable for sharing outside the authentication team.

## Input

`$ARGUMENTS` — user ID (numeric), device ID, or dispute claim ID. Resolve to user_id using Step 1 of `ato-deep-dive.md`.

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

Run queries A–G from `ato-deep-dive.md` in parallel. Add one additional pull after the fraud date is known:

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

---

## Output — HTML Artifact

Same CSS token system as `ato-deep-dive.md`. Design differences for beta:

- Primary accent: `--c-info` (blue) for controls that engaged; `--c-ato` (red) for confirmed fraud transactions only
- Nav bar chips: `chip-neutral` or `chip-info` — no `chip-warn` / `chip-ato` in the header
- Clock bar colors: amber = probe/login entries, red = transactions, blue = controls/challenges, green = victim sessions
- No root-cause policy critique section

### §1 — Case Summary

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

Identical to standard skill §2, with one added column: **ML Band** — given the device's max ML score, which ATOM v204 band does it fall in? Label each row with the band (STEP-DOWN / PASS / STEP-UP / SCAN-ID / NO SCORE).

### §4 — Score vs. Threshold

Two parts:

**A. Spectrum bar** — a horizontal bar spanning 0–1.0 with labeled threshold markers at 0.03 (v183 step_down), 0.07 (v204 step_down), 0.70 (step_up boundary), and 0.98 (scan_id boundary). Color-fill each band. Plot each fraud-day session as a labeled vertical tick on the bar. Mark ML-triggered sessions (where the score crossing a band boundary caused the outcome) with a distinct indicator (e.g., ★ or bold tick).

**B. Per-session table** — columns: Session | Device | ML Score | Band (v204) | Expected Outcome | Actual AUTHN Outcome | Control Source

In the "Control Source" column, state either:
- `ATOM ML score (< 0.03 band)` — score crossed a boundary, ML caused the outcome
- `Velocity rule` — velocity counter fired; ML score irrelevant to this outcome
- `Deterministic rule` — policy rule with no ML dependency

**Near-threshold highlight:** If any score is within 0.02 of a band boundary, add a ★ marker and a note in the table. This helps reviewers understand margin without implying policy failure.

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

---

## Tone

- State what happened, not what should have happened
- "ATOM score placed this session in the pass band (0.1334, 0.07–0.70)" not "ML failed to catch this"
- "Velocity rule applied SCAN_ID on new out-of-state device" not "fraudster was blocked"
- "OTP issued and confirmed on the phone number on file at that moment" not "OTP bypass"
- Quantify everything: scores, timestamps, counts, dollar amounts
- Remove modifiers like "clearly", "obviously", "significantly"
- If something is uncertain, either verify it or put it in a clearly labeled appendix

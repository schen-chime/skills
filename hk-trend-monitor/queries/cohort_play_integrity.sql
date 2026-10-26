-- READ ONLY: live Android snapshot plus event-time qualified-login signal volume.
-- This metric is independent of new additions and of the new-user majority rule.
-- It differs from the historical latest-pre-phone-change 145/908 vs 39/4165 rate.
--
-- Required session variables: $chart_start = $cutoff minus 7 days; $cutoff.
-- Snapshot activity and selected-state callbacks use [chart_start, cutoff).
-- Qualified login tracking additionally scans 24h before chart_start for prior PI,
-- registration evidence, and bounded attempt-first-observed boundary deduplication.
-- The 24h freshness cap is a monitoring choice, not a guarantee of current state.
-- Snapshot flags are NEVER projected backward to classify historical attempts.
-- Per-attempt lookup matches the exact registration plus SDK device and member;
-- it is a prior observation association, not verified attestation request binding.
-- Template substitutions (caller must validate before substitution):
--   COHORT_USERS: a typed SELECT with one positive numeric user_id column.
--     Empty: SELECT NULL::NUMBER user_id WHERE FALSE
--   BASELINE_LIMIT: positive integer, normally 5000, bounded by the caller.
-- No member IDs, device IDs, IPs, or query results belong in this template.
--
-- SDK device identity is TRIM(device_id), case preserved, in AUTHN and the
-- verified REGISTRATION_STATUS_UPDATED._device_id field. registration_device_id
-- is a different namespace and is never silently equated to the SDK device ID.
-- The bridge uses DEVICE_PLATFORM_ANDROID_APP rows, including JOURNEY_APP_OPEN.
-- Its table is in the production stream; it has no assumed shadow-mode field.
-- Ownership checks inspect every production AUTHN owner and every explicit
-- status-stream owner of an eligible SDK device in the common seven-day window.
-- Multiple/invalid owners and devices without a positive AUTHN owner are excluded.
-- Anonymous AUTHN 0/NULL pre-login events do not conflict with one positive owner.
-- This window cannot establish whether a device had another owner before it.
--
-- Registrations use the eight-day evidence interval and are accepted only when all observed rows identify one exact
-- (positive member, SDK device) pair. Anonymous status-stream owners (0/NULL)
-- may inherit that device's unique AUTHN-backed owner; invalid owner strings do
-- not. All visible owners of target registrations, including outside the cohort
-- and selected baseline, are inspected. Vendor user 0/NULL is permitted through
-- this unambiguous registration map; a conflicting/invalid vendor owner is not.
-- Mapping observed later in the window can explain an earlier callback. This
-- reconstructs a cutoff snapshot, not historical warehouse availability.
--
-- Eligible baseline = unambiguous active Android devices with NO cohort owner.
-- HASH(device_id), then device_id, deterministically bounds the baseline sample.
-- All campaign-related devices, sampled eligible baseline devices, and up to 500
-- other ownership exclusions are emitted. Full exclusion and unsampled baseline
-- counts remain in coverage. Excluded diagnostics NEVER expand the PI scan.
--
-- A device's state comes from its latest valid HTTP-2xx, object-payload callback
-- in the window. A latest unevaluated app-access array stays unknown; older clean
-- verdicts are not substituted. Conflicting callback variants/ownership observed
-- at or after the selected callback block the state to unknown. HTTP/JSON errors
-- remain diagnostic and do not erase an otherwise valid selected callback.
-- Repeated callbacks never increase a device prevalence denominator.
--
-- Exact app-access enums only. Recognized positives remain positive alongside
-- an unknown enum. A negative requires a nonempty array containing only the eight
-- recognized evaluated app-access enums. Empty/missing/UNEVALUATED/new values
-- are unknown. known_only_controlling requires known present and unknown absent.
-- app_access_evaluated means the entire array is recognized and nonempty; use
-- each nullable signal's IS NOT NULL count as its own evaluated denominator.
-- first_positive_at/last_positive_at refer to UNKNOWN_CONTROLLING observations,
-- for context only; they never replace the latest selected state in live rates.
-- No app identity, installation path, malicious operator, or token binding is
-- inferred or independently verified by this query.
WITH
params AS (
  SELECT $chart_start::TIMESTAMP_TZ chart_start, $cutoff::TIMESTAMP_TZ cutoff,
    DATEADD('hour',-24,$chart_start::TIMESTAMP_TZ) pi_start,
    24::NUMBER pi_max_age_hours,{{BASELINE_LIMIT}}::NUMBER(38,0) baseline_limit
),
cohort_input AS (
  {{COHORT_USERS}}
),
cohort_users AS (
  SELECT DISTINCT TRY_TO_NUMBER(user_id::STRING) user_id
  FROM cohort_input WHERE TRY_TO_NUMBER(user_id::STRING)>0
),
authn_observation AS (
  SELECT DISTINCT a.original_timestamp observed_at,
    TRY_TO_NUMBER(a.user_id::STRING) user_id,
    NULLIF(TRIM(a.user_id::STRING),'') raw_user_id,
    NULLIF(TRIM(a.device_id::STRING),'') device_id,
    NULLIF(TRIM(a.registration_id::STRING),'') registration_id,
    LOWER(TRIM(a.platform::STRING)) platform,
    NULLIF(TRIM(a.account_access_attempt_id::STRING),'') attempt_id,
    NULLIF(TRIM(a.decision_id::STRING),'') decision_id,
    LOWER(TRIM(a.event_name::STRING)) event_name,
    LOWER(TRIM(a.sub_event_name::STRING)) sub_event_name,
    a.ml_inference_model::STRING ml_inference_model
  FROM chime.decision_platform.authn a CROSS JOIN params p
  WHERE a.original_timestamp>=p.pi_start AND a.original_timestamp<p.cutoff
    AND a.is_shadow_mode=FALSE
),
authn_window AS (
  SELECT DISTINCT observed_at,user_id,raw_user_id,device_id,registration_id,platform
  FROM authn_observation CROSS JOIN params p WHERE observed_at>=p.chart_start
),
active_android_devices AS (
  SELECT device_id,MIN(observed_at) first_active_at,MAX(observed_at) last_active_at,
    COUNT(*) active_authn_rows
  FROM authn_window WHERE platform='android' AND device_id IS NOT NULL
  GROUP BY 1
),
status_observation AS (
  SELECT DISTINCT s._creation_timestamp observed_at,
    TRY_TO_NUMBER(s._user_id::STRING) user_id,
    NULLIF(TRIM(s._user_id::STRING),'') raw_user_id,
    NULLIF(TRIM(s._device_id::STRING),'') device_id,
    NULLIF(TRIM(s.registration_id::STRING),'') registration_id,
    UPPER(TRIM(s.platform::STRING)) platform,
    UPPER(TRIM(s.journey::STRING)) journey
  FROM streaming_platform.segment_and_hawker_production.device_events_v1_registration_status_updated s
  CROSS JOIN params p
  WHERE s._creation_timestamp>=p.pi_start AND s._creation_timestamp<p.cutoff
),
status_window AS (
  SELECT s.* FROM status_observation s CROSS JOIN params p
  WHERE s.observed_at>=p.chart_start
),
device_owner_evidence AS (
  SELECT a.device_id,a.user_id,a.raw_user_id,'authn' source,
    IFF(a.raw_user_id IS NULL OR a.user_id=0,FALSE,
      COALESCE(a.user_id<0,TRUE)) invalid_owner
  FROM authn_window a JOIN active_android_devices d USING(device_id)
  UNION ALL
  SELECT s.device_id,s.user_id,s.raw_user_id,'registration_status' source,
    IFF(s.raw_user_id IS NULL OR s.user_id=0,FALSE,
      COALESCE(s.user_id<0,TRUE)) invalid_owner
  FROM status_window s JOIN active_android_devices d USING(device_id)
),
device_owner_stats AS (
  SELECT e.device_id,COUNT(DISTINCT IFF(e.user_id>0,e.user_id,NULL)) owner_count,
    COUNT(DISTINCT IFF(e.source='authn' AND e.user_id>0,e.user_id,NULL)) authn_positive_owner_count,
    COUNT(DISTINCT IFF(e.user_id>0 AND c.user_id IS NOT NULL,e.user_id,NULL)) cohort_owner_count,
    COUNT(DISTINCT IFF(e.user_id>0 AND c.user_id IS NULL,e.user_id,NULL)) other_owner_count,
    MIN(IFF(e.user_id>0,e.user_id,NULL)) sole_positive_owner,
    COALESCE(COUNT_IF(e.invalid_owner),0) invalid_owner_rows,
    COALESCE(COUNT_IF(e.source='authn' AND (e.raw_user_id IS NULL OR e.user_id=0)),0) anonymous_authn_rows,
    COALESCE(COUNT_IF(e.source='registration_status' AND (e.raw_user_id IS NULL OR e.user_id=0)),0) anonymous_status_rows
  FROM device_owner_evidence e LEFT JOIN cohort_users c ON c.user_id=e.user_id
  GROUP BY 1
),
device_state AS (
  SELECT d.*,o.owner_count,o.authn_positive_owner_count,o.cohort_owner_count,o.other_owner_count,
    o.invalid_owner_rows,o.anonymous_authn_rows,o.anonymous_status_rows,
    IFF(o.owner_count=1 AND o.authn_positive_owner_count=1 AND o.invalid_owner_rows=0,
      o.sole_positive_owner,NULL)::NUMBER user_id,
    CASE WHEN o.cohort_owner_count>0 AND o.other_owner_count>0 THEN 'ambiguous'
      WHEN o.cohort_owner_count>0 THEN 'campaign'
      WHEN o.other_owner_count>0 THEN 'baseline' ELSE 'ambiguous' END cohort,
    COALESCE(o.owner_count=1 AND o.authn_positive_owner_count=1 AND o.invalid_owner_rows=0,FALSE) ownership_eligible,
    CASE WHEN o.cohort_owner_count>0 AND o.other_owner_count>0 THEN 'shared_cohort_and_noncohort_owners'
      WHEN o.owner_count>1 THEN 'multiple_observed_member_owners'
      WHEN o.owner_count=0 THEN 'no_positive_member_owner'
      WHEN o.authn_positive_owner_count=0 THEN 'no_positive_authn_member_owner'
      WHEN o.invalid_owner_rows>0 THEN 'invalid_or_missing_observed_owner'
      ELSE NULL END exclusion_reason
  FROM active_android_devices d JOIN device_owner_stats o USING(device_id)
),
baseline_ranked AS (
  SELECT d.device_id,ROW_NUMBER() OVER (ORDER BY HASH(d.device_id),d.device_id) selection_rank
  FROM device_state d WHERE d.cohort='baseline' AND d.ownership_eligible
),
baseline_sample AS (
  SELECT b.* FROM baseline_ranked b CROSS JOIN params p
  WHERE b.selection_rank<=p.baseline_limit
),
excluded_diagnostic_ranked AS (
  SELECT device_id,ROW_NUMBER() OVER (ORDER BY HASH(device_id),device_id) diagnostic_rank
  FROM device_state WHERE NOT ownership_eligible AND cohort_owner_count=0
),
selected_devices AS (
  SELECT d.*,b.selection_rank baseline_selection_rank,
    e.diagnostic_rank exclusion_diagnostic_rank,
    COALESCE(d.ownership_eligible AND d.cohort IN ('campaign','baseline'),FALSE) eligible
  FROM device_state d LEFT JOIN baseline_sample b USING(device_id)
  LEFT JOIN excluded_diagnostic_ranked e USING(device_id)
  WHERE d.cohort_owner_count>0 OR b.device_id IS NOT NULL OR e.diagnostic_rank<=500
),
device_registration_candidates AS (
  SELECT DISTINCT a.device_id,a.registration_id
  FROM authn_observation a JOIN selected_devices d USING(device_id)
  WHERE d.eligible AND a.registration_id IS NOT NULL
  UNION
  SELECT DISTINCT s.device_id,s.registration_id
  FROM status_observation s JOIN selected_devices d USING(device_id)
  WHERE d.eligible AND s.registration_id IS NOT NULL AND s.platform='DEVICE_PLATFORM_ANDROID_APP'
),
target_registrations AS (
  SELECT DISTINCT registration_id FROM device_registration_candidates
),
registration_evidence AS (
  SELECT a.registration_id,a.device_id,a.user_id,a.raw_user_id,a.observed_at,
    'authn' source,TRUE source_can_map
  FROM authn_observation a JOIN target_registrations t USING(registration_id)
  UNION ALL
  SELECT s.registration_id,s.device_id,
    CASE WHEN s.raw_user_id IS NULL OR s.user_id=0 THEN d.user_id ELSE s.user_id END user_id,
    s.raw_user_id,s.observed_at,'registration_status' source,
    s.platform='DEVICE_PLATFORM_ANDROID_APP' source_can_map
  FROM status_observation s JOIN target_registrations t USING(registration_id)
  LEFT JOIN device_state d ON d.device_id=s.device_id AND d.ownership_eligible
),
registration_pairs AS (
  SELECT registration_id,user_id,device_id,MIN(observed_at) mapping_first_at,
    MAX(observed_at) mapping_last_at,
    MAX(IFF(source='authn' AND source_can_map,1,0)) has_authn,
    MAX(IFF(source='registration_status' AND source_can_map,1,0)) has_android_status,
    COALESCE(COUNT_IF(user_id IS NULL OR user_id<=0 OR device_id IS NULL),0) invalid_pair_rows
  FROM registration_evidence GROUP BY 1,2,3
),
registration_cardinality AS (
  SELECT registration_id,COUNT(*) member_device_pairs,
    SUM(invalid_pair_rows) invalid_pair_rows,
    MAX(mapping_last_at) ownership_last_observed_at,
    MAX(has_authn) has_authn,MAX(has_android_status) has_android_status
  FROM registration_pairs GROUP BY 1
),
unique_registration AS (
  SELECT r.*,d.cohort
  FROM registration_pairs r JOIN registration_cardinality k USING(registration_id)
  JOIN selected_devices d ON d.device_id=r.device_id AND d.user_id=r.user_id
  WHERE d.eligible AND k.member_device_pairs=1 AND k.invalid_pair_rows=0
    AND (r.has_authn=1 OR r.has_android_status=1)
),
registration_coverage AS (
  SELECT c.device_id,COUNT(DISTINCT c.registration_id) candidate_registrations,
    COUNT(DISTINCT IFF(u.registration_id IS NOT NULL,c.registration_id,NULL)) usable_registrations,
    COUNT(DISTINCT IFF(k.member_device_pairs>1 OR k.invalid_pair_rows>0,c.registration_id,NULL)) ambiguous_registrations,
    COUNT(DISTINCT IFF(u.has_authn=1,c.registration_id,NULL)) authn_mapped_registrations,
    COUNT(DISTINCT IFF(u.has_authn=0 AND u.has_android_status=1,c.registration_id,NULL)) bridge_only_registrations
  FROM device_registration_candidates c JOIN registration_cardinality k USING(registration_id)
  LEFT JOIN unique_registration u ON u.registration_id=c.registration_id AND u.device_id=c.device_id
  GROUP BY 1
),
vendor_target_stable_ids AS (
  -- Discover target stable IDs, then inspect every in-window PI variant of those
  -- IDs, including variants whose registration is outside the selected devices.
  SELECT DISTINCT NULLIF(TRIM(v._message_id::STRING),'') stable_event_id
  FROM streaming_platform.segment_and_hawker_production.device_events_v1_vendor_response v
  CROSS JOIN params p
  WHERE v.name='VENDOR_PLAY_INTEGRITY'
    AND v._creation_timestamp>=p.pi_start AND v._creation_timestamp<p.cutoff
    AND NULLIF(TRIM(v.registration_id::STRING),'') IN
      (SELECT registration_id FROM target_registrations)
    AND NULLIF(TRIM(v._message_id::STRING),'') IS NOT NULL
),
vendor_parsed AS (
  SELECT v._creation_timestamp observed_at,
    NULLIF(TRIM(v.registration_id::STRING),'') registration_id,
    NULLIF(TRIM(v._message_id::STRING),'') message_id,
    NULLIF(TRIM(v._user_id::STRING),'') raw_vendor_user_id,
    TRY_TO_NUMBER(v._user_id::STRING) vendor_user_id,
    NULLIF(TRIM(v._device_id::STRING),'') vendor_device_id,
    v.http_status::STRING http_status_raw,
    TRY_TO_NUMBER(v.http_status::STRING) http_status_number,
    TRY_PARSE_JSON(v.body) parsed_body,
    SHA2(CONCAT_WS('|',COALESCE(TRIM(v.registration_id::STRING),''),
      TO_VARCHAR(v._creation_timestamp),COALESCE(TRIM(v._user_id::STRING),''),
      COALESCE(TRIM(v._device_id::STRING),''),COALESCE(v.http_status::STRING,''),
      COALESCE(v.body,''))) callback_variant_hash
  FROM streaming_platform.segment_and_hawker_production.device_events_v1_vendor_response v
  CROSS JOIN params p
  WHERE v.name='VENDOR_PLAY_INTEGRITY'
    AND v._creation_timestamp>=p.pi_start AND v._creation_timestamp<p.cutoff
    AND (NULLIF(TRIM(v.registration_id::STRING),'') IN
      (SELECT registration_id FROM target_registrations)
      OR NULLIF(TRIM(v._message_id::STRING),'') IN
        (SELECT stable_event_id FROM vendor_target_stable_ids))
),
vendor_raw AS (
  SELECT *,COALESCE(message_id,callback_variant_hash) stable_event_id,
    CONCAT(COALESCE(message_id,callback_variant_hash),':',callback_variant_hash) callback_id,
    parsed_body:tokenPayloadExternal token_payload,
    COALESCE(http_status_number BETWEEN 200 AND 299,FALSE) http_success
  FROM vendor_parsed
  QUALIFY ROW_NUMBER() OVER (PARTITION BY COALESCE(message_id,callback_variant_hash),callback_variant_hash
    ORDER BY observed_at)=1
),
vendor_variants AS (
  SELECT stable_event_id,COUNT(*) variant_count,MAX(observed_at) last_variant_observed_at
  FROM vendor_raw GROUP BY 1
),
vendor_linked AS (
  SELECT u.user_id,u.device_id,u.mapping_first_at,u.mapping_last_at,
    u.has_authn,u.has_android_status,v.*,x.variant_count,
    CASE WHEN v.raw_vendor_user_id IS NULL OR v.vendor_user_id=0 THEN FALSE
      WHEN v.vendor_user_id=u.user_id THEN FALSE ELSE TRUE END vendor_user_conflict
  FROM vendor_raw v JOIN unique_registration u USING(registration_id)
  JOIN vendor_variants x USING(stable_event_id)
),
pi_valid AS (
  SELECT * FROM vendor_linked
  WHERE http_success AND TYPEOF(token_payload)='OBJECT'
    AND NOT vendor_user_conflict
),
app_array_stats AS (
  SELECT v.callback_id,COUNT(*) app_access_items,
    COALESCE(COUNT_IF(a.value::STRING IN ('KNOWN_INSTALLED','UNKNOWN_INSTALLED',
      'KNOWN_CONTROLLING','UNKNOWN_CONTROLLING','KNOWN_CAPTURING','UNKNOWN_CAPTURING',
      'KNOWN_OVERLAYS','UNKNOWN_OVERLAYS')),0) known_evaluated_items,
    COALESCE(COUNT_IF(a.value::STRING='UNKNOWN_CONTROLLING'),0) unknown_controlling_items,
    COALESCE(COUNT_IF(a.value::STRING='KNOWN_CONTROLLING'),0) known_controlling_items
  FROM pi_valid v,LATERAL FLATTEN(INPUT=>v.token_payload:environmentDetails:appAccessRiskVerdict:appsDetected) a
  WHERE TYPEOF(v.token_payload:environmentDetails:appAccessRiskVerdict:appsDetected)='ARRAY'
  GROUP BY 1
),
pi_app_evaluation AS (
  SELECT v.*,v.token_payload:environmentDetails:appAccessRiskVerdict:appsDetected apps_detected,
    TYPEOF(v.token_payload:environmentDetails:appAccessRiskVerdict:appsDetected)='ARRAY' has_app_access_array,
    COALESCE(a.app_access_items,0) app_access_items,
    COALESCE(a.known_evaluated_items,0) known_evaluated_items,
    COALESCE(a.unknown_controlling_items,0) unknown_controlling_items,
    COALESCE(a.known_controlling_items,0) known_controlling_items,
    COALESCE(TYPEOF(v.token_payload:environmentDetails:appAccessRiskVerdict:appsDetected)='ARRAY'
      AND a.app_access_items>0 AND a.known_evaluated_items=a.app_access_items,FALSE) app_access_evaluated
  FROM pi_valid v LEFT JOIN app_array_stats a USING(callback_id)
),
pi_signals_all AS (
  SELECT *,
    CASE WHEN unknown_controlling_items>0 THEN TRUE WHEN app_access_evaluated THEN FALSE
      ELSE NULL::BOOLEAN END unknown_controlling,
    CASE WHEN known_controlling_items>0 THEN TRUE WHEN app_access_evaluated THEN FALSE
      ELSE NULL::BOOLEAN END known_controlling,
    CASE WHEN unknown_controlling_items>0 THEN FALSE
      WHEN app_access_evaluated AND known_controlling_items>0 THEN TRUE
      WHEN app_access_evaluated THEN FALSE ELSE NULL::BOOLEAN END known_only_controlling,
    CASE WHEN unknown_controlling_items>0 OR known_controlling_items>0 THEN TRUE
      WHEN app_access_evaluated THEN FALSE ELSE NULL::BOOLEAN END any_controlling
  FROM pi_app_evaluation
),
pi_signals AS (
  SELECT s.* FROM pi_signals_all s CROSS JOIN params p
  WHERE s.variant_count=1 AND s.observed_at>=p.chart_start
),
latest_valid_candidates AS (
  SELECT * FROM pi_signals
  QUALIFY DENSE_RANK() OVER (PARTITION BY device_id ORDER BY observed_at DESC)=1
),
latest_valid_ties AS (
  SELECT device_id,MAX(observed_at) observed_at,COUNT(*) latest_callback_tie_count,
    COUNT(DISTINCT COALESCE(TO_JSON(apps_detected),'__MISSING_APP_ACCESS_ARRAY__')) latest_callback_tie_variants
  FROM latest_valid_candidates GROUP BY 1
),
latest_valid AS (
  SELECT * FROM latest_valid_candidates
  QUALIFY ROW_NUMBER() OVER (PARTITION BY device_id ORDER BY observed_at DESC,callback_id DESC)=1
),
positive_history AS (
  SELECT device_id,COUNT(*) valid_callbacks,
    COALESCE(COUNT_IF(app_access_evaluated),0) fully_evaluated_callbacks,
    COALESCE(COUNT_IF(unknown_controlling IS NOT NULL),0) unknown_controlling_evaluated_callbacks,
    COALESCE(COUNT_IF(known_controlling IS NOT NULL),0) known_controlling_evaluated_callbacks,
    MIN(IFF(unknown_controlling,observed_at,NULL)) first_positive_at,
    MAX(IFF(unknown_controlling,observed_at,NULL)) last_positive_at,
    MIN(IFF(known_controlling,observed_at,NULL)) first_known_positive_at,
    MAX(IFF(known_controlling,observed_at,NULL)) last_known_positive_at,
    MIN(IFF(any_controlling,observed_at,NULL)) first_any_positive_at,
    MAX(IFF(any_controlling,observed_at,NULL)) last_any_positive_at,
    COALESCE(COUNT_IF(has_authn=0 AND has_android_status=1),0) bridge_only_valid_callbacks
  FROM pi_signals GROUP BY 1
),
device_vendor_diagnostics AS (
  SELECT c.device_id,COUNT(DISTINCT v.callback_id) observed_callbacks,
    COUNT(DISTINCT IFF(v.http_success,v.callback_id,NULL)) http_success_callbacks,
    COUNT(DISTINCT IFF(NOT v.http_success,v.callback_id,NULL)) http_error_or_unknown_callbacks,
    COUNT(DISTINCT IFF(v.parsed_body IS NULL,v.callback_id,NULL)) invalid_json_callbacks,
    COUNT(DISTINCT IFF(TYPEOF(v.token_payload)<>'OBJECT' OR v.token_payload IS NULL,v.callback_id,NULL)) missing_token_payload_callbacks,
    COUNT(DISTINCT IFF(x.variant_count>1,v.callback_id,NULL)) conflicting_variant_callbacks,
    COUNT(DISTINCT IFF(k.member_device_pairs>1 OR k.invalid_pair_rows>0,v.callback_id,NULL)) ambiguous_mapping_callbacks,
    MIN(v.observed_at) first_callback_at,MAX(v.observed_at) last_callback_at,
    MAX(IFF(x.variant_count>1,GREATEST(v.observed_at,x.last_variant_observed_at),NULL)) latest_variant_conflict_at,
    MAX(IFF(k.member_device_pairs>1 OR k.invalid_pair_rows>0,
      GREATEST(v.observed_at,k.ownership_last_observed_at),NULL)) latest_mapping_conflict_at
  FROM device_registration_candidates c JOIN vendor_raw v USING(registration_id)
  JOIN vendor_variants x USING(stable_event_id)
  JOIN registration_cardinality k USING(registration_id)
  CROSS JOIN params p WHERE v.observed_at>=p.chart_start
  GROUP BY 1
),
linked_vendor_diagnostics AS (
  SELECT device_id,COALESCE(COUNT_IF(vendor_user_conflict),0) vendor_user_conflict_callbacks,
    COALESCE(COUNT_IF(raw_vendor_user_id IS NULL OR vendor_user_id=0),0) anonymous_vendor_callbacks,
    MAX(IFF(vendor_user_conflict,observed_at,NULL)) latest_vendor_user_conflict_at
  FROM vendor_linked CROSS JOIN params p WHERE observed_at>=p.chart_start
  GROUP BY 1
),
blocking_observations AS (
  SELECT device_id,latest_variant_conflict_at observed_at,'conflicting_callback_variants' reason
  FROM device_vendor_diagnostics WHERE latest_variant_conflict_at IS NOT NULL
  UNION ALL
  SELECT device_id,latest_mapping_conflict_at,'ambiguous_registration_ownership'
  FROM device_vendor_diagnostics WHERE latest_mapping_conflict_at IS NOT NULL
  UNION ALL
  SELECT device_id,latest_vendor_user_conflict_at,'conflicting_vendor_member'
  FROM linked_vendor_diagnostics WHERE latest_vendor_user_conflict_at IS NOT NULL
  UNION ALL
  SELECT device_id,observed_at,'same_time_conflicting_valid_callbacks'
  FROM latest_valid_ties WHERE latest_callback_tie_variants>1
),
latest_blocking AS (
  SELECT * FROM blocking_observations
  QUALIFY ROW_NUMBER() OVER (PARTITION BY device_id ORDER BY observed_at DESC,reason)=1
),
device_joined AS (
  SELECT d.*,p.chart_start,p.cutoff,
    COALESCE(r.candidate_registrations,0) candidate_registrations,
    COALESCE(r.usable_registrations,0) usable_registrations,
    COALESCE(r.ambiguous_registrations,0) ambiguous_registrations,
    COALESCE(r.authn_mapped_registrations,0) authn_mapped_registrations,
    COALESCE(r.bridge_only_registrations,0) bridge_only_registrations,
    COALESCE(h.valid_callbacks,0) valid_callbacks,
    COALESCE(h.fully_evaluated_callbacks,0) fully_evaluated_callbacks,
    COALESCE(h.unknown_controlling_evaluated_callbacks,0) unknown_controlling_evaluated_callbacks,
    COALESCE(h.known_controlling_evaluated_callbacks,0) known_controlling_evaluated_callbacks,
    COALESCE(h.bridge_only_valid_callbacks,0) bridge_only_valid_callbacks,
    h.first_positive_at,h.last_positive_at,h.first_known_positive_at,h.last_known_positive_at,
    h.first_any_positive_at,h.last_any_positive_at,
    COALESCE(v.observed_callbacks,0) observed_callbacks,
    COALESCE(v.http_success_callbacks,0) http_success_callbacks,
    COALESCE(v.http_error_or_unknown_callbacks,0) http_error_or_unknown_callbacks,
    COALESCE(v.invalid_json_callbacks,0) invalid_json_callbacks,
    COALESCE(v.missing_token_payload_callbacks,0) missing_token_payload_callbacks,
    COALESCE(v.conflicting_variant_callbacks,0) conflicting_variant_callbacks,
    COALESCE(v.ambiguous_mapping_callbacks,0) ambiguous_mapping_callbacks,
    COALESCE(w.vendor_user_conflict_callbacks,0) vendor_user_conflict_callbacks,
    COALESCE(w.anonymous_vendor_callbacks,0) anonymous_vendor_callbacks,
    v.first_callback_at,v.last_callback_at,
    l.observed_at latest_valid_callback_at,l.callback_id latest_valid_callback_id,
    l.registration_id latest_registration_id,l.vendor_device_id latest_vendor_device_id,
    l.mapping_first_at,l.mapping_last_at,l.has_authn,l.has_android_status,
    l.apps_detected,l.has_app_access_array,l.app_access_items,l.known_evaluated_items,
    l.app_access_evaluated latest_array_evaluated,
    l.unknown_controlling latest_unknown_controlling,l.known_controlling latest_known_controlling,
    l.known_only_controlling latest_known_only_controlling,l.any_controlling latest_any_controlling,
    COALESCE(t.latest_callback_tie_count,0) latest_callback_tie_count,
    COALESCE(t.latest_callback_tie_variants,0) latest_callback_tie_variants,
    b.observed_at latest_blocking_at,b.reason blocking_reason,
    COALESCE(b.observed_at>=l.observed_at OR (b.observed_at IS NOT NULL AND l.observed_at IS NULL),FALSE) state_blocked
  FROM selected_devices d CROSS JOIN params p
  LEFT JOIN registration_coverage r USING(device_id)
  LEFT JOIN positive_history h USING(device_id)
  LEFT JOIN device_vendor_diagnostics v USING(device_id)
  LEFT JOIN linked_vendor_diagnostics w USING(device_id)
  LEFT JOIN latest_valid l USING(device_id)
  LEFT JOIN latest_valid_ties t USING(device_id)
  LEFT JOIN latest_blocking b USING(device_id)
),
device_metrics AS (
  SELECT *,
    IFF(eligible AND NOT state_blocked,latest_unknown_controlling,NULL)::BOOLEAN unknown_controlling,
    IFF(eligible AND NOT state_blocked,latest_known_controlling,NULL)::BOOLEAN known_controlling,
    IFF(eligible AND NOT state_blocked,latest_known_only_controlling,NULL)::BOOLEAN known_only_controlling,
    IFF(eligible AND NOT state_blocked,latest_any_controlling,NULL)::BOOLEAN any_controlling,
    COALESCE(eligible AND NOT state_blocked AND latest_array_evaluated,FALSE) app_access_evaluated,
    CASE WHEN state_blocked THEN latest_blocking_at
      ELSE COALESCE(latest_valid_callback_at,last_callback_at) END latest_observed_at,
    CASE WHEN NOT eligible THEN exclusion_reason
      WHEN state_blocked THEN blocking_reason
      WHEN candidate_registrations=0 THEN 'no_registration_mapping_in_window'
      WHEN usable_registrations=0 THEN 'no_unambiguous_registration_in_window'
      WHEN observed_callbacks=0 THEN 'no_vendor_callbacks_in_window'
      WHEN valid_callbacks=0 AND http_success_callbacks=0 THEN 'no_http_success_callbacks'
      WHEN valid_callbacks=0 THEN 'no_valid_payload_callback_with_consistent_owner'
      WHEN NOT COALESCE(has_app_access_array,FALSE) THEN 'app_access_array_absent_or_not_array'
      WHEN app_access_items=0 THEN 'app_access_empty_array'
      WHEN NOT COALESCE(latest_array_evaluated,FALSE) THEN 'app_access_unknown_or_unevaluated_enum'
      ELSE NULL END missing_reason
  FROM device_joined
),
group_metrics AS (
  SELECT cohort,COUNT(*) emitted_device_rows,COALESCE(COUNT_IF(eligible),0) eligible_devices,
    COALESCE(COUNT_IF(NOT eligible),0) excluded_devices,
    COALESCE(COUNT_IF(eligible AND valid_callbacks>0),0) devices_with_valid_callbacks,
    COALESCE(COUNT_IF(eligible AND app_access_evaluated),0) app_access_fully_evaluated_devices,
    COALESCE(COUNT_IF(eligible AND unknown_controlling IS NOT NULL),0) unknown_controlling_evaluated_devices,
    COALESCE(COUNT_IF(eligible AND unknown_controlling),0) unknown_controlling_positive_devices,
    COALESCE(COUNT_IF(eligible AND known_controlling IS NOT NULL),0) known_controlling_evaluated_devices,
    COALESCE(COUNT_IF(eligible AND known_controlling),0) known_controlling_positive_devices,
    COALESCE(COUNT_IF(eligible AND known_only_controlling IS NOT NULL),0) known_only_controlling_evaluated_devices,
    COALESCE(COUNT_IF(eligible AND known_only_controlling),0) known_only_controlling_positive_devices,
    COALESCE(COUNT_IF(eligible AND any_controlling IS NOT NULL),0) any_controlling_evaluated_devices,
    COALESCE(COUNT_IF(eligible AND any_controlling),0) any_controlling_positive_devices
  FROM device_metrics GROUP BY 1
),
-- Login volume uses the earliest observed production Android atom/member_logins
-- row per real attempt, independent of success/allow. The 24h pre-window scan
-- prevents normal boundary-crossing stages from becoming fresh chart attempts.
login_source_rows AS (
  SELECT * FROM authn_observation
  WHERE platform='android' AND event_name='atom_event' AND sub_event_name='member_logins'
    AND COALESCE(ml_inference_model,'')<>'atom_model'
),
-- A qualified attempt necessarily touches a selected eligible SDK device.
-- Restrict expensive attempt/stage aggregation to those candidate IDs, then
-- RESTORE ALL login-source rows for each ID, including other devices and owners.
-- Filtering login rows directly by selected device would hide ambiguity.
login_candidate_attempt_ids AS (
  SELECT DISTINCT a.attempt_id
  FROM login_source_rows a JOIN selected_devices d
    ON d.device_id=a.device_id AND d.eligible
  WHERE a.attempt_id IS NOT NULL AND UPPER(a.attempt_id)<>'NOT FOUND'
),
login_rows AS (
  SELECT a.* FROM login_source_rows a
  JOIN login_candidate_attempt_ids c USING(attempt_id)
),
login_attempt_rollup AS (
  SELECT attempt_id,MIN(observed_at) attempt_at,
    COUNT(DISTINCT IFF(user_id>0,user_id,NULL)) positive_users,
    MIN(IFF(user_id>0,user_id,NULL)) user_id,
    COUNT(DISTINCT device_id) sdk_devices,MIN(device_id) device_id,
    COUNT(DISTINCT decision_id) live_decisions,MIN(decision_id) decision_id,
    COUNT(DISTINCT registration_id) registrations,MIN(registration_id) registration_id,
    COALESCE(COUNT_IF(raw_user_id IS NOT NULL AND COALESCE(user_id<>0,TRUE) AND
      COALESCE(user_id<0,TRUE)),0) invalid_owner_rows
  FROM login_rows WHERE attempt_id IS NOT NULL AND UPPER(attempt_id)<>'NOT FOUND'
  GROUP BY 1
),
login_attempt_anchor AS (
  SELECT r.attempt_id,COUNT(DISTINCT IFF(r.user_id>0,r.user_id,NULL)) anchor_users,
    MIN(IFF(r.user_id>0,r.user_id,NULL)) anchor_user_id,
    COUNT(DISTINCT r.device_id) anchor_devices,MIN(r.device_id) anchor_device_id,
    COUNT(DISTINCT r.registration_id) anchor_registrations,MIN(r.registration_id) anchor_registration_id
  FROM login_rows r JOIN login_attempt_rollup a ON a.attempt_id=r.attempt_id
    AND a.attempt_at=r.observed_at
  GROUP BY 1
),
qualified_login_attempts AS (
  SELECT a.attempt_id,a.attempt_at,a.user_id,a.device_id,a.decision_id,
    IFF(a.registrations=1 AND f.anchor_registrations=1
      AND UPPER(f.anchor_registration_id)<>'NOT FOUND',f.anchor_registration_id,NULL) registration_id,
    a.registrations,d.cohort
  FROM login_attempt_rollup a JOIN login_attempt_anchor f USING(attempt_id)
  JOIN selected_devices d
    ON d.device_id=a.device_id AND d.user_id=a.user_id AND d.eligible
  CROSS JOIN params p
  WHERE a.attempt_at>=p.chart_start AND a.attempt_at<p.cutoff
    AND a.positive_users=1 AND a.sdk_devices=1 AND a.live_decisions=1
    AND f.anchor_users=1 AND f.anchor_user_id=a.user_id
    AND f.anchor_devices=1 AND f.anchor_device_id=a.device_id
    AND a.invalid_owner_rows=0 AND UPPER(a.device_id)<>'NOT FOUND'
    AND UPPER(a.decision_id)<>'NOT FOUND'
),
-- Conflict time is the first time TWO variants of one stable callback ID are
-- visible. Later variants never rewrite the prior signal on an earlier attempt.
login_variant_conflict AS (
  SELECT a.stable_event_id,MIN(GREATEST(a.observed_at,b.observed_at)) conflict_at
  FROM vendor_raw a JOIN vendor_raw b ON a.stable_event_id=b.stable_event_id
    AND a.callback_variant_hash<>b.callback_variant_hash
  GROUP BY 1
),
login_prior_candidates AS (
  SELECT q.*,v.observed_at pi_observed_at,v.callback_id,v.apps_detected,
    v.unknown_controlling,v.known_controlling,v.known_only_controlling,v.any_controlling
  FROM qualified_login_attempts q JOIN pi_signals_all v
    ON v.device_id=q.device_id AND v.user_id=q.user_id
    AND v.registration_id=q.registration_id AND v.observed_at<=q.attempt_at
    AND v.mapping_first_at<=q.attempt_at
  CROSS JOIN params p
  WHERE v.observed_at>=DATEADD('hour',-p.pi_max_age_hours,q.attempt_at)
  QUALIFY DENSE_RANK() OVER (PARTITION BY q.attempt_id ORDER BY v.observed_at DESC)=1
),
login_prior_selected AS (
  SELECT *,COUNT(DISTINCT COALESCE(TO_JSON(apps_detected),'__MISSING_APP_ACCESS_ARRAY__'))
    OVER(PARTITION BY attempt_id) same_time_verdict_variants
  FROM login_prior_candidates
  QUALIFY ROW_NUMBER() OVER(PARTITION BY attempt_id ORDER BY callback_id DESC)=1
),
-- Invalid HTTP/payload callbacks remain diagnostics and do not erase a valid
-- prior observation. Owner/registration/variant conflict observations do.
login_conflict_observations AS (
  SELECT c.device_id,c.registration_id,GREATEST(v.observed_at,x.conflict_at) observed_at,
    'conflicting_callback_variants' reason
  FROM device_registration_candidates c JOIN vendor_raw v USING(registration_id)
  JOIN login_variant_conflict x USING(stable_event_id)
  UNION ALL
  SELECT c.device_id,c.registration_id,v.observed_at,'ambiguous_registration_ownership'
  FROM device_registration_candidates c JOIN vendor_raw v USING(registration_id)
  JOIN registration_cardinality k USING(registration_id)
  WHERE k.member_device_pairs>1 OR k.invalid_pair_rows>0
  UNION ALL
  SELECT device_id,registration_id,observed_at,'conflicting_vendor_member'
  FROM vendor_linked WHERE vendor_user_conflict
),
login_prior_blockers AS (
  SELECT q.attempt_id,MAX(b.observed_at) latest_blocking_at
  FROM qualified_login_attempts q JOIN login_conflict_observations b
    ON b.device_id=q.device_id AND b.registration_id=q.registration_id
    AND b.observed_at<=q.attempt_at
  GROUP BY 1
),
login_attempt_signals AS (
  SELECT q.*,l.pi_observed_at,l.callback_id,
    CASE WHEN q.registration_id IS NULL THEN 'missing_or_ambiguous_attempt_registration'
      WHEN l.pi_observed_at IS NULL THEN 'no_valid_prior_callback_within_24h'
      WHEN l.same_time_verdict_variants>1 THEN 'same_time_conflicting_valid_callbacks'
      WHEN b.latest_blocking_at>=l.pi_observed_at THEN 'prior_conflicting_callback_or_owner'
      ELSE 'prior_callback_selected' END lookup_status,
    IFF(l.same_time_verdict_variants=1 AND COALESCE(b.latest_blocking_at<l.pi_observed_at,TRUE),
      l.unknown_controlling,NULL)::BOOLEAN unknown_controlling,
    IFF(l.same_time_verdict_variants=1 AND COALESCE(b.latest_blocking_at<l.pi_observed_at,TRUE),
      l.known_controlling,NULL)::BOOLEAN known_controlling,
    IFF(l.same_time_verdict_variants=1 AND COALESCE(b.latest_blocking_at<l.pi_observed_at,TRUE),
      l.known_only_controlling,NULL)::BOOLEAN known_only_controlling,
    IFF(l.same_time_verdict_variants=1 AND COALESCE(b.latest_blocking_at<l.pi_observed_at,TRUE),
      l.any_controlling,NULL)::BOOLEAN any_controlling
  FROM qualified_login_attempts q LEFT JOIN login_prior_selected l USING(attempt_id)
  LEFT JOIN login_prior_blockers b USING(attempt_id)
),
login_signal_rows AS (
  SELECT a.cohort,a.attempt_id,a.attempt_at,a.lookup_status,s.signal,
    CASE s.signal WHEN 'unknown_controlling' THEN a.unknown_controlling
      WHEN 'known_controlling' THEN a.known_controlling
      WHEN 'known_only_controlling' THEN a.known_only_controlling
      WHEN 'any_controlling' THEN a.any_controlling END signal_value
  FROM login_attempt_signals a CROSS JOIN (
    SELECT column1::STRING signal FROM VALUES ('unknown_controlling'),('known_controlling'),
      ('known_only_controlling'),('any_controlling')) s
),
login_hour_actual AS (
  SELECT cohort,signal,FLOOR(DATEDIFF('second',p.chart_start,a.attempt_at)/3600) hour_index,
    COUNT(*) qualified_attempts,COUNT(signal_value) evaluated_attempts,
    COALESCE(COUNT_IF(signal_value),0) triggered_attempts,
    COALESCE(COUNT_IF(signal_value IS NULL),0) unknown_attempts
  FROM login_signal_rows a CROSS JOIN params p GROUP BY 1,2,3
),
login_hour_spine AS (
  SELECT ROW_NUMBER() OVER (ORDER BY SEQ4())-1 hour_index
  FROM TABLE(GENERATOR(ROWCOUNT=>168))
),
login_hourly AS (
  SELECT c.cohort,s.signal,h.hour_index,
    DATEADD('hour',h.hour_index,p.chart_start) hour_start,
    DATEADD('hour',h.hour_index+1,p.chart_start) hour_end,
    COALESCE(a.qualified_attempts,0) qualified_attempts,
    COALESCE(a.evaluated_attempts,0) evaluated_attempts,
    COALESCE(a.triggered_attempts,0) triggered_attempts,
    COALESCE(a.unknown_attempts,0) unknown_attempts
  FROM login_hour_spine h CROSS JOIN params p
  CROSS JOIN (SELECT column1::STRING cohort FROM VALUES ('campaign'),('baseline')) c
  CROSS JOIN (SELECT column1::STRING signal FROM VALUES ('unknown_controlling'),('known_controlling'),
    ('known_only_controlling'),('any_controlling')) s
  LEFT JOIN login_hour_actual a ON a.hour_index=h.hour_index AND a.cohort=c.cohort AND a.signal=s.signal
),
login_group_metrics AS (
  SELECT cohort,signal,SUM(qualified_attempts) qualified_attempts,
    SUM(evaluated_attempts) evaluated_attempts,SUM(triggered_attempts) triggered_attempts,
    SUM(unknown_attempts) unknown_attempts
  FROM login_hourly GROUP BY 1,2
),
records AS (
  SELECT 'COHORT_DEVICE' record_type,OBJECT_CONSTRUCT_KEEP_NULL(
    'metric','live_active_android_device_snapshot','device_id',device_id,'user_id',user_id,
    'cohort',cohort,'eligible',eligible,'exclusion_reason',exclusion_reason,
    'unknown_controlling',unknown_controlling,'known_controlling',known_controlling,
    'known_only_controlling',known_only_controlling,'any_controlling',any_controlling,
    'app_access_evaluated',app_access_evaluated,'app_access_fully_evaluated',app_access_evaluated,
    'latest_observed_at',latest_observed_at,'latest_valid_callback_at',latest_valid_callback_at,
    'latest_callback_at',last_callback_at,'latest_blocking_at',latest_blocking_at,
    'latest_callback_tie_count',latest_callback_tie_count,'latest_callback_tie_variants',latest_callback_tie_variants,
    'latest_age_seconds',DATEDIFF('second',latest_observed_at,cutoff),
    'latest_valid_callback_age_seconds',DATEDIFF('second',latest_valid_callback_at,cutoff),
    'first_positive_at',first_positive_at,'last_positive_at',last_positive_at,
    'first_known_positive_at',first_known_positive_at,'last_known_positive_at',last_known_positive_at,
    'first_any_positive_at',first_any_positive_at,'last_any_positive_at',last_any_positive_at,
    'valid_callbacks',valid_callbacks,'fully_evaluated_callbacks',fully_evaluated_callbacks,
    'unknown_controlling_evaluated_callbacks',unknown_controlling_evaluated_callbacks,
    'known_controlling_evaluated_callbacks',known_controlling_evaluated_callbacks,
    'observed_callbacks',observed_callbacks,'http_success_callbacks',http_success_callbacks,
    'http_error_or_unknown_callbacks',http_error_or_unknown_callbacks,
    'invalid_json_callbacks',invalid_json_callbacks,'missing_token_payload_callbacks',missing_token_payload_callbacks,
    'conflicting_variant_callbacks',conflicting_variant_callbacks,
    'ambiguous_mapping_callbacks',ambiguous_mapping_callbacks,
    'vendor_user_conflict_callbacks',vendor_user_conflict_callbacks,
    'anonymous_vendor_callbacks',anonymous_vendor_callbacks,
    'candidate_registrations',candidate_registrations,'usable_registrations',usable_registrations,
    'ambiguous_registrations',ambiguous_registrations,'authn_mapped_registrations',authn_mapped_registrations,
    'bridge_only_registrations',bridge_only_registrations,'bridge_only_valid_callbacks',bridge_only_valid_callbacks,
    'owner_count',owner_count,'authn_positive_owner_count',authn_positive_owner_count,
    'cohort_owner_count',cohort_owner_count,'other_owner_count',other_owner_count,
    'invalid_owner_rows',invalid_owner_rows,'anonymous_authn_rows',anonymous_authn_rows,
    'anonymous_status_rows',anonymous_status_rows,
    'first_active_at',first_active_at,'last_active_at',last_active_at,'active_authn_rows',active_authn_rows,
    'first_callback_at',first_callback_at,'baseline_selection_rank',baseline_selection_rank,
    'exclusion_diagnostic_rank',exclusion_diagnostic_rank,
    'latest_registration_id',latest_registration_id,'latest_vendor_device_id',latest_vendor_device_id,
    'mapping_first_at',mapping_first_at,'mapping_last_at',mapping_last_at,
    'latest_mapping_has_authn',has_authn,'latest_mapping_has_android_status',has_android_status,
    'apps_detected',apps_detected,'state_blocked',state_blocked,'missing_reason',missing_reason,
    'chart_start',chart_start,'cutoff',cutoff,'window_end_exclusive',TRUE,
    'sdk_device_namespace','AUTHN.device_id=REGISTRATION_STATUS_UPDATED._device_id',
    'registration_device_id_used_as_sdk',FALSE,'attestation_request_binding_checked',FALSE,
    'new_user_majority_eligible',FALSE) payload
  FROM device_metrics
  UNION ALL
  SELECT 'COHORT_COVERAGE',OBJECT_CONSTRUCT_KEEP_NULL(
    'metric','live_active_android_device_snapshot','scope','run',
    'chart_start',p.chart_start,'cutoff',p.cutoff,'window_end_exclusive',TRUE,
    'window_days',DATEDIFF('second',p.chart_start,p.cutoff)/86400.0,
    'seven_day_window_valid',DATEDIFF('second',p.chart_start,p.cutoff)=604800,
    'cohort_members',(SELECT COUNT(*) FROM cohort_users),
    'full_active_android_devices',(SELECT COUNT(*) FROM device_state),
    'full_campaign_devices',(SELECT COUNT(*) FROM device_state WHERE cohort='campaign'),
    'full_eligible_campaign_devices',(SELECT COUNT(*) FROM device_state WHERE cohort='campaign' AND ownership_eligible),
    'full_eligible_baseline_devices',(SELECT COUNT(*) FROM device_state WHERE cohort='baseline' AND ownership_eligible),
    'full_baseline_devices',(SELECT COUNT(*) FROM device_state WHERE cohort='baseline'),
    'full_ambiguous_devices',(SELECT COUNT(*) FROM device_state WHERE cohort='ambiguous'),
    'full_excluded_devices',(SELECT COUNT(*) FROM device_state WHERE NOT ownership_eligible),
    'shared_cohort_noncohort_devices',(SELECT COUNT(*) FROM device_state WHERE cohort_owner_count>0 AND other_owner_count>0),
    'baseline_sample_limit',p.baseline_limit,
    'sampled_baseline_devices',(SELECT COUNT(*) FROM baseline_sample),
    'emitted_device_rows',(SELECT COUNT(*) FROM selected_devices),
    'android_authn_rows_missing_device_id',(SELECT COUNT(*) FROM authn_window WHERE platform='android' AND device_id IS NULL),
    'selection','all campaign-related devices + HASH(device_id),device_id bounded eligible baseline + up to500 other ownership exclusions',
    'noncampaign_exclusion_diagnostic_limit',500,
    'emitted_excluded_devices',(SELECT COUNT(*) FROM selected_devices WHERE NOT eligible),
    'pi_scan_excludes_ownership_diagnostics',TRUE,
    'baseline_exclusion','any observed cohort owner in the common window',
    'ownership_window','common [chart_start,cutoff); earlier device owners are not established',
    'baseline_sample_is_deterministic',TRUE,
    'mapping','unique positive member / SDK device / registration across AUTHN and status stream; 24h pre-window evidence included',
    'app_open_bridge_enabled',TRUE,
    'app_open_bridge_source','DEVICE_EVENTS_V1_REGISTRATION_STATUS_UPDATED',
    'app_open_bridge_platform','DEVICE_PLATFORM_ANDROID_APP',
    'anonymous_status_owner_rule','0/NULL inherits only unique AUTHN-backed SDK device owner',
    'anonymous_vendor_owner_rule','0/NULL allowed only through unique registration mapping',
    'registration_device_id_used_as_sdk',FALSE,
    'id_normalization','TRIM; SDK device and registration case preserved; numeric positive owner',
    'callback_rule','latest valid HTTP2xx/object payload in common window; newer mapping/variant conflicts make state unknown',
    'state_rule','exact enum positives; negatives require nonempty fully recognized array',
    'first_last_positive_rule','UNKNOWN_CONTROLLING context; not used as latest state',
    'historical_benchmark_comparable',FALSE,
    'historical_benchmark_difference','active Android SDK devices in common 7d window; historical metric was selected member phone change with latest prior AUTHN-only verdict',
    'new_user_majority_eligible',FALSE,'historical_warehouse_availability_verified',FALSE,
    'attestation_request_binding_checked',FALSE,
    'group_metrics',(SELECT ARRAY_AGG(OBJECT_CONSTRUCT_KEEP_NULL(
      'cohort',cohort,'emitted_device_rows',emitted_device_rows,'eligible_devices',eligible_devices,
      'excluded_devices',excluded_devices,'devices_with_valid_callbacks',devices_with_valid_callbacks,
      'app_access_fully_evaluated_devices',app_access_fully_evaluated_devices,
      'unknown_controlling_evaluated_devices',unknown_controlling_evaluated_devices,
      'unknown_controlling_positive_devices',unknown_controlling_positive_devices,
      'known_controlling_evaluated_devices',known_controlling_evaluated_devices,
      'known_controlling_positive_devices',known_controlling_positive_devices,
      'known_only_controlling_evaluated_devices',known_only_controlling_evaluated_devices,
      'known_only_controlling_positive_devices',known_only_controlling_positive_devices,
      'any_controlling_evaluated_devices',any_controlling_evaluated_devices,
      'any_controlling_positive_devices',any_controlling_positive_devices)) FROM group_metrics))
  FROM params p
  UNION ALL
  SELECT 'COHORT_LOGIN_HOURLY',OBJECT_CONSTRUCT_KEEP_NULL(
    'metric','qualified_android_login_signal_hourly','cohort',cohort,'signal',signal,
    'hour_index',hour_index,'hour_start',hour_start,'hour_end',hour_end,
    'qualified_attempts',qualified_attempts,'evaluated_attempts',evaluated_attempts,
    'triggered_attempts',triggered_attempts,'unknown_attempts',unknown_attempts)
  FROM login_hourly
  UNION ALL
  SELECT 'COHORT_LOGIN_COVERAGE',OBJECT_CONSTRUCT_KEEP_NULL(
    'metric','qualified_android_login_signal_hourly','scope','run','status','available',
    'extraction_complete',TRUE,'chart_start',p.chart_start,'window_start',p.chart_start,
    'cutoff',p.cutoff,'window_end_exclusive',TRUE,
    'expected_hourly_rows',1344,'emitted_hourly_rows',(SELECT COUNT(*) FROM login_hourly),
    'pi_lookup_start',p.pi_start,'pi_max_age_hours',p.pi_max_age_hours,
    'qualified_attempts',(SELECT COUNT(*) FROM qualified_login_attempts),
    'cohort_members',(SELECT COUNT(*) FROM cohort_users),
    'baseline_sample_limit',p.baseline_limit,'baseline_sampled_devices',(SELECT COUNT(*) FROM baseline_sample),
    'full_eligible_baseline_devices',(SELECT COUNT(*) FROM device_state WHERE cohort='baseline' AND ownership_eligible),
    'attempt_key','ACCOUNT_ACCESS_ATTEMPT_ID; exactly one distinct live DECISION_ID',
    'attempt_filter','production AUTHN atom_event/member_logins Android; duplicate atom_model copy excluded; positive unique member and SDK device; outcome unrestricted',
    'attempt_time','MIN(original_timestamp) across bounded eight-day production Android login observations; chart counts first observations in seven-day interval',
    'registration_rule','one exact registration_id present at first login observation and consistent through observed stages; missing/multiple registration IDs remain qualified but signal unknown',
    'pi_lookup','latest valid HTTP2xx/object callback observed at or before attempt on exact owner/SDKdevice/registration, no older than 24 hours; latest unevaluated remains unknown',
    'pi_future_callbacks_used',FALSE,'attestation_request_binding_checked',FALSE,
    'volume_label','login attempts with signal, latest prior PI within 24h',
    'ownership_caveat','whole-window device and registration ambiguity exclusions may use ownership learned after an attempt; mapping_first_at must be <= attempt; these are reconstructed event-time signals, not point-in-time warehouse availability',
    'baseline_rule','all qualified attempts on deterministic bounded other-active-Android device sample; compare signal/evaluated-attempt rates, never raw baseline sample volume as population',
    'missing_attempt_id_login_rows',(SELECT COUNT(*) FROM login_source_rows CROSS JOIN params z WHERE observed_at>=z.chart_start AND (attempt_id IS NULL OR UPPER(attempt_id)='NOT FOUND')),
    'attempt_rollup_scope','candidate IDs touching selected eligible SDK devices; every source login row for each ID retained for ambiguity and first-observed checks',
    'excluded_ambiguous_identity_or_decision_attempts_scope','candidate attempt IDs only; not a global population diagnostic',
    'excluded_ambiguous_identity_or_decision_attempts',(SELECT COUNT(*) FROM login_attempt_rollup CROSS JOIN params z WHERE attempt_at>=z.chart_start AND (positive_users<>1 OR sdk_devices<>1 OR live_decisions<>1 OR invalid_owner_rows>0)),
    'lookup_status_counts',(SELECT ARRAY_AGG(OBJECT_CONSTRUCT_KEEP_NULL('cohort',cohort,'status',lookup_status,'attempts',n)) FROM (SELECT cohort,lookup_status,COUNT(*) n FROM login_attempt_signals GROUP BY 1,2)),
    'group_metrics',(SELECT ARRAY_AGG(OBJECT_CONSTRUCT_KEEP_NULL(
      'cohort',cohort,'signal',signal,'qualified_attempts',qualified_attempts,
      'evaluated_attempts',evaluated_attempts,'triggered_attempts',triggered_attempts,
      'unknown_attempts',unknown_attempts)) FROM login_group_metrics))
  FROM params p
)
SELECT record_type,payload FROM records
ORDER BY record_type,payload:cohort::STRING,payload:signal::STRING,payload:hour_index::NUMBER,payload:device_id::STRING;

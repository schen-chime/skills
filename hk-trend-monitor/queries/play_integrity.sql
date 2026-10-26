-- HK trend monitor: included, lower-priority Play Integrity and unlock tracker.
-- READ ONLY. External session variables: $cutoff and $chart_start (TIMESTAMP_TZ).
-- Replace {{NEW_USERS}} with a typed SELECT returning user_id NUMBER,
-- first_qualified_at TIMESTAMP_TZ. Safe empty replacement:
-- SELECT NULL::NUMBER user_id, NULL::TIMESTAMP_TZ first_qualified_at WHERE FALSE
-- Do not put member/device/IP result data in the public skill repository.
--
-- Window: each new member's first same-day evidence minus 7 days through cutoff,
-- always excluding cutoff itself. AUTHN mapping has a bounded 45-day baseline.
-- A later registration event before cutoff can map an earlier vendor callback;
-- this reconstructs telemetry available by cutoff, not historical warehouse availability.
-- Vendor _USER_ID=0/NULL is retained through an exact, uniquely mapped registration.
-- Unambiguous AUTHN (member, SDK device, registration) is required for PI risk rows.
-- Vendor _DEVICE_ID is preserved as provenance and is not silently equated to SDK IDs.
--
-- App risk mapping: only KNOWN/UNKNOWN CONTROLLING, CAPTURING, OVERLAYS are risky.
-- INSTALLED alone is not risky. Play Protect HIGH_RISK/MEDIUM_RISK and app
-- UNRECOGNIZED_VERSION are risky indicators. A present array lacking
-- MEETS_DEVICE_INTEGRITY is clean against this monitor's explicit device threshold.
-- A known weaker BASIC/VIRTUAL-only verdict is below the threshold; missing/empty,
-- unrecognized and inconsistent STRONG-without-DEVICE arrays remain unknown.
-- Lack of optional MEETS_STRONG_INTEGRITY is not risky.
-- Licensing, raw labels and unknown/new enum values are reported without assuming risk.
-- Source semantics: https://developer.android.com/google/play/integrity/verdicts
-- These are risk indicators; none establishes ATO or identifies a particular app.
-- This query does not independently verify token nonce/request-hash/package binding.
--
-- Unlock namespace has not been validated live. Exact same-member/device-string
-- associations are therefore provisional, never confirmed unlock-linked risk and
-- never included in majority-signal calculations. Capability fields do not identify
-- the method used to unlock. Independent PI risks remain majority-eligible.
WITH
params AS (
  SELECT $cutoff::TIMESTAMP_TZ cutoff, $chart_start::TIMESTAMP_TZ chart_start,
    FALSE unlock_device_namespace_validated
),
new_users_input AS (
  {{NEW_USERS}}
),
new_users AS (
  SELECT user_id::NUMBER user_id, MIN(first_qualified_at)::TIMESTAMP_TZ first_qualified_at
  FROM new_users_input
  WHERE user_id IS NOT NULL AND first_qualified_at IS NOT NULL
    AND first_qualified_at < (SELECT cutoff FROM params)
  GROUP BY 1
),
bounds AS (
  SELECT p.cutoff, p.chart_start, p.unlock_device_namespace_validated,
    COALESCE(DATEADD('day',-7,MIN(n.first_qualified_at)),p.chart_start) telemetry_start,
    DATEADD('day',-45,COALESCE(DATEADD('day',-7,MIN(n.first_qualified_at)),p.chart_start)) mapping_start
  FROM params p LEFT JOIN new_users n ON TRUE
  GROUP BY 1,2,3
),
-- First identify registrations genuinely observed for a selected new member.
target_authn AS (
  SELECT TRY_TO_NUMBER(a.user_id) user_id, NULLIF(TRIM(a.device_id),'') device_id,
    NULLIF(TRIM(a.registration_id),'') registration_id, a.original_timestamp map_observed_at,
    COALESCE(NULLIF(a.decision_id,''),NULLIF(a.event_id,''),
      SHA2(CONCAT_WS('|',COALESCE(a.user_id,''),COALESCE(a.device_id,''),
        COALESCE(a.registration_id,''),TO_VARCHAR(a.original_timestamp)))) map_event_id
  FROM chime.decision_platform.authn a
  JOIN new_users n ON n.user_id=TRY_TO_NUMBER(a.user_id)
  CROSS JOIN bounds b
  WHERE a.original_timestamp>=b.mapping_start AND a.original_timestamp<b.cutoff
    AND a.is_shadow_mode=FALSE AND NULLIF(TRIM(a.registration_id),'') IS NOT NULL
  QUALIFY ROW_NUMBER() OVER (PARTITION BY map_event_id ORDER BY a.original_timestamp)=1
),
-- Inspect all visible owners of those registrations, including users outside additions.
-- A registration shared by multiple member/device pairs is quarantined.
registration_pairs AS (
  SELECT a.registration_id, TRY_TO_NUMBER(a.user_id) user_id,
    NULLIF(TRIM(a.device_id),'') device_id, MIN(a.original_timestamp) mapping_first_at,
    MAX(a.original_timestamp) mapping_last_at
  FROM chime.decision_platform.authn a CROSS JOIN bounds b
  WHERE a.original_timestamp>=b.mapping_start AND a.original_timestamp<b.cutoff
    AND a.is_shadow_mode=FALSE
    AND a.registration_id IN (SELECT registration_id FROM target_authn)
  GROUP BY 1,2,3
),
registration_cardinality AS (
  SELECT registration_id, COUNT(*) member_device_pairs,
    COUNT_IF(user_id IS NULL OR user_id<=0 OR device_id IS NULL) invalid_pairs
  FROM registration_pairs GROUP BY 1
),
unique_registration AS (
  SELECT r.*
  FROM registration_pairs r JOIN registration_cardinality k USING(registration_id)
  JOIN new_users n ON n.user_id=r.user_id
  WHERE k.member_device_pairs=1 AND k.invalid_pairs=0
),
vendor_raw AS (
  SELECT v._message_id message_id, v._creation_timestamp observed_at,
    v.registration_id, v._user_id vendor_user_id, v._device_id vendor_device_id,
    v.http_status::STRING http_status_raw,
    TRY_TO_NUMBER(v.http_status::STRING) http_status_number,
    TRY_PARSE_JSON(v.body) parsed_body,
    SHA2(CONCAT_WS('|',COALESCE(v.registration_id,''),
      TO_VARCHAR(v._creation_timestamp),COALESCE(v._user_id::STRING,''),
      COALESCE(v._device_id,''),COALESCE(v.http_status::STRING,''),
      COALESCE(v.body,''))) callback_variant_hash,
    COALESCE(NULLIF(v._message_id,''),callback_variant_hash) stable_event_id
  FROM streaming_platform.segment_and_hawker_production.device_events_v1_vendor_response v
  CROSS JOIN bounds b
  WHERE v.name='VENDOR_PLAY_INTEGRITY'
    AND v._creation_timestamp>=b.telemetry_start AND v._creation_timestamp<b.cutoff
    AND v.registration_id IN (SELECT registration_id FROM target_authn)
  -- Preserve conflicting variants of a stable ID; discard only exact repeats.
  QUALIFY ROW_NUMBER() OVER (PARTITION BY stable_event_id,callback_variant_hash
    ORDER BY v._creation_timestamp)=1
),
vendor_id_variants AS (
  SELECT stable_event_id, COUNT(*) variant_count FROM vendor_raw GROUP BY 1
),
vendor_linked AS (
  SELECT r.user_id,r.device_id,r.mapping_first_at,r.mapping_last_at,
    n.first_qualified_at,v.*,x.variant_count,
    CONCAT(v.stable_event_id,':',v.callback_variant_hash) callback_id,
    v.parsed_body:tokenPayloadExternal token_payload,
    COALESCE(v.http_status_number BETWEEN 200 AND 299,FALSE) http_success,
    COALESCE(v.vendor_user_id NOT IN (0,r.user_id),FALSE) vendor_user_conflict
  FROM vendor_raw v JOIN unique_registration r USING(registration_id)
  JOIN new_users n ON n.user_id=r.user_id
  JOIN vendor_id_variants x USING(stable_event_id)
  WHERE v.observed_at>=DATEADD('day',-7,n.first_qualified_at)
),
pi_valid AS (
  SELECT * FROM vendor_linked
  WHERE http_success AND NOT vendor_user_conflict
    AND TYPEOF(token_payload)='OBJECT' AND variant_count=1
),
-- Six standardized nullable booleans per valid callback give each signal its own
-- evaluated denominator. A raw enum's absence is not itself an evaluated negative.
-- An explicit recognized positive remains true even alongside an unknown value.
-- A negative requires a nonempty array made entirely of the known evaluated enums;
-- empty, null, unknown-only, UNEVALUATED and mixed unknown arrays are not clean.
pi_app_array_stats AS (
  SELECT v.callback_id,COUNT(*) app_access_items,
    COUNT_IF(a.value::STRING IN ('KNOWN_INSTALLED','UNKNOWN_INSTALLED',
      'KNOWN_CONTROLLING','UNKNOWN_CONTROLLING','KNOWN_CAPTURING','UNKNOWN_CAPTURING',
      'KNOWN_OVERLAYS','UNKNOWN_OVERLAYS')) known_evaluated_items,
    COUNT_IF(a.value::STRING IN ('KNOWN_CONTROLLING','UNKNOWN_CONTROLLING')) controlling_items,
    COUNT_IF(a.value::STRING IN ('KNOWN_CAPTURING','UNKNOWN_CAPTURING')) capturing_items,
    COUNT_IF(a.value::STRING IN ('KNOWN_OVERLAYS','UNKNOWN_OVERLAYS')) overlay_items
  FROM pi_valid v,
    LATERAL FLATTEN(INPUT=>v.token_payload:environmentDetails:appAccessRiskVerdict:appsDetected) a
  WHERE TYPEOF(v.token_payload:environmentDetails:appAccessRiskVerdict:appsDetected)='ARRAY'
  GROUP BY 1
),
pi_app_evaluation AS (
  SELECT v.*,COALESCE(a.app_access_items,0) app_access_items,
    COALESCE(a.known_evaluated_items,0) known_evaluated_items,
    COALESCE(a.controlling_items,0) controlling_items,
    COALESCE(a.capturing_items,0) capturing_items,
    COALESCE(a.overlay_items,0) overlay_items,
    COALESCE(TYPEOF(v.token_payload:environmentDetails:appAccessRiskVerdict:appsDetected)='ARRAY'
      AND a.app_access_items>0 AND a.known_evaluated_items=a.app_access_items,FALSE) app_access_negative_evaluable
  FROM pi_valid v LEFT JOIN pi_app_array_stats a ON a.callback_id=v.callback_id
),
pi_device_array_stats AS (
  SELECT v.callback_id,COUNT(*) device_verdict_items,
    COUNT_IF(a.value::STRING IN ('MEETS_BASIC_INTEGRITY','MEETS_DEVICE_INTEGRITY',
      'MEETS_STRONG_INTEGRITY','MEETS_VIRTUAL_INTEGRITY')) known_device_verdict_items,
    COUNT_IF(a.value::STRING='MEETS_DEVICE_INTEGRITY') device_integrity_items,
    COUNT_IF(a.value::STRING IN ('MEETS_BASIC_INTEGRITY','MEETS_VIRTUAL_INTEGRITY')) weaker_integrity_items,
    COUNT_IF(a.value::STRING='MEETS_STRONG_INTEGRITY') strong_integrity_items
  FROM pi_valid v,
    LATERAL FLATTEN(INPUT=>v.token_payload:deviceIntegrity:deviceRecognitionVerdict) a
  WHERE TYPEOF(v.token_payload:deviceIntegrity:deviceRecognitionVerdict)='ARRAY'
  GROUP BY 1
),
pi_device_evaluation AS (
  SELECT v.callback_id,
    CASE WHEN TYPEOF(v.token_payload:deviceIntegrity:deviceRecognitionVerdict)='ARRAY'
        AND COALESCE(d.device_integrity_items,0)>0 THEN FALSE
      WHEN TYPEOF(v.token_payload:deviceIntegrity:deviceRecognitionVerdict)='ARRAY'
        AND d.device_verdict_items>0 AND d.known_device_verdict_items=d.device_verdict_items
        AND d.weaker_integrity_items>0 AND COALESCE(d.strong_integrity_items,0)=0 THEN TRUE
      ELSE NULL::BOOLEAN END device_below_device_integrity
  FROM pi_valid v LEFT JOIN pi_device_array_stats d ON d.callback_id=v.callback_id
),
pi_evaluation AS (
  SELECT a.*,d.device_below_device_integrity
  FROM pi_app_evaluation a JOIN pi_device_evaluation d ON d.callback_id=a.callback_id
),
pi_standardized AS (
  SELECT v.*, f.key::STRING signal_name,
    IFF(IS_NULL_VALUE(f.value),NULL::BOOLEAN,f.value::BOOLEAN) risky
  FROM pi_evaluation v,LATERAL FLATTEN(INPUT=>OBJECT_CONSTRUCT_KEEP_NULL(
    'play_integrity:app_access_controlling',
      CASE WHEN TYPEOF(v.token_payload:environmentDetails:appAccessRiskVerdict:appsDetected)='ARRAY' AND v.controlling_items>0 THEN TRUE
        WHEN v.app_access_negative_evaluable THEN FALSE
        ELSE NULL::BOOLEAN END,
    'play_integrity:app_access_capturing',
      CASE WHEN TYPEOF(v.token_payload:environmentDetails:appAccessRiskVerdict:appsDetected)='ARRAY' AND v.capturing_items>0 THEN TRUE
        WHEN v.app_access_negative_evaluable THEN FALSE
        ELSE NULL::BOOLEAN END,
    'play_integrity:app_access_overlays',
      CASE WHEN TYPEOF(v.token_payload:environmentDetails:appAccessRiskVerdict:appsDetected)='ARRAY' AND v.overlay_items>0 THEN TRUE
        WHEN v.app_access_negative_evaluable THEN FALSE
        ELSE NULL::BOOLEAN END,
    'play_integrity:protect_harmful',
      CASE v.token_payload:environmentDetails:playProtectVerdict::STRING
        WHEN 'HIGH_RISK' THEN TRUE WHEN 'MEDIUM_RISK' THEN TRUE
        WHEN 'NO_ISSUES' THEN FALSE ELSE NULL::BOOLEAN END,
    'play_integrity:unrecognized_app',
      CASE v.token_payload:appIntegrity:appRecognitionVerdict::STRING
        WHEN 'UNRECOGNIZED_VERSION' THEN TRUE WHEN 'PLAY_RECOGNIZED' THEN FALSE
        ELSE NULL::BOOLEAN END,
    'play_integrity:device_below_device_integrity',
      v.device_below_device_integrity
  )) f
),
-- All raw signal values are retained; mapping to risky is explicit below.
pi_signal_values AS (
  SELECT v.*, 'apps_detected' signal_family, a.value::STRING raw_value,
    CASE
      WHEN a.value::STRING IN ('KNOWN_CONTROLLING','UNKNOWN_CONTROLLING',
        'KNOWN_CAPTURING','UNKNOWN_CAPTURING','KNOWN_OVERLAYS','UNKNOWN_OVERLAYS') THEN TRUE
      WHEN a.value::STRING IN ('KNOWN_INSTALLED','UNKNOWN_INSTALLED') THEN FALSE
      ELSE NULL::BOOLEAN
    END risky,
    'explicit_app_access_risk_enum' risk_mapping
  FROM pi_valid v,
    LATERAL FLATTEN(INPUT=>v.token_payload:environmentDetails:appAccessRiskVerdict:appsDetected) a
  UNION ALL
  SELECT v.*, 'play_protect',v.token_payload:environmentDetails:playProtectVerdict::STRING,
    CASE v.token_payload:environmentDetails:playProtectVerdict::STRING
      WHEN 'HIGH_RISK' THEN TRUE WHEN 'MEDIUM_RISK' THEN TRUE
      WHEN 'NO_ISSUES' THEN FALSE ELSE NULL::BOOLEAN END,
    'high_or_medium_only_other_values_unknown'
  FROM pi_valid v WHERE v.token_payload:environmentDetails:playProtectVerdict IS NOT NULL
  UNION ALL
  SELECT v.*, 'app_recognition',v.token_payload:appIntegrity:appRecognitionVerdict::STRING,
    CASE v.token_payload:appIntegrity:appRecognitionVerdict::STRING
      WHEN 'UNRECOGNIZED_VERSION' THEN TRUE WHEN 'PLAY_RECOGNIZED' THEN FALSE
      ELSE NULL::BOOLEAN END,
    'unrecognized_version_only'
  FROM pi_valid v WHERE v.token_payload:appIntegrity:appRecognitionVerdict IS NOT NULL
  UNION ALL
  SELECT v.*, 'app_licensing',v.token_payload:accountDetails:appLicensingVerdict::STRING,
    NULL::BOOLEAN,'metadata_only_no_risk_inference'
  FROM pi_valid v WHERE v.token_payload:accountDetails:appLicensingVerdict IS NOT NULL
  UNION ALL
  SELECT v.*, 'device_recognition',a.value::STRING,NULL::BOOLEAN,
    'raw_label_only_optional_labels_not_required'
  FROM pi_valid v,
    LATERAL FLATTEN(INPUT=>v.token_payload:deviceIntegrity:deviceRecognitionVerdict) a
  UNION ALL
  SELECT v.*, 'device_threshold',
    CASE WHEN d.device_below_device_integrity THEN 'BELOW_MEETS_DEVICE_INTEGRITY'
      WHEN NOT d.device_below_device_integrity THEN 'MEETS_DEVICE_INTEGRITY'
      ELSE 'UNKNOWN_EMPTY_UNRECOGNIZED_OR_INCONSISTENT_DEVICE_ARRAY' END,
    d.device_below_device_integrity,
    'explicit_device_or_known_weaker_verdicts_only_optional_strong_not_required'
  FROM pi_valid v JOIN pi_device_evaluation d ON d.callback_id=v.callback_id
  WHERE TYPEOF(v.token_payload:deviceIntegrity:deviceRecognitionVerdict)='ARRAY'
),
pi_signals AS (
  SELECT user_id,device_id,signal_family,raw_value,risky,risk_mapping,
    MIN(observed_at) first_observed_at,MAX(observed_at) observed_at,
    COUNT(DISTINCT callback_id) callbacks,COUNT(DISTINCT registration_id) registrations,
    COUNT(DISTINCT IFF(observed_at<=first_qualified_at,callback_id,NULL)) callbacks_before_qualification,
    COUNT(DISTINCT IFF(observed_at>first_qualified_at,callback_id,NULL)) callbacks_after_qualification,
    COUNT(DISTINCT IFF(variant_count>1,stable_event_id,NULL)) conflicting_stable_ids,
    ARRAY_AGG(DISTINCT registration_id) registration_ids,
    ARRAY_AGG(DISTINCT vendor_device_id) vendor_device_ids
  FROM pi_signal_values GROUP BY 1,2,3,4,5,6
),
unlock_raw AS (
  SELECT u._message_id message_id,u._user_id user_id,u._device_id event_device_id,
    u._creation_timestamp observed_at,u.session_id,
    u.biometry_type,u.device_security_level,u.os:name::STRING os_name,
    SHA2(CONCAT_WS('|',COALESCE(u._user_id::STRING,''),COALESCE(u._device_id,''),
      TO_VARCHAR(u._creation_timestamp),COALESCE(u.session_id,''),
      COALESCE(u.biometry_type,''),COALESCE(u.device_security_level,''))) unlock_variant_hash,
    COALESCE(NULLIF(u._message_id,''),unlock_variant_hash) stable_event_id
  FROM streaming_platform.segment_and_hawker_production.mobile_event_router_v1_mobile_app_access_changed u
  JOIN new_users n ON n.user_id=u._user_id CROSS JOIN bounds b
  WHERE u._creation_timestamp>=b.telemetry_start AND u._creation_timestamp<b.cutoff
    AND u._creation_timestamp>=DATEADD('day',-7,n.first_qualified_at)
    AND u.type='ACCESS_TYPE_UNLOCKED'
  QUALIFY ROW_NUMBER() OVER (PARTITION BY stable_event_id,unlock_variant_hash
    ORDER BY u._creation_timestamp)=1
),
unlock_prior_pi AS (
  SELECT u.*,CONCAT(u.stable_event_id,':',u.unlock_variant_hash) unlock_event_id,
    p.callback_id,p.registration_id,p.device_id,p.observed_at pi_observed_at,p.token_payload,
    b.unlock_device_namespace_validated,
    DATEDIFF('second',p.observed_at,u.observed_at) prior_pi_age_seconds
  FROM unlock_raw u CROSS JOIN bounds b
  LEFT JOIN pi_valid p ON p.user_id=u.user_id AND p.device_id=u.event_device_id
    AND p.observed_at<=u.observed_at AND p.observed_at>=DATEADD('day',-7,u.observed_at)
    AND p.mapping_first_at<=u.observed_at
  QUALIFY ROW_NUMBER() OVER (PARTITION BY u.stable_event_id,u.unlock_variant_hash
    ORDER BY p.observed_at DESC,p.callback_id DESC)=1
),
unlock_signal_values AS (
  SELECT u.user_id,u.event_device_id device_id,u.unlock_event_id,u.observed_at,
    u.pi_observed_at,u.prior_pi_age_seconds,u.unlock_device_namespace_validated,
    s.signal_name signal_family,s.risky::STRING raw_value,s.risky,
    'standardized_nullable_boolean_per_prior_callback' risk_mapping
  FROM unlock_prior_pi u JOIN pi_standardized s ON s.callback_id=u.callback_id
),
unlock_signals AS (
  SELECT user_id,device_id,signal_family,raw_value,risky,risk_mapping,
    MIN(observed_at) first_observed_at,MAX(observed_at) observed_at,
    MAX(pi_observed_at) latest_pi_observed_at,COUNT(DISTINCT unlock_event_id) unlocks,
    MAX(prior_pi_age_seconds) maximum_pi_age_seconds,
    MAX(IFF(unlock_device_namespace_validated,1,0)) namespace_validated
  FROM unlock_signal_values GROUP BY 1,2,3,4,5,6
),
authn_coverage AS (
  SELECT t.user_id,COUNT(DISTINCT t.registration_id) authn_registrations,
    COUNT(DISTINCT t.device_id) authn_devices,
    COUNT(DISTINCT IFF(k.member_device_pairs<>1 OR k.invalid_pairs>0,t.registration_id,NULL)) ambiguous_registrations,
    COUNT(DISTINCT r.registration_id) usable_registrations
  FROM target_authn t JOIN registration_cardinality k USING(registration_id)
  LEFT JOIN unique_registration r ON r.registration_id=t.registration_id AND r.user_id=t.user_id
  GROUP BY 1
),
vendor_coverage AS (
  SELECT user_id,COUNT(*) mapped_vendor_callbacks,
    COUNT_IF(NOT http_success) http_error_or_unknown_callbacks,
    COUNT_IF(parsed_body IS NULL) invalid_json_callbacks,
    COUNT_IF(TYPEOF(token_payload)<>'OBJECT' OR token_payload IS NULL) missing_token_payload_callbacks,
    COUNT_IF(vendor_user_conflict) vendor_user_conflict_callbacks,
    COUNT_IF(variant_count>1) callbacks_with_stable_id_variants,
    COUNT_IF(http_success AND NOT vendor_user_conflict AND TYPEOF(token_payload)='OBJECT' AND variant_count=1) valid_pi_callbacks,
    COUNT_IF(http_success AND NOT vendor_user_conflict AND variant_count=1 AND
      TYPEOF(token_payload:environmentDetails:appAccessRiskVerdict:appsDetected)='ARRAY') apps_detected_array_callbacks,
    COUNT_IF(http_success AND NOT vendor_user_conflict AND variant_count=1 AND
      TYPEOF(token_payload:deviceIntegrity:deviceRecognitionVerdict)='ARRAY') device_verdict_array_callbacks,
    COUNT(DISTINCT IFF(http_success AND NOT vendor_user_conflict AND TYPEOF(token_payload)='OBJECT' AND variant_count=1,device_id,NULL)) pi_devices,
    MIN(observed_at) first_vendor_observed_at,MAX(observed_at) last_vendor_observed_at
  FROM vendor_linked GROUP BY 1
),
app_access_coverage AS (
  SELECT user_id,COUNT_IF(app_access_negative_evaluable) app_access_fully_evaluated_callbacks,
    COUNT_IF(controlling_items>0 OR capturing_items>0 OR overlay_items>0) app_access_known_positive_callbacks,
    COUNT_IF(NOT app_access_negative_evaluable AND
      (controlling_items>0 OR capturing_items>0 OR overlay_items>0)) app_access_partly_unknown_callbacks,
    COUNT_IF(NOT app_access_negative_evaluable AND
      controlling_items=0 AND capturing_items=0 AND overlay_items=0) app_access_unknown_callbacks
  FROM pi_app_evaluation GROUP BY 1
),
unmapped_vendor_coverage AS (
  SELECT t.user_id,COUNT(DISTINCT CONCAT(v.stable_event_id,':',v.callback_variant_hash)) unmapped_vendor_callbacks
  FROM (SELECT DISTINCT user_id,registration_id FROM target_authn) t
  JOIN vendor_raw v USING(registration_id)
  LEFT JOIN unique_registration r ON r.registration_id=t.registration_id AND r.user_id=t.user_id
  WHERE r.registration_id IS NULL GROUP BY 1
),
unlock_coverage AS (
  SELECT user_id,COUNT(*) unlock_events,
    COUNT_IF(LOWER(os_name)='android') android_unlock_events,
    COUNT_IF(callback_id IS NOT NULL) direct_device_prior_pi_unlocks,
    COUNT_IF(callback_id IS NULL) unlocks_without_mapped_prior_pi,
    COUNT_IF(callback_id IS NOT NULL AND unlock_device_namespace_validated) confirmed_unlock_pi_links,
    COUNT_IF(callback_id IS NOT NULL AND NOT unlock_device_namespace_validated) provisional_unlock_pi_links,
    MAX(observed_at) last_unlock_observed_at
  FROM unlock_prior_pi GROUP BY 1
),
records AS (
  SELECT 'RISK' record_type,OBJECT_CONSTRUCT_KEEP_NULL(
    'user_id',s.user_id,'device_id',s.device_id,'signal',s.signal_name,
    'signal_family','play_integrity_standardized','raw_value',s.risky,'risky',s.risky,
    'risk_mapping','standardized_nullable_boolean_per_valid_callback',
    'observed_at',s.observed_at,'source','DEVICE_EVENTS_V1_VENDOR_RESPONSE/VENDOR_PLAY_INTEGRITY',
    'scope','pi_independent','device_link','authn_unique_user_device_registration',
    'coverage',IFF(s.risky IS NULL,'unknown_not_evaluated_or_missing','observed_evaluated'),
    'majority_eligible',TRUE,'confirmed_unlock_link',FALSE,
    'callback_id',s.callback_id,'registration_id',s.registration_id,
    'vendor_device_id',s.vendor_device_id,'first_qualified_at',s.first_qualified_at,
    'observed_before_qualification',s.observed_at<=s.first_qualified_at,
    'stable_id_variant_count',s.variant_count,
    'app_access_negative_evaluable',s.app_access_negative_evaluable,
    'apps_detected',s.token_payload:environmentDetails:appAccessRiskVerdict:appsDetected,
    'play_protect_verdict',s.token_payload:environmentDetails:playProtectVerdict,
    'app_recognition_verdict',s.token_payload:appIntegrity:appRecognitionVerdict,
    'device_recognition_verdict',s.token_payload:deviceIntegrity:deviceRecognitionVerdict,
    'attestation_request_binding_checked',FALSE) payload
  FROM pi_standardized s
  UNION ALL
  SELECT 'RISK' record_type,OBJECT_CONSTRUCT_KEEP_NULL(
    'user_id',s.user_id,'device_id',s.device_id,
    'signal',CONCAT(s.signal_family,':',s.raw_value),'signal_family',s.signal_family,
    'raw_value',s.raw_value,'risky',s.risky,'risk_mapping',s.risk_mapping,
    'observed_at',s.observed_at,'first_observed_at',s.first_observed_at,
    'source','DEVICE_EVENTS_V1_VENDOR_RESPONSE/VENDOR_PLAY_INTEGRITY',
    'scope','pi_raw_observation','device_link','authn_unique_user_device_registration',
    'coverage','raw_metadata_observation','majority_eligible',FALSE,'metadata_only',TRUE,
    'confirmed_unlock_link',FALSE,'callbacks',s.callbacks,'registrations',s.registrations,
    'registration_ids',s.registration_ids,'vendor_device_ids',s.vendor_device_ids,
    'callbacks_before_qualification',s.callbacks_before_qualification,
    'callbacks_after_qualification',s.callbacks_after_qualification,
    'conflicting_stable_ids',s.conflicting_stable_ids,
    'attestation_request_binding_checked',FALSE) payload
  FROM pi_signals s
  UNION ALL
  SELECT 'RISK',OBJECT_CONSTRUCT_KEEP_NULL(
    'user_id',s.user_id,'device_id',s.device_id,
    'signal',s.signal_family,'signal_family','play_integrity_standardized',
    'raw_value',s.raw_value,'risky',s.risky,'risk_mapping',s.risk_mapping,
    'observed_at',s.observed_at,'first_observed_at',s.first_observed_at,
    'pi_observed_at',s.latest_pi_observed_at,
    'source','MOBILE_APP_ACCESS_CHANGED+prior_PLAY_INTEGRITY',
    'scope','unlock_association_provisional',
    'device_link','exact_user_and_device_string_namespace_unvalidated',
    'coverage','provisional_same_string_device_association',
    'majority_eligible',FALSE,'confirmed_unlock_link',FALSE,
    'unlocks',s.unlocks,'maximum_pi_age_seconds',s.maximum_pi_age_seconds,
    'unlock_method','unknown_capability_fields_do_not_establish_method',
    'attestation_request_binding_checked',FALSE)
  FROM unlock_signals s
  UNION ALL
  SELECT 'COVERAGE',OBJECT_CONSTRUCT_KEEP_NULL(
    'user_id',n.user_id,'first_qualified_at',n.first_qualified_at,
    'context_start',DATEADD('day',-7,n.first_qualified_at),'cutoff',b.cutoff,
    'mapping_baseline_start',b.mapping_start,
    'authn_registrations',COALESCE(a.authn_registrations,0),
    'authn_devices',COALESCE(a.authn_devices,0),
    'usable_registrations',COALESCE(a.usable_registrations,0),
    'ambiguous_registrations',COALESCE(a.ambiguous_registrations,0),
    'mapped_vendor_callbacks',COALESCE(v.mapped_vendor_callbacks,0),
    'unmapped_vendor_callbacks',COALESCE(m.unmapped_vendor_callbacks,0),
    'http_error_or_unknown_callbacks',COALESCE(v.http_error_or_unknown_callbacks,0),
    'invalid_json_callbacks',COALESCE(v.invalid_json_callbacks,0),
    'missing_token_payload_callbacks',COALESCE(v.missing_token_payload_callbacks,0),
    'vendor_user_conflict_callbacks',COALESCE(v.vendor_user_conflict_callbacks,0),
    'callbacks_with_stable_id_variants',COALESCE(v.callbacks_with_stable_id_variants,0),
    'valid_pi_callbacks',COALESCE(v.valid_pi_callbacks,0),
    'apps_detected_array_callbacks',COALESCE(v.apps_detected_array_callbacks,0),
    'app_access_fully_evaluated_callbacks',COALESCE(ac.app_access_fully_evaluated_callbacks,0),
    'app_access_known_positive_callbacks',COALESCE(ac.app_access_known_positive_callbacks,0),
    'app_access_partly_unknown_callbacks',COALESCE(ac.app_access_partly_unknown_callbacks,0),
    'app_access_unknown_callbacks',COALESCE(ac.app_access_unknown_callbacks,0),
    'device_verdict_array_callbacks',COALESCE(v.device_verdict_array_callbacks,0),
    'pi_devices',COALESCE(v.pi_devices,0),
    'first_vendor_observed_at',v.first_vendor_observed_at,'last_vendor_observed_at',v.last_vendor_observed_at,
    'pi_coverage',IFF(COALESCE(v.valid_pi_callbacks,0)>0,'observed','unknown_no_valid_mapped_pi'),
    'app_access_coverage',CASE WHEN COALESCE(ac.app_access_fully_evaluated_callbacks,0)>0 THEN 'observed_evaluated'
      WHEN COALESCE(ac.app_access_known_positive_callbacks,0)>0 THEN 'observed_risk_other_signals_unknown'
      ELSE 'unknown_not_evaluated_empty_unrecognized_or_absent' END,
    'unlock_events',COALESCE(u.unlock_events,0),'android_unlock_events',COALESCE(u.android_unlock_events,0),
    'direct_device_prior_pi_unlocks',COALESCE(u.direct_device_prior_pi_unlocks,0),
    'unlocks_without_mapped_prior_pi',COALESCE(u.unlocks_without_mapped_prior_pi,0),
    'confirmed_unlock_pi_links',COALESCE(u.confirmed_unlock_pi_links,0),
    'provisional_unlock_pi_links',COALESCE(u.provisional_unlock_pi_links,0),
    'unlock_coverage',IFF(COALESCE(u.unlock_events,0)>0,'observed','unknown_no_unlock_observed'),
    'unlock_device_namespace_validated',FALSE,'last_unlock_observed_at',u.last_unlock_observed_at,
    'source_errors_are_not_clean',TRUE,'attestation_request_binding_checked',FALSE)
  FROM new_users n CROSS JOIN bounds b
  LEFT JOIN authn_coverage a ON a.user_id=n.user_id
  LEFT JOIN vendor_coverage v ON v.user_id=n.user_id
  LEFT JOIN app_access_coverage ac ON ac.user_id=n.user_id
  LEFT JOIN unmapped_vendor_coverage m ON m.user_id=n.user_id
  LEFT JOIN unlock_coverage u ON u.user_id=n.user_id
  UNION ALL
  SELECT 'COVERAGE',OBJECT_CONSTRUCT_KEEP_NULL(
    'scope','run','all_new_users',(SELECT COUNT(*) FROM new_users),
    'cutoff',b.cutoff,'telemetry_start',b.telemetry_start,
    'mapping_baseline_start',b.mapping_start,
    'unlock_device_namespace_validated',FALSE,
    'majority_rule','risky=true AND scope=pi_independent; distinct user numerator > 50% of all_new_users',
    'query_success_empty_new_users_is_valid',TRUE,
    'historical_warehouse_availability_verified',FALSE)
  FROM bounds b
)
SELECT record_type,payload FROM records
ORDER BY record_type,payload:user_id::NUMBER,payload:scope::STRING,
  payload:signal::STRING,payload:device_id::STRING;

-- Inputs are typed session variables: cutoff, day_start, chart_start, history_start.
-- All windows are half-open. No account/registry mutations are performed.
WITH
registry AS (
  SELECT TRY_TO_NUMBER(resource_id) user_id, MIN(created_at) first_recorded_at
  FROM postgres_db.penny.notes
  WHERE created_at < $cutoff AND content ILIKE '%gambling_app_compromise%'
    AND LOWER(resource_type)='user'
    AND TRY_TO_NUMBER(resource_id) > 0
  GROUP BY 1
),
raw_requests AS (
  SELECT *, COALESCE(NULLIF(decision_id,''), 'fallback:' || SHA2(CONCAT_WS('|',
    user_id, TO_VARCHAR(original_timestamp), COALESCE(request_id,''),
    COALESCE(device_id,''), COALESCE(device_ip_address,''), update_context),256)) event_key
  FROM chime.decision_platform.user_service
  WHERE original_timestamp >= DATEADD('minute',-30,$history_start)
    AND original_timestamp < $cutoff AND is_shadow_mode = FALSE
    AND pii_type='email' AND TRY_TO_NUMBER(user_id)>0
    AND update_context IN ('email_verification_email_change','in_app_email_verification_check')
),
decisions AS (
  SELECT TRY_TO_NUMBER(user_id) user_id,event_key,update_context,
    MIN(original_timestamp) ts,MAX(original_timestamp) last_policy_ts,
    IFF(COUNT(DISTINCT device_ip_address)=1,MIN(device_ip_address),NULL) ip,
    IFF(COUNT(DISTINCT device_id)=1,MIN(device_id),NULL) device_id,
    IFF(COUNT(DISTINCT originating_client)=1,MIN(originating_client),NULL) client,
    IFF(COUNT(DISTINCT device_platform)=1,MIN(device_platform),NULL) platform,
    COUNT(*) raw_policy_rows,COUNT(DISTINCT device_id) device_variants,
    COUNT(DISTINCT device_ip_address) ip_variants,
    COUNT_IF(decision_outcome='allow')>0 AND
      COUNT_IF(decision_outcome IS NOT NULL AND decision_outcome<>'allow')=0 policy_allowed
  FROM raw_requests GROUP BY 1,2,3
),
clicks AS (
  SELECT * FROM decisions WHERE update_context='email_verification_email_change'
    AND ts >= $history_start
),
app_requests AS (
  SELECT * FROM decisions WHERE update_context='in_app_email_verification_check'
    AND client='api' AND LOWER(platform) IN ('android','ios')
),
-- Only preceding IP observations are used. Same-time conflicting geographies stay unknown.
geo_points AS (
  SELECT connection_data_ip_address ip, original_timestamp geo_ts,
    IFF(COUNT(DISTINCT geo_ip_data_country)=1,MIN(geo_ip_data_country),NULL) country,
    IFF(COUNT(DISTINCT connection_data_connection_type)=1,MIN(connection_data_connection_type),NULL) connection_type,
    IFF(COUNT(DISTINCT connection_data_isp)=1,MIN(connection_data_isp),NULL) isp,
    COUNT(DISTINCT geo_ip_data_country)>1 geo_conflict
  FROM chime.decision_platform.device_intelligence
  WHERE original_timestamp >= DATEADD('day',-45,$history_start)
    AND original_timestamp < $cutoff
    AND connection_data_ip_address IN (SELECT ip FROM clicks WHERE ip IS NOT NULL)
  GROUP BY 1,2
),
click_geo AS (
  SELECT c.*,g.country,g.connection_type,g.isp,g.geo_ts,g.geo_conflict,
    DATEDIFF('second',g.geo_ts,c.ts)/3600.0 geo_age_hours
  FROM clicks c LEFT JOIN geo_points g ON g.ip=c.ip AND g.geo_ts<=c.ts
    AND g.geo_ts>=DATEADD('day',-45,c.ts)
  QUALIFY ROW_NUMBER() OVER(PARTITION BY c.user_id,c.event_key ORDER BY g.geo_ts DESC NULLS LAST)=1
),
audit AS (
  SELECT item_id user_id,versions_id audit_id,created_at audit_ts,
    SPLIT_PART(LOWER(TRIM(change_to)),'@',-1) to_domain
  FROM analytics.looker.versions_pivot
  WHERE item_type='User' AND object='email'
    AND created_at>=DATEADD('second',-10,$history_start) AND created_at<$cutoff
    AND NULLIF(TRIM(change_to),'') IS NOT NULL
    AND LOWER(TRIM(COALESCE(change_from,'')))<>LOWER(TRIM(COALESCE(change_to,'')))
    AND item_id IN (SELECT user_id FROM clicks)
),
audit_candidates AS (
  SELECT c.user_id,c.event_key,a.audit_id,a.audit_ts,a.to_domain,
    COUNT(*) OVER(PARTITION BY c.user_id,c.event_key) audits_per_click,
    COUNT(*) OVER(PARTITION BY a.user_id,a.audit_id) clicks_per_audit
  FROM click_geo c JOIN audit a ON a.user_id=c.user_id
    AND a.audit_ts>=DATEADD('second',-10,c.ts)
    AND a.audit_ts<=DATEADD('second',10,c.ts)
),
audit_unique AS (
  SELECT * FROM audit_candidates WHERE audits_per_click=1 AND clicks_per_audit=1
),
audit_counts AS (
  SELECT user_id,event_key,COUNT(*) candidate_audits FROM audit_candidates GROUP BY 1,2
),
app_pair_candidates AS (
  SELECT c.user_id,c.event_key,r.event_key app_event_key,r.ts app_ts,r.device_id app_device_id,
    COUNT(*) OVER(PARTITION BY c.user_id,c.event_key) app_pair_candidates,
    ROW_NUMBER() OVER(PARTITION BY c.user_id,c.event_key ORDER BY r.ts DESC,r.event_key) rn
  FROM click_geo c JOIN app_requests r ON r.user_id=c.user_id
    AND r.ts<=c.ts AND r.ts>=DATEADD('minute',-30,c.ts)
),
events AS (
  SELECT c.*,a.audit_id,a.audit_ts,a.to_domain,
    a.audit_id IS NOT NULL persisted_success,
    IFF(a.audit_id IS NOT NULL,GREATEST(c.ts,a.audit_ts),NULL) success_available_at,
    COALESCE(ac.candidate_audits,0) audit_candidates,
    p.app_event_key,p.app_ts,p.app_device_id,p.app_pair_candidates,
    p.app_event_key IS NOT NULL app_to_web_temporal_pair,
    COALESCE(c.country='HK',FALSE) is_hk,
    COALESCE(REGEXP_REPLACE(UPPER(c.connection_type),'[^A-Z]','')='DATACENTER',FALSE) is_datacenter
  FROM click_geo c LEFT JOIN audit_unique a ON a.user_id=c.user_id AND a.event_key=c.event_key
  LEFT JOIN audit_counts ac ON ac.user_id=c.user_id AND ac.event_key=c.event_key
  LEFT JOIN app_pair_candidates p ON p.user_id=c.user_id AND p.event_key=c.event_key AND p.rn=1
),
-- Candidate infrastructure qualifies only after its cumulative evidence crosses the thresholds.
ip_first_users AS (
  SELECT ip,user_id,MIN(ts) first_attempt_at
  FROM events WHERE is_hk AND is_datacenter GROUP BY 1,2
),
ip_first_outlook AS (
  SELECT ip,user_id,MIN(success_available_at) first_outlook_at
  FROM events WHERE is_hk AND is_datacenter AND persisted_success AND to_domain='outlook.com'
  GROUP BY 1,2
),
ip_increments AS (
  SELECT ip,first_attempt_at ts,1 user_delta,0 outlook_delta FROM ip_first_users
  UNION ALL SELECT ip,first_outlook_at,0,1 FROM ip_first_outlook
),
ip_running AS (
  SELECT ip,ts,
    SUM(SUM(user_delta)) OVER(PARTITION BY ip ORDER BY ts ROWS UNBOUNDED PRECEDING) accounts,
    SUM(SUM(outlook_delta)) OVER(PARTITION BY ip ORDER BY ts ROWS UNBOUNDED PRECEDING) outlook_accounts
  FROM ip_increments GROUP BY 1,2
),
discovered_ips AS (
  SELECT ip,ts first_qualified_at,accounts qualification_accounts,
    outlook_accounts qualification_outlook_accounts
  FROM ip_running WHERE accounts>=15 AND outlook_accounts/NULLIF(accounts,0)>=0.8
  QUALIFY ROW_NUMBER() OVER(PARTITION BY ip ORDER BY ts)=1
),
-- These are campaign-linked indicators, not a physical-device or fraud adjudication.
campaign_ip_evidence AS (
  SELECT e.ip,MIN(GREATEST(e.success_available_at,r.first_recorded_at)) first_known_at
  FROM events e JOIN registry r ON r.user_id=e.user_id
  WHERE e.persisted_success AND e.to_domain='outlook.com' AND e.is_hk AND e.is_datacenter AND e.ip IS NOT NULL
  GROUP BY 1
),
known_devices AS (
  SELECT e.device_id,MIN(GREATEST(e.success_available_at,r.first_recorded_at)) first_known_at
  FROM events e JOIN registry r ON r.user_id=e.user_id
  WHERE e.persisted_success AND e.to_domain='outlook.com' AND e.is_hk AND e.is_datacenter AND e.device_id IS NOT NULL
  GROUP BY 1
),
classified AS (
  SELECT e.*,d.first_known_at device_first_known_at,k.first_known_at ip_first_known_at,
    i.first_qualified_at ip_first_qualified_at,
    COALESCE(d.first_known_at<$day_start AND d.first_known_at<=e.ts,FALSE) is_known_bad_device,
    r.first_recorded_at,
    CASE
      WHEN e.persisted_success AND d.first_known_at<$day_start AND d.first_known_at<$cutoff
        THEN GREATEST(e.success_available_at,d.first_known_at)
      WHEN e.persisted_success AND e.to_domain='outlook.com' AND k.first_known_at<$day_start
        THEN GREATEST(e.success_available_at,k.first_known_at)
      WHEN e.persisted_success AND e.to_domain='outlook.com' AND e.is_hk AND e.is_datacenter
           AND i.first_qualified_at<$cutoff THEN GREATEST(e.success_available_at,i.first_qualified_at)
    END candidate_qualified_at,
    CASE
      WHEN e.persisted_success AND d.first_known_at<$day_start AND d.first_known_at<$cutoff THEN 'persisted_on_pre_day_campaign_linked_device'
      WHEN e.persisted_success AND e.to_domain='outlook.com' AND k.first_known_at<$day_start THEN 'persisted_outlook_on_pre_day_campaign_ip'
      WHEN e.persisted_success AND e.to_domain='outlook.com' AND e.is_hk AND e.is_datacenter AND i.first_qualified_at<$cutoff THEN 'persisted_outlook_on_qualified_hk_datacenter_ip'
    END candidate_reason
  FROM events e LEFT JOIN known_devices d ON d.device_id=e.device_id
  LEFT JOIN campaign_ip_evidence k ON k.ip=e.ip
  LEFT JOIN discovered_ips i ON i.ip=e.ip LEFT JOIN registry r ON r.user_id=e.user_id
),
candidate_members AS (
  SELECT user_id,MIN(candidate_qualified_at) first_qualified_at,MIN(ts) evidence_event_at,
    ARRAY_AGG(DISTINCT candidate_reason) reasons
  FROM classified WHERE candidate_qualified_at<$cutoff AND ts >=$day_start AND ts<$cutoff
    AND (first_recorded_at IS NULL OR first_recorded_at >=$day_start)
  GROUP BY 1
),
hourly AS (
  SELECT DATEADD('hour',FLOOR(DATEDIFF('second',$chart_start,ts)/3600),$chart_start) bucket_start,
    COUNT_IF(is_hk) hk_attempts,COUNT_IF(is_hk AND policy_allowed) hk_allowed,
    COUNT_IF(is_hk AND persisted_success) hk_successes,
    COUNT_IF(is_known_bad_device) bad_device_attempts,
    COUNT_IF(is_known_bad_device AND policy_allowed) bad_device_allowed,
    COUNT_IF(is_known_bad_device AND persisted_success) bad_device_successes,
    COUNT_IF(app_to_web_temporal_pair) app_to_web_attempts,
    COUNT_IF(app_to_web_temporal_pair AND policy_allowed) app_to_web_allowed,
    COUNT_IF(app_to_web_temporal_pair AND persisted_success) app_to_web_successes
  FROM classified WHERE ts>=$chart_start AND ts<$cutoff GROUP BY 1
),
app_hourly AS (
  SELECT DATEADD('hour',FLOOR(DATEDIFF('second',$chart_start,ts)/3600),$chart_start) bucket_start,
    COUNT(*) app_initiations FROM app_requests WHERE ts>=$chart_start AND ts<$cutoff GROUP BY 1
),
hour_grid AS (
  SELECT DATEADD('hour',ROW_NUMBER() OVER(ORDER BY SEQ4())-1,$chart_start) bucket_start FROM TABLE(GENERATOR(ROWCOUNT=>168))
),
campaign_activity AS (
  SELECT * FROM classified
  WHERE first_recorded_at<=ts OR is_known_bad_device OR
    (candidate_qualified_at IS NOT NULL AND candidate_qualified_at<$cutoff)
),
ip_summary AS (
  SELECT ip,COUNT(*) attempts,COUNT_IF(policy_allowed) allowed,COUNT_IF(persisted_success) persisted_successes,
    COUNT(DISTINCT user_id) accounts,COUNT(DISTINCT IFF(persisted_success AND to_domain='outlook.com',user_id,NULL)) outlook_accounts,
    MIN(ts) first_seen,MAX(ts) last_seen,COUNT_IF(country IS NULL) missing_geo,
    COUNT(DISTINCT country) country_variants,ARRAY_AGG(DISTINCT country) countries
  FROM classified WHERE ip IS NOT NULL GROUP BY 1
),
latest_ip_geo AS (
  SELECT ip,country,connection_type,isp,geo_ts FROM classified WHERE ip IS NOT NULL
  QUALIFY ROW_NUMBER() OVER(PARTITION BY ip ORDER BY ts DESC,event_key)=1
),
new_campaign_ips AS (
  SELECT ip,MIN(ts) first_seen,COUNT(*) attempts,COUNT_IF(persisted_success) successes
  FROM campaign_activity WHERE ip IS NOT NULL GROUP BY 1 HAVING MIN(ts)>=$day_start
),
new_campaign_countries AS (
  SELECT country,MIN(ts) first_seen,COUNT(DISTINCT user_id) accounts
  FROM campaign_activity WHERE country IS NOT NULL GROUP BY 1 HAVING MIN(ts)>=$day_start
)
SELECT 'MEMBER' RECORD_TYPE,OBJECT_CONSTRUCT_KEEP_NULL(
  'user_id',TO_VARCHAR(user_id),'membership_kind','recorded','first_qualified_at',first_recorded_at,
  'evidence_event_at',first_recorded_at,'reasons',ARRAY_CONSTRUCT('recorded_campaign_annotation')) PAYLOAD FROM registry
UNION ALL
SELECT 'MEMBER',OBJECT_CONSTRUCT_KEEP_NULL('user_id',TO_VARCHAR(user_id),'membership_kind','candidate',
  'first_qualified_at',first_qualified_at,'evidence_event_at',evidence_event_at,'reasons',reasons) FROM candidate_members
UNION ALL
SELECT 'HOURLY',OBJECT_CONSTRUCT_KEEP_NULL('bucket_start',g.bucket_start,
  'hk_attempts',COALESCE(h.hk_attempts,0),'hk_allowed',COALESCE(h.hk_allowed,0),'hk_successes',COALESCE(h.hk_successes,0),
  'bad_device_attempts',COALESCE(h.bad_device_attempts,0),'bad_device_allowed',COALESCE(h.bad_device_allowed,0),
  'bad_device_successes',COALESCE(h.bad_device_successes,0),'app_to_web_attempts',COALESCE(h.app_to_web_attempts,0),
  'app_to_web_allowed',COALESCE(h.app_to_web_allowed,0),'app_to_web_successes',COALESCE(h.app_to_web_successes,0),
  'app_initiations',COALESCE(a.app_initiations,0)) FROM hour_grid g LEFT JOIN hourly h ON h.bucket_start=g.bucket_start
  LEFT JOIN app_hourly a ON a.bucket_start=g.bucket_start
UNION ALL
SELECT 'IP',OBJECT_CONSTRUCT_KEEP_NULL('ip',s.ip,'country',g.country,'countries',s.countries,
  'connection_type',g.connection_type,'isp',g.isp,'attempts',s.attempts,'allowed',s.allowed,
  'persisted_successes',s.persisted_successes,'accounts',s.accounts,'outlook_accounts',s.outlook_accounts,
  'outlook_share',s.outlook_accounts/NULLIF(s.accounts,0),'first_seen',s.first_seen,'last_seen',s.last_seen,
  'first_qualified_at',d.first_qualified_at,'campaign_first_known_at',k.first_known_at,
  'qualification_accounts',d.qualification_accounts,'qualification_outlook_accounts',d.qualification_outlook_accounts,
  'qualification_outlook_share',d.qualification_outlook_accounts/NULLIF(d.qualification_accounts,0),
  'missing_geo',s.missing_geo,'country_variants',s.country_variants,'geo_observed_at',g.geo_ts)
FROM ip_summary s LEFT JOIN latest_ip_geo g ON g.ip=s.ip LEFT JOIN discovered_ips d ON d.ip=s.ip
LEFT JOIN campaign_ip_evidence k ON k.ip=s.ip
WHERE d.ip IS NOT NULL OR s.ip IN (SELECT ip FROM campaign_activity) OR 'HK'=g.country
UNION ALL
SELECT 'ALERT',OBJECT_CONSTRUCT('key','new_campaign_ip','ip',ip,'first_seen',first_seen,
  'attempts',attempts,'successes',successes) FROM new_campaign_ips
UNION ALL
SELECT 'ALERT',OBJECT_CONSTRUCT('key','new_campaign_country','country',country,'first_seen',first_seen,'accounts',accounts)
FROM new_campaign_countries
UNION ALL
SELECT 'ALERT',OBJECT_CONSTRUCT('key','new_candidate_hk_ip','ip',ip,'first_qualified_at',first_qualified_at,
  'qualification_accounts',qualification_accounts,'qualification_outlook_accounts',qualification_outlook_accounts,
  'qualification_outlook_share',qualification_outlook_accounts/NULLIF(qualification_accounts,0))
FROM discovered_ips WHERE first_qualified_at>=$day_start
UNION ALL
SELECT 'COVERAGE',OBJECT_CONSTRUCT('key','extraction_complete','value',TRUE)
UNION ALL SELECT 'COVERAGE',OBJECT_CONSTRUCT('key','current_registry_available','value',TRUE)
UNION ALL SELECT 'COVERAGE',OBJECT_CONSTRUCT('key','campaign_activity_alerts_available','value',TRUE)
UNION ALL SELECT 'COVERAGE',OBJECT_CONSTRUCT('key','history_start','value',$history_start)
UNION ALL SELECT 'COVERAGE',OBJECT_CONSTRUCT('key','cutoff','value',$cutoff)
UNION ALL SELECT 'COVERAGE',OBJECT_CONSTRUCT('key','missing_geo_events','value',COUNT_IF(country IS NULL)) FROM events
UNION ALL SELECT 'COVERAGE',OBJECT_CONSTRUCT('key','ambiguous_audit_events','value',COUNT_IF(audit_candidates>0 AND NOT persisted_success)) FROM events
UNION ALL SELECT 'COVERAGE',OBJECT_CONSTRUCT('key','unmatched_audit_events','value',COUNT_IF(audit_candidates=0)) FROM events
UNION ALL SELECT 'COVERAGE',OBJECT_CONSTRUCT('key','conflicting_device_or_ip_events','value',COUNT_IF(device_variants>1 OR ip_variants>1)) FROM events
UNION ALL SELECT 'COVERAGE',OBJECT_CONSTRUCT('key','multi_candidate_app_pairs','value',COUNT_IF(app_pair_candidates>1)) FROM events
UNION ALL SELECT 'COVERAGE',OBJECT_CONSTRUCT('key','success_semantics','value','unique_bidirectional_user_time_email_audit_within_10s; policy_allow_is_separate')
UNION ALL SELECT 'COVERAGE',OBJECT_CONSTRUCT('key','knowledge_basis','value','event_time_reconstruction; no historical ingestion or annotation-edit snapshot asserted')
UNION ALL SELECT 'COVERAGE',OBJECT_CONSTRUCT('key','campaign_source','value','penny note marker; inferred candidates are proposals, not registry writes')
ORDER BY RECORD_TYPE;

-- Synthetic nullable PI array truth table; no production tables, network or writes.
-- Run as one Snowflake statement. Every row must return PASSED=TRUE.
-- Columns: case, appsDetected JSON, deviceRecognitionVerdict JSON,
-- expected controlling, capturing, overlays, below-device-threshold.
WITH cases AS (
  SELECT column1::STRING case_name,TRY_PARSE_JSON(column2) apps,
    TRY_PARSE_JSON(column3) device,
    column4::BOOLEAN expected_controlling,column5::BOOLEAN expected_capturing,
    column6::BOOLEAN expected_overlays,column7::BOOLEAN expected_below_device
  FROM VALUES
    ('missing','null','null',NULL,NULL,NULL,NULL),
    ('empty','[]','[]',NULL,NULL,NULL,NULL),
    ('unevaluated','["UNEVALUATED"]','["UNEVALUATED"]',NULL,NULL,NULL,NULL),
    ('unknown_enum','["FUTURE_ENUM"]','["FUTURE_ENUM"]',NULL,NULL,NULL,NULL),
    ('known_installed','["KNOWN_INSTALLED"]','["MEETS_DEVICE_INTEGRITY"]',FALSE,FALSE,FALSE,FALSE),
    ('known_unknown_installed','["KNOWN_INSTALLED","UNKNOWN_INSTALLED"]','["MEETS_BASIC_INTEGRITY"]',FALSE,FALSE,FALSE,TRUE),
    ('known_controlling','["UNKNOWN_CONTROLLING"]','["MEETS_VIRTUAL_INTEGRITY"]',TRUE,FALSE,FALSE,TRUE),
    ('known_capturing','["KNOWN_CAPTURING"]','["MEETS_BASIC_INTEGRITY","MEETS_VIRTUAL_INTEGRITY"]',FALSE,TRUE,FALSE,TRUE),
    ('known_overlays','["UNKNOWN_OVERLAYS"]','["MEETS_DEVICE_INTEGRITY","MEETS_BASIC_INTEGRITY"]',FALSE,FALSE,TRUE,FALSE),
    ('all_risky','["KNOWN_CONTROLLING","UNKNOWN_CAPTURING","KNOWN_OVERLAYS"]','["MEETS_DEVICE_INTEGRITY","MEETS_STRONG_INTEGRITY"]',TRUE,TRUE,TRUE,FALSE),
    ('installed_plus_unknown','["KNOWN_INSTALLED","FUTURE_ENUM"]','["MEETS_BASIC_INTEGRITY","FUTURE_ENUM"]',NULL,NULL,NULL,NULL),
    ('positive_plus_unknown','["UNKNOWN_CONTROLLING","FUTURE_ENUM"]','["MEETS_DEVICE_INTEGRITY","FUTURE_ENUM"]',TRUE,NULL,NULL,FALSE),
    ('positive_plus_unevaluated','["KNOWN_CAPTURING","UNEVALUATED"]','["MEETS_BASIC_INTEGRITY","UNEVALUATED"]',NULL,TRUE,NULL,NULL),
    ('null_array_item','[null]','[null]',NULL,NULL,NULL,NULL),
    ('installed_plus_null','["KNOWN_INSTALLED",null]','["MEETS_BASIC_INTEGRITY",null]',NULL,NULL,NULL,NULL),
    ('strong_without_device','["KNOWN_INSTALLED"]','["MEETS_STRONG_INTEGRITY"]',FALSE,FALSE,FALSE,NULL),
    ('basic_strong_without_device','["KNOWN_INSTALLED"]','["MEETS_BASIC_INTEGRITY","MEETS_STRONG_INTEGRITY"]',FALSE,FALSE,FALSE,NULL),
    ('non_array','{"value":"UNKNOWN_CONTROLLING"}','{"value":"MEETS_BASIC_INTEGRITY"}',NULL,NULL,NULL,NULL)
),
app_stats AS (
  SELECT c.case_name,COUNT(*) items,
    COUNT_IF(a.value::STRING IN ('KNOWN_INSTALLED','UNKNOWN_INSTALLED',
      'KNOWN_CONTROLLING','UNKNOWN_CONTROLLING','KNOWN_CAPTURING','UNKNOWN_CAPTURING',
      'KNOWN_OVERLAYS','UNKNOWN_OVERLAYS')) known_items,
    COUNT_IF(a.value::STRING IN ('KNOWN_CONTROLLING','UNKNOWN_CONTROLLING')) controlling,
    COUNT_IF(a.value::STRING IN ('KNOWN_CAPTURING','UNKNOWN_CAPTURING')) capturing,
    COUNT_IF(a.value::STRING IN ('KNOWN_OVERLAYS','UNKNOWN_OVERLAYS')) overlays
  FROM cases c,LATERAL FLATTEN(INPUT=>c.apps) a
  WHERE TYPEOF(c.apps)='ARRAY' GROUP BY 1
),
device_stats AS (
  SELECT c.case_name,COUNT(*) items,
    COUNT_IF(a.value::STRING IN ('MEETS_BASIC_INTEGRITY','MEETS_DEVICE_INTEGRITY',
      'MEETS_STRONG_INTEGRITY','MEETS_VIRTUAL_INTEGRITY')) known_items,
    COUNT_IF(a.value::STRING='MEETS_DEVICE_INTEGRITY') device_integrity,
    COUNT_IF(a.value::STRING IN ('MEETS_BASIC_INTEGRITY','MEETS_VIRTUAL_INTEGRITY')) weaker_integrity,
    COUNT_IF(a.value::STRING='MEETS_STRONG_INTEGRITY') strong_integrity
  FROM cases c,LATERAL FLATTEN(INPUT=>c.device) a
  WHERE TYPEOF(c.device)='ARRAY' GROUP BY 1
),
actual AS (
  SELECT c.*,
    CASE WHEN TYPEOF(c.apps)='ARRAY' AND COALESCE(a.controlling,0)>0 THEN TRUE
      WHEN TYPEOF(c.apps)='ARRAY' AND a.items>0 AND a.known_items=a.items THEN FALSE
      ELSE NULL::BOOLEAN END actual_controlling,
    CASE WHEN TYPEOF(c.apps)='ARRAY' AND COALESCE(a.capturing,0)>0 THEN TRUE
      WHEN TYPEOF(c.apps)='ARRAY' AND a.items>0 AND a.known_items=a.items THEN FALSE
      ELSE NULL::BOOLEAN END actual_capturing,
    CASE WHEN TYPEOF(c.apps)='ARRAY' AND COALESCE(a.overlays,0)>0 THEN TRUE
      WHEN TYPEOF(c.apps)='ARRAY' AND a.items>0 AND a.known_items=a.items THEN FALSE
      ELSE NULL::BOOLEAN END actual_overlays,
    CASE WHEN TYPEOF(c.device)='ARRAY' AND COALESCE(d.device_integrity,0)>0 THEN FALSE
      WHEN TYPEOF(c.device)='ARRAY' AND d.items>0 AND d.known_items=d.items
        AND d.weaker_integrity>0 AND COALESCE(d.strong_integrity,0)=0 THEN TRUE
      ELSE NULL::BOOLEAN END actual_below_device
  FROM cases c LEFT JOIN app_stats a USING(case_name) LEFT JOIN device_stats d USING(case_name)
)
SELECT case_name,apps,device,expected_controlling,actual_controlling,
  expected_capturing,actual_capturing,expected_overlays,actual_overlays,
  expected_below_device,actual_below_device,
  (expected_controlling IS NOT DISTINCT FROM actual_controlling)
    AND (expected_capturing IS NOT DISTINCT FROM actual_capturing)
    AND (expected_overlays IS NOT DISTINCT FROM actual_overlays)
    AND (expected_below_device IS NOT DISTINCT FROM actual_below_device) passed
FROM actual ORDER BY case_name;

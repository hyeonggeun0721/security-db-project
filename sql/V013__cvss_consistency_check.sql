-- =========================================================
-- 마이그레이션 2) CVSS - 심각도 정합성 검증 (cvss_consistency_check.sql)
--
--   CVSS v3.x 정성 등급(qualitative severity rating) 기준:
--     0.0        = NONE
--     0.1 - 3.9  = LOW
--     4.0 - 6.9  = MEDIUM
--     7.0 - 8.9  = HIGH
--     9.0 - 10.0 = CRITICAL
--
--   이 기준으로 라벨(severity)이 점수와 어긋나는 "이상 후보" 행을 뷰로 노출한다.
--   - vulnerabilities : cvss_score 로 산출한 등급 vs severity 컬럼
--   - security_events : 연결된 취약점(vuln_id)의 cvss_score 로 산출한 등급 vs 이벤트 severity
--       (이벤트 severity 는 "운영상 영향도"라 CVE 기본점수와 정당하게 다를 수 있음.
--        따라서 하드 CHECK 로 막지 않고, 검토용 후보로만 보여준다. NULL vuln_id 는 제외.)
--
--   하드 제약을 걸지 않는 이유: 과거 데이터/예외 케이스(재평가된 심각도, 환경점수 반영 등)가
--   존재할 수 있어 INSERT/UPDATE 를 막으면 운영에 지장. 뷰로 "리뷰 큐"만 제공.
--
--   재실행 안전: 함수/뷰 모두 CREATE OR REPLACE.
-- =========================================================

-- CVSS 점수 -> 등급 라벨 (재사용 가능한 순수 함수)
CREATE OR REPLACE FUNCTION fn_cvss_band(p_score numeric)
RETURNS text
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT CASE
        WHEN p_score IS NULL      THEN NULL
        WHEN p_score >= 9.0       THEN 'CRITICAL'
        WHEN p_score >= 7.0       THEN 'HIGH'
        WHEN p_score >= 4.0       THEN 'MEDIUM'
        WHEN p_score >  0.0       THEN 'LOW'
        ELSE 'NONE'
    END;
$$;

COMMENT ON FUNCTION fn_cvss_band(numeric) IS 'CVSS v3.x 점수를 정성 등급(NONE/LOW/MEDIUM/HIGH/CRITICAL)으로 변환';

-- 등급 라벨의 서열(간격 계산용)
CREATE OR REPLACE FUNCTION fn_severity_rank(p_label text)
RETURNS int
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT CASE upper(p_label)
        WHEN 'NONE'     THEN 0
        WHEN 'LOW'      THEN 1
        WHEN 'MEDIUM'   THEN 2
        WHEN 'HIGH'     THEN 3
        WHEN 'CRITICAL' THEN 4
        ELSE NULL
    END;
$$;

-- -----------------------------------------------------------
-- 이상 후보 뷰
-- -----------------------------------------------------------
CREATE OR REPLACE VIEW vw_cvss_severity_mismatch AS
-- (A) vulnerabilities: 점수 기반 등급 vs 라벨
SELECT
    'vulnerabilities'                                   AS source_table,
    v.vuln_id                                           AS record_id,
    v.cve_id                                            AS ref_code,
    v.cvss_score                                        AS cvss_score,
    v.severity                                          AS labeled_severity,
    fn_cvss_band(v.cvss_score)                          AS expected_severity,
    abs( fn_severity_rank(v.severity)
       - fn_severity_rank(fn_cvss_band(v.cvss_score)) ) AS severity_gap
FROM vulnerabilities v
WHERE v.cvss_score IS NOT NULL
  AND v.severity IS DISTINCT FROM fn_cvss_band(v.cvss_score)

UNION ALL

-- (B) security_events: 연결된 취약점의 점수 기반 등급 vs 이벤트 라벨
SELECT
    'security_events'                                   AS source_table,
    e.event_id                                          AS record_id,
    a.asset_name || ' / ' || v.cve_id                   AS ref_code,
    v.cvss_score                                        AS cvss_score,
    e.severity                                          AS labeled_severity,
    fn_cvss_band(v.cvss_score)                          AS expected_severity,
    abs( fn_severity_rank(e.severity)
       - fn_severity_rank(fn_cvss_band(v.cvss_score)) ) AS severity_gap
FROM security_events e
JOIN vulnerabilities v ON v.vuln_id = e.vuln_id
JOIN assets a          ON a.asset_id = e.asset_id
WHERE v.cvss_score IS NOT NULL
  AND e.severity IS DISTINCT FROM fn_cvss_band(v.cvss_score);

COMMENT ON VIEW vw_cvss_severity_mismatch IS
    'CVSS 점수로 산출한 등급과 severity 라벨이 불일치하는 이상 후보 (하드 제약 아님, 검토용)';

GRANT SELECT ON vw_cvss_severity_mismatch TO security_analyst, security_admin, security_manager;

-- -----------------------------------------------------------
-- 테스트
-- -----------------------------------------------------------
\echo ''
\echo '################ fn_cvss_band 동작 확인 ################'
SELECT s AS score, fn_cvss_band(s) AS band
FROM (VALUES (0.0),(3.9),(4.0),(6.9),(7.0),(8.9),(9.0),(10.0)) t(s);

\echo ''
\echo '################ vw_cvss_severity_mismatch : source 별 후보 건수 ################'
SELECT source_table, count(*) AS mismatch_rows, max(severity_gap) AS max_gap
FROM vw_cvss_severity_mismatch GROUP BY source_table ORDER BY source_table;

\echo ''
\echo '################ vw_cvss_severity_mismatch : 간격(gap) 큰 순 상위 20건 ################'
SELECT source_table, record_id, ref_code, cvss_score,
       labeled_severity, expected_severity, severity_gap
FROM vw_cvss_severity_mismatch
ORDER BY severity_gap DESC, source_table, record_id
LIMIT 20;

\echo ''
\echo '################ (참고) vulnerabilities 는 현재 전부 정합 -> 후보 0건 예상 ################'
SELECT count(*) AS vuln_mismatch FROM vw_cvss_severity_mismatch WHERE source_table='vulnerabilities';

-- =========================================================
-- 보안/성능 강화 8) 자산 위험도 구체화 뷰 (materialized_risk_score.sql)
--
--   vw_asset_risk_score 는 매 조회마다 asset_vulnerabilities x vulnerabilities 를
--   집계한다. 대시보드처럼 자주 읽고 실시간성이 덜 중요한 소비자를 위해
--   MATERIALIZED VIEW(mv_asset_risk_score)를 "병행" 제공한다.
--   기존 일반 뷰(vw_asset_risk_score)는 그대로 둔다.
--
--   갱신: fn_refresh_risk_score() 가 REFRESH MATERIALIZED VIEW CONCURRENTLY 수행.
--     - CONCURRENTLY 는 유니크 인덱스가 있어야 하고, 갱신 중에도 읽기가 안 막힌다.
--     - 운영에서는 pg_cron 등으로 주기 실행:
--         SELECT cron.schedule('refresh-risk-score','*/10 * * * *',
--                              $$SELECT fn_refresh_risk_score()$$);
--       (이 파일에서 스케줄러를 설치/등록하지는 않는다)
--
--   재실행 안전: DROP MATERIALIZED VIEW IF EXISTS 후 재생성 / 함수 OR REPLACE.
-- =========================================================

BEGIN;

DROP MATERIALIZED VIEW IF EXISTS mv_asset_risk_score;

CREATE MATERIALIZED VIEW mv_asset_risk_score AS
WITH open_vuln AS (
    SELECT av.asset_id,
           COUNT(*)                    AS open_vuln_count,
           MAX(v.cvss_score)           AS max_open_cvss,
           ROUND(AVG(v.cvss_score), 2) AS avg_open_cvss
    FROM asset_vulnerabilities av
    JOIN vulnerabilities v ON v.vuln_id = av.vuln_id
    WHERE av.status = 'OPEN'
    GROUP BY av.asset_id
)
SELECT
    a.asset_id,
    a.asset_name,
    a.asset_type,
    a.department,
    a.importance_level,
    COALESCE(ov.open_vuln_count, 0)                              AS open_vuln_count,
    COALESCE(ov.max_open_cvss, 0)::numeric(3,1)                  AS max_open_cvss,
    COALESCE(ov.avg_open_cvss, 0)::numeric(4,2)                  AS avg_open_cvss,
    ROUND(a.importance_level * COALESCE(ov.max_open_cvss, 0), 1) AS risk_score,
    CASE
        WHEN a.importance_level * COALESCE(ov.max_open_cvss, 0) >= 40 THEN 'CRITICAL'
        WHEN a.importance_level * COALESCE(ov.max_open_cvss, 0) >= 24 THEN 'HIGH'
        WHEN a.importance_level * COALESCE(ov.max_open_cvss, 0) >= 10 THEN 'MEDIUM'
        ELSE 'LOW'
    END AS risk_label,
    now() AS refreshed_at
FROM assets a
LEFT JOIN open_vuln ov ON ov.asset_id = a.asset_id
WITH DATA;

COMMENT ON MATERIALIZED VIEW mv_asset_risk_score IS
    'vw_asset_risk_score 의 구체화 버전(스냅샷). fn_refresh_risk_score() 로 갱신. refreshed_at 에 마지막 갱신시각.';

-- REFRESH ... CONCURRENTLY 전제: 유니크 인덱스
CREATE UNIQUE INDEX mv_asset_risk_score_pk ON mv_asset_risk_score (asset_id);
-- 대시보드 조회 패턴(라벨/점수 정렬)용 보조 인덱스
CREATE INDEX mv_asset_risk_score_label_idx ON mv_asset_risk_score (risk_label, risk_score DESC);

GRANT SELECT ON mv_asset_risk_score TO security_analyst, security_admin, security_manager;

CREATE OR REPLACE FUNCTION fn_refresh_risk_score()
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
BEGIN
    REFRESH MATERIALIZED VIEW CONCURRENTLY mv_asset_risk_score;
END;
$$;

COMMENT ON FUNCTION fn_refresh_risk_score() IS
    'mv_asset_risk_score 를 CONCURRENTLY 갱신. 운영에서는 pg_cron 등으로 주기 실행.';

-- 새 함수 기본 PUBLIC EXECUTE 회수 후 유지보수 role 에만 부여 (function_privilege_hardening 방침)
REVOKE EXECUTE ON FUNCTION fn_refresh_risk_score() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION fn_refresh_risk_score() TO security_admin;

COMMIT;

-- =========================================================
-- 검증
-- =========================================================
\echo ''
\echo '################ mv 와 일반 뷰가 동일 결과인지 (라벨별 건수) ################'
SELECT 'view' AS src, risk_label, count(*) FROM vw_asset_risk_score GROUP BY risk_label
UNION ALL
SELECT 'mv',        risk_label, count(*) FROM mv_asset_risk_score GROUP BY risk_label
ORDER BY risk_label, src;

\echo ''
\echo '################ [TEST] fn_refresh_risk_score() 실행 가능 확인 (CONCURRENTLY) ################'
SELECT fn_refresh_risk_score();
SELECT 'refresh OK, refreshed_at=' || max(refreshed_at)::text AS result FROM mv_asset_risk_score;

\echo ''
\echo '################ [TEST] 스냅샷 특성: 데이터 변경 시 일반뷰는 즉시/ mv 는 refresh 전까지 그대로 (BEGIN..ROLLBACK) ################'
-- CONCURRENTLY 는 트랜잭션 안에서 못 쓰므로, 이 데모에서는 일반 REFRESH 사용
BEGIN;
  INSERT INTO asset_vulnerabilities (asset_id, vuln_id, detected_date, status)
  VALUES (5, 1, CURRENT_DATE, 'OPEN');   -- vuln 1 = CVE-2025-0001 (cvss 9.8), asset 5 importance 2 -> risk 19.6
  SELECT '변경 직후 vw (즉시 반영)' AS chk, risk_score, risk_label FROM vw_asset_risk_score WHERE asset_id=5;
  SELECT '변경 직후 mv (아직 옛 스냅샷)' AS chk, risk_score, risk_label FROM mv_asset_risk_score WHERE asset_id=5;
  REFRESH MATERIALIZED VIEW mv_asset_risk_score;   -- 비CONCURRENTLY (트랜잭션 내 허용)
  SELECT 'REFRESH 후 mv (반영됨)' AS chk, risk_score, risk_label FROM mv_asset_risk_score WHERE asset_id=5;
ROLLBACK;
\echo '   (ROLLBACK - av 임시행 제거)'

\echo ''
\echo '################ 롤백으로 mv 가 트랜잭션 내 옛 데이터로 남았을 수 있어 마지막에 한 번 더 정합화 ################'
SELECT fn_refresh_risk_score();
SELECT 'view=mv 동일?' AS chk,
       (SELECT count(*) FROM vw_asset_risk_score) AS view_rows,
       (SELECT count(*) FROM mv_asset_risk_score) AS mv_rows,
       (SELECT count(*) FROM (SELECT asset_id,risk_score,risk_label FROM vw_asset_risk_score
                              EXCEPT SELECT asset_id,risk_score,risk_label FROM mv_asset_risk_score) d) AS diff_rows;

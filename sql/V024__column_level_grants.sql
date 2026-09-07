-- =========================================================
-- 보안 강화 6) 컬럼 단위 최소 권한 (column_level_grants.sql)
--
--   부서 전용 계정(dept_infra/dept_dev/dept_sales)은 자산의 IP 주소를 알 필요가 없다.
--   assets 에 대한 "테이블 단위 SELECT" 를 회수하고, ip_address 를 제외한
--   컬럼에만 "컬럼 단위 SELECT" 를 부여한다.
--     허용: asset_id, asset_name, asset_type, department, importance_level, created_at
--     차단: ip_address
--   security_analyst / security_admin / security_manager 는 전체 컬럼 유지.
--   RLS(행 필터)는 그대로 — 컬럼 권한과 행 보안은 직교한다.
--
--   PostgreSQL 동작 참고:
--     컬럼 단위 권한만 있는 상태에서 `SELECT *` 는 ip_address 까지 확장되므로
--     "permission denied for column ip_address" 로 거부된다(컬럼을 조용히 빼주지 않음).
--     → 허용 컬럼을 명시하면 정상 조회된다. 편의를 위해 ip_address 없는
--       뷰 vw_assets_dept 도 함께 제공(부서 계정이 SELECT * 하고 싶을 때 사용).
--
--   재실행 안전: REVOKE/GRANT 멱등, 뷰 OR REPLACE.
-- =========================================================

BEGIN;

-- 1) 테이블 단위 SELECT 회수
REVOKE SELECT ON assets FROM dept_infra, dept_dev, dept_sales;

-- 2) ip_address 를 제외한 컬럼 단위 SELECT 부여
GRANT SELECT (asset_id, asset_name, asset_type, department, importance_level, created_at)
    ON assets TO dept_infra, dept_dev, dept_sales;

-- 3) 편의 뷰 (ip_address 없음).
--    ※ security_invoker=true (PG15+) 필수: 이게 없으면 뷰가 소유자(summer=superuser)
--      권한으로 실행되어 assets RLS 를 통째로 우회한다(모든 행 노출). invoker 모드면
--      호출한 부서 계정 기준으로 RLS 가 적용된다.
DROP VIEW IF EXISTS vw_assets_dept;
CREATE VIEW vw_assets_dept WITH (security_invoker = true) AS
SELECT asset_id, asset_name, asset_type, department, importance_level, created_at
FROM assets;
COMMENT ON VIEW vw_assets_dept IS '부서 계정용 assets 뷰 (ip_address 제외, security_invoker). 행 필터는 호출자 기준 assets RLS 를 상속.';
GRANT SELECT ON vw_assets_dept TO dept_infra, dept_dev, dept_sales,
                                  security_analyst, security_admin, security_manager;

-- security_* 는 assets 전체 컬럼 SELECT 유지(rbac.sql 에서 부여됨). 여기서 건드리지 않음.

COMMIT;

-- @migrate:verify  (이 아래는 검증 절: ON_ERROR_STOP=0, 마이그레이션 성공 여부와 무관. \! 서브셸/의도적 타임아웃 포함)

-- =========================================================
-- 검증
-- =========================================================
\echo ''
\echo '################ assets 컬럼별 SELECT 권한 (dept_* 에 ip_address 없어야) ################'
SELECT grantee, string_agg(column_name, ', ' ORDER BY column_name) AS selectable_columns
FROM information_schema.role_column_grants
WHERE table_name='assets' AND privilege_type='SELECT'
  AND grantee IN ('dept_infra','dept_dev','dept_sales','security_analyst','security_admin','security_manager')
GROUP BY grantee ORDER BY grantee;

\echo ''
\echo '################ [TEST] dept_infra : 허용 컬럼 명시 조회 -> 정상 ################'
\! psql -d security_db -U dept_infra -c "SELECT asset_id, asset_name, asset_type, department, importance_level FROM assets ORDER BY asset_id;" 2>&1

\echo ''
\echo '################ [TEST] dept_infra : ip_address 조회 -> 거부 기대 ################'
\! psql -d security_db -U dept_infra -c "SELECT asset_id, ip_address FROM assets;" 2>&1

\echo ''
\echo '################ [TEST] dept_infra : SELECT * -> ip_address 때문에 거부 기대 ################'
\! psql -d security_db -U dept_infra -c "SELECT * FROM assets;" 2>&1

\echo ''
\echo '################ [TEST] dept_infra : vw_assets_dept 로 SELECT * -> 정상(ip_address 없음) ################'
\! psql -d security_db -U dept_infra -c "SELECT * FROM vw_assets_dept ORDER BY asset_id LIMIT 3;" 2>&1

\echo ''
\echo '################ [TEST] security_manager : assets SELECT * -> ip_address 포함 정상 ################'
\! psql -d security_db -U security_manager -c "SELECT asset_id, asset_name, ip_address FROM assets ORDER BY asset_id LIMIT 3;" 2>&1

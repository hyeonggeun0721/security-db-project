-- =========================================================
-- 마이그레이션 4) RLS 적용 범위 확장 (rls_expansion.sql)
--
--   assets 에만 걸려 있던 부서 기반 Row-Level Security 를 security_events, responses
--   까지 확장한다.
--     - security_events : asset_id -> assets.department 로 부서 판정
--     - responses       : event_id -> security_events -> assets.department 로 부서 판정
--     - 부서 컨텍스트: 세션변수 app.department 우선, 없으면 rls_role_department 매핑
--       (row_level_security.sql 과 동일한 규칙)
--     - security_analyst / security_admin / security_manager : 전체 접근 유지
--
--   판정 로직은 SECURITY DEFINER 헬퍼 함수로 캡슐화한다. RLS 정책의 서브쿼리가
--   RLS 걸린 테이블을 다시 참조하면서 생기는 순환/이중필터를 피하기 위함이다.
--
--   재실행 안전: 함수 CREATE OR REPLACE, 정책 DROP ... IF EXISTS 후 CREATE.
-- =========================================================

BEGIN;

-- ---------------------------------------------------------
-- 0) 부서 역할이 두 테이블을 조회할 수 있도록 SELECT 부여
--    (쓰기 권한은 주지 않음 - RBAC 정책 유지)
-- ---------------------------------------------------------
GRANT SELECT ON security_events TO dept_infra, dept_dev, dept_sales;
GRANT SELECT ON responses       TO dept_infra, dept_dev, dept_sales;

-- ---------------------------------------------------------
-- 1) 헬퍼 함수
-- ---------------------------------------------------------
-- 현재 세션의 "부서 컨텍스트"
--   SECURITY INVOKER(기본): current_user 가 실제 접속 role 이어야 rls_role_department
--   매핑이 맞는다. (SECURITY DEFINER 로 하면 current_user 가 함수 소유자로 바뀌어
--   매핑이 깨진다 - row_level_security.sql 의 인라인 정책과 동일한 의미를 유지)
--   dept_* role 은 rls_role_department 에 SELECT 권한을 갖고 있다(row_level_security.sql).
CREATE OR REPLACE FUNCTION fn_current_dept()
RETURNS text
LANGUAGE sql
STABLE
SET search_path = pg_catalog, public
AS $$
    SELECT COALESCE(
        NULLIF(current_setting('app.department', true), ''),
        (SELECT r.department FROM rls_role_department r WHERE r.role_name = current_user)
    );
$$;

-- asset_id -> 소속 부서 (RLS 우회)
CREATE OR REPLACE FUNCTION fn_asset_department(p_asset_id int)
RETURNS text
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT a.department FROM assets a WHERE a.asset_id = p_asset_id;
$$;

-- event_id -> 그 이벤트가 발생한 자산의 부서 (RLS 우회)
CREATE OR REPLACE FUNCTION fn_event_department(p_event_id int)
RETURNS text
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT a.department
    FROM security_events e
    JOIN assets a ON a.asset_id = e.asset_id
    WHERE e.event_id = p_event_id;
$$;

-- ---------------------------------------------------------
-- 2) security_events RLS
-- ---------------------------------------------------------
ALTER TABLE security_events ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS p_events_dept_scope ON security_events;
CREATE POLICY p_events_dept_scope ON security_events
    FOR SELECT
    TO dept_infra, dept_dev, dept_sales
    USING (fn_asset_department(asset_id) = fn_current_dept());

DROP POLICY IF EXISTS p_events_rbac_all ON security_events;
CREATE POLICY p_events_rbac_all ON security_events
    FOR ALL
    TO security_analyst, security_admin, security_manager
    USING (true) WITH CHECK (true);

-- ---------------------------------------------------------
-- 3) responses RLS
-- ---------------------------------------------------------
ALTER TABLE responses ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS p_responses_dept_scope ON responses;
CREATE POLICY p_responses_dept_scope ON responses
    FOR SELECT
    TO dept_infra, dept_dev, dept_sales
    USING (fn_event_department(event_id) = fn_current_dept());

DROP POLICY IF EXISTS p_responses_rbac_all ON responses;
CREATE POLICY p_responses_rbac_all ON responses
    FOR ALL
    TO security_analyst, security_admin, security_manager
    USING (true) WITH CHECK (true);

COMMIT;

-- @migrate:verify  (이 아래는 검증 절: ON_ERROR_STOP=0, 마이그레이션 성공 여부와 무관. \! 서브셸/의도적 타임아웃 포함)

-- =========================================================
-- 테스트
-- =========================================================
\echo ''
\echo '################ 소유자(summer) 기준 전체 건수 (RLS 우회) ################'
SELECT (SELECT count(*) FROM security_events) AS events_total,
       (SELECT count(*) FROM responses)       AS responses_total;

\echo ''
\echo '################ 부서별 자산 -> 이벤트/대응 분포 (기대값 계산용, 소유자 시점) ################'
SELECT a.department,
       count(DISTINCT e.event_id)    AS events,
       count(DISTINCT r.response_id) AS responses
FROM assets a
LEFT JOIN security_events e ON e.asset_id = a.asset_id
LEFT JOIN responses r       ON r.event_id = e.event_id
GROUP BY a.department ORDER BY a.department;

\echo ''
\echo '################ [dept_infra] 인프라팀 이벤트/대응만 보여야 함 ################'
\! psql -d security_db -U dept_infra -c "SELECT count(*) AS events, string_agg(DISTINCT (SELECT department FROM assets a WHERE a.asset_id=e.asset_id), ',') AS depts FROM security_events e;" 2>&1
\! psql -d security_db -U dept_infra -c "SELECT count(*) AS responses FROM responses;" 2>&1

\echo ''
\echo '################ [dept_dev] 개발팀 이벤트/대응만 보여야 함 ################'
\! psql -d security_db -U dept_dev -c "SELECT count(*) AS events FROM security_events;" 2>&1
\! psql -d security_db -U dept_dev -c "SELECT count(*) AS responses FROM responses;" 2>&1
\! psql -d security_db -U dept_dev -c "SELECT event_id, asset_id FROM security_events ORDER BY event_id;" 2>&1

\echo ''
\echo '################ [dept_sales] 영업팀 이벤트/대응만 보여야 함 ################'
\! psql -d security_db -U dept_sales -c "SELECT count(*) AS events FROM security_events;" 2>&1
\! psql -d security_db -U dept_sales -c "SELECT count(*) AS responses FROM responses;" 2>&1

\echo ''
\echo '################ [dept_dev] 세션변수로 인프라팀 컨텍스트 override (인프라팀 이벤트 수로 바뀌어야 함) ################'
\! PGOPTIONS="-c app.department=인프라팀" psql -d security_db -U dept_dev -c "SELECT count(*) AS events FROM security_events;" 2>&1

\echo ''
\echo '################ [security_manager] 전체 접근 유지 확인 ################'
\! psql -d security_db -U security_manager -c "SELECT (SELECT count(*) FROM security_events) AS events, (SELECT count(*) FROM responses) AS responses;" 2>&1

-- =========================================================
-- 보안 강화 9) 자원 보호 - 연결 수 / 문 실행시간 / 유휴 트랜잭션 (resource_limits.sql)
--
--   일반(비관리) 계정이 커넥션을 고갈시키거나, 폭주 쿼리로 CPU/IO 를 물거나,
--   트랜잭션을 열어둔 채 방치해 잠금/부풀림(bloat)을 유발하는 것을 role 단위로 제한한다.
--
--   대상/값 (판단):
--     role              | CONNECTION LIMIT | statement_timeout | idle_in_transaction_session_timeout
--     ------------------+------------------+-------------------+------------------------------------
--     dept_infra/dev/sales |            5   |       15s         |            5min
--     security_analyst     |           10   |       30s         |            5min
--     security_manager     |           15   |       30s         |            5min   (Streamlit 대시보드 다중 뷰어 여유)
--     security_admin       |  (제한 없음)   |   (제한 없음)     |            5min   (유지보수 장시간 작업 대비, 유휴 트랜잭션만 방지)
--
--   ALTER ROLE ... SET 은 "다음 접속부터" 적용된다(기존 세션엔 미적용).
--   재실행 안전: ALTER ROLE 은 멱등.
-- =========================================================

BEGIN;

-- 동시 연결 수
ALTER ROLE dept_infra       CONNECTION LIMIT 5;
ALTER ROLE dept_dev         CONNECTION LIMIT 5;
ALTER ROLE dept_sales       CONNECTION LIMIT 5;
ALTER ROLE security_analyst CONNECTION LIMIT 10;
ALTER ROLE security_manager CONNECTION LIMIT 15;
-- security_admin: 무제한 유지(명시적으로 -1 = 무제한)
ALTER ROLE security_admin   CONNECTION LIMIT -1;

-- 문 실행시간 상한
ALTER ROLE dept_infra       SET statement_timeout = '15s';
ALTER ROLE dept_dev         SET statement_timeout = '15s';
ALTER ROLE dept_sales       SET statement_timeout = '15s';
ALTER ROLE security_analyst SET statement_timeout = '30s';
ALTER ROLE security_manager SET statement_timeout = '30s';
-- security_admin 은 statement_timeout 미설정(유지보수 장시간 작업 허용)

-- 유휴 트랜잭션 방치 차단 (6개 일반 role + admin 도)
ALTER ROLE dept_infra       SET idle_in_transaction_session_timeout = '5min';
ALTER ROLE dept_dev         SET idle_in_transaction_session_timeout = '5min';
ALTER ROLE dept_sales       SET idle_in_transaction_session_timeout = '5min';
ALTER ROLE security_analyst SET idle_in_transaction_session_timeout = '5min';
ALTER ROLE security_manager SET idle_in_transaction_session_timeout = '5min';
ALTER ROLE security_admin   SET idle_in_transaction_session_timeout = '5min';

COMMIT;

-- @migrate:verify  (이 아래는 검증 절: ON_ERROR_STOP=0, 마이그레이션 성공 여부와 무관. \! 서브셸/의도적 타임아웃 포함)

-- =========================================================
-- 검증
-- =========================================================
\echo ''
\echo '################ role 별 연결 제한 / 세션 파라미터 ################'
SELECT r.rolname,
       r.rolconnlimit AS conn_limit,
       (SELECT string_agg(cfg, ', ') FROM unnest(r.rolconfig) AS cfg) AS session_settings
FROM pg_roles r
WHERE r.rolname IN ('dept_infra','dept_dev','dept_sales',
                    'security_analyst','security_admin','security_manager')
ORDER BY r.rolname;

\echo ''
\echo '################ [TEST] 각 role 로 실제 접속 -> 파라미터 적용 & 정상 쿼리 타임아웃 안 걸림 ################'
\! psql -d security_db -U dept_infra       -c "SHOW statement_timeout; SHOW idle_in_transaction_session_timeout; SELECT count(*) AS ok_events FROM security_events;" 2>&1
\! psql -d security_db -U security_analyst -c "SHOW statement_timeout; SELECT count(*) AS ok_join FROM responses r JOIN staff s ON s.staff_id=r.staff_id;" 2>&1
\! psql -d security_db -U security_manager -c "SHOW statement_timeout; SELECT count(*) AS ok_view FROM vw_asset_risk_score;" 2>&1

\echo ''
\echo '################ [TEST] statement_timeout 이 실제로 동작하는지 (dept_infra 로 16초 sleep -> 15s 에서 취소 기대) ################'
\! psql -d security_db -U dept_infra -c "SELECT pg_sleep(16);" 2>&1

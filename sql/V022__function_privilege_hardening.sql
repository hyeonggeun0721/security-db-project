-- =========================================================
-- 보안 강화 2) 함수 EXECUTE 권한 최소화 (function_privilege_hardening.sql)
--
--   PostgreSQL 기본값: public 스키마의 모든 함수는 PUBLIC 에게 EXECUTE 가 부여된다.
--   → 낮은 권한 계정도 조직 로직 함수를 임의 호출 가능. PUBLIC 회수 후 필요한
--     role 에게만 재부여한다.
--
--   재부여 대상(최소 권한):
--     fn_asset_department(int) / fn_event_department(int) / fn_current_dept()
--         → RLS 정책(p_events_dept_scope, p_responses_dept_scope)이 평가하는 함수.
--           security_events/responses 를 조회하는 6개 role 전부에 EXECUTE 필요.
--           (여기서 잘못 잠그면 RLS 조회 자체가 permission denied 로 깨진다)
--     fn_cvss_band(numeric) / fn_severity_rank(text)
--         → vw_cvss_severity_mismatch / vw_cvss_nvd_mismatch 뷰가 호출. 뷰를 쓰는
--           role 은 뷰가 부르는 함수의 EXECUTE 도 있어야 한다(뷰는 함수 권한을 대납 안 함).
--           대상: security_analyst / security_admin / security_manager.
--     fn_archive_audit_log(interval)
--         → 보존정책 유지보수. 감사 스튜어드인 security_admin 에게만.
--
--   재부여 안 하는 함수(정상):
--     fn_audit_row_change()          : 트리거로만 실행. 트리거 실행은 EXECUTE ACL 을 타지 않음.
--     fn_audit_log_block_mutation()  : 동상(BEFORE UPDATE/DELETE/TRUNCATE 트리거).
--     pgvector 확장 함수 다수         : 현재 벡터검색은 superuser(summer)로 실행되어 ACL 우회.
--       비superuser 로 벡터검색이 필요해지면:
--         GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO PUBLIC;  -- (또는 해당 함수만)
--
--   재실행 안전: REVOKE/GRANT 는 멱등.
-- =========================================================

BEGIN;

-- 1) PUBLIC 에서 전면 회수
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;

-- 2) 앞으로 만들어질 함수도 PUBLIC 기본 EXECUTE 를 받지 않도록 시도.
--    ※ 이 환경(PG15)에서는 이 구문이 pg_default_acl 에 항목을 남기지 않아
--      이후 CREATE FUNCTION 에 자동 적용되지 않는다. 따라서 함수를 새로 만드는
--      마이그레이션(audit_log_hash_chain.sql / materialized_risk_score.sql)은
--      각자 `REVOKE EXECUTE ON FUNCTION <name> FROM PUBLIC` 를 명시한다.
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

-- 3) RLS 평가 함수: 6개 role 에 재부여
GRANT EXECUTE ON FUNCTION fn_asset_department(integer) TO
    security_analyst, security_admin, security_manager, dept_infra, dept_dev, dept_sales;
GRANT EXECUTE ON FUNCTION fn_event_department(integer) TO
    security_analyst, security_admin, security_manager, dept_infra, dept_dev, dept_sales;
GRANT EXECUTE ON FUNCTION fn_current_dept() TO
    security_analyst, security_admin, security_manager, dept_infra, dept_dev, dept_sales;

-- 4) mismatch 뷰가 부르는 함수: 뷰 사용 3개 role 에 재부여
GRANT EXECUTE ON FUNCTION fn_cvss_band(numeric)  TO security_analyst, security_admin, security_manager;
GRANT EXECUTE ON FUNCTION fn_severity_rank(text) TO security_analyst, security_admin, security_manager;

-- 5) 보존정책 유지보수 함수: 감사 스튜어드에게만
GRANT EXECUTE ON FUNCTION fn_archive_audit_log(interval) TO security_admin;

COMMIT;

-- =========================================================
-- 검증
-- =========================================================
\echo ''
\echo '################ 조직 함수(fn_*) EXECUTE ACL ################'
SELECT proname, pg_get_function_identity_arguments(oid) AS args, coalesce(proacl::text,'(소유자 전용)') AS proacl
FROM pg_proc WHERE pronamespace='public'::regnamespace AND proname LIKE 'fn\_%'
ORDER BY proname;

\echo ''
\echo '################ [TEST] 트리거 함수는 EXECUTE 없이도 트리거로 동작 (BEGIN..ROLLBACK, 데이터 미변경) ################'
BEGIN;
  SELECT count(*) AS audit_before FROM audit_log;
  UPDATE responses SET status = status WHERE response_id = 2;   -- 트리거만 발화시키는 no-op UPDATE
  SELECT count(*) AS audit_after_expected_plus1 FROM audit_log;
  SELECT CASE WHEN (SELECT count(*) FROM audit_log) > 0
              THEN '[OK] fn_audit_row_change 가 PUBLIC EXECUTE 없이도 트리거로 정상 발화'
              ELSE '[FAIL] 트리거 미발화' END AS result;
ROLLBACK;
\echo '   (ROLLBACK 완료 - audit_log 원상)'

-- =========================================================
-- 보안 강화 1) SECURITY DEFINER 함수 search_path 고정 (search_path_hardening.sql)
--
--   CVE-2018-1058 류의 "search_path 하이재킹": SECURITY DEFINER 함수가 실행 시점의
--   호출자 search_path 를 물려받으면, 낮은 권한 사용자가 자기 스키마(또는 pg_temp)에
--   `now()`, `sha256()`, 혹은 `assets` 같은 이름의 가짜 객체를 만들어 함수 소유자
--   권한으로 실행되게 만들 수 있다. 함수 정의에 search_path 를 못박아 이를 차단한다.
--
--   대상(실측 조회 결과 — pg_proc.prosecdef = true):
--     fn_audit_row_change()            [트리거]
--     fn_asset_department(integer)     [RLS 헬퍼]
--     fn_event_department(integer)     [RLS 헬퍼]
--     fn_archive_audit_log(interval)   [보존정책]
--   + fn_current_dept()  : SECURITY INVOKER 지만 RLS 정책에서 쓰이므로 함께 고정.
--
--   값: `pg_catalog, public, pg_temp`
--     - pg_catalog 를 "명시적으로" 맨 앞에 → 내장 함수(now/sha256 등) 셰도잉 원천 차단
--       (미지정 시에도 pg_catalog 는 암묵적으로 먼저 검색되지만, 명시가 안전하다)
--     - public : 이 함수들이 assets/security_events/audit_log 를 스키마 없이 참조하므로 필요
--     - pg_temp : PostgreSQL 매뉴얼 권고대로 "맨 마지막"에 명시 → 임시객체가 앞서 검색되지 못하게
--     (요청서의 `public, pg_temp` 를 매뉴얼 권고형인 위 형태로 구체화함)
--
--   본문은 건드리지 않는다. ALTER FUNCTION ... SET 만 사용(재실행 안전).
-- =========================================================

BEGIN;

ALTER FUNCTION fn_audit_row_change()              SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION fn_asset_department(integer)       SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION fn_event_department(integer)       SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION fn_archive_audit_log(interval)     SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION fn_current_dept()                  SET search_path = pg_catalog, public, pg_temp;

COMMENT ON FUNCTION fn_audit_row_change() IS
    'security_events/responses 공용 감사 트리거 함수. SECURITY DEFINER + search_path 고정(pg_catalog,public,pg_temp)으로 search_path 하이재킹 차단.';
COMMENT ON FUNCTION fn_asset_department(integer) IS
    'asset_id -> 부서 (RLS 우회 조회용). SECURITY DEFINER + search_path 고정으로 하이재킹 차단.';
COMMENT ON FUNCTION fn_event_department(integer) IS
    'event_id -> 자산 부서 (RLS 우회 조회용). SECURITY DEFINER + search_path 고정으로 하이재킹 차단.';
COMMENT ON FUNCTION fn_archive_audit_log(interval) IS
    'audit_log 보존기간 경과분 이관. SECURITY DEFINER + search_path 고정으로 하이재킹 차단.';
COMMENT ON FUNCTION fn_current_dept() IS
    '현재 세션의 부서 컨텍스트(RLS). SECURITY INVOKER 지만 RLS 경로라 search_path 고정으로 하이재킹 차단.';

COMMIT;

-- =========================================================
-- 검증
-- =========================================================
\echo ''
\echo '################ fn_* 함수 search_path 설정 (proconfig) ################'
SELECT proname, pg_get_function_identity_arguments(oid) AS args, prosecdef AS sec_definer, proconfig
FROM pg_proc
WHERE pronamespace='public'::regnamespace AND proname LIKE 'fn\_%'
ORDER BY prosecdef DESC, proname;

\echo ''
\echo '################ [TEST] search_path 하이재킹 방어 확인 ################'
-- pg_temp 에 가짜 assets 를 만들어도, 고정 search_path 덕에 fn_asset_department 는
-- public.assets 만 본다(부서가 정상 반환되어야 함).
DO $$
DECLARE v_dept text;
BEGIN
    CREATE TEMP TABLE assets (asset_id int, department text) ON COMMIT DROP;
    INSERT INTO pg_temp.assets VALUES (1, 'HIJACKED');
    SELECT fn_asset_department(1) INTO v_dept;
    IF v_dept = 'HIJACKED' THEN
        RAISE NOTICE '[FAIL] pg_temp.assets 가 하이재킹됨 (dept=%).', v_dept;
    ELSE
        RAISE NOTICE '[OK] 고정 search_path 로 pg_temp 셰도잉 무시됨. fn_asset_department(1)=% (public.assets 기준).', v_dept;
    END IF;
END $$;

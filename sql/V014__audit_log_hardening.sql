-- =========================================================
-- 마이그레이션 3) 감사 로그 불변성 + 보존 정책 (audit_log_hardening.sql)
--
--   (1) 불변성(append-only):
--       - 모든 일반 role 에서 audit_log 의 UPDATE/DELETE/TRUNCATE 권한 회수, INSERT 만 허용
--       - 추가 방어선: BEFORE UPDATE/DELETE/TRUNCATE 트리거로 변경을 원천 차단
--         (테이블 소유자까지 막는다. 단 슈퍼유저가 session_replication_role='replica'
--          로 트리거를 끄는 것까지는 DB 레벨에서 막을 수 없음 - OS/백업 통제 영역)
--       - 유지보수(보존정책 이관)만 SET LOCAL audit_log.maintenance='on' 으로 예외 허용
--
--   (2) 보존 정책:
--       - audit_log_archive 테이블 + fn_archive_audit_log(retention) 함수
--       - changed_at 이 retention(기본 1년) 보다 오래된 로그를 archive 로 옮기고 원본에서 삭제
--       - 실제 정기 실행은 이 파일에서 하지 않음. 스케줄링 방법은 아래 주석 참고.
--
--   재실행 안전: 함수/트리거 CREATE OR REPLACE / DROP IF EXISTS, 테이블 IF NOT EXISTS.
-- =========================================================

BEGIN;

-- ---------------------------------------------------------
-- (1a) 권한: audit_log 는 append-only
-- ---------------------------------------------------------
REVOKE UPDATE, DELETE, TRUNCATE, TRIGGER, REFERENCES ON audit_log
    FROM PUBLIC, security_analyst, security_admin, security_manager,
         dept_infra, dept_dev, dept_sales;

-- INSERT 만 부여 (트리거 경유가 정상 경로지만, 명시적 직접 INSERT 도 허용)
GRANT INSERT ON audit_log
    TO security_analyst, security_admin, security_manager,
       dept_infra, dept_dev, dept_sales;

-- 감사자는 읽을 수 있어야 함 (analyst/admin/manager 는 rbac.sql 에서 SELECT 보유, 유지)
GRANT SELECT ON audit_log TO security_admin, security_manager, security_analyst;

-- ---------------------------------------------------------
-- (1b) 변경 차단 트리거 (소유자 포함)
-- ---------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_audit_log_block_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    -- 보존정책 함수가 SET LOCAL 로 켠 경우에만 통과
    IF current_setting('audit_log.maintenance', true) = 'on' THEN
        IF TG_OP = 'DELETE' THEN
            RETURN OLD;
        END IF;
        RETURN NULL; -- TRUNCATE(문 단위)
    END IF;

    RAISE EXCEPTION 'audit_log 는 append-only 입니다: % 불가 (보존정책 함수만 예외)', TG_OP
        USING ERRCODE = 'insufficient_privilege';
END;
$$;

DROP TRIGGER IF EXISTS trg_audit_log_no_update ON audit_log;
CREATE TRIGGER trg_audit_log_no_update
    BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION fn_audit_log_block_mutation();

DROP TRIGGER IF EXISTS trg_audit_log_no_truncate ON audit_log;
CREATE TRIGGER trg_audit_log_no_truncate
    BEFORE TRUNCATE ON audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION fn_audit_log_block_mutation();

-- ---------------------------------------------------------
-- (2a) 아카이브 테이블
-- ---------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_log_archive (
    LIKE audit_log INCLUDING DEFAULTS INCLUDING COMMENTS,
    archived_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
COMMENT ON TABLE audit_log_archive IS 'audit_log 보존기간 경과분 이관 보관소 (fn_archive_audit_log 가 채움)';

REVOKE ALL ON audit_log_archive FROM PUBLIC, security_analyst,
       dept_infra, dept_dev, dept_sales;
REVOKE UPDATE, DELETE, TRUNCATE ON audit_log_archive FROM security_admin, security_manager;
GRANT SELECT ON audit_log_archive TO security_admin, security_manager;

-- ---------------------------------------------------------
-- (2b) 보존정책 함수
-- ---------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_archive_audit_log(p_retention interval DEFAULT interval '1 year')
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_cutoff timestamptz := now() - p_retention;
    v_moved  bigint;
BEGIN
    -- 변경 차단 트리거를 이 트랜잭션에 한해 예외 처리
    PERFORM set_config('audit_log.maintenance', 'on', true);  -- true = SET LOCAL

    WITH cte AS (
        DELETE FROM audit_log
        WHERE changed_at < v_cutoff
        RETURNING audit_id, table_name, row_pk, operation, old_data, new_data, changed_by, changed_at
    )
    INSERT INTO audit_log_archive
        (audit_id, table_name, row_pk, operation, old_data, new_data, changed_by, changed_at)
    SELECT audit_id, table_name, row_pk, operation, old_data, new_data, changed_by, changed_at
    FROM cte;

    GET DIAGNOSTICS v_moved = ROW_COUNT;
    RETURN v_moved;
END;
$$;

COMMENT ON FUNCTION fn_archive_audit_log(interval) IS
    'changed_at 이 p_retention(기본 1년) 보다 오래된 audit_log 행을 audit_log_archive 로 이관하고 이관 건수를 반환';

COMMIT;

-- @migrate:verify  (이 아래는 검증 절: ON_ERROR_STOP=0, 마이그레이션 성공 여부와 무관. \! 서브셸/의도적 타임아웃 포함)

-- =========================================================
-- 보존정책 정기 실행 방법 (실제 실행은 여기서 하지 않음)
-- =========================================================
--  A) DB 내부 스케줄러(pg_cron 확장 설치 시):
--       CREATE EXTENSION IF NOT EXISTS pg_cron;
--       -- 매일 03:10 에 1년 경과 로그 이관
--       SELECT cron.schedule('audit-log-retention', '10 3 * * *',
--                            $$SELECT fn_archive_audit_log(interval '1 year')$$);
--
--  B) OS 크론 + psql (pg_cron 미사용 시):
--       10 3 * * *  psql -d security_db -c "SELECT fn_archive_audit_log(interval '1 year');"
--
--  C) 수동 1회 실행:
--       SELECT fn_archive_audit_log();                    -- 기본 1년
--       SELECT fn_archive_audit_log(interval '6 months'); -- 보존기간 지정
-- =========================================================

-- =========================================================
-- 테스트
-- =========================================================
\echo ''
\echo '################ audit_log 현재 권한 (INSERT/SELECT 만 남아야 함) ################'
SELECT grantee, string_agg(privilege_type, ', ' ORDER BY privilege_type) AS privileges
FROM information_schema.role_table_grants
WHERE table_name='audit_log' AND grantee <> 'summer'
GROUP BY grantee ORDER BY grantee;

\echo ''
\echo '################ 감사 로그 시드(트리거 경유) : responses 1건 UPDATE 후 원복 ################'
UPDATE responses SET status='COMPLETED'   WHERE response_id=2;
UPDATE responses SET status='IN_PROGRESS' WHERE response_id=2;
SELECT count(*) AS audit_rows FROM audit_log;

\echo ''
\echo '################ [테스트] security_admin 이 audit_log UPDATE 시도 -> 거부 기대 ################'
\! psql -d security_db -U security_admin -c "UPDATE audit_log SET changed_by='tampered' WHERE audit_id=1;" 2>&1

\echo ''
\echo '################ [테스트] security_analyst 가 audit_log DELETE 시도 -> 거부 기대 ################'
\! psql -d security_db -U security_analyst -c "DELETE FROM audit_log WHERE audit_id=1;" 2>&1

\echo ''
\echo '################ [테스트] security_manager 가 audit_log TRUNCATE 시도 -> 거부 기대 ################'
\! psql -d security_db -U security_manager -c "TRUNCATE audit_log;" 2>&1

\echo ''
\echo '################ [테스트] 소유자(summer) 가 audit_log UPDATE 시도 -> 트리거가 차단 기대 ################'
DO $$
BEGIN
    BEGIN
        UPDATE audit_log SET changed_by='owner-tamper' WHERE audit_id=1;
        RAISE NOTICE '[FAIL] 소유자 UPDATE 가 통과함 (예상: 트리거 차단).';
    EXCEPTION WHEN insufficient_privilege THEN
        RAISE NOTICE '[OK] 소유자 UPDATE 도 불변성 트리거로 차단됨.';
    END;
END $$;

\echo ''
\echo '################ [테스트] 보존정책 함수 실행 (100년 기준 -> 이관 0건, 무해) ################'
SELECT fn_archive_audit_log(interval '100 years') AS rows_archived;
SELECT count(*) AS audit_log_rows, (SELECT count(*) FROM audit_log_archive) AS archive_rows FROM audit_log;

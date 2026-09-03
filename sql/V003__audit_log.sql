-- =========================================================
-- 고도화 기능 1) 감사 로그 (audit_log)
--   security_events, responses 테이블의 INSERT/UPDATE/DELETE를
--   트리거로 자동 포착하여 audit_log에 변경 전/후 값(JSONB)까지 기록한다.
--
-- 실행 전제: security_db_starter.sql 이 먼저 적용되어 있어야 함
-- 기존 스키마/데이터는 건드리지 않고 새 객체(테이블/함수/트리거)만 추가한다.
-- 재실행 안전(idempotent): CREATE ... IF NOT EXISTS / OR REPLACE / DROP TRIGGER IF EXISTS
-- =========================================================

BEGIN;

-- -----------------------------
-- 1) 감사 로그 테이블
-- -----------------------------
CREATE TABLE IF NOT EXISTS audit_log (
    audit_id    BIGSERIAL PRIMARY KEY,
    table_name  TEXT        NOT NULL,                 -- 대상 테이블
    row_pk      TEXT,                                 -- 대상 행의 기본키(텍스트 표현)
    operation   TEXT        NOT NULL
                CHECK (operation IN ('INSERT', 'UPDATE', 'DELETE')),
    old_data    JSONB,                                -- 변경 전 전체 행 (INSERT면 NULL)
    new_data    JSONB,                                -- 변경 후 전체 행 (DELETE면 NULL)
    changed_by  TEXT        NOT NULL DEFAULT session_user,   -- 작업 수행 DB 로그인 계정
    changed_at  TIMESTAMPTZ NOT NULL DEFAULT now()            -- 변경 시각
);

COMMENT ON TABLE  audit_log IS 'security_events / responses 변경 감사 로그 (트리거 자동 기록)';
COMMENT ON COLUMN audit_log.old_data IS '변경 전 행 스냅샷(JSONB). INSERT의 경우 NULL';
COMMENT ON COLUMN audit_log.new_data IS '변경 후 행 스냅샷(JSONB). DELETE의 경우 NULL';

CREATE INDEX IF NOT EXISTS idx_audit_log_table_time
    ON audit_log (table_name, changed_at DESC);

-- -----------------------------
-- 2) 공용 트리거 함수 (PL/pgSQL)
--    대상 테이블에 관계없이 동작하도록 TG_* 메타변수를 사용한다.
--
--    SECURITY DEFINER 로 선언한다: 감사 대상 테이블(responses 등)에 쓰기 권한만
--    가진 낮은 권한 role 이 DML 을 실행해도, 트리거가 audit_log 에 기록할 수 있어야
--    하기 때문이다. audit_log 자체에는 INSERT 권한을 아무에게도 주지 않아
--    (감사 레코드 위조 방지) 트리거 경로로만 기록되도록 한다.
--    search_path 를 고정해 SECURITY DEFINER 함수의 이름 하이재킹을 예방한다.
-- -----------------------------
CREATE OR REPLACE FUNCTION fn_audit_row_change()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_row_pk TEXT;
    v_old    JSONB := NULL;
    v_new    JSONB := NULL;
BEGIN
    IF (TG_OP = 'DELETE') THEN
        v_old := to_jsonb(OLD);
    ELSIF (TG_OP = 'INSERT') THEN
        v_new := to_jsonb(NEW);
    ELSE  -- UPDATE
        v_old := to_jsonb(OLD);
        v_new := to_jsonb(NEW);
    END IF;

    -- 대상 테이블별 기본키 추출
    v_row_pk := CASE TG_TABLE_NAME
        WHEN 'security_events' THEN COALESCE(v_new ->> 'event_id',    v_old ->> 'event_id')
        WHEN 'responses'       THEN COALESCE(v_new ->> 'response_id', v_old ->> 'response_id')
        ELSE NULL
    END;

    -- SECURITY DEFINER 이므로 current_user 는 함수 소유자로 바뀐다.
    -- 실제 작업자를 남기기 위해 session_user(원 로그인 role)를 명시적으로 기록한다.
    INSERT INTO audit_log (table_name, row_pk, operation, old_data, new_data, changed_by)
    VALUES (TG_TABLE_NAME, v_row_pk, TG_OP, v_old, v_new, session_user);

    -- AFTER 트리거이므로 반환값은 무시되지만 관례상 채워준다.
    IF (TG_OP = 'DELETE') THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION fn_audit_row_change() IS 'security_events/responses 공용 감사 트리거 함수';

-- -----------------------------
-- 3) 트리거 부착 (행 단위, AFTER)
-- -----------------------------
DROP TRIGGER IF EXISTS trg_audit_security_events ON security_events;
CREATE TRIGGER trg_audit_security_events
    AFTER INSERT OR UPDATE OR DELETE ON security_events
    FOR EACH ROW EXECUTE FUNCTION fn_audit_row_change();

DROP TRIGGER IF EXISTS trg_audit_responses ON responses;
CREATE TRIGGER trg_audit_responses
    AFTER INSERT OR UPDATE OR DELETE ON responses
    FOR EACH ROW EXECUTE FUNCTION fn_audit_row_change();

COMMIT;

-- =========================================================
-- 4) 동작 테스트
--    responses.response_id = 2 의 status 를 잠깐 바꿨다가 원복한다.
--    (기존 데이터는 테스트 종료 시점에 원래 값으로 복구된다.)
-- =========================================================
-- 테스트 출력을 결정적으로 만들기 위해 로그를 비우고 시작(감사 로그는 신규 테이블이라 안전)
TRUNCATE audit_log RESTART IDENTITY;

\echo '--- [TEST] responses 행 UPDATE 전/후 ---'
UPDATE responses SET status = 'COMPLETED'   WHERE response_id = 2;
UPDATE responses SET status = 'IN_PROGRESS' WHERE response_id = 2;   -- 원복

\echo '--- [TEST] audit_log 기록 확인 (responses 관련) ---'
SELECT audit_id, table_name, row_pk, operation, changed_by, changed_at,
       old_data ->> 'status' AS old_status,
       new_data ->> 'status' AS new_status
FROM audit_log
WHERE table_name = 'responses'
ORDER BY audit_id;

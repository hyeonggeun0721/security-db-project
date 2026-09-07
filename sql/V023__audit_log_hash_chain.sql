-- =========================================================
-- 보안 강화 4) 감사 로그 위변조 탐지 - 해시 체인 (audit_log_hash_chain.sql)
--
--   기존 한계: audit_log 불변성은 트리거(fn_audit_log_block_mutation)로 지키지만,
--   슈퍼유저가 session_replication_role='replica' 로 트리거를 끄면 조용히 조작 가능
--   → "막지는 못해도 탐지는 한다"를 추가한다.
--
--   방식(블록체인식 해시 체인):
--     각 행 삽입 시  row_hash = sha256( prev_hash || '|' || <이번 행 내용> )
--     - prev_hash  = 직전(audit_id 최대) 행의 row_hash. 첫 행은 genesis(64*'0').
--     - <이번 행 내용> = table_name|row_pk|operation|old_data|new_data|changed_by|changed_at
--       (audit_id 는 INSERT 전에 알 수 없어 해시 입력에서 제외. 순서 무결성은 prev_hash 링크로 보장)
--     - sha256() 는 PG11+ 내장(bytea 반환). 별도 확장 불필요.
--
--   구성:
--     1) audit_log 에 prev_hash / row_hash 컬럼 추가
--     2) fn_audit_row_change() 를 "해시를 채워 INSERT" 하도록 수정
--        (SECURITY DEFINER + search_path 고정 유지)
--     3) 기존 행 소급 백필(audit_id 순서대로)
--     4) fn_verify_audit_chain() : audit_id 순회하며 prev_hash 링크와 row_hash 재계산 검증,
--        깨진 지점을 행으로 반환(정상이면 0행)
--
--   동시성 주의: 두 트랜잭션이 동시에 audit_log 에 INSERT 하면 같은 prev_hash 를 읽어
--   체인이 분기할 수 있다. 로컬 단일 사용자 검증 환경 전제. 운영에서는 전용
--   시퀀스 테이블 + advisory lock 으로 직렬화해야 한다.
--
--   재실행 안전: ADD COLUMN IF NOT EXISTS / CREATE OR REPLACE / 백필은 이미 채워졌으면 동일값 재기록.
--   ※ 불변성 트리거 fn_audit_log_block_mutation 는 maintenance='on' 이어도 UPDATE 를
--     RETURN NULL(행 스킵)로 처리한다(원래 DELETE/TRUNCATE 전용 우회구). 따라서 백필 UPDATE 는
--     트랜잭션 안에서 트리거를 잠깐 DISABLE 했다가 ENABLE 한다(ALTER TABLE 은 트랜잭션 롤백 대상).
-- =========================================================

BEGIN;

-- ---------------------------------------------------------
-- 1) 컬럼 추가
-- ---------------------------------------------------------
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS prev_hash TEXT;
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS row_hash  TEXT;

COMMENT ON COLUMN audit_log.prev_hash IS '직전 행(audit_id 최대)의 row_hash. 첫 행은 genesis(64자 0).';
COMMENT ON COLUMN audit_log.row_hash  IS 'sha256(prev_hash || 이번 행 내용). 해시 체인 위변조 탐지용.';

-- ---------------------------------------------------------
-- 2) 트리거 함수 수정 (해시 채워 INSERT)
-- ---------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_audit_row_change()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
    v_row_pk     TEXT;
    v_old        JSONB := NULL;
    v_new        JSONB := NULL;
    v_changed_at TIMESTAMPTZ := now();   -- 원본 DEFAULT now() 의미 유지
    v_actor      TEXT := session_user;
    v_prev       TEXT;
    v_hash       TEXT;
BEGIN
    IF (TG_OP = 'DELETE') THEN
        v_old := to_jsonb(OLD);
    ELSIF (TG_OP = 'INSERT') THEN
        v_new := to_jsonb(NEW);
    ELSE  -- UPDATE
        v_old := to_jsonb(OLD);
        v_new := to_jsonb(NEW);
    END IF;

    v_row_pk := CASE TG_TABLE_NAME
        WHEN 'security_events' THEN COALESCE(v_new ->> 'event_id',    v_old ->> 'event_id')
        WHEN 'responses'       THEN COALESCE(v_new ->> 'response_id', v_old ->> 'response_id')
        ELSE NULL
    END;

    -- 직전 행의 row_hash (없으면 genesis)
    SELECT row_hash INTO v_prev FROM audit_log ORDER BY audit_id DESC LIMIT 1;
    v_prev := COALESCE(v_prev, repeat('0', 64));

    v_hash := encode(sha256(convert_to(
          v_prev
       || '|' || TG_TABLE_NAME
       || '|' || COALESCE(v_row_pk, '')
       || '|' || TG_OP
       || '|' || COALESCE(v_old::text, '')
       || '|' || COALESCE(v_new::text, '')
       || '|' || v_actor
       || '|' || v_changed_at::text
       , 'UTF8')), 'hex');

    INSERT INTO audit_log (table_name, row_pk, operation, old_data, new_data,
                           changed_by, changed_at, prev_hash, row_hash)
    VALUES (TG_TABLE_NAME, v_row_pk, TG_OP, v_old, v_new,
            v_actor, v_changed_at, v_prev, v_hash);

    IF (TG_OP = 'DELETE') THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION fn_audit_row_change() IS
    'security_events/responses 공용 감사 트리거. SECURITY DEFINER + search_path 고정. 각 행에 해시 체인(prev_hash/row_hash) 기록.';

-- ---------------------------------------------------------
-- 3) 기존 행 소급 백필 (audit_id 오름차순)
--    불변성 트리거를 이 트랜잭션 동안만 비활성화 (실패 시 ROLLBACK 으로 원복)
-- ---------------------------------------------------------
ALTER TABLE audit_log DISABLE TRIGGER trg_audit_log_no_update;

DO $$
DECLARE
    r     RECORD;
    v_prev TEXT := repeat('0', 64);
    v_hash TEXT;
BEGIN
    FOR r IN SELECT * FROM audit_log ORDER BY audit_id LOOP
        v_hash := encode(sha256(convert_to(
              v_prev
           || '|' || r.table_name
           || '|' || COALESCE(r.row_pk, '')
           || '|' || r.operation
           || '|' || COALESCE(r.old_data::text, '')
           || '|' || COALESCE(r.new_data::text, '')
           || '|' || r.changed_by
           || '|' || r.changed_at::text
           , 'UTF8')), 'hex');
        UPDATE audit_log SET prev_hash = v_prev, row_hash = v_hash WHERE audit_id = r.audit_id;
        v_prev := v_hash;
    END LOOP;
END $$;

ALTER TABLE audit_log ENABLE TRIGGER trg_audit_log_no_update;

-- ---------------------------------------------------------
-- 4) 체인 검증 함수
-- ---------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_verify_audit_chain()
RETURNS TABLE(audit_id bigint, problem text, expected_hash text, stored_hash text)
LANGUAGE plpgsql
STABLE
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
    r      RECORD;
    v_prev TEXT := repeat('0', 64);   -- genesis
    v_calc TEXT;
BEGIN
    FOR r IN SELECT * FROM audit_log ORDER BY audit_id LOOP
        v_calc := encode(sha256(convert_to(
              v_prev
           || '|' || r.table_name
           || '|' || COALESCE(r.row_pk, '')
           || '|' || r.operation
           || '|' || COALESCE(r.old_data::text, '')
           || '|' || COALESCE(r.new_data::text, '')
           || '|' || r.changed_by
           || '|' || r.changed_at::text
           , 'UTF8')), 'hex');

        IF r.prev_hash IS DISTINCT FROM v_prev THEN
            audit_id := r.audit_id;
            problem  := 'prev_hash 링크 끊김 (직전 행이 삭제/삽입/재정렬됨)';
            expected_hash := v_prev; stored_hash := r.prev_hash;
            RETURN NEXT;
        END IF;

        IF r.row_hash IS DISTINCT FROM v_calc THEN
            audit_id := r.audit_id;
            problem  := 'row_hash 불일치 (이 행 내용이 조작됨)';
            expected_hash := v_calc; stored_hash := r.row_hash;
            RETURN NEXT;
        END IF;

        -- 다음 반복의 prev 비교 기준은 "저장된" row_hash (조작 지점을 정확히 1행으로 국한)
        v_prev := r.row_hash;
    END LOOP;
END $$;

COMMENT ON FUNCTION fn_verify_audit_chain() IS
    'audit_log 해시 체인 무결성 검증. 조작/삭제/삽입된 지점을 행으로 반환. 0행이면 무결.';

-- 새 함수는 기본으로 PUBLIC EXECUTE 를 받으므로(ALTER DEFAULT PRIVILEGES 로도 잘 안 막힘)
-- function_privilege_hardening.sql 과 동일하게 명시적으로 회수 후 필요한 role 에만 부여
REVOKE EXECUTE ON FUNCTION fn_verify_audit_chain() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION fn_verify_audit_chain() TO security_admin, security_manager, security_analyst;

COMMIT;

-- =========================================================
-- 검증
-- =========================================================
\echo ''
\echo '################ 백필 결과 (모든 행에 해시가 채워졌는지) ################'
SELECT count(*) AS total_rows,
       count(prev_hash) AS with_prev_hash,
       count(row_hash)  AS with_row_hash
FROM audit_log;

\echo ''
\echo '################ 체인 앞부분 미리보기 ################'
SELECT audit_id, table_name, operation, left(prev_hash,12)||'…' AS prev_hash, left(row_hash,12)||'…' AS row_hash
FROM audit_log ORDER BY audit_id LIMIT 6;

\echo ''
\echo '################ [TEST 1] 무결 상태 검증 -> 0행 이어야 함 ################'
SELECT * FROM fn_verify_audit_chain();
SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM fn_verify_audit_chain())
            THEN '[OK] 체인 무결 (깨진 지점 없음)'
            ELSE '[FAIL] 초기 상태인데 불일치가 보고됨' END AS result;

\echo ''
\echo '################ [TEST 2] 한 행을 강제 조작(BEGIN..ROLLBACK) -> 정확히 그 지점을 잡는지 ################'
BEGIN;
  ALTER TABLE audit_log DISABLE TRIGGER trg_audit_log_no_update;   -- 슈퍼유저 조작 시뮬레이션
  -- 중간 지점 하나 고른다: audit_id 오름차순 3번째 행
  UPDATE audit_log
     SET changed_by = 'ATTACKER'
   WHERE audit_id = (SELECT audit_id FROM audit_log ORDER BY audit_id OFFSET 2 LIMIT 1);
  \echo '  -- 조작 후 검증 결과 (조작 행에 row_hash 불일치가 떠야 함) --'
  SELECT * FROM fn_verify_audit_chain();
ROLLBACK;   -- ALTER TABLE(트리거 재활성) + UPDATE 모두 원복

\echo ''
\echo '################ [TEST 3] ROLLBACK 후 재검증 -> 다시 0행 ################'
SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM fn_verify_audit_chain())
            THEN '[OK] 원상복구 확인, 체인 다시 무결'
            ELSE '[FAIL] 롤백 후에도 불일치' END AS result;

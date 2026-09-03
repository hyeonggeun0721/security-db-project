-- =========================================================
-- 보완 2) 트랜잭션 처리 예제 (transaction_example.sql)
--
--   시나리오: "보안 이벤트 대응"
--     - responses 에 대응 기록을 INSERT 하면서
--     - 동시에 해당 security_events.status 를 갱신하는 두 쓰기를
--     - 하나의 트랜잭션(BEGIN ~ COMMIT)으로 원자적으로 처리한다.
--
--   포함 내용:
--     A. 정상 커밋 예제 (두 변경이 함께 반영됨)
--     B. 실패/롤백 예제 (중간에 FK 위반 → 트랜잭션 전체가 취소되어
--        앞선 INSERT/UPDATE 도 남지 않음)
--
--   ※ 이 파일은 데모용이라, A 에서 넣은 데이터는 마지막에 원상복구한다
--     (재실행 가능하도록). 실제 운영에서는 복구 블록 없이 그대로 커밋하면 된다.
--   ※ B 는 의도적으로 에러를 발생시키므로 psql 을 ON_ERROR_STOP 없이 실행할 것:
--        psql -d security_db -f transaction_example.sql
--
-- ---------------------------------------------------------
-- 격리수준(isolation level)에 대한 메모
-- ---------------------------------------------------------
--   PostgreSQL 기본값은 READ COMMITTED 이다. 각 SQL 문은 "그 문이 시작된 시점"에
--   커밋된 데이터만 본다(더티 리드 없음). 이 대응 워크플로우는
--     - 특정 PK 한 건에 대한 INSERT 1회 + UPDATE 1회로 끝나는 짧은 원자적 쓰기이고,
--     - 트랜잭션 안에서 같은 데이터를 반복 조회해 그 사이 불변을 가정하지 않으며,
--     - 집계 결과의 팬텀/재현성에 의존하지 않는다.
--   따라서 READ COMMITTED 로 충분하다. 원자성(둘 다 반영 or 둘 다 취소)은
--   격리수준이 아니라 트랜잭션 경계(BEGIN/COMMIT/ROLLBACK)가 보장한다.
--
--   더 강한 수준이 필요한 경우(참고):
--     - REPEATABLE READ : 한 트랜잭션에서 같은 행/집계를 여러 번 읽고 그 값이
--       끝까지 변하지 않아야 할 때(예: 리포트 스냅샷).
--     - SERIALIZABLE    : 읽은 값을 근거로 쓰기를 결정하는 로직이 동시 실행돼도
--       "직렬로 하나씩 실행한 것과 동일"함을 보장해야 할 때(예: 잔여 한도 검사 후 차감).
-- =========================================================

-- @migrate:verify
-- 이 파일은 스키마 변경이 없는 "트랜잭션 데모"다. 전체가 검증 절(ON_ERROR_STOP=0)로 실행되며
-- B 절이 의도적으로 FK 위반 ERROR 를 낸다. migrate.py 는 이 파일을 "적용 성공"으로 기록한다
-- (DDL 이 없으므로 항상 안전, 데이터도 자체 복구).

-- #########################################################
-- A. 정상 커밋 예제
-- #########################################################
\echo ''
\echo '=== [A] 커밋 전 상태: event_id=22 (asset 8, 결제API서버) ==='
SELECT event_id, event_type, status FROM security_events WHERE event_id = 22;
SELECT count(*) AS responses_before FROM responses;

BEGIN;
    -- (기본 격리수준을 명시적으로 확인)
    SHOW transaction_isolation;

    -- 1) 대응 기록 추가
    INSERT INTO responses (event_id, staff_id, action_taken, status)
    VALUES (22, 4, '[TX데모] 결제API서버 비정상접근 대응: 세션 차단 및 로그 확보', 'COMPLETED');

    -- 2) 같은 트랜잭션에서 이벤트 상태를 RESOLVED 로 전이
    UPDATE security_events
    SET status = 'RESOLVED'
    WHERE event_id = 22;
COMMIT;

\echo ''
\echo '=== [A] 커밋 후 상태: 두 변경이 함께 반영됨 ==='
SELECT event_id, event_type, status FROM security_events WHERE event_id = 22;
SELECT response_id, event_id, staff_id, status, action_taken
FROM responses WHERE action_taken LIKE '[TX데모]%';

-- --- (데모용 원상복구: 재실행 가능하도록 A 의 변경을 되돌린다) ---
BEGIN;
    DELETE FROM responses WHERE action_taken LIKE '[TX데모]%';
    UPDATE security_events SET status = 'OPEN' WHERE event_id = 22;
COMMIT;
\echo '--- [A] 데모 원상복구 완료 (event 22 -> OPEN, TX데모 response 삭제) ---'


-- #########################################################
-- B. 실패 → 전체 롤백 예제
--    유효한 INSERT/UPDATE 를 먼저 실행한 뒤,
--    존재하지 않는 staff_id(999) 로 INSERT 하여 FK 위반을 유도한다.
-- #########################################################
\echo ''
\echo '=== [B] 롤백 전 상태: event_id=27 (asset 2, 사내DB서버) ==='
SELECT event_id, event_type, status FROM security_events WHERE event_id = 27;
SELECT count(*) AS responses_before FROM responses;

BEGIN;
    -- 1) 유효한 대응 기록 (아직 커밋 전)
    INSERT INTO responses (event_id, staff_id, action_taken, status)
    VALUES (27, 2, '[TX실패데모] 사내DB서버 권한상승 시도 대응 착수', 'IN_PROGRESS');

    -- 2) 유효한 이벤트 상태 전이 (아직 커밋 전)
    UPDATE security_events
    SET status = 'IN_PROGRESS'
    WHERE event_id = 27;

    -- 3) 의도적 오류: staff_id=999 는 staff 테이블에 없음 → responses_staff_id_fkey 위반
    INSERT INTO responses (event_id, staff_id, action_taken, status)
    VALUES (27, 999, '[TX실패데모] 존재하지 않는 담당자', 'IN_PROGRESS');

    -- 여기에 도달하기 전에 위 문장이 에러를 냈고, 트랜잭션은 aborted 상태가 된다.
    UPDATE security_events SET status = 'RESOLVED' WHERE event_id = 27;  -- 실행 안 됨
ROLLBACK;

\echo ''
\echo '=== [B] 롤백 후 상태: 앞선 INSERT/UPDATE 도 전혀 남지 않음 ==='
SELECT event_id, event_type, status FROM security_events WHERE event_id = 27;   -- 여전히 OPEN
SELECT count(*) AS responses_after FROM responses;                              -- 변화 없음
SELECT count(*) AS tx_fail_rows FROM responses WHERE action_taken LIKE '[TX실패데모]%';  -- 0

\echo ''
\echo '=== 최종: 데이터 건수 원상 확인 (responses 18, security_events 30) ==='
SELECT (SELECT count(*) FROM responses) AS responses,
       (SELECT count(*) FROM security_events) AS security_events;

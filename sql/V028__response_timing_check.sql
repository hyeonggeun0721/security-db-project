-- =========================================================
-- V028) 테이블 간 시간 논리 제약: responses.action_date >= 연결 이벤트의 detected_at
--
--   대응 기록 시각이 그 사건의 탐지 시각보다 이를 수 없다.
--   CHECK 는 다른 테이블을 못 보므로 BEFORE INSERT OR UPDATE 트리거로 강제한다.
--     fn_validate_response_timing() : NEW.event_id 의 detected_at 을 조회,
--       NEW.action_date < detected_at 이면 예외.
--     trg_responses_time_check      : responses 에 부착.
--
--   함수는 SECURITY DEFINER + search_path 고정(V021 방침). 이벤트 조회가 RLS 를
--   타지 않아야 검증이 일관된다(대응은 analyst/admin 만 쓰지만 방어적으로).
--   트리거 전용이므로 EXECUTE 는 PUBLIC 에서 회수만 하고 재부여하지 않는다(V022 방침).
--
--   재실행 안전: 함수 OR REPLACE, 트리거 DROP IF EXISTS 후 CREATE.
-- =========================================================

BEGIN;

CREATE OR REPLACE FUNCTION fn_validate_response_timing()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
    v_detected_at TIMESTAMPTZ;
BEGIN
    SELECT detected_at INTO v_detected_at
    FROM security_events
    WHERE event_id = NEW.event_id;

    IF v_detected_at IS NULL THEN
        -- event_id FK 가 보장하므로 정상적으로는 도달 불가
        RAISE EXCEPTION 'responses.event_id=% 에 해당하는 security_events 가 없습니다', NEW.event_id
            USING ERRCODE = 'foreign_key_violation';
    END IF;

    IF NEW.action_date < v_detected_at THEN
        RAISE EXCEPTION
          '대응 시각(action_date=%)이 사건 탐지 시각(detected_at=%)보다 앞설 수 없습니다 (event_id=%)',
          NEW.action_date, v_detected_at, NEW.event_id
          USING ERRCODE = 'check_violation';
    END IF;

    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION fn_validate_response_timing() IS
    'responses BEFORE INSERT/UPDATE: action_date 가 연결 이벤트 detected_at 보다 이르면 거부. SECURITY DEFINER + search_path 고정.';

REVOKE EXECUTE ON FUNCTION fn_validate_response_timing() FROM PUBLIC;

DROP TRIGGER IF EXISTS trg_responses_time_check ON responses;
CREATE TRIGGER trg_responses_time_check
    BEFORE INSERT OR UPDATE ON responses
    FOR EACH ROW EXECUTE FUNCTION fn_validate_response_timing();

COMMIT;

-- @migrate:verify
-- =========================================================
-- 검증
-- =========================================================
\echo ''
\echo '################ 기존 responses 는 전부 규칙을 만족하는가 (위반 0 기대) ################'
SELECT count(*) AS existing_violations
FROM responses r JOIN security_events e ON e.event_id = r.event_id
WHERE r.action_date < e.detected_at;

\echo ''
\echo '################ [TEST] 과거로 조작한 action_date 로 INSERT -> 거부 기대 ################'
-- event_id=22 의 detected_at 은 2025-08-14 03:55(+09). 그보다 이른 값으로 시도.
BEGIN;
  INSERT INTO responses (event_id, staff_id, action_taken, action_date)
  VALUES (22, 1, '[V028 TEST] 탐지보다 이른 대응', TIMESTAMPTZ '2025-08-14 01:00:00+09');
ROLLBACK;
\echo '   (위에 check_violation ERROR 가 떠야 정상. ROLLBACK 완료)'

\echo ''
\echo '################ [TEST] 정상 action_date (탐지 이후) 로 INSERT -> 통과 기대 ################'
BEGIN;
  INSERT INTO responses (event_id, staff_id, action_taken, action_date)
  VALUES (22, 1, '[V028 TEST] 정상 시각 대응', TIMESTAMPTZ '2025-08-14 05:00:00+09')
  RETURNING response_id, event_id, action_date;
ROLLBACK;
\echo '   (INSERT 1 후 ROLLBACK - 원상)'

\echo ''
\echo '################ [TEST] UPDATE 로 action_date 를 과거로 -> 거부 기대 ################'
BEGIN;
  UPDATE responses SET action_date = TIMESTAMPTZ '2020-01-01 00:00:00+09'
  WHERE response_id = (SELECT min(response_id) FROM responses);
ROLLBACK;
\echo '   (위에 check_violation ERROR 가 떠야 정상. ROLLBACK 완료)'

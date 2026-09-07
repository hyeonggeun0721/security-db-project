-- =========================================================
-- V032) 알림 발송 이력 / 중복 알림 방지 (alert_log)
--
-- 실시간 알림 파이프라인(scripts/alert_poller.py)이 "이미 알림 보낸 것"을 추적한다.
-- 왜 별도 테이블인가:
--   - security_events 에 alerted_at 컬럼을 추가하면, 알림 표시를 위한 UPDATE 가
--     감사 트리거(fn_audit_row_change)를 발화시켜 audit_log/해시체인에 잡음을 남긴다.
--   - alert_log 는 security_events 를 안 건드리고, 두 소스(CRITICAL 이벤트 / 감사체인 ALERT)를
--     한 테이블에서 dedup 한다.
--   - (alert_type, ref_key) UNIQUE + INSERT..ON CONFLICT DO NOTHING RETURNING 으로
--     "새 알림인지" 판정을 원자적으로 처리 → 폴링이 겹쳐 돌아도 중복 발송 없음.
--
-- 재실행 안전: 테이블/인덱스 IF NOT EXISTS.
-- =========================================================

BEGIN;

CREATE TABLE IF NOT EXISTS alert_log (
    alert_id     BIGSERIAL PRIMARY KEY,
    alert_type   TEXT NOT NULL CHECK (alert_type IN ('CRITICAL_EVENT', 'AUDIT_CHAIN')),
    ref_key      TEXT NOT NULL,                 -- CRITICAL_EVENT: event_id, AUDIT_CHAIN: 손상 지문
    severity     TEXT,
    summary      TEXT NOT NULL,
    channels     TEXT[]        NOT NULL DEFAULT '{}',   -- 실제 발송된 채널
    is_synthetic BOOLEAN       NOT NULL DEFAULT false,  -- [SIM] 이벤트 유래인지
    payload      JSONB,
    created_at   TIMESTAMPTZ   NOT NULL DEFAULT now(),
    CONSTRAINT uq_alert_log_dedup UNIQUE (alert_type, ref_key)
);

COMMENT ON TABLE alert_log IS
    '알림 발송 이력 + 중복 방지. (alert_type, ref_key) 가 이미 있으면 재발송 안 함.';
COMMENT ON COLUMN alert_log.ref_key IS
    'CRITICAL_EVENT=security_events.event_id, AUDIT_CHAIN=db명:breaks:깨진audit_id들 지문';

CREATE INDEX IF NOT EXISTS idx_alert_log_created  ON alert_log (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alert_log_type     ON alert_log (alert_type, created_at DESC);

REVOKE ALL ON alert_log FROM PUBLIC;
GRANT SELECT ON alert_log TO security_analyst, security_admin, security_manager;
GRANT SELECT, INSERT ON alert_log TO security_admin;
GRANT USAGE, SELECT ON SEQUENCE alert_log_alert_id_seq TO security_admin;

COMMIT;

-- @migrate:verify
-- =========================================================
-- 검증
-- =========================================================
\echo ''
\echo '################ alert_log 스키마 ################'
\d alert_log

\echo ''
\echo '################ [TEST] 같은 (alert_type, ref_key) 두 번 INSERT -> 두 번째는 무시(dedup) ################'
BEGIN;
  INSERT INTO alert_log (alert_type, ref_key, summary) VALUES ('CRITICAL_EVENT', 'test-999', 'first')
  ON CONFLICT (alert_type, ref_key) DO NOTHING RETURNING alert_id;
  \echo '  (위: 1행 반환 = 신규)'
  INSERT INTO alert_log (alert_type, ref_key, summary) VALUES ('CRITICAL_EVENT', 'test-999', 'second')
  ON CONFLICT (alert_type, ref_key) DO NOTHING RETURNING alert_id;
  \echo '  (위: 0행 반환 = 중복, 재발송 안 함)'
  SELECT count(*) AS rows_for_test999 FROM alert_log WHERE ref_key='test-999';
ROLLBACK;
\echo '   (ROLLBACK - 원상)'

\echo ''
\echo '################ [TEST] 잘못된 alert_type -> CHECK 거부 ################'
BEGIN;
  INSERT INTO alert_log (alert_type, ref_key, summary) VALUES ('BOGUS', 'x', 's');
ROLLBACK;
\echo '   (위에 check_violation ERROR 가 떠야 정상)'

-- =========================================================
-- V039) FDS 경보 요약 알림 유형 (FDS_RUN_DIGEST)   [fds-integration 브랜치 전용]
--
--   문제: FDS 배치 채점 1회(run)에서 CRITICAL 이벤트가 수십 건 한꺼번에 생김
--         (run 2: 33건) → 이벤트마다 알림을 보내면 담당자에게 33번 연속 알림 = 알림 피로
--   해결: FDS 이벤트(FRAUD_SUSPECT)는 개별 알림 대상에서 빼고(alert_poller),
--         채점 실행(run) 1회당 요약 알림 1건만 보낸다.
--         개별 이벤트는 security_events 에 그대로 남고, 확인은 대시보드/대기열에서.
--
--   여기서는 alert_log 의 알림 유형 목록에 'FDS_RUN_DIGEST' 를 추가한다.
--     ref_key = fds.model_runs.run_id → (alert_type, ref_key) UNIQUE 로 실행당 1번만 발송
--   재실행 안전: 제약을 지우고 같은 이름으로 다시 만든다.
-- =========================================================

BEGIN;

ALTER TABLE alert_log DROP CONSTRAINT IF EXISTS alert_log_alert_type_check;
ALTER TABLE alert_log ADD CONSTRAINT alert_log_alert_type_check
    CHECK (alert_type IN ('CRITICAL_EVENT', 'AUDIT_CHAIN', 'FDS_RUN_DIGEST'));

COMMENT ON COLUMN alert_log.ref_key IS
    'CRITICAL_EVENT=security_events.event_id, AUDIT_CHAIN=db명:breaks:깨진audit_id들 지문, FDS_RUN_DIGEST=fds.model_runs.run_id';

COMMIT;

-- @migrate:verify
-- =========================================================
-- 검증 (BEGIN..ROLLBACK, 미영속)
-- =========================================================
\echo ''
\echo '################ alert_log 알림 유형 제약 ################'
SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname = 'alert_log_alert_type_check';

\echo ''
\echo '################ [TEST] FDS_RUN_DIGEST 기록 -> 정상, 같은 run 두 번 -> 중복으로 무시 ################'
BEGIN;
  INSERT INTO alert_log (alert_type, ref_key, severity, summary)
  VALUES ('FDS_RUN_DIGEST', 'verify-run', 'CRITICAL', '검증용 요약')
  ON CONFLICT (alert_type, ref_key) DO NOTHING;
  INSERT INTO alert_log (alert_type, ref_key, severity, summary)
  VALUES ('FDS_RUN_DIGEST', 'verify-run', 'CRITICAL', '검증용 요약(중복)')
  ON CONFLICT (alert_type, ref_key) DO NOTHING;
  \echo '   (INSERT 0 1 다음 INSERT 0 0 이면 성공)'
ROLLBACK;

\echo ''
\echo '################ [TEST] 목록에 없는 유형 -> CHECK 거부 기대 ################'
BEGIN;
  INSERT INTO alert_log (alert_type, ref_key, summary) VALUES ('UNKNOWN', 'x', 'x');
ROLLBACK;
\echo '   (위에 check constraint ERROR 가 떠야 정상)'

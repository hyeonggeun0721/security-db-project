-- =========================================================
-- V038) FDS(이상거래탐지) 경보 → 보안 이벤트 연동   [fds-integration 브랜치 전용]
--
--   FDS 프로젝트(~/fds)가 같은 DB의 fds 스키마에 저장한 '경보'를 보안 이벤트로 올리기 위한
--   과제 쪽 준비. 실제로 이벤트를 만드는 트리거는 FDS 저장소의 db/F003 이 담당한다.
--
--   1) event_types 에 'FRAUD_SUSPECT'(이상거래 의심) 추가
--   2) assets 에 '카드결제승인시스템'(APPLICATION, 중요도 5, 개발팀) 추가
--      → 보안 이벤트는 반드시 자산에 연결돼야 하므로(asset_id NOT NULL)
--   3) FDS 채점 계정 svc_fds_scorer 최소권한 (V029 svc_event_ingest 와 같은 원칙)
--      - security_events 에 INSERT 만 (SELECT 없음 = 순수 피더, id 는 nextval 로 미리 받음)
--      - RLS WITH CHECK: 유형 FRAUD_SUSPECT + 설명 '[FDS]' 접두사 + 결제 자산 — 셋 다 맞아야 통과
--        → 이 계정으로는 다른 종류의 보안 이벤트를 물리적으로 만들 수 없음
--      - 새 role 은 만들지 않는다(role 은 클러스터 전체 공유). svc_fds_scorer 는 FDS 의 F001 이 만든다.
--        role 이 없으면(예: FDS 없이 빈 DB 에서 재현) 3)은 건너뛰고 1)·2)만 적용
--
--   알림: 기존 alert_poller 가 severity='CRITICAL' 이벤트를 자동으로 알림 → 코드 변경 없음
--   재실행 안전: NOT EXISTS / DROP POLICY IF EXISTS
-- =========================================================

BEGIN;

-- 1) 이벤트 유형
INSERT INTO event_types (event_type_name, description)
SELECT 'FRAUD_SUSPECT', 'FDS(이상거래탐지) 모델 경보 — 카드 거래 사기 의심. 설명은 [FDS] 접두사'
WHERE NOT EXISTS (SELECT 1 FROM event_types WHERE event_type_name = 'FRAUD_SUSPECT');

-- 2) 결제 자산
INSERT INTO assets (asset_name, asset_type, department, importance_level)
SELECT '카드결제승인시스템', 'APPLICATION', '개발팀', 5
WHERE NOT EXISTS (SELECT 1 FROM assets WHERE asset_name = '카드결제승인시스템');

-- 3) svc_fds_scorer 권한 + RLS
DO $$
DECLARE
    v_asset integer;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'svc_fds_scorer') THEN
        RAISE NOTICE 'svc_fds_scorer role 없음 → FDS 연동 권한은 건너뜀 (FDS db/F001 을 먼저 적용한 DB 에서만 권한이 생김)';
        RETURN;
    END IF;

    SELECT asset_id INTO STRICT v_asset FROM assets WHERE asset_name = '카드결제승인시스템';

    GRANT USAGE ON SCHEMA public TO svc_fds_scorer;
    GRANT INSERT ON security_events TO svc_fds_scorer;
    GRANT USAGE ON SEQUENCE security_events_event_id_seq TO svc_fds_scorer;   -- nextval 용

    -- 정책의 자산 조건은 숫자로 박아 넣는다: 정책 안에서 assets 를 조회하면
    -- 채점 계정 권한으로 실행돼 assets RLS 에 막히기 때문
    EXECUTE 'DROP POLICY IF EXISTS p_events_svc_fds ON security_events';
    EXECUTE format($p$
        CREATE POLICY p_events_svc_fds ON security_events
            FOR INSERT
            TO svc_fds_scorer
            WITH CHECK (event_type = 'FRAUD_SUSPECT'
                        AND description LIKE '[FDS]%%'
                        AND asset_id = %s)$p$, v_asset);
END $$;

COMMIT;

-- @migrate:verify
-- =========================================================
-- 검증 (SET ROLE + BEGIN..ROLLBACK, 미영속)
-- =========================================================
\echo ''
\echo '################ FRAUD_SUSPECT 유형 / 결제 자산 ################'
SELECT event_type_name, is_active FROM event_types WHERE event_type_name = 'FRAUD_SUSPECT';
SELECT asset_id, asset_name, asset_type, department, importance_level FROM assets WHERE asset_name = '카드결제승인시스템';

SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'svc_fds_scorer') AS has_fds_role \gset
SELECT asset_id AS fds_asset FROM assets WHERE asset_name = '카드결제승인시스템' \gset
\if :has_fds_role
\echo ''
\echo '################ [TEST] svc_fds_scorer 가 [FDS] FRAUD_SUSPECT 이벤트 INSERT -> 정상 ################'
BEGIN;
  SET ROLE svc_fds_scorer;
  INSERT INTO security_events (event_id, asset_id, event_type, severity, description)
  VALUES (nextval('security_events_event_id_seq'), :fds_asset, 'FRAUD_SUSPECT', 'HIGH', '[FDS] 검증용');
  RESET ROLE;
  \echo '   (INSERT 0 1 이면 성공)'
ROLLBACK;

\echo ''
\echo '################ [TEST] [FDS] 접두사 없음 -> RLS 거부 기대 ################'
BEGIN;
  SET ROLE svc_fds_scorer;
  INSERT INTO security_events (event_id, asset_id, event_type, severity, description)
  VALUES (nextval('security_events_event_id_seq'), :fds_asset, 'FRAUD_SUSPECT', 'HIGH', '실제 사건인 척');
ROLLBACK;
\echo '   (위에 "new row violates row-level security policy" ERROR 가 떠야 정상)'

\echo ''
\echo '################ [TEST] 다른 유형(비정상접근) -> RLS 거부 기대 ################'
BEGIN;
  SET ROLE svc_fds_scorer;
  INSERT INTO security_events (event_id, asset_id, event_type, severity, description)
  VALUES (nextval('security_events_event_id_seq'), :fds_asset, '비정상접근', 'HIGH', '[FDS] 유형 위장');
ROLLBACK;
\echo '   (위에 RLS ERROR 가 떠야 정상)'

\echo ''
\echo '################ [TEST] 다른 자산(asset_id=1) -> RLS 거부 기대 ################'
BEGIN;
  SET ROLE svc_fds_scorer;
  INSERT INTO security_events (event_id, asset_id, event_type, severity, description)
  VALUES (nextval('security_events_event_id_seq'), 1, 'FRAUD_SUSPECT', 'HIGH', '[FDS] 자산 위장');
ROLLBACK;
\echo '   (위에 RLS ERROR 가 떠야 정상)'

\echo ''
\echo '################ [TEST] svc_fds_scorer 는 security_events 를 읽을 수 없다 -> 권한 거부 기대 ################'
BEGIN;
  SET ROLE svc_fds_scorer;
  SELECT count(*) FROM security_events;
ROLLBACK;
\echo '   (위에 permission denied ERROR 가 떠야 정상)'
\else
\echo '   svc_fds_scorer role 없음 → 권한 검증 건너뜀'
\endif

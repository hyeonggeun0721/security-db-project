-- =========================================================
-- V029) 합성(시뮬레이션) 보안 이벤트 지원
--
--   scripts/generate_synthetic_events.py 가 대시보드를 "살아있게" 보이도록
--   현실적 패턴의 합성 이벤트를 주기적으로 넣는다. 실제 사건과 절대 혼동되면 안 되므로:
--
--   1) security_events.description 컬럼 신설(자유 텍스트 상세). 합성 데이터는
--      description 이 '[SIM] ' 로 시작한다. → WHERE description LIKE '[SIM]%' 로
--      합성분만 골라서 분석 제외/삭제 가능.
--
--   2) 전용 서비스 계정 svc_event_ingest (실제 모니터링 도구가 붙는 상황을 흉내):
--      - security_events / responses 에 INSERT 만, event_types/assets/staff 는 SELECT 만
--      - RLS 정책의 WITH CHECK (description LIKE '[SIM]%') 로 "이 계정은 합성 태그
--        없는 행을 물리적으로 넣을 수 없다" 를 DB 레벨에서 강제 → 실데이터 오염 원천 차단
--      - 자원 제한(V026 방침): CONNECTION LIMIT 3, statement_timeout 15s
--
--   재실행 안전: ADD COLUMN IF NOT EXISTS, DO 블록 role 생성, 정책 DROP..IF EXISTS 후 CREATE.
-- =========================================================

BEGIN;

-- 1) 상세 컬럼
ALTER TABLE security_events ADD COLUMN IF NOT EXISTS description TEXT;
COMMENT ON COLUMN security_events.description IS
    '이벤트 상세 메모(자유 텍스트). ''[SIM] '' 접두사 = 합성/시뮬레이션 데이터(실사건 아님).';

-- 2) 서비스 계정
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'svc_event_ingest') THEN
        CREATE ROLE svc_event_ingest LOGIN PASSWORD 'SvcIngest#Tmp-2026!chg';
    END IF;
END $$;

-- 최소 권한
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM svc_event_ingest;
GRANT USAGE ON SCHEMA public TO svc_event_ingest;

GRANT SELECT ON event_types TO svc_event_ingest;                       -- 활성 유형 목록
GRANT SELECT (asset_id, asset_name, department) ON assets TO svc_event_ingest;  -- ip_address 제외(V024 방침)
GRANT SELECT (staff_id, staff_name)            ON staff  TO svc_event_ingest;

-- INSERT 만. RETURNING 을 쓰지 않으므로(스크립트는 nextval 로 id 를 미리 받음)
-- security_events / responses 에 SELECT 는 주지 않는다(순수 피더).
GRANT INSERT ON security_events, responses TO svc_event_ingest;
GRANT USAGE, SELECT ON SEQUENCE security_events_event_id_seq TO svc_event_ingest;
GRANT USAGE, SELECT ON SEQUENCE responses_response_id_seq    TO svc_event_ingest;

-- 3) RLS: svc_event_ingest 의 INSERT 는 반드시 '[SIM]' 태그가 있어야 통과
--    (svc 는 SELECT 권한이 없어 USING/조회는 애초에 불가 → FOR INSERT WITH CHECK 로 충분)
DROP POLICY IF EXISTS p_events_svc_ingest ON security_events;
CREATE POLICY p_events_svc_ingest ON security_events
    FOR INSERT
    TO svc_event_ingest
    WITH CHECK (description LIKE '[SIM]%');

DROP POLICY IF EXISTS p_responses_svc_ingest ON responses;
CREATE POLICY p_responses_svc_ingest ON responses
    FOR INSERT
    TO svc_event_ingest
    WITH CHECK (action_taken LIKE '[SIM]%');

-- assets 는 RLS ENABLE 상태이고 svc 대상 정책이 없으면 기본 거부 → FK 선택용 읽기 허용
DROP POLICY IF EXISTS p_assets_svc_ingest ON assets;
CREATE POLICY p_assets_svc_ingest ON assets
    FOR SELECT
    TO svc_event_ingest
    USING (true);

-- 4) 자원 제한
ALTER ROLE svc_event_ingest CONNECTION LIMIT 3;
ALTER ROLE svc_event_ingest SET statement_timeout = '15s';
ALTER ROLE svc_event_ingest SET idle_in_transaction_session_timeout = '5min';

COMMIT;

-- @migrate:verify
-- =========================================================
-- 검증 (SET ROLE + BEGIN..ROLLBACK, DB 무관·미영속)
-- =========================================================
\echo ''
\echo '################ svc_event_ingest 권한 요약 ################'
SELECT table_name, string_agg(privilege_type, ',' ORDER BY privilege_type) AS privs
FROM information_schema.role_table_grants
WHERE grantee = 'svc_event_ingest' AND table_schema = 'public'
GROUP BY table_name ORDER BY table_name;

\echo ''
\echo '################ [TEST] svc 가 [SIM] 이벤트 INSERT (id 는 nextval 로 미리) -> 정상 ################'
BEGIN;
  SET ROLE svc_event_ingest;
  INSERT INTO security_events (event_id, asset_id, event_type, severity, description, detected_at)
  VALUES (nextval('security_events_event_id_seq'), 2, '비정상접근', 'LOW', '[SIM] 검증용 합성 이벤트', now());
  RESET ROLE;
  \echo '   (INSERT 0 1 이면 성공)'
ROLLBACK;
\echo '   (ROLLBACK - 원상)'

\echo ''
\echo '################ [TEST] svc 가 [SIM] 접두사 없는 이벤트 INSERT -> RLS WITH CHECK 로 거부 기대 ################'
BEGIN;
  SET ROLE svc_event_ingest;
  INSERT INTO security_events (event_id, asset_id, event_type, severity, description)
  VALUES (nextval('security_events_event_id_seq'), 2, '비정상접근', 'LOW', '실제 사건인 척');
  RESET ROLE;
ROLLBACK;
\echo '   (위에 "new row violates row-level security policy" ERROR 가 떠야 정상)'

\echo ''
\echo '################ [TEST] svc 가 event_types 에 INSERT -> 권한 거부 기대 ################'
BEGIN;
  SET ROLE svc_event_ingest;
  INSERT INTO event_types (event_type_name) VALUES ('svc가만든유형');
  RESET ROLE;
ROLLBACK;
\echo '   (위에 permission denied ERROR 가 떠야 정상)'

\echo ''
\echo '################ [TEST] svc 는 security_events 를 SELECT 할 수 없다(순수 피더) -> 권한 거부 기대 ################'
BEGIN;
  SET ROLE svc_event_ingest;
  SELECT count(*) FROM security_events;
  RESET ROLE;
ROLLBACK;
\echo '   (위에 permission denied ERROR 가 떠야 정상)'

\echo ''
\echo '################ [TEST] svc 는 참조용 테이블(event_types/assets/staff)만 읽을 수 있다 ################'
BEGIN;
  SET ROLE svc_event_ingest;
  SELECT (SELECT count(*) FROM event_types WHERE is_active) AS active_types,
         (SELECT count(*) FROM assets)                      AS assets,
         (SELECT count(*) FROM staff)                       AS staff;
  RESET ROLE;
ROLLBACK;

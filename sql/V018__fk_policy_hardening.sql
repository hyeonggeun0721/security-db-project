-- =========================================================
-- 보완 마이그레이션) FK ON DELETE / ON UPDATE 정책 명시 (fk_policy_hardening.sql)
--
--   원본 스키마의 7개 FK 는 참조동작이 지정돼 있지 않아 전부 NO ACTION 이었다.
--   부모 행 삭제/키 변경 시의 의도를 아래와 같이 명시한다:
--
--     asset_vulnerabilities.asset_id -> assets              : ON DELETE CASCADE
--     asset_vulnerabilities.vuln_id  -> vulnerabilities     : ON DELETE CASCADE
--     security_events.asset_id       -> assets              : ON DELETE RESTRICT  (이벤트 이력은 감사증거)
--     security_events.vuln_id        -> vulnerabilities     : ON DELETE SET NULL  (원인 취약점이 지워져도 이벤트 사실은 남김)
--     responses.event_id            -> security_events      : ON DELETE CASCADE
--     responses.staff_id            -> staff                : ON DELETE RESTRICT  (처리 담당자 이력 보존)
--     threat_reports.related_event_id -> security_events     : ON DELETE SET NULL
--     (공통) ON UPDATE CASCADE
--
--   PostgreSQL 은 FK 옵션을 ALTER 로 못 바꾸므로 DROP CONSTRAINT + ADD CONSTRAINT 로
--   재생성한다. 제약조건 "이름은 기존 그대로" 유지한다. 재실행 안전(DROP ... IF EXISTS).
--
--   ※ 하단 [검증] 절은 실패를 유도하는 RESTRICT 테스트를 포함하므로
--     psql 을 ON_ERROR_STOP 없이 실행할 것:  psql -d security_db -f fk_policy_hardening.sql
--   ※ 모든 검증 삭제는 BEGIN ... ROLLBACK 안에서만 수행하며 데이터를 남기지 않는다.
-- =========================================================

BEGIN;

-- asset_vulnerabilities.asset_id -> assets : CASCADE
ALTER TABLE asset_vulnerabilities DROP CONSTRAINT IF EXISTS asset_vulnerabilities_asset_id_fkey;
ALTER TABLE asset_vulnerabilities
    ADD CONSTRAINT asset_vulnerabilities_asset_id_fkey
    FOREIGN KEY (asset_id) REFERENCES assets(asset_id)
    ON UPDATE CASCADE ON DELETE CASCADE;

-- asset_vulnerabilities.vuln_id -> vulnerabilities : CASCADE
ALTER TABLE asset_vulnerabilities DROP CONSTRAINT IF EXISTS asset_vulnerabilities_vuln_id_fkey;
ALTER TABLE asset_vulnerabilities
    ADD CONSTRAINT asset_vulnerabilities_vuln_id_fkey
    FOREIGN KEY (vuln_id) REFERENCES vulnerabilities(vuln_id)
    ON UPDATE CASCADE ON DELETE CASCADE;

-- security_events.asset_id -> assets : RESTRICT (자산을 지우려면 그 이벤트부터 정리해야 함)
ALTER TABLE security_events DROP CONSTRAINT IF EXISTS security_events_asset_id_fkey;
ALTER TABLE security_events
    ADD CONSTRAINT security_events_asset_id_fkey
    FOREIGN KEY (asset_id) REFERENCES assets(asset_id)
    ON UPDATE CASCADE ON DELETE RESTRICT;

-- security_events.vuln_id -> vulnerabilities : SET NULL (이미 NULL 허용 컬럼)
ALTER TABLE security_events DROP CONSTRAINT IF EXISTS security_events_vuln_id_fkey;
ALTER TABLE security_events
    ADD CONSTRAINT security_events_vuln_id_fkey
    FOREIGN KEY (vuln_id) REFERENCES vulnerabilities(vuln_id)
    ON UPDATE CASCADE ON DELETE SET NULL;

-- responses.event_id -> security_events : CASCADE
ALTER TABLE responses DROP CONSTRAINT IF EXISTS responses_event_id_fkey;
ALTER TABLE responses
    ADD CONSTRAINT responses_event_id_fkey
    FOREIGN KEY (event_id) REFERENCES security_events(event_id)
    ON UPDATE CASCADE ON DELETE CASCADE;

-- responses.staff_id -> staff : RESTRICT
ALTER TABLE responses DROP CONSTRAINT IF EXISTS responses_staff_id_fkey;
ALTER TABLE responses
    ADD CONSTRAINT responses_staff_id_fkey
    FOREIGN KEY (staff_id) REFERENCES staff(staff_id)
    ON UPDATE CASCADE ON DELETE RESTRICT;

-- threat_reports.related_event_id -> security_events : SET NULL
ALTER TABLE threat_reports DROP CONSTRAINT IF EXISTS threat_reports_related_event_id_fkey;
ALTER TABLE threat_reports
    ADD CONSTRAINT threat_reports_related_event_id_fkey
    FOREIGN KEY (related_event_id) REFERENCES security_events(event_id)
    ON UPDATE CASCADE ON DELETE SET NULL;

COMMIT;

-- @migrate:verify
-- migrate.py 는 이 마커 위까지를 "마이그레이션 본문"(ON_ERROR_STOP=1)으로,
-- 아래를 "검증 절"(ON_ERROR_STOP=0, 실패해도 마이그레이션은 성공)로 실행한다.
-- 아래 RESTRICT 거부 테스트는 의도적으로 ERROR 를 낸다.
-- =========================================================
-- 검증
-- =========================================================
\echo ''
\echo '################ 재생성된 FK 정책 (d=삭제, u=갱신 : a=NOACTION r=RESTRICT c=CASCADE n=SETNULL) ################'
SELECT conrelid::regclass AS child_table, conname,
       confdeltype AS on_delete, confupdtype AS on_update,
       pg_get_constraintdef(oid) AS definition
FROM pg_constraint
WHERE contype='f' AND connamespace='public'::regnamespace
  AND conrelid::regclass::text IN ('asset_vulnerabilities','security_events','responses','threat_reports')
ORDER BY conrelid::regclass::text, conname;

\echo ''
\echo '=== [TEST 1] vulnerabilities(vuln_id=12) 삭제 -> av CASCADE, security_events.vuln_id SET NULL ==='
-- 사전: event_id=16 은 vuln_id=12 를 참조한다.
BEGIN;
  SELECT 'BEFORE: security_events(16).vuln_id' AS check, vuln_id FROM security_events WHERE event_id = 16;
  DELETE FROM vulnerabilities WHERE vuln_id = 12;
  SELECT 'asset_vulnerabilities WHERE vuln_id=12 (기대 0)' AS check, count(*) AS n FROM asset_vulnerabilities WHERE vuln_id = 12;
  SELECT 'AFTER: security_events(16).vuln_id (기대 NULL)' AS check, vuln_id FROM security_events WHERE event_id = 16;
ROLLBACK;
\echo '   (ROLLBACK 완료 - 원상)'

\echo ''
\echo '=== [TEST 2] assets(asset_id=9) 직접 삭제 -> security_events RESTRICT 로 거부 기대 ==='
BEGIN;
  DELETE FROM assets WHERE asset_id = 9;   -- 기대: ERROR (RESTRICT, 자산 9 에 이벤트 존재)
ROLLBACK;
\echo '   (위에 foreign key 위반 ERROR 가 떠야 정상. ROLLBACK 완료)'

\echo ''
\echo '=== [TEST 2b] 이벤트부터 정리 후 assets(9) 삭제 -> av CASCADE 확인 ==='
BEGIN;
  DELETE FROM security_events WHERE asset_id = 9;      -- responses 는 CASCADE 로 함께 삭제
  DELETE FROM assets WHERE asset_id = 9;               -- 이제 RESTRICT 통과, av 는 CASCADE
  SELECT 'asset_vulnerabilities WHERE asset_id=9 (기대 0)' AS check, count(*) AS n FROM asset_vulnerabilities WHERE asset_id = 9;
ROLLBACK;
\echo '   (ROLLBACK 완료 - 원상)'

\echo ''
\echo '=== [TEST 3] security_events(event_id=3) 삭제 -> responses CASCADE, threat_reports.related_event_id SET NULL ==='
BEGIN;
  DELETE FROM security_events WHERE event_id = 3;
  SELECT 'responses WHERE event_id=3 (기대 0)' AS check, count(*) AS n FROM responses WHERE event_id = 3;
  SELECT 'threat_reports.related_event_id=3 였던 행 (기대 0, SET NULL 됨)' AS check, count(*) AS n
  FROM threat_reports WHERE related_event_id = 3;
ROLLBACK;
\echo '   (ROLLBACK 완료 - 원상)'

\echo ''
\echo '=== [TEST 4] staff(staff_id=1) 삭제 -> responses RESTRICT 로 거부 기대 ==='
BEGIN;
  DELETE FROM staff WHERE staff_id = 1;   -- 기대: ERROR (RESTRICT)
ROLLBACK;
\echo '   (위에 foreign key 위반 ERROR 가 떠야 정상. ROLLBACK 완료)'

\echo ''
\echo '=== [TEST 5] ON UPDATE CASCADE : assets.asset_id 5 -> 900 변경이 자식으로 전파 ==='
BEGIN;
  UPDATE assets SET asset_id = 900 WHERE asset_id = 5;
  SELECT 'security_events WHERE asset_id=900 (기대 >=1)'       AS check, count(*) AS n FROM security_events WHERE asset_id = 900;
  SELECT 'asset_vulnerabilities WHERE asset_id=900 (기대 >=1)' AS check, count(*) AS n FROM asset_vulnerabilities WHERE asset_id = 900;
ROLLBACK;
\echo '   (ROLLBACK 완료 - 원상)'

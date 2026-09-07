-- =========================================================
-- V027) event_type 를 확장 가능한 마스터 테이블로 전환 (departments 패턴)
--
--   V020 에서 security_events.event_type 을 CHECK IN (11개 하드코딩) 으로 막았다.
--   유형 추가 때마다 ALTER 를 해야 하므로, departments_normalization(V019) 과 같은
--   패턴으로 마스터 테이블 + FK 로 바꾼다.
--
--     - event_types(event_type_name PK, description, is_active, created_at)
--     - 기존 CHECK 제거, security_events.event_type -> event_types(event_type_name) FK
--       (ON UPDATE CASCADE ON DELETE RESTRICT — V018/V019 와 일관)
--     - 새 유형 추가 = INSERT INTO event_types (ALTER 불필요)
--       단, 카탈로그 변경 권한은 security_admin 만. 나머지는 SELECT.
--     - is_active : 유형을 물리삭제 없이 비활성화(과거 이벤트는 참조 유지). FK 는 PK 만
--       보므로 "비활성 유형으로 새 이벤트 금지"까지 강제하려면 트리거가 필요(별도).
--
--   재실행 안전: 테이블 IF NOT EXISTS, INSERT ON CONFLICT, 제약 DROP/ADD IF EXISTS.
-- =========================================================

BEGIN;

CREATE TABLE IF NOT EXISTS event_types (
    event_type_name VARCHAR(30) PRIMARY KEY,
    description      TEXT,
    is_active        BOOLEAN     NOT NULL DEFAULT true,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
COMMENT ON TABLE event_types IS 'security_events.event_type 마스터. 새 유형은 INSERT 로 추가(권한: security_admin).';
COMMENT ON COLUMN event_types.is_active IS 'false = 신규 사용 비권장(과거 이벤트 참조는 유지). FK 는 이 값을 보지 않음.';

INSERT INTO event_types (event_type_name, description) VALUES
    ('침입시도',       '외부/내부에서 시스템 침입을 시도한 정황'),
    ('비정상접근',     '비인가 계정·시간대·경로의 접근 또는 접근제어 우회 시도'),
    ('권한상승시도',   '일반 권한에서 관리자/상위 권한 획득 시도'),
    ('악성코드탐지',   'EDR/AV 가 악성 파일·프로세스를 탐지'),
    ('웹취약점스캔',   '웹 애플리케이션 대상 자동화 취약점 스캐닝'),
    ('스팸대량수신',   '스팸/피싱 메일 대량 유입'),
    ('무차별대입시도', '자격증명 무차별 대입(brute force) 시도'),
    ('피싱메일보고',   '사용자가 신고한 피싱 의심 메일'),
    ('정책위반',       '보안정책 위반 행위(반출, 미승인 SW 등)'),
    ('로그위변조시도', '감사/시스템 로그 삭제·변조 시도'),
    ('데이터유출시도', '대량 조회·외부 전송 등 데이터 반출 정황')
ON CONFLICT (event_type_name) DO NOTHING;

-- 기존 CHECK 제거 -> FK 로 대체
ALTER TABLE security_events DROP CONSTRAINT IF EXISTS chk_security_events_event_type;
ALTER TABLE security_events DROP CONSTRAINT IF EXISTS fk_security_events_event_type;
ALTER TABLE security_events
    ADD CONSTRAINT fk_security_events_event_type
    FOREIGN KEY (event_type) REFERENCES event_types(event_type_name)
    ON UPDATE CASCADE ON DELETE RESTRICT;

-- 권한: 카탈로그 조회는 넓게, 변경은 security_admin 만
REVOKE ALL ON event_types FROM PUBLIC;
GRANT SELECT ON event_types
    TO security_analyst, security_manager, dept_infra, dept_dev, dept_sales;
GRANT SELECT, INSERT, UPDATE, DELETE ON event_types TO security_admin;

COMMIT;

-- @migrate:verify
-- =========================================================
-- 검증
-- =========================================================
\echo ''
\echo '################ event_types 목록 (11건 + is_active) ################'
SELECT event_type_name, is_active, description FROM event_types ORDER BY created_at, event_type_name;

\echo ''
\echo '################ FK 로 교체됐는지 (CHECK 없어야, FK 있어야) ################'
SELECT conname, contype, pg_get_constraintdef(oid) AS def
FROM pg_constraint
WHERE conrelid='security_events'::regclass AND conname LIKE '%event_type%'
ORDER BY conname;

-- 검증은 \! 서브셸(DB명 하드코딩) 대신 SET ROLE + BEGIN..ROLLBACK 으로 (DB 무관, 미영속)

\echo ''
\echo '################ [TEST] security_admin: 새 유형 INSERT + 그 유형으로 이벤트 등록 -> 정상 ################'
BEGIN;
  SET ROLE security_admin;
  INSERT INTO event_types(event_type_name, description) VALUES ('내부자위협', '재직자의 의도적 정보 유출/파괴 정황');
  INSERT INTO security_events(asset_id, event_type, severity) VALUES (2, '내부자위협', 'HIGH')
    RETURNING event_id, event_type;
  RESET ROLE;
ROLLBACK;
\echo '   (ROLLBACK - 원상)'

\echo ''
\echo '################ [TEST] 목록에 없는 유형으로 이벤트 등록 -> FK 거부 기대 ################'
BEGIN;
  SET ROLE security_admin;
  INSERT INTO security_events(asset_id, event_type, severity) VALUES (2, '존재하지않는유형', 'LOW');
  RESET ROLE;
ROLLBACK;
\echo '   (위에 foreign key 위반 ERROR 가 떠야 정상)'

\echo ''
\echo '################ [TEST] security_analyst 가 event_types 에 INSERT 시도 -> 권한 거부 기대 ################'
BEGIN;
  SET ROLE security_analyst;
  INSERT INTO event_types(event_type_name) VALUES ('analyst가만든유형');
  RESET ROLE;
ROLLBACK;
\echo '   (위에 permission denied ERROR 가 떠야 정상)'

-- =========================================================
-- 보완 마이그레이션) CHECK 제약 추가 (additional_check_constraints.sql)
--
--   (1) security_events.event_type : 현재 쓰이는 11개 값으로 화이트리스트 CHECK.
--       목적은 "오타 유입 방지". 지금 데이터에 있는 값은 전부 허용한다.
--       새 유형이 생기면 이 제약을 ALTER 로 갱신(=관리 포인트를 명시적으로 남김).
--   (2) nvd_cve_details.nvd_severity / nvd_watch_candidates.nvd_severity :
--       NVD 가 돌려주는 정성 등급만 허용. 아직 점수 미할당(NULL) 은 허용.
--
--   전제: security_db_starter.sql(security_events) + nvd_integration.sql(nvd_* 테이블).
--   재실행 안전: DROP CONSTRAINT IF EXISTS 후 ADD. 전체 1 트랜잭션.
-- =========================================================

BEGIN;

-- ---------------------------------------------------------
-- (1) security_events.event_type 화이트리스트
--     현재 distinct: 침입시도, 비정상접근, 권한상승시도, 악성코드탐지, 웹취약점스캔,
--                    스팸대량수신, 무차별대입시도, 피싱메일보고, 정책위반,
--                    로그위변조시도, 데이터유출시도
-- ---------------------------------------------------------
ALTER TABLE security_events DROP CONSTRAINT IF EXISTS chk_security_events_event_type;
ALTER TABLE security_events
    ADD CONSTRAINT chk_security_events_event_type
    CHECK (event_type IN (
        '침입시도',
        '비정상접근',
        '권한상승시도',
        '악성코드탐지',
        '웹취약점스캔',
        '스팸대량수신',
        '무차별대입시도',
        '피싱메일보고',
        '정책위반',
        '로그위변조시도',
        '데이터유출시도'
    ));

COMMENT ON CONSTRAINT chk_security_events_event_type ON security_events IS
    '이벤트 유형 화이트리스트(오타 방지). 새 유형 추가 시 이 제약을 ALTER 로 갱신할 것';

-- ---------------------------------------------------------
-- (2) nvd_severity 정성 등급 CHECK (NULL 허용)
-- ---------------------------------------------------------
ALTER TABLE nvd_cve_details DROP CONSTRAINT IF EXISTS chk_nvd_cve_details_nvd_severity;
ALTER TABLE nvd_cve_details
    ADD CONSTRAINT chk_nvd_cve_details_nvd_severity
    CHECK (nvd_severity IS NULL OR nvd_severity IN ('NONE','LOW','MEDIUM','HIGH','CRITICAL'));

ALTER TABLE nvd_watch_candidates DROP CONSTRAINT IF EXISTS chk_nvd_watch_candidates_nvd_severity;
ALTER TABLE nvd_watch_candidates
    ADD CONSTRAINT chk_nvd_watch_candidates_nvd_severity
    CHECK (nvd_severity IS NULL OR nvd_severity IN ('NONE','LOW','MEDIUM','HIGH','CRITICAL'));

COMMIT;

-- =========================================================
-- 검증
-- =========================================================
\echo ''
\echo '################ 추가된 CHECK 제약 ################'
SELECT conrelid::regclass AS tbl, conname, pg_get_constraintdef(oid) AS def
FROM pg_constraint
WHERE contype='c' AND conname IN (
    'chk_security_events_event_type',
    'chk_nvd_cve_details_nvd_severity',
    'chk_nvd_watch_candidates_nvd_severity')
ORDER BY conrelid::regclass::text, conname;

\echo ''
\echo '################ [TEST] 기존 11개 값은 전부 통과해야 함 (위반 시 이 파일 적용 자체가 실패했을 것) ################'
SELECT event_type, count(*) AS n FROM security_events GROUP BY event_type ORDER BY event_type;

\echo ''
\echo '################ [TEST] 오타 event_type INSERT -> CHECK 로 거부 기대 ################'
DO $$
BEGIN
    BEGIN
        INSERT INTO security_events (asset_id, event_type, severity)
        VALUES (1, '비정상접근오타', 'LOW');
        RAISE NOTICE '[FAIL] 오타 event_type 이 삽입됨 (예상: 거부).';
    EXCEPTION WHEN check_violation THEN
        RAISE NOTICE '[OK] 오타 event_type INSERT 가 CHECK 로 거부됨.';
    END;
END $$;

\echo ''
\echo '################ [TEST] 잘못된 nvd_severity INSERT -> CHECK 로 거부 기대 ################'
DO $$
BEGIN
    BEGIN
        INSERT INTO nvd_watch_candidates (cve_id, matched_keywords, nvd_severity)
        VALUES ('CVE-2099-99999', ARRAY['test'], 'SEVERE');
        RAISE NOTICE '[FAIL] 잘못된 nvd_severity 가 삽입됨 (예상: 거부).';
    EXCEPTION WHEN check_violation THEN
        RAISE NOTICE '[OK] 잘못된 nvd_severity INSERT 가 CHECK 로 거부됨.';
    END;
END $$;

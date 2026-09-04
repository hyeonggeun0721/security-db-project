-- =========================================================
-- 마이그레이션 1) 타입 보강 (type_hardening.sql)
--
--   운영 관점 보완:
--     (1) 시각 컬럼을 timestamp without time zone -> timestamptz 로 변경.
--         기존 naive 값은 "KST(Asia/Seoul) 벽시계 시각"으로 기록된 것이라 가정하고
--         USING <col> AT TIME ZONE 'Asia/Seoul' 로 변환한다.
--         대상: assets.created_at, responses.action_date, security_events.detected_at
--         제외: *_date 컬럼(detected_date, published_date, report_date)은 DATE 타입,
--               audit_log.changed_at 은 이미 timestamptz.
--     (2) assets.ip_address : varchar(45) -> inet (형식 검증 + 서브넷 연산 가능)
--     (3) vulnerabilities.cve_id : 'CVE-YYYY-NNNN' 형식 CHECK 추가 (NULL 허용)
--
--   원본 스키마/고도화 파일의 구조는 수정하지 않는다. 다만 detected_at 타입 변경을
--   위해 이 컬럼에 의존하는 뷰 vw_open_high_risk_events 를 "동일 정의로" 재생성한다
--   (PostgreSQL 은 뷰가 참조하는 컬럼의 타입을 바꿀 수 없기 때문).
--
--   전체를 하나의 트랜잭션으로 실행한다. 재실행 시 CHECK 중복만 문제되므로
--   제약은 존재 여부를 확인 후 추가한다.
-- =========================================================

BEGIN;

-- ---------------------------------------------------------
-- (1) timestamptz 전환
-- ---------------------------------------------------------
-- detected_at 에 의존하는 뷰를 잠시 제거
DROP VIEW IF EXISTS vw_open_high_risk_events;

ALTER TABLE assets
    ALTER COLUMN created_at TYPE timestamptz
    USING created_at AT TIME ZONE 'Asia/Seoul';

ALTER TABLE responses
    ALTER COLUMN action_date TYPE timestamptz
    USING action_date AT TIME ZONE 'Asia/Seoul';

ALTER TABLE security_events
    ALTER COLUMN detected_at TYPE timestamptz
    USING detected_at AT TIME ZONE 'Asia/Seoul';

-- 뷰 재생성 (원본 security_db_starter.sql 의 정의와 동일)
CREATE VIEW vw_open_high_risk_events AS
 SELECT e.event_id,
    a.asset_name,
    e.event_type,
    e.severity,
    e.detected_at
   FROM security_events e
     JOIN assets a ON a.asset_id = e.asset_id
  WHERE e.status::text <> 'RESOLVED'::text
    AND e.severity::text = ANY (ARRAY['HIGH'::varchar, 'CRITICAL'::varchar]::text[]);

-- 재생성된 뷰의 조회 권한 원복 (rbac.sql 이 부여했던 것)
GRANT SELECT ON vw_open_high_risk_events TO security_analyst, security_admin, security_manager;

-- ---------------------------------------------------------
-- (2) assets.ip_address -> inet
-- ---------------------------------------------------------
ALTER TABLE assets
    ALTER COLUMN ip_address TYPE inet
    USING ip_address::inet;

-- ---------------------------------------------------------
-- (3) vulnerabilities.cve_id 형식 CHECK
-- ---------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'chk_vulnerabilities_cve_id_format'
          AND conrelid = 'vulnerabilities'::regclass
    ) THEN
        ALTER TABLE vulnerabilities
            ADD CONSTRAINT chk_vulnerabilities_cve_id_format
            CHECK (cve_id IS NULL OR cve_id ~ '^CVE-\d{4}-\d{4,}$');
    END IF;
END $$;

COMMIT;

-- =========================================================
-- 검증
-- =========================================================
\echo ''
\echo '################ 변경된 컬럼 타입 ################'
SELECT table_name, column_name, data_type
FROM information_schema.columns
WHERE table_schema='public'
  AND ( (table_name='assets'          AND column_name IN ('created_at','ip_address'))
     OR (table_name='responses'       AND column_name='action_date')
     OR (table_name='security_events' AND column_name='detected_at') )
ORDER BY table_name, column_name;

\echo ''
\echo '################ assets: 시각/ IP 데이터 손실 없이 변환됐는지 ################'
SELECT asset_id, asset_name, ip_address, host(ip_address) AS ip_host, created_at
FROM assets ORDER BY asset_id LIMIT 6;

\echo ''
\echo '################ security_events / responses 시각 샘플 (timestamptz, +09 표기) ################'
SELECT event_id, detected_at FROM security_events ORDER BY event_id LIMIT 4;
SELECT response_id, action_date FROM responses ORDER BY response_id LIMIT 4;

\echo ''
\echo '################ 행 수 불변 확인 ################'
SELECT (SELECT count(*) FROM assets) AS assets,
       (SELECT count(*) FROM responses) AS responses,
       (SELECT count(*) FROM security_events) AS security_events,
       (SELECT count(*) FROM vulnerabilities) AS vulnerabilities;

\echo ''
\echo '################ cve_id CHECK 제약 동작 테스트 (잘못된 형식은 거부되어야 함) ################'
DO $$
BEGIN
    BEGIN
        INSERT INTO vulnerabilities (cve_id, description, cvss_score, severity)
        VALUES ('CVE-25-1', '형식 위반 테스트', 5.0, 'MEDIUM');
        RAISE NOTICE '[FAIL] 잘못된 형식이 삽입되었습니다 (예상: 거부).';
    EXCEPTION WHEN check_violation THEN
        RAISE NOTICE '[OK] 잘못된 cve_id 형식 INSERT 가 CHECK 제약으로 거부됨.';
    END;
END $$;

\echo ''
\echo '################ vulnerabilities 제약 목록 ################'
SELECT conname, pg_get_constraintdef(oid) AS definition
FROM pg_constraint WHERE conrelid='vulnerabilities'::regclass AND contype='c'
ORDER BY conname;

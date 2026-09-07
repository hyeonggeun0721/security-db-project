-- =========================================================
-- V030) KISA 취약점 스캐너(설정 취약점) 결과를 통합
--
-- 배경: KISA U-01~U-72 진단 결과는 CVE 번호가 없는 "설정 취약점"이다.
--   NVD발 CVE 취약점(vulnerabilities.cve_id, nvd_cve_details)과 성격이 다르다.
--
-- 설계 판단: **(a) vulnerabilities 재사용** 방식 채택.
--   - vulnerabilities 에 `source`(NVD/SCAN/MANUAL) + `finding_ref`(비-CVE 식별자,
--     'KISA-U-47' 등) + `remediation`(조치권고) 컬럼 추가.
--   - KISA 항목 1건 = vulnerabilities 1행 (source='SCAN', finding_ref='KISA-U-##',
--     cve_id NULL). 여러 호스트에서 같은 항목이 나오면 동일 행을 공유.
--   - asset_vulnerabilities 로 스캔 대상 asset 과 연결(status='OPEN' 등 기존 상태값 그대로).
--   - **기존 위험도 스코어링(vw_asset_risk_score = importance_level × max_open_cvss)을
--     그대로 재사용**하기 위해, KISA 중요도(상/중/하)를 CVSS 밴드 대표값으로 환산해
--     cvss_score / severity 에 넣는다(아래 매핑). (b) 별도 scan_findings 테이블은
--     위험도 로직을 새로 만들어야 해서 제외.
--
--   KISA 중요도 → severity / 환산 cvss_score (실제 CVE 기본점수 아님, source='SCAN' 으로 구분):
--     상 → HIGH   / 7.5   (KISA "상": 시스템 장악·대량 정보유출 위험. CVSS HIGH 밴드 7.0~8.9 대표값)
--     중 → MEDIUM / 5.0   (CVSS MEDIUM 밴드 4.0~6.9 대표값)
--     하 → LOW    / 2.5   (CVSS LOW 밴드 0.1~3.9 대표값)
--   * CRITICAL 은 설정취약점에 배정하지 않음 — NVD CVSS≥9.0 원격 RCE 류 전용으로 유지.
--   * 환산값은 severity 라벨과 밴드가 일치하므로 vw_cvss_severity_mismatch 에 오탐을 만들지 않음.
--
-- 스캔 실행 메타(언제/어디서/root 여부/집계)는 `scan_runs` 테이블에 별도 기록.
--
-- 데이터(asset, vulnerabilities 행, 연결)는 이 마이그레이션이 아니라
--   scripts/import_kisa_results.py 가 JSON 리포트를 파싱해 적재한다(nvd_sync.py 와 동일 패턴).
--
-- 재실행 안전: ADD COLUMN IF NOT EXISTS / 제약은 존재확인 후 추가 / 테이블 IF NOT EXISTS.
-- =========================================================

BEGIN;

-- ---------------------------------------------------------
-- 1) vulnerabilities: 출처 구분 + 비-CVE 식별자 + 조치권고
-- ---------------------------------------------------------
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS source      VARCHAR(10) NOT NULL DEFAULT 'NVD';
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS finding_ref VARCHAR(40);
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS remediation TEXT;

COMMENT ON COLUMN vulnerabilities.source      IS 'NVD=CVE(외부), SCAN=설정취약점 진단(KISA 등), MANUAL=수동 등록';
COMMENT ON COLUMN vulnerabilities.finding_ref IS 'CVE 가 아닌 외부 식별자 (예: KISA-U-47). source=SCAN 이면 필수, UNIQUE.';
COMMENT ON COLUMN vulnerabilities.remediation IS '조치 권고 (SCAN/MANUAL 에서 사용). NVD 행은 보통 NULL.';

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='chk_vuln_source' AND conrelid='vulnerabilities'::regclass) THEN
        ALTER TABLE vulnerabilities ADD CONSTRAINT chk_vuln_source CHECK (source IN ('NVD','SCAN','MANUAL'));
    END IF;
    -- SCAN 행은 CVE 없이 finding_ref 를 가져야 함 (NVD/MANUAL 은 제약 없음)
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='chk_vuln_scan_ident' AND conrelid='vulnerabilities'::regclass) THEN
        ALTER TABLE vulnerabilities ADD CONSTRAINT chk_vuln_scan_ident
            CHECK (source <> 'SCAN' OR (cve_id IS NULL AND finding_ref IS NOT NULL));
    END IF;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS uq_vulnerabilities_finding_ref
    ON vulnerabilities (finding_ref) WHERE finding_ref IS NOT NULL;

-- 출처별 조회를 위한 보조 인덱스 (규모 대비)
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_source ON vulnerabilities (source);

-- ---------------------------------------------------------
-- 2) 스캔 실행 메타
-- ---------------------------------------------------------
CREATE TABLE IF NOT EXISTS scan_runs (
    scan_run_id     SERIAL PRIMARY KEY,
    tool            VARCHAR(50)  NOT NULL DEFAULT 'KISA-U (U-01~U-72)',
    target_asset_id INT          REFERENCES assets(asset_id) ON UPDATE CASCADE ON DELETE SET NULL,
    target_hostname VARCHAR(100),
    target_platform VARCHAR(60),
    target_distro   VARCHAR(80),
    scanned_as_root BOOLEAN,
    scanned_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    total_checks    INT,
    cnt_good        INT,   -- 양호
    cnt_vuln        INT,   -- 취약
    cnt_na          INT,   -- 점검불가
    report_path     TEXT,
    imported_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    UNIQUE (tool, target_hostname, scanned_at)
);
COMMENT ON TABLE scan_runs IS '설정취약점 스캐너 1회 실행 메타 (KISA kisa_scanner.py 등). 개별 취약 항목은 vulnerabilities(source=SCAN) + asset_vulnerabilities 로 적재.';

GRANT SELECT ON scan_runs TO security_analyst, security_admin, security_manager;
GRANT SELECT, INSERT, UPDATE ON scan_runs TO security_admin;
GRANT USAGE, SELECT ON SEQUENCE scan_runs_scan_run_id_seq TO security_admin;

-- ---------------------------------------------------------
-- 3) asset_vulnerabilities: 어느 스캔에서 나왔는지 + 그 호스트의 현재 설정값
-- ---------------------------------------------------------
ALTER TABLE asset_vulnerabilities ADD COLUMN IF NOT EXISTS scan_run_id     INT
    REFERENCES scan_runs(scan_run_id) ON UPDATE CASCADE ON DELETE SET NULL;
ALTER TABLE asset_vulnerabilities ADD COLUMN IF NOT EXISTS observed_detail TEXT;

COMMENT ON COLUMN asset_vulnerabilities.scan_run_id     IS '이 연결을 만든 스캔 실행 (SCAN 출처일 때). 수동 연결은 NULL.';
COMMENT ON COLUMN asset_vulnerabilities.observed_detail IS '해당 호스트에서 관측된 실제 설정값 (KISA current_setting).';

CREATE INDEX IF NOT EXISTS idx_asset_vulnerabilities_scan_run_id
    ON asset_vulnerabilities (scan_run_id) WHERE scan_run_id IS NOT NULL;

COMMIT;

-- @migrate:verify
-- =========================================================
-- 검증
-- =========================================================
\echo ''
\echo '################ vulnerabilities 새 컬럼/제약 ################'
SELECT column_name, data_type, column_default
FROM information_schema.columns
WHERE table_name='vulnerabilities' AND column_name IN ('source','finding_ref','remediation')
ORDER BY column_name;
SELECT conname, pg_get_constraintdef(oid) FROM pg_constraint
WHERE conrelid='vulnerabilities'::regclass AND conname IN ('chk_vuln_source','chk_vuln_scan_ident');

\echo ''
\echo '################ 기존 12개 vulnerabilities 는 전부 source=NVD 로 채워짐 ################'
SELECT source, count(*) FROM vulnerabilities GROUP BY source ORDER BY source;

\echo ''
\echo '################ [TEST] SCAN 행은 cve_id 없이 finding_ref 필수 (BEGIN..ROLLBACK) ################'
BEGIN;
  -- cve_id 를 넣은 SCAN 행 -> chk_vuln_scan_ident 위반 기대
  INSERT INTO vulnerabilities (cve_id, description, cvss_score, severity, source, finding_ref)
  VALUES ('CVE-2099-0001', 'bad scan row', 5.0, 'MEDIUM', 'SCAN', 'KISA-U-99');
ROLLBACK;
\echo '   (위에 check_violation ERROR 가 떠야 정상)'

BEGIN;
  -- 정상 SCAN 행
  INSERT INTO vulnerabilities (description, cvss_score, severity, source, finding_ref, remediation)
  VALUES ('[SCAN 검증] KISA-U-99 test', 7.5, 'HIGH', 'SCAN', 'KISA-U-99', '조치권고 test')
  RETURNING vuln_id, source, finding_ref, severity;
ROLLBACK;
\echo '   (INSERT 1 후 ROLLBACK - 원상)'

\echo ''
\echo '################ scan_runs 테이블 + asset_vulnerabilities 새 컬럼 ################'
\d scan_runs
SELECT column_name FROM information_schema.columns
WHERE table_name='asset_vulnerabilities' AND column_name IN ('scan_run_id','observed_detail');

\echo ''
\echo '################ vw_asset_risk_score 는 여전히 오류 없이 조회됨 (SCAN 행 반영 준비) ################'
SELECT count(*) AS rows, max(risk_score) AS max_risk FROM vw_asset_risk_score;

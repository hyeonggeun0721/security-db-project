-- =========================================================
-- 심화 기능) NVD API 연동 - 스키마 (nvd_integration.sql)
--
--   설계 판단: vulnerabilities 에 컬럼을 추가하지 않고 별도 테이블
--   (nvd_cve_details, nvd_watch_candidates)로 분리한다.
--   이유:
--     1) NVD 값은 "외부 출처 + 주기적 재동기화" 대상이다. 우리 조직의 평가치
--        (vulnerabilities.cvss_score/severity)와 NVD 공식값을 물리적으로 분리해야
--        "누가 매긴 값인지"가 명확하고, 재동기화가 코어 테이블을 건드리지 않는다.
--     2) nvd_reference_urls(TEXT[]), 긴 nvd_description, synced_at 같은 동기화 메타데이터를
--        코어 테이블에서 격리한다.
--     3) 1:1 관계이므로 cve_id FK 조인이 단순하고, mismatch 뷰도 깔끔하다.
--     4) 신규 CVE 워치 후보는 아직 vulnerabilities 에 없는 CVE 도 담아야 하므로
--        어차피 별도 테이블이 필요하다 -> 일관성 있게 둘 다 분리.
--
--   재실행 안전: 테이블 IF NOT EXISTS, 뷰 CREATE OR REPLACE. 데이터 UPSERT 는 파이썬에서.
-- =========================================================

BEGIN;

-- ---------------------------------------------------------
-- 1) 기존 취약점의 NVD 공식 상세 (1:1)
-- ---------------------------------------------------------
CREATE TABLE IF NOT EXISTS nvd_cve_details (
    cve_id              VARCHAR(20) PRIMARY KEY
                        REFERENCES vulnerabilities(cve_id) ON UPDATE CASCADE ON DELETE CASCADE,
    nvd_cvss_score      NUMERIC(3,1),
    nvd_severity        VARCHAR(20),
    nvd_cvss_version    VARCHAR(10),         -- 점수를 가져온 metric 버전 (3.1 / 3.0 / 2.0)
    nvd_vector_string   TEXT,
    nvd_description     TEXT,
    nvd_published_date  TIMESTAMPTZ,
    nvd_last_modified   TIMESTAMPTZ,
    nvd_reference_urls  TEXT[],
    nvd_status          VARCHAR(20) NOT NULL DEFAULT 'SYNCED'
                        CHECK (nvd_status IN ('SYNCED', 'NOT_FOUND', 'ERROR')),
    synced_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE nvd_cve_details IS 'vulnerabilities.cve_id 별 NVD REST API 2.0 공식 상세 (nvd_sync.py 가 UPSERT)';
COMMENT ON COLUMN nvd_cve_details.nvd_status IS 'SYNCED=조회성공, NOT_FOUND=NVD에 해당 CVE 없음, ERROR=조회실패';

-- ---------------------------------------------------------
-- 2) 신규 CVE 워치 후보 (키워드 검색 결과, 분석가 검토용 - 자동 병합 금지)
-- ---------------------------------------------------------
CREATE TABLE IF NOT EXISTS nvd_watch_candidates (
    cve_id                     VARCHAR(20) PRIMARY KEY,
    matched_keywords           TEXT[]      NOT NULL,
    nvd_cvss_score             NUMERIC(3,1),
    nvd_severity               VARCHAR(20),
    nvd_description            TEXT,
    nvd_published_date         TIMESTAMPTZ,
    nvd_reference_urls         TEXT[],
    already_in_vulnerabilities BOOLEAN     NOT NULL DEFAULT false,
    review_status              VARCHAR(20) NOT NULL DEFAULT 'NEW'
                               CHECK (review_status IN ('NEW', 'REVIEWED', 'IMPORTED', 'IGNORED')),
    discovered_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    synced_at                  TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE nvd_watch_candidates IS 'NVD 키워드 검색으로 발견한 최근 신규 CVE 후보. vulnerabilities 로 자동 병합하지 않음(검토 큐)';

-- ---------------------------------------------------------
-- 3) 우리 평가치 vs NVD 공식값 불일치 뷰 (vw_cvss_severity_mismatch 와 동일 패턴)
-- ---------------------------------------------------------
CREATE OR REPLACE VIEW vw_cvss_nvd_mismatch AS
SELECT
    v.vuln_id,
    v.cve_id,
    v.cvss_score                                                    AS our_cvss,
    v.severity                                                      AS our_severity,
    n.nvd_cvss_score                                                AS nvd_cvss,
    n.nvd_severity                                                  AS nvd_severity,
    n.nvd_cvss_version,
    round(abs(v.cvss_score - n.nvd_cvss_score), 1)                  AS cvss_abs_diff,
    abs( fn_severity_rank(v.severity)
       - fn_severity_rank(n.nvd_severity) )                         AS severity_gap,
    n.synced_at
FROM vulnerabilities v
JOIN nvd_cve_details n ON n.cve_id = v.cve_id
WHERE n.nvd_status = 'SYNCED'
  AND n.nvd_cvss_score IS NOT NULL
  AND ( v.severity IS DISTINCT FROM n.nvd_severity
        OR abs(v.cvss_score - n.nvd_cvss_score) >= 0.5 );

COMMENT ON VIEW vw_cvss_nvd_mismatch IS
    '우리 DB 평가치(cvss_score/severity)와 NVD 공식값이 어긋나는 취약점 (severity 불일치 또는 CVSS 0.5점 이상 차이)';

-- ---------------------------------------------------------
-- 4) 조회 권한 (대시보드는 security_manager 로 접속)
-- ---------------------------------------------------------
GRANT SELECT ON nvd_cve_details, nvd_watch_candidates, vw_cvss_nvd_mismatch
    TO security_manager, security_admin, security_analyst;

COMMIT;

-- =========================================================
-- 확인
-- =========================================================
\echo ''
\echo '################ 생성된 객체 ################'
\d nvd_cve_details
\d nvd_watch_candidates
\echo ''
\echo '################ vw_cvss_nvd_mismatch 정의 확인 (데이터는 nvd_sync.py 실행 후) ################'
SELECT count(*) AS rows_now FROM vw_cvss_nvd_mismatch;

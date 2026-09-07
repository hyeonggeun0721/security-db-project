-- =========================================================
-- V031) EPSS(악용 확률) 연동 + CVSS×EPSS 우선순위 스코어링
--
-- 배경: CVSS 는 "악용되면 얼마나 심각한가"(영향도)만 말한다. EPSS(FIRST.org)는
--   "향후 30일 내 악용 활동이 관측될 확률"(0~1)을 준다. 둘을 결합하면 실무
--   패치 우선순위를 훨씬 잘 잡는다 — 특히 "CVSS 는 낮은데 실제 악용 중"인 항목.
--
-- 저장 위치 판단: **nvd_cve_details 에 컬럼 추가**.
--   - nvd_cve_details 는 이미 "cve_id 별 외부 CVE 인텔리전스"(NVD 공식값) 테이블이다.
--     EPSS 도 같은 성격(외부·CVE단위·주기적 재동기화)이라 한곳에 모으는 게 자연스럽다.
--   - 1:1 cve_id, FK, synced_at 패턴이 이미 있다. 뷰에서 vulnerabilities ⨝ nvd_cve_details
--     한 번의 조인으로 CVSS+NVD+EPSS 를 다 얻는다.
--   - 코어 vulnerabilities 는 깨끗하게 유지(V017 설계 원칙). KISA SCAN 행(cve_id 없음)은 대상 아님.
--
-- 결합 공식 (문서화):
--   priority_score = round(cvss_score * epss_score, 3)    -- 0~10, "확률 가중 CVSS"
--     · 해석: 기대 영향도 = 심각도(CVSS) × 악용 확률(EPSS). FIRST.org 권고 사용법
--       (EPSS 를 영향도 지표에 곱한다)과 일치.
--     · 가중합(w1·cvss/10 + w2·epss) 대신 곱을 쓰는 이유: 가중합은 "CVSS 9.8 인데
--       아무도 안 건드리는" 취약점을 계속 위험해 보이게 한다. 곱은 그런 항목을 자연히
--       낮추고, "CVSS 5.3 인데 EPSS 0.999" 항목을 최상위로 올린다 — 그게 EPSS 를 쓰는 이유.
--     · 트레이드오프: 갓 공개된 CRITICAL 은 EPSS 가 아직 낮아(모델 지연) 곱이 작아질 수 있다.
--       그래서 뷰는 cvss_score / epss_percentile / epss_band 를 함께 노출하고
--       epss_over_cvss 플래그로 "CVSS 낮음 + 악용 상위" 케이스를 별도 강조한다.
--   (자산 단위로 확장하려면 vw_asset_risk_score 의 max_open_cvss 자리에
--    MAX(priority_score) 를 넣은 vw_asset_risk_score_epss 를 별도로 만들면 된다. 이번엔 미포함.)
--
-- 재실행 안전: ADD COLUMN IF NOT EXISTS / 제약 존재확인 / 뷰 OR REPLACE.
-- 데이터는 scripts/epss_sync.py 가 적재 (nvd_sync.py 와 동일 패턴).
-- =========================================================

BEGIN;

-- ---------------------------------------------------------
-- 1) nvd_cve_details 에 EPSS 컬럼
-- ---------------------------------------------------------
ALTER TABLE nvd_cve_details ADD COLUMN IF NOT EXISTS epss_score      NUMERIC(8,7);
ALTER TABLE nvd_cve_details ADD COLUMN IF NOT EXISTS epss_percentile NUMERIC(8,7);
ALTER TABLE nvd_cve_details ADD COLUMN IF NOT EXISTS epss_model_date DATE;          -- FIRST.org 모델 산출일('date')
ALTER TABLE nvd_cve_details ADD COLUMN IF NOT EXISTS epss_updated_at TIMESTAMPTZ;

COMMENT ON COLUMN nvd_cve_details.epss_score      IS 'EPSS 악용확률 0~1 (FIRST.org). 향후 30일 내 악용 활동 관측 확률.';
COMMENT ON COLUMN nvd_cve_details.epss_percentile IS 'EPSS 백분위 0~1 (전체 CVE 대비 상대 순위).';
COMMENT ON COLUMN nvd_cve_details.epss_model_date IS 'EPSS API 응답의 date (모델 산출 기준일).';

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='chk_epss_score' AND conrelid='nvd_cve_details'::regclass) THEN
        ALTER TABLE nvd_cve_details ADD CONSTRAINT chk_epss_score
            CHECK (epss_score IS NULL OR (epss_score >= 0 AND epss_score <= 1));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='chk_epss_percentile' AND conrelid='nvd_cve_details'::regclass) THEN
        ALTER TABLE nvd_cve_details ADD CONSTRAINT chk_epss_percentile
            CHECK (epss_percentile IS NULL OR (epss_percentile >= 0 AND epss_percentile <= 1));
    END IF;
END $$;

-- epss_sync.py 가 NVD 상세보다 먼저 도는 경우: EPSS 만 채운 행을 'PENDING' 으로 표시.
-- (nvd_sync.py 재실행 시 SYNCED/NOT_FOUND 로 정정됨. vw_cvss_nvd_mismatch 등은 nvd_status='SYNCED' 만 보므로 무해)
ALTER TABLE nvd_cve_details DROP CONSTRAINT IF EXISTS nvd_cve_details_nvd_status_check;
ALTER TABLE nvd_cve_details ADD CONSTRAINT nvd_cve_details_nvd_status_check
    CHECK (nvd_status IN ('SYNCED','NOT_FOUND','ERROR','PENDING'));

-- ---------------------------------------------------------
-- 2) 우선순위 뷰 — CVSS×EPSS, "낮은 CVSS / 높은 EPSS" 강조
-- ---------------------------------------------------------
CREATE OR REPLACE VIEW vw_priority_vulnerabilities AS
SELECT
    v.vuln_id,
    v.cve_id,
    v.source,
    v.cvss_score,
    v.severity                                              AS cvss_severity,
    n.epss_score,
    n.epss_percentile,
    round(v.cvss_score * n.epss_score, 3)                   AS priority_score,   -- 확률 가중 CVSS (0~10)
    CASE
        WHEN n.epss_percentile >= 0.99 THEN 'TOP 1%'
        WHEN n.epss_percentile >= 0.95 THEN 'TOP 5%'
        WHEN n.epss_percentile >= 0.90 THEN 'TOP 10%'
        WHEN n.epss_percentile >= 0.75 THEN 'TOP 25%'
        ELSE '—'
    END                                                    AS epss_band,
    -- CVSS 는 LOW/MEDIUM 인데 EPSS 백분위는 상위 10% → "지표가 우선순위를 과소평가"
    (n.epss_percentile >= 0.90 AND v.severity IN ('LOW','MEDIUM')) AS epss_over_cvss,
    (SELECT count(*) FROM asset_vulnerabilities av
      WHERE av.vuln_id = v.vuln_id AND av.status = 'OPEN')  AS open_on_assets
FROM vulnerabilities v
JOIN nvd_cve_details n ON n.cve_id = v.cve_id
WHERE v.cve_id IS NOT NULL
  AND n.epss_score IS NOT NULL
ORDER BY epss_over_cvss DESC, priority_score DESC, v.cvss_score DESC;

COMMENT ON VIEW vw_priority_vulnerabilities IS
    'CVSS×EPSS 우선순위. priority_score = cvss_score × epss_score. epss_over_cvss=TRUE 는 CVSS 낮음+악용 상위10% (EPSS 를 쓰는 핵심 케이스).';

GRANT SELECT ON vw_priority_vulnerabilities TO security_analyst, security_admin, security_manager;

COMMIT;

-- @migrate:verify
-- =========================================================
-- 검증
-- =========================================================
\echo ''
\echo '################ nvd_cve_details EPSS 컬럼/제약 ################'
SELECT column_name, data_type FROM information_schema.columns
WHERE table_name='nvd_cve_details' AND column_name LIKE 'epss%' ORDER BY column_name;
SELECT conname, pg_get_constraintdef(oid) FROM pg_constraint
WHERE conrelid='nvd_cve_details'::regclass AND conname LIKE 'chk_epss%';

\echo ''
\echo '################ [TEST] epss_score 범위 밖 -> CHECK 거부 기대 (BEGIN..ROLLBACK) ################'
BEGIN;
  UPDATE nvd_cve_details SET epss_score = 1.5 WHERE cve_id = (SELECT cve_id FROM nvd_cve_details LIMIT 1);
ROLLBACK;
\echo '   (위에 check_violation ERROR 가 떠야 정상)'

\echo ''
\echo '################ vw_priority_vulnerabilities 조회 가능 (데이터는 epss_sync.py 후) ################'
SELECT count(*) AS rows_now FROM vw_priority_vulnerabilities;

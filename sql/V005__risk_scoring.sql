-- =========================================================
-- 고도화 기능 3) CVSS 기반 위험도 스코어링 (vw_asset_risk_score)
--   assets.importance_level (1~5) 와 자산에 연결된 vulnerabilities.cvss_score (0~10)
--   를 조합해 자산별 위험도 점수와 LOW/MEDIUM/HIGH/CRITICAL 라벨을 부여하는 뷰.
--
--   점수 정의:
--     base_score  = importance_level * max_open_cvss           (0 ~ 50)
--     risk_score  = round(base_score, 1)
--   * 미해결(status='OPEN') 취약점만 위험도에 반영한다(패치 완료분은 잔여위험 제외).
--   * 연결된 미해결 취약점이 없으면 max_open_cvss = 0 → risk_score = 0 → LOW.
--
--   라벨 구간 (risk_score 기준):
--     CRITICAL : >= 40
--     HIGH     : >= 24
--     MEDIUM   : >= 10
--     LOW      : <  10
--
-- 기존 스키마/데이터 변경 없음. 뷰만 추가(재실행 안전: OR REPLACE).
-- =========================================================

CREATE OR REPLACE VIEW vw_asset_risk_score AS
WITH open_vuln AS (
    SELECT av.asset_id,
           COUNT(*)                       AS open_vuln_count,
           MAX(v.cvss_score)              AS max_open_cvss,
           ROUND(AVG(v.cvss_score), 2)    AS avg_open_cvss
    FROM asset_vulnerabilities av
    JOIN vulnerabilities v ON v.vuln_id = av.vuln_id
    WHERE av.status = 'OPEN'
    GROUP BY av.asset_id
)
SELECT
    a.asset_id,
    a.asset_name,
    a.asset_type,
    a.department,
    a.importance_level,
    COALESCE(ov.open_vuln_count, 0)                              AS open_vuln_count,
    COALESCE(ov.max_open_cvss, 0)::numeric(3,1)                  AS max_open_cvss,
    COALESCE(ov.avg_open_cvss, 0)::numeric(4,2)                  AS avg_open_cvss,
    ROUND(a.importance_level * COALESCE(ov.max_open_cvss, 0), 1) AS risk_score,
    CASE
        WHEN a.importance_level * COALESCE(ov.max_open_cvss, 0) >= 40 THEN 'CRITICAL'
        WHEN a.importance_level * COALESCE(ov.max_open_cvss, 0) >= 24 THEN 'HIGH'
        WHEN a.importance_level * COALESCE(ov.max_open_cvss, 0) >= 10 THEN 'MEDIUM'
        ELSE 'LOW'
    END AS risk_label
FROM assets a
LEFT JOIN open_vuln ov ON ov.asset_id = a.asset_id;

COMMENT ON VIEW vw_asset_risk_score IS
    '자산 중요도(importance_level) x 미해결 취약점 최대 CVSS 로 계산한 위험도 점수/라벨';

-- RBAC role 들도 조회할 수 있도록 SELECT 권한 부여
GRANT SELECT ON vw_asset_risk_score TO security_analyst, security_manager, security_admin;

-- -----------------------------
-- 테스트
-- -----------------------------
\echo '--- [TEST] 자산별 위험도 (risk_score 내림차순) ---'
SELECT asset_id, asset_name, department, importance_level AS imp,
       open_vuln_count AS open_vulns, max_open_cvss, risk_score, risk_label
FROM vw_asset_risk_score
ORDER BY risk_score DESC, asset_id;

\echo '--- [TEST] 라벨별 자산 수 ---'
SELECT risk_label, COUNT(*) AS asset_count
FROM vw_asset_risk_score
GROUP BY risk_label
ORDER BY MIN(risk_score) DESC;

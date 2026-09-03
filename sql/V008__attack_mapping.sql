-- =========================================================
-- 고도화 기능 6) MITRE ATT&CK 매핑
--   vulnerabilities 테이블에 ATT&CK tactic / technique 컬럼을 추가하고,
--   기존 4개 취약점에 Enterprise ATT&CK 용어로 매핑값을 채운다.
--
--   매핑 근거:
--     CVE-2025-0001 OpenSSL 원격 코드 실행
--         → Initial Access (TA0001) / T1190 Exploit Public-Facing Application
--     CVE-2025-0044 Apache 설정 오류로 인한 정보노출
--         → Reconnaissance (TA0043) / T1592 Gather Victim Host Information
--     CVE-2025-0099 DB 접근제어 우회
--         → Privilege Escalation (TA0004) / T1548 Abuse Elevation Control Mechanism
--     CVE-2025-0150 OS 커널 권한상승
--         → Privilege Escalation (TA0004) / T1068 Exploitation for Privilege Escalation
--
-- 기존 데이터 보존: ALTER TABLE ADD COLUMN IF NOT EXISTS 로 컬럼만 추가하고
-- 기존 4개 행을 UPDATE 로 채운다(행 삭제/재삽입 없음). 재실행 안전.
-- =========================================================

ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS attack_tactic          VARCHAR(40);
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS attack_tactic_id       VARCHAR(10);
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS attack_technique       VARCHAR(10);
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS attack_technique_name  VARCHAR(80);

COMMENT ON COLUMN vulnerabilities.attack_tactic         IS 'MITRE ATT&CK Enterprise Tactic 명칭';
COMMENT ON COLUMN vulnerabilities.attack_tactic_id      IS 'ATT&CK Tactic ID (예: TA0004)';
COMMENT ON COLUMN vulnerabilities.attack_technique      IS 'ATT&CK Technique ID (예: T1068)';
COMMENT ON COLUMN vulnerabilities.attack_technique_name IS 'ATT&CK Technique 명칭';

UPDATE vulnerabilities SET
    attack_tactic         = 'Initial Access',
    attack_tactic_id      = 'TA0001',
    attack_technique      = 'T1190',
    attack_technique_name = 'Exploit Public-Facing Application'
WHERE cve_id = 'CVE-2025-0001';

UPDATE vulnerabilities SET
    attack_tactic         = 'Reconnaissance',
    attack_tactic_id      = 'TA0043',
    attack_technique      = 'T1592',
    attack_technique_name = 'Gather Victim Host Information'
WHERE cve_id = 'CVE-2025-0044';

UPDATE vulnerabilities SET
    attack_tactic         = 'Privilege Escalation',
    attack_tactic_id      = 'TA0004',
    attack_technique      = 'T1548',
    attack_technique_name = 'Abuse Elevation Control Mechanism'
WHERE cve_id = 'CVE-2025-0099';

UPDATE vulnerabilities SET
    attack_tactic         = 'Privilege Escalation',
    attack_tactic_id      = 'TA0004',
    attack_technique      = 'T1068',
    attack_technique_name = 'Exploitation for Privilege Escalation'
WHERE cve_id = 'CVE-2025-0150';

-- -----------------------------
-- 테스트
-- -----------------------------
\echo '--- [TEST] 취약점별 ATT&CK 매핑 현황 ---'
SELECT vuln_id, cve_id, severity, cvss_score,
       attack_tactic_id, attack_tactic, attack_technique, attack_technique_name
FROM vulnerabilities
ORDER BY vuln_id;

\echo '--- [TEST] ATT&CK Tactic 별 취약점 분포 (GROUP BY) ---'
SELECT attack_tactic_id,
       attack_tactic,
       COUNT(*)                                                   AS vuln_count,
       ROUND(AVG(cvss_score), 1)                                  AS avg_cvss,
       MAX(cvss_score)                                            AS max_cvss,
       STRING_AGG(cve_id || ' / ' || attack_technique, ', '
                  ORDER BY vuln_id)                               AS cves_techniques
FROM vulnerabilities
WHERE attack_tactic IS NOT NULL
GROUP BY attack_tactic_id, attack_tactic
ORDER BY vuln_count DESC, attack_tactic_id;

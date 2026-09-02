-- =========================================================
-- 보안 이벤트 / 취약점 관리 시스템 - 프로젝트 스타터 스크립트
-- DBMS: PostgreSQL
-- 실행 순서: 1) DB 생성 -> 2) 이 파일 전체 실행 -> 3) 하단 예제 쿼리로 확인
-- =========================================================

-- -----------------------------
-- 0) 데이터베이스 생성 (최초 1회, psql에서 실행)
-- -----------------------------
-- CREATE DATABASE security_db;
-- \c security_db

-- -----------------------------
-- 1) 기존 테이블 정리 (재실행 대비)
-- -----------------------------
DROP TABLE IF EXISTS responses CASCADE;
DROP TABLE IF EXISTS security_events CASCADE;
DROP TABLE IF EXISTS asset_vulnerabilities CASCADE;
DROP TABLE IF EXISTS vulnerabilities CASCADE;
DROP TABLE IF EXISTS assets CASCADE;
DROP TABLE IF EXISTS staff CASCADE;

-- -----------------------------
-- 2) 강한 개체(독립 엔티티) 먼저 생성
-- -----------------------------

-- 자산 (서버, 네트워크 장비, 애플리케이션 등)
CREATE TABLE assets (
    asset_id        SERIAL PRIMARY KEY,
    asset_name      VARCHAR(100) NOT NULL,
    asset_type      VARCHAR(30)  NOT NULL
                     CHECK (asset_type IN ('SERVER','NETWORK','APPLICATION','DATABASE','ENDPOINT')),
    ip_address      VARCHAR(45),
    department      VARCHAR(50),
    importance_level SMALLINT NOT NULL DEFAULT 3
                     CHECK (importance_level BETWEEN 1 AND 5),  -- 1=낮음 5=매우높음
    created_at      TIMESTAMP NOT NULL DEFAULT now()
);

-- 담당자 (보안 분석가 / 대응 담당자)
CREATE TABLE staff (
    staff_id    SERIAL PRIMARY KEY,
    staff_name  VARCHAR(50) NOT NULL,
    department  VARCHAR(50),
    role        VARCHAR(30) CHECK (role IN ('ANALYST','ADMIN','MANAGER'))
);

-- 취약점 (CVE 기준)
CREATE TABLE vulnerabilities (
    vuln_id         SERIAL PRIMARY KEY,
    cve_id          VARCHAR(20) UNIQUE,          -- 예: CVE-2025-12345
    description     TEXT,
    cvss_score      NUMERIC(3,1) CHECK (cvss_score BETWEEN 0 AND 10),
    severity        VARCHAR(10) NOT NULL
                     CHECK (severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
    published_date  DATE
);

-- -----------------------------
-- 3) 다대다 관계 (자산 <-> 취약점)
-- -----------------------------
CREATE TABLE asset_vulnerabilities (
    asset_id        INT NOT NULL REFERENCES assets(asset_id),
    vuln_id         INT NOT NULL REFERENCES vulnerabilities(vuln_id),
    detected_date   DATE NOT NULL DEFAULT CURRENT_DATE,
    status          VARCHAR(15) NOT NULL DEFAULT 'OPEN'
                     CHECK (status IN ('OPEN','PATCHED','ACCEPTED_RISK')),
    PRIMARY KEY (asset_id, vuln_id)
);

-- -----------------------------
-- 4) 보안 이벤트 (자산 + 취약점을 참조하는 이력성 데이터)
-- -----------------------------
CREATE TABLE security_events (
    event_id     SERIAL PRIMARY KEY,
    asset_id     INT NOT NULL REFERENCES assets(asset_id),
    vuln_id      INT REFERENCES vulnerabilities(vuln_id),  -- 취약점이 원인이 아닐 수도 있어 NULL 허용
    event_type   VARCHAR(30) NOT NULL,           -- 예: 침입시도, 악성코드탐지, 비정상접근
    severity     VARCHAR(10) NOT NULL
                 CHECK (severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
    detected_at  TIMESTAMP NOT NULL DEFAULT now(),
    status       VARCHAR(15) NOT NULL DEFAULT 'OPEN'
                 CHECK (status IN ('OPEN','IN_PROGRESS','RESOLVED'))
);

-- -----------------------------
-- 5) 대응 조치 (이벤트 처리 이력)
-- -----------------------------
CREATE TABLE responses (
    response_id   SERIAL PRIMARY KEY,
    event_id      INT NOT NULL REFERENCES security_events(event_id),
    staff_id      INT NOT NULL REFERENCES staff(staff_id),
    action_taken  TEXT NOT NULL,
    action_date   TIMESTAMP NOT NULL DEFAULT now(),
    status        VARCHAR(15) NOT NULL DEFAULT 'IN_PROGRESS'
                  CHECK (status IN ('IN_PROGRESS','COMPLETED'))
);

-- =========================================================
-- 6) 샘플 데이터
-- =========================================================

INSERT INTO assets (asset_name, asset_type, ip_address, department, importance_level) VALUES
('웹서버-01', 'SERVER', '10.0.1.11', '인프라팀', 5),
('사내DB서버', 'DATABASE', '10.0.1.20', '인프라팀', 5),
('사용자포털', 'APPLICATION', '10.0.2.15', '개발팀', 4),
('방화벽-메인', 'NETWORK', '10.0.0.1', '인프라팀', 5),
('직원노트북-023', 'ENDPOINT', '192.168.10.23', '영업팀', 2);

INSERT INTO staff (staff_name, department, role) VALUES
('김보안', '보안팀', 'ANALYST'),
('이관리', '보안팀', 'ADMIN'),
('박팀장', '보안팀', 'MANAGER');

INSERT INTO vulnerabilities (cve_id, description, cvss_score, severity, published_date) VALUES
('CVE-2025-0001', 'OpenSSL 원격 코드 실행 취약점', 9.8, 'CRITICAL', '2025-01-15'),
('CVE-2025-0044', 'Apache 설정 오류로 인한 정보노출', 6.5, 'MEDIUM', '2025-03-02'),
('CVE-2025-0099', 'DB 접근제어 우회 취약점', 8.1, 'HIGH', '2025-04-20'),
('CVE-2025-0150', 'OS 커널 권한상승 취약점', 7.8, 'HIGH', '2025-05-10');

INSERT INTO asset_vulnerabilities (asset_id, vuln_id, detected_date, status) VALUES
(1, 1, '2025-02-01', 'OPEN'),
(1, 2, '2025-03-05', 'PATCHED'),
(2, 3, '2025-04-25', 'OPEN'),
(4, 4, '2025-05-15', 'OPEN'),
(3, 2, '2025-03-06', 'OPEN');

INSERT INTO security_events (asset_id, vuln_id, event_type, severity, detected_at, status) VALUES
(1, 1, '침입시도', 'CRITICAL', '2025-02-02 09:15:00', 'RESOLVED'),
(2, 3, '비정상접근', 'HIGH', '2025-04-26 14:20:00', 'IN_PROGRESS'),
(4, 4, '권한상승시도', 'HIGH', '2025-05-16 03:40:00', 'OPEN'),
(5, NULL, '악성코드탐지', 'MEDIUM', '2025-06-01 11:00:00', 'OPEN');

INSERT INTO responses (event_id, staff_id, action_taken, action_date, status) VALUES
(1, 1, '방화벽 룰 추가 및 패치 적용', '2025-02-02 11:00:00', 'COMPLETED'),
(2, 2, '접근 로그 분석 중, 계정 임시 잠금', '2025-04-26 15:00:00', 'IN_PROGRESS');

-- =========================================================
-- 7) 뷰 (SQL II / 뷰 파트에서 다루는 내용 미리 적용)
-- =========================================================

-- 미해결 고위험 이벤트만 보여주는 뷰
CREATE OR REPLACE VIEW vw_open_high_risk_events AS
SELECT e.event_id, a.asset_name, e.event_type, e.severity, e.detected_at
FROM security_events e
JOIN assets a ON a.asset_id = e.asset_id
WHERE e.status <> 'RESOLVED' AND e.severity IN ('HIGH','CRITICAL');

-- 자산별 취약점 현황 요약 뷰
CREATE OR REPLACE VIEW vw_asset_vuln_summary AS
SELECT a.asset_id, a.asset_name,
       COUNT(*) FILTER (WHERE av.status = 'OPEN') AS open_vuln_count,
       COUNT(*) AS total_vuln_count
FROM assets a
JOIN asset_vulnerabilities av ON av.asset_id = a.asset_id
GROUP BY a.asset_id, a.asset_name;

-- =========================================================
-- 8) 확인용 예제 쿼리 (SQL 실력 보여주기 좋은 것들)
-- =========================================================

-- (1) 자산별 미해결 취약점 개수 (GROUP BY + HAVING)
-- SELECT a.asset_name, COUNT(*) AS open_count
-- FROM assets a
-- JOIN asset_vulnerabilities av ON av.asset_id = a.asset_id
-- WHERE av.status = 'OPEN'
-- GROUP BY a.asset_name
-- HAVING COUNT(*) >= 1
-- ORDER BY open_count DESC;

-- (2) 가장 취약점이 많은 자산 (서브쿼리)
-- SELECT asset_name FROM assets
-- WHERE asset_id = (
--     SELECT asset_id FROM asset_vulnerabilities
--     GROUP BY asset_id ORDER BY COUNT(*) DESC LIMIT 1
-- );

-- (3) 담당자별 처리 실적
-- SELECT s.staff_name, COUNT(*) AS handled_count
-- FROM responses r
-- JOIN staff s ON s.staff_id = r.staff_id
-- GROUP BY s.staff_name;

-- (4) 뷰 조회
-- SELECT * FROM vw_open_high_risk_events;
-- SELECT * FROM vw_asset_vuln_summary;

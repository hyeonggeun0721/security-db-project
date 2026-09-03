-- =========================================================
-- 보완 1) 핵심 테이블 샘플 데이터 확충
--
--   원본 스키마(security_db_starter.sql / vector_search_addon.sql)와
--   고도화 6개 파일의 "구조"는 전혀 건드리지 않는다. 이 파일은 데이터 INSERT 와
--   신규 vulnerabilities 행에 대한 ATT&CK 컬럼 채움(UPDATE 상당 = 데이터)만 수행한다.
--
--   확장 규모:
--     assets                 5  -> 14   (부서/유형/중요도 다양화)
--     staff                  3  ->  6   (부서 다양화)
--     vulnerabilities        4  -> 12   (CVSS/심각도 분포 + ATT&CK 매핑 포함)
--     asset_vulnerabilities  5  -> 25   (OPEN/PATCHED/ACCEPTED_RISK 혼합)
--     security_events        4  -> 30   (상시 급증 시나리오 2건 포함)
--     responses              2  -> 18
--
--   security_events 급증 시나리오(임시 아님, 상시 데이터):
--     - asset_id 8 (결제API서버): 2025-08-14 02:05~05:20 사이 8건 집중
--     - asset_id 2 (사내DB서버) : 2025-09-01 22:10~23:50 사이 5건 집중
--
--   전체를 하나의 트랜잭션으로 적재한다(부분 적재 방지).
--   ※ 이 파일은 1회성 적재 스크립트다(INSERT 에 존재검사 없음). 이미 적재된
--     DB 에 다시 실행하면 PK/UNIQUE 위반으로 트랜잭션이 통째로 롤백된다.
-- =========================================================

BEGIN;

-- 과거 검증 과정에서 responses 시퀀스가 앞서 있으므로 현재 최대값으로 정렬
SELECT setval('responses_response_id_seq', (SELECT MAX(response_id) FROM responses));

-- -----------------------------------------------------------
-- 1) assets : +9건 (asset_id 6~14)
-- -----------------------------------------------------------
INSERT INTO assets (asset_name, asset_type, ip_address, department, importance_level) VALUES
    ('메일서버-01',            'SERVER',      '10.0.1.30',     'IT운영팀',    4),
    ('VPN게이트웨이',          'NETWORK',     '10.0.0.2',      '인프라팀',    5),
    ('결제API서버',            'APPLICATION', '10.0.2.20',     '개발팀',      5),
    ('백업스토리지',           'DATABASE',    '10.0.1.40',     '인프라팀',    4),
    ('인사관리시스템',         'APPLICATION', '10.0.3.10',     '인사팀',      3),
    ('재무DB서버',             'DATABASE',    '10.0.3.20',     '재무팀',      5),
    ('개발자워크스테이션-07',  'ENDPOINT',    '192.168.20.7',  '개발팀',      2),
    ('콜센터단말-14',          'ENDPOINT',    '192.168.30.14', '고객지원팀',  2),
    ('로그수집서버',           'SERVER',      '10.0.1.50',     '보안팀',      4);

-- -----------------------------------------------------------
-- 2) staff : +3건 (staff_id 4~6)
-- -----------------------------------------------------------
INSERT INTO staff (staff_name, department, role) VALUES
    ('정분석', '보안팀',    'ANALYST'),
    ('최대응', 'IT운영팀',  'ANALYST'),
    ('한관리', '인프라팀',  'ADMIN');

-- -----------------------------------------------------------
-- 3) vulnerabilities : +8건 (vuln_id 5~12) — ATT&CK 매핑도 함께 채움
-- -----------------------------------------------------------
INSERT INTO vulnerabilities
    (cve_id, description, cvss_score, severity, published_date,
     attack_tactic, attack_tactic_id, attack_technique, attack_technique_name) VALUES
    ('CVE-2025-0210', 'JNDI 조회를 악용한 원격 코드 실행 (Log4j 계열)', 9.6, 'CRITICAL', '2025-02-20',
     'Initial Access',      'TA0001', 'T1190', 'Exploit Public-Facing Application'),
    ('CVE-2025-0255', 'SQL 인젝션을 통한 인증 우회',                    8.6, 'HIGH',     '2025-03-11',
     'Credential Access',   'TA0006', 'T1212', 'Exploitation for Credential Access'),
    ('CVE-2025-0301', '약한 자격증명 정책으로 SSH 무차별 대입 허용',   7.5, 'HIGH',     '2025-03-25',
     'Credential Access',   'TA0006', 'T1110', 'Brute Force'),
    ('CVE-2025-0333', '구형 TLS 1.0 지원으로 중간자 공격 노출',        5.9, 'MEDIUM',   '2025-04-02',
     'Collection',          'TA0009', 'T1557', 'Adversary-in-the-Middle'),
    ('CVE-2025-0378', '컨테이너 격리 탈출 취약점',                     8.8, 'HIGH',     '2025-04-15',
     'Privilege Escalation','TA0004', 'T1611', 'Escape to Host'),
    ('CVE-2025-0412', '관리자 페이지 인증 없이 접근 가능',             9.1, 'CRITICAL', '2025-05-01',
     'Initial Access',      'TA0001', 'T1190', 'Exploit Public-Facing Application'),
    ('CVE-2025-0450', '저장형 XSS로 세션 토큰 탈취',                   6.1, 'MEDIUM',   '2025-05-18',
     'Credential Access',   'TA0006', 'T1539', 'Steal Web Session Cookie'),
    ('CVE-2025-0491', '상세 오류 메시지로 내부 경로/버전 정보 노출',   3.7, 'LOW',      '2025-06-05',
     'Reconnaissance',      'TA0043', 'T1592', 'Gather Victim Host Information');

-- -----------------------------------------------------------
-- 4) asset_vulnerabilities : +20건 (총 25건, 상태 혼합)
-- -----------------------------------------------------------
INSERT INTO asset_vulnerabilities (asset_id, vuln_id, detected_date, status) VALUES
    ( 2,  1, '2025-02-10', 'PATCHED'),
    ( 2,  6, '2025-03-15', 'OPEN'),
    ( 3,  5, '2025-02-25', 'OPEN'),
    ( 3, 10, '2025-05-20', 'ACCEPTED_RISK'),
    ( 4,  7, '2025-03-28', 'OPEN'),
    ( 5, 12, '2025-06-10', 'OPEN'),
    ( 6,  3, '2025-04-22', 'OPEN'),
    ( 6,  8, '2025-04-10', 'PATCHED'),
    ( 7,  7, '2025-03-30', 'OPEN'),
    ( 7,  4, '2025-05-12', 'OPEN'),
    ( 8,  5, '2025-02-28', 'OPEN'),
    ( 8,  6, '2025-03-18', 'OPEN'),
    ( 8,  9, '2025-04-18', 'OPEN'),
    ( 9,  1, '2025-02-15', 'ACCEPTED_RISK'),
    (10, 11, '2025-05-22', 'OPEN'),
    (11,  3, '2025-04-25', 'OPEN'),
    (11, 10, '2025-05-05', 'PATCHED'),
    (12,  9, '2025-04-20', 'OPEN'),
    (13, 11, '2025-05-25', 'ACCEPTED_RISK'),
    (14,  2, '2025-03-08', 'PATCHED');

-- -----------------------------------------------------------
-- 5) security_events : +26건 (event_id 5~30)
--    5~17  : 여러 자산/기간에 흩어진 정상 베이스라인
--    18~25 : [급증 A] asset_id 8, 2025-08-14 새벽 3시간여 8건
--    26~30 : [급증 B] asset_id 2, 2025-09-01 야간 2시간 내 5건
-- -----------------------------------------------------------
INSERT INTO security_events (asset_id, vuln_id, event_type, severity, detected_at, status) VALUES
    ( 3,  5, '웹취약점스캔',    'MEDIUM',   '2025-03-01 10:00:00', 'RESOLVED'),
    ( 6, NULL,'스팸대량수신',    'LOW',      '2025-04-05 08:30:00', 'RESOLVED'),
    ( 7,  7, '무차별대입시도',  'HIGH',     '2025-04-12 19:20:00', 'RESOLVED'),
    ( 1,  1, '악성코드탐지',    'HIGH',     '2025-04-20 13:00:00', 'RESOLVED'),
    ( 9, NULL,'비정상접근',      'MEDIUM',   '2025-05-03 04:10:00', 'OPEN'),
    (10, 11, '피싱메일보고',    'MEDIUM',   '2025-05-15 09:45:00', 'RESOLVED'),
    (11,  3, '비정상접근',      'HIGH',     '2025-05-28 16:30:00', 'IN_PROGRESS'),
    (12,  9, '권한상승시도',    'HIGH',     '2025-06-08 11:15:00', 'IN_PROGRESS'),
    (13, 11, '악성코드탐지',    'MEDIUM',   '2025-06-22 14:50:00', 'RESOLVED'),
    ( 4,  7, '정책위반',        'LOW',      '2025-07-01 17:00:00', 'RESOLVED'),
    (14,  2, '로그위변조시도',  'HIGH',     '2025-07-19 03:25:00', 'IN_PROGRESS'),
    ( 5, 12, '악성코드탐지',    'MEDIUM',   '2025-07-30 12:00:00', 'IN_PROGRESS'),
    ( 8,  5, '웹취약점스캔',    'MEDIUM',   '2025-08-02 15:30:00', 'RESOLVED'),
    -- [급증 A] asset_id 8
    ( 8,  6, '비정상접근',      'HIGH',     '2025-08-14 02:05:00', 'RESOLVED'),
    ( 8,  6, '비정상접근',      'HIGH',     '2025-08-14 02:32:00', 'OPEN'),
    ( 8,  9, '권한상승시도',    'CRITICAL', '2025-08-14 03:01:00', 'RESOLVED'),
    ( 8,  5, '침입시도',        'HIGH',     '2025-08-14 03:20:00', 'OPEN'),
    ( 8,  6, '비정상접근',      'HIGH',     '2025-08-14 03:55:00', 'OPEN'),
    ( 8,  9, '권한상승시도',    'CRITICAL', '2025-08-14 04:18:00', 'IN_PROGRESS'),
    ( 8,  5, '데이터유출시도',  'CRITICAL', '2025-08-14 04:47:00', 'IN_PROGRESS'),
    ( 8,  6, '비정상접근',      'HIGH',     '2025-08-14 05:20:00', 'IN_PROGRESS'),
    -- [급증 B] asset_id 2
    ( 2,  3, '비정상접근',      'HIGH',     '2025-09-01 22:10:00', 'RESOLVED'),
    ( 2,  3, '권한상승시도',    'HIGH',     '2025-09-01 22:38:00', 'OPEN'),
    ( 2,  1, '침입시도',        'CRITICAL', '2025-09-01 23:05:00', 'IN_PROGRESS'),
    ( 2,  3, '비정상접근',      'HIGH',     '2025-09-01 23:29:00', 'IN_PROGRESS'),
    ( 2,  3, '비정상접근',      'MEDIUM',   '2025-09-01 23:50:00', 'IN_PROGRESS');

-- -----------------------------------------------------------
-- 6) responses : +16건 (response_id 3~18) — 확장된 이벤트에 연결
-- -----------------------------------------------------------
INSERT INTO responses (event_id, staff_id, action_taken, action_date, status) VALUES
    ( 3, 1, '방화벽 룰 추가 및 소스 IP 차단',                  '2025-05-16 05:00:00', 'COMPLETED'),
    ( 5, 4, '스캐너 IP 차단, WAF 시그니처 업데이트',           '2025-03-01 12:00:00', 'COMPLETED'),
    ( 7, 5, '계정 잠금 정책 강화(실패 임계치 하향)',           '2025-04-12 21:00:00', 'COMPLETED'),
    ( 8, 1, 'EDR 격리 후 단말 재이미징',                       '2025-04-20 15:30:00', 'COMPLETED'),
    (10, 4, '피싱 메일 회수, 전사 주의 공지 및 교육',          '2025-05-15 11:00:00', 'COMPLETED'),
    (11, 2, 'DB 접근 계정 점검, 의심 계정 임시 비활성화',      '2025-05-28 18:00:00', 'IN_PROGRESS'),
    (12, 6, '커널 패치 변경관리 등록, 유지보수 창 배정',       '2025-06-09 10:00:00', 'IN_PROGRESS'),
    (15, 1, '로그 무결성 검증, 원격 로깅 서버로 전환',         '2025-07-19 06:00:00', 'IN_PROGRESS'),
    (18, 1, '결제API 서버 비정상 접근 인지, 모니터링 강화',    '2025-08-14 02:40:00', 'COMPLETED'),
    (20, 2, '권한상승 시도 확인, 관리자 세션 강제 종료',       '2025-08-14 03:30:00', 'COMPLETED'),
    (23, 4, '침해지표(IOC) 수집, 네트워크 세그먼트 격리',      '2025-08-14 04:40:00', 'IN_PROGRESS'),
    (24, 2, '데이터 유출 정황 조사, DLP 룰 긴급 적용',         '2025-08-14 05:10:00', 'IN_PROGRESS'),
    (25, 1, '결제API 서버 격리 및 포렌식 이미지 확보',         '2025-08-14 06:00:00', 'IN_PROGRESS'),
    (26, 5, 'DB서버 야간 비정상 접근 대응 착수, 접근 차단',    '2025-09-01 22:30:00', 'COMPLETED'),
    (28, 2, '침입시도 소스 IP 차단, 서비스 계정 자격증명 회전','2025-09-01 23:20:00', 'IN_PROGRESS'),
    (29, 1, 'DB 쿼리 감사 로깅 활성화, 이상 쿼리 패턴 분석',   '2025-09-02 00:15:00', 'IN_PROGRESS');

COMMIT;

-- =========================================================
-- 검증
-- =========================================================
\echo ''
\echo '################ 테이블별 건수 ################'
SELECT 'assets' AS table_name, count(*) FROM assets
UNION ALL SELECT 'staff',                 count(*) FROM staff
UNION ALL SELECT 'vulnerabilities',       count(*) FROM vulnerabilities
UNION ALL SELECT 'asset_vulnerabilities', count(*) FROM asset_vulnerabilities
UNION ALL SELECT 'security_events',       count(*) FROM security_events
UNION ALL SELECT 'responses',             count(*) FROM responses
UNION ALL SELECT 'threat_reports',        count(*) FROM threat_reports
ORDER BY table_name;

\echo ''
\echo '################ asset_vulnerabilities 상태 분포 ################'
SELECT status, count(*) FROM asset_vulnerabilities GROUP BY status ORDER BY status;

\echo ''
\echo '################ vulnerabilities 심각도 분포 ################'
SELECT severity, count(*), min(cvss_score) AS min_cvss, max(cvss_score) AS max_cvss
FROM vulnerabilities GROUP BY severity ORDER BY max_cvss;

\echo ''
\echo '################ [고도화3] vw_asset_risk_score (위험도 내림차순) ################'
SELECT asset_id, asset_name, department, importance_level AS imp,
       open_vuln_count AS open_v, max_open_cvss, risk_score, risk_label
FROM vw_asset_risk_score ORDER BY risk_score DESC, asset_id;

\echo ''
\echo '################ [스타터뷰] vw_open_high_risk_events ################'
SELECT * FROM vw_open_high_risk_events ORDER BY detected_at;

\echo ''
\echo '################ [스타터뷰] vw_asset_vuln_summary ################'
SELECT * FROM vw_asset_vuln_summary ORDER BY open_vuln_count DESC, asset_id;

\echo ''
\echo '################ [고도화6] ATT&CK Tactic 분포 (신규 취약점 포함 12건) ################'
SELECT attack_tactic_id, attack_tactic, count(*) AS vuln_count,
       round(avg(cvss_score),1) AS avg_cvss
FROM vulnerabilities
GROUP BY attack_tactic_id, attack_tactic
ORDER BY vuln_count DESC, attack_tactic_id;

\echo ''
\echo '################ [고도화5-A] 24시간 롤링 윈도우 급증 경보 (>=4건) : 상시 데이터 ################'
SELECT s.asset_id, s.asset_name, s.event_id, s.detected_at, s.events_last_24h, s.gap_from_prev
FROM (
    SELECT e.asset_id, a.asset_name, e.event_id, e.detected_at,
           COUNT(*) OVER w AS events_last_24h,
           e.detected_at - LAG(e.detected_at) OVER (PARTITION BY e.asset_id ORDER BY e.detected_at) AS gap_from_prev
    FROM security_events e
    JOIN assets a ON a.asset_id = e.asset_id
    WINDOW w AS (PARTITION BY e.asset_id ORDER BY e.detected_at
                 RANGE BETWEEN INTERVAL '24 hours' PRECEDING AND CURRENT ROW)
) s
WHERE s.events_last_24h >= 4
ORDER BY s.events_last_24h DESC, s.detected_at;

\echo ''
\echo '################ [고도화5-B] 일일 이벤트 수 vs 직전 7일 이동평균 (delta 큰 날 = 급증일) ################'
-- 윈도우(이동평균)를 먼저 계산한 뒤 바깥에서 필터해야 이동평균이 정확하다.
WITH daily AS (
    SELECT asset_id, date_trunc('day', detected_at)::date AS day, COUNT(*) AS daily_cnt
    FROM security_events GROUP BY asset_id, date_trunc('day', detected_at)::date
),
scored AS (
    SELECT d.asset_id, d.day, d.daily_cnt,
           AVG(d.daily_cnt) OVER (PARTITION BY d.asset_id ORDER BY d.day
                 ROWS BETWEEN 7 PRECEDING AND 1 PRECEDING) AS trailing_7d_avg
    FROM daily d
)
SELECT s.asset_id, a.asset_name, s.day, s.daily_cnt,
       ROUND(s.trailing_7d_avg, 2) AS trailing_7d_avg,
       ROUND(s.daily_cnt - COALESCE(s.trailing_7d_avg, 0), 2) AS delta_vs_avg
FROM scored s JOIN assets a ON a.asset_id = s.asset_id
WHERE s.daily_cnt >= 3          -- 하루 3건 이상인 날만 급증 후보로 표시
ORDER BY delta_vs_avg DESC, s.asset_id, s.day;

\echo ''
\echo '################ [고도화1] 대량 적재로 트리거가 audit_log 를 채웠는지 확인 후 정리 ################'
SELECT table_name, operation, count(*) AS n FROM audit_log GROUP BY table_name, operation ORDER BY table_name, operation;
-- 적재 이력은 실제 "사고 대응 감사"가 아니므로 깨끗한 상태로 초기화(신규 테이블이라 안전)
TRUNCATE audit_log RESTART IDENTITY;
SELECT count(*) AS audit_log_rows_after_reset FROM audit_log;

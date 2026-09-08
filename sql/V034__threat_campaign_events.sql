-- =========================================================
-- V034) threat_reports 5개 주제 커버리지 확보 + 실제 이벤트 표본 확충
--
--   배경: security_events 의 "실제(non-SIM)" 이벤트가 30건뿐이라 V033 매칭 품질
--   검증 표본이 부족했다. 또 threat_reports 8건 중 3(랜섬웨어), 5(피싱 자격증명
--   탈취), 6(DDoS), 7(클라우드 버킷 오설정), 8(공급망 공격)은 related_event_id 가
--   NULL 이라, 대응까지 이어진 큐레이션 이벤트가 하나도 없었다.
--
--   이 파일이 하는 일 (데이터만, 스키마 변경 없음):
--     1) 실제 보안 이벤트 12건 INSERT
--        - 리포트 3/5/6/7/8 캠페인 이벤트 8건 (각자 다른 자산/시각, 문장 전부 상이)
--        - 특정 리포트와 안 엮이는 일반 이벤트 4건 (표본 다양화)
--        - [SIM] 접두사 없음. vuln_id 는 실제 관련 있을 때만 연결.
--     2) 각 이벤트의 실제 대응 responses 12건 INSERT
--        (action_date 는 V028 트리거 때문에 반드시 event.detected_at 이후)
--     3) threat_reports.related_event_id 를 report 3/5/6/7/8 각각에 대해
--        해당 캠페인의 최초 탐지 이벤트로 UPDATE (지금 NULL 인 것을 실제 연결)
--
--   전체를 하나의 트랜잭션으로 적재한다.
--   ※ 1회성 적재. detected_at/description 이 고정이라 재실행하면 임베딩·매칭
--     스크립트(event_threat_linker.py)는 멱등이지만, 이 파일 자체는 재실행 시
--     동일 이벤트가 중복 INSERT 된다(migrate.py 가 1회만 실행하므로 문제 없음).
--
--   detected_at 분산: 2026-08-25 ~ 2026-09-07 (최근 수 주). 캠페인 내부는 시간순.
-- =========================================================

BEGIN;

-- 임베딩/매칭 스크립트가 나중에 채우므로 embedding 은 넣지 않는다.
CREATE TEMP TABLE _v034_ev (tag text PRIMARY KEY, event_id int) ON COMMIT DROP;

-- -----------------------------------------------------------
-- 1) security_events 12건
--    tag 규칙: A*=랜섬웨어(rpt3), B*=피싱(rpt5), C1=DDoS(rpt6),
--             D1=클라우드버킷(rpt7), E1=공급망(rpt8), G*=일반(무연결)
-- -----------------------------------------------------------
WITH v(tag, asset_id, vuln_id, event_type, severity, detected_at, status, description) AS (
    VALUES
    -- [랜섬웨어 캠페인] report_id=3
    ('A1', 6, NULL::int, '악성코드탐지',   'HIGH',     TIMESTAMPTZ '2026-08-25 08:40+09', 'RESOLVED',
        '메일서버-01 로 수신된 피싱 메일 첨부파일 실행 후 최초 침투 정황 포착, 첨부 실행 직후 의심 프로세스가 기동됨'),
    ('A2', 5, 4,        '권한상승시도',   'HIGH',     TIMESTAMPTZ '2026-08-25 11:20+09', 'RESOLVED',
        '직원노트북-023 에서 로컬 권한 상승 시도 및 커널 익스플로잇 흔적 발견, 위 침투 건과 동일 공격자 소행으로 판단'),
    ('A3', 2, NULL,     '악성코드탐지',   'CRITICAL', TIMESTAMPTZ '2026-08-25 14:05+09', 'RESOLVED',
        '사내DB서버 로 내부 이동(lateral movement) 시도 탐지, 랜섬웨어 계열 행위 확인되어 자동 격리 조치'),
    -- [피싱 자격증명 탈취] report_id=5
    ('B1', 6, NULL,     '피싱메일보고',   'MEDIUM',   TIMESTAMPTZ '2026-08-30 10:15+09', 'RESOLVED',
        '다수 직원 대상 위장 로그인 페이지 유도 피싱 메일 캠페인이 메일서버-01 게이트웨이에서 일부 탐지·차단됨'),
    ('B2', 7, NULL,     '비정상접근',     'HIGH',     TIMESTAMPTZ '2026-08-31 03:30+09', 'IN_PROGRESS',
        'VPN게이트웨이 에서 위 피싱으로 탈취된 것으로 의심되는 계정의 비정상 재접속 시도 탐지'),
    -- [DDoS] report_id=6
    ('C1', 3, NULL,     '비정상접근',     'HIGH',     TIMESTAMPTZ '2026-09-02 16:45+09', 'RESOLVED',
        '사용자포털 대상으로 짧은 시간 내 비정상적으로 많은 요청이 유입되어 분산서비스거부(DDoS) 공격으로 판단됨'),
    -- [클라우드 버킷 오설정] report_id=7
    ('D1', 9, NULL,     '정책위반',       'HIGH',     TIMESTAMPTZ '2026-09-03 11:00+09', 'RESOLVED',
        '정기 점검 중 클라우드 스토리지 버킷 접근 권한이 외부 공개로 설정되어 있음을 발견'),
    -- [공급망 공격] report_id=8
    ('E1', 12, NULL,    '악성코드탐지',   'HIGH',     TIMESTAMPTZ '2026-09-05 09:30+09', 'RESOLVED',
        '빌드 파이프라인에서 사용하는 오픈소스 서드파티 패키지에서 의심스러운 코드 변경이 탐지됨'),
    -- [일반 - 특정 리포트 무연결] 표본 다양화
    ('G1', 8, 6,        '웹취약점스캔',   'MEDIUM',   TIMESTAMPTZ '2026-09-01 22:10+09', 'RESOLVED',
        '결제API서버 관리 콘솔 경로를 노린 자동화 취약점 스캐너 트래픽이 WAF 로그에서 확인됨, SQL 인젝션 및 인증 우회 페이로드 다수 포함'),
    ('G2', 7, 7,        '무차별대입시도', 'HIGH',     TIMESTAMPTZ '2026-09-04 02:50+09', 'RESOLVED',
        '새벽 시간대 VPN게이트웨이 SSH 서비스에 대해 사전 기반 비밀번호 대입이 분당 수백 회 규모로 반복됨'),
    ('G3', 13, NULL,    '정책위반',       'LOW',      TIMESTAMPTZ '2026-09-06 13:20+09', 'RESOLVED',
        '자산 실사에서 콜센터단말-14 에 승인되지 않은 원격제어 소프트웨어가 설치된 것이 확인됨'),
    ('G4', 14, NULL,    '로그위변조시도', 'HIGH',     TIMESTAMPTZ '2026-09-07 19:40+09', 'IN_PROGRESS',
        '로그수집서버의 감사 로그 일부 구간이 원본 해시와 불일치하여 보존 로그에 대한 위·변조 시도가 의심됨')
),
ins AS (
    INSERT INTO security_events (asset_id, vuln_id, event_type, severity, detected_at, status, description)
    SELECT asset_id, vuln_id, event_type, severity, detected_at, status, description FROM v
    RETURNING event_id, description
)
INSERT INTO _v034_ev (tag, event_id)
SELECT v.tag, ins.event_id
FROM ins JOIN v ON v.description = ins.description;

-- -----------------------------------------------------------
-- 2) responses 12건 (event 당 1건). action_date = 해당 event.detected_at + 오프셋.
--    V028 fn_validate_response_timing 이 action_date >= detected_at 를 강제.
-- -----------------------------------------------------------
WITH r(tag, staff_id, off_hours, status, action_taken) AS (
    VALUES
    ('A1', 1, 3.0,  'COMPLETED',   '감염 단말 네트워크 격리 및 메일 게이트웨이에서 동일 발신·첨부 해시 일괄 차단, 초기 침투 경로 분석 완료'),
    ('A2', 4, 4.0,  'COMPLETED',   '직원노트북-023 을 오프라인 격리 후 디스크 이미지 확보, 커널 패치 적용 및 계정 자격증명 회전'),
    ('A3', 2, 6.0,  'COMPLETED',   '사내DB서버 세션 강제 종료 및 스냅샷 롤백, 랜섬웨어 IOC 를 전사 배포하고 백업 무결성 검증 수행'),
    ('B1', 1, 5.0,  'COMPLETED',   '피싱 메일 전량 회수 및 위장 도메인 차단, 전사 비밀번호 초기화와 MFA 강제 적용을 공지'),
    ('B2', 5, 2.0,  'IN_PROGRESS', '해당 계정 즉시 비활성화 및 VPN 세션 종료, 접속 원본 IP 대역을 차단하고 추가 도용 계정 여부 조사 진행 중'),
    ('C1', 5, 1.5,  'COMPLETED',   '상단 CDN 에 트래픽 스크러빙과 레이트리밋 규칙을 적용, 비정상 소스 대역 필터링으로 정상 응답 복구'),
    ('D1', 6, 2.0,  'COMPLETED',   '버킷을 즉시 비공개로 전환하고 사전서명 URL 정책을 재수립, 최근 90일 접근 로그를 전수 검토'),
    ('E1', 4, 8.0,  'COMPLETED',   '문제 패키지를 직전 검증 버전으로 롤백하고 빌드 산출물 폐기, 파이프라인에 패키지 서명·해시 검증 단계를 추가'),
    ('G1', 1, 10.0, 'COMPLETED',   '스캐너 소스 IP 차단 및 WAF 시그니처 갱신, 결제 API 인증 우회 관련 입력 검증 로직을 재점검'),
    ('G2', 5, 3.0,  'COMPLETED',   '대상 계정 잠금 임계치 하향 및 소스 대역 차단, VPN 에 대한 MFA 적용 범위를 확대'),
    ('G3', 6, 24.0, 'COMPLETED',   '미승인 소프트웨어를 원격 제거하고 자산 표준 이미지를 재적용, 단말 소프트웨어 화이트리스트 정책을 배포'),
    ('G4', 2, 3.0,  'IN_PROGRESS', '원격 로깅 서버로 전환하고 해시 체인 재검증 수행 중, 변경 발생 구간의 OS·접근 로그를 상호 대조하는 중')
)
INSERT INTO responses (event_id, staff_id, action_taken, action_date, status)
SELECT n.event_id, r.staff_id, r.action_taken,
       e.detected_at + make_interval(mins => (r.off_hours * 60)::int),
       r.status
FROM r
JOIN _v034_ev n  ON n.tag = r.tag
JOIN security_events e ON e.event_id = n.event_id;

-- -----------------------------------------------------------
-- 3) threat_reports.related_event_id 연결 (지금 NULL -> 캠페인 최초 탐지 이벤트)
-- -----------------------------------------------------------
UPDATE threat_reports tr
SET related_event_id = n.event_id
FROM (VALUES (3,'A1'), (5,'B1'), (6,'C1'), (7,'D1'), (8,'E1')) AS m(report_id, tag)
JOIN _v034_ev n ON n.tag = m.tag
WHERE tr.report_id = m.report_id
  AND tr.related_event_id IS NULL;

COMMIT;

-- @migrate:verify
-- =========================================================
-- 검증
-- =========================================================
\echo ''
\echo '################ [1] 신규 이벤트 12건 (asset/type/vuln/status) ################'
SELECT e.event_id, a.asset_name, e.event_type, e.severity, e.status,
       e.detected_at, e.vuln_id, left(e.description, 42) AS description
FROM security_events e
JOIN assets a ON a.asset_id = e.asset_id
WHERE e.detected_at >= TIMESTAMPTZ '2026-08-25' AND e.description NOT LIKE '[SIM]%'
ORDER BY e.detected_at;

\echo ''
\echo '################ [2] 신규 responses 12건 - action_date >= detected_at 이어야 정상 ################'
SELECT r.response_id, r.event_id, s.staff_name, r.status,
       (r.action_date >= e.detected_at) AS timing_ok,
       r.action_date
FROM responses r
JOIN security_events e ON e.event_id = r.event_id
JOIN staff s ON s.staff_id = r.staff_id
WHERE e.detected_at >= TIMESTAMPTZ '2026-08-25' AND e.description NOT LIKE '[SIM]%'
ORDER BY r.event_id;

\echo ''
\echo '################ [3] threat_reports.related_event_id - 이제 8건 모두 연결돼야 정상 ################'
SELECT report_id, title, related_event_id,
       (related_event_id IS NOT NULL) AS linked
FROM threat_reports
ORDER BY report_id;

\echo ''
\echo '################ [4] 타이밍 위반 responses 수 (0 이어야 정상) ################'
SELECT count(*) AS timing_violations
FROM responses r
JOIN security_events e ON e.event_id = r.event_id
WHERE r.action_date < e.detected_at;

\echo ''
\echo '################ [5] 감사 해시체인 무결성 (0 행 = breaks 없음) ################'
SELECT * FROM fn_verify_audit_chain();

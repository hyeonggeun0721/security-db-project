-- =========================================================
-- 보완 3) 인덱스 전략 (indexes.sql)
--
--   PostgreSQL 은 PRIMARY KEY / UNIQUE 제약에는 인덱스를 자동 생성하지만,
--   FOREIGN KEY "참조하는 쪽" 컬럼에는 자동으로 만들어주지 않는다.
--   → 조인/필터에 자주 쓰이는 FK 컬럼에 수동으로 btree 인덱스를 추가한다.
--
--   부수 효과: 자식 테이블 FK 컬럼에 인덱스가 있으면 부모 행 UPDATE/DELETE 시
--   참조 무결성 검사가 Seq Scan 대신 Index Scan 으로 처리되어 잠금 시간이 짧아진다.
--
--   모든 인덱스는 CREATE INDEX IF NOT EXISTS 로 재실행 안전하게 만든다.
-- =========================================================

-- -----------------------------------------------------------
-- 1) FK 컬럼 인덱스
-- -----------------------------------------------------------

-- security_events.asset_id : "특정 자산의 이벤트 조회", assets 와의 조인,
--   이상탐지 쿼리의 PARTITION BY asset_id 에 사용. FK(assets) 자동 인덱스 없음.
CREATE INDEX IF NOT EXISTS idx_security_events_asset_id
    ON security_events (asset_id);

-- security_events.vuln_id : 취약점별 이벤트 집계, vulnerabilities 조인에 사용.
--   NULL 허용 FK 라 인덱스가 더더욱 유용(NULL 은 인덱스에서 건너뜀).
CREATE INDEX IF NOT EXISTS idx_security_events_vuln_id
    ON security_events (vuln_id);

-- responses.event_id : "이 이벤트에 달린 대응들" 조회, security_events 조인,
--   그리고 security_events 행 삭제/갱신 시 FK 검사에 사용.
CREATE INDEX IF NOT EXISTS idx_responses_event_id
    ON responses (event_id);

-- responses.staff_id : 담당자별 대응 실적 집계, staff 조인,
--   staff 행 삭제 시 FK 검사에 사용.
CREATE INDEX IF NOT EXISTS idx_responses_staff_id
    ON responses (staff_id);

-- asset_vulnerabilities : PK 가 (asset_id, vuln_id) 이므로 선두 컬럼 asset_id 는
--   PK 인덱스로 커버되지만, vuln_id 단독 조회("이 취약점을 가진 자산들")와
--   vulnerabilities 행 삭제 시 FK 검사는 커버되지 않는다.
CREATE INDEX IF NOT EXISTS idx_asset_vulnerabilities_vuln_id
    ON asset_vulnerabilities (vuln_id);

-- threat_reports.related_event_id : 보고서 ↔ 이벤트 연결 조회, security_events 조인.
--   NULL 이 많은 FK 라 부분 인덱스로 만들어 크기를 줄인다.
CREATE INDEX IF NOT EXISTS idx_threat_reports_related_event_id
    ON threat_reports (related_event_id)
    WHERE related_event_id IS NOT NULL;

-- -----------------------------------------------------------
-- 2) 조회 패턴 복합 인덱스
-- -----------------------------------------------------------

-- 이상탐지/타임라인 쿼리는 "특정 자산의 시간순 이벤트"를 본다.
--   (asset_id, detected_at) 복합 인덱스는 PARTITION BY asset_id ORDER BY detected_at,
--   그리고 asset_id = ? AND detected_at BETWEEN ? AND ? 범위 스캔을 한 번에 지원한다.
CREATE INDEX IF NOT EXISTS idx_security_events_asset_id_detected_at
    ON security_events (asset_id, detected_at);

-- vw_open_high_risk_events 는 status <> 'RESOLVED' AND severity IN ('HIGH','CRITICAL')
--   를 필터한다. 미해결 고위험 이벤트만 담는 부분 인덱스로 조회를 좁힌다.
CREATE INDEX IF NOT EXISTS idx_security_events_open_high_risk
    ON security_events (severity, detected_at)
    WHERE status <> 'RESOLVED';

ANALYZE security_events;
ANALYZE responses;
ANALYZE asset_vulnerabilities;
ANALYZE threat_reports;

-- -----------------------------------------------------------
-- 3) 생성된 인덱스 목록
-- -----------------------------------------------------------
\echo ''
\echo '################ 이 파일로 추가된 인덱스 ################'
SELECT tablename, indexname, indexdef
FROM pg_indexes
WHERE schemaname = 'public' AND indexname LIKE 'idx_%'
ORDER BY tablename, indexname;

-- =========================================================
-- 4) EXPLAIN ANALYZE 로 실행계획 비교
--
--   주의: 현재 샘플 데이터는 테이블당 수십 건뿐이라, 옵티마이저 입장에서는
--   전체를 훑는 Seq Scan 이 인덱스 조회보다 저렴하다고 판단하는 경우가 많다.
--   그래서 "자연 상태 계획"에서는 인덱스가 있어도 Seq Scan 이 나올 수 있다.
--   인덱스가 실제로 사용 가능한지, 그리고 데이터가 커졌을 때 어떤 계획이 되는지는
--   enable_seqscan 을 꺼서 강제로 비교해 보여준다.
-- =========================================================

\echo ''
\echo '========== (a) responses 를 event_id 로 조회 =========='
\echo '--- [자연 상태] 계획 ---'
EXPLAIN (ANALYZE, TIMING OFF, SUMMARY OFF)
SELECT * FROM responses WHERE event_id = 22;

\echo '--- [Seq Scan 강제 비활성화] 계획: 인덱스 사용 여부 확인 ---'
SET enable_seqscan = off;
EXPLAIN (ANALYZE, TIMING OFF, SUMMARY OFF)
SELECT * FROM responses WHERE event_id = 22;
RESET enable_seqscan;

\echo ''
\echo '========== (b) 특정 자산의 시간대별 이벤트 (이상탐지 패턴) =========='
\echo '--- [자연 상태] 계획 ---'
EXPLAIN (ANALYZE, TIMING OFF, SUMMARY OFF)
SELECT event_id, detected_at, event_type, severity
FROM security_events
WHERE asset_id = 8
  AND detected_at >= TIMESTAMP '2025-08-13 00:00:00'
  AND detected_at <  TIMESTAMP '2025-08-15 00:00:00'
ORDER BY detected_at;

\echo '--- [Seq Scan 강제 비활성화] 계획 ---'
SET enable_seqscan = off;
EXPLAIN (ANALYZE, TIMING OFF, SUMMARY OFF)
SELECT event_id, detected_at, event_type, severity
FROM security_events
WHERE asset_id = 8
  AND detected_at >= TIMESTAMP '2025-08-13 00:00:00'
  AND detected_at <  TIMESTAMP '2025-08-15 00:00:00'
ORDER BY detected_at;
RESET enable_seqscan;

\echo ''
\echo '========== (c) 담당자별 대응 실적 조인 =========='
\echo '--- [자연 상태] 계획 ---'
EXPLAIN (ANALYZE, TIMING OFF, SUMMARY OFF)
SELECT s.staff_name, count(*) AS handled
FROM responses r
JOIN staff s ON s.staff_id = r.staff_id
GROUP BY s.staff_name;

\echo '--- [Seq Scan 강제 비활성화] 계획 ---'
SET enable_seqscan = off;
EXPLAIN (ANALYZE, TIMING OFF, SUMMARY OFF)
SELECT s.staff_name, count(*) AS handled
FROM responses r
JOIN staff s ON s.staff_id = r.staff_id
GROUP BY s.staff_name;
RESET enable_seqscan;

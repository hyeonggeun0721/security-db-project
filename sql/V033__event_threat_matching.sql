-- =========================================================
-- V033) 보안 이벤트 <-> 위협 리포트 / 과거 유사 사건 자동 연결
--
-- 배경: V002 에서 threat_reports 에 pgvector 임베딩을 채워 "사람이 검색어를
--   입력하면" 유사 사례를 찾을 수 있게 했다(search_similar_reports.py). 하지만
--   security_events 파이프라인(synth 합성 이벤트, 실제 입력)과는 연결되어 있지
--   않아 "지금 들어온 이 이벤트, 예전에 본 패턴과 비슷한가?" 는 여전히 수작업이었다.
--
-- 설계 판단:
--   - security_events 에도 threat_reports 와 동일 모델/차원(all-MiniLM-L6-v2,
--     384) 의 embedding 컬럼을 추가한다 -> 두 테이블의 벡터가 같은 임베딩 공간에
--     있으므로 코사인 거리로 직접 비교 가능.
--   - 매칭 결과는 매번 재계산하지 않고 event_threat_matches 에 영속화한다(다른
--     파생 데이터 테이블인 alert_log/scan_runs 와 동일 패턴). 이유:
--       1) 대시보드가 매 새로고침마다 벡터 유사도 계산을 하지 않아도 됨.
--       2) "언제 어떤 근거로 연결됐는지" 이력이 남는다(threat_reports 는 계속 늘어날
--          수 있으므로 같은 이벤트라도 나중에 새 리포트가 추가되면 새 매칭 행이 생김).
--   - 매칭 대상은 두 종류라 한 테이블에서 match_type 으로 구분한다(alert_log 가
--     alert_type 으로 두 소스를 한 테이블에 합친 것과 같은 이유 - 조회/대시보드
--     조인이 하나로 단순해짐):
--       THREAT_REPORT : threat_reports 의 과거 위협 인텔리전스 리포트와 매칭
--       PAST_EVENT    : 이미 임베딩된 다른 security_events(이전 유사 사건)와 매칭
--   - 실제 임베딩 계산과 매칭 저장은 마이그레이션이 아니라
--     scripts/event_threat_linker.py 가 수행한다(nvd_sync.py/import_kisa_results.py
--     와 동일 패턴 - 스키마와 데이터 적재를 분리).
--
-- 재실행 안전: ALTER ... ADD COLUMN IF NOT EXISTS / 테이블·인덱스 IF NOT EXISTS.
-- =========================================================

BEGIN;

-- ---------------------------------------------------------
-- 1) security_events 에 임베딩 컬럼 추가 (threat_reports.embedding 과 동일 차원)
-- ---------------------------------------------------------
ALTER TABLE security_events ADD COLUMN IF NOT EXISTS embedding VECTOR(384);

COMMENT ON COLUMN security_events.embedding IS
    'description 텍스트 임베딩(all-MiniLM-L6-v2, 384차원). scripts/event_threat_linker.py 가 채움. '
    'threat_reports.embedding 과 동일 모델/차원 -> 코사인 거리(<=>)로 직접 비교 가능. description 이 '
    'NULL 이거나 아직 처리 전이면 NULL.';

CREATE INDEX IF NOT EXISTS idx_security_events_embedding_hnsw
    ON security_events USING hnsw (embedding vector_cosine_ops);

-- ---------------------------------------------------------
-- 2) 매칭 결과 테이블
-- ---------------------------------------------------------
CREATE TABLE IF NOT EXISTS event_threat_matches (
    match_id           BIGSERIAL   PRIMARY KEY,
    event_id           INT         NOT NULL REFERENCES security_events(event_id) ON DELETE CASCADE,
    match_type         VARCHAR(13) NOT NULL CHECK (match_type IN ('THREAT_REPORT', 'PAST_EVENT')),
    matched_report_id  INT         REFERENCES threat_reports(report_id) ON DELETE CASCADE,
    matched_event_id   INT         REFERENCES security_events(event_id) ON DELETE CASCADE,
    similarity         NUMERIC(5,4) NOT NULL CHECK (similarity BETWEEN 0 AND 1),
    matched_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT chk_etm_target CHECK (
        (match_type = 'THREAT_REPORT' AND matched_report_id IS NOT NULL AND matched_event_id IS NULL)
        OR
        (match_type = 'PAST_EVENT'    AND matched_event_id  IS NOT NULL AND matched_report_id IS NULL
                                       AND matched_event_id <> event_id)
    )
);

COMMENT ON TABLE event_threat_matches IS
    'security_events.description 임베딩과 threat_reports/과거 security_events 임베딩 간 코사인 유사도 '
    '자동 매칭 결과. scripts/event_threat_linker.py 가 채움(수동 UPDATE 대상 아님).';
COMMENT ON COLUMN event_threat_matches.similarity IS
    '1 - 코사인거리(<=>). 1.0 에 가까울수록 유사. MIN_SIMILARITY(event_threat_linker.py) 미만은 저장 안 함.';

-- 재실행/재처리 시 같은 (event, 대상) 조합 중복 저장 방지.
-- matched_report_id / matched_event_id 중 하나는 항상 NULL 이라 COALESCE 로 감싸야
-- UNIQUE 가 NULL 을 "서로 다른 값"으로 취급하는 표준 동작을 피해 실제 dedup 이 된다.
CREATE UNIQUE INDEX IF NOT EXISTS uq_etm_dedup
    ON event_threat_matches (event_id, match_type, COALESCE(matched_report_id, -1), COALESCE(matched_event_id, -1));

CREATE INDEX IF NOT EXISTS idx_etm_event_id   ON event_threat_matches (event_id);
CREATE INDEX IF NOT EXISTS idx_etm_similarity ON event_threat_matches (similarity DESC);

REVOKE ALL ON event_threat_matches FROM PUBLIC;
GRANT SELECT ON event_threat_matches TO security_analyst, security_admin, security_manager;
GRANT SELECT, INSERT ON event_threat_matches TO security_admin;
GRANT USAGE, SELECT ON SEQUENCE event_threat_matches_match_id_seq TO security_admin;

-- ---------------------------------------------------------
-- 3) 대시보드/조회용 뷰 (event/report/과거이벤트 정보를 미리 조인)
-- ---------------------------------------------------------
CREATE OR REPLACE VIEW vw_event_threat_matches AS
SELECT
    m.match_id,
    m.event_id,
    e.description        AS event_description,
    e.severity            AS event_severity,
    e.detected_at         AS event_detected_at,
    m.match_type,
    m.similarity,
    m.matched_report_id,
    tr.title               AS matched_report_title,
    tr.report_date         AS matched_report_date,
    m.matched_event_id,
    pe.description          AS matched_event_description,
    pe.severity              AS matched_event_severity,
    pe.detected_at           AS matched_event_detected_at,
    m.matched_at
FROM event_threat_matches m
JOIN security_events e        ON e.event_id = m.event_id
LEFT JOIN threat_reports tr   ON tr.report_id = m.matched_report_id
LEFT JOIN security_events pe  ON pe.event_id = m.matched_event_id;

COMMENT ON VIEW vw_event_threat_matches IS
    'event_threat_matches 를 대상(threat_reports/과거 security_events) 정보와 조인한 조회 편의 뷰. '
    'soc_dashboard.py 섹션 i 가 사용.';

GRANT SELECT ON vw_event_threat_matches TO security_analyst, security_admin, security_manager;

COMMIT;

-- @migrate:verify
-- =========================================================
-- 검증
-- =========================================================
\echo ''
\echo '################ security_events.embedding 컬럼 + HNSW 인덱스 ################'
SELECT column_name, udt_name FROM information_schema.columns
WHERE table_name='security_events' AND column_name='embedding';
SELECT indexname FROM pg_indexes WHERE tablename='security_events' AND indexname='idx_security_events_embedding_hnsw';

\echo ''
\echo '################ event_threat_matches 스키마 ################'
\d event_threat_matches

\echo ''
\echo '################ [TEST] 같은 (event, report) 매칭 두 번 INSERT -> ON CONFLICT 로 두 번째는 무시(dedup) ################'
BEGIN;
  INSERT INTO event_threat_matches (event_id, match_type, matched_report_id, similarity)
  SELECT (SELECT event_id FROM security_events ORDER BY event_id LIMIT 1),
         'THREAT_REPORT',
         (SELECT report_id FROM threat_reports ORDER BY report_id LIMIT 1),
         0.9000
  ON CONFLICT (event_id, match_type, COALESCE(matched_report_id,-1), COALESCE(matched_event_id,-1)) DO NOTHING
  RETURNING match_id;
  \echo '  (위: 1행 반환 = 신규)'
  INSERT INTO event_threat_matches (event_id, match_type, matched_report_id, similarity)
  SELECT (SELECT event_id FROM security_events ORDER BY event_id LIMIT 1),
         'THREAT_REPORT',
         (SELECT report_id FROM threat_reports ORDER BY report_id LIMIT 1),
         0.9000
  ON CONFLICT (event_id, match_type, COALESCE(matched_report_id,-1), COALESCE(matched_event_id,-1)) DO NOTHING
  RETURNING match_id;
  \echo '  (위: 0행 반환 = 중복, dedup 정상)'
ROLLBACK;
\echo '   (ROLLBACK - 원상)'

\echo ''
\echo '################ [TEST] match_type=THREAT_REPORT 인데 matched_event_id 도 세팅 -> CHECK 거부 ################'
BEGIN;
  INSERT INTO event_threat_matches (event_id, match_type, matched_report_id, matched_event_id, similarity)
  VALUES (
      (SELECT event_id FROM security_events ORDER BY event_id LIMIT 1),
      'THREAT_REPORT',
      (SELECT report_id FROM threat_reports ORDER BY report_id LIMIT 1),
      (SELECT event_id FROM security_events ORDER BY event_id DESC LIMIT 1),
      0.5000
  );
ROLLBACK;
\echo '   (위에 check_violation ERROR 가 떠야 정상)'

\echo ''
\echo '################ [TEST] PAST_EVENT 가 자기 자신을 가리킴 -> CHECK 거부 ################'
BEGIN;
  INSERT INTO event_threat_matches (event_id, match_type, matched_event_id, similarity)
  SELECT event_id, 'PAST_EVENT', event_id, 0.5000
  FROM security_events ORDER BY event_id LIMIT 1;
ROLLBACK;
\echo '   (위에 check_violation ERROR 가 떠야 정상)'

\echo ''
\echo '################ vw_event_threat_matches (event_threat_linker.py 실행 전이면 0건이 정상) ################'
SELECT count(*) FROM vw_event_threat_matches;

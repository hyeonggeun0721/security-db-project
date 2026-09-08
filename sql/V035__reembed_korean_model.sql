-- =========================================================
-- V035) 임베딩 모델 교체: all-MiniLM-L6-v2(384) → jhgan/ko-sroberta-multitask(768)
--
--   배경: V033~V034 검증에서 다국어 범용 모델 all-MiniLM-L6-v2 가 한국어 보안
--   이벤트 문장을 주제가 맞는 threat_reports 와 정렬하지 못했다. 특히 report 5
--   (피싱 자격증명 탈취)는 어떤 이벤트에서도 TOP_K(3) 안에 들지 못해
--   event_threat_matches 커버리지가 7/8 에 머물렀다(PROJECT_LOG 2026-09-08 V034 항목).
--
--   교체 모델: jhgan/ko-sroberta-multitask (한국어 특화, 768차원).
--     - 사전 평가에서 피싱 대표 이벤트(80) ↔ report 5 유사도가 0.523(6위) →
--       0.755(1위)로 개선. 5개 캠페인 대표 이벤트 전부 자기 리포트가 1위.
--     - 로컬 다운로드/추론 부담 감당 가능(로드 ~26s, CPU). bge-m3(1024차원)는
--       더 무거워 후순위로만 고려 — 이 모델로 목표(report 5 커버리지) 달성돼 미채택.
--
--   이 파일이 하는 일 (스키마: 임베딩 컬럼 재정의만. V002/V033 파일은 불변):
--     1) threat_reports.embedding / security_events.embedding 을 DROP 후
--        VECTOR(768) 로 재생성. 차원이 바뀌어 기존 384차원 값과 호환 불가라
--        ALTER TYPE 이 아니라 DROP+ADD 로 처리(기존 값은 버린다).
--     2) 두 HNSW 인덱스도 DROP 후 새 차원으로 재생성.
--     3) COMMENT ON COLUMN 을 새 모델/차원으로 갱신.
--     4) event_threat_matches TRUNCATE — 저장된 유사도가 이전 모델 기준이라
--        새 모델 값과 섞이면 안 된다. event_threat_linker.py 재실행으로 전량 재계산.
--
--   재임베딩(데이터)은 이 파일이 아니라 스크립트가 수행:
--     python3 scripts/generate_embeddings.py      # threat_reports 8건
--     python3 scripts/event_threat_linker.py      # security_events 전량 + 매칭 재계산
--
--   감사 영향 없음: DDL 은 행 트리거(trg_audit_security_events)를 발화시키지 않고,
--   event_threat_matches 에는 감사 트리거가 없다. 해시체인 무결성 불변.
-- =========================================================

BEGIN;

-- ---- threat_reports.embedding : 384 -> 768 --------------------------------
DROP INDEX IF EXISTS threat_reports_embedding_idx;
ALTER TABLE threat_reports DROP COLUMN IF EXISTS embedding;
ALTER TABLE threat_reports ADD COLUMN embedding vector(768);
CREATE INDEX threat_reports_embedding_idx
    ON threat_reports USING hnsw (embedding vector_cosine_ops);
COMMENT ON COLUMN threat_reports.embedding IS
    'content 텍스트 임베딩(jhgan/ko-sroberta-multitask, 768차원). 이전엔 all-MiniLM-L6-v2(384차원)였으나 V035 에서 한국어 주제 해상도 위해 교체. scripts/generate_embeddings.py 가 채움.';

-- ---- security_events.embedding : 384 -> 768 ------------------------------
DROP INDEX IF EXISTS idx_security_events_embedding_hnsw;
ALTER TABLE security_events DROP COLUMN IF EXISTS embedding;
ALTER TABLE security_events ADD COLUMN embedding vector(768);
CREATE INDEX idx_security_events_embedding_hnsw
    ON security_events USING hnsw (embedding vector_cosine_ops);
COMMENT ON COLUMN security_events.embedding IS
    'description 텍스트 임베딩(jhgan/ko-sroberta-multitask, 768차원; V035 에서 all-MiniLM-L6-v2 384차원에서 교체). threat_reports.embedding 과 동일 모델/차원 -> 코사인 거리(<=>)로 직접 비교. scripts/event_threat_linker.py 가 채움. description 이 NULL 이거나 처리 전이면 NULL.';

-- ---- 이전 모델 기준 매칭 결과 폐기 -------------------------------------
TRUNCATE event_threat_matches RESTART IDENTITY;

COMMIT;

-- @migrate:verify
-- =========================================================
-- 검증
-- =========================================================
\echo ''
\echo '################ [1] embedding 컬럼 타입 - 둘 다 vector(768) 이어야 정상 ################'
SELECT c.relname AS table_name, format_type(a.atttypid, a.atttypmod) AS embedding_type
FROM pg_attribute a
JOIN pg_class c ON c.oid = a.attrelid
WHERE a.attname = 'embedding' AND c.relname IN ('threat_reports', 'security_events')
ORDER BY c.relname;

\echo ''
\echo '################ [2] HNSW 인덱스 - 둘 다 재생성됐어야 정상 ################'
SELECT indexname, indexdef FROM pg_indexes
WHERE indexname IN ('threat_reports_embedding_idx', 'idx_security_events_embedding_hnsw')
ORDER BY indexname;

\echo ''
\echo '################ [3] 임베딩 값은 전부 비워졌어야 정상 (스크립트가 다시 채움) ################'
SELECT
  (SELECT count(*) FROM threat_reports  WHERE embedding IS NOT NULL) AS tr_embedded,
  (SELECT count(*) FROM security_events WHERE embedding IS NOT NULL) AS ev_embedded,
  (SELECT count(*) FROM event_threat_matches)                        AS etm_rows;

\echo ''
\echo '################ [4] COMMENT 갱신 확인 ################'
SELECT c.relname||'.embedding' AS col, d.description
FROM pg_description d
JOIN pg_class c ON c.oid = d.objoid
JOIN pg_attribute a ON a.attrelid = d.objoid AND a.attnum = d.objsubid
WHERE a.attname = 'embedding' AND c.relname IN ('threat_reports','security_events')
ORDER BY c.relname;

\echo ''
\echo '################ [5] 감사 해시체인 (0행 = breaks 없음) - DDL 은 영향 없어야 정상 ################'
SELECT * FROM fn_verify_audit_chain();

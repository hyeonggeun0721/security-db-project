-- =========================================================
-- 심화 기능: 벡터 기반 유사 사례 검색 (pgvector)
-- 실행 전제: security_db_starter.sql이 먼저 실행되어 있어야 함
--            (security_events 테이블을 참조하기 때문)
-- =========================================================

-- -----------------------------
-- 0) pgvector 확장 설치 (최초 1회)
-- -----------------------------
-- macOS Homebrew: 터미널에서 아래를 먼저 실행
--   brew install pgvector
-- 그 다음 psql 안에서:
CREATE EXTENSION IF NOT EXISTS vector;

-- -----------------------------
-- 1) 과거 위협 분석 보고서 / 침해사고 로그 테이블
-- -----------------------------
DROP TABLE IF EXISTS threat_reports CASCADE;

CREATE TABLE threat_reports (
    report_id         SERIAL PRIMARY KEY,
    title             VARCHAR(200) NOT NULL,
    content           TEXT NOT NULL,               -- 보고서 원문 (비정형 텍스트)
    report_date       DATE,
    related_event_id  INT REFERENCES security_events(event_id),  -- 실제 대응까지 이어졌다면 연결
    embedding         VECTOR(384)                  -- all-MiniLM-L6-v2 기준 384차원
);

-- 유사도 검색 성능을 위한 인덱스 (HNSW, 코사인 거리 기준)
CREATE INDEX ON threat_reports USING hnsw (embedding vector_cosine_ops);

-- =========================================================
-- 2) 샘플 데이터 (임베딩 없이 텍스트만 우선 삽입 - 아래 파이썬 스크립트로 임베딩 채움)
-- =========================================================

INSERT INTO threat_reports (title, content, report_date, related_event_id) VALUES
('2024년 OpenSSL 원격코드실행 침해사고 사례 분석',
 '공격자는 패치되지 않은 OpenSSL 취약점을 악용하여 웹서버에 원격으로 코드를 실행시켰다. 초기 침투 이후 방화벽 우회를 시도했으며, 담당팀은 긴급 패치와 방화벽 룰 추가로 대응하였다.',
 '2024-11-03', 1),
('내부 DB 접근제어 우회 사고 대응 보고서',
 '내부망에서 데이터베이스 접근제어를 우회하려는 시도가 다수 관측되었다. 공격자는 권한 상승을 시도했고, 계정 임시 잠금 및 로그 분석으로 대응하였다.',
 '2025-02-14', 2),
('랜섬웨어 초기 침투 위협 인텔리전스 리포트',
 '피싱 메일을 통한 초기 침투 후 권한 상승 및 내부 이동(lateral movement)이 관측되었다. 커널 취약점을 이용한 권한상승 시도가 함께 발견되었다.',
 '2025-05-20', NULL),
('방화벽 장비 커널 권한상승 시도 대응 보고서',
 '경계 방화벽 장비의 운영체제 커널 취약점을 이용해 공격자가 관리자 권한을 획득하려는 시도가 관측되었다. 담당팀은 장비를 격리하고 커널 패치를 적용하여 대응하였다.',
 '2025-05-17', 3),
('피싱 캠페인을 통한 자격증명 탈취 및 2차 침투 사고',
 '위장 로그인 페이지로 유도하는 피싱 메일을 통해 다수 직원의 계정 자격증명이 탈취되었다. 탈취된 계정으로 내부 시스템에 재접속을 시도한 정황이 확인되어 전사 비밀번호 초기화와 다중 인증(MFA) 강제 적용으로 대응하였다.',
 '2025-01-22', NULL),
('대규모 DDoS 공격 대응 및 트래픽 완화 사례',
 '사용자포털을 대상으로 짧은 시간에 비정상적으로 많은 요청이 유입되는 분산서비스거부(DDoS) 공격이 발생하였다. CDN 및 트래픽 스크러빙 서비스를 통해 악성 트래픽을 필터링하여 서비스 가용성을 회복하였다.',
 '2025-03-30', NULL),
('클라우드 스토리지 버킷 오설정으로 인한 고객 데이터 노출',
 '클라우드 스토리지 버킷의 접근 권한이 외부에 공개로 설정되어 있어 고객 데이터 일부가 노출된 사실이 확인되었다. 버킷 접근 정책을 비공개로 전환하고 접근 로그 전수 검토를 실시하였다.',
 '2025-06-11', NULL),
('오픈소스 라이브러리 공급망 공격 사고 분석',
 '빌드 과정에서 사용하는 오픈소스 서드파티 라이브러리 패키지에 악성 코드가 삽입된 공급망 공격이 확인되었다. 해당 버전의 의존성을 즉시 롤백하고 빌드 파이프라인 무결성 검증 절차를 추가하였다.',
 '2025-07-08', NULL);

-- =========================================================
-- 3) 임베딩 생성 (Python, sentence-transformers 사용 - 무료/로컬)
-- =========================================================
-- 아래는 별도 터미널에서 실행하는 파이썬 스크립트 예시입니다.
-- pip install sentence-transformers psycopg2-binary --break-system-packages
--
-- from sentence_transformers import SentenceTransformer
-- import psycopg2
--
-- model = SentenceTransformer('all-MiniLM-L6-v2')
-- conn = psycopg2.connect(dbname='security_db')
-- cur = conn.cursor()
-- cur.execute("SELECT report_id, content FROM threat_reports")
-- rows = cur.fetchall()
-- for report_id, content in rows:
--     vec = model.encode(content).tolist()
--     cur.execute("UPDATE threat_reports SET embedding = %s WHERE report_id = %s", (vec, report_id))
-- conn.commit()

-- =========================================================
-- 4) 유사 사례 검색 예제 (임베딩이 채워진 뒤 실행)
-- =========================================================

-- 현재 이벤트(security_events)와 가장 유사한 과거 보고서 Top 5
-- :query_embedding 자리에는 조회하려는 이벤트 설명을 같은 모델로 임베딩한 벡터를 바인딩합니다.
--
-- SELECT report_id, title, 1 - (embedding <=> :query_embedding) AS similarity
-- FROM threat_reports
-- ORDER BY embedding <=> :query_embedding
-- LIMIT 5;

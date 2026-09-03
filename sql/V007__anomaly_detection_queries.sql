-- =========================================================
-- 고도화 기능 5) 윈도우 함수 기반 이상탐지 쿼리 (쿼리 전용, 신규 테이블 없음)
--
--   목적: 특정 자산에서 짧은 시간(24시간) 안에 security_events 가 급증하는
--         패턴을 윈도우 함수로 탐지한다.
--
--   Query A) 자산별 24시간 롤링 윈도우 이벤트 수 (COUNT() OVER + RANGE) → 임계치 초과 경보
--   Query B) 자산별 일일 이벤트 수 vs 직전 7일 이동평균 (AVG() OVER + LAG) → 급증일 식별
--
--   섹션 1 은 현재 데이터로 그대로 실행한다(급증이 없으면 경보 0건이 정상).
--   섹션 2 는 BEGIN ... ROLLBACK 안에서 테스트용 급증 이벤트를 잠깐 넣어
--   탐지가 실제로 동작하는지 보여준 뒤 전량 되돌린다(데이터/시퀀스 영구 변경 없음).
-- =========================================================


-- #########################################################
-- 섹션 1) 현재 데이터 대상 실행
-- #########################################################

\echo '=== [A] 자산별 24시간 롤링 윈도우 이벤트 수 (임계치 >= 4 건 경보) : 현재 데이터 ==='
SELECT *
FROM (
    SELECT e.asset_id,
           a.asset_name,
           e.event_id,
           e.detected_at,
           COUNT(*) OVER w                                                   AS events_last_24h,
           e.detected_at - LAG(e.detected_at) OVER (PARTITION BY e.asset_id
                                                    ORDER BY e.detected_at)  AS gap_from_prev
    FROM security_events e
    JOIN assets a ON a.asset_id = e.asset_id
    WINDOW w AS (PARTITION BY e.asset_id
                 ORDER BY e.detected_at
                 RANGE BETWEEN INTERVAL '24 hours' PRECEDING AND CURRENT ROW)
) s
WHERE events_last_24h >= 4
ORDER BY events_last_24h DESC, detected_at;

\echo '=== [B] 자산별 일일 이벤트 수 vs 직전 7일 이동평균 : 현재 데이터 ==='
WITH daily AS (
    SELECT asset_id,
           date_trunc('day', detected_at)::date AS day,
           COUNT(*)                             AS daily_cnt
    FROM security_events
    GROUP BY asset_id, date_trunc('day', detected_at)::date
)
SELECT d.asset_id,
       a.asset_name,
       d.day,
       d.daily_cnt,
       ROUND(AVG(d.daily_cnt) OVER (PARTITION BY d.asset_id ORDER BY d.day
                                    ROWS BETWEEN 7 PRECEDING AND 1 PRECEDING), 2) AS trailing_7d_avg,
       d.daily_cnt
         - COALESCE(ROUND(AVG(d.daily_cnt) OVER (PARTITION BY d.asset_id ORDER BY d.day
                                    ROWS BETWEEN 7 PRECEDING AND 1 PRECEDING), 2), 0) AS delta_vs_avg
FROM daily d
JOIN assets a ON a.asset_id = d.asset_id
ORDER BY d.asset_id, d.day;


-- #########################################################
-- 섹션 2) 테스트용 급증 이벤트를 넣고 탐지 재실행 후 ROLLBACK
--         (자산 2 = 사내DB서버 에 24시간 내 6건 주입)
-- #########################################################
BEGIN;

INSERT INTO security_events (asset_id, vuln_id, event_type, severity, detected_at, status) VALUES
    (2, 3, '비정상접근',   'HIGH',   TIMESTAMP '2026-09-03 01:00:00', 'OPEN'),
    (2, 3, '비정상접근',   'HIGH',   TIMESTAMP '2026-09-03 01:35:00', 'OPEN'),
    (2, 3, '권한상승시도', 'HIGH',   TIMESTAMP '2026-09-03 02:10:00', 'OPEN'),
    (2, 3, '비정상접근',   'MEDIUM', TIMESTAMP '2026-09-03 02:50:00', 'OPEN'),
    (2, 3, '권한상승시도', 'HIGH',   TIMESTAMP '2026-09-03 03:30:00', 'OPEN'),
    (2, 3, '비정상접근',   'HIGH',   TIMESTAMP '2026-09-03 04:15:00', 'OPEN');

\echo '=== [A] 24시간 롤링 윈도우 경보 (임계치 >= 4) : 테스트 급증 주입 후 ==='
SELECT *
FROM (
    SELECT e.asset_id,
           a.asset_name,
           e.event_id,
           e.detected_at,
           COUNT(*) OVER w                                                   AS events_last_24h,
           e.detected_at - LAG(e.detected_at) OVER (PARTITION BY e.asset_id
                                                    ORDER BY e.detected_at)  AS gap_from_prev
    FROM security_events e
    JOIN assets a ON a.asset_id = e.asset_id
    WINDOW w AS (PARTITION BY e.asset_id
                 ORDER BY e.detected_at
                 RANGE BETWEEN INTERVAL '24 hours' PRECEDING AND CURRENT ROW)
) s
WHERE events_last_24h >= 4
ORDER BY events_last_24h DESC, detected_at;

\echo '=== [B] 일일 이벤트 수 vs 직전 7일 이동평균 : 테스트 급증 주입 후 (delta 큰 날이 급증일) ==='
WITH daily AS (
    SELECT asset_id,
           date_trunc('day', detected_at)::date AS day,
           COUNT(*)                             AS daily_cnt
    FROM security_events
    GROUP BY asset_id, date_trunc('day', detected_at)::date
)
SELECT d.asset_id,
       a.asset_name,
       d.day,
       d.daily_cnt,
       ROUND(AVG(d.daily_cnt) OVER (PARTITION BY d.asset_id ORDER BY d.day
                                    ROWS BETWEEN 7 PRECEDING AND 1 PRECEDING), 2) AS trailing_7d_avg,
       d.daily_cnt
         - COALESCE(ROUND(AVG(d.daily_cnt) OVER (PARTITION BY d.asset_id ORDER BY d.day
                                    ROWS BETWEEN 7 PRECEDING AND 1 PRECEDING), 2), 0) AS delta_vs_avg
FROM daily d
JOIN assets a ON a.asset_id = d.asset_id
ORDER BY d.asset_id, d.day;

ROLLBACK;

-- 시퀀스는 트랜잭션 롤백의 영향을 받지 않으므로(값이 전진함) 현재 최대 event_id 로 되돌린다.
-- (동시 쓰기가 없는 로컬 검증 환경 전제)
SELECT setval('security_events_event_id_seq', (SELECT MAX(event_id) FROM security_events));

\echo '=== 롤백 후 security_events 건수(원래 4건) 및 시퀀스 복원 확인 ==='
SELECT COUNT(*) AS total_events,
       (SELECT last_value FROM security_events_event_id_seq) AS seq_last_value
FROM security_events;

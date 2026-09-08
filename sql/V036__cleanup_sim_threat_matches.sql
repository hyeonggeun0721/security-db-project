-- =========================================================
-- V036) 합성([SIM]) 이벤트가 실제 위협 인텔리전스(threat_reports)와 매칭된
--       event_threat_matches 행 정리
--
-- 배경: scripts/event_threat_linker.py 의 link_threat_reports() 가 매칭 대상
--   이벤트를 뽑을 때 '[SIM]%' 합성 이벤트를 제외하지 않아, 템플릿으로 생성된
--   합성 이벤트가 사람이 큐레이션한 threat_reports 와 매칭되어 6건이 저장돼
--   있었다. 대시보드는 SIM 토글로 화면에서만 걸렀을 뿐 데이터에는 남아 있었다.
--
-- 조치:
--   1) (스크립트 쪽) link_threat_reports() pending 쿼리에
--      "AND coalesce(e.description,'') NOT LIKE '[SIM]%'" 를 추가해 재발 방지.
--   2) (이 마이그레이션) 이미 저장된 SIM 기반 THREAT_REPORT 매칭을 삭제.
--
-- 왜 필요한가: 합성 이벤트는 SOC 대시보드를 "살아있는 것처럼" 보이게 하려는
--   시뮬레이션 데이터일 뿐이라, 실제 위협 인텔리전스 리포트와의 매칭 이력에
--   섞이면 분석 신호를 오염시킨다. PAST_EVENT 매칭은 패턴 반복 관찰용이라 유지.
--
-- 참고: event_threat_matches 에는 감사 트리거가 없어 DELETE 가 해시체인에
--   영향을 주지 않는다(V033 에서 감사 대상으로 잡지 않음).
-- =========================================================

BEGIN;

DELETE FROM event_threat_matches
WHERE match_type = 'THREAT_REPORT'
  AND event_id IN (
      SELECT event_id FROM security_events WHERE description LIKE '[SIM]%'
  );

COMMIT;

-- @migrate:verify
-- =========================================================
-- 검증
-- =========================================================
\echo ''
\echo '################ [1] SIM 이벤트 기반 THREAT_REPORT 매칭 - 0 이어야 정상 ################'
SELECT count(*) AS sim_threat_report_matches
FROM event_threat_matches m
JOIN security_events e ON e.event_id = m.event_id
WHERE m.match_type = 'THREAT_REPORT'
  AND e.description LIKE '[SIM]%';

\echo ''
\echo '################ [2] 남은 THREAT_REPORT 매칭 (전부 실제 이벤트여야 정상) ################'
SELECT count(*) AS total_threat_report_matches,
       count(*) FILTER (WHERE e.description NOT LIKE '[SIM]%') AS real_event_matches
FROM event_threat_matches m
JOIN security_events e ON e.event_id = m.event_id
WHERE m.match_type = 'THREAT_REPORT';

\echo ''
\echo '################ [3] PAST_EVENT 매칭은 건드리지 않았는지 (SIM 발 매칭 남아 있어야 정상) ################'
SELECT count(*) AS sim_past_event_matches
FROM event_threat_matches m
JOIN security_events e ON e.event_id = m.event_id
WHERE m.match_type = 'PAST_EVENT'
  AND e.description LIKE '[SIM]%';

\echo ''
\echo '################ [4] 감사 해시체인 (0행 = breaks 없음) ################'
SELECT * FROM fn_verify_audit_chain();

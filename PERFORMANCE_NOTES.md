# security_db — 성능 점검 노트 (2026-09-07)

현재 데이터 규모(테이블당 6~45행, 총 ~1MB)에서 **성능 이슈 없음**. 아래는
(1) 왜 지금은 문제가 없는지, (2) 데이터가 10만~100만 행대로 커지면 어디가
병목이 될지, (3) 그때 무엇을 하면 되는지를 정리한다.

측정: `EXPLAIN (ANALYZE, BUFFERS)` + `pg_stat_user_indexes` / `pg_stat_user_tables`.

---

## 1. 왜 지금은 전부 빠른가

- 모든 테이블이 `shared_buffers` 에 완전히 상주한다. `EXPLAIN (BUFFERS)` 가
  전부 `shared hit=N`, `read=0` — 디스크 I/O 자체가 없다.
- 테이블이 14~45행이라 **Seq Scan 이 Index Scan 보다 싸다.** PostgreSQL 옵티마이저가
  정확히 그렇게 판단하고 있다(비용 모델 정상 동작).
- 예: `security_events` 시간범위 조회는 지금 Seq Scan 이지만,
  `SET enable_seqscan=off` 를 주면 `idx_security_events_asset_id_detected_at` 를
  이용한 Index Scan 으로 전환된다 — **인덱스는 올바르게 설계돼 있고, planner 가
  아직 쓸 이유가 없을 뿐**이다.

### 현재 인덱스 사용 현황 (`pg_stat_user_indexes`, idx_scan)

| 자주 쓰임 | scan 수 | 왜 |
|---|---|---|
| `vulnerabilities_cve_id_key` | 209 | `nvd_sync.py` 가 `cve_id` 로 UPSERT/조인 |
| `audit_log_pkey` | 76 | 해시체인 "직전 행 조회", verify |
| `assets_pkey`, `vulnerabilities_pkey`, `security_events_pkey` … | 50~70 | PK 조인 |
| `idx_responses_event_id` | 15 | "이 이벤트의 대응들" |
| `threat_reports_embedding_idx` (HNSW) | 2 | **벡터 유사도 검색에서 실제 사용됨** (8행인데도 Index Scan 선택) |

| 아직 미사용 (idx_scan = 0) | 왜 미사용 / 판단 |
|---|---|
| `idx_security_events_asset_id`, `idx_security_events_asset_id_detected_at`, `idx_security_events_open_high_risk`, `idx_security_events_vuln_id` | 테이블 45행 → Seq Scan 이 더 쌈. **삭제 대상 아님** — V011 에 근거가 명시된 "규모 대비 사전 준비" 인덱스. planner 가 크로스오버(대략 수백~수천 행, 선택도에 따라)에 도달하면 자동 활성화된다. |
| `idx_threat_reports_related_event_id`, `idx_asset_vulnerabilities_vuln_id` | 동상. 조인/FK 검사용 사전 인덱스. |
| `mv_asset_risk_score_pk`, `_label_idx` | `mv_asset_risk_score` 를 아직 대시보드가 안 씀(섹션 c 는 일반 뷰 `vw_asset_risk_score` 사용). `REFRESH … CONCURRENTLY` 시 PK 인덱스가 필요하므로 유지. |

→ **"전혀 안 쓰이는 불필요한 인덱스"는 없다.** 전부 (a) 지금 쓰이거나 (b) 규모 대비
사전 배치이며 근거가 문서화돼 있다. 다만 아래 3-D 참고(중복 후보 1건).

---

## 2. 대시보드 주요 쿼리 실행계획 요약

| # | 쿼리 (대시보드 위치) | 현재 계획 | 규모 확대 시 |
|---|---|---|---|
| 1 | `vw_asset_risk_score` (섹션 c) | Seq Scan ×3 + HashAggregate + Hash Left Join + Sort. `shared hit=6` | `asset_vulnerabilities`/`vulnerabilities` 커지면 HashAggregate 비용 증가 |
| 2 | 최근 24h 이벤트 count (섹션 a) | Seq Scan + Filter (45행 제거) | `security_events` 풀스캔 → **`detected_at` 인덱스 필요** |
| 3 | **RLS 부서 조회** `SELECT count(*) FROM security_events` (dept_infra) | Seq Scan + `Filter: fn_asset_department(asset_id) = fn_current_dept()` | ⚠ **행마다 함수 2회 호출** — 최대 병목 (3-A) |
| 4 | 일별 이벤트 추이 (섹션 d) | Seq Scan + Sort + GroupAggregate | 풀스캔·정렬 → 시간범위 제한 + 인덱스 or 사전집계 |
| 5 | 심각도 분포 / ATT&CK (섹션 b, f) | Seq Scan + GROUP BY (+ LEFT JOIN vulnerabilities) | 동상 |
| 6 | 벡터 유사도 검색 | `Index Scan using threat_reports_embedding_idx` (HNSW) | HNSW 는 준선형 — **문제 없음** |
| 7 | `fn_verify_audit_chain()` (감사 자동검증) | `audit_log` 전체 정렬 스캔 + 행별 sha256 | O(n) — 100만 행이면 수 초~수십 초 (3-E) |

---

## 3. 데이터가 커지면 병목이 될 지점 + 대응

### 3-A. RLS 정책의 행별 함수 호출 — **가장 먼저 터질 곳**

`p_events_dept_scope` / `p_responses_dept_scope` 는
`fn_asset_department(asset_id) = fn_current_dept()` 를 **후보 행마다** 평가한다.
`p_assets_dept_scope` 도 `department = (SELECT … FROM rls_role_department WHERE role_name = current_user)` 서브쿼리를 행마다 탄다.

- 지금: `assets` 4,951 seq_scan / `rls_role_department` 4,318 seq_scan (14행·3행 테이블이라
  무해). 하지만 100만 이벤트에 대한 `dept_infra` 의 `SELECT count(*)` = 함수 100만 회.
- 함수는 이미 `STABLE` 이라 옵티마이저가 쿼리 내 일부 캐시는 하지만, 행별 호출 자체는 남는다.
- **대응 (택1)**:
  1. `security_events` / `responses` 에 `department` 를 **비정규화**(트리거로 유지) 후
     정책을 `department = fn_current_dept()` 로 단순화 → `(department)` 인덱스로 Index Scan.
  2. `fn_current_dept()` 결과를 세션 GUC(`SET app.department`)로 고정(이미 지원됨)해
     정책에서 서브쿼리를 제거. 애플리케이션이 접속 시 1회 SET.
  3. 파티셔닝(`RUN_ORDER.md` 「파티셔닝 검토」참고 — `security_events` 는 FK 때문에
     보류 상태) 이 가능해지면 파티션 프루닝으로 후보 행 자체를 줄임.

### 3-B. 대시보드 전체집계 쿼리 (섹션 b/d/f/a)

`WHERE` 없이 `security_events` 전체를 `GROUP BY` → 매 새로고침마다 풀스캔 4~5회.

- **대응**:
  - 대시보드에 **시간창 제한** (예: 최근 90일) + `CREATE INDEX ON security_events (detected_at)`.
    지금은 `idx_security_events_asset_id_detected_at` 이 있으나 선두 컬럼이 `asset_id` 라
    `detected_at` 단독 범위조회엔 안 쓰인다 → `detected_at` 단독(또는 선두) 인덱스 추가.
  - 심각도·전술·일별 카운트는 **사전집계 매트뷰**(`mv_asset_risk_score` 패턴)로 만들고
    `pg_cron` 으로 5~10분 주기 REFRESH. 대시보드는 매트뷰만 읽음.

### 3-C. `vw_asset_risk_score` (섹션 c)

`asset_vulnerabilities × vulnerabilities` 조인·집계. 자산·취약점이 수만 건이면 HashAggregate 비용↑.

- **대응**: 이미 만들어 둔 **`mv_asset_risk_score`(V025)** 로 대시보드 섹션 c 를 교체하고
  `fn_refresh_risk_score()` 를 주기 실행. (현재 섹션 c 는 실시간 뷰를 직접 조회 중 — 규모
  커지면 매트뷰로 전환 권장. 코드 1줄: `FROM vw_asset_risk_score` → `FROM mv_asset_risk_score`.)

### 3-D. `[SIM]` 필터 (`coalesce(description,'') NOT LIKE '[SIM]%'`)

접두사 부정 매칭이라 btree 인덱스로 못 탄다. 지금은 45행이라 무해.

- **대응**: `security_events.is_synthetic boolean NOT NULL DEFAULT false` 컬럼 +
  `CREATE INDEX … WHERE NOT is_synthetic` (부분 인덱스). 합성 생성기가 `true` 로 넣게 하고
  대시보드 필터를 `WHERE NOT is_synthetic` 로 바꾸면 인덱스 활용 가능.
  (지금 구조도 기능상 정확하므로 규모 커질 때 도입.)

### 3-E. `fn_verify_audit_chain()` 자동검증

전체 `audit_log` 를 `audit_id` 순으로 스캔하며 행별 sha256 재계산 — O(n).
100만 행이면 매일 새벽 실행이 수 초~수십 초.

- **대응**:
  - `verify_audit_chain.sh` 를 "최근 N일 구간 검증(매일) + 전체 검증(주 1회)" 로 분리.
  - 또는 체크포인트: "audit_id ≤ X 까지 검증 완료 + 그 시점 row_hash" 를 별도 테이블에
    저장하고, 다음 실행은 X 이후만 검증.

### 3-F. `audit_log` 자체 증가

INSERT 트리거가 `security_events`/`responses` 변경마다 1행씩 추가. 합성 생성기가
25분마다 돌면 하루 ~100행, 1년 ~4만 행 — 그 자체는 문제 없음. 다만:

- `fn_archive_audit_log()` (V014) 로 1년 경과분을 `audit_log_archive` 로 이관하는 잡을
  `pg_cron` 에 등록(현재 미등록, 함수만 존재). 해시체인은 이관 후에도 남은 구간에서 연속.

---

## 4. 지금 당장 할 것 / 규모 커지면 할 것

| 시점 | 조치 |
|---|---|
| **지금** | 없음. 인덱스·쿼리 모두 규모에 적정. (선택) 대시보드 섹션 c 를 `mv_asset_risk_score` 로 교체. |
| ~수천 행 | `security_events (detected_at)` 단독 인덱스 추가. 대시보드 집계에 시간창(최근 90일) 도입. |
| ~수만 행 | RLS 부서 정책의 함수 호출 제거(3-A: `department` 비정규화 또는 세션 GUC 고정). 심각도/일별/전술 카운트 매트뷰화 + `pg_cron` REFRESH. |
| ~수십만~백만 행 | `verify_audit_chain` 을 증분/체크포인트 방식으로. `is_synthetic` 부분 인덱스. `fn_archive_audit_log` 정기 실행. 파티셔닝 재검토(FK 모델 변경 동반). |

---

## 부록: 재현 명령

```sql
-- 실행계획
EXPLAIN (ANALYZE, BUFFERS) SELECT * FROM vw_asset_risk_score ORDER BY risk_score DESC;
SET ROLE dept_infra; EXPLAIN (ANALYZE) SELECT count(*) FROM security_events; RESET ROLE;
SET enable_seqscan=off; EXPLAIN SELECT * FROM security_events
  WHERE asset_id=8 AND detected_at BETWEEN '2025-08-13' AND '2025-08-15'; RESET enable_seqscan;

-- 사용 통계
SELECT relname, indexrelname, idx_scan FROM pg_stat_user_indexes
  WHERE schemaname='public' ORDER BY idx_scan DESC;
SELECT relname, seq_scan, idx_scan, n_live_tup FROM pg_stat_user_tables
  WHERE schemaname='public' ORDER BY seq_scan DESC;

-- 통계 리셋(재측정 전)
SELECT pg_stat_reset();
```

# FDS(이상거래탐지) 연동 — `fds-integration` 브랜치

> 이 브랜치는 개인 포트폴리오 프로젝트 **FDS**(`~/fds`, 비공개 저장소 `fds-fraud-detection`)의 탐지 경보를
> 이 보안 DB의 이벤트·알림·대시보드에 연결한다.
> **수업 과제 제출본은 `main` 브랜치와 원본 DB `security_db`이며, 이 브랜치는 그것을 건드리지 않는다.**
> (`reports/PROJECT_LOG.md`·`sql/RUN_ORDER.md`는 main과의 충돌을 피하려고 수정하지 않고 이 문서에 따로 기록)

## 한눈에 보기

```
FDS 배치 채점 (~/fds/scripts/14_score_batch.py, svc_fds_scorer)
   │  fds.scores 에 경보(is_alert) 저장
   ▼  트리거 fds.fn_publish_alert  (FDS db/F003, 같은 트랜잭션)
public.security_events  ← event_type 'FRAUD_SUSPECT', 자산 '카드결제승인시스템'   (V038)
   │                       점수 ≥ 0.99 → CRITICAL, 나머지 → HIGH
   ├─ alert_poller.py --source fds : 실행(run)당 요약 알림 1건 (FDS_RUN_DIGEST)   (V039)
   │     ※ 개별 CRITICAL 알림에서는 FRAUD_SUSPECT 제외 (알림 폭주 방지)
   └─ soc_dashboard.py 섹션 j : 경보 대기열 · 시간대별 재현율 · 기준점 점검
```

## 실행 환경

| 항목 | 값 |
|---|---|
| 코드 | 이 브랜치를 펼친 worktree `~/security_db_fds` (`git worktree add ~/security_db_fds -b fds-integration`) |
| DB | **`security_db_fds`** — 원본 `security_db`를 `pg_dump -Fc` → `pg_restore`로 복제 (2026-11-06) |
| 기본 DB 지정 | `~/security_db_fds/.env` 에 `PGDATABASE=security_db_fds` (git 제외). 스크립트 실행 시 `--database security_db_fds` 또는 `export PGDATABASE=security_db_fds` |
| 자동 작업(launchd) | 복제본에는 등록하지 않음. 원본의 backup/synth/alertpoll 등은 계속 `security_db`만 대상 |

복제 직후 검증: 23개 테이블 행 수 원본과 일치, `migrate.py status` 적용 37 · drift 0, `fn_verify_audit_chain()` 문제 0건.

## 이 브랜치의 변경

| 커밋 | 파일 | 내용 |
|---|---|---|
| `32880ff` | `sql/V038__fds_fraud_events.sql` | `event_types`에 `FRAUD_SUSPECT` / `assets`에 '카드결제승인시스템'(APPLICATION·중요도 5·개발팀) / `svc_fds_scorer`에 `security_events` INSERT만 + RLS `p_events_svc_fds`(유형 FRAUD_SUSPECT + 설명 `[FDS]` 접두사 + 결제 자산, 셋 다 일치해야 통과) |
| `e6a694a` | `sql/V039__fds_alert_digest.sql` | `alert_log.alert_type`에 `FDS_RUN_DIGEST` 추가 (ref_key = run_id → 실행당 1번) |
| `e6a694a` | `scripts/alert_poller.py` | ① 개별 CRITICAL 알림에서 `FRAUD_SUSPECT` 제외 ② `--source fds`: 끝난 실행 중 CRITICAL이 있는 실행마다 요약 1건. fds 스키마가 없는 DB에서는 건너뜀 |
| `35076dc` | `scripts/soc_dashboard.py` | 섹션 j 추가. fds 스키마가 없는 DB에서는 안내만 표시 |

### 설계 메모
- **새 role을 만들지 않음**: role은 PostgreSQL 클러스터 전체가 공유하므로, FDS가 만든 `svc_fds_scorer`에 이 DB 안에서만 권한을 준다. role이 없는 DB(예: 빈 DB 재현, CI)에서는 V038의 권한 부분을 건너뛴다.
- **RLS 정책의 자산 조건은 숫자로 고정**: 정책 안에서 `assets`를 조회하면 채점 계정 권한으로 실행돼 `assets` RLS에 막힌다 → 적용 시점에 asset_id를 찾아 `format()`으로 정책을 만든다.
- **채점 계정은 security_events를 읽을 수 없음**(V029 `svc_event_ingest`와 같은 순수 피더). 이벤트 번호는 `RETURNING` 대신 `nextval`로 먼저 받는다.
- **감사로그**: 기존 `trg_audit_security_events`(SECURITY DEFINER)가 FDS 이벤트도 그대로 기록 → 해시체인 정상.
- **알림 폭주**: run 2에서 경보 56건 중 33건이 CRITICAL(점수 ≥ 0.99). 이벤트마다 알림하면 한 번에 33건 → 실행당 요약 1건으로 변경.

## 적용 순서 (새 복제본에서 처음부터)

```bash
# 1) 복제 DB
createdb security_db_fds
pg_dump -Fc -d security_db | pg_restore -d security_db_fds

# 2) FDS 스키마·적재 (~/fds)
cd ~/fds && source .venv/bin/activate
psql -d security_db_fds -v ON_ERROR_STOP=1 -f db/F001_fds_schema.sql
python scripts/13_load_db.py data_raw/creditcard.csv --db security_db_fds
psql -d security_db_fds -v ON_ERROR_STOP=1 -f db/F002_fds_monitoring.sql

# 3) 이 브랜치 마이그레이션 (V038 은 svc_fds_scorer 가 있어야 권한까지 적용됨 → 2) 다음에)
cd ~/security_db_fds
~/opt/anaconda3/bin/python scripts/migrate.py up --database security_db_fds

# 4) 경보 → 이벤트 트리거, 채점
cd ~/fds
psql -d security_db_fds -v ON_ERROR_STOP=1 -f db/F003_fds_alert_events.sql
python scripts/14_score_batch.py --db security_db_fds

# 5) 알림·대시보드
cd ~/security_db_fds
~/opt/anaconda3/bin/python scripts/alert_poller.py --database security_db_fds --dry-run
~/opt/anaconda3/bin/python scripts/alert_poller.py --database security_db_fds
export PGDATABASE=security_db_fds SOC_DASHBOARD_AUTH_HASH='<bcrypt 해시>'
~/opt/anaconda3/bin/streamlit run scripts/soc_dashboard.py --server.port 8502
```

## 확인 쿼리

```sql
SELECT severity, count(*) FROM fds.alert_events WHERE run_id = 2 GROUP BY 1;            -- CRITICAL 33 / HIGH 23
SELECT count(*) FROM security_events WHERE event_type = 'FRAUD_SUSPECT';                -- 56
SELECT count(*) AS problems FROM fn_verify_audit_chain();                                -- 0
SELECT alert_type, ref_key, left(summary, 80) FROM alert_log WHERE alert_type = 'FDS_RUN_DIGEST';
```

## 결과 (2026-11-06, run 2 · FDS 코드 203450b)

| 항목 | 값 |
|---|---|
| 채점 | 시간 구간 4 거래 56,746건 (구간 0~3으로 학습) |
| 경보 → 보안 이벤트 | 56건 (사기 53 / 오경보 3), CRITICAL 33 · HIGH 23, 이벤트 #2821~#2876 |
| 알림 | 요약 1건 (개별 발송이었다면 33건) |
| 재현율 / 정밀도 | 71.6% / 94.6% — 과거 구간에서 정한 기준점이 새 구간에서는 엄격(목표 80%) |
| 기준점 점검 | 재현율 80% → 오경보 29건, 90% → 1,220건 |

이벤트 번호 중간이 비는 것은 V038 검증절이 `nextval`을 쓰고 롤백했기 때문(시퀀스는 롤백되지 않음) — 정상.

## 되돌리기

- **복제본째 삭제**(가장 간단): `dropdb security_db_fds` — 원본 `security_db`에는 영향 없음
- 복제본은 두고 FDS만 제거: `psql -d security_db_fds -f ~/fds/db/F000_drop_fds.sql`
  (보안 이벤트·감사로그에 남은 `[FDS]` 행은 그대로 — 감사로그는 불변이 원칙)
- 이 브랜치 마이그레이션은 forward-only 원칙(RUN_ORDER 참고)에 따라 되돌리는 파일을 두지 않는다.

## main에 합치기 전에 정할 것 (과제 제출 후)

1. **원본 DB에 FDS 스키마를 둘지**: 두면 매일 백업(`backup_scheduled.sh`, 14일 보관)에 FDS 거래 28만 건이 포함돼 덤프가 약 91MB로 커짐 → 백업에서 `--exclude-schema=fds`를 쓰거나 FDS는 계속 별도 DB에 둘지 결정
2. **알림 폴러**: 합치면 원본의 launchd `alertpoll` 작업이 `--source all`로 FDS 요약도 처리(fds 스키마가 없으면 자동으로 건너뜀)
3. **문서**: 합칠 때 이 문서 내용을 `reports/PROJECT_LOG.md`·`sql/RUN_ORDER.md`에 옮기고, `schema_dump.sql` 재생성

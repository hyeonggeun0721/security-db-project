# security_db — 마이그레이션 순서 (canonical run order)

> **프로젝트 경로**: `~/security_db_project/` (2026-09-07 `~/Desktop/security_db_project` 에서 이동).
> macOS TCC 가 `~/Desktop`/`~/Documents`/`~/Downloads` 하위를 백그라운드 에이전트(launchd)로부터
> 차단하기 때문. 이동 후 launchd 자동 스케줄 2종이 정상 등록·실행됨(아래 "자동 스케줄" 참고).
>
> **Git 워크플로**: 2026-09-08 Git 저장소 초기화 + GitHub 비공개 저장소 연결. 이전 라운드들은
> 단계별로 커밋 히스토리를 재구성함(각 커밋 날짜를 실제 작업 시점에 맞춤). **이제부터 매 작업
> 라운드가 끝날 때마다 `git add -A && git commit`(origin 연결 시 `git push`)까지 하는 것을 기본으로 한다.**

## 적용 방법: `scripts/migrate.py`

sql/ 의 마이그레이션은 `V<번호>__<이름>.sql` 로 번호가 매겨져 있고, **`migrate.py`** 로 적용한다.

```
python3 scripts/migrate.py status            # 적용/미적용/drift 현황
python3 scripts/migrate.py up                # 미적용분을 번호순으로 적용 (드리프트면 중단)
python3 scripts/migrate.py up --dry-run      # 적용 대상만 표시
python3 scripts/migrate.py baseline --up-to NNN   # 기존 DB 채택: V001~VNNN 을 '적용됨'으로 기록(실행 안 함)
```

- 이력 테이블 `schema_migrations(version, filename, checksum, applied_at, applied_by, exec_seconds)`.
- 적용된 마이그레이션 파일을 수정하면 sha256 불일치 → **drift 로 `up` 이 중단**된다.
  스키마를 바꾸려면 기존 파일을 고치지 말고 **새 `V###` 파일을 추가**한다.
- 파일에 `-- @migrate:verify` 마커가 있으면 그 위=본문(`ON_ERROR_STOP=1`),
  아래=검증절(`ON_ERROR_STOP=0`, 실패해도 마이그레이션은 성공). 의도적 ERROR·`\!` 서브셸은 검증절에 둔다.
- 빈 DB 에 `up` 하면 V001→V032 전체가 한 흐름으로 적용된다. QA 재현성 테스트(2026-09-07, 32개)에서 확인.
- Flyway(13.5.0, brew 설치 가능)는 SQL 을 JDBC 로 실행해 `\echo`/`\!`/`\d` psql 메타명령을
  못 읽는다(V003 에서 `syntax error at or near "\"`). 24/26 파일이 메타명령에 의존하므로 자체 러너를 쓴다.

## 순서·의존성 표

| V### | 파일 | 구분 | 선행 의존 |
|---|------|------|-----------|
| 0 | `CREATE DATABASE security_db;` + `CREATE EXTENSION vector;` | 준비 | pgvector 설치 필요 |
| V001 | `security_db_starter` | 원본 스키마 | — |
| V002 | `vector_search_addon` | 원본(벡터검색) | 1 (security_events 참조) |
| V003 | `audit_log` | 고도화 1 | 1 |
| V004 | `rbac` | 고도화 2 | 1 |
| V005 | `risk_scoring` | 고도화 3 | 4 |
| V006 | `row_level_security` | 고도화 4 | 4 |
| V007 | `anomaly_detection_queries` | 고도화 5 | 1 (쿼리 전용) |
| V008 | `attack_mapping` | 고도화 6 | 1 |
| V009 | `sample_data_expansion` | 데이터 확충 | **8**(vulnerabilities 의 attack_* 컬럼에 INSERT), 3 |
| V010 | `transaction_example` | 트랜잭션 예제 | 9. 전체가 `@migrate:verify`(스키마 변경 없음, B 절 의도적 FK 위반) |
| V011 | `indexes` | 인덱스 전략 | 9 |
| V012 | `type_hardening` | 마이그레이션 1 | 4 |
| V013 | `cvss_consistency_check` | 마이그레이션 2 | 4 |
| V014 | `audit_log_hardening` | 마이그레이션 3 | 3, 6, **9 이후**(9 가 audit_log TRUNCATE, 이 파일이 차단) |
| V015 | `rls_expansion` | 마이그레이션 4 | 6 |
| V016 | `auth_hardening` | 마이그레이션 5 | 4, 6 |
| V017 | `nvd_integration` | NVD 연동 | 1, **13**(`fn_severity_rank()`) |
| V018 | `fk_policy_hardening` | 보완: FK 참조동작 | 1, 2. 검증절에 RESTRICT 거부 테스트(`@migrate:verify`) |
| V019 | `departments_normalization` | 보완: 부서 마스터 | 1, **6**(`rls_role_department`). `@migrate:verify` |
| V020 | `additional_check_constraints` | 보완: CHECK 제약 | 1, **17** |
| V021 | `search_path_hardening` | 보안: SECURITY DEFINER search_path 고정 | 3,6,14 |
| V022 | `function_privilege_hardening` | 보안: 함수 EXECUTE 최소화 | 4,6,13,17 |
| V023 | `audit_log_hash_chain` | 보안: 감사로그 해시 체인 + 검증함수 | 3,14. 백필 위해 트리거 DISABLE/ENABLE |
| V024 | `column_level_grants` | 보안: assets 컬럼 단위 권한(ip_address 차단) | 4,6. `security_invoker` 뷰(PG15+). `@migrate:verify` |
| V025 | `materialized_risk_score` | 성능: mv_asset_risk_score + 갱신함수 | 1,4,5,9 |
| V026 | `resource_limits` | 보안: 연결수/타임아웃 role 제한 | 4,6. `@migrate:verify`(의도적 timeout 테스트) |
| V027 | `event_types` | 확장: event_type CHECK → 마스터테이블 + FK | **20**(V020 의 CHECK 제거), 9. `@migrate:verify` |
| V028 | `response_timing_check` | 무결성: responses.action_date ≥ event.detected_at 트리거 | 1, 3(트리거 공존). `@migrate:verify` |
| V029 | `synthetic_events_support` | 합성 이벤트 지원: `security_events.description` 컬럼 + `svc_event_ingest` 서비스 계정 + RLS(`[SIM]` 태그 강제) | 1, 4, 6, 20(event_types), 26(자원제한 방침). `@migrate:verify` |
| V030 | `scan_findings_integration` | KISA 설정취약점 통합: `vulnerabilities.source`/`finding_ref`/`remediation` 컬럼 + `scan_runs` 테이블 + `asset_vulnerabilities.scan_run_id`/`observed_detail` | 1, 4(GRANT). `@migrate:verify`. 데이터는 `import_kisa_results.py` 가 적재 |
| V031 | `epss_priority_scoring` | EPSS 연동: `nvd_cve_details.epss_*` 컬럼(0~1 CHECK) + `nvd_status` 에 `PENDING` 추가 + `vw_priority_vulnerabilities`(priority = cvss×epss) | **17**(nvd_cve_details). `@migrate:verify`. 데이터는 `epss_sync.py` 가 적재 |
| V032 | `alert_log` | 실시간 알림 dedup 테이블: `(alert_type, ref_key)` UNIQUE. `alert_poller.py` 가 중복 알림 방지에 사용 | 4(GRANT). `@migrate:verify` |

각 그룹(V018~20, V021~26)은 대체로 상호 독립이며 표 순서가 자연스럽다.
V021(search_path)은 V022(EXECUTE 회수)보다 먼저 — 함수 정의를 만지므로.
V023(hash_chain)은 `fn_audit_row_change` 를 재정의하므로 V021 뒤 (파일에 `SET search_path` 를 다시 넣어둠).
V027 은 V020 이 건 `chk_security_events_event_type` 를 제거하고 FK 로 대체하므로 V020 뒤여야 한다.

## 향후 과제 (미적용)

- **파티셔닝**: 아래 "파티셔닝 검토" 섹션 참고. 스크래치 DB(`security_db_part`)에서 검증한
  결과 **라이브 미적용, 향후 과제로 보류**.
- **TLS/SSL**: `TLS_SSL_GUIDE.md` 참고. 운영 반영 시 절차만 문서화, 라이브 미적용.
- **auth_hardening / pg_hba scram 전환**: `auth_hardening.sql` 주석 가이드. 라이브 미적용.

## 파티셔닝 검토 (2026-09-07, 스크래치 DB `security_db_part`)

전체 26개 파일을 스크래치 DB 에 재구축한 뒤 `security_events` / `audit_log` 를
`detected_at` / `changed_at` 기준 월 RANGE 파티션으로 전환 시도.

### `security_events` — **불가 (FK 무결성과 충돌)**

- 파티션 테이블의 UNIQUE/PK 는 **파티션 키 컬럼을 반드시 포함**해야 한다.
  → `PRIMARY KEY (event_id)` 불가 (`ERROR: unique constraint on partitioned table must
  include all partitioning columns`). `PRIMARY KEY (event_id, detected_at)` 만 가능.
- 그러면 `event_id` **단독 UNIQUE** 가 없어져,
  `responses.event_id → security_events(event_id)` 와
  `threat_reports.related_event_id → security_events(event_id)` FK 를 만들 수 없다
  (`ERROR: there is no unique constraint matching given keys`).
- 이 FK 들은 방금 `fk_policy_hardening.sql` 로 정비한 핵심 무결성 장치다. 유지하려면
  `responses`/`threat_reports` 에 `detected_at` 를 복제하고 복합 FK 로 바꾸는 모델 전반의
  침습적 변경이 필요 → 이번 범위를 크게 벗어남.
- **결론: 보류.** 데이터가 수백만 건대로 커지면 그때 (a) 복합키 모델 재설계 또는
  (b) 파티션 대신 `BRIN(detected_at)` 인덱스 + 오래된 데이터 아카이브 테이블 이관을 검토.

### `audit_log` — **기술적으로는 가능하나 이득 대비 복잡도 커서 보류**

- 유입 FK 가 없어 복합 PK `(audit_id, changed_at)` 로 파티션 가능. 기존 행 이관,
  불변성/ TRUNCATE 트리거의 파티션 부모 부착까지 스크래치에서 정상 확인.
- 그러나:
  1. 해시 체인(`fn_audit_row_change` 의 "직전 행 row_hash 조회", `fn_verify_audit_chain`
     의 `ORDER BY audit_id` 순회)이 파티션 다중 스캔이 되고, `audit_id` 단독 인덱스를
     PK 로 못 써서 별도 인덱스 설계가 필요.
  2. 해시 체인 백필의 `ALTER TABLE ... DISABLE TRIGGER` 가 파티션 부모/자식에서 의미가
     달라 마이그레이션 재작성 필요.
  3. `audit_log_archive` (`LIKE audit_log`), `TRUNCATE ... RESTART IDENTITY` 상호작용 재검증 필요.
  4. 다음 달 파티션 사전 생성 잡(pg_partman/cron) 없으면 DEFAULT 파티션에 쌓임.
  5. 현재 이득이 거의 없음 — `audit_log` 는 이미 `fn_archive_audit_log()` →
     `audit_log_archive` 라는 보존/이관 경로가 있다.
- **결론: 보류.** 도입한다면 `fn_archive_audit_log` 를 "월 파티션 detach + archive" 방식으로
  바꾸는 별도 설계로 진행.

라이브 `security_db` 에는 **아무 변경도 적용하지 않았다.**

## 파이썬 후속 단계 (마이그레이션 적용 후)

```
python3 scripts/migrate.py up                          # ← 스키마: V001~V031 적용 (드리프트 검사 포함)
python3 scripts/generate_embeddings.py                 # threat_reports.embedding 8건 채움
python3 scripts/nvd_sync.py                            # nvd_cve_details UPSERT (재실행 안전)
python3 scripts/epss_sync.py                           # nvd_cve_details.epss_* UPSERT (FIRST.org EPSS, 재실행 안전)
python3 scripts/nvd_watch.py                           # nvd_watch_candidates UPSERT (재실행 안전)
python3 scripts/alert_poller.py --dry-run              # 알림 대상 미리보기 (launchd 2분 주기로 자동 실행)
streamlit run scripts/soc_dashboard.py                 # SOC 대시보드 (security_manager 접속)
bash    scripts/backup_scheduled.sh                    # 수동 백업 1회 (launchd 스케줄은 헤더 참고)
```

### 합성(시뮬레이션) 이벤트 생성 — `scripts/generate_synthetic_events.py`

실제 SOC 로그가 없으므로, 현실적 패턴의 **합성** 보안 이벤트를 주기적으로 넣어
대시보드가 살아있게 한다. 접속 계정은 최소권한 서비스 계정 `svc_event_ingest`(V029).

```
python3 scripts/generate_synthetic_events.py            # 1~3개(랜덤) 생성
python3 scripts/generate_synthetic_events.py --count 5  # 5개 (최대 50)
python3 scripts/generate_synthetic_events.py --dry-run  # INSERT 없이 미리보기
```

- **실사건과 구분**: 모든 합성 행의 `description` / `action_taken` 이 `'[SIM] '` 로 시작.
  `WHERE description LIKE '[SIM]%'` 로 골라 삭제/분석제외 가능. 게다가 `svc_event_ingest` 의
  RLS `WITH CHECK (description LIKE '[SIM]%')` 가 태그 없는 INSERT 를 DB 레벨에서 거부한다.
- `event_types` 를 동적 SELECT(하드코딩 없음), 심각도 분포 LOW40/MED35/HIGH20/CRIT5,
  자산은 `assets` 에서 랜덤, `detected_at`≈now, 약 30% 는 `responses` 도 생성
  (`action_date` 는 V028 트리거 통과하도록 항상 `detected_at` 이후).

### KISA 설정취약점 스캔 → DB 통합 — `kisa_scanner.py` + `import_kisa_results.py`

KISA 주요정보통신기반시설 U-01~U-72 진단(설정 취약점)을 실제 리눅스에서 돌려 결과를 DB 에 통합한다.

```
# 1) 리눅스 대상에서 스캔 (root 권장). systemd 컨테이너가 아니면 서비스 항목 일부는 "점검불가".
docker run -d --name kisa_target ubuntu:22.04 sleep infinity
docker exec kisa_target bash -c 'apt-get update -qq && apt-get install -y -qq python3 openssh-server cron rsyslog'
docker cp scripts/kisa_scanner.py kisa_target:/root/
docker exec kisa_target python3 /root/kisa_scanner.py --output-dir /root/scan_out --format both --verbose
docker cp kisa_target:/root/scan_out/. reports/kisa_scans/
docker rm -f kisa_target

# 2) JSON 리포트를 DB 에 적재 ("취약" 만. "점검불가/양호" 는 로그로만)
python3 scripts/import_kisa_results.py            # reports/kisa_scans/ 최신 리포트
python3 scripts/import_kisa_results.py --dry-run  # 미리보기
```

- 설계(V030): KISA 항목 = `vulnerabilities` 행(`source='SCAN'`, `finding_ref='KISA-U-##'`, `cve_id=NULL`).
  스캔 대상 asset 이 없으면 `import_kisa_results.py` 가 생성(`asset_type='SERVER'`, `department='보안팀'`,
  `importance_level=2`). `asset_vulnerabilities` 로 연결하고 `scan_runs` 에 실행 메타 기록.
- **KISA 중요도 → severity / 환산 cvss_score**: 상→HIGH/7.5, 중→MEDIUM/5.0, 하→LOW/2.5.
  환산 cvss 는 실제 CVE 점수가 아니며(`source='SCAN'` 으로 구분) `vw_asset_risk_score`
  (importance × max_open_cvss) 재사용을 위한 것. severity 라벨과 밴드가 일치해
  `vw_cvss_severity_mismatch` 에 오탐을 만들지 않는다.
- 재실행 안전: `finding_ref` UNIQUE + `(asset_id, vuln_id)` PK 로 UPSERT.
- 접속 계정: 관리자 ETL(`nvd_sync.py` 와 동일) → 소유자 계정.

### 실시간 알림 / 에스컬레이션 — `alert_notifier.py` + `alert_poller.py` (V032)

두 소스에 알림을 건다: (a) 최근 CRITICAL `security_events`, (b) 감사로그 해시체인 손상.

- **채널**: `alert_notifier.notify()` 가 macOS 네이티브 알림(기본, 의존 없음) → Slack 웹훅
  (`SLACK_WEBHOOK_URL`) → 이메일(`ALERT_SMTP_*`) 순으로 시도. 발송 여부와 무관하게 `logs/alerts.log` 기록.
- **트리거 방식 = 폴링(launchd 2분)**. LISTEN/NOTIFY 대신 폴링을 고른 이유:
  · 이 프로젝트 운영 계층이 이미 전부 launchd 주기 잡 → 일관성, 상주 데몬 수명관리 불필요.
  · NOTIFY 는 리스너 없을 때 유실(영속성 없음). 폴링 + `alert_log` dedup 은 실행이 밀려도 다음 주기에 자가복구.
  · 규모가 작아(이벤트 수십~수백/일) 2분 지연은 데모에 충분.
  · 대량/즉시성이 필요해지면 `security_events` 트리거 `pg_notify` + 상주 리스너로 전환(그때도 `alert_log` dedup 재사용).
- **중복 방지**: `alert_log(alert_type, ref_key)` UNIQUE. `INSERT .. ON CONFLICT DO NOTHING RETURNING` →
  행이 반환되면 신규 → 발송. `security_events` 는 안 건드리므로 감사 트리거/해시체인에 영향 없음.
  ref_key: CRITICAL_EVENT=`event_id`, AUDIT_CHAIN=`db명:breaks수:깨진audit_id들`.
- **CRITICAL 범위**: `detected_at >= now() - 2h` (오래된 이벤트 알림은 무의미). `[SIM]` 이벤트도 알림하되
  문구에 `[SIM]` 표기(`ALERT_INCLUDE_SIM=0` 으로 제외 가능).
- `verify_audit_chain.sh` 는 ALERT(exit 2) 시 `alert_poller.py --source audit` 를 호출한다(같은 dedup 경유).

## 자동 스케줄 (launchd) — 등록 완료 (2026-09-07)

프로젝트를 `~/security_db_project` 로 옮긴 뒤 아래 **다섯 개** LaunchAgent 가 정상 등록·실행됨
(`launchctl start` → 전부 **exit 0** 확인).

| plist (scripts/) | Label | 주기 | 하는 일 | 실행 로그 |
|---|---|---|---|---|
| `com.security-db.backup.plist` | `com.security-db.backup` | 매일 03:30 | `pg_dump --format=custom` → `db_backups/` + `pg_dumpall --roles-only` → `roles_<ts>.sql`, 14일/7개 보존정책 | `db_backups/backup.log` (+ `~/Library/Logs/security-db-backup.{out,err}.log`) |
| `com.security-db.synth.plist` | `com.security-db.synth` | 25분마다 | `generate_synthetic_events.py` 로 합성 이벤트 1~3건 생성 | `~/Library/Logs/security-db-synth.{out,err}.log` |
| `com.security-db.auditverify.plist` | `com.security-db.auditverify` | 매일 04:00 | `verify_audit_chain.sh` — `fn_verify_audit_chain()` 실행, breaks>0 이면 `*** ALERT ***` 기록 + `alert_poller.py --source audit` 호출 + exit 2 | `logs/audit_verify.log` |
| `com.security-db.epsssync.plist` | `com.security-db.epsssync` | 매일 05:00 | `epss_sync.py` — FIRST.org EPSS 재동기화 (EPSS 값은 매일 갱신) | `~/Library/Logs/security-db-epsssync.{out,err}.log` |
| `com.security-db.alertpoll.plist` | `com.security-db.alertpoll` | **2분 주기** (`StartInterval 120`) | `alert_poller.py` — 최근 2h CRITICAL 이벤트 + 감사체인 손상 폴링 → `alert_notifier` 발송 (`alert_log` dedup) | `~/Library/Logs/security-db-alertpoll.{out,err}.log` |

### 등록 / 해제 / 확인

```
# 등록 (다섯 개)
cp scripts/com.security-db.*.plist ~/Library/LaunchAgents/
for j in backup synth auditverify epsssync alertpoll; do launchctl load ~/Library/LaunchAgents/com.security-db.$j.plist; done

# 스케줄이 살아있는지 확인 (가운데 숫자 = 마지막 종료코드, 0 이면 정상)
launchctl list | grep security-db

# 즉시 1회 실행
for j in backup synth auditverify epsssync alertpoll; do launchctl start com.security-db.$j; done

# 로그 확인
tail -f db_backups/backup.log
tail -f logs/audit_verify.log
tail -f ~/Library/Logs/security-db-synth.out.log
tail -f ~/Library/Logs/security-db-alertpoll.out.log
tail -f logs/alerts.log            # 알림 발송 이력 (모든 채널)

# 해제
for j in backup synth auditverify epsssync alertpoll; do launchctl unload ~/Library/LaunchAgents/com.security-db.$j.plist; done
rm ~/Library/LaunchAgents/com.security-db.*.plist
```

주의:
- `com.security-db.{synth,epsssync,alertpoll}.plist` 의 `ProgramArguments` 는 **psycopg2(+requests) 가 설치된
  인터프리터**(`/Users/summer/opt/anaconda3/bin/python3`)를 가리킨다. `which python3` 결과가 다르면 맞춰야 한다.
- `alertpoll` 은 macOS 네이티브 알림이 기본. `EnvironmentVariables` 에 `SLACK_WEBHOOK_URL` /
  `ALERT_SMTP_*` 를 넣으면 해당 채널도 자동 시도한다. `ALERT_INCLUDE_SIM=0` 이면 `[SIM]` CRITICAL 은 알림 제외.
- `epss_sync` 가 만든 `nvd_status='PENDING'` 행은 `nvd_sync.py` 실행 시 SYNCED 로 정리된다
  (정기화하려면 05:00 잡 앞에 `nvd_sync.py` 도 등록).
- 25분 주기면 하루 약 100~150건이 쌓인다. 데모 기간에만 `load`, 끝나면 `unload` 하거나
  `ProgramArguments` 에 `--count 1` 을 추가해 볼륨을 줄일 수 있다.

## 운영 검증 (2026-09-07 수행)

- **복구 드릴**: `db_backups/` 최신 덤프를 `security_db_restore_test` 로 `pg_restore` →
  원본과 **모든 지표 완전 일치**(행수·뷰·함수·트리거·인덱스·FK/CHECK·RLS 정책·테이블/컬럼 GRANT·
  pgvector 확장·`threat_reports.embedding` 8건·해시체인 breaks=0). 벡터검색·RLS(`SET ROLE`)도 정상.
  **RTO(데이터 복원 구간) ≈ 0.2초.**
  발견사항: `pg_dump`(단일 DB)에는 **role 정의가 안 담긴다**(cluster-global). 같은 클러스터로
  복구하면 role 이 이미 있어 무해하나, **새 클러스터 복구 시 role 을 먼저 만들어야** GRANT/RLS 가
  붙는다 → `backup_scheduled.sh` 가 이제 `pg_dumpall --roles-only` 로 `roles_<ts>.sql` 도 함께 뜬다.
- **감사로그 해시체인 자동검증**: `verify_audit_chain.sh` + `com.security-db.auditverify`(매일 04:00).
  스크래치 DB 에서 `audit_log` 한 행을 강제 조작 → `logs/audit_verify.log` 에 `*** ALERT ***` +
  깨진 `audit_id`·해시 diff 기록, exit 2 확인. (라이브 감사로그는 미변경)
- **대시보드 합성(SIM) 필터**: `soc_dashboard.py` 사이드바 "합성(시뮬레이션) 데이터 포함 보기"
  체크박스. **기본값 OFF**(제외) — 이 대시보드의 1차 목적은 큐레이션된 실제 데이터를 보여주는 것이고,
  합성 이벤트는 `vuln_id`/ATT&CK 가 없어 e/f 섹션을 "(미매핑)" 으로 희석시키기 때문. 데모에서
  "피드가 흐른다"를 보일 때만 켠다. 토글 시 카드·차트·표 전부 일관 필터
  (`security_events.description` / `responses.action_taken` / `audit_log` 대상행).
- **성능 점검**: `PERFORMANCE_NOTES.md` 참고. 현재 규모(테이블당 6~45행)에서 이슈 없음.
  규모 확대 시 1순위 병목은 **RLS 부서 정책의 행별 함수 호출**(`fn_asset_department`/`fn_current_dept`).

## 숨은 의존성 3가지 (순서를 바꾸면 실패)

1. **8 → 9**: `sample_data_expansion.sql` 은 `vulnerabilities` 에 `attack_tactic` 등
   ATT&CK 컬럼을 포함해 INSERT 한다. `attack_mapping.sql`(8) 이 먼저 그 컬럼을 추가해야 한다.
2. **9 → 14**: `sample_data_expansion.sql`(9) 마지막에 `TRUNCATE audit_log` 가 있다.
   `audit_log_hardening.sql`(14) 는 audit_log 의 TRUNCATE/UPDATE/DELETE 를 트리거로 차단하므로
   반드시 9 뒤에 와야 한다. (같은 이유로 `audit_log.sql` 도 14 이후에는 재실행 불가 — 자체 TRUNCATE 때문.)
3. **13 → 17**: `nvd_integration.sql` 의 `vw_cvss_nvd_mismatch` 뷰가
   `cvss_consistency_check.sql`(13) 이 만드는 `fn_severity_rank()` 함수를 참조한다.
4. **6 → 19**: `departments_normalization.sql`(19) 는 `assets`+`staff`+`rls_role_department`
   세 곳의 distinct 부서명을 마스터에 채운 뒤 FK 를 건다. `rls_role_department` 는
   `row_level_security.sql`(6) 이 만들므로 6 이후여야 3곳 모두 반영된다.
5. **17 → 20**: `additional_check_constraints.sql`(20) 이 `nvd_cve_details` /
   `nvd_watch_candidates` 에 CHECK 를 걸므로 `nvd_integration.sql`(17) 이후여야 한다.

6. **20 → 27**: `V027__event_types.sql` 는 `V020` 이 건 `chk_security_events_event_type`
   CHECK 를 제거하고 `event_types(event_type_name)` FK 로 대체한다. V020 뒤여야 한다.

## 재실행(idempotency) 주의

- `migrate.py up` 은 이미 적용된(checksum 일치) 마이그레이션을 건너뛴다. 두 번 실행해도 무해.
- 각 파일도 대부분 `CREATE ... IF NOT EXISTS` / `OR REPLACE` / `DROP ... IF EXISTS` 로 재실행 안전.
- **예외**: `V009__sample_data_expansion.sql` — 1회성 적재(INSERT 존재검사 없음).
  이미 적재된 DB 에 재실행하면 PK/UNIQUE 위반. `migrate.py` 가 checksum 으로 재적용을 막으므로 정상 흐름에선 문제없음.

## `\!` 서브셸 주의 (V014, V015, V024)

`V014__audit_log_hardening.sql`, `V015__rls_expansion.sql`, `V024__column_level_grants.sql` 의
검증절(`@migrate:verify` 아래)은 `\! psql -d security_db ...` 로 **DB 이름이 하드코딩된**
서브셸을 띄운다. 다른 이름의 DB 로 재구축할 때 그 검증절 출력은 테스트 DB 가 아니라
`security_db` 를 향한다(마이그레이션 본문·적용에는 영향 없음. V027/V028 은 이 문제를 피해
`SET ROLE` + `BEGIN..ROLLBACK` 로 검증한다).

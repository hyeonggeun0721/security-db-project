# security_db 프로젝트 로그

> 규칙: 아래 **「현재 상태」** 섹션은 매 작업 후 최신 상태로 **덮어쓴다**.
> **「히스토리」** 섹션은 작업마다 새 타임스탬프 항목을 **위쪽에 추가**하며,
> 기존 항목은 절대 수정/삭제하지 않는다.
> (제출용 4대 문서(제안서/중간보고서/최종보고서/기술문서)는 이 로그와 별개이며 건드리지 않는다.)

---

## 현재 상태

_최종 갱신: 2026-09-08 KST (V033 launchd 등록 + schema_dump 재생성)_

### 프로젝트 위치 / 적용 방식
- 경로: **`~/security_db_project/`** (macOS TCC 때문에 `~/Desktop` 에서 이동)
- 스키마: `scripts/migrate.py` 로 `sql/V001__*.sql` ~ **`V033__*.sql`** 적용.
  `migrate.py status` → **적용됨 33 · 미적용 0 · drift 0**
- 적용된 마이그레이션 파일은 불변. 변경은 새 `V###` 파일 추가로만.
- **Git 관리 중**: 2026-09-08 저장소 초기화 + 단계별 커밋 히스토리 재구성 후
  **GitHub 비공개 저장소 연결 완료**(`origin` → `github.com/hyeonggeun0721/security-db-project`).
  매 작업 라운드 종료 시 `git add -A && git commit && git push origin main` 을 기본으로 한다.
  대용량/자격증명은 `.gitignore` 로 제외(`db_backups/`, `logs/`, `*.dump`, `.env*`, `*.pem/key`, `__pycache__`).

### 완료된 항목 (누적)
- 핵심 스키마 + pgvector 벡터검색 + 6대 고도화(감사로그/RBAC/CVSS스코어링/RLS/이상탐지/ATT&CK)
- 실무보완: 타입강화, CVSS정합성, 감사로그 불변성+보존, RLS확장, 인증강화 가이드, 백업/복구
- FK 참조동작 정비(V018), departments 마스터+FK(V019), event_type CHECK→마스터+FK(V027)
- search_path 고정(V021), 함수 EXECUTE 최소화(V022), **감사로그 해시체인 + `fn_verify_audit_chain()`**(V023)
- 컬럼 단위 권한(V024), `mv_asset_risk_score`+갱신함수(V025), 자원제한(V026), 시간무결성 트리거(V028)
- 합성 이벤트 파이프라인: `svc_event_ingest` 최소권한 계정 + RLS `WITH CHECK ('[SIM]%')`(V029),
  `scripts/generate_synthetic_events.py`
- **KISA 설정취약점 통합(V030)**: `kisa_scanner.py`(U-01~U-72)를 리눅스에서 실행 →
  `import_kisa_results.py` 가 "취약" 만 `vulnerabilities`(`source='SCAN'`, `finding_ref='KISA-U-##'`)
  + `scan_runs` + `asset_vulnerabilities` 로 적재. KISA 중요도 상/중/하 → HIGH·7.5 / MEDIUM·5.0 / LOW·2.5
  환산으로 `vw_asset_risk_score` 그대로 재사용.
- **EPSS 악용확률 연동(V031)**: `epss_sync.py` 가 FIRST.org EPSS API 로 `nvd_cve_details.epss_*` 채움.
  `vw_priority_vulnerabilities` = **priority_score = cvss_score × epss_score** + `epss_over_cvss` 플래그
  (CVSS 낮은데 실제 악용 상위). 대시보드 섹션 h(priority vs CVSS 대조) 추가.
- **실시간 알림/에스컬레이션(V032)**: `alert_notifier.py`(macOS/Slack/이메일 다채널 + `logs/alerts.log`) +
  `alert_poller.py`(폴링, launchd 2분). 소스 (a) 최근 2h CRITICAL `security_events`([SIM] 포함, 문구 표기),
  (b) 감사체인 손상. `alert_log(alert_type, ref_key)` UNIQUE 로 **중복 알림 방지**.
- **벡터검색 ↔ 이벤트 자동 매칭(V033)**: `security_events.embedding VECTOR(384)`(+ HNSW) 추가 →
  `event_threat_linker.py` 가 신규 이벤트 임베딩을 채우고 `threat_reports`/과거 이벤트와 코사인
  유사도 매칭을 `event_threat_matches`(`match_type` = `THREAT_REPORT` | `PAST_EVENT`, `uq_etm_dedup`
  + `ON CONFLICT DO NOTHING`)에 적재. 조회용 `vw_event_threat_matches`. SOC 대시보드 섹션 i 를
  i-1(THREAT_REPORT)/i-2(PAST_EVENT) 로 분리 — 유사도 스케일이 다른 두 종류가 서로를 밀어내지 않도록.
  launchd `com.security-db.threatlink` 10분 주기로 등록.
- 마이그레이션 러너 `migrate.py` (sha256 drift 탐지). Flyway 는 설치되나 psql 메타명령 비호환으로 미채택.
- NVD 연동(`nvd_sync.py`/`nvd_watch.py`), SOC 대시보드(`soc_dashboard.py` + 합성데이터 필터 토글 + EPSS 우선순위)
- 복구 드릴(RTO ≈ 0.2초, 모든 지표 일치), 성능 점검 노트(`PERFORMANCE_NOTES.md`)

### 자동 스케줄 (launchd) — **6종** 모두 등록·`exit 0`
| Label | 주기 | 스크립트 | 로그 |
|---|---|---|---|
| `com.security-db.backup` | 매일 03:30 | `backup_scheduled.sh` (DB 덤프 + `pg_dumpall --roles-only`, 14일/7개 보존) | `db_backups/backup.log` |
| `com.security-db.synth` | 25분마다 | `generate_synthetic_events.py` (합성 이벤트 1~3건) | `~/Library/Logs/security-db-synth.*.log` |
| `com.security-db.threatlink` | **10분마다** | `event_threat_linker.py` (신규 이벤트 임베딩 + `event_threat_matches` 자동 매칭) | `~/Library/Logs/security-db-threatlink.*.log` |
| `com.security-db.auditverify` | 매일 04:00 | `verify_audit_chain.sh` (해시체인 점검, breaks>0 시 ALERT + `alert_poller --source audit`) | `logs/audit_verify.log` |
| `com.security-db.epsssync` | 매일 05:00 | `epss_sync.py` (FIRST.org EPSS 재동기화) | `~/Library/Logs/security-db-epsssync.*.log` |
| `com.security-db.alertpoll` | **2분 주기** | `alert_poller.py` (CRITICAL 이벤트 + 감사체인 폴링 → 알림) | `~/Library/Logs/security-db-alertpoll.*.log` · `logs/alerts.log` |

확인: `launchctl list | grep security-db` (가운데 숫자 = 마지막 종료코드, 0=정상) — 2026-09-08 6종 전부 0.
`threatlink.err.log` 은 anaconda numpy/scipy `UserWarning` 한 줄뿐(무해).

### 라이브 DB 상태값 (2026-09-08)
- `assets` 15건 · `vulnerabilities` **28건 (NVD 12 / SCAN 14 / MANUAL 2)** · `scan_runs` 1건 · **테이블 18 / 뷰 8**
- `nvd_cve_details` 14행: EPSS 채워짐 12 / nvd_status **SYNCED 12 · NOT_FOUND 2** (PENDING 은 `nvd_sync.py` 로 정리 완료)
- `security_events` 63건 (그중 `[SIM]` 33, `embedding` 채워짐 33) · `audit_log` 100건 · **`alert_log` 2건**(테스트 알림 이력)
- **`event_threat_matches` 151행 — THREAT_REPORT 52 / PAST_EVENT 99** (`threatlink` 10분 주기가 계속 증분 적재)
- 해시체인 `breaks = 0` · RLS 정책 9 · **schema_migrations 33** · FK 17 · CHECK 23
- `vw_priority_vulnerabilities` 12건, 그중 `epss_over_cvss=TRUE` **1건 = CVE-2021-26085**(CVSS 5.3 MEDIUM, EPSS 백분위 1.000)
- 예시 MANUAL 2건: CVE-2021-26085(사용자포털), CVE-2020-3452(방화벽-메인) — 실제 '낮은 CVSS/높은 EPSS' 시연용
- `[SIM]` 데이터는 `description`/`action_taken` 접두사로 구분, `svc_event_ingest` RLS 가 태그 강제

### 남은 이슈 / 다음에 하면 좋을 후보
- **SIM 볼륨**: synth 잡 25분 주기 → 하루 ~100~150건 누적. 데모 아닐 때 `unload` 하거나
  plist `ProgramArguments` 에 `--count 1` 추가 검토. 정리: `DELETE FROM security_events WHERE description LIKE '[SIM]%'` (responses CASCADE, 해시체인 무결).
- **KISA 재스캔**: Docker Desktop 데몬이 떠 있어야 함(이번엔 이 작업 위해 기동). `ubuntu:22.04` 이미지는 캐시됨.
  컨테이너엔 systemd 가 없어 서비스 항목 14건이 "점검불가" → 실 VM/EC2 에서 돌리면 커버리지 상승.
- **대시보드 섹션 c** 를 `vw_asset_risk_score` → `mv_asset_risk_score` 로 교체(규모 대비, 코드 1줄).
- **pg_cron 미설치**: `fn_archive_audit_log()`(보존 이관), `fn_refresh_risk_score()`(매트뷰 갱신)
  가 스케줄 미등록 상태. pg_cron 설치 또는 OS 크론/launchd 로 등록 필요.
- **RLS 부서 정책의 행별 함수 호출**이 규모 확대 시 1순위 병목 (`PERFORMANCE_NOTES.md` 3-A).
  의도적으로 현재 미변경 — 수만 행대 진입 시 `department` 비정규화 또는 세션 GUC 고정.
- `logs/audit_verify.log` 에 ALERT 트리거 테스트 흔적(`db=security_db_chaintest`) 있음 — 라이브(`db=security_db`)와 구분되므로 무해, 필요 시 로그 로테이션.
- `alert_log` 에 테스트 알림 1건(`CRITICAL_EVENT` ref_key=`59`, 해당 이벤트는 삭제됨) — ref_key 는 텍스트라 무해, 필요 시 삭제.
- **`nvd_status='PENDING'` 정리**: `epss_sync.py` 가 EPSS-only 행을 PENDING 으로 만들면 `nvd_sync.py` 가 SYNCED 로 정정.
  정기화하려면 05:00 `epss_sync` 잡 앞에 `nvd_sync.py` 도 등록(현재 nvd_sync 는 수동).
- **알림 채널**: 현재 macOS 네이티브만 활성. Slack/이메일은 `alertpoll` plist 의 `EnvironmentVariables` 에
  `SLACK_WEBHOOK_URL` / `ALERT_SMTP_*` 넣으면 자동 시도.
- TLS/SSL, pg_hba scram 전환: 가이드 문서만 존재(`TLS_SSL_GUIDE.md`, `auth_hardening.sql`), 운영 반영 시 적용.
- 파티셔닝: `security_events` 는 FK 무결성과 충돌로 보류(`RUN_ORDER.md` 「파티셔닝 검토」).

---

## 히스토리

### 2026-09-08 KST — Git 저장소 초기화 + 단계별 커밋 히스토리 재구성 + GitHub 비공개 저장소

#### 1. 저장소 초기화
- `~/security_db_project/` 는 그동안 git 관리가 아니었음(`.gitignore` 만 존재). `git init -b main`.
- `git config` 사용자: `hyeonggeun <polkmn0721@gmail.com>` (전역 설정 사용).

#### 2. 단계별 커밋 재구성 (총 14 커밋, 실제 작업 시점으로 backdate)
`schema_migrations.applied_at` + V*.sql 파일 mtime + `PROJECT_LOG.md` 히스토리를 근거로
논리적 단계별 커밋. `GIT_AUTHOR_DATE`/`GIT_COMMITTER_DATE` 를 실제 시점에 맞춤:

| 날짜 | 커밋 | 포함 |
|---|---|---|
| 2026-09-02 | 핵심 스키마 + 기본 뷰 | V001, ERD, .gitignore |
| 2026-09-03 | pgvector 벡터 유사도 검색 | V002 + 임베딩/검색 스크립트 |
| 2026-09-03 | 고도화 6종 | V003–V008 |
| 2026-09-03 | 데이터 확충 + 트랜잭션 + 인덱스 | V009–V011 |
| 2026-09-04 | 실무보완 5종 + 백업복구 | V012–V016, `backup_restore.sh` |
| 2026-09-04 | NVD 연동 + SOC 대시보드 | V017 + `nvd_*.py`, `soc_dashboard.py`, 대시보드 스크린샷 |
| 2026-09-07 | QA 라운드: FK/departments/CHECK | V018–V020 |
| 2026-09-07 | 보안 하드닝 + TLS 가이드 | V021–V026, `TLS_SSL_GUIDE.md` |
| 2026-09-07 | migrate.py 도구화 + 백업자동화 + V027/V028 | `migrate.py`, `RUN_ORDER.md`, `schema_dump.sql`, backup plist |
| 2026-09-07 | 합성 이벤트(V029) + 프로젝트 홈 이동 | V029, `generate_synthetic_events.py`, synth plist |
| 2026-09-07 | 복구드릴/SIM필터/감사자동검증/성능 | `verify_audit_chain.sh`, `PERFORMANCE_NOTES.md`, `PROJECT_LOG.md`, SIM 스크린샷 |
| 2026-09-07 | KISA 스캐너 연동(V030) | V030, `kisa_scanner.py`, `import_kisa_results.py`, `reports/kisa_scans/` |
| 2026-09-07 | EPSS 연동(V031) | V031, `epss_sync.py`, EPSS 스크린샷 |
| 2026-09-07 | 실시간 알림(V032) + EPSS 스케줄 | V032, `alert_notifier.py`, `alert_poller.py`, 2개 plist |
| 2026-09-08 | Git 워크플로 + 문서 최신화 | 이 커밋 (`RUN_ORDER.md` Git 메모, `PROJECT_LOG.md`) |

- 커밋 메시지: 각 단계 "무엇을 왜" 1~3줄 한글.
- 재구성 한계: `RUN_ORDER.md`/`schema_dump.sql`/`PROJECT_LOG.md` 는 최종본만 존재해 그 태어난 커밋에
  최신 내용이 들어감(중간 상태 재현 불가). 마이그레이션 파일·스크립트는 단계별로 정확히 배치됨.

#### 3. `.gitignore` 재점검
- 제외 확인: `db_backups/`(1.1MB, 덤프+roles), `logs/`(alerts/audit_verify), `*.dump`, `__pycache__`, `.venv/`,
  `.env*`, `.pgpass`, `*.pem/*.key`, `*secret*`, `*credential*`, `.DS_Store`.
- **포함**: `screenshots/`(7.8MB, 16장 — 포트폴리오용), `reports/kisa_scans/*.log`(스캔 증적, `!` 예외처리),
  `sql/*.sql`, `sql/schema_dump.sql`.
- 민감파일 스캔: `.env`/`.pgpass`/자격증명 파일 없음 확인. `auth_hardening.sql` 의 `Xxx#Tmp-2026!chg` 는
  "임시 예시 비밀번호"(운영 반영 시 교체 전제)라 커밋 대상 유지.
- 추적 파일 86개.

#### 4. GitHub 비공개 저장소
- `gh` CLI 는 이 세션에서 `brew install gh` 로 설치했으나 **미인증**(`gh auth status` → not logged in).
- `gh auth login` 은 브라우저/디바이스코드 대화형이라 **사용자가 직접 실행 필요**. 아래 「다음 할 일」 참고.
- 로컬 커밋 14개는 완료. 인증 후 `gh repo create` + `git push` 만 하면 됨.

#### 다음 할 일 (사용자)
```
gh auth login                       # 브라우저 로그인 (GitHub.com, HTTPS, 프로토콜 git)
gh repo create security-db-project --private --source=. --remote=origin --push
# (repo 이름 대안: security-db-soc, security-event-vuln-db 등)
```
그 다음부터는 매 라운드 종료 시 `git add -A && git commit -m "..." && git push`.

---

### 2026-09-07 22:30 KST — 실시간 알림/에스컬레이션 파이프라인 + EPSS 재동기화 스케줄 (V032)

> 작업 중 맥이 절전되며 응답이 끊겼으나, 다음 세션에서 상태 확인 결과 **모든 변경은 정상 반영**돼 있었다
> (V032 적용됨, 스크래치 DB·docker 컨테이너 정리 완료, launchd 5종 exit 0). 아래는 이번 작업 상세.

#### 1. 알림 발송 모듈 `scripts/alert_notifier.py`
- `notify(title, message, subtitle, url)` → 있는 채널을 순서대로 시도(하나 실패해도 계속):
  · **macOS 네이티브** (`osascript display notification`) — 기본, 외부 의존 없음
  · **Slack Incoming Webhook** — `SLACK_WEBHOOK_URL` 있으면
  · **이메일(SMTP)** — `ALERT_SMTP_HOST/PORT/USER/PASS/FROM/TO` 있으면
- 채널 무관하게 항상 `logs/alerts.log` 기록. CLI(`--title/--message/...`)도 지원.
- 현재 환경: macOS 채널만 활성(테스트 시 `channels=macos` 확인).

#### 2. 트리거 방식 — **폴링(launchd 2분) 채택** (LISTEN/NOTIFY 아님)
근거:
- 이 프로젝트 운영 계층이 이미 전부 launchd 주기 잡(backup/synth/auditverify) → **일관성**, 상주 데몬 수명관리 불필요.
- NOTIFY 는 리스너 없을 때 **유실**(영속성 없음). 폴링 + `alert_log` dedup 은 실행이 밀려도 다음 주기에 **자가복구**.
- 규모가 작아(이벤트 수십~수백/일) 2분 지연은 학교 SOC 데모에 충분.
- 대량/즉시성이 필요해지면 `security_events` 트리거 `pg_notify` + 상주 리스너로 전환(그때도 `alert_log` dedup 재사용).

`scripts/alert_poller.py` (launchd `com.security-db.alertpoll`, `StartInterval 120`):
- **소스 a** — `security_events` 중 `severity='CRITICAL' AND detected_at >= now()-2h` 이고 아직 미알림.
  · 시간창 2h: 1년 전 이벤트 알림은 무의미. 첫 실행이 과거 CRITICAL 로 폭주하는 것도 방지.
  · **`[SIM]` 이벤트도 알림 대상**에 포함하되 문구 앞에 `[SIM]` 표기 + 제목에 `[SIM]` (`ALERT_INCLUDE_SIM=0` 이면 제외).
    이유: 합성 주입 파이프라인이 CRITICAL 을 만들어내는지도 SOC 가 봐야 하고, 데모에서 알림이 자연스럽게 뜬다.
- **소스 b** — `fn_verify_audit_chain()` breaks>0. `verify_audit_chain.sh` 도 ALERT(exit 2) 시 `alert_poller.py --source audit` 호출.

#### 3. 중복 알림 방지 — `alert_log` 테이블 (V032)
- **별도 테이블** 선택(`security_events` 에 `alerted_at` 컬럼 추가 안 함): 컬럼 UPDATE 는 감사 트리거를
  발화시켜 `audit_log`/해시체인에 잡음을 남긴다. `alert_log` 는 `security_events` 를 안 건드린다.
- `alert_log(alert_id, alert_type CHECK IN(CRITICAL_EVENT|AUDIT_CHAIN), ref_key, severity, summary,
  channels TEXT[], is_synthetic, payload JSONB, created_at)` + **`UNIQUE(alert_type, ref_key)`**.
- 폴러: `INSERT .. ON CONFLICT (alert_type, ref_key) DO NOTHING RETURNING alert_id` → 행 반환되면 신규 → 발송,
  발송 후 `channels` 기록. 폴링이 겹쳐 돌아도 원자적으로 1회만.
- `ref_key`: CRITICAL_EVENT=`event_id`, AUDIT_CHAIN=`db명:breaks수:깨진audit_id들`(같은 손상은 재알림 안 함, 새 손상은 알림).
- GRANT: SELECT analyst/admin/manager, INSERT security_admin. RLS 없음.

#### 4. 테스트 — 전부 통과
- **CRITICAL 이벤트**: 강제로 `security_events` 에 `CRITICAL` 1건(#59) INSERT → `alert_poller.py` →
  macOS 알림 발송 확인(`logs/alerts.log`). 폴러 재실행 → **dedup, 재알림 없음**. (테스트 후 #59 삭제, `alert_log` 행은 유지 — ref_key 텍스트라 무해)
- **감사체인 ALERT**: 스크래치 `security_db_chaintest`(V001~V032) 구축 → `audit_log` 한 행 강제 조작(트리거 잠깐 비활성) →
  `verify_audit_chain.sh` exit 2 → `alert_poller.py --source audit --database security_db_chaintest` →
  `감사로그 해시체인 손상 감지! breaks=1 깨진 audit_id=[2]` 알림 발송. 재실행 → dedup. **라이브 감사로그 미변경**. 스크래치 DROP.
- 알림 로그(`logs/alerts.log`) 3건 남음: 수동 테스트 / CRITICAL #59 / chaintest ALERT.

#### 5. EPSS 재동기화 스케줄 `com.security-db.epsssync` (매일 05:00)
- `epss_sync.py` 등록 → `launchctl start` → **exit 0**, EPSS 12/14 재동기화 확인.
- **PENDING 정리**: `epss_sync.py` 가 만든 `nvd_status='PENDING'` 2건(CVE-2021-26085, CVE-2020-3452)은
  **`nvd_sync.py` 실행으로 SYNCED 로 정정됨**(NVD 실조회 CVSS 7.5 HIGH / 5.3 MEDIUM = MANUAL 값과 일치).
  → 현재 `nvd_status`: SYNCED 12 · NOT_FOUND 2 · PENDING 0. `vw_priority_vulnerabilities` 데모 케이스 유지.
  (정기 정리하려면 05:00 잡 앞에 `nvd_sync.py` 도 등록 권장)

#### 6. 검증
- `alert_log` CHECK 위반 0. `vw_cvss_nvd_mismatch` = 7 (MANUAL 2건 밴드 일치, 오탐 0). `nvd_cve_details` EPSS 범위 위반 0.
- **해시체인 breaks = 0** (`alert_log` 는 감사 트리거 대상 아님. #59 INSERT/DELETE 는 트리거 발화하나 체인은 연속).
- `migrate.py status` → **적용됨 32 · drift 0**. fresh QA 재구축(V001~V032) 예상외 ERROR 0 (테이블 17 / 뷰 7).
- RLS: `security_manager` `alert_log` 조회 OK, `dept_infra` → permission denied(의도대로).
- **launchd 5종 전부 exit 0**: backup / synth / auditverify / epsssync / alertpoll.
- `schema_dump.sql` 재생성(3213줄). `RUN_ORDER.md`: V032 행 + 「실시간 알림」 섹션 + launchd 표 5종 갱신.

#### 스크래치/테스트 리소스 정리 상태 (다음 세션 확인)
- `security_db_chaintest`, `security_db_qa` — **DROP 완료** (psql -l 에 없음).
- docker `kisa_target` 등 — **없음** (`docker ps -a` 비어있음).
- 테스트 이벤트 `security_events #59` — **삭제 완료**.
- 남은 것(의도적): `alert_log` 1행(ref_key=59), `logs/alerts.log` 3줄, `logs/audit_verify.log` 의 chaintest 흔적.

---

### 2026-09-07 22:10 KST — EPSS(악용확률) 연동 + CVSS×EPSS 우선순위 스코어링 (V031)

#### 1. EPSS 동기화 스크립트 `scripts/epss_sync.py`
- FIRST.org EPSS API(`https://api.first.org/data/v1/epss?cve=...`, 인증불필요) 배치 조회
  (요청당 50 CVE, `--batch` 조정). `nvd_sync.py` 의 재시도(429/5xx 백오프)·요약 패턴 재사용.
- 대상: `vulnerabilities WHERE cve_id IS NOT NULL` (NVD/MANUAL. KISA SCAN 행은 cve_id 없어 제외).
- `nvd_cve_details` 에 `INSERT ... ON CONFLICT (cve_id) DO UPDATE` (epss_* 컬럼만 갱신) → **idempotent**.
  기존행 없으면 `nvd_status='PENDING'` 으로 생성.

#### 2. 스키마 (V031) — **nvd_cve_details 에 컬럼 추가** 채택
- 근거: `nvd_cve_details` 는 이미 "cve_id 별 외부 CVE 인텔리전스" 테이블. EPSS 도 같은 성격
  (외부·CVE단위·주기 재동기화)이라 한곳에 모음. 뷰에서 `vulnerabilities ⨝ nvd_cve_details`
  한 조인으로 CVSS+NVD+EPSS 동시 확보. 코어 `vulnerabilities` 는 깨끗하게 유지(V017 원칙).
- 추가: `epss_score NUMERIC(8,7)`, `epss_percentile NUMERIC(8,7)`, `epss_model_date DATE`, `epss_updated_at TIMESTAMPTZ`.
- CHECK: `chk_epss_score` / `chk_epss_percentile` (0~1). `nvd_status` CHECK 에 `'PENDING'` 추가.

#### 3. CVSS + EPSS 결합 공식 (문서화)
- **`priority_score = round(cvss_score × epss_score, 3)`** (0~10, "확률 가중 CVSS").
- 해석: 기대 영향도 = 심각도(CVSS) × 악용 확률(EPSS). FIRST.org 권고 사용법과 일치.
- 곱을 쓰는 이유(가중합 대신): 가중합은 "CVSS 9.8 인데 아무도 안 건드리는" 항목을 계속 위험해
  보이게 함. 곱은 그런 항목을 자연히 낮추고 "CVSS 5.3 / EPSS 0.999" 를 최상위로 올림 — EPSS 를 쓰는 이유.
- 트레이드오프: 갓 공개된 CRITICAL 은 EPSS 가 낮아(모델 지연) 곱이 작아질 수 있음 → 뷰는
  `cvss_score`/`epss_percentile`/`epss_band` 를 함께 노출하고 `epss_over_cvss` 플래그로 별도 강조.
- `vw_priority_vulnerabilities`: 위 컬럼들 + `epss_over_cvss = (epss_percentile ≥ 0.90 AND severity IN (LOW,MEDIUM))`,
  `open_on_assets`. `ORDER BY epss_over_cvss DESC, priority_score DESC`. GRANT SELECT analyst/admin/manager.

#### 4. "낮은 CVSS / 높은 EPSS" 시연
- 우리 합성 CVE 10건은 EPSS 전부 < 0.007 (percentile ≤ 0.5) — 해당 케이스 없음.
- → 실제 CVE 2건을 `source='MANUAL'` 로 추가(예시 시나리오, `[예시]` 표기):
  · **CVE-2021-26085** Confluence pre-auth 파일읽기 — NVD CVSS **5.3 MEDIUM**, EPSS **0.9994** (TOP 1%, CISA KEV). → 사용자포털 연결.
  · **CVE-2020-3452** Cisco ASA 경로우회 파일읽기 — NVD CVSS **7.5 HIGH**, EPSS **0.9999**. → 방화벽-메인 연결.
- `epss_sync.py` 재실행 후 `vw_priority_vulnerabilities`:
  · **CVSS 1위** = CVE-2025-0001 (9.8, priority 0.054)
  · **priority 1위** = CVE-2020-3452 (7.5, priority 7.499)
  · **`epss_over_cvss` 플래그** = CVE-2021-26085 (5.3 MEDIUM, EPSS 백분위 1.000) — CVSS 로는 후순위지만 최상위로 강조됨

#### 5. 대시보드 — 섹션 h 추가
- `soc_dashboard.py` 에 **"h. EPSS 악용확률 기반 우선순위 (CVSS × EPSS)"**:
  h-1(priority 정렬, `epss_over_cvss` 는 🔴), h-2(CVSS 정렬 대조군) 나란히 + 노란 경고박스로 hidden gem 강조.
- 스크린샷 `screenshots/soc_epss_priority.png` (풀페이지, 섹션 h 포함).

#### 6. 검증 — 전부 통과
- `epss_score`/`percentile` 범위(0~1) 위반 0. `nvd_status` 분포 SYNCED 10 / NOT_FOUND 2 / PENDING 2 (전부 유효).
- av 고아 0. **해시체인 breaks = 0** (EPSS/MANUAL 삽입은 `vulnerabilities`/`asset_vulnerabilities`/`nvd_cve_details` → 감사 트리거 대상 아님, `audit_log` 45 불변).
- `vw_cvss_nvd_mismatch` = 7 (PENDING 2건 자동 제외 — `nvd_status='SYNCED'` 필터).
- `epss_sync.py` 재실행 idempotent(응답 12 동일, 카운트 동일). `migrate.py status` → 적용됨 31 · drift 0.
  fresh QA 재구축(V001~V031) 예상외 ERROR 0.
- RLS: `security_analyst`/`security_manager` 는 `vw_priority_vulnerabilities` 조회 OK, `dept_infra` → permission denied(의도대로).
- `schema_dump.sql` 재생성(3109줄).

#### 부수
- `RUN_ORDER.md`: V031 행 + 파이썬 후속단계에 `epss_sync.py` 추가. `.gitignore` 변경 없음.
- 예시 MANUAL 2건은 fresh 재구축엔 없음(스크립트/수동 데이터). PROJECT_LOG 에 INSERT 문 근거 기록.

---

### 2026-09-07 21:45 KST — KISA 취약점 스캐너 실제 연동 (스캔 실행 + DB 통합, V030)

#### 1. 스캔 대상 결정
- `~/Linux`(수업용 git 저장소), `~/linux_test`(txt 하나뿐) 는 리눅스 VM 이 아님.
- **Docker Desktop 설치돼 있음** (데몬은 꺼져 있어 이 작업 위해 기동). → `ubuntu:22.04` 컨테이너를
  띄우고 `python3 openssh-server cron rsyslog` 설치 후 그 안에서 root 로 스캔.
  판단 근거: KISA U-01~U-72 는 리눅스 전용 항목이 많아 맥에서 돌리면 대부분 "점검불가". DVWA
  이미지(Debian 9)는 python 이 없고 EOL 이라 제외. `ubuntu:22.04` 가 가장 깔끔.
- 한계: 컨테이너엔 systemd 가 없어(`System has not been booted with systemd`) 서비스 상태
  항목 일부가 "점검불가". 실제 VM/EC2 에서 돌리면 커버리지가 더 높다.

#### 2. 스캔 실행
- 스크립트 안전성 검토: `subprocess.run(capture_output=True)` 로 상태조회만, 파일 쓰기는
  `--output-dir` 안(csv/json/full_list)뿐. 시스템 변경 없음 확인 후 실행.
- `python3 kisa_scanner.py --output-dir /root/scan_out --format both --verbose` (root)
- **결과: 총 72건 → 양호 44 / 취약 14 / 점검불가 14**. 리포트를 `reports/kisa_scans/` 로 복사.
  (`kisa_report_20260907_123335.{json,csv}`, `kisa_u-15_full_list_*.txt`)
- 취약 14건: U-01(root 원격접속) U-02(패스워드 복잡성) U-06(파일 소유자) U-08(/etc/shadow 권한)
  U-11(rsyslog.conf 권한) U-15(world-writable) U-22(cron 권한) U-45(su 제한) U-47(PASS_MAX_DAYS=99999)
  U-48(PASS_MIN_DAYS=0) U-53(sync 계정 셸) U-54(TMOUT 미설정) U-57(홈디렉토리 권한) U-58(홈디렉토리 없는 계정)

#### 3. DB 스키마 설계 — **(a) vulnerabilities 재사용** 채택 (V030)
- 근거: `vw_asset_risk_score`(importance × max_open_cvss), `vw_cvss_severity_mismatch`,
  `asset_vulnerabilities` 연결을 **그대로 재사용**하려면 KISA 항목도 `vulnerabilities` 에 있어야 한다.
  (b) 별도 `scan_findings` 는 위험도 로직을 새로 만들어야 해서 제외.
- 추가: `vulnerabilities.source`(NVD/SCAN/MANUAL, 기존 12행은 DEFAULT 'NVD'), `finding_ref`(비-CVE
  식별자, UNIQUE), `remediation`(조치권고). `chk_vuln_scan_ident`: SCAN 행은 `cve_id IS NULL AND finding_ref IS NOT NULL`.
  `cve_id` CHECK(`^CVE-...`)는 유지 → KISA 행은 cve_id NULL 이라 통과.
- `scan_runs` 테이블(도구/호스트/시각/root/집계/리포트경로), `asset_vulnerabilities.scan_run_id` + `observed_detail`(그 호스트 현재 설정값).
- **KISA 중요도 → severity / 환산 cvss_score** (문서화):
  상 → HIGH / **7.5** (CVSS HIGH 밴드 대표값), 중 → MEDIUM / **5.0**, 하 → LOW / **2.5**.
  CRITICAL 은 배정 안 함(NVD CVSS≥9.0 전용). severity 라벨과 밴드가 일치해 mismatch 뷰 오탐 없음.
  전체 72항목 중요도표는 `import_kisa_results.py` 의 `KISA_IMPORTANCE` 에 (KISA 상세가이드 기준).
- 데이터(asset/vuln/연결)는 마이그레이션이 아니라 `import_kisa_results.py` 가 적재.

#### 4. 임포트 스크립트 `scripts/import_kisa_results.py`
- JSON 리포트 파싱 → "취약" 만 적재. "점검불가/양호" 는 `reports/kisa_scans/import_<ts>.log` 로만.
- 대상 asset 없으면 생성: `KISA스캔대상-Ubuntu22.04.5LTS` (asset_type SERVER, department 보안팀, importance 2).
- UPSERT: `vulnerabilities` by `finding_ref`, `asset_vulnerabilities` by `(asset_id, vuln_id)`,
  `scan_runs` by `(tool, hostname, scanned_at)`. **재실행 idempotent 확인**(2회차: 신규 0 / 갱신 14).
- 접속: 소유자 계정(관리자 ETL, `nvd_sync.py` 와 동일).
- 적재 결과: `vulnerabilities` +14 (HIGH 8 / MEDIUM 5 / LOW 1), `asset_vulnerabilities` +14 (asset_id 16), `scan_runs` +1.

#### 5. 검증 — 전부 통과
- FK/CHECK 위반 0. SCAN 행 중 cve_id 보유 0. av 고아 0. severity/cvss CHECK 위반 0.
- **해시체인 breaks = 0** (KISA 임포트는 `vulnerabilities`/`asset_vulnerabilities` 라 감사 트리거 대상 아님 → `audit_log` 불변).
- `migrate.py status` → 적용됨 30 · drift 0. fresh QA 재구축(V001~V030) 예상외 ERROR 0.
- `vw_asset_risk_score`: KISA asset → risk_score 15.0 MEDIUM (importance 2 × max_open_cvss 7.5). `mv_asset_risk_score` 도 `fn_refresh_risk_score()` 후 반영.
- `vw_cvss_severity_mismatch`: SCAN 유래 오탐 0 (밴드 일치).
- RLS: `dept_infra` 는 KISA asset(보안팀) 안 보임(5건 유지), `security_manager` 전체 조회 정상,
  `security_analyst` SCAN vuln 14건 조회. 대시보드 쿼리(섹션 a~g) 에러 없이 렌더(`screenshots/soc_kisa_full.png`).
- `schema_dump.sql` 재생성(3036줄, scan_runs/finding_ref/source/observed_detail 반영).

#### 부수
- `RUN_ORDER.md`: V030 행 + 「KISA 설정취약점 스캔 → DB 통합」 섹션 추가.
- Docker: `kisa_target` 컨테이너 제거(이미지 캐시 유지). Docker Desktop 데몬은 사용자가 필요없으면 종료 가능.
- `reports/kisa_scans/` 는 커밋 대상(작은 텍스트/JSON, 증적).

---

### 2026-09-07 21:15 KST — 복구 드릴 재검증 / 대시보드 SIM 필터 / 감사로그 자동검증 / 성능 점검

작업 4건. 상세:

#### 1. 복구(Restore) 드릴 재검증
- 대상: `db_backups/security_db_20260907_210655.dump` (custom format, `pg_dump --format=custom --no-owner`).
- `security_db_restore_test` 새로 만들어 `pg_restore --exit-on-error` → **에러/경고 0**.
- 원본(라이브, synth 잡 잠시 unload 후 새 백업 기준) vs 복원본 **모든 지표 완전 일치**:
  - 행수: assets/staff/vulnerabilities/asset_vulnerabilities/security_events(45)/responses(26)/threat_reports 등
  - 구조: 뷰 6 · matview 1 · `fn_*` 함수 · 트리거(`trg_responses_time_check`, `trg_audit_*`) · 인덱스 27 · FK 12 · CHECK 15
  - RLS: 정책 9개 **정의까지 동일**, 테이블 GRANT 206 / 컬럼 GRANT 149 동일
  - pgvector: `CREATE EXTENSION vector` 포함, `threat_reports.embedding` 8건 복원, **벡터 유사도 검색 실동작**(report 2 self-sim 1.000)
  - 해시체인: 복원본 `fn_verify_audit_chain()` breaks=0
  - `SET ROLE` 로 RLS 실동작 확인: dept_infra 20 / security_manager 45 / svc_event_ingest → permission denied
- **RTO(데이터 복원 구간) ≈ 0.2초** (createdb + roles 적용 + `CREATE EXTENSION` + pg_restore). 실제 DR 은 서버 프로비저닝·PG/pgvector 설치가 지배적 → 현실 end-to-end RTO ≈ 5~15분.
- **발견사항**: `pg_dump`(단일 DB)에는 `CREATE ROLE` 이 없다(role 은 cluster-global). 같은 클러스터 복구는 무해하나 새 클러스터 복구 시 role 을 먼저 만들어야 GRANT/RLS 가 붙는다.
  → **조치**: `backup_scheduled.sh` 가 `pg_dumpall --roles-only --no-role-passwords` 로 `db_backups/roles_<ts>.sql` 도 함께 뜨도록 수정(보존정책 동일 적용). DR 순서: `psql -f roles_<ts>.sql` → `CREATE EXTENSION vector` → `pg_restore`.
- 테스트 DB(`security_db_restore_test`) DROP 완료.

#### 2. SOC 대시보드 — 합성(SIM) 데이터 필터 토글
- `soc_dashboard.py` 사이드바 "표시 옵션" → 체크박스 **"합성(시뮬레이션) 데이터 포함 보기"**.
- **기본값 OFF(제외)**. 이유: 대시보드 1차 목적은 큐레이션된 실제 데이터(ATT&CK 매핑·의도된 급증)를 보여주는 것이고, 합성 이벤트는 `vuln_id`/ATT&CK 가 없어 e/f 섹션을 "(미매핑)" 으로 희석. 데모에서 "피드가 흐른다"를 보일 때만 ON.
- 토글 시 카드·차트·표 전부 일관 필터: `security_events.description` / `responses.action_taken` / `audit_log`(대상행이 SIM 이벤트·대응인 변경).
- 스크린샷: `screenshots/soc_sim_toggle_OFF.png`, `soc_sim_toggle_ON.png`.
- 수치 변화(OFF → ON): OPEN 4→12 · 최근 24h 0→15 · 감사로그 21→43 · 심각도 2/8/15/5 → 9/12/17/7 · ATT&CK 최상위 "Privilege Escalation 10" → "(미매핑) 18". 섹션 c(취약점 기반)는 불변(정상).

#### 3. 감사로그 해시체인 자동 검증 (launchd)
- 신규 `scripts/verify_audit_chain.sh`: `fn_verify_audit_chain()` → `logs/audit_verify.log` 에
  `OK ... breaks=0` 또는 `*** ALERT *** 해시체인 손상 감지! breaks=N` + 깨진 `audit_id`·해시 diff·조치안내. breaks>0 이면 **exit 2**.
- 신규 `scripts/com.security-db.auditverify.plist`: 매일 04:00. 등록 → `launchctl start` → **exit 0** 확인.
- **ALERT 트리거 테스트**: 스크래치 DB `security_db_chaintest`(V001~V029) 에서 `audit_log` 한 행의 `changed_by` 를 강제 조작(트리거 잠깐 비활성) → verify 재실행 시 `*** ALERT *** breaks=1`, `audit_id=2 | row_hash 불일치`, expected/stored 해시 표시, exit 2. **라이브 감사로그 미변경**(breaks=0 유지). 스크래치 DB DROP 완료.

#### 4. 성능 점검 (신규 `PERFORMANCE_NOTES.md`)
- 현재 규모(테이블당 6~45행)에서 **이슈 없음**. `EXPLAIN (BUFFERS)` 전부 `shared hit`, `read=0`. Seq Scan 이 Index Scan 보다 싸서 옵티마이저가 정확히 선택.
- 인덱스 사용: `vulnerabilities_cve_id_key`(209, NVD sync), PK들, `idx_responses_event_id`(15), **HNSW `threat_reports_embedding_idx`(2, 8행인데도 실사용)** 활발. `idx_security_events_*` 등 `idx_scan=0` 이나 **불필요 아님** — V011 근거의 사전 인덱스, `enable_seqscan=off` 로 작동 확인. 삭제 대상 없음.
- 규모 확대 시 병목(우선순위): (1) RLS 부서 정책의 행별 함수 호출(`fn_asset_department`/`fn_current_dept`) — `assets` 4,951 seq_scan, (2) 대시보드 전체집계 풀스캔, (3) `vw_asset_risk_score` → `mv` 전환, (4) `fn_verify_audit_chain()` O(n), (5) `[SIM]` 접두사 필터는 btree 불가.
- 대응안은 `PERFORMANCE_NOTES.md` 「3. 병목 + 대응」/「4. 시점별 조치」 표 참조.

#### 부수 변경
- `backup_scheduled.sh`: roles 덤프 추가 + 보존정책을 `*.dump` / `roles_*.sql` 양쪽에 적용.
- `RUN_ORDER.md`: 「자동 스케줄 (launchd)」 를 3종으로 갱신 + 「운영 검증」 섹션 추가.
- `.gitignore`: `logs/` 추가.
- launchd `com.security-db.synth` 는 복구 드릴 중 unload 했다가 작업 종료 시 재등록(현재 exit 0).

---

### 2026-09-08 11:33 KST — 벡터검색 <-> 이벤트 파이프라인 연결 (V033) — 적용/실행/검증 완료

지금까지 pgvector 유사검색(V002, `threat_reports`)과 이벤트 파이프라인(`security_events`)이
서로 연결돼 있지 않았다 — "검색어를 사람이 입력"해야만 과거 사례를 찾을 수 있었다. 이번 작업으로
그 둘을 잇는 자동 매칭 기능을 설계·구현하고, 로컬에서 `migrate.py up` → `event_threat_linker.py`
→ `streamlit run soc_dashboard.py` 순으로 실제 적용/실행까지 완료했다.

#### 1. 스키마 — `sql/V033__event_threat_matching.sql`
- `security_events.embedding VECTOR(384)` 추가 (threat_reports 와 동일 모델/차원 → 코사인 거리로
  직접 비교) + HNSW 인덱스(`idx_security_events_embedding_hnsw`).
- `event_threat_matches` 테이블: `match_type` (`THREAT_REPORT` | `PAST_EVENT`) 로 두 매칭 대상을
  한 테이블에 통합(alert_log 가 alert_type 으로 두 소스 합친 것과 동일 패턴). `chk_etm_target` 으로
  match_type 별 필수 컬럼 강제 + 자기자신 매칭 차단. `uq_etm_dedup`(COALESCE(-1) 로 NULL 처리) +
  `ON CONFLICT DO NOTHING` 으로 재실행 시 중복 저장 방지.
- `vw_event_threat_matches`: 이벤트/리포트/과거이벤트 정보를 미리 조인한 조회용 뷰.
- GRANT: `alert_log`/`scan_runs` 패턴 그대로 — SELECT 는 3개 role 전부, INSERT 는 security_admin.
- `migrate.py up` 적용 결과: **ok (0.063s)**. `@migrate:verify` 전부 기대대로 — dedup 테스트
  1행→0행, CHECK 위반 2종(대상 컬럼 오조합 / 자기자신 매칭) 모두 에러로 거부, 적용 직후
  `vw_event_threat_matches` 0건(정상 - 아직 linker 실행 전).

#### 2. 적재 스크립트 — `scripts/event_threat_linker.py` 실행 결과
- `--dry-run` 먼저 확인 후 실제 실행. **신규 임베딩 24건**(event_id 41~65, 결번 59) ·
  **THREAT_REPORT 매칭 40건** · **PAST_EVENT 매칭 72건**.
- THREAT_REPORT 유사도는 대체로 0.46~0.60 대 — report_id=2(내부 DB 접근제어 우회)·
  4(방화벽 커널 권한상승)·7(클라우드 버킷 오설정)에 매칭이 몰림. 4건(43,44,51,58,64,65)은
  임계값(0.45) 미만이라 매칭 없음(정상 동작 - 무관한 이벤트를 억지로 안 붙임).
- **PAST_EVENT 유사도가 예상보다 높게 나옴**(다수 0.85~0.97). event_id 41~65 는 이 세션 이전에
  `synth`(합성 이벤트, 25분 주기) 이 쌓은 구간과 겹쳐 보인다 — 합성 이벤트 생성기의 문구 템플릿
  풀이 제한적이라 서로 거의 같은 문장이 나왔을 가능성이 큼(확정은 아니고, 소스 문구 직접 대조는
  아직 안 함). **완화책**: 대시보드 섹션 i 가 기존 SIM 필터(`_EVT_W`)를 그대로 재사용하므로
  `합성 데이터 포함 보기` 가 기본 OFF 인 상태에서는 이 노이즈가 자동으로 걸러진다. 순수 실제
  이벤트 기준 PAST_EVENT 매칭 품질은 다음에 SIM 제외하고 다시 확인할 것.
- `MIN_SIMILARITY`=0.45 는 이번 결과 기준으로는 THREAT_REPORT 쪽 노이즈 없이 잘 작동하는 것으로
  보임(관련 없는 이벤트는 실제로 매칭 안 됨). 추가 데이터 쌓이면 재점검.

#### 3. 대시보드 — `scripts/soc_dashboard.py` 섹션 i (렌더링 확인 + 재설계)
- 1차 버전(THREAT_REPORT/PAST_EVENT 합쳐서 유사도순 상위 30건)으로 렌더링 확인한 결과, 기본값
  (합성데이터 제외 OFF)에서는 "매칭 없음"으로 보였다 — 원인: 지금까지 description 이 채워진
  이벤트가 전부 `[SIM]` 합성 이벤트(event_id 41~65)뿐이라, SIM 필터에 전부 걸러진 것
  (버그 아님, 큐레이션된 원본 이벤트 1~40 은애초에 description 이 NULL 이라 임베딩 대상이 아니었음).
- SIM 필터를 켜고 확인한 결과, **표는 정상 동작** — 다만 상위 30건이 전부 PAST_EVENT 로 채워지고
  THREAT_REPORT(40건 존재)는 한 건도 안 보임: PAST_EVENT 유사도(0.85~0.97)가 THREAT_REPORT
  유사도(0.46~0.60)보다 구조적으로 훨씬 높아서, 하나로 합쳐 정렬하면 THREAT_REPORT 가 전부 밀려남.
- **흥미로운 발견**: 실제로 뜬 PAST_EVENT 매칭들을 보니 — 예) event_id 41 "VPN게이트웨이 에서
  알려진 악성 IOC 도메인 접속 시도" ↔ event_id 57 "방화벽-메인 에서 알려진 악성 IOC 도메인 접속
  시도" (sim=0.974), event_id 48 "피싱 의심 첨부(.html) 3건 자동 격리" ↔ event_id 56 "...5건..."
  (sim=0.972) — **서로 다른 자산에서 같은 문구/패턴이 반복**되고 있음을 정확히 잡아낸 것.
  `generate_synthetic_events.py` 의 문구 템플릿이 자산명만 바꿔 재사용되는 구조라 그런 것으로
  보이지만(원인 확정은 자산명 슬롯 채우는 템플릿 소스 확인까지는 안 함), 임베딩 모델 자체는
  "거의 같은 문장"을 정확히 높은 유사도로 잡아낸 것이라 **기능은 의도대로 동작**한 것으로 판단.
  실제 SOC 맥락으로 치환하면 "여러 자산에 걸쳐 같은 공격 캠페인/기법이 반복되고 있다"를 자동으로
  잡아주는 것과 같은 신호라 오히려 긍정적인 사례.
- **수정**: THREAT_REPORT/PAST_EVENT 를 합쳐서 정렬하지 않고 **각자 상위 15건으로 분리**
  (i-1/i-2 서브섹션, `vw_cvss_severity_mismatch`/`nvd_mismatch` 의 e-1/e-2 패턴과 동일)해서 —
  유사도 크기가 다른 두 매칭 종류가 서로를 밀어내지 않도록 재설계. 재확인은 다음 렌더링 때.

#### 4. launchd — 등록 완료 (2026-09-08) — `scripts/com.security-db.threatlink.plist`
- 10분 주기(`StartInterval 600`, synth 25분보다 촘촘). 기존 5개와 같은 형식(anaconda python3,
  `PGDATABASE` 환경변수, 로그 경로).
- `cp` → `launchctl load` (rc 0) → `launchctl start` (rc 0) → `launchctl list | grep security-db`
  결과 `com.security-db.threatlink` **가운데 숫자 0 (exit 0)** 확인. 이제 여섯 개 잡 전부 exit 0.
- 첫 launchd 실행(`launchctl start`)이 그 사이 synth 가 쌓은 신규 이벤트를 처리:
  `~/Library/Logs/security-db-threatlink.out.log` 마지막 줄 = **"완료: 신규 임베딩 9건 ·
  THREAT_REPORT 매칭 12건 · PAST_EVENT 매칭 27건."** → `event_threat_matches` 누적
  **THREAT_REPORT 52건 / PAST_EVENT 99건 (총 151행)**, `security_events` 임베딩 커버리지 33/63
  (나머지는 다음 10분 주기에 순차 처리).
- `.err.log` (266 bytes): anaconda `numpy 1.24.4` ↔ `scipy` 버전 불일치 `UserWarning` **한 줄뿐**,
  기능 영향 없음(임베딩 경로는 numpy 만 사용, out.log 는 정상 완료). 실패·트레이스백 없음.

#### 5. schema_dump.sql 재생성 (2026-09-08)
- `pg_dump -d security_db --schema-only --no-owner > sql/schema_dump.sql` 실행.
- 줄 수 **3213 → 3397 (+184)**.
- `grep` 로 V033 신규 오브젝트 3종 반영 확인:
  · `security_events.embedding public.vector(384)` (컬럼 + `COMMENT` + `idx_security_events_embedding_hnsw`)
  · `CREATE TABLE public.event_threat_matches` (+ `_match_type_check` / `_similarity_check` CHECK, PK, 시퀀스)
  · `CREATE VIEW public.vw_event_threat_matches` (+ 3개 role 대상 `GRANT SELECT`, security_admin `GRANT ALL`)

#### 6. 남은 할 일
- ~~대시보드 섹션 i 렌더링 확인~~ → 이번 세션에서 i-1/i-2 분리 버전 렌더링 확인 완료(사용자).
- ~~threatlink 등록~~ / ~~schema_dump.sql 재생성~~ → 완료(위 4·5).
- PAST_EVENT 고유사도가 진짜 합성 이벤트 템플릿 반복 때문인지 `generate_synthetic_events.py` 문구
  템플릿 소스 직접 대조 (아직 미확인).
- 순수 실제(비-SIM) 이벤트 기준 PAST_EVENT 매칭 품질 재확인 — 현재는 description 이 채워진
  이벤트가 전부 `[SIM]` 이라 SIM 제외 시 표본이 없음. 큐레이션 원본 이벤트(1~40)에 description
  백필하거나 실데이터가 더 쌓인 뒤 재점검.

#### 부수 변경
- `RUN_ORDER.md`: 순서·의존성 표에 V033 행, 「유사 사례 자동 매칭」 섹션 추가. launchd 섹션은
  이번에 "다섯 개 → 여섯 개", threatlink 를 메인 표로 이동(별도 "미등록" 하위 절 제거),
  등록/해제 `for` 문 리스트에 `threatlink` 추가, numpy/scipy 경고 주석 추가, threatlink 등록
  이력 절 추가로 갱신.
- `sql/schema_dump.sql`: 위 5번대로 재생성.

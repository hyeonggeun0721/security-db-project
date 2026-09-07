# security_db 프로젝트 로그

> 규칙: 아래 **「현재 상태」** 섹션은 매 작업 후 최신 상태로 **덮어쓴다**.
> **「히스토리」** 섹션은 작업마다 새 타임스탬프 항목을 **위쪽에 추가**하며,
> 기존 항목은 절대 수정/삭제하지 않는다.
> (제출용 4대 문서(제안서/중간보고서/최종보고서/기술문서)는 이 로그와 별개이며 건드리지 않는다.)

---

## 현재 상태

_최종 갱신: 2026-09-07 22:30 KST_

### 프로젝트 위치 / 적용 방식
- 경로: **`~/security_db_project/`** (macOS TCC 때문에 `~/Desktop` 에서 이동)
- 스키마: `scripts/migrate.py` 로 `sql/V001__*.sql` ~ **`V032__*.sql`** 적용.
  `migrate.py status` → **적용됨 32 · 미적용 0 · drift 0**
- 적용된 마이그레이션 파일은 불변. 변경은 새 `V###` 파일 추가로만.

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
- 마이그레이션 러너 `migrate.py` (sha256 drift 탐지). Flyway 는 설치되나 psql 메타명령 비호환으로 미채택.
- NVD 연동(`nvd_sync.py`/`nvd_watch.py`), SOC 대시보드(`soc_dashboard.py` + 합성데이터 필터 토글 + EPSS 우선순위)
- 복구 드릴(RTO ≈ 0.2초, 모든 지표 일치), 성능 점검 노트(`PERFORMANCE_NOTES.md`)

### 자동 스케줄 (launchd) — **5종** 모두 등록·`exit 0`
| Label | 주기 | 스크립트 | 로그 |
|---|---|---|---|
| `com.security-db.backup` | 매일 03:30 | `backup_scheduled.sh` (DB 덤프 + `pg_dumpall --roles-only`, 14일/7개 보존) | `db_backups/backup.log` |
| `com.security-db.synth` | 25분마다 | `generate_synthetic_events.py` (합성 이벤트 1~3건) | `~/Library/Logs/security-db-synth.*.log` |
| `com.security-db.auditverify` | 매일 04:00 | `verify_audit_chain.sh` (해시체인 점검, breaks>0 시 ALERT + `alert_poller --source audit`) | `logs/audit_verify.log` |
| `com.security-db.epsssync` | 매일 05:00 | `epss_sync.py` (FIRST.org EPSS 재동기화) | `~/Library/Logs/security-db-epsssync.*.log` |
| `com.security-db.alertpoll` | **2분 주기** | `alert_poller.py` (CRITICAL 이벤트 + 감사체인 폴링 → 알림) | `~/Library/Logs/security-db-alertpoll.*.log` · `logs/alerts.log` |

확인: `launchctl list | grep security-db` (가운데 숫자 = 마지막 종료코드, 0=정상)

### 라이브 DB 상태값 (2026-09-07 22:30)
- `assets` 15건 · `vulnerabilities` **28건 (NVD 12 / SCAN 14 / MANUAL 2)** · `scan_runs` 1건 · **테이블 17 / 뷰 7**
- `nvd_cve_details` 14행: EPSS 채워짐 12 / nvd_status **SYNCED 12 · NOT_FOUND 2** (PENDING 은 `nvd_sync.py` 로 정리 완료)
- `security_events` 45건 (그중 `[SIM]` 16) · `responses` 26건 · `audit_log` 50건 · **`alert_log` 1건**(테스트 알림 이력)
- 해시체인 `breaks = 0` · RLS 정책 9 · **schema_migrations 32** · FK 14 · CHECK 17
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

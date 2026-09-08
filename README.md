# security_db

보안 이벤트·취약점 관리 시스템 — **PostgreSQL 15 + pgvector** 기반 SOC(보안 관제) 플랫폼.
자산/취약점/보안이벤트/대응 이력을 한 스키마에 담고, RBAC·행 수준 보안(RLS)·감사 로그
해시체인으로 보호하며, NVD/EPSS/KISA 데이터를 연동해 위험도를 스코어링하고, 벡터 임베딩으로
"이 사건, 예전에 본 패턴과 비슷한가?" 를 자동 매칭한다. Streamlit SOC 대시보드로 조회한다.

> 대학 데이터베이스 강의 기말 프로젝트를 "현직자가 인수인계 받아 바로 운영할 수 있는" 수준으로
> 끌어올린 결과물. 학습·포트폴리오 목적.

---

## 아키텍처 개요

스키마는 아래 계층으로 쌓여 있다. 각 계층은 번호가 매겨진 마이그레이션(`sql/V###__*.sql`)으로
적용되며, **적용 순서와 계층 간 의존 관계는 [`sql/RUN_ORDER.md`](sql/RUN_ORDER.md) 가 정본이다.**

| 계층 | 내용 | 대표 마이그레이션 |
|---|---|---|
| 핵심 스키마 | `assets` / `vulnerabilities` / `security_events` / `responses` / `staff` / `threat_reports` | V001 |
| 벡터검색 | `pgvector` 확장 + `threat_reports.embedding`(HNSW) | V002 |
| RBAC / RLS / 감사 | 역할 6종, 부서 스코프 RLS, `audit_log` 해시체인(`fn_verify_audit_chain()`) | V003·V004·V006·V023 |
| 데이터 품질 | 타입 강화, CVSS↔severity 정합성, FK 참조동작, CHECK 제약, 시간 무결성 트리거 | V012·V013·V018·V020·V028 |
| 외부 연동 | NVD REST API, EPSS 악용확률(`priority = cvss × epss`), KISA 설정취약점 스캐너 | V017·V030·V031 |
| 실시간 알림 | `alert_log` dedup + 폴링 기반 다채널 알림(macOS/Slack/이메일) | V032 |
| 유사 사례 매칭 | `security_events.embedding` + `event_threat_matches`(THREAT_REPORT / PAST_EVENT) | V033·V035 |
| SOC 대시보드 | Streamlit — 요약 카드, 자산 위험도, ATT&CK 분포, EPSS 우선순위, 유사 사례 매칭 | `scripts/soc_dashboard.py` |

작업 히스토리(무엇을 왜 바꿨는지)는 [`reports/PROJECT_LOG.md`](reports/PROJECT_LOG.md) 에 라운드별로 남아 있다.

---

## 사전 요구사항

- **PostgreSQL 15+** 와 **pgvector** 확장 (`CREATE EXTENSION vector;` 가능해야 함).
  로컬 개발은 Homebrew `postgresql@15` + `pgvector` 로 검증됨.
- **Python 3.10+** (임베딩 스크립트는 `sentence-transformers` + PyTorch 를 쓰므로 메모리 여유 권장).
- `psql` 이 `PATH` 에 있어야 한다 (`scripts/migrate.py` 가 psql 래퍼다).

---

## 5분 퀵스타트

```bash
# 1) DB 생성 + 확장
createdb security_db
psql -d security_db -c "CREATE EXTENSION IF NOT EXISTS vector;"

# 2) 파이썬 의존성
pip install -r requirements.txt          # 운영 파이프라인용
# pip install -r requirements-dev.txt    # (선택) 스크린샷 자동화 등 개발 보조

# 3) 스키마 적용 — V001 부터 최신까지 한 흐름으로
python3 scripts/migrate.py up
python3 scripts/migrate.py status        # "미적용 0 · drift 0" 이면 정상

# 4) (선택·권장) 운영 role 비밀번호를 랜덤값으로 로테이션
#    sql/V016 에 커밋돼 있던 예시 비밀번호를 무력화한다. 자세히는 아래 "보안 주의사항".
python3 scripts/bootstrap_role_passwords.py

# 5) SOC 대시보드
#    로그인 게이트가 있어 bcrypt 해시를 환경변수로 넣어야 한다.
export SOC_DASHBOARD_AUTH_HASH="$(python3 -c "import bcrypt;print(bcrypt.hashpw(b'바꿀비밀번호', bcrypt.gensalt()).decode())")"
streamlit run scripts/soc_dashboard.py
```

환경변수 전체 목록과 용도는 [`.env.example`](.env.example) 참고.

---

## 주요 스크립트 / 자동화

`scripts/` 의 파이썬·쉘 스크립트 중 상시 도는 것은 launchd(macOS) job 6종이다. Linux 로 옮길
때의 systemd/cron 대응은 [`sql/SYSTEMD_DEPLOYMENT_GUIDE.md`](sql/SYSTEMD_DEPLOYMENT_GUIDE.md) 참고.

| launchd job | 주기 | 스크립트 | 하는 일 |
|---|---|---|---|
| `com.security-db.backup` | 매일 03:30 | `backup_scheduled.sh` | `pg_dump`(custom) + `pg_dumpall --roles-only`, 14일/7개 보존정책 |
| `com.security-db.synth` | 25분마다 | `generate_synthetic_events.py` | 합성(`[SIM]`) 보안 이벤트 1~3건 생성 — 대시보드가 "살아있게" |
| `com.security-db.threatlink` | 10분마다 | `event_threat_linker.py` | 신규 이벤트 임베딩 + `event_threat_matches` 자동 매칭 |
| `com.security-db.auditverify` | 매일 04:00 | `verify_audit_chain.sh` | `fn_verify_audit_chain()` — 해시체인 깨지면 ALERT + 알림 |
| `com.security-db.epsssync` | 매일 05:00 | `epss_sync.py` | FIRST.org EPSS 악용확률 재동기화 |
| `com.security-db.alertpoll` | 2분마다 | `alert_poller.py` | 최근 CRITICAL 이벤트 / 감사체인 손상 폴링 → `alert_notifier` 발송 |

그 외 수동 실행 스크립트: `nvd_sync.py`(NVD CVE 적재), `kisa_scanner.py` + `import_kisa_results.py`
(KISA U-01~U-72 설정 점검), `generate_embeddings.py`(threat_reports 임베딩),
`search_similar_reports.py`(자유 텍스트로 유사 리포트 검색).

---

## 문서 지도

| 문서 | 내용 |
|---|---|
| [`sql/RUN_ORDER.md`](sql/RUN_ORDER.md) | **마이그레이션 적용 순서·의존관계의 정본.** forward-only 정책, 숨은 의존성, 재실행 주의 |
| [`reports/PROJECT_LOG.md`](reports/PROJECT_LOG.md) | 라운드별 작업 히스토리 + "현재 상태" 스냅샷 |
| [`PERFORMANCE_NOTES.md`](PERFORMANCE_NOTES.md) | 인덱스 전략, RLS 함수 호출 비용, 병목 후보 |
| [`sql/TLS_SSL_GUIDE.md`](sql/TLS_SSL_GUIDE.md) | 운영 전환 시 TLS/SSL + pg_hba scram 적용 절차 (현재 미적용) |
| [`sql/SYSTEMD_DEPLOYMENT_GUIDE.md`](sql/SYSTEMD_DEPLOYMENT_GUIDE.md) | launchd → systemd timer / cron 이식 가이드 (현재 미적용) |
| `.github/workflows/migrate-check.yml` | 빈 DB 에 전체 마이그레이션 재현 + drift 0 자동 검증 (CI) |

---

## 보안 주의사항

- **로컬 인증은 `trust`(개발용)** 이다. `pg_hba.conf` 가 로컬/루프백을 비밀번호 없이 허용한다.
  운영 반영 전에 반드시:
  1. `scripts/bootstrap_role_passwords.py` 로 6개 운영 role 비밀번호를 랜덤값으로 교체
     (`sql/V016` 에 커밋돼 있던 `<역할명>#Tmp-2026!chg` 예시 비밀번호는 **노출된 것으로 간주**한다.
     `sql/V037` 이 이 사실을 각 role 코멘트에 기록한다).
  2. [`sql/TLS_SSL_GUIDE.md`](sql/TLS_SSL_GUIDE.md) 절차대로 `pg_hba.conf` 를 `scram-sha-256` 으로 전환.
- SOC 대시보드는 **fail-closed** 다. `SOC_DASHBOARD_AUTH_HASH`(bcrypt 해시) 환경변수가 없으면
  대시보드를 열지 않는다. 해시는 코드/저장소에 두지 말고 환경변수/시크릿 매니저로만 주입한다.
- `.env`, `secrets/`, `db_backups/`, `*.dump`, `*.pem`/`*.key` 는 `.gitignore` 로 제외돼 있다.

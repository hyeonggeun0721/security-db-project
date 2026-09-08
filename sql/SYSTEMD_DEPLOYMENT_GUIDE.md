# security_db — launchd → Linux(systemd / cron) 이식 가이드

> ⚠️ **이 문서는 안내만 한다. 지금 적용하지 않는다.**
> 현재 자동화는 macOS `launchd` LaunchAgent 6종으로 돌아간다(개발 머신). Linux 서버로
> 옮길 때 아래 두 가지 방법 중 하나를 쓴다: **systemd timer(권장)** 또는 **cron(가벼움)**.
> `TLS_SSL_GUIDE.md` / `auth_hardening.sql` 의 scram 전환도 같이 검토할 것 — 서버에서는
> TCP + 비밀번호 인증이 기본이므로 각 유닛에 `PGHOST`/`PGUSER`/`PGPASSWORD`(또는 `~/.pgpass`)
> 를 넣어야 한다.

---

## 0. 현재 launchd job 6종 요약

| Label | 트리거 (plist) | 실행 |
|---|---|---|
| `com.security-db.backup` | `StartCalendarInterval` Hour 3 / Minute 30 | `bash scripts/backup_scheduled.sh` |
| `com.security-db.synth` | `StartInterval` 1500 (25분) | `python3 scripts/generate_synthetic_events.py` |
| `com.security-db.threatlink` | `StartInterval` 600 (10분) | `python3 scripts/event_threat_linker.py` |
| `com.security-db.auditverify` | `StartCalendarInterval` Hour 4 / Minute 0 | `bash scripts/verify_audit_chain.sh` |
| `com.security-db.epsssync` | `StartCalendarInterval` Hour 5 / Minute 0 | `python3 scripts/epss_sync.py` |
| `com.security-db.alertpoll` | `StartInterval` 120 (2분) | `python3 scripts/alert_poller.py` |

공통 환경변수(plist `EnvironmentVariables`): `PGDATABASE=security_db`,
`PATH=<python 있는 경로>:/usr/bin:/bin:/usr/sbin:/sbin`. `alertpoll` 은 추가로
`ALERT_INCLUDE_SIM=1`(+ 선택적으로 `SLACK_WEBHOOK_URL`, `ALERT_SMTP_*`).

---

## 1. 주기 대응표

| launchd | systemd (`.timer`) | cron |
|---|---|---|
| `StartInterval` 120 (2분) | `OnBootSec=2min` + `OnUnitActiveSec=2min` | `*/2 * * * *` |
| `StartInterval` 600 (10분) | `OnUnitActiveSec=10min` | `*/10 * * * *` |
| `StartInterval` 1500 (25분) | `OnUnitActiveSec=25min` | `*/25 * * * *` (근사 — cron 은 25분 배수를 정확히 못 맞춤; systemd 권장) |
| `StartCalendarInterval` Hour 3 Minute 30 | `OnCalendar=*-*-* 03:30:00` | `30 3 * * *` |
| `StartCalendarInterval` Hour 4 Minute 0 | `OnCalendar=*-*-* 04:00:00` | `0 4 * * *` |
| `StartCalendarInterval` Hour 5 Minute 0 | `OnCalendar=*-*-* 05:00:00` | `0 5 * * *` |

- `OnUnitActiveSec` = "이전 실행이 끝난 뒤 N 후 다시" (launchd `StartInterval` 과 동일 의미:
  겹쳐 돌지 않음). `OnCalendar` = 절대 시각(launchd `StartCalendarInterval` 과 동일).
- systemd timer 는 `Persistent=true` 로 "머신이 꺼져 있던 사이 놓친 실행"을 부팅 후 보충한다
  (launchd 에는 이 개념이 부분적으로만 있음).

---

## 2. systemd 방법 (권장)

`root` 로 운영한다면 `/etc/systemd/system/` 에, 특정 서비스 계정으로 돌린다면
`~/.config/systemd/user/` 에 유닛을 둔다(후자는 `systemctl --user`, `loginctl enable-linger <user>` 필요).

경로/사용자는 실제 배포에 맞게 바꾼다. 아래 예시는 `/opt/security_db_project` 에 배포하고
`secdb` 계정으로 돌리는 경우.

### 2-1. 공통 environment 파일

```ini
# /opt/security_db_project/deploy/security-db.env   (chmod 600, secdb 소유)
PGHOST=127.0.0.1
PGPORT=5432
PGUSER=secdb_app
PGDATABASE=security_db
# PGPASSWORD 는 여기 두지 말고 ~secdb/.pgpass (chmod 600) 를 쓰는 것을 권장
PATH=/opt/security_db_project/.venv/bin:/usr/bin:/bin
```

### 2-2. 반복형 job — `threatlink` 예시 (10분 주기)

```ini
# /etc/systemd/system/security-db-threatlink.service
[Unit]
Description=security_db - event/threat 벡터 자동 매칭
After=postgresql.service
Wants=postgresql.service

[Service]
Type=oneshot
User=secdb
WorkingDirectory=/opt/security_db_project
EnvironmentFile=/opt/security_db_project/deploy/security-db.env
ExecStart=/opt/security_db_project/.venv/bin/python3 scripts/event_threat_linker.py
Nice=10
```

```ini
# /etc/systemd/system/security-db-threatlink.timer
[Unit]
Description=security_db threatlink 10분 주기

[Timer]
OnBootSec=2min
OnUnitActiveSec=10min
Persistent=true

[Install]
WantedBy=timers.target
```

`synth`(25분), `alertpoll`(2분)도 같은 꼴 — `ExecStart` 스크립트와 `OnUnitActiveSec` 만 바꾼다.
`alertpoll` 서비스에는 `Environment=ALERT_INCLUDE_SIM=1` 을(그리고 필요 시 `SLACK_WEBHOOK_URL=`,
`ALERT_SMTP_*=`) 추가한다.

### 2-3. 시각 고정 job — `backup` 예시 (매일 03:30)

```ini
# /etc/systemd/system/security-db-backup.service
[Unit]
Description=security_db - pg_dump 백업 + 보존정책
After=postgresql.service
Wants=postgresql.service

[Service]
Type=oneshot
User=secdb
WorkingDirectory=/opt/security_db_project
EnvironmentFile=/opt/security_db_project/deploy/security-db.env
ExecStart=/bin/bash scripts/backup_scheduled.sh
```

```ini
# /etc/systemd/system/security-db-backup.timer
[Unit]
Description=security_db 백업 매일 03:30

[Timer]
OnCalendar=*-*-* 03:30:00
Persistent=true

[Install]
WantedBy=timers.target
```

`auditverify`(04:00), `epsssync`(05:00)도 `OnCalendar` 만 바꿔 동일하게.

### 2-4. 활성화 / 확인

```bash
sudo systemctl daemon-reload
for j in backup synth threatlink auditverify epsssync alertpoll; do
    sudo systemctl enable --now security-db-$j.timer
done
systemctl list-timers 'security-db-*'          # 다음 실행 시각
systemctl status security-db-threatlink.service  # 마지막 실행 결과
journalctl -u security-db-threatlink.service -n 50
```

로그: 스크립트가 이미 `logs/` 아래(`alerts.log` 는 회전, 쉘 스크립트도 자체 크기 로테이션)에
남기므로 별도 설정 불필요. journald 쪽 stdout/stderr 는 `journalctl` 로 본다.

---

## 3. cron 방법 (더 가벼움)

`crontab -e` (배포 계정) 에 아래를 넣는다. `BASH_ENV` 로 환경변수 파일을 읽게 한다.

```cron
BASH_ENV=/opt/security_db_project/deploy/security-db.env
PROJ=/opt/security_db_project
PY=/opt/security_db_project/.venv/bin/python3

*/2  * * * *  cd $PROJ && $PY scripts/alert_poller.py            >> $PROJ/logs/cron-alertpoll.log 2>&1
*/10 * * * *  cd $PROJ && $PY scripts/event_threat_linker.py     >> $PROJ/logs/cron-threatlink.log 2>&1
*/25 * * * *  cd $PROJ && $PY scripts/generate_synthetic_events.py >> $PROJ/logs/cron-synth.log 2>&1
30 3 * * *    cd $PROJ && /bin/bash scripts/backup_scheduled.sh
0  4 * * *    cd $PROJ && /bin/bash scripts/verify_audit_chain.sh
0  5 * * *    cd $PROJ && $PY scripts/epss_sync.py               >> $PROJ/logs/cron-epsssync.log 2>&1
```

- cron 은 `*/25` 를 "0,25,50 분" 으로 해석하므로 실제 간격이 25/25/10 분으로 들쭉날쭉하다.
  25분 주기가 중요하면 systemd `OnUnitActiveSec=25min` 을 쓴다.
- cron 은 `PATH` 가 매우 짧다(`/usr/bin:/bin`). 위처럼 `$PY` 절대경로를 쓰거나
  `BASH_ENV` 파일에서 `PATH` 를 확장한다.
- cron 은 "놓친 실행 보충"이 없다. 머신이 꺼졌다 켜지는 환경이면 systemd + `Persistent=true`.

---

## 4. 이관 체크리스트

- [ ] `python3 -m venv .venv && .venv/bin/pip install -r requirements.txt`
- [ ] `deploy/security-db.env` 작성(chmod 600), `~/.pgpass` 로 비밀번호 분리
- [ ] `psql -d security_db -c "CREATE EXTENSION IF NOT EXISTS vector;"` → `python3 scripts/migrate.py up`
- [ ] `python3 scripts/bootstrap_role_passwords.py` 로 role 비밀번호 로테이션(V037)
- [ ] `pg_hba.conf` scram 전환 + `TLS_SSL_GUIDE.md` (TCP 접속이므로)
- [ ] SOC 대시보드는 `systemd` service 로 상시 기동한다면 그 유닛 env 에
      `SOC_DASHBOARD_AUTH_HASH` 필수(없으면 fail-closed 로 안 열림)
- [ ] 6개 timer `enable --now` 후 `systemctl list-timers 'security-db-*'` 로 확인

# security_db — 전송구간 암호화(TLS/SSL) 적용 가이드

> ⚠️ **이 문서는 안내만 한다. 지금 적용하지 않는다.**
> `pg_hba.conf` 를 `trust` → `scram` 으로 바꿀 때와 같은 이유 — 잘못 적용하면 현재
> 세션/스크립트 접속이 끊긴다. 아래는 운영 환경에 반영할 때의 순서다.
> (로컬 개발 환경은 Unix 도메인 소켓 접속이라 TLS 가 의미 없다. TLS 는 TCP 접속에만 적용된다.)

관련: `auth_hardening.sql`(비밀번호 인증 전환 가이드)와 함께 수행하는 것이 좋다.
비밀번호를 평문으로 네트워크에 흘리지 않으려면 **TLS 먼저 또는 동시에** 켠다.

---

## 0. 사전 확인

```sql
SHOW ssl;                    -- 'off' 이면 아직 비활성
SHOW config_file;            -- postgresql.conf 위치
SHOW hba_file;               -- pg_hba.conf 위치
```

## 1. 서버 인증서 준비

운영에서는 사내 CA 또는 Let's Encrypt 인증서를 쓴다. 자체 서명(self-signed)은 테스트용.

```bash
# 데이터 디렉터리(예: /opt/homebrew/var/postgresql@15)에서
openssl req -new -x509 -days 365 -nodes -text \
  -out server.crt -keyout server.key \
  -subj "/CN=db.internal.example.com"
chmod 600 server.key
# 소유자는 postgres 프로세스 실행 계정이어야 함
```

사내 CA 를 쓰면 `root.crt`(신뢰 체인)도 서버에 둔다(클라이언트 인증서 검증까지 할 경우).

## 2. postgresql.conf

```conf
ssl = on
ssl_cert_file = 'server.crt'
ssl_key_file  = 'server.key'
# (선택) 클라이언트 인증서 검증 시:
# ssl_ca_file = 'root.crt'
ssl_min_protocol_version = 'TLSv1.2'
ssl_prefer_server_ciphers = on
```

## 3. pg_hba.conf — 평문 TCP 거부, TLS 강제

`host` 라인을 `hostssl` 로 바꾸고, 평문 TCP 는 `hostnossl ... reject` 로 명시 차단한다.

```conf
# TYPE      DATABASE   USER   ADDRESS         METHOD
hostnossl   all        all    0.0.0.0/0       reject
hostnossl   all        all    ::/0            reject
hostssl     all        all    10.0.0.0/8      scram-sha-256
# (선택) 클라이언트 인증서까지 요구:
# hostssl   all        all    10.0.0.0/8      scram-sha-256   clientcert=verify-full
```

로컬 `local` (소켓) 라인은 그대로 둔다 — 소켓은 네트워크를 안 탄다.

## 4. 반영 순서 (세션 안 끊기게)

1. **기존 psql 세션 하나를 열어둔 채** 설정을 바꾼다(문제 시 되돌릴 창구).
2. 인증서 파일 권한/소유자 확인(`server.key` 는 0600, DB 실행계정 소유).
3. 설정 리로드:
   ```sql
   SELECT pg_reload_conf();   -- ssl 관련 일부는 리로드로 적용. 안 되면 재시작 필요
   ```
   `ssl = on` 최초 활성화는 **재시작**이 필요할 수 있다: `pg_ctl restart` 또는 `brew services restart postgresql@15`.
4. 새 세션으로 TLS 접속 테스트:
   ```bash
   psql "host=db.internal.example.com dbname=security_db user=security_analyst sslmode=verify-full sslrootcert=/path/to/root.crt"
   psql -d security_db -c "SELECT ssl, version, cipher FROM pg_stat_ssl WHERE pid = pg_backend_pid();"
   ```
5. 애플리케이션/스크립트 접속 문자열에 `sslmode` 반영:
   - 파이썬(psycopg2): DSN 에 `sslmode=verify-full sslrootcert=...` 추가하거나
     환경변수 `PGSSLMODE=verify-full`, `PGSSLROOTCERT=...` 설정.
   - `sslmode` 등급: `require`(암호화만) < `verify-ca`(CA 검증) < `verify-full`(호스트명까지 검증, 권장).
6. 모든 클라이언트 전환 확인 후 `hostnossl ... reject` 를 활성화해 평문 접속을 완전히 차단.

## 5. 되돌리기

`postgresql.conf` 의 `ssl = off`, `pg_hba.conf` 의 `hostssl`→`host` / `hostnossl reject` 제거 후
`pg_reload_conf()` (또는 재시작).

## 6. 체크리스트

- [ ] `server.key` 권한 0600, DB 실행계정 소유
- [ ] `ssl_min_protocol_version = 'TLSv1.2'` 이상
- [ ] 클라이언트가 `sslmode=verify-full` + 올바른 `sslrootcert` 사용
- [ ] `pg_stat_ssl` 로 실제 세션이 `ssl=t` 인지 확인
- [ ] `hostnossl ... reject` 로 평문 폴백 차단
- [ ] 인증서 만료 모니터링/자동 갱신(certbot 등) 구성

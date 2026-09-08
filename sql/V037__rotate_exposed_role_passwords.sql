-- =========================================================
-- V037) 노출된 V016 비밀번호 폐기 기록 (role 코멘트)
--
-- ■ 배경 (보안 감사)
--   sql/V016__auth_hardening.sql 에 6개 운영 role 의 비밀번호가
--     <역할명>#Tmp-2026!chg  (예: Analyst#Tmp-2026!chg)
--   패턴으로 평문 커밋돼 있고, 실제로 교체된 적이 없었다. 패턴이 예측 가능해
--   저장소 접근자가 전 계정 비밀번호를 즉시 유추할 수 있다.
--
-- ■ 선행 조건 (이 마이그레이션 적용 전에 반드시!)
--     python3 scripts/bootstrap_role_passwords.py
--   를 먼저 실행해 6개 role 비밀번호를 secrets.token_urlsafe(24) 랜덤값으로
--   로테이션해 둔 상태여야 한다. (RUN_ORDER.md 에 순서 명시)
--   이 마이그레이션은 비밀번호를 바꾸지 않는다 — "V016 값은 노출된 것으로 간주해
--   폐기했고, 현재 값은 bootstrap 스크립트로 로테이션됐다" 는 사실을 스키마 자체
--   (COMMENT ON ROLE)에 남겨, "V016 값이 아직 살아있는 게 아니다" 를 명확히 한다.
--
-- ■ 새 고정 비밀번호를 여기 하드코딩하지 않는다 (그러면 V016 문제 반복).
--
-- 재실행 안전: COMMENT ON ROLE 은 멱등.
-- =========================================================

DO $$
DECLARE
    r text;
    note text := '비밀번호는 2026-09-08 보안 감사 후 scripts/bootstrap_role_passwords.py '
               || '(secrets.token_urlsafe) 로 로테이션됨. sql/V016 의 하드코딩 값'
               || '(<역할명>#Tmp-2026!chg)은 노출된 것으로 간주해 폐기됨.';
BEGIN
    FOREACH r IN ARRAY ARRAY[
        'security_analyst','security_admin','security_manager',
        'dept_infra','dept_dev','dept_sales'
    ] LOOP
        EXECUTE format('COMMENT ON ROLE %I IS %L', r, note);
    END LOOP;
END $$;

-- @migrate:verify
-- migrate.py 는 이 마커 위까지를 본문(ON_ERROR_STOP=1), 아래를 검증절
-- (ON_ERROR_STOP=0)로 실행한다. 아래 \! 접속 테스트는 인증 방식에 따라
-- 의미가 달라지므로, 먼저 현재 pg_hba 인증 방식을 확인해 분기한다.
-- =========================================================
-- 검증
-- =========================================================
\echo ''
\echo '################ [1] 6개 role 코멘트가 "폐기됨" 취지로 남았는지 ################'
SELECT r.rolname,
       left(d.description, 60) || '...' AS role_comment
FROM pg_roles r
JOIN pg_shdescription d ON d.objoid = r.oid AND d.classoid = 'pg_authid'::regclass
WHERE r.rolname IN ('security_analyst','security_admin','security_manager',
                    'dept_infra','dept_dev','dept_sales')
ORDER BY r.rolname;

\echo ''
\echo '################ [2] 비밀번호 검증자가 scram-sha-256 로 저장돼 있는지 ################'
SELECT rolname,
       CASE WHEN rolpassword LIKE 'SCRAM-SHA-256%' THEN 'scram-sha-256'
            WHEN rolpassword LIKE 'md5%'           THEN 'md5'
            WHEN rolpassword IS NULL               THEN '(none!)'
            ELSE 'other' END AS verifier
FROM pg_authid
WHERE rolname IN ('security_analyst','security_admin','security_manager',
                  'dept_infra','dept_dev','dept_sales')
ORDER BY rolname;

\echo ''
\echo '################ [3] 옛 V016 비밀번호로 로그인 실패하는지 (인증 방식에 따라 분기) ################'
SELECT coalesce(bool_and(auth_method = 'trust'), true) AS local_is_trust
FROM pg_hba_file_rules
WHERE 'all' = ANY(database);
\gset

\if :local_is_trust
\echo '  >>> SKIP: 현재 로컬 pg_hba 인증이 trust 다.'
\echo '  >>> trust 에서는 비밀번호 값 자체가 검사되지 않으므로, 옛 비밀번호로 접속해도'
\echo '  >>> "성공" 한다 — 이는 로테이션이 안 됐다는 뜻이 아니라 인증 방식이 비밀번호를'
\echo '  >>> 안 보기 때문이다. 아래 테스트는 pg_hba 를 scram-sha-256 으로 전환한 뒤'
\echo '  >>> (V016 주석 / RUN_ORDER.md 전환 가이드) 재실행해 6건 전부 인증 실패해야 정상.'
\echo '  >>> === 지금은 검증 불가로 표시 (거짓 통과 아님) ==='
\else
\echo '  scram 인증 감지 — 옛 V016 비밀번호로 실제 접속을 시도한다. 6건 전부 실패해야 정상.'
\! echo "  [analyst ] 옛 비밀번호 접속 시도 (실패=정상):"; PGPASSWORD='Analyst#Tmp-2026!chg' psql "host=127.0.0.1 dbname=security_db user=security_analyst connect_timeout=5" -tAc 'select 1' 2>&1 | sed 's/^/    /'
\! echo "  [admin   ] 옛 비밀번호 접속 시도 (실패=정상):"; PGPASSWORD='Admin#Tmp-2026!chg' psql "host=127.0.0.1 dbname=security_db user=security_admin connect_timeout=5" -tAc 'select 1' 2>&1 | sed 's/^/    /'
\! echo "  [manager ] 옛 비밀번호 접속 시도 (실패=정상):"; PGPASSWORD='Manager#Tmp-2026!chg' psql "host=127.0.0.1 dbname=security_db user=security_manager connect_timeout=5" -tAc 'select 1' 2>&1 | sed 's/^/    /'
\! echo "  [infra   ] 옛 비밀번호 접속 시도 (실패=정상):"; PGPASSWORD='Infra#Tmp-2026!chg' psql "host=127.0.0.1 dbname=security_db user=dept_infra connect_timeout=5" -tAc 'select 1' 2>&1 | sed 's/^/    /'
\! echo "  [dev     ] 옛 비밀번호 접속 시도 (실패=정상):"; PGPASSWORD='Dev#Tmp-2026!chg' psql "host=127.0.0.1 dbname=security_db user=dept_dev connect_timeout=5" -tAc 'select 1' 2>&1 | sed 's/^/    /'
\! echo "  [sales   ] 옛 비밀번호 접속 시도 (실패=정상):"; PGPASSWORD='Sales#Tmp-2026!chg' psql "host=127.0.0.1 dbname=security_db user=dept_sales connect_timeout=5" -tAc 'select 1' 2>&1 | sed 's/^/    /'
\endif

\echo ''
\echo '################ [참고] 현재 서버 인증 파라미터 ################'
SHOW password_encryption;
SHOW hba_file;

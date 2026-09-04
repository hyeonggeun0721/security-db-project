-- =========================================================
-- 마이그레이션 5) 인증 강화 (auth_hardening.sql)
--
--   (1) 6개 운영 role 에 LOGIN + 임시 비밀번호 설정 (ALTER ROLE ... WITH LOGIN PASSWORD)
--       - password_encryption=scram-sha-256 (PG13+ 기본) 이면 SCRAM 검증자로 저장된다.
--       - 지금 로컬 인증이 trust 라 비밀번호는 검사되지 않지만, (2) 적용 시 즉시 유효.
--       - 임시 비밀번호이므로 최초 로그인 후 각자 변경하도록 안내한다.
--         만료를 강제하려면 VALID UNTIL 을 과거/근미래로 설정한다(아래 주석 참고).
--
--   (2) pg_hba.conf 를 trust -> scram-sha-256 으로 바꾸는 방법은 "주석 안내만" 한다.
--       실제로 지금 바꾸면 비밀번호 없는 세션이 끊길 수 있으므로 이 파일에서는
--       실행하지 않는다.
--
--   재실행 안전: ALTER ROLE 은 멱등.
-- =========================================================

-- ---------------------------------------------------------
-- (1) role 별 LOGIN + 임시 비밀번호
--     ※ 아래 비밀번호는 "임시 예시"다. 운영 반영 시 반드시 교체할 것.
-- ---------------------------------------------------------
ALTER ROLE security_analyst WITH LOGIN PASSWORD 'Analyst#Tmp-2026!chg';
ALTER ROLE security_admin   WITH LOGIN PASSWORD 'Admin#Tmp-2026!chg';
ALTER ROLE security_manager WITH LOGIN PASSWORD 'Manager#Tmp-2026!chg';
ALTER ROLE dept_infra       WITH LOGIN PASSWORD 'Infra#Tmp-2026!chg';
ALTER ROLE dept_dev         WITH LOGIN PASSWORD 'Dev#Tmp-2026!chg';
ALTER ROLE dept_sales       WITH LOGIN PASSWORD 'Sales#Tmp-2026!chg';

-- (선택) 임시 비밀번호 강제 만료: 아래처럼 과거 시점으로 VALID UNTIL 을 걸면
--        비밀번호 로그인이 즉시 차단되어 관리자가 재발급해야 한다.
--   ALTER ROLE security_analyst VALID UNTIL '2026-09-05';
--   ... (각 role 반복)

-- ---------------------------------------------------------
-- (2) pg_hba.conf 전환 가이드 (실행하지 않음)
-- ---------------------------------------------------------
-- 현재 설정 파일 위치 확인:
--   SHOW hba_file;        -- 예: /opt/homebrew/var/postgresql@15/pg_hba.conf
--   SHOW password_encryption;   -- 'scram-sha-256' 여야 함 (PG13+ 기본)
--
-- 단계:
--   1) 슈퍼유저(summer)에도 비밀번호를 먼저 설정한다. 안 하면 전환 후 로그인 불가.
--        ALTER ROLE summer WITH PASSWORD '<강력한_비밀번호>';
--   2) pg_hba.conf 의 로컬/루프백 라인을 trust -> scram-sha-256 으로 수정:
--        # TYPE  DATABASE  USER  ADDRESS        METHOD
--        local   all       all                  scram-sha-256
--        host    all       all   127.0.0.1/32   scram-sha-256
--        host    all       all   ::1/128        scram-sha-256
--      (replication 라인도 동일하게 전환 권장)
--   3) 기존 세션 하나를 열어둔 채로 설정을 다시 읽는다(문제 시 롤백 여지 확보):
--        SELECT pg_reload_conf();      -- 또는  pg_ctl reload
--   4) 새 세션으로 접속 테스트:
--        psql "postgresql://security_analyst:<pw>@127.0.0.1/security_db"
--      비밀번호는 대화형 입력, 또는 ~/.pgpass (chmod 600) 사용. PGPASSWORD 환경변수는
--      프로세스 목록에 노출될 수 있으니 스크립트 외에는 지양.
--   5) 애플리케이션/크론/백업 스크립트의 접속 문자열에 자격증명이 반영됐는지 확인.
--
-- 되돌리기: pg_hba.conf 를 trust 로 복원 후 다시 SELECT pg_reload_conf();
-- =========================================================

-- =========================================================
-- 검증 (권한/속성만 확인, 실제 비밀번호 로그인 테스트는 pg_hba 전환 후에 가능)
-- =========================================================
\echo ''
\echo '################ role 속성 (rolcanlogin=t, 비밀번호 설정 여부) ################'
SELECT r.rolname,
       r.rolcanlogin       AS can_login,
       (s.rolpassword IS NOT NULL) AS has_password,
       CASE WHEN s.rolpassword LIKE 'SCRAM-SHA-256%' THEN 'scram-sha-256'
            WHEN s.rolpassword LIKE 'md5%'           THEN 'md5'
            WHEN s.rolpassword IS NULL               THEN '(none)'
            ELSE 'other' END AS password_type,
       r.rolvaliduntil     AS valid_until
FROM pg_roles r
LEFT JOIN pg_authid s ON s.rolname = r.rolname
WHERE r.rolname IN ('security_analyst','security_admin','security_manager',
                    'dept_infra','dept_dev','dept_sales')
ORDER BY r.rolname;

\echo ''
\echo '################ 참고: 현재 유효 인증 방식 (pg_hba, 아직 trust) ################'
SELECT type, database, user_name, address, auth_method
FROM pg_hba_file_rules
WHERE 'all' = ANY(database) OR database IS NULL
ORDER BY line_number;

\echo ''
\echo '################ 참고: 서버 파라미터 ################'
SHOW hba_file;
SHOW password_encryption;

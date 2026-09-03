-- =========================================================
-- 고도화 기능 2) 역할 기반 접근제어 (RBAC)
--   3개 로그인 ROLE 을 만들고 테이블별 권한을 GRANT/REVOKE 로 실제 제한한다.
--
--   - security_analyst : 전체 SELECT + responses 에 대해서만 INSERT/UPDATE/DELETE
--   - security_admin   : 전체 테이블 전체 권한(DML) + 시퀀스 사용
--   - security_manager : 전체 SELECT 만, 쓰기 일절 불가
--
-- 기존 스키마/데이터 변경 없음. ROLE 은 클러스터 전역 객체이므로
-- DO 블록으로 존재 여부를 확인 후 생성한다(재실행 안전).
-- 로컬 pg_hba 가 trust 인증이라 테스트 시 비밀번호 입력은 불필요하지만,
-- 형식상 비밀번호도 지정해 둔다.
-- =========================================================

-- -----------------------------
-- 1) ROLE 생성 (없을 때만)
-- -----------------------------
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'security_analyst') THEN
        CREATE ROLE security_analyst LOGIN PASSWORD 'analyst_pw';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'security_admin') THEN
        CREATE ROLE security_admin LOGIN PASSWORD 'admin_pw';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'security_manager') THEN
        CREATE ROLE security_manager LOGIN PASSWORD 'manager_pw';
    END IF;
END $$;

-- -----------------------------
-- 2) 기존 권한 초기화 (깨끗한 재적용)
-- -----------------------------
REVOKE ALL ON ALL TABLES    IN SCHEMA public FROM security_analyst, security_admin, security_manager;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM security_analyst, security_admin, security_manager;
REVOKE ALL ON SCHEMA public FROM security_analyst, security_admin, security_manager;

-- -----------------------------
-- 3) 스키마 접근
-- -----------------------------
GRANT USAGE ON SCHEMA public TO security_analyst, security_admin, security_manager;

-- -----------------------------
-- 4) security_admin : 전체 권한
-- -----------------------------
GRANT ALL PRIVILEGES ON ALL TABLES    IN SCHEMA public TO security_admin;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO security_admin;
-- 이후 새로 만들어지는 테이블/시퀀스에도 자동 적용
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL PRIVILEGES ON TABLES    TO security_admin;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL PRIVILEGES ON SEQUENCES TO security_admin;

-- -----------------------------
-- 5) security_manager : 전체 조회만
-- -----------------------------
GRANT SELECT ON ALL TABLES IN SCHEMA public TO security_manager;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO security_manager;

-- -----------------------------
-- 6) security_analyst : 전체 조회 + responses 쓰기만
-- -----------------------------
GRANT SELECT ON ALL TABLES IN SCHEMA public TO security_analyst;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO security_analyst;
GRANT INSERT, UPDATE, DELETE ON responses TO security_analyst;
GRANT USAGE, SELECT ON SEQUENCE responses_response_id_seq TO security_analyst;

-- -----------------------------
-- 7) 권한 부여 현황 확인
-- -----------------------------
\echo '--- [CHECK] role 별 테이블 권한 (information_schema.role_table_grants) ---'
SELECT grantee, table_name, string_agg(privilege_type, ', ' ORDER BY privilege_type) AS privileges
FROM information_schema.role_table_grants
WHERE grantee IN ('security_analyst', 'security_admin', 'security_manager')
  AND table_schema = 'public'
GROUP BY grantee, table_name
ORDER BY grantee, table_name;

-- =========================================================
-- 고도화 기능 4) Row-Level Security (assets 부서별 격리)
--   assets 테이블에 RLS 를 걸어, 부서 전용 계정은 자기 부서 자산만 SELECT 하도록 제한.
--
--   매핑 방식(두 가지 동시 지원):
--     (a) role 이름 -> 부서 : rls_role_department 매핑 테이블
--     (b) 세션 변수     : SET app.department = '<부서명>'  (설정 시 이 값이 우선)
--
--   주의: PostgreSQL 에서 RLS 는 테이블 소유자/슈퍼유저에게는 적용되지 않는다.
--         (owner 인 summer 는 계속 전체 자산을 본다 — 기존 동작 유지)
--         따라서 실제 제한 효과는 아래에서 새로 만드는 비(非)슈퍼유저 role 로 확인한다.
--   RBAC(기능 2)의 security_admin/manager/analyst 는 자산 전체 조회가 유지되어야 하므로
--   별도 허용(permissive true) 정책을 추가한다. (RLS 활성화 시 정책 없는 role 은 기본 거부)
--
-- 기존 스키마/데이터 변경 없음. 신규: 매핑 테이블 1개 + 로그인 role 3개 + 정책 2개.
-- 재실행 안전(idempotent).
-- =========================================================

-- -----------------------------
-- 1) role -> 부서 매핑 테이블
-- -----------------------------
CREATE TABLE IF NOT EXISTS rls_role_department (
    role_name  TEXT PRIMARY KEY,
    department VARCHAR(50) NOT NULL
);

INSERT INTO rls_role_department (role_name, department) VALUES
    ('dept_infra', '인프라팀'),
    ('dept_dev',   '개발팀'),
    ('dept_sales', '영업팀')
ON CONFLICT (role_name) DO UPDATE SET department = EXCLUDED.department;

-- -----------------------------
-- 2) 부서 전용 로그인 role (없을 때만)
-- -----------------------------
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dept_infra') THEN
        CREATE ROLE dept_infra LOGIN PASSWORD 'infra_pw';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dept_dev') THEN
        CREATE ROLE dept_dev LOGIN PASSWORD 'dev_pw';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dept_sales') THEN
        CREATE ROLE dept_sales LOGIN PASSWORD 'sales_pw';
    END IF;
END $$;

GRANT USAGE ON SCHEMA public TO dept_infra, dept_dev, dept_sales;
GRANT SELECT ON assets              TO dept_infra, dept_dev, dept_sales;
GRANT SELECT ON rls_role_department TO dept_infra, dept_dev, dept_sales;

-- -----------------------------
-- 3) RLS 활성화 + 정책
-- -----------------------------
ALTER TABLE assets ENABLE ROW LEVEL SECURITY;

-- (a) 부서 전용 role: 세션변수 app.department 가 있으면 그것, 없으면 role 매핑 부서
DROP POLICY IF EXISTS p_assets_dept_scope ON assets;
CREATE POLICY p_assets_dept_scope ON assets
    FOR SELECT
    TO dept_infra, dept_dev, dept_sales
    USING (
        department = COALESCE(
            NULLIF(current_setting('app.department', true), ''),
            (SELECT r.department FROM rls_role_department r WHERE r.role_name = current_user)
        )
    );

-- (b) RBAC role: 자산 전체 접근 유지
DROP POLICY IF EXISTS p_assets_rbac_all ON assets;
CREATE POLICY p_assets_rbac_all ON assets
    FOR ALL
    TO security_admin, security_manager, security_analyst
    USING (true)
    WITH CHECK (true);

-- -----------------------------
-- 4) 테스트
-- -----------------------------
\echo '--- [TEST] owner(summer): RLS 우회, 전체 5건 ---'
SELECT asset_id, asset_name, department FROM assets ORDER BY asset_id;

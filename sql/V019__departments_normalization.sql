-- =========================================================
-- 보완 마이그레이션) 부서 마스터 테이블 (departments_normalization.sql)
--
--   department 가 assets / staff / rls_role_department 3곳에 자유문자열로 중복돼
--   있어 오타·개명 시 정합성이 깨진다. 자연키(dept_name)를 그대로 PK 로 쓰는
--   마스터 테이블을 만들고, 3개 컬럼에 FK 만 추가한다.
--     - 컬럼 타입/값을 바꾸지 않으므로 RLS 정책(department 값 비교)은 그대로 동작.
--     - 서로게이트 PK 를 새로 만들지 않는다.
--     - ON UPDATE CASCADE : 부서명 변경이 3개 테이블로 자동 전파.
--     - ON DELETE RESTRICT : 사용 중인 부서는 삭제 불가.
--
--   dept_infra / dept_dev / dept_sales 같은 전용 RLS 역할이 없는 부서
--   (재무팀·인사팀·고객지원팀·IT운영팀·보안팀)도 마스터에는 정상 포함한다.
--   (그 부서 전용 로그인 역할을 새로 만들지는 않는다 — 별개 사안)
--
--   재실행 안전: 테이블 IF NOT EXISTS, INSERT ... ON CONFLICT DO NOTHING,
--                FK 는 DROP ... IF EXISTS 후 ADD.
-- =========================================================

BEGIN;

-- ---------------------------------------------------------
-- 1) 마스터 테이블 (자연키 PK)
-- ---------------------------------------------------------
CREATE TABLE IF NOT EXISTS departments (
    dept_name        VARCHAR(50) PRIMARY KEY,
    dept_description  TEXT
);
COMMENT ON TABLE departments IS '부서 마스터. assets/staff/rls_role_department.department 가 참조';

-- ---------------------------------------------------------
-- 2) 현재 3개 테이블에서 쓰이는 모든 부서명을 채운다
-- ---------------------------------------------------------
INSERT INTO departments (dept_name)
SELECT DISTINCT d FROM (
    SELECT department AS d FROM assets              WHERE department IS NOT NULL
    UNION
    SELECT department      FROM staff               WHERE department IS NOT NULL
    UNION
    SELECT department      FROM rls_role_department  WHERE department IS NOT NULL
) s
ON CONFLICT (dept_name) DO NOTHING;

-- 알려진 부서 설명 보강(없을 때만)
UPDATE departments SET dept_description = v.descr
FROM (VALUES
    ('인프라팀',   '서버·네트워크·클라우드 등 IT 인프라 구축/운영'),
    ('개발팀',     '사내/대외 애플리케이션 개발'),
    ('영업팀',     '영업 및 고객 계약'),
    ('보안팀',     '보안 관제·사고 대응·취약점 관리'),
    ('IT운영팀',   '사내 IT 서비스 및 헬프데스크 운영'),
    ('인사팀',     '인사·채용·급여'),
    ('재무팀',     '회계·자금·재무보고'),
    ('고객지원팀', '고객 문의 대응 및 콜센터 운영')
) AS v(name, descr)
WHERE departments.dept_name = v.name
  AND departments.dept_description IS NULL;

-- ---------------------------------------------------------
-- 3) FK 추가 (department 컬럼 타입/값은 불변)
-- ---------------------------------------------------------
ALTER TABLE assets              DROP CONSTRAINT IF EXISTS fk_assets_department;
ALTER TABLE assets
    ADD CONSTRAINT fk_assets_department
    FOREIGN KEY (department) REFERENCES departments(dept_name)
    ON UPDATE CASCADE ON DELETE RESTRICT;

ALTER TABLE staff               DROP CONSTRAINT IF EXISTS fk_staff_department;
ALTER TABLE staff
    ADD CONSTRAINT fk_staff_department
    FOREIGN KEY (department) REFERENCES departments(dept_name)
    ON UPDATE CASCADE ON DELETE RESTRICT;

ALTER TABLE rls_role_department  DROP CONSTRAINT IF EXISTS fk_rls_role_department_department;
ALTER TABLE rls_role_department
    ADD CONSTRAINT fk_rls_role_department_department
    FOREIGN KEY (department) REFERENCES departments(dept_name)
    ON UPDATE CASCADE ON DELETE RESTRICT;

-- ---------------------------------------------------------
-- 4) 조회 권한 (rbac.sql 의 ALTER DEFAULT PRIVILEGES 로 향후 자동 적용되지만 명시)
-- ---------------------------------------------------------
GRANT SELECT ON departments TO security_analyst, security_admin, security_manager;

COMMIT;

-- @migrate:verify
-- 이 마커 아래는 검증 절(ON_ERROR_STOP=0). "사용 중인 부서 DELETE -> RESTRICT" 테스트가
-- 의도적으로 ERROR 를 낸다.
-- =========================================================
-- 검증
-- =========================================================
\echo ''
\echo '################ departments 전체 목록 (전용 RLS 역할 유무 표시) ################'
SELECT d.dept_name,
       CASE WHEN r.role_name IS NOT NULL THEN r.role_name ELSE '(전용 역할 없음)' END AS rls_role,
       d.dept_description
FROM departments d
LEFT JOIN rls_role_department r ON r.department = d.dept_name
ORDER BY (r.role_name IS NULL), d.dept_name;

\echo ''
\echo '################ 추가된 FK ################'
SELECT conrelid::regclass AS child_table, conname, pg_get_constraintdef(oid) AS definition
FROM pg_constraint
WHERE contype='f' AND conname LIKE 'fk_%department%'
ORDER BY conrelid::regclass::text;

\echo ''
\echo '################ [TEST] 없는 부서명 INSERT -> FK 로 거부 기대 ################'
DO $$
BEGIN
    BEGIN
        INSERT INTO assets (asset_name, asset_type, department, importance_level)
        VALUES ('테스트자산', 'SERVER', '존재하지않는팀', 3);
        RAISE NOTICE '[FAIL] 없는 부서로 INSERT 가 통과함 (예상: 거부).';
    EXCEPTION WHEN foreign_key_violation THEN
        RAISE NOTICE '[OK] 없는 부서명 INSERT 가 FK 로 거부됨.';
    END;
END $$;

\echo ''
\echo '################ [TEST] 부서명 개명 ON UPDATE CASCADE 전파 (BEGIN..ROLLBACK) ################'
BEGIN;
  UPDATE departments SET dept_name = 'IT운영팀_NEW' WHERE dept_name = 'IT운영팀';
  SELECT 'assets   에 IT운영팀_NEW 로 전파된 행 수' AS check, count(*) AS n FROM assets WHERE department = 'IT운영팀_NEW';
  SELECT 'staff    에 IT운영팀_NEW 로 전파된 행 수' AS check, count(*) AS n FROM staff  WHERE department = 'IT운영팀_NEW';
ROLLBACK;
\echo '   (ROLLBACK 완료 - 원상)'

\echo ''
\echo '################ [TEST] 사용 중인 부서 DELETE -> RESTRICT 로 거부 기대 ################'
BEGIN;
  DELETE FROM departments WHERE dept_name = '인프라팀';   -- 기대: ERROR (RESTRICT)
ROLLBACK;
\echo '   (위에 foreign key 위반 ERROR 가 떠야 정상. ROLLBACK 완료)'

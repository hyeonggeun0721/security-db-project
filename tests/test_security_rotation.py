"""
보안 로테이션 기록 회귀 테스트 — 스크래치 DB(security_db_pytest)에서만 돈다.

옮겨온 검증절:
  8. V037 — 6개 운영 role 전부
       (a) COMMENT ON ROLE 에 "로테이션됨" 취지 문구가 있는지
       (b) pg_authid.rolpassword 검증자가 SCRAM-SHA-256 형식인지

  주의: 이 스위트의 스크래치 DB 는 scripts/bootstrap_role_passwords.py 를 돌리지 않는다.
  V037 이 기록하는 것은 "구조적 사실"(코멘트 + scram 검증자 존재)이고, 그건 V016 이
  password_encryption=scram-sha-256 환경에서 ALTER ROLE ... WITH PASSWORD 를 하면
  이미 성립한다. 실제 비밀번호 값 자체(랜덤인지)는 여기서 검증하지 않는다.
"""
ROLES = [
    "security_analyst",
    "security_admin",
    "security_manager",
    "dept_infra",
    "dept_dev",
    "dept_sales",
]


def test_v037_all_operational_roles_have_rotation_comment(su):
    cur = su.cursor()
    cur.execute(
        "SELECT r.rolname, d.description "
        "FROM pg_roles r "
        "JOIN pg_shdescription d ON d.objoid = r.oid AND d.classoid = 'pg_authid'::regclass "
        "WHERE r.rolname = ANY(%s)",
        (ROLES,),
    )
    comments = dict(cur.fetchall())

    missing = [r for r in ROLES if r not in comments]
    assert not missing, f"COMMENT ON ROLE 이 없는 role: {missing}"

    no_keyword = [r for r, c in comments.items() if "로테이션" not in (c or "")]
    assert not no_keyword, f"코멘트에 '로테이션' 문구가 없는 role: {no_keyword}"


def test_v037_all_operational_roles_use_scram_verifier(su):
    cur = su.cursor()
    cur.execute(
        "SELECT rolname, "
        "       CASE WHEN rolpassword LIKE 'SCRAM-SHA-256%%' THEN 'scram' "
        "            WHEN rolpassword LIKE 'md5%%'           THEN 'md5' "
        "            WHEN rolpassword IS NULL                THEN 'none' "
        "            ELSE 'other' END AS verifier "
        "FROM pg_authid WHERE rolname = ANY(%s)",
        (ROLES,),
    )
    verifier = dict(cur.fetchall())

    missing = [r for r in ROLES if r not in verifier]
    assert not missing, f"pg_authid 에 없는 role: {missing}"

    not_scram = [r for r, v in verifier.items() if v != "scram"]
    assert not not_scram, f"scram-sha-256 검증자가 아닌 role: { {r: verifier[r] for r in not_scram} }"

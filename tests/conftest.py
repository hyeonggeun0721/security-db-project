"""
pytest 회귀 스위트 — 마이그레이션 검증절(-- @migrate:verify) 중 보안·무결성상 중요한
8가지를 자동 pass/fail 로 옮긴 것.

■ 라이브 DB(security_db) 는 이 스위트의 접속 대상이 아니다 — 코드로 보장한다:
  - 접속 가능한 dbname 은 상수 두 개뿐이다:
      SCRATCH_DB = "security_db_pytest"  (테스트 대상, 세션마다 새로 만들고 끝나면 DROP)
      MAINT_DB   = "template1"           (CREATE/DROP DATABASE 발행용, 항상 존재)
  - _connect() 는 그 외 dbname 을 받으면 RuntimeError 를 던진다. "security_db" 는 명시적으로 차단.
  - 테스트/픽스처 어디에도 dbname 을 인자로 바꿀 여지를 두지 않았다.

■ 접속 자격증명: 로컬은 trust 라 불필요. CI(원격/scram)는 libpq 표준 PG* 환경변수
  (PGHOST/PGPORT/PGUSER/PGPASSWORD)를 psycopg2 가 알아서 읽는다.

■ 세션 픽스처 scratch_db:
  1) security_db_pytest 를 DROP(있으면) 후 CREATE ... TEMPLATE template0
  2) CREATE EXTENSION vector
  3) python3 scripts/migrate.py up --database security_db_pytest --skip-verify
     (--skip-verify: 검증절의 \\! 서브셸이 다른 DB 로 접속하는 부작용을 막는다)
  4) yield
  5) 성공/실패 무관하게 security_db_pytest 를 DROP
     (환경변수 PYTEST_KEEP_DB 가 있으면 디버깅용으로 남긴다)
"""
import contextlib
import os
import subprocess
import sys
from pathlib import Path

import psycopg2
from psycopg2 import sql
import pytest

SCRATCH_DB = "security_db_pytest"
LIVE_DB_FORBIDDEN = "security_db"     # 라이브 — 절대 접속 금지
MAINT_DB = "template1"               # CREATE/DROP DATABASE 발행 전용 (항상 존재)

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _connect(dbname):
    """허용된 dbname 만 접속한다. 그 외(특히 라이브 security_db)는 즉시 차단."""
    if dbname == LIVE_DB_FORBIDDEN:
        raise RuntimeError("안전장치: 라이브 DB(security_db) 접속은 이 스위트에서 금지됨")
    if dbname not in (SCRATCH_DB, MAINT_DB):
        raise RuntimeError(
            f"안전장치: 허용 dbname 은 {SCRATCH_DB!r} 또는 유지보수용 {MAINT_DB!r} 뿐 (요청: {dbname!r})"
        )
    return psycopg2.connect(dbname=dbname)


def _subprocess_env():
    """migrate.py 서브프로세스용 env. homebrew/apt 의 psql 경로를 PATH 앞에 얹는다."""
    env = os.environ.copy()
    for cand in (
        "/opt/homebrew/opt/postgresql@15/bin",
        "/usr/local/opt/postgresql@15/bin",
        "/usr/lib/postgresql/15/bin",
    ):
        if Path(cand).is_dir():
            env["PATH"] = cand + os.pathsep + env.get("PATH", "")
    env["PGDATABASE"] = SCRATCH_DB
    return env


def _drop_scratch():
    maint = _connect(MAINT_DB)
    maint.autocommit = True
    try:
        with maint.cursor() as cur:
            cur.execute(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                "WHERE datname = %s AND pid <> pg_backend_pid()",
                (SCRATCH_DB,),
            )
            cur.execute(sql.SQL("DROP DATABASE IF EXISTS {}").format(sql.Identifier(SCRATCH_DB)))
    finally:
        maint.close()


@pytest.fixture(scope="session")
def scratch_db():
    # ---------- provision ----------
    _drop_scratch()
    maint = _connect(MAINT_DB)
    maint.autocommit = True
    try:
        with maint.cursor() as cur:
            cur.execute(
                sql.SQL("CREATE DATABASE {} TEMPLATE template0").format(sql.Identifier(SCRATCH_DB))
            )
    finally:
        maint.close()

    s = _connect(SCRATCH_DB)
    s.autocommit = True
    try:
        with s.cursor() as cur:
            cur.execute("CREATE EXTENSION IF NOT EXISTS vector")
    finally:
        s.close()

    r = subprocess.run(
        [
            sys.executable,
            str(PROJECT_ROOT / "scripts" / "migrate.py"),
            "up",
            "--database",
            SCRATCH_DB,
            "--skip-verify",
        ],
        capture_output=True,
        text=True,
        env=_subprocess_env(),
        cwd=str(PROJECT_ROOT),
    )
    if r.returncode != 0:
        _drop_scratch()
        raise RuntimeError(
            f"migrate.py up (스크래치 DB) 실패 (exit {r.returncode}):\n"
            f"--- stdout ---\n{r.stdout[-4000:]}\n--- stderr ---\n{r.stderr[-4000:]}"
        )

    try:
        yield SCRATCH_DB
    finally:
        # ---------- teardown (성공/실패 무관) ----------
        if os.environ.get("PYTEST_KEEP_DB"):
            print(f"\n[conftest] PYTEST_KEEP_DB 설정됨 — {SCRATCH_DB} 를 DROP 하지 않고 남깁니다.")
        else:
            _drop_scratch()


@pytest.fixture
def su(scratch_db):
    """슈퍼유저 커넥션(스크래치 DB). autocommit=False — 각 테스트 끝에 rollback 하므로
    테스트가 만든 위반/조작 데이터는 다음 테스트로 넘어가지 않는다."""
    conn = _connect(SCRATCH_DB)
    conn.autocommit = False
    try:
        yield conn
    finally:
        conn.rollback()
        conn.close()


@pytest.fixture
def set_role():
    """
    RLS/RBAC 테스트용. 열린 트랜잭션 안에서 SET LOCAL ROLE 을 걸어준다.
    사용:
        with set_role(su, "dept_infra") as cur:
            cur.execute("SELECT count(*) FROM security_events")

    블록은 자기완결적이다: 빠져나올 때 conn.rollback() 을 호출해 SET LOCAL ROLE 을 풀고,
    블록 안에서 한 쓰기(INSERT 등)는 모두 되돌린다. 따라서 슈퍼유저 사전 셋업과 role 조회를
    한 트랜잭션에 묶어야 하는 테스트에는 쓰지 않는다(현재 그런 테스트는 없다).
    """
    @contextlib.contextmanager
    def _ctx(conn, role):
        cur = conn.cursor()
        cur.execute(sql.SQL("SET LOCAL ROLE {}").format(sql.Identifier(role)))
        try:
            yield cur
        finally:
            cur.close()
            conn.rollback()

    return _ctx

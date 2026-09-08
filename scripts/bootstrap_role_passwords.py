#!/usr/bin/env python3
"""
bootstrap_role_passwords.py — 운영 role 6종의 비밀번호를 암호학적 랜덤값으로 로테이션

■ 왜 필요한가 (보안 감사 결과)
  sql/V016__auth_hardening.sql 에 6개 운영 role 의 비밀번호가
    <역할명>#Tmp-2026!chg  (예: Analyst#Tmp-2026!chg)
  패턴으로 평문 커밋돼 있다. "임시 예시, 운영 반영 시 교체" 주석이 있지만 실제로 교체된
  적이 없다. 패턴이 예측 가능해 저장소 접근자는 즉시 전 계정 비밀번호를 유추할 수 있다.
  이 스크립트로 각 role 에 secrets.token_urlsafe(24) 급 랜덤 비밀번호를 새로 걸어
  V016 의 노출된 값을 무력화한다.

■ 현재 로컬 인증은 trust 다 (pg_hba.conf)
  즉 지금은 비밀번호 값 자체가 검증되지 않으므로, 이 로테이션은 "trust → scram-sha-256
  전환 이후"를 대비한 선제 조치다. 전환 절차는 V016 주석 / RUN_ORDER.md 참고.
  password_encryption=scram-sha-256 이라 ALTER ROLE ... WITH PASSWORD 는 SCRAM
  검증자로 저장된다.

■ 절대 하지 말 것
  - 새 고정 비밀번호를 다시 SQL/코드/커밋 메시지에 하드코딩. (그러면 같은 문제 반복.)
  - 생성된 비밀번호를 로그/터미널 스크롤백 외의 곳에 무심코 남기기.

■ 사전 준비
  pip install psycopg2-binary --break-system-packages   # 이미 설치돼 있으면 불필요
  # 접속: 로컬 trust 라 자격증명 불필요. 원격/scram 이면 PGHOST/PGUSER + ~/.pgpass(chmod 600).
  # 이 스크립트는 ALTER ROLE 권한이 있는 계정(기본: 슈퍼유저 summer)으로 접속해야 한다.

■ 사용법
  python3 scripts/bootstrap_role_passwords.py --dry-run        # 대상 role 만 출력, 변경 없음
  python3 scripts/bootstrap_role_passwords.py                  # 6종 로테이션, 새 비밀번호를 터미널에 1회만 출력
  python3 scripts/bootstrap_role_passwords.py --roles security_admin dept_infra
  python3 scripts/bootstrap_role_passwords.py --save-to-file secrets/roles_2026-09-08.txt

  기본은 파일로 저장하지 않는다. 출력된 비밀번호를 즉시 비밀번호 관리자(1Password 등)에
  넣어야 하며, 스크립트를 다시 돌리기 전에는 재조회할 수 없다.
  --save-to-file 은 .gitignore 로 걸린 위치(secrets/ 등)만 허용한다.
"""
import argparse
import os
import secrets
import subprocess
import sys

import psycopg2
from psycopg2 import sql

DEFAULT_ROLES = [
    "security_analyst",
    "security_admin",
    "security_manager",
    "dept_infra",
    "dept_dev",
    "dept_sales",
]

DB_NAME = os.environ.get("PGDATABASE", "security_db")


def _git_ignored(path: str) -> bool:
    """git 이 이 경로를 무시(ignore)하는지 확인. git 밖이거나 오류면 False(안전측)."""
    try:
        repo_root = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        r = subprocess.run(
            ["git", "check-ignore", "-q", os.path.abspath(path)],
            cwd=repo_root,
        )
        return r.returncode == 0
    except Exception:
        return False


def main():
    ap = argparse.ArgumentParser(
        description="운영 role 비밀번호를 암호학적 랜덤값으로 로테이션",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--roles", nargs="+", default=DEFAULT_ROLES,
                    help=f"대상 role (기본: {' '.join(DEFAULT_ROLES)})")
    ap.add_argument("--database", default=DB_NAME)
    ap.add_argument("--dry-run", action="store_true",
                    help="대상 role 만 출력하고 비밀번호 생성/변경을 하지 않음")
    ap.add_argument("--save-to-file", metavar="PATH", default=None,
                    help="생성된 비밀번호를 이 경로에 저장 (.gitignore 로 걸린 위치만 허용)")
    a = ap.parse_args()

    if a.dry_run:
        print(f"[dry-run] DB={a.database}  로테이션 대상 {len(a.roles)}개:")
        for r in a.roles:
            print(f"  - {r}")
        print("\n[dry-run] 실제 비밀번호 생성/변경은 하지 않았습니다.")
        return

    if a.save_to_file and not _git_ignored(a.save_to_file):
        sys.exit(
            f"거부: --save-to-file 경로 '{a.save_to_file}' 가 .gitignore 로 걸려 있지 않습니다.\n"
            f"       secrets/ 같이 무시되는 위치를 쓰거나, .gitignore 에 먼저 추가하세요.\n"
            f"       (비밀번호 파일이 실수로 커밋되는 걸 막기 위한 안전장치)"
        )

    # 접속: 로컬 trust 면 자격증명 불필요. 원격/scram 이면 PG* 환경변수/.pgpass 사용.
    conn = psycopg2.connect(dbname=a.database)
    conn.autocommit = False

    generated = {}
    try:
        with conn.cursor() as cur:
            # 대상 role 실재 확인
            cur.execute(
                "SELECT rolname FROM pg_roles WHERE rolname = ANY(%s)",
                (a.roles,),
            )
            found = {r[0] for r in cur.fetchall()}
            missing = [r for r in a.roles if r not in found]
            if missing:
                sys.exit(f"거부: 존재하지 않는 role: {', '.join(missing)}")

            for role in a.roles:
                new_pw = secrets.token_urlsafe(24)
                # role 이름 = 식별자(안전한 quoting), 비밀번호 = 파라미터 바인딩. 문자열 concat 금지.
                cur.execute(
                    sql.SQL("ALTER ROLE {} WITH PASSWORD %s").format(sql.Identifier(role)),
                    (new_pw,),
                )
                generated[role] = new_pw
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    print(f"✔ DB={a.database}  {len(generated)}개 role 비밀번호 로테이션 완료 "
          f"(scram-sha-256 검증자로 저장됨).\n")
    print("=" * 68)
    print("아래 비밀번호는 지금 이 화면에서만 볼 수 있습니다. 다시 조회 불가.")
    print("즉시 비밀번호 관리자(1Password 등)에 저장하세요.")
    print("=" * 68)
    for role, pw in generated.items():
        print(f"  {role:<18} {pw}")
    print("=" * 68)

    if a.save_to_file:
        os.makedirs(os.path.dirname(os.path.abspath(a.save_to_file)) or ".", exist_ok=True)
        with open(a.save_to_file, "w") as f:
            f.write("# security_db 운영 role 비밀번호 (bootstrap_role_passwords.py 생성)\n")
            f.write("# 이 파일은 .gitignore 로 제외됨. 관리자에 옮긴 뒤 삭제 권장.\n")
            for role, pw in generated.items():
                f.write(f"{role}\t{pw}\n")
        os.chmod(a.save_to_file, 0o600)
        print(f"\n(저장됨: {a.save_to_file}, chmod 600 — 관리자에 옮긴 뒤 삭제 권장)")

    print("\n다음 단계: sql/V037__rotate_exposed_role_passwords.sql 을 migrate.py 로 적용해")
    print("           'V016 값은 폐기됨' 을 스키마(role 코멘트)에 기록하세요.")


if __name__ == "__main__":
    main()

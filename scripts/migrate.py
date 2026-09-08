#!/usr/bin/env python3
"""
migrate.py — security_db 마이그레이션 러너 (psql 래퍼 + 체크섬 drift 탐지)

왜 자체 러너인가:
  Flyway 는 brew 로 설치 가능하지만 SQL 을 JDBC 로 직접 실행한다. 이 프로젝트의
  sql/V*.sql 중 24/26 개가 psql 메타명령(\echo, \!, \d, \set)과 파일 내부
  검증/테스트 블록에 의존하므로, JDBC 실행기로는 대부분 파일이 깨진다.
  → 마이그레이션을 "psql 로" 실행해야 하는 상황의 표준 패턴: 얇은 psql 래퍼에
    이력 테이블 + 체크섬 drift 탐지(마이그레이션 도구의 핵심 가치)를 얹는다.

이력 테이블: schema_migrations(version, filename, checksum, applied_at, applied_by, exec_seconds)

명령:
  python3 scripts/migrate.py status              # 무엇이 적용/미적용/drift 인지 (기본)
  python3 scripts/migrate.py up [--dry-run] [--skip-verify]   # 미적용 마이그레이션을 순서대로 적용
                                                # --skip-verify: '-- @migrate:verify' 절은 건너뛴다(본문만 적용)
  python3 scripts/migrate.py baseline [--force]  # 기존 DB 채택: 현재 V*.sql 을 "이미 적용됨"으로 기록(실행 안 함)
  옵션: --database NAME (기본 $PGDATABASE 또는 security_db), --sql-dir PATH

동작 규칙:
  - sql/V<번호>__<이름>.sql 만 마이그레이션으로 인식. 번호 오름차순 적용.
  - 파일별 sha256(원본 바이트) 을 schema_migrations.checksum 과 대조.
      · 미기록            -> 적용 대상(pending)
      · 기록 + 체크섬 일치 -> skip (idempotent)
      · 기록 + 체크섬 불일치 -> DRIFT: 에러로 중단(적용된 마이그레이션 파일은 불변)
  - '-- @migrate:verify' 마커가 있으면 그 위=본문(ON_ERROR_STOP=1), 아래=검증절
    (ON_ERROR_STOP=0, 실패해도 마이그레이션은 성공으로 기록). 마커 없으면 전체가 본문.
"""
import argparse
import hashlib
import os
import re
import subprocess
import sys
import time
from pathlib import Path

MARKER = "-- @migrate:verify"
FNAME_RE = re.compile(r"^V(\d+)__(.+)\.sql$")

BOOTSTRAP_SQL = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version      TEXT PRIMARY KEY,
    filename     TEXT NOT NULL,
    checksum     TEXT NOT NULL,
    applied_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    applied_by   TEXT NOT NULL DEFAULT session_user,
    exec_seconds NUMERIC(10,3)
);
COMMENT ON TABLE schema_migrations IS
  'migrate.py 마이그레이션 이력. version=Vnnn, checksum=파일 sha256. 적용된 행의 파일을 수정하면 drift 로 차단됨.';
"""


def sh(args, **kw):
    return subprocess.run(args, capture_output=True, text=True, **kw)


class Migrator:
    def __init__(self, database, sql_dir):
        self.database = database
        self.sql_dir = Path(sql_dir)

    # ---- psql helpers -------------------------------------------------
    def _psql_base(self):
        return ["psql", "-d", self.database, "-X", "-q", "-v", "ON_ERROR_STOP=1"]

    def psql_scalar(self, sql):
        r = sh(self._psql_base() + ["-t", "-A", "-c", sql])
        if r.returncode != 0:
            raise RuntimeError(f"psql 실패: {r.stderr.strip()}")
        return r.stdout.strip()

    def psql_exec(self, sql, stop_on_error=True):
        args = ["psql", "-d", self.database, "-X", "-q",
                "-v", f"ON_ERROR_STOP={'1' if stop_on_error else '0'}", "-c", sql]
        return sh(args)

    def psql_file_text(self, text, stop_on_error=True):
        args = ["psql", "-d", self.database, "-X", "-q",
                "-v", f"ON_ERROR_STOP={'1' if stop_on_error else '0'}", "-f", "-"]
        return sh(args, input=text)

    # ---- discovery --------------------------------------------------
    def discover(self):
        out = []
        for p in sorted(self.sql_dir.glob("V*.sql")):
            m = FNAME_RE.match(p.name)
            if not m:
                continue
            raw = p.read_bytes()
            out.append({
                "version": f"{int(m.group(1)):03d}",
                "name": m.group(2),
                "filename": p.name,
                "path": p,
                "checksum": hashlib.sha256(raw).hexdigest(),
            })
        out.sort(key=lambda d: int(d["version"]))
        if not out:
            sys.exit(f"[migrate] {self.sql_dir} 에 V*.sql 마이그레이션이 없습니다.")
        return out

    def applied_map(self):
        sh(self._psql_base() + ["-c", BOOTSTRAP_SQL])  # idempotent bootstrap
        r = sh(self._psql_base() + ["-t", "-A", "-F", "\x1f",
               "-c", "SELECT version, filename, checksum, applied_at, applied_by FROM schema_migrations"])
        if r.returncode != 0:
            sys.exit(f"[migrate] schema_migrations 조회 실패:\n{r.stderr}")
        m = {}
        for line in r.stdout.splitlines():
            if not line.strip():
                continue
            v, fn, cs, at, by = line.split("\x1f")
            m[v] = {"filename": fn, "checksum": cs, "applied_at": at, "applied_by": by}
        return m

    # ---- classification -------------------------------------------
    def plan(self):
        migs = self.discover()
        applied = self.applied_map()
        rows = []
        for d in migs:
            a = applied.get(d["version"])
            if a is None:
                state = "pending"
            elif a["checksum"] == d["checksum"]:
                state = "applied"
            else:
                state = "DRIFT"
            rows.append({**d, "state": state, "applied": a})
        # 이력에는 있는데 파일이 사라진 경우
        known = {d["version"] for d in migs}
        for v, a in sorted(applied.items()):
            if v not in known:
                rows.append({"version": v, "filename": a["filename"], "name": "",
                             "path": None, "checksum": None, "state": "MISSING-FILE", "applied": a})
        return rows

    # ---- commands -------------------------------------------------
    def cmd_status(self):
        rows = self.plan()
        w = max((len(r["filename"]) for r in rows), default=10)
        print(f"DB: {self.database}\n")
        print(f"{'VER':<5} {'FILE':<{w}} {'STATE':<13} {'APPLIED_AT':<29} APPLIED_BY")
        print("-" * (5 + w + 13 + 29 + 12))
        for r in rows:
            a = r["applied"] or {}
            print(f"{r['version']:<5} {r['filename']:<{w}} {r['state']:<13} "
                  f"{(a.get('applied_at') or ''):<29} {a.get('applied_by') or ''}")
        drift = [r for r in rows if r["state"] in ("DRIFT", "MISSING-FILE")]
        pend = [r for r in rows if r["state"] == "pending"]
        print()
        if drift:
            print(f"⚠  DRIFT {len(drift)}건 — 적용된 마이그레이션 파일이 변경/삭제됨. 'up' 이 차단됩니다.")
        print(f"적용됨 {sum(1 for r in rows if r['state']=='applied')} · "
              f"미적용 {len(pend)} · drift {len(drift)}")
        return 2 if drift else 0

    def _split(self, text):
        for i, line in enumerate(text.splitlines(keepends=True)):
            if line.strip().startswith(MARKER):
                cut = text.index(line)
                return text[:cut], text[cut:]
        return text, ""

    def cmd_up(self, dry_run=False, skip_verify=False):
        rows = self.plan()
        drift = [r for r in rows if r["state"] in ("DRIFT", "MISSING-FILE")]
        if drift:
            print("✖ DRIFT 감지 — 적용을 중단합니다. 적용된 마이그레이션은 불변입니다.\n")
            for r in drift:
                if r["state"] == "DRIFT":
                    print(f"  {r['filename']}")
                    print(f"    기록된 checksum : {r['applied']['checksum']}")
                    print(f"    현재  checksum : {r['checksum']}")
                    print(f"    → 되돌리거나, 변경분은 새 V### 마이그레이션으로 추가하세요.")
                else:
                    print(f"  {r['filename']} — 이력에 있으나 파일이 없음")
            return 1

        pending = [r for r in rows if r["state"] == "pending"]
        if not pending:
            print(f"DB: {self.database} — 미적용 마이그레이션 없음. 최신 상태입니다.")
            return 0

        print(f"DB: {self.database} — 적용 대상 {len(pending)}건"
              f"{' (dry-run)' if dry_run else ''}:\n")
        for r in pending:
            print(f"  → V{r['version']} {r['filename']}")
        if dry_run:
            return 0
        print()

        for r in pending:
            text = r["path"].read_text()
            body, verify = self._split(text)
            print(f"── V{r['version']} {r['filename']} 적용 …")
            t0 = time.time()
            res = self.psql_file_text(body, stop_on_error=True)
            secs = round(time.time() - t0, 3)
            if res.returncode != 0:
                print(res.stdout)
                print(res.stderr, file=sys.stderr)
                print(f"\n✖ V{r['version']} 적용 실패 (psql exit {res.returncode}). "
                      f"이후 마이그레이션 중단. schema_migrations 에 기록하지 않음.")
                return 1
            # 이력 기록
            ins = self.psql_exec(
                "INSERT INTO schema_migrations(version, filename, checksum, exec_seconds) "
                f"VALUES ('{r['version']}', '{r['filename']}', '{r['checksum']}', {secs})")
            if ins.returncode != 0:
                print(ins.stderr, file=sys.stderr)
                print(f"\n✖ V{r['version']} 본문은 적용됐으나 이력 기록 실패. "
                      f"수동으로 위 INSERT 를 넣어야 재실행이 안전합니다.")
                return 1
            print(f"   ok ({secs}s)")
            if verify.strip() and not skip_verify:
                vr = self.psql_file_text(verify, stop_on_error=False)
                tail = "\n".join(l for l in vr.stdout.splitlines() if l.strip())[-1500:]
                if tail:
                    print("   [검증절 출력 발췌]")
                    print("   " + tail.replace("\n", "\n   "))
        print(f"\n✔ 완료. {len(pending)}건 적용.")
        return 0

    def cmd_baseline(self, force=False, up_to=None):
        applied = self.applied_map()
        if applied and not force:
            sys.exit(f"[migrate] schema_migrations 에 이미 {len(applied)}건 있음. "
                     f"baseline 은 빈 이력에서만. 강행하려면 --force.")
        migs = self.discover()
        if up_to is not None:
            keep = f"{int(up_to):03d}"
            migs = [d for d in migs if d["version"] <= keep]
        print(f"DB: {self.database} — V*.sql {len(migs)}개를 '적용됨(baseline)'으로 기록 "
              f"(실행하지 않음"
              + (f", V{up_to} 까지" if up_to is not None else "") + "):\n")
        vals = ",".join(
            f"('{d['version']}','{d['filename']}','{d['checksum']}', 'baseline')" for d in migs)
        sql = ("INSERT INTO schema_migrations(version, filename, checksum, applied_by) "
               f"VALUES {vals} "
               "ON CONFLICT (version) DO UPDATE SET checksum=EXCLUDED.checksum, "
               "filename=EXCLUDED.filename, applied_by='baseline', applied_at=now()")
        r = self.psql_exec(sql)
        if r.returncode != 0:
            print(r.stderr, file=sys.stderr)
            return 1
        for d in migs:
            print(f"  V{d['version']} {d['filename']}  {d['checksum'][:12]}…")
        print(f"\n✔ baseline 완료. 이후 'up' 은 새 V### 파일만 적용합니다.")
        return 0


def main():
    ap = argparse.ArgumentParser(description="security_db 마이그레이션 러너")
    ap.add_argument("command", nargs="?", default="status",
                    choices=["status", "up", "baseline"])
    ap.add_argument("--database", default=os.environ.get("PGDATABASE", "security_db"))
    ap.add_argument("--sql-dir",
                    default=str(Path(__file__).resolve().parent.parent / "sql"))
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--skip-verify", action="store_true",
                    help="up: 각 파일의 '-- @migrate:verify' 검증절을 실행하지 않는다. "
                         "본문(스키마)은 그대로 적용된다. 빈 DB 프로비저닝(pytest 스크래치 DB 등)에서 "
                         "검증절의 \\! 서브셸이 다른 DB 로 접속하는 부작용을 피하려는 용도.")
    ap.add_argument("--up-to", metavar="NNN",
                    help="baseline: 이 버전까지만 '적용됨'으로 기록 (그 이후는 up 이 실제 적용)")
    a = ap.parse_args()
    m = Migrator(a.database, a.sql_dir)
    if a.command == "status":
        sys.exit(m.cmd_status())
    if a.command == "up":
        sys.exit(m.cmd_up(dry_run=a.dry_run, skip_verify=a.skip_verify))
    if a.command == "baseline":
        sys.exit(m.cmd_baseline(force=a.force, up_to=a.up_to))


if __name__ == "__main__":
    main()

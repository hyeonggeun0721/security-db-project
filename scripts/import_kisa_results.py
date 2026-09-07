#!/usr/bin/env python3
"""
import_kisa_results.py — KISA 취약점 스캐너(kisa_scanner.py) JSON 리포트를 security_db 에 적재

무엇을 넣나:
  - "취약" 판정 항목만 DB 에 적재한다.
      · vulnerabilities  : source='SCAN', finding_ref='KISA-U-##', cve_id=NULL
                           (KISA 중요도 → severity/환산 cvss_score. 아래 매핑)
      · scan_runs        : 스캔 1회 실행 메타(호스트/시각/root/집계)
      · asset_vulnerabilities : 스캔 대상 asset ↔ vulnerabilities 연결(status='OPEN'),
                                scan_run_id + observed_detail(그 호스트의 현재 설정값)
  - "점검불가"/"양호" 는 DB 에 넣지 않고 로그(reports/kisa_scans/import_<ts>.log)에만 남긴다.

KISA 중요도(상/중/하) → severity / 환산 cvss_score  (V030 주석과 동일):
      상 → HIGH   / 7.5      중 → MEDIUM / 5.0      하 → LOW / 2.5
  * CRITICAL 은 설정취약점에 배정하지 않음. 환산 cvss 는 실제 CVE 기본점수가 아니며
    source='SCAN' 으로 구분된다. vw_asset_risk_score(importance × max_open_cvss) 재사용 목적.

DB 접속: 관리자 ETL 성격(nvd_sync.py 와 동일) → 소유자 계정으로 접속(로컬 trust).

사용:
  python3 scripts/import_kisa_results.py                       # reports/kisa_scans/ 최신 JSON
  python3 scripts/import_kisa_results.py --report <path.json>
  python3 scripts/import_kisa_results.py --asset-name "KISA스캔대상-ubuntu2204"
  python3 scripts/import_kisa_results.py --dry-run
"""
import argparse
import datetime as dt
import glob
import json
import os
import sys
from pathlib import Path

import psycopg2
from psycopg2.extras import execute_values

DB_NAME = os.environ.get("PGDATABASE", "security_db")
PROJ = Path(__file__).resolve().parent.parent
SCAN_DIR = PROJ / "reports" / "kisa_scans"

# ── KISA U-01~U-72 중요도 (KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세가이드).
#    조직 정책에 맞게 조정 가능.
KISA_IMPORTANCE = {
    "U-01": "상", "U-02": "상", "U-03": "중", "U-04": "상", "U-05": "중",
    "U-06": "상", "U-07": "상", "U-08": "상", "U-09": "상", "U-10": "상",
    "U-11": "상", "U-12": "상", "U-13": "상", "U-14": "중", "U-15": "상",
    "U-16": "하", "U-17": "상", "U-18": "상", "U-19": "상", "U-20": "상",
    "U-21": "상", "U-22": "중", "U-23": "상", "U-24": "상", "U-25": "상",
    "U-26": "하", "U-27": "중", "U-28": "중", "U-29": "상", "U-30": "상",
    "U-31": "상", "U-32": "중", "U-33": "상", "U-34": "상", "U-35": "상",
    "U-36": "상", "U-37": "상", "U-38": "하", "U-39": "중", "U-40": "상",
    "U-41": "중", "U-42": "상", "U-43": "하", "U-44": "상", "U-45": "상",
    "U-46": "중", "U-47": "상", "U-48": "중", "U-49": "상", "U-50": "상",
    "U-51": "중", "U-52": "중", "U-53": "중", "U-54": "중", "U-55": "하",
    "U-56": "중", "U-57": "중", "U-58": "하", "U-59": "중", "U-60": "상",
    "U-61": "상", "U-62": "상", "U-63": "중", "U-64": "중", "U-65": "중",
    "U-66": "상", "U-67": "중", "U-68": "하", "U-69": "중", "U-70": "중",
    "U-71": "중", "U-72": "상",
}
IMPORTANCE_MAP = {          # KISA 중요도 -> (severity, 환산 cvss_score)
    "상": ("HIGH", 7.5),
    "중": ("MEDIUM", 5.0),
    "하": ("LOW", 2.5),
}
DEFAULT_IMPORTANCE = "중"


def latest_report():
    files = sorted(glob.glob(str(SCAN_DIR / "kisa_report_*.json")))
    if not files:
        sys.exit(f"{SCAN_DIR} 에 kisa_report_*.json 이 없습니다. 먼저 kisa_scanner.py 를 실행하세요.")
    return files[-1]


def derive_asset_name(rep):
    plat = (rep.get("distro") or {}).get("pretty_name") or rep.get("platform") or "unknown"
    # 예: "KISA스캔대상-Ubuntu 22.04.5 LTS" -> 공백/괄호 정리
    tag = plat.replace(" ", "").replace("(", "").replace(")", "")
    return f"KISA스캔대상-{tag}"[:100]


def main():
    ap = argparse.ArgumentParser(description="KISA 스캔 결과 → security_db 적재")
    ap.add_argument("--report", help="KISA JSON 리포트 경로 (기본: reports/kisa_scans/ 최신)")
    ap.add_argument("--asset-name", help="스캔 대상 asset 이름 (기본: 리포트에서 유도)")
    ap.add_argument("--asset-importance", type=int, default=2,
                    help="대상 asset 이 새로 생성될 때 importance_level (1~5, 기본 2=샌드박스)")
    ap.add_argument("--asset-department", default="보안팀", help="새 asset 의 department (기본 보안팀)")
    ap.add_argument("--database", default=DB_NAME)
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    path = a.report or latest_report()
    rep = json.load(open(path, encoding="utf-8"))
    results = rep.get("results", [])
    vuln_items = [r for r in results if r.get("result") == "취약"]
    na_items = [r for r in results if r.get("result") == "점검불가"]
    good_items = [r for r in results if r.get("result") == "양호"]
    asset_name = a.asset_name or derive_asset_name(rep)
    scanned_at = rep.get("scan_timestamp") or dt.datetime.now().isoformat()

    print(f"리포트      : {path}")
    print(f"대상 호스트  : {rep.get('hostname')} / {rep.get('platform')} / "
          f"{(rep.get('distro') or {}).get('pretty_name')} / root={rep.get('is_root')}")
    print(f"asset 이름   : {asset_name}")
    print(f"집계        : 총 {rep.get('total')}  양호 {len(good_items)}  취약 {len(vuln_items)}  점검불가 {len(na_items)}")
    print(f"DB 적재 대상 : 취약 {len(vuln_items)}건 (점검불가/양호는 로그만)")
    print()

    # 적재 미리보기
    for r in vuln_items:
        code = r["item_code"]
        imp = KISA_IMPORTANCE.get(code, DEFAULT_IMPORTANCE)
        sev, cvss = IMPORTANCE_MAP[imp]
        print(f"  KISA-{code}  중요도 {imp} -> {sev}/{cvss}  {r['item_name']}")
        print(f"     관측: {r['current_setting'][:100]}")

    if a.dry_run:
        print("\n(dry-run) DB 변경 없음.")
        return

    conn = psycopg2.connect(dbname=a.database)
    conn.autocommit = False
    try:
        cur = conn.cursor()

        # 1) 대상 asset upsert
        cur.execute("SELECT asset_id FROM assets WHERE asset_name = %s", (asset_name,))
        row = cur.fetchone()
        if row:
            asset_id = row[0]
            print(f"\nasset '{asset_name}' 기존 사용 (asset_id={asset_id})")
        else:
            cur.execute(
                "INSERT INTO assets (asset_name, asset_type, ip_address, department, importance_level) "
                "VALUES (%s, 'SERVER', NULL, %s, %s) RETURNING asset_id",
                (asset_name, a.asset_department, a.asset_importance))
            asset_id = cur.fetchone()[0]
            print(f"\nasset '{asset_name}' 신규 생성 (asset_id={asset_id}, dept={a.asset_department}, importance={a.asset_importance})")

        # 2) scan_runs upsert (tool+hostname+scanned_at UNIQUE)
        d = rep.get("distro") or {}
        cur.execute(
            "INSERT INTO scan_runs "
            "(tool, target_asset_id, target_hostname, target_platform, target_distro, "
            " scanned_as_root, scanned_at, total_checks, cnt_good, cnt_vuln, cnt_na, report_path) "
            "VALUES ('KISA-U (U-01~U-72)', %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) "
            "ON CONFLICT (tool, target_hostname, scanned_at) DO UPDATE SET "
            "  target_asset_id=EXCLUDED.target_asset_id, cnt_good=EXCLUDED.cnt_good, "
            "  cnt_vuln=EXCLUDED.cnt_vuln, cnt_na=EXCLUDED.cnt_na, report_path=EXCLUDED.report_path, "
            "  imported_at=now() "
            "RETURNING scan_run_id",
            (asset_id, rep.get("hostname"), rep.get("platform"), d.get("pretty_name"),
             rep.get("is_root"), scanned_at, rep.get("total"),
             len(good_items), len(vuln_items), len(na_items), path))
        scan_run_id = cur.fetchone()[0]
        print(f"scan_runs 기록 (scan_run_id={scan_run_id})")

        # 3) 취약 항목 -> vulnerabilities + asset_vulnerabilities upsert
        n_vuln_new = n_vuln_upd = n_link = 0
        for r in vuln_items:
            code = r["item_code"]
            fref = f"KISA-{code}"
            imp = KISA_IMPORTANCE.get(code, DEFAULT_IMPORTANCE)
            sev, cvss = IMPORTANCE_MAP[imp]
            desc = f"[KISA {code}] {r['item_name']} (설정 취약점, 중요도 {imp})"
            remediation = r.get("recommendation")

            cur.execute(
                "INSERT INTO vulnerabilities "
                "(cve_id, description, cvss_score, severity, published_date, source, finding_ref, remediation) "
                "VALUES (NULL, %s, %s, %s, NULL, 'SCAN', %s, %s) "
                "ON CONFLICT (finding_ref) WHERE finding_ref IS NOT NULL DO UPDATE SET "
                "  description=EXCLUDED.description, cvss_score=EXCLUDED.cvss_score, "
                "  severity=EXCLUDED.severity, remediation=EXCLUDED.remediation, source='SCAN' "
                "RETURNING vuln_id, (xmax = 0) AS inserted",
                (desc, cvss, sev, fref, remediation))
            vuln_id, inserted = cur.fetchone()
            if inserted:
                n_vuln_new += 1
            else:
                n_vuln_upd += 1

            cur.execute(
                "INSERT INTO asset_vulnerabilities "
                "(asset_id, vuln_id, detected_date, status, scan_run_id, observed_detail) "
                "VALUES (%s, %s, CURRENT_DATE, 'OPEN', %s, %s) "
                "ON CONFLICT (asset_id, vuln_id) DO UPDATE SET "
                "  status = CASE WHEN asset_vulnerabilities.status = 'PATCHED' THEN 'OPEN' "
                "                ELSE asset_vulnerabilities.status END, "
                "  detected_date = CURRENT_DATE, scan_run_id = EXCLUDED.scan_run_id, "
                "  observed_detail = EXCLUDED.observed_detail",
                (asset_id, vuln_id, scan_run_id, r.get("current_setting")))
            n_link += 1

        conn.commit()

        # 4) 점검불가/양호 는 로그로만
        ts = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
        logf = SCAN_DIR / f"import_{ts}.log"
        with open(logf, "w", encoding="utf-8") as f:
            f.write(f"# KISA import {ts}  report={path}  asset_id={asset_id}  scan_run_id={scan_run_id}\n")
            f.write(f"# 적재: vulnerabilities 신규 {n_vuln_new} / 갱신 {n_vuln_upd}, asset_vulnerabilities {n_link}\n\n")
            f.write("## DB 미적재 - 점검불가 (%d)\n" % len(na_items))
            for r in na_items:
                f.write(f"  {r['item_code']:6} | {r['item_name']} | {r['current_setting']}\n")
            f.write("\n## DB 미적재 - 양호 (%d)\n" % len(good_items))
            for r in good_items:
                f.write(f"  {r['item_code']:6} | {r['item_name']}\n")

        print(f"\n✔ 커밋 완료")
        print(f"  vulnerabilities : 신규 {n_vuln_new} / 갱신 {n_vuln_upd}  (source='SCAN')")
        print(f"  asset_vulnerabilities : {n_link}건 연결 (asset_id={asset_id}, scan_run_id={scan_run_id})")
        print(f"  점검불가 {len(na_items)} / 양호 {len(good_items)} → 로그: {logf}")
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


if __name__ == "__main__":
    main()

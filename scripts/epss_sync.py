#!/usr/bin/env python3
"""
epss_sync.py - FIRST.org EPSS API 로 vulnerabilities.cve_id 들의 악용확률(EPSS)을
               nvd_cve_details.epss_* 컬럼에 UPSERT 한다 (재실행 가능 / idempotent).

  EPSS = "향후 30일 내 해당 CVE 의 악용 활동이 관측될 확률" (0~1). 인증 불필요, 무료.
  API: https://api.first.org/data/v1/epss?cve=CVE-x,CVE-y,...   (콤마로 여러 개 배치 조회)

  대상: vulnerabilities WHERE cve_id IS NOT NULL  (NVD 유래. KISA SCAN 행은 cve_id 없어 제외)
  저장: nvd_cve_details (V031 에서 epss_score/epss_percentile/epss_model_date/epss_updated_at 추가).
        nvd_cve_details 에 행이 없던 CVE 는 nvd_status='PENDING' 으로 생성됨
        (nvd_sync.py 를 나중에 돌리면 SYNCED/NOT_FOUND 로 정정).

  실행:  python3 scripts/epss_sync.py
         python3 scripts/epss_sync.py --batch 50
"""
import argparse
import datetime as dt
import os
import sys
import time

import psycopg2
import requests
from psycopg2.extras import execute_values

DB_NAME = os.environ.get("PGDATABASE", "security_db")
EPSS_URL = "https://api.first.org/data/v1/epss"
REQUEST_TIMEOUT = 30
SLEEP_SEC = 1.0            # 공개 API — 배치 간 예의상 대기
BATCH_DEFAULT = 50        # 한 요청에 조회할 CVE 수 (API limit 은 훨씬 크지만 URL 길이 여유)

UPSERT_SQL = """
INSERT INTO nvd_cve_details
    (cve_id, nvd_status, epss_score, epss_percentile, epss_model_date, epss_updated_at)
VALUES %s
ON CONFLICT (cve_id) DO UPDATE SET
    epss_score      = EXCLUDED.epss_score,
    epss_percentile = EXCLUDED.epss_percentile,
    epss_model_date = EXCLUDED.epss_model_date,
    epss_updated_at = EXCLUDED.epss_updated_at
"""
# 신규행은 nvd_status='PENDING' (아직 NVD 상세 미동기화), 기존행은 nvd_status 유지
UPSERT_TEMPLATE = "(%s, 'PENDING', %s::numeric, %s::numeric, %s::date, %s::timestamptz)"


def fetch_epss_batch(cve_ids):
    """CVE 목록을 한 번에 조회. {cve_id: (epss, percentile, date)} 반환. 429/5xx 는 백오프 재시도."""
    param = ",".join(cve_ids)
    for attempt in range(1, 5):
        try:
            r = requests.get(EPSS_URL, params={"cve": param}, timeout=REQUEST_TIMEOUT)
        except requests.RequestException as e:
            print(f"    ! 요청 예외({attempt}/4): {e}")
            time.sleep(SLEEP_SEC * attempt + 2)
            continue

        if r.status_code == 200:
            out = {}
            for row in r.json().get("data", []):
                try:
                    out[row["cve"]] = (
                        float(row["epss"]), float(row["percentile"]), row.get("date"))
                except (KeyError, ValueError):
                    continue
            return out

        if r.status_code in (429, 500, 502, 503):
            wait = SLEEP_SEC * (attempt + 1) + 5
            print(f"    ! HTTP {r.status_code} - {wait:.0f}s 대기 후 재시도({attempt}/4)")
            time.sleep(wait)
            continue

        print(f"    ! HTTP {r.status_code}: {r.text[:160]}")
        return None
    return None


def chunks(seq, n):
    for i in range(0, len(seq), n):
        yield seq[i:i + n]


def main():
    ap = argparse.ArgumentParser(description="FIRST.org EPSS → nvd_cve_details 동기화")
    ap.add_argument("--batch", type=int, default=BATCH_DEFAULT, help=f"요청당 CVE 수 (기본 {BATCH_DEFAULT})")
    ap.add_argument("--database", default=DB_NAME)
    a = ap.parse_args()

    conn = psycopg2.connect(dbname=a.database)
    conn.autocommit = False
    cur = conn.cursor()

    cur.execute("SELECT cve_id FROM vulnerabilities WHERE cve_id IS NOT NULL ORDER BY cve_id")
    cve_ids = [r[0] for r in cur.fetchall()]
    if not cve_ids:
        print("cve_id 가 있는 vulnerabilities 행이 없습니다.")
        return 0
    print(f"대상 CVE {len(cve_ids)}건, 요청당 {a.batch}건씩\n")

    now = dt.datetime.now(dt.timezone.utc)
    found = {}
    for bi, batch in enumerate(chunks(cve_ids, a.batch), 1):
        print(f"[배치 {bi}] {len(batch)}건 조회 ...", end=" ", flush=True)
        res = fetch_epss_batch(batch)
        if res is None:
            print("실패 — 롤백")
            conn.rollback()
            return 1
        found.update(res)
        print(f"응답 {len(res)}건")
        time.sleep(SLEEP_SEC)

    rows = []
    for cid in cve_ids:
        if cid in found:
            epss, pct, mdate = found[cid]
            rows.append((cid, epss, pct, mdate, now))

    if rows:
        execute_values(cur, UPSERT_SQL, rows, template=UPSERT_TEMPLATE)
    conn.commit()

    # 요약
    cur.execute("""
        SELECT count(*) FILTER (WHERE epss_score IS NOT NULL),
               round(max(epss_score),5), round(max(epss_percentile),5), max(epss_updated_at)
        FROM nvd_cve_details
    """)
    n_epss, max_e, max_p, last = cur.fetchone()
    cur.execute("SELECT count(*) FROM vw_priority_vulnerabilities")
    n_prio = cur.fetchone()[0]
    cur.execute("SELECT count(*) FROM vw_priority_vulnerabilities WHERE epss_over_cvss")
    n_over = cur.fetchone()[0]
    cur.execute("SELECT count(*) FROM nvd_cve_details WHERE nvd_status='PENDING'")
    n_pending = cur.fetchone()[0]

    missing = [c for c in cve_ids if c not in found]
    print("\n=== EPSS 동기화 결과 ===")
    print(f"  이번 실행: 응답 {len(found)} / 대상 {len(cve_ids)}   (EPSS 미제공: {len(missing)}{' — '+', '.join(missing) if missing else ''})")
    print(f"  nvd_cve_details.epss 채워진 행: {n_epss}  (최대 epss={max_e}, 최대 percentile={max_p})")
    print(f"  nvd_status='PENDING' (EPSS만, NVD 상세 미동기화): {n_pending}")
    print(f"  vw_priority_vulnerabilities: {n_prio}건  (그중 epss_over_cvss=TRUE: {n_over})")
    print(f"  epss_updated_at: {last}")

    cur.close()
    conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())

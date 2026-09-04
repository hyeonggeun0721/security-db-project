"""
nvd_watch.py - (선택 심화) 주요 기술 키워드로 NVD 키워드 검색 API를 호출해
               최근 7일 내 발행된 CVE 를 nvd_watch_candidates 에 "후보"로만 적재한다.
               vulnerabilities 로 자동 병합하지 않는다 (분석가 검토 큐).

사전 준비: nvd_integration.sql 실행 완료
API 키:   NVD_API_KEY 있으면 0.6s, 없으면 6s 대기 (nvd_sync.py 와 동일 분기)

실행:
    python3 nvd_watch.py
    python3 nvd_watch.py --days 14        # 조회 기간 조정(기본 7일, NVD 최대 120일)
"""

import os
import sys
import time
import argparse
import datetime as dt

import requests
import psycopg2
from psycopg2.extras import execute_values

DB_NAME = os.environ.get("PGDATABASE", "security_db")   # 자격증명은 PGPASSWORD/PGUSER 환경변수나 ~/.pgpass 사용
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

API_KEY = os.environ.get("NVD_API_KEY", "").strip()
SLEEP_SEC = 0.6 if API_KEY else 6.0
HEADERS = {"apiKey": API_KEY} if API_KEY else {}
REQUEST_TIMEOUT = 40

# assets / vulnerabilities 에서 실제로 쓰이는 스택 기준 키워드.
# (운영에서는 assets.asset_type / vulnerabilities.description 파싱으로 자동 생성 가능)
KEYWORDS = ["OpenSSL", "Apache HTTP Server", "nginx", "PostgreSQL", "OpenSSH", "Log4j", "TLS"]


def pick_metric(cve: dict):
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            entry = metrics[key][0]
            data = entry.get("cvssData", {})
            return (data.get("baseScore"), data.get("baseSeverity") or entry.get("baseSeverity"))
    return (None, None)


def parse_iso(s):
    if not s:
        return None
    try:
        return dt.datetime.fromisoformat(s).replace(tzinfo=dt.timezone.utc)
    except ValueError:
        return None


def search_keyword(keyword: str, start: dt.datetime, end: dt.datetime):
    params = {
        "keywordSearch": keyword,
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": 2000,
    }
    for attempt in range(1, 5):
        try:
            r = requests.get(NVD_URL, params=params, headers=HEADERS, timeout=REQUEST_TIMEOUT)
        except requests.RequestException as e:
            print(f"    ! 요청 예외({attempt}/4): {e}")
            time.sleep(SLEEP_SEC * attempt)
            continue
        if r.status_code == 200:
            data = r.json()
            return data.get("totalResults", 0), data.get("vulnerabilities", [])
        if r.status_code in (403, 429):
            wait = SLEEP_SEC * (attempt + 1) + 5
            print(f"    ! 레이트리밋({r.status_code}) - {wait:.0f}s 대기")
            time.sleep(wait)
            continue
        print(f"    ! HTTP {r.status_code}: {r.text[:160]}")
        return 0, []
    return 0, []


UPSERT_SQL = """
INSERT INTO nvd_watch_candidates
    (cve_id, matched_keywords, nvd_cvss_score, nvd_severity, nvd_description,
     nvd_published_date, nvd_reference_urls, already_in_vulnerabilities, synced_at)
VALUES %s
ON CONFLICT (cve_id) DO UPDATE SET
    matched_keywords          = (
        SELECT array_agg(DISTINCT k)
        FROM unnest(nvd_watch_candidates.matched_keywords || EXCLUDED.matched_keywords) AS k
    ),
    nvd_cvss_score            = EXCLUDED.nvd_cvss_score,
    nvd_severity              = EXCLUDED.nvd_severity,
    nvd_description           = EXCLUDED.nvd_description,
    nvd_published_date        = EXCLUDED.nvd_published_date,
    nvd_reference_urls        = EXCLUDED.nvd_reference_urls,
    already_in_vulnerabilities= EXCLUDED.already_in_vulnerabilities,
    synced_at                 = EXCLUDED.synced_at;
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=7, help="조회 기간(일), 기본 7, NVD 최대 120")
    args = ap.parse_args()

    end = dt.datetime.now(dt.timezone.utc)
    start = end - dt.timedelta(days=min(max(args.days, 1), 120))
    print(f"NVD API 키: {'사용 (0.6s)' if API_KEY else '미사용 (6s)'}")
    print(f"조회 구간: {start:%Y-%m-%d} ~ {end:%Y-%m-%d} ({args.days}일)")
    print(f"키워드 {len(KEYWORDS)}개: {', '.join(KEYWORDS)}\n")

    conn = psycopg2.connect(dbname=DB_NAME)
    cur = conn.cursor()
    cur.execute("SELECT cve_id FROM vulnerabilities WHERE cve_id IS NOT NULL")
    known = {row[0] for row in cur.fetchall()}

    merged = {}   # cve_id -> dict
    for i, kw in enumerate(KEYWORDS, 1):
        print(f"[{i}/{len(KEYWORDS)}] '{kw}' ...", end=" ", flush=True)
        total, vulns = search_keyword(kw, start, end)
        print(f"NVD totalResults={total}, 수신={len(vulns)}")
        for item in vulns:
            cve = item.get("cve", {})
            cid = cve.get("id")
            if not cid:
                continue
            score, severity = pick_metric(cve)
            descs = cve.get("descriptions", [])
            en = next((d["value"] for d in descs if d.get("lang") == "en"), None)
            refs = [ref["url"] for ref in cve.get("references", [])]
            if cid not in merged:
                merged[cid] = {
                    "keywords": set(), "score": score, "severity": severity,
                    "desc": en, "pub": parse_iso(cve.get("published")), "refs": refs,
                }
            merged[cid]["keywords"].add(kw)
        if i < len(KEYWORDS):
            time.sleep(SLEEP_SEC)

    rows = [
        (cid, sorted(d["keywords"]), d["score"], d["severity"], d["desc"],
         d["pub"], d["refs"], cid in known, end)
        for cid, d in merged.items()
    ]

    if rows:
        execute_values(cur, UPSERT_SQL, rows)
    conn.commit()

    cur.execute("SELECT count(*), count(*) FILTER (WHERE already_in_vulnerabilities) FROM nvd_watch_candidates")
    total_cand, already = cur.fetchone()
    cur.execute("""SELECT nvd_severity, count(*) FROM nvd_watch_candidates
                   GROUP BY nvd_severity ORDER BY count(*) DESC""")
    by_sev = cur.fetchall()
    sev_str = ", ".join("{}={}".format(s or "N/A", c) for s, c in by_sev)

    print("\n=== 워치 결과 ===")
    print(f"  이번 실행 신규/갱신 후보: {len(rows)}건")
    print(f"  nvd_watch_candidates 누적: {total_cand}건 (이미 vulnerabilities 에 있는 것: {already}건)")
    print(f"  심각도 분포: {sev_str}")

    cur.close()
    conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())

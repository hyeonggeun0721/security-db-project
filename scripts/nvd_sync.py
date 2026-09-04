"""
nvd_sync.py - NVD REST API 2.0 로 기존 vulnerabilities.cve_id 의 공식 상세를 가져와
             nvd_cve_details 테이블에 UPSERT 한다 (재실행 가능 / idempotent).

사전 준비:
    nvd_integration.sql 을 먼저 실행 (테이블/뷰 생성)
    pip install requests psycopg2-binary   (이미 설치돼 있으면 생략)

API 키:
    환경변수 NVD_API_KEY 가 있으면 헤더에 실어 보내고 요청 간 0.6초 대기,
    없으면 6초 대기 (NVD 권장 레이트리밋).
        export NVD_API_KEY=xxxxxxxx-xxxx-...   # https://nvd.nist.gov/developers/request-an-api-key

실행:
    python3 nvd_sync.py
"""

import os
import sys
import time
import datetime as dt

import requests
import psycopg2
from psycopg2.extras import execute_values

DB_NAME = os.environ.get("PGDATABASE", "security_db")   # ETL: 로컬 trust 로 소유자 접속(읽기/쓰기).
# 운영 시엔 비밀번호를 코드에 넣지 말고 PGPASSWORD/PGUSER/PGHOST 환경변수나 ~/.pgpass(chmod 600) 사용.
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

API_KEY = os.environ.get("NVD_API_KEY", "").strip()
SLEEP_SEC = 0.6 if API_KEY else 6.0
HEADERS = {"apiKey": API_KEY} if API_KEY else {}
REQUEST_TIMEOUT = 40


def pick_metric(cve: dict):
    """metrics 에서 CVSS v3.1 -> v3.0 -> v2.0 순으로 basescore/severity/vector 추출."""
    metrics = cve.get("metrics", {})
    for key, version in (("cvssMetricV31", "3.1"),
                         ("cvssMetricV30", "3.0"),
                         ("cvssMetricV2", "2.0")):
        if metrics.get(key):
            entry = metrics[key][0]
            data = entry.get("cvssData", {})
            severity = data.get("baseSeverity") or entry.get("baseSeverity")  # v2 는 entry 쪽에 있음
            return (data.get("baseScore"), severity, version, data.get("vectorString"))
    return (None, None, None, None)


def parse_iso(s):
    if not s:
        return None
    # NVD 는 타임존 없는 UTC ISO ("2021-12-10T10:15:09.143") 로 준다
    try:
        return dt.datetime.fromisoformat(s).replace(tzinfo=dt.timezone.utc)
    except ValueError:
        return None


def fetch_cve(cve_id: str):
    """단일 CVE 조회. (status, dict|None) 반환. 429/403 은 백오프 재시도."""
    for attempt in range(1, 5):
        try:
            r = requests.get(NVD_URL, params={"cveId": cve_id},
                             headers=HEADERS, timeout=REQUEST_TIMEOUT)
        except requests.RequestException as e:
            print(f"    ! 요청 예외({attempt}/4): {e}")
            time.sleep(SLEEP_SEC * attempt)
            continue

        if r.status_code == 200:
            data = r.json()
            if data.get("totalResults", 0) == 0 or not data.get("vulnerabilities"):
                return ("NOT_FOUND", None)
            return ("SYNCED", data["vulnerabilities"][0]["cve"])

        if r.status_code in (403, 429):
            wait = SLEEP_SEC * (attempt + 1) + 5
            print(f"    ! 레이트리밋({r.status_code}) - {wait:.0f}s 대기 후 재시도")
            time.sleep(wait)
            continue

        print(f"    ! HTTP {r.status_code}: {r.text[:160]}")
        return ("ERROR", None)

    return ("ERROR", None)


UPSERT_SQL = """
INSERT INTO nvd_cve_details
    (cve_id, nvd_cvss_score, nvd_severity, nvd_cvss_version, nvd_vector_string,
     nvd_description, nvd_published_date, nvd_last_modified, nvd_reference_urls,
     nvd_status, synced_at)
VALUES %s
ON CONFLICT (cve_id) DO UPDATE SET
    nvd_cvss_score     = EXCLUDED.nvd_cvss_score,
    nvd_severity       = EXCLUDED.nvd_severity,
    nvd_cvss_version   = EXCLUDED.nvd_cvss_version,
    nvd_vector_string  = EXCLUDED.nvd_vector_string,
    nvd_description    = EXCLUDED.nvd_description,
    nvd_published_date = EXCLUDED.nvd_published_date,
    nvd_last_modified  = EXCLUDED.nvd_last_modified,
    nvd_reference_urls = EXCLUDED.nvd_reference_urls,
    nvd_status         = EXCLUDED.nvd_status,
    synced_at          = EXCLUDED.synced_at;
"""


def main():
    print(f"NVD API 키: {'사용 (요청 간 0.6s)' if API_KEY else '미사용 (요청 간 6s)'}")

    conn = psycopg2.connect(dbname=DB_NAME)
    conn.autocommit = False
    cur = conn.cursor()

    cur.execute("SELECT cve_id FROM vulnerabilities WHERE cve_id IS NOT NULL ORDER BY cve_id")
    cve_ids = [row[0] for row in cur.fetchall()]
    print(f"대상 CVE {len(cve_ids)}건: {', '.join(cve_ids)}\n")

    rows = []
    counts = {"SYNCED": 0, "NOT_FOUND": 0, "ERROR": 0}
    now = dt.datetime.now(dt.timezone.utc)

    for i, cve_id in enumerate(cve_ids, 1):
        print(f"[{i}/{len(cve_ids)}] {cve_id} ...", end=" ", flush=True)
        status, cve = fetch_cve(cve_id)
        counts[status] += 1

        if status == "SYNCED":
            score, severity, version, vector = pick_metric(cve)
            descs = cve.get("descriptions", [])
            en_desc = next((d["value"] for d in descs if d.get("lang") == "en"), None)
            refs = [ref["url"] for ref in cve.get("references", [])]
            rows.append((
                cve_id, score, severity, version, vector,
                en_desc, parse_iso(cve.get("published")), parse_iso(cve.get("lastModified")),
                refs, "SYNCED", now,
            ))
            print(f"OK  cvss={score} severity={severity} (v{version}) refs={len(refs)}")
        else:
            rows.append((cve_id, None, None, None, None, None, None, None, None, status, now))
            print(status)

        if i < len(cve_ids):
            time.sleep(SLEEP_SEC)

    execute_values(cur, UPSERT_SQL, rows)
    conn.commit()

    # 결과 요약
    cur.execute("""
        SELECT count(*) FILTER (WHERE nvd_status='SYNCED'),
               count(*) FILTER (WHERE nvd_status='NOT_FOUND'),
               count(*) FILTER (WHERE nvd_status='ERROR'),
               max(synced_at)
        FROM nvd_cve_details
    """)
    s, nf, err, last = cur.fetchone()
    cur.execute("SELECT count(*) FROM vw_cvss_nvd_mismatch")
    mismatch = cur.fetchone()[0]

    print("\n=== 동기화 결과 ===")
    print(f"  이번 실행: SYNCED={counts['SYNCED']}  NOT_FOUND={counts['NOT_FOUND']}  ERROR={counts['ERROR']}")
    print(f"  nvd_cve_details 누적: SYNCED={s}  NOT_FOUND={nf}  ERROR={err}  (synced_at={last})")
    print(f"  vw_cvss_nvd_mismatch 불일치 건수: {mismatch}")

    cur.close()
    conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())

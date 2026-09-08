#!/usr/bin/env python3
"""
backfill_event_descriptions.py — 원본(큐레이션) security_events description 채우기/다양화

■ 배경
  security_events.description 컬럼은 V029 에서 뒤늦게 추가됐다. 그 전에 수기로 넣은
  큐레이션 이벤트(event_id 1~30)는 description 이 NULL 로 남았고, 이후 벡터 임베딩
  (V033, event_threat_linker.py)의 대상에서 통째로 빠져 있었다.

■ 두 가지 모드
  (기본) 백필  : description IS NULL 인 이벤트를 실데이터만으로 한 줄 요약해 UPDATE.
                 UPDATE 는 WHERE description IS NULL 로 한정 → 멱등.
  --rewrite    : 이미 채워진 큐레이션 이벤트(event_id 1~30, non-SIM)의 description 을
                 다시 생성해 UPDATE(WHERE event_id = %s 로 명시 지정). 2026-09-08 도입.
                 이유: 1차 백필은 (event_type, asset, CVE) 조합이 같으면 문장이
                 바이트 단위로 동일해져, PAST_EVENT 매칭에 유사도 정확히 1.000 이
                 26건 생겼다. 이 모드는 문장 끝에 그 이벤트의 실제 status + 첫
                 responses.action_taken 요지(둘 다 실데이터)를 한 조각 덧붙여
                 같은 조합이어도 문장이 갈라지게 한다.

■ 공통 원칙 (두 모드 모두)
  - 새로운 사실을 지어내지 않는다. 문장의 모든 명사는 아래 컬럼에서만 온다:
      assets.asset_name / vulnerabilities.cve_id·description(vuln_id 있을 때) /
      severity / event_type / status / detected_at / responses.action_taken
  - '[SIM] ' 접두사를 붙이지 않는다 → 합성 이벤트와 구분 유지.

■ 사용법
  python scripts/backfill_event_descriptions.py                 # 백필 미리보기
  python scripts/backfill_event_descriptions.py --apply         # 백필 반영
  python scripts/backfill_event_descriptions.py --rewrite       # 재작성 미리보기
  python scripts/backfill_event_descriptions.py --rewrite --apply  # 재작성 반영

  환경변수 PGDATABASE(기본 security_db). 로컬 trust 인증.
  UPDATE 는 감사 트리거(trg_audit_security_events)를 정상적으로 발동시킨다.
  반영 후  SELECT * FROM fn_verify_audit_chain()  로 breaks=0 을 확인할 것.
"""
import argparse
import os

import psycopg2
import psycopg2.extras

DB_NAME = os.environ.get("PGDATABASE", "security_db")

SEV_KO = {"CRITICAL": "심각", "HIGH": "높음", "MEDIUM": "중간", "LOW": "낮음"}
STATUS_KO = {"OPEN": "미대응 상태", "IN_PROGRESS": "대응 진행 중", "RESOLVED": "대응 완료"}


# vulnerabilities.description 은 대부분 "... 취약점" 으로 끝난다. 뒤에서 다시 "취약점"
# 을 붙이면 중복되므로, 표기용으로 끝의 "취약점" 만 떼어낸다(의미는 유지).
def _vshort(vdesc: str) -> str:
    v = (vdesc or "").strip()
    if v.endswith("취약점"):
        v = v[: -len("취약점")].rstrip()
    return v


def _action_gist(action_taken: str) -> str:
    """responses.action_taken 의 첫 구절(쉼표/세미콜론/괄호 전)만 추려 요지로 쓴다."""
    a = (action_taken or "").strip()
    if not a:
        return ""
    for sep in (", ", "; ", " ("):
        idx = a.find(sep)
        if idx > 0:
            a = a[:idx]
            break
    return a.strip().rstrip(".")


def _status_tail(status: str, action_taken: str) -> str:
    """status(+대응 요지) 를 문장 끝에 붙일 짧은 실데이터 조각으로 만든다.

    같은 (event_type, asset, CVE) 여도 이 조각이 달라 문장이 갈라진다.
    """
    label = STATUS_KO.get(status, status)
    gist = _action_gist(action_taken)
    if gist:
        return f"{label}(대응 요지: {gist})"
    return label


def build_body(row) -> str:
    """row 의 실데이터로 본문(핵심 한 줄) 생성. status 조각은 붙이지 않는다."""
    et = row["event_type"]
    asset = row["asset_name"]
    sev_k = SEV_KO.get(row["severity"], row["severity"])
    cve = row["cve_id"]
    vdesc = _vshort(row["vuln_desc"])
    finding = row["finding_ref"]

    if cve:
        v = f"{cve}({vdesc})" if vdesc else cve
        table = {
            "침입시도":       f"{asset} 대상 {v} 취약점 익스플로잇을 노린 외부 침입 시도 탐지",
            "비정상접근":     f"{asset}에 대한 비정상 접근 시도 탐지, {v} 취약점과 연관",
            "권한상승시도":   f"{asset}에서 {v} 취약점 악용으로 권한 상승 시도 정황 포착",
            "악성코드탐지":   f"{asset}에서 악성코드 활동 탐지, {v} 취약점 악용과 연관",
            "웹취약점스캔":   f"{asset} 대상 웹 취약점 스캐닝 탐지, {v} 탐지 시도 포함",
            "무차별대입시도": f"{asset}에 대한 자격증명 무차별 대입 시도, {v} 취약점과 연관",
            "피싱메일보고":   f"{asset} 사용자의 피싱 메일 신고 접수, {v} 악용 가능성 확인",
            "정책위반":       f"{asset}에서 보안 정책 위반 행위 탐지, {v} 관련 설정 미흡",
            "로그위변조시도": f"{asset}의 감사 로그 위·변조 시도 탐지, {v} 취약점과 연관",
            "데이터유출시도": f"{asset}에서 외부로의 데이터 유출 시도 정황, {v} 악용 연계",
            "스팸대량수신":   f"{asset}에서 대량 스팸·피싱 메일 수신, {v} 연관",
        }
        return table.get(et) or f"{asset}에서 '{et}' 유형 보안 이벤트 탐지, {v} 취약점과 연관"

    if finding:  # SCAN 유래(현재 큐레이션 셋엔 없지만 방어적으로)
        table = {
            "정책위반": f"{asset}에서 보안 정책 위반 탐지, 설정 점검 항목 {finding} 위반",
        }
        return table.get(et) or f"{asset}에서 '{et}' 유형 이벤트 탐지, 설정 점검 {finding} 관련"

    # vuln 연결 없음: event_type + 자산명 + severity 로 작성
    table = {
        "악성코드탐지":   f"{asset}에서 악성코드 의심 활동 탐지 및 격리 (심각도 {sev_k})",
        "비정상접근":     f"{asset}에 대한 비정상 접근 시도 탐지 (심각도 {sev_k})",
        "스팸대량수신":   f"{asset}에서 대량 스팸·피싱 메일 수신, 게이트웨이에서 격리 (심각도 {sev_k})",
        "침입시도":       f"{asset} 대상 외부 침입 시도 탐지 (심각도 {sev_k})",
        "권한상승시도":   f"{asset}에서 권한 상승 시도 정황 포착 (심각도 {sev_k})",
        "무차별대입시도": f"{asset}에 대한 자격증명 무차별 대입 시도 (심각도 {sev_k})",
        "피싱메일보고":   f"{asset} 사용자의 피싱 메일 신고 접수 (심각도 {sev_k})",
        "웹취약점스캔":   f"{asset} 대상 웹 취약점 스캐닝 트래픽 탐지 (심각도 {sev_k})",
        "정책위반":       f"{asset}에서 보안 정책 위반 행위 탐지 (심각도 {sev_k})",
        "로그위변조시도": f"{asset}의 감사 로그 위·변조 시도 탐지 (심각도 {sev_k})",
        "데이터유출시도": f"{asset}에서 외부로의 데이터 유출 시도 정황 (심각도 {sev_k})",
    }
    return table.get(et) or f"{asset}에서 '{et}' 유형 보안 이벤트 탐지 (심각도 {sev_k})"


def build_description(row, *, with_status_tail: bool) -> str:
    """본문 + (재작성 모드일 때) 실데이터 status 조각."""
    body = build_body(row)
    if not with_status_tail:
        return body
    return f"{body}; {_status_tail(row['status'], row['action_taken'])}"


QUERY_TMPL = """
    SELECT e.event_id, e.event_type, e.severity, e.status,
           e.detected_at::date AS d,
           a.asset_name, a.asset_type,
           v.cve_id,
           v.description AS vuln_desc,
           v.finding_ref,
           r.action_taken
    FROM security_events e
    JOIN assets a          ON a.asset_id = e.asset_id
    LEFT JOIN vulnerabilities v ON v.vuln_id = e.vuln_id
    LEFT JOIN LATERAL (
        SELECT action_taken
        FROM responses
        WHERE event_id = e.event_id
        ORDER BY action_date
        LIMIT 1
    ) r ON true
    WHERE {where}
    ORDER BY e.event_id
"""

# 재작성 대상: 1차 백필로 채워진 원본 큐레이션 이벤트만. V034 신규(77~88)와 SIM 은 건드리지 않음.
REWRITE_WHERE = "e.event_id BETWEEN 1 AND 30 AND coalesce(e.description,'') NOT LIKE '[SIM]%'"
BACKFILL_WHERE = "e.description IS NULL"


def main():
    ap = argparse.ArgumentParser(description="원본 security_events description 채우기/다양화")
    ap.add_argument("--apply", action="store_true", help="실제 UPDATE + 커밋 (미지정 시 미리보기만)")
    ap.add_argument("--rewrite", action="store_true",
                    help="이미 채워진 큐레이션 이벤트(1~30)의 description 을 status 조각 포함해 재작성")
    ap.add_argument("--limit", type=int, default=None, help="미리보기 건수 제한")
    ap.add_argument("--database", default=DB_NAME)
    a = ap.parse_args()

    mode = "재작성(rewrite)" if a.rewrite else "백필(NULL)"
    where = REWRITE_WHERE if a.rewrite else BACKFILL_WHERE

    conn = psycopg2.connect(dbname=a.database)
    conn.autocommit = False
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(QUERY_TMPL.format(where=where))
            rows = cur.fetchall()

        if not rows:
            print(f"[{mode}] 대상 이벤트가 없습니다.")
            return

        print(f"DB={a.database}  모드={mode}  대상 {len(rows)}건\n")
        shown = rows if a.limit is None else rows[: a.limit]
        for r in shown:
            new_desc = build_description(r, with_status_tail=a.rewrite)
            vtag = r["cve_id"] or r["finding_ref"] or "(vuln 없음)"
            print(f"  event #{r['event_id']:<3} {r['d']}  {r['severity']:<8} {r['status']:<11} "
                  f"{r['event_type']:<12} {r['asset_name']} / {vtag}")
            print(f"     → {new_desc}")
        if a.limit is not None and len(rows) > a.limit:
            print(f"  ... 외 {len(rows) - a.limit}건 (미리보기 생략)")

        if not a.apply:
            print("\n(미리보기) 실제 반영하려면 --apply 를 붙이세요.")
            return

        n = 0
        with conn.cursor() as cur:
            for r in rows:
                new_desc = build_description(r, with_status_tail=a.rewrite)
                if a.rewrite:
                    cur.execute(
                        "UPDATE security_events SET description = %s WHERE event_id = %s",
                        (new_desc, r["event_id"]),
                    )
                else:
                    cur.execute(
                        "UPDATE security_events SET description = %s "
                        "WHERE event_id = %s AND description IS NULL",
                        (new_desc, r["event_id"]),
                    )
                n += cur.rowcount
        conn.commit()
        guard = "event_id 명시 지정" if a.rewrite else "WHERE description IS NULL 한정"
        print(f"\n✔ 커밋 완료: security_events.description {n}건 갱신 ({guard}, [SIM] 접두사 없음).")
        print("  이어서: python scripts/event_threat_linker.py   (임베딩+매칭)")
        print("  확인:   SELECT count(*) FROM fn_verify_audit_chain();  -- breaks=0 이어야 정상")
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


if __name__ == "__main__":
    main()

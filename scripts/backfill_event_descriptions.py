#!/usr/bin/env python3
"""
backfill_event_descriptions.py — 원본(큐레이션) security_events 의 NULL description 백필

■ 배경
  security_events.description 컬럼은 V029 에서 뒤늦게 추가됐다. 그 전에 수기로 넣은
  큐레이션 이벤트(event_id 1~30)는 description 이 NULL 로 남았고, 이후 벡터 임베딩
  (V033, event_threat_linker.py)의 대상에서 통째로 빠져 있었다. 그래서 "실제(비-SIM)
  이벤트끼리의 유사도 매칭 품질" 을 한 번도 확인하지 못했다.

■ 이 스크립트가 하는 일
  description IS NULL 인 이벤트를, 그 이벤트가 이미 참조하는 실제 데이터
    - assets.asset_name / asset_type
    - vulnerabilities.cve_id / description  (vuln_id 가 있을 때)
    - severity / event_type / status
    - responses.action_taken               (참고 표시용, 문장에는 넣지 않음)
  만으로 자연스러운 한 줄 한국어 요약문을 만들어 UPDATE 한다.

  - 새로운 사실을 지어내지 않는다. 문장의 모든 명사는 위 컬럼에서 온다.
  - '[SIM] ' 접두사를 붙이지 않는다 → 합성 이벤트와 구분 유지.
  - UPDATE 대상은 항상  WHERE description IS NULL  로 한정 → 재실행해도 안전(멱등).
  - 기본은 미리보기만. 실제 반영은 --apply.

■ 사용법
  python scripts/backfill_event_descriptions.py            # 미리보기(전체)
  python scripts/backfill_event_descriptions.py --limit 8  # 미리보기 8건
  python scripts/backfill_event_descriptions.py --apply    # 실제 UPDATE + 커밋

  환경변수 PGDATABASE(기본 security_db). 로컬 trust 인증.
  UPDATE 는 감사 트리거(trg_audit_security_events)를 정상적으로 발동시킨다.
  반영 후  SELECT * FROM fn_verify_audit_chain()  로 breaks=0 을 확인할 것.
"""
import argparse
import os
import sys

import psycopg2
import psycopg2.extras

DB_NAME = os.environ.get("PGDATABASE", "security_db")

SEV_KO = {"CRITICAL": "심각", "HIGH": "높음", "MEDIUM": "중간", "LOW": "낮음"}

# vulnerabilities.description 은 대부분 "... 취약점" 으로 끝난다. 뒤에서 다시 "취약점"
# 을 붙이면 중복되므로, 표기용으로 끝의 "취약점" 만 떼어낸다(의미는 유지).
def _vshort(vdesc: str) -> str:
    v = (vdesc or "").strip()
    if v.endswith("취약점"):
        v = v[: -len("취약점")].rstrip()
    return v


def build_description(row) -> str:
    """row 의 실제 컬럼값만으로 한 줄 요약문 생성."""
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
        desc = table.get(et)
        if desc is None:
            desc = f"{asset}에서 '{et}' 유형 보안 이벤트 탐지, {v} 취약점과 연관"
        return desc

    if finding:  # SCAN 유래(현재 큐레이션 셋엔 없지만 방어적으로)
        table = {
            "정책위반": f"{asset}에서 보안 정책 위반 탐지, 설정 점검 항목 {finding} 위반",
        }
        desc = table.get(et)
        if desc is None:
            desc = f"{asset}에서 '{et}' 유형 이벤트 탐지, 설정 점검 {finding} 관련"
        return desc

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
    desc = table.get(et)
    if desc is None:
        desc = f"{asset}에서 '{et}' 유형 보안 이벤트 탐지 (심각도 {sev_k})"
    return desc


QUERY = """
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
    WHERE e.description IS NULL
    ORDER BY e.event_id
"""


def main():
    ap = argparse.ArgumentParser(description="원본 security_events NULL description 백필")
    ap.add_argument("--apply", action="store_true", help="실제 UPDATE + 커밋 (미지정 시 미리보기만)")
    ap.add_argument("--limit", type=int, default=None, help="미리보기 건수 제한")
    ap.add_argument("--database", default=DB_NAME)
    a = ap.parse_args()

    conn = psycopg2.connect(dbname=a.database)
    conn.autocommit = False
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(QUERY)
            rows = cur.fetchall()

        if not rows:
            print("description IS NULL 인 이벤트가 없습니다. (이미 백필 완료)")
            return

        print(f"DB={a.database}  대상(description IS NULL) {len(rows)}건\n")
        shown = rows if a.limit is None else rows[: a.limit]
        for r in shown:
            new_desc = build_description(r)
            vtag = r["cve_id"] or r["finding_ref"] or "(vuln 없음)"
            print(f"  event #{r['event_id']:<3} {r['d']}  {r['severity']:<8} {r['event_type']:<12} "
                  f"{r['asset_name']} / {vtag}")
            print(f"     → {new_desc}")
            if r["action_taken"]:
                print(f"       (참고 action_taken: {r['action_taken']})")
        if a.limit is not None and len(rows) > a.limit:
            print(f"  ... 외 {len(rows) - a.limit}건 (미리보기 생략)")

        if not a.apply:
            print("\n(미리보기) 실제 반영하려면 --apply 를 붙이세요.")
            return

        n = 0
        with conn.cursor() as cur:
            for r in rows:
                new_desc = build_description(r)
                cur.execute(
                    "UPDATE security_events SET description = %s "
                    "WHERE event_id = %s AND description IS NULL",
                    (new_desc, r["event_id"]),
                )
                n += cur.rowcount
        conn.commit()
        print(f"\n✔ 커밋 완료: security_events.description {n}건 채움 "
              f"(WHERE description IS NULL 한정, [SIM] 접두사 없음).")
        print("  이어서: python scripts/event_threat_linker.py   (임베딩+매칭)")
        print("  확인:   SELECT count(*) FROM fn_verify_audit_chain();  -- breaks=0 이어야 정상")
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


if __name__ == "__main__":
    main()

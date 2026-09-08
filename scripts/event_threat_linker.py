"""
event_threat_linker.py — 신규 보안 이벤트(security_events.description)를
threat_reports(과거 위협 리포트) / 이미 임베딩된 다른 security_events(과거 유사 사건)와
자동으로 매칭해서 event_threat_matches 에 저장하는 스크립트.

배경: generate_embeddings.py + search_similar_reports.py 로 threat_reports 유사 검색은
이미 가능했지만, "검색어를 사람이 입력"해야만 동작했다. 이 스크립트는 그 파이프라인을
security_events 인입 흐름에 붙여서 "새 이벤트가 들어오면 자동으로 예전 사례를 찾아준다"를
만든다 (V033__event_threat_matching.sql 참고).

동작:
  1) security_events 중 description 은 있는데 embedding 이 아직 없는 행을 임베딩.
  2) embedding 이 있는 이벤트 중 아직 THREAT_REPORT 매칭을 시도하지 않은 이벤트 ->
     threat_reports 코사인 유사도 상위 TOP_K 중 MIN_SIMILARITY 이상만 저장.
  3) 같은 방식으로 아직 PAST_EVENT 매칭을 시도하지 않은 이벤트 -> 다른 security_events
     (자기 자신 제외) 중 유사도 상위 TOP_K 중 MIN_SIMILARITY 이상만 저장.
  재실행 안전: "아직 그 match_type 을 시도하지 않은 이벤트"만 대상으로 삼고(NOT EXISTS),
  거기에 더해 (event_id, match_type, 대상) UNIQUE 인덱스 + ON CONFLICT DO NOTHING 이중 방어.

사전 준비 (최초 1회, generate_embeddings.py 와 동일):
    pip install sentence-transformers psycopg2-binary --break-system-packages

실행:
    python3 event_threat_linker.py
    python3 event_threat_linker.py --dry-run   # 계산/출력만, DB 반영 없음
                                                 # (주의: dry-run 은 새 임베딩을 저장하지
                                                 #  않으므로, 그 이벤트에 대한 매칭 단계는
                                                 #  건너뛴다 - 이미 임베딩된 이벤트 기준으로만
                                                 #  매칭 미리보기가 됨)

launchd 로 정기 실행 권장 (com.security-db.threatlink.plist, 10분 주기 - synth 합성 이벤트
25분 주기보다 촘촘하게 잡아 새 이벤트를 놓치지 않도록).
"""
import argparse
import os

os.environ["USE_TF"] = "0"       # 아나콘다에 깔린 TensorFlow를 안 불러오게 막음
os.environ["USE_TORCH"] = "1"    # PyTorch 백엔드만 사용

from sentence_transformers import SentenceTransformer
import psycopg2

DB_NAME = os.environ.get("PGDATABASE", "security_db")   # 로컬 trust 인증이라 비밀번호 불필요.
MODEL_NAME = "jhgan/ko-sroberta-multitask"               # threat_reports.embedding 과 동일 모델(768차원).
# 2026-09-08 V035 에서 all-MiniLM-L6-v2(384차원)에서 교체 — 다국어 범용 모델이 한국어 보안
# 이벤트 문장을 주제가 맞는 threat_reports 와 정렬하지 못해(report 5 커버리지 공백) 한국어
# 특화 모델로 변경. 차원 384->768 이라 반드시 V035 적용 후 실행할 것.
TOP_K = 3
# V035(ko-sroberta) 분포 기준 재튜닝: 명백히 맞는 매칭은 >=0.60, 약한/무관 쌍은 0.60 미만에
# 몰린다(이전 MiniLM 0.45 는 무관 쌍이 0.45~0.53 이라 잡은 값). PROJECT_LOG 2026-09-08 V035 참고.
MIN_SIMILARITY = 0.60


def embed_pending_events(conn, model, dry_run):
    cur = conn.cursor()
    cur.execute("""
        SELECT event_id, description FROM security_events
        WHERE description IS NOT NULL AND embedding IS NULL
        ORDER BY event_id
    """)
    rows = cur.fetchall()
    if not rows:
        print("임베딩 대기 중인 이벤트 없음.")
        cur.close()
        return 0

    print(f"{len(rows)}건 이벤트 임베딩 생성 중...")
    for event_id, description in rows:
        vec = model.encode(description).tolist()
        if not dry_run:
            cur.execute(
                "UPDATE security_events SET embedding = %s::vector WHERE event_id = %s",
                (vec, event_id),
            )
        print(f"  - event_id={event_id} 임베딩 완료{' (dry-run, 미저장)' if dry_run else ''}")

    if not dry_run:
        conn.commit()
    cur.close()
    return len(rows)


def _insert_match(cur, event_id, match_type, matched_report_id, matched_event_id, similarity):
    cur.execute(
        """
        INSERT INTO event_threat_matches (event_id, match_type, matched_report_id, matched_event_id, similarity)
        VALUES (%s, %s, %s, %s, %s)
        ON CONFLICT (event_id, match_type, COALESCE(matched_report_id,-1), COALESCE(matched_event_id,-1))
        DO NOTHING
        """,
        (event_id, match_type, matched_report_id, matched_event_id, round(float(similarity), 4)),
    )
    return cur.rowcount


def link_threat_reports(conn, dry_run):
    cur = conn.cursor()
    # 합성([SIM]) 이벤트는 THREAT_REPORT 매칭 대상에서 제외한다. threat_reports 는
    # 사람이 큐레이션한 실제 위협 인텔리전스라, 템플릿으로 찍어낸 합성 이벤트가 여기에
    # 매칭되면 event_threat_matches 에 노이즈가 쌓인다(다른 스크립트들과 동일한
    # '[SIM]%' 제외 컨벤션). PAST_EVENT 매칭(link_past_events)은 합성/실이벤트 간
    # 패턴 유사도를 보는 용도라 이 제외를 적용하지 않는다.
    cur.execute("""
        SELECT e.event_id FROM security_events e
        WHERE e.embedding IS NOT NULL
          AND coalesce(e.description, '') NOT LIKE '[SIM]%'
          AND NOT EXISTS (
              SELECT 1 FROM event_threat_matches m
              WHERE m.event_id = e.event_id AND m.match_type = 'THREAT_REPORT'
          )
        ORDER BY e.event_id
    """)
    pending = [r[0] for r in cur.fetchall()]

    inserted = 0
    for event_id in pending:
        cur.execute(
            """
            SELECT report_id, title,
                   1 - (embedding <=> (SELECT embedding FROM security_events WHERE event_id = %s)) AS similarity
            FROM threat_reports
            WHERE embedding IS NOT NULL
            ORDER BY embedding <=> (SELECT embedding FROM security_events WHERE event_id = %s)
            LIMIT %s
            """,
            (event_id, event_id, TOP_K),
        )
        found_any = False
        for report_id, title, similarity in cur.fetchall():
            if similarity < MIN_SIMILARITY:
                continue
            found_any = True
            print(f"  [THREAT_REPORT] event_id={event_id} -> report_id={report_id} '{title}' sim={similarity:.3f}")
            if not dry_run:
                inserted += _insert_match(cur, event_id, "THREAT_REPORT", report_id, None, similarity)
        if not found_any:
            print(f"  [THREAT_REPORT] event_id={event_id} -> 임계값({MIN_SIMILARITY}) 이상 매칭 없음")

    if not dry_run:
        conn.commit()
    cur.close()
    return inserted


def link_past_events(conn, dry_run):
    cur = conn.cursor()
    cur.execute("""
        SELECT e.event_id FROM security_events e
        WHERE e.embedding IS NOT NULL
          AND NOT EXISTS (
              SELECT 1 FROM event_threat_matches m
              WHERE m.event_id = e.event_id AND m.match_type = 'PAST_EVENT'
          )
        ORDER BY e.event_id
    """)
    pending = [r[0] for r in cur.fetchall()]

    inserted = 0
    for event_id in pending:
        cur.execute(
            """
            SELECT e2.event_id,
                   1 - (e2.embedding <=> (SELECT embedding FROM security_events WHERE event_id = %s)) AS similarity
            FROM security_events e2
            WHERE e2.embedding IS NOT NULL AND e2.event_id <> %s
            ORDER BY e2.embedding <=> (SELECT embedding FROM security_events WHERE event_id = %s)
            LIMIT %s
            """,
            (event_id, event_id, event_id, TOP_K),
        )
        found_any = False
        for matched_event_id, similarity in cur.fetchall():
            if similarity < MIN_SIMILARITY:
                continue
            found_any = True
            print(f"  [PAST_EVENT]    event_id={event_id} -> event_id={matched_event_id} sim={similarity:.3f}")
            if not dry_run:
                inserted += _insert_match(cur, event_id, "PAST_EVENT", None, matched_event_id, similarity)
        if not found_any:
            print(f"  [PAST_EVENT]    event_id={event_id} -> 임계값({MIN_SIMILARITY}) 이상 매칭 없음")

    if not dry_run:
        conn.commit()
    cur.close()
    return inserted


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dry-run", action="store_true", help="DB 반영 없이 임베딩/매칭 결과만 출력")
    args = ap.parse_args()

    conn = psycopg2.connect(dbname=DB_NAME)

    print("임베딩 모델 로딩 중... (최초 1회는 모델 다운로드로 몇 분 걸릴 수 있음)")
    model = SentenceTransformer(MODEL_NAME)

    n_embedded = embed_pending_events(conn, model, args.dry_run)
    n_report_matches = link_threat_reports(conn, args.dry_run)
    n_event_matches = link_past_events(conn, args.dry_run)

    print(
        f"\n완료: 신규 임베딩 {n_embedded}건 · THREAT_REPORT 매칭 {n_report_matches}건 · "
        f"PAST_EVENT 매칭 {n_event_matches}건"
        + (" (dry-run, 실제 DB 반영 없음)" if args.dry_run else ".")
    )

    conn.close()


if __name__ == "__main__":
    main()

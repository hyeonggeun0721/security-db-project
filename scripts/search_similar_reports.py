"""
자유 텍스트(현재 발생한 이벤트 설명)를 입력하면,
threat_reports 중 의미론적으로 가장 유사한 과거 사례 Top-K를 보여주는 스크립트.

실행:
    python3 search_similar_reports.py "DB 접근제어를 우회하려는 시도가 발견됨"
"""

import sys
import os
os.environ["USE_TF"] = "0"       # 아나콘다에 깔린 TensorFlow를 안 불러오게 막음
os.environ["USE_TORCH"] = "1"    # PyTorch 백엔드만 사용

from sentence_transformers import SentenceTransformer
import psycopg2

DB_NAME = os.environ.get("PGDATABASE", "security_db")   # 자격증명은 PGPASSWORD/PGUSER 환경변수나 ~/.pgpass 사용
TOP_K = 5

def main():
    if len(sys.argv) < 2:
        print('사용법: python3 search_similar_reports.py "검색할 이벤트 설명"')
        sys.exit(1)

    query_text = sys.argv[1]

    # 2026-09-08 V035 에서 all-MiniLM-L6-v2(384차원)에서 교체 (한국어 특화, 768차원).
    # threat_reports.embedding 이 새 모델로 채워져 있으므로 검색도 같은 모델을 써야 한다.
    model = SentenceTransformer("jhgan/ko-sroberta-multitask")
    query_vec = model.encode(query_text).tolist()

    conn = psycopg2.connect(dbname=DB_NAME)
    cur = conn.cursor()
    cur.execute(
        """
        SELECT report_id, title, 1 - (embedding <=> %s::vector) AS similarity
        FROM threat_reports
        WHERE embedding IS NOT NULL
        ORDER BY embedding <=> %s::vector
        LIMIT %s
        """,
        (query_vec, query_vec, TOP_K),
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()

    print(f'\n검색어: "{query_text}"')
    print(f"가장 유사한 과거 사례 Top {TOP_K}:\n")
    for report_id, title, similarity in rows:
        print(f"  [{similarity:.3f}] (report_id={report_id}) {title}")

if __name__ == "__main__":
    main()

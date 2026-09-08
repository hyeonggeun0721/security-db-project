"""
threat_reports 테이블의 content(원문 텍스트)를 임베딩해서
embedding 컬럼을 채우는 스크립트.

사전 준비 (터미널에서 한 번만):
    pip install sentence-transformers psycopg2-binary

실행:
    python3 generate_embeddings.py
"""

import os
os.environ["USE_TF"] = "0"       # 아나콘다에 깔린 TensorFlow를 안 불러오게 막음
os.environ["USE_TORCH"] = "1"    # PyTorch 백엔드만 사용

from sentence_transformers import SentenceTransformer
import psycopg2

DB_NAME = os.environ.get("PGDATABASE", "security_db")   # 로컬 trust 인증이라 비밀번호 불필요.
# 운영(비밀번호 인증) 시엔 코드에 넣지 말고 PGPASSWORD/PGUSER/PGHOST 환경변수나 ~/.pgpass(chmod 600) 사용.

def main():
    print("임베딩 모델 로딩 중... (최초 1회는 모델 다운로드로 몇 분 걸릴 수 있음)")
    # 2026-09-08 V035 에서 all-MiniLM-L6-v2(384차원)에서 교체 — 한국어 특화 모델로
    # 바꿔야 threat_reports ↔ security_events 문장이 주제 기준으로 정렬된다.
    model = SentenceTransformer("jhgan/ko-sroberta-multitask")  # 768차원

    conn = psycopg2.connect(dbname=DB_NAME)
    cur = conn.cursor()

    cur.execute("SELECT report_id, content FROM threat_reports WHERE embedding IS NULL")
    rows = cur.fetchall()

    if not rows:
        print("임베딩이 비어있는 행이 없습니다. 이미 다 채워져 있거나 threat_reports가 비어있습니다.")
        return

    print(f"{len(rows)}개 보고서 임베딩 생성 중...")
    for report_id, content in rows:
        vec = model.encode(content).tolist()
        cur.execute(
            "UPDATE threat_reports SET embedding = %s WHERE report_id = %s",
            (vec, report_id),
        )
        print(f"  - report_id={report_id} 완료")

    conn.commit()
    cur.close()
    conn.close()
    print("모든 임베딩 저장 완료.")

if __name__ == "__main__":
    main()

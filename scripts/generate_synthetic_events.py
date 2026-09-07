#!/usr/bin/env python3
"""
generate_synthetic_events.py — 합성(시뮬레이션) 보안 이벤트 생성기

■ 목적
  실제 회사 SOC 로그는 구할 수 없으므로, 현실적인 패턴을 흉내낸 "합성" 보안 이벤트를
  주기적으로 security_events 에 넣어 SOC 대시보드가 계속 살아있는 것처럼 보이게 한다.

■ 실제 사건과의 구분 (중요)
  모든 합성 데이터는 security_events.description / responses.action_taken 이
  '[SIM] ' 접두사로 시작한다.
    - 교수님/검토자가 실제 사건과 헷갈리지 않게
    - 나중에  WHERE description LIKE '[SIM]%'  로 합성분만 골라 삭제/분석제외 가능
  게다가 접속 계정(svc_event_ingest)의 RLS 정책이
    WITH CHECK (description LIKE '[SIM]%')
  로 강제하므로, 이 스크립트(또는 이 계정)는 태그 없는 행을 물리적으로 넣을 수 없다.

■ DB 접속 계정 : svc_event_ingest  (V029 에서 신설)
  "실제 모니터링 도구가 붙는 서비스 계정" 성격의 최소 권한 계정.
    - security_events / responses 에 INSERT 만. 두 테이블 SELECT 불가(순수 피더).
    - event_types / assets / staff 는 참조용 SELECT 만 (assets.ip_address 는 제외)
    - 시퀀스 USAGE (event_id/response_id 를 nextval 로 미리 받아 RETURNING 없이 INSERT)
    - RLS: '[SIM]' 태그 없는 INSERT 는 거부 / CONNECTION LIMIT 3 / statement_timeout 15s
  → security_analyst 는 security_events INSERT 불가, security_admin 은 과권한이라
    전용 계정을 따로 둔다. RLS/RBAC 와 충돌 없음(V029 검증절에서 확인).

■ 사용법
  python scripts/generate_synthetic_events.py                # 1~3개(랜덤) 생성
  python scripts/generate_synthetic_events.py --count 5      # 5개 생성
  python scripts/generate_synthetic_events.py --dry-run      # INSERT 없이 미리보기만
  python scripts/generate_synthetic_events.py --count 3 --dry-run

  환경변수: PGDATABASE(기본 security_db). 로컬 trust 인증이라 비밀번호 불필요.
           운영에선 PGPASSWORD / ~/.pgpass 사용.

■ 볼륨
  기본 1~3개/실행. --count 는 50 으로 상한(학교 프로젝트 규모 유지).
"""
import argparse
import os
import random
import sys
from datetime import datetime, timedelta, timezone

import psycopg2

DB_NAME = os.environ.get("PGDATABASE", "security_db")
DB_USER = os.environ.get("SYNTH_DB_USER", "svc_event_ingest")
SIM = "[SIM] "
MAX_COUNT = 50

# 현실적 심각도 분포 (low/medium 높게, high/critical 낮게)
SEVERITY_CHOICES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
SEVERITY_WEIGHTS = [0.40, 0.35, 0.20, 0.05]

# 상태 분포: 대부분 OPEN(처리 필요), 일부는 자동 처리/진행중
STATUS_CHOICES = ["OPEN", "IN_PROGRESS", "RESOLVED"]
STATUS_WEIGHTS = [0.70, 0.15, 0.15]

# RFC 5737 문서화 전용(비라우팅) 대역 — 실제 IP 와 혼동 불가
DOC_IP_PREFIXES = ["192.0.2.", "198.51.100.", "203.0.113."]
FAKE_USERS = ["j.kim", "s.lee", "y.park", "guest01", "svc-batch", "unknown"]

# 이벤트 유형별 description 템플릿. event_types 는 DB 에서 동적 로드하고,
# 아래 딕셔너리에 없는(새로 추가된) 유형은 GENERIC 템플릿을 쓴다.
TEMPLATES = {
    "침입시도": [
        "방화벽에서 {ip} 발 포트 스캔 {n}회 탐지",
        "{ip} 에서 SSH 접속 시도 {n}건 연속 차단",
        "{asset} 경계 IPS 가 익스플로잇 시그니처 {n}건 탐지",
    ],
    "비정상접근": [
        "{asset} 에 업무시간 외 접근 (계정 {user})",
        "{ip} 에서 5분간 로그인 실패 {n}회 후 성공",
        "{user} 계정이 평소와 다른 지역대에서 인증",
    ],
    "권한상승시도": [
        "{asset} 에서 sudo 오용 시도 {n}회",
        "서비스 계정 {user} 가 관리자 그룹 편입 시도",
        "{asset} 에서 커널 취약점 익스플로잇 흔적",
    ],
    "악성코드탐지": [
        "{asset} EDR 이 의심 프로세스 격리 (sha256 {hash}...)",
        "{asset} 에서 알려진 악성 IOC 도메인 접속 시도",
        "{asset} 에 랜섬웨어 계열 행위 탐지, 자동 격리",
    ],
    "웹취약점스캔": [
        "{ip} 발 자동 취약점 스캐너 트래픽 {n}req/s",
        "{asset} 대상 SQLi 페이로드 {n}건 WAF 차단",
        "{asset} 관리자 페이지 대상 디렉터리 브루트포싱 {n}회",
    ],
    "스팸대량수신": [
        "동일 발신 도메인에서 스팸 {n}통 유입, 게이트웨이 격리",
        "피싱 의심 첨부(.html) {n}건 자동 격리",
    ],
    "무차별대입시도": [
        "{ip} 에서 자격증명 대입 {n}회 (대상 계정 {user})",
        "SMB 인증 실패 급증: 분당 {n}회, 소스 {ip}",
        "VPN 게이트웨이에 {n}개 계정 대상 패스워드 스프레이",
    ],
    "피싱메일보고": [
        "사용자 신고 피싱 메일 {n}건 (URL 호스트 {ip})",
        "{user} 가 사칭 메일 신고, 유사 메일 {n}건 회수",
    ],
    "정책위반": [
        "{asset} 에서 미승인 클라우드 스토리지로 {n}MB 업로드",
        "{user} 가 대용량 USB 반출 {n}MB 시도",
        "{asset} 에 미승인 원격제어 SW 설치 탐지",
    ],
    "로그위변조시도": [
        "{asset} 감사 로그 삭제 시도 탐지",
        "{asset} 의 원격 syslog 전송이 {n}분간 중단 후 재개",
    ],
    "데이터유출시도": [
        "{asset} 에서 외부로 비정상 아웃바운드 {n}MB",
        "DB 대량 SELECT({n}만 행) 직후 압축 파일 외부 전송",
        "{user} 계정이 단시간에 문서 {n}건 대량 다운로드",
    ],
}
GENERIC = [
    "{asset} 에서 '{etype}' 유형 이벤트 탐지 (지표값 {n})",
    "{ip} 관련 '{etype}' 활동이 관측됨",
]

RESPONSE_ACTIONS = [
    "1차 트리아지 완료: 소스 IP 차단 및 관련 계정 세션 종료",
    "EDR 격리 확인, 영향 자산 스냅샷 확보",
    "방화벽/WAF 룰 추가, 알림 임계치 상향",
    "담당 부서 통보 및 계정 임시 비활성화",
    "IOC 수집 후 위협 인텔 피드와 대조, 오탐 여부 확인 중",
    "로그 상세 분석 착수, 유출 정황 없음 잠정 판단",
]


def weighted(choices, weights):
    return random.choices(choices, weights=weights, k=1)[0]


def make_description(etype, asset_name):
    tpl = random.choice(TEMPLATES.get(etype, GENERIC))
    return SIM + tpl.format(
        ip=random.choice(DOC_IP_PREFIXES) + str(random.randint(2, 254)),
        n=random.choice([3, 5, 7, 8, 12, 15, 22, 35, 48, 120, 300]),
        asset=asset_name,
        user=random.choice(FAKE_USERS),
        hash="".join(random.choice("0123456789abcdef") for _ in range(10)),
        etype=etype,
    )


def build_batch(count, event_types, assets, staff):
    """DB 에 넣을 (event, optional response) 목록을 만든다. now() 기준."""
    now = datetime.now(timezone.utc)
    batch = []
    for _ in range(count):
        etype = random.choice(event_types)
        asset_id, asset_name = random.choice(assets)
        severity = weighted(SEVERITY_CHOICES, SEVERITY_WEIGHTS)
        status = weighted(STATUS_CHOICES, STATUS_WEIGHTS)
        detected_at = now - timedelta(seconds=random.randint(0, 300))
        desc = make_description(etype, asset_name)

        resp = None
        # RESOLVED/IN_PROGRESS 이벤트는 대응 이력 동반(≈30%). OPEN 은 미대응으로 남김.
        if status in ("RESOLVED", "IN_PROGRESS"):
            staff_id, staff_name = random.choice(staff)
            action_date = detected_at + timedelta(minutes=random.randint(5, 180))
            resp = {
                "staff_id": staff_id,
                "staff_name": staff_name,
                "action_taken": SIM + random.choice(RESPONSE_ACTIONS),
                "action_date": action_date,
                "status": "COMPLETED" if status == "RESOLVED" else "IN_PROGRESS",
            }
        batch.append({
            "asset_id": asset_id, "asset_name": asset_name, "event_type": etype,
            "severity": severity, "status": status, "detected_at": detected_at,
            "description": desc, "response": resp,
        })
    return batch


def _lt(dt):
    """tz-aware(UTC) -> 로컬 시각 문자열 (표시용). DB 에는 원래 tz-aware 값이 들어간다."""
    return dt.astimezone().strftime("%m-%d %H:%M:%S")


def print_preview(batch):
    for i, e in enumerate(batch, 1):
        print(f"  [{i}] {_lt(e['detected_at'])} {e['severity']:<8} {e['status']:<11} "
              f"asset#{e['asset_id']}({e['asset_name']}) / {e['event_type']}")
        print(f"      {e['description']}")
        if e["response"]:
            r = e["response"]
            print(f"      └ response by {r['staff_name']} @ {_lt(r['action_date'])} "
                  f"[{r['status']}] {r['action_taken']}")


def main():
    ap = argparse.ArgumentParser(description="합성 보안 이벤트 생성기")
    ap.add_argument("--count", type=int, default=None,
                    help=f"생성할 이벤트 수 (기본: 1~3 랜덤, 최대 {MAX_COUNT})")
    ap.add_argument("--dry-run", action="store_true", help="INSERT 없이 미리보기만")
    ap.add_argument("--database", default=DB_NAME)
    ap.add_argument("--user", default=DB_USER)
    a = ap.parse_args()

    count = a.count if a.count is not None else random.randint(1, 3)
    if count < 1:
        sys.exit("--count 는 1 이상이어야 합니다.")
    if count > MAX_COUNT:
        sys.exit(f"--count 는 최대 {MAX_COUNT} (학교 프로젝트 규모 유지). 요청: {count}")

    conn = psycopg2.connect(dbname=a.database, user=a.user)
    conn.autocommit = False
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT event_type_name FROM event_types WHERE is_active ORDER BY event_type_name")
            event_types = [r[0] for r in cur.fetchall()]
            cur.execute("SELECT asset_id, asset_name FROM assets ORDER BY asset_id")
            assets = cur.fetchall()
            cur.execute("SELECT staff_id, staff_name FROM staff ORDER BY staff_id")
            staff = cur.fetchall()

        if not event_types or not assets or not staff:
            sys.exit("event_types / assets / staff 중 비어있는 참조 테이블이 있습니다.")

        batch = build_batch(count, event_types, assets, staff)

        print(f"DB={a.database}  role={a.user}  대상 이벤트 {count}개  "
              f"(활성 유형 {len(event_types)}종, 자산 {len(assets)}개)")
        print(f"{'미리보기 (--dry-run, INSERT 안 함)' if a.dry_run else '생성 내용'}:")
        print_preview(batch)

        if a.dry_run:
            print("\n(dry-run) 실제 INSERT 는 수행하지 않았습니다.")
            return

        n_evt = n_resp = 0
        with conn.cursor() as cur:
            for e in batch:
                cur.execute("SELECT nextval('security_events_event_id_seq')")
                eid = cur.fetchone()[0]
                cur.execute(
                    "INSERT INTO security_events "
                    "(event_id, asset_id, event_type, severity, detected_at, status, description) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s)",
                    (eid, e["asset_id"], e["event_type"], e["severity"],
                     e["detected_at"], e["status"], e["description"]),
                )
                n_evt += 1
                if e["response"]:
                    r = e["response"]
                    cur.execute("SELECT nextval('responses_response_id_seq')")
                    rid = cur.fetchone()[0]
                    cur.execute(
                        "INSERT INTO responses "
                        "(response_id, event_id, staff_id, action_taken, action_date, status) "
                        "VALUES (%s, %s, %s, %s, %s, %s)",
                        (rid, eid, r["staff_id"], r["action_taken"],
                         r["action_date"], r["status"]),
                    )
                    n_resp += 1
        conn.commit()

        by_sev = {}
        by_status = {}
        for e in batch:
            by_sev[e["severity"]] = by_sev.get(e["severity"], 0) + 1
            by_status[e["status"]] = by_status.get(e["status"], 0) + 1
        print(f"\n✔ 커밋 완료: security_events +{n_evt}, responses +{n_resp}")
        print("  severity : " + ", ".join(f"{k}={v}" for k, v in sorted(by_sev.items())))
        print("  status   : " + ", ".join(f"{k}={v}" for k, v in sorted(by_status.items())))
        print("  모든 행은 description/action_taken 이 '[SIM] ' 로 시작합니다.")
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


if __name__ == "__main__":
    main()

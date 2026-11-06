#!/usr/bin/env python3
"""
alert_poller.py — 폴링 방식 알림 트리거 (launchd 로 1~2분 주기 실행)

세 소스를 검사하고, 아직 알림 안 보낸 건만 alert_notifier.notify() 로 발송한다:
  a) security_events 의 최근(기본 2h) CRITICAL 이벤트          [--source events]
     (FDS 이상거래 이벤트 FRAUD_SUSPECT 는 제외 → c 의 요약으로)
  b) fn_verify_audit_chain() 로 감사로그 해시체인 손상 감지     [--source audit]
  c) FDS 채점 실행(run)별 경보 요약 — CRITICAL 이 있는 끝난 실행당 1건 [--source fds]  (V039)
     배치 채점 1회에 CRITICAL 이 수십 건 생겨 개별 알림이 폭주하는 문제(알림 피로) 대응.
     fds 스키마가 없는 DB 에서는 건너뜀.
중복 방지: alert_log(alert_type, ref_key) UNIQUE + INSERT..ON CONFLICT DO NOTHING RETURNING.

■ 폴링(launchd) vs LISTEN/NOTIFY 선택 근거
  - 이 프로젝트의 운영 계층은 이미 전부 launchd 주기 잡(backup/synth/auditverify)이다.
    폴링 알림도 같은 패턴이라 일관적이고, 상주 데몬 수명관리가 필요 없다.
  - NOTIFY 는 리스너가 없을 때 유실된다(영속성 없음). 폴링 + alert_log dedup 은
    launchd 실행이 한두 번 밀려도 다음 주기에 스스로 복구된다.
  - 규모가 작아(이벤트 수십~수백/일) 2분 지연은 학교 SOC 데모에 충분.
  → 폴링 채택. (대량 트래픽/즉시성이 중요해지면 security_events 트리거 pg_notify +
     상주 리스너로 전환. 이땐 alert_log dedup 은 그대로 재사용 가능)

사용:
  python3 scripts/alert_poller.py                       # 두 소스 다
  python3 scripts/alert_poller.py --source audit        # 감사체인만 (verify_audit_chain.sh 가 호출)
  python3 scripts/alert_poller.py --source events --window-hours 6
  python3 scripts/alert_poller.py --source fds          # FDS 실행별 요약만
  python3 scripts/alert_poller.py --dry-run             # 발송 없이 대상만 출력
환경변수: PGDATABASE, ALERT_INCLUDE_SIM(기본 1; 0 이면 [SIM] CRITICAL 은 알림 제외)
"""
import argparse
import datetime as dt
import json
import os
import sys
from pathlib import Path

import psycopg2

sys.path.insert(0, str(Path(__file__).resolve().parent))
from alert_notifier import notify  # noqa: E402

DB_NAME = os.environ.get("PGDATABASE", "security_db")
INCLUDE_SIM = os.environ.get("ALERT_INCLUDE_SIM", "1").strip() not in ("0", "false", "no", "")


def _record_and_notify(cur, alert_type, ref_key, summary, severity, is_syn, payload, url):
    """alert_log 에 dedup INSERT. 신규면 알림 발송하고 채널을 기록. (sent?, channels) 반환."""
    cur.execute(
        "INSERT INTO alert_log (alert_type, ref_key, severity, summary, is_synthetic, payload) "
        "VALUES (%s, %s, %s, %s, %s, %s) "
        "ON CONFLICT (alert_type, ref_key) DO NOTHING RETURNING alert_id",
        (alert_type, ref_key, severity, summary, is_syn, json.dumps(payload, ensure_ascii=False)))
    row = cur.fetchone()
    if not row:
        return (False, [])                      # 이미 알림 보냄
    if alert_type == "AUDIT_CHAIN":
        title = "🛑 security_db SOC — 감사로그 무결성"
    elif alert_type == "FDS_RUN_DIGEST":
        title = "🟠 security_db SOC — FDS 이상거래 요약"
    else:
        title = "🔴 security_db SOC — CRITICAL 이벤트" + (" [SIM]" if is_syn else "")
    channels = notify(title, summary, subtitle=severity or alert_type, url=url)
    cur.execute("UPDATE alert_log SET channels = %s WHERE alert_id = %s", (channels, row[0]))
    return (True, channels)


def check_events(cur, window_hours, dry_run):
    cur.execute(
        """
        SELECT e.event_id, e.event_type, e.severity, e.detected_at, e.status,
               coalesce(e.description,'') AS descr, a.asset_name
        FROM security_events e
        JOIN assets a ON a.asset_id = e.asset_id
        WHERE e.severity = 'CRITICAL'
          AND e.event_type <> 'FRAUD_SUSPECT'          -- FDS 경보는 실행별 요약(check_fds)으로 보냄
          AND e.detected_at >= now() - (%s || ' hours')::interval
          AND NOT EXISTS (SELECT 1 FROM alert_log al
                          WHERE al.alert_type='CRITICAL_EVENT' AND al.ref_key = e.event_id::text)
        ORDER BY e.detected_at
        """, (window_hours,))
    rows = cur.fetchall()
    sent = skipped = 0
    for eid, etype, sev, det, status, descr, asset in rows:
        is_syn = descr.startswith("[SIM]")
        if is_syn and not INCLUDE_SIM:
            skipped += 1
            continue
        tag = "[SIM] " if is_syn else ""
        summary = (f"{tag}CRITICAL '{etype}' @ {asset} "
                   f"(event #{eid}, {det:%Y-%m-%d %H:%M}, status={status})"
                   + (f" — {descr[:120]}" if descr else ""))
        if dry_run:
            print(f"  [would notify] {summary}")
            sent += 1
            continue
        did, ch = _record_and_notify(
            cur, "CRITICAL_EVENT", str(eid), summary, "CRITICAL", is_syn,
            {"event_id": eid, "event_type": etype, "asset": asset,
             "detected_at": det.isoformat(), "synthetic": is_syn}, None)
        if did:
            sent += 1
            print(f"  notified: {summary}  -> {','.join(ch) or 'NONE'}")
        else:
            skipped += 1
    return sent, skipped, len(rows)


def check_audit(cur, database, dry_run):
    cur.execute("SELECT audit_id, problem FROM fn_verify_audit_chain() ORDER BY audit_id")
    breaks = cur.fetchall()
    if not breaks:
        return 0, 0, 0
    ids = [str(b[0]) for b in breaks]
    ref_key = f"{database}:{len(ids)}:{'.'.join(ids)}"          # 손상 지문 (같은 손상은 재알림 안 함)
    summary = (f"감사로그 해시체인 손상 감지! db={database} breaks={len(ids)} "
               f"깨진 audit_id=[{', '.join(ids)}] — {breaks[0][1]}. "
               f"마지막 정상 백업 대조 / 변경이력·OS로그 확인 필요.")
    if dry_run:
        print(f"  [would notify] {summary}")
        return 1, 0, len(breaks)
    did, ch = _record_and_notify(
        cur, "AUDIT_CHAIN", ref_key, summary, "CRITICAL", False,
        {"database": database, "breaks": len(ids), "audit_ids": ids}, None)
    if did:
        print(f"  notified: {summary}  -> {','.join(ch) or 'NONE'}")
        return 1, 0, len(breaks)
    print("  (이미 알림 보낸 손상 — 재발송 안 함)")
    return 0, 1, len(breaks)


def check_fds(cur, dry_run):
    """FDS 채점 실행(run)마다 경보 요약 1건. CRITICAL 이 1건 이상이고 실행이 끝난(finished_at) run 만."""
    cur.execute("SELECT to_regclass('fds.alert_events') IS NOT NULL")
    if not cur.fetchone()[0]:
        return 0, 0, 0                                   # FDS 연동 안 된 DB
    cur.execute(
        """
        SELECT r.run_id, r.finished_at,
               count(*)                                          AS n_alert,
               count(*) FILTER (WHERE ae.severity = 'CRITICAL')  AS n_crit,
               count(*) FILTER (WHERE ae.severity = 'HIGH')      AS n_high,
               (array_agg(format('txn %s(%s)', s.txn_id, to_char(s.score, 'FM0.0000'))
                          ORDER BY s.score DESC))[1:3]           AS top3,
               min(ae.event_id), max(ae.event_id)
        FROM fds.alert_events ae
        JOIN fds.model_runs r USING (run_id)
        JOIN fds.scores s USING (run_id, txn_id)
        WHERE r.finished_at IS NOT NULL                          -- 채점이 끝난 실행만 (중간 요약 방지)
          AND NOT EXISTS (SELECT 1 FROM alert_log al
                          WHERE al.alert_type = 'FDS_RUN_DIGEST' AND al.ref_key = r.run_id::text)
        GROUP BY r.run_id, r.finished_at
        HAVING count(*) FILTER (WHERE ae.severity = 'CRITICAL') > 0
        ORDER BY r.run_id
        """)
    rows = cur.fetchall()
    sent = skipped = 0
    for run_id, fin, n, n_crit, n_high, top3, ev_min, ev_max in rows:
        summary = (f"FDS run {run_id} ({fin:%Y-%m-%d %H:%M} 완료): 경보 {n}건 "
                   f"(CRITICAL {n_crit} / HIGH {n_high}) · 상위 {', '.join(top3)} · "
                   f"이벤트 #{ev_min}~#{ev_max} — 대기열(fds.vw_alert_queue)에서 확인")
        if dry_run:
            print(f"  [would notify] {summary}")
            sent += 1
            continue
        did, ch = _record_and_notify(
            cur, "FDS_RUN_DIGEST", str(run_id), summary, "CRITICAL", False,
            {"run_id": run_id, "alerts": n, "critical": n_crit, "high": n_high,
             "top3": top3, "event_range": [ev_min, ev_max]}, None)
        if did:
            sent += 1
            print(f"  notified: {summary}  -> {','.join(ch) or 'NONE'}")
        else:
            skipped += 1
    return sent, skipped, len(rows)


def main():
    ap = argparse.ArgumentParser(description="폴링 알림 트리거")
    ap.add_argument("--source", choices=["all", "events", "audit", "fds"], default="all")
    ap.add_argument("--window-hours", type=int, default=2)
    ap.add_argument("--database", default=DB_NAME)
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    conn = psycopg2.connect(dbname=a.database)
    conn.autocommit = False
    try:
        cur = conn.cursor()
        total_sent = 0
        if a.source in ("all", "events"):
            s, sk, n = check_events(cur, a.window_hours, a.dry_run)
            total_sent += s
            print(f"[events] 대상 {n}건 · 발송 {s} · 스킵(중복/제외) {sk}")
        if a.source in ("all", "audit"):
            s, sk, nb = check_audit(cur, a.database, a.dry_run)
            total_sent += s
            print(f"[audit ] 깨진행 {nb} · 발송 {s} · 스킵(중복) {sk}")
        if a.source in ("all", "fds"):
            s, sk, nr = check_fds(cur, a.dry_run)
            total_sent += s
            print(f"[fds   ] 요약 대상 실행 {nr} · 발송 {s} · 스킵(중복) {sk}")
        if not a.dry_run:
            conn.commit()
        return 0
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


if __name__ == "__main__":
    sys.exit(main())

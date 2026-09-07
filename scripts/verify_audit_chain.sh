#!/bin/bash
# =====================================================================
# verify_audit_chain.sh — audit_log 해시체인 무결성 자동 점검 (launchd 용)
#
#   fn_verify_audit_chain() 를 실행해 깨진 지점 수(breaks)를 logs/audit_verify.log 에 남긴다.
#   breaks > 0 이면 로그에 "*** ALERT ***" 를 눈에 띄게 찍고 exit 2.
#
# --- 스케줄 등록 (매일 04:00) --------------------------------------
#   cp scripts/com.security-db.auditverify.plist ~/Library/LaunchAgents/
#   launchctl load ~/Library/LaunchAgents/com.security-db.auditverify.plist
#   launchctl list | grep security-db          # 등록/마지막 종료코드 확인
#
# --- 즉시 1회 실행 -------------------------------------------------
#   launchctl start com.security-db.auditverify      (등록돼 있을 때)
#   bash scripts/verify_audit_chain.sh               (수동)
#
# --- 스케줄 해제 -------------------------------------------------
#   launchctl unload ~/Library/LaunchAgents/com.security-db.auditverify.plist
#   rm ~/Library/LaunchAgents/com.security-db.auditverify.plist
# =====================================================================
set -u

DB="${PGDATABASE:-security_db}"
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_DIR="$PROJECT_DIR/logs"
LOG="$LOG_DIR/audit_verify.log"

PSQL="/opt/homebrew/opt/postgresql@15/bin/psql"
[ -x "$PSQL" ] || PSQL="$(command -v psql)"

mkdir -p "$LOG_DIR"
TS="$(date '+%Y-%m-%d %H:%M:%S')"

# 깨진 행 수
BREAKS="$("$PSQL" -d "$DB" -tAc 'SELECT count(*) FROM fn_verify_audit_chain()' 2>>"$LOG")"
RC=$?

if [ "$RC" -ne 0 ] || [ -z "$BREAKS" ]; then
    echo "$TS  [ERROR] fn_verify_audit_chain() 실행 실패 (psql exit $RC) — 점검 불가" >> "$LOG"
    exit 3
fi

AUDIT_ROWS="$("$PSQL" -d "$DB" -tAc 'SELECT count(*) FROM audit_log' 2>/dev/null)"

if [ "$BREAKS" -eq 0 ]; then
    echo "$TS  OK    db=$DB  audit_log 행=$AUDIT_ROWS  해시체인 무결 (breaks=0)" >> "$LOG"
    exit 0
else
    {
        echo "$TS  *** ALERT *** db=$DB  해시체인 손상 감지! breaks=$BREAKS  (audit_log 행=$AUDIT_ROWS)"
        echo "$TS  *** ALERT *** 깨진 지점 상세:"
        "$PSQL" -d "$DB" -c \
          "SELECT audit_id, problem, left(expected_hash,16) AS expected, left(stored_hash,16) AS stored FROM fn_verify_audit_chain()" \
          2>&1 | sed "s/^/$TS  *** ALERT *** /"
        echo "$TS  *** ALERT *** 조치: 마지막 정상 백업으로 대조, 변경 이력/OS 로그 확인. audit_log 는 append-only 이어야 함."
    } >> "$LOG"

    # 실시간 알림 (dedup 은 alert_poller 가 alert_log 로 처리)
    PYBIN="/Users/summer/opt/anaconda3/bin/python3"
    [ -x "$PYBIN" ] || PYBIN="$(command -v python3)"
    PGDATABASE="$DB" "$PYBIN" "$PROJECT_DIR/scripts/alert_poller.py" --source audit --database "$DB" \
        >> "$LOG" 2>&1 || echo "$TS  [WARN] alert_poller 호출 실패" >> "$LOG"

    exit 2
fi

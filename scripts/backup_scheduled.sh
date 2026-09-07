#!/bin/bash
# =====================================================================
# backup_scheduled.sh — security_db 자동 백업 + 보존정책 (macOS launchd 용)
#
#   - pg_dump --format=custom 으로 db_backups/<db>_<YYYYmmdd_HHMMSS>.dump 생성
#   - 보존정책: 14일 지난 백업 삭제. 단 "최근 7개"는 나이와 무관하게 무조건 보존
#   - 실행 로그: db_backups/backup.log
#
# --- 스케줄 등록 (매일 03:30) --------------------------------------
#   cp scripts/com.security-db.backup.plist ~/Library/LaunchAgents/
#   launchctl load ~/Library/LaunchAgents/com.security-db.backup.plist
#   launchctl list | grep com.security-db.backup        # 등록 확인
#
# --- 즉시 1회 실행 (등록된 job 트리거) ----------------------------
#   launchctl start com.security-db.backup
#
# --- 수동 실행 (등록 없이) ---------------------------------------
#   bash scripts/backup_scheduled.sh
#
# --- 스케줄 해제 -----------------------------------------------
#   launchctl unload ~/Library/LaunchAgents/com.security-db.backup.plist
#   rm ~/Library/LaunchAgents/com.security-db.backup.plist
#
# --- ⚠ macOS TCC 주의 -----------------------------------------
#   이 프로젝트는 ~/Desktop 아래에 있고, macOS 는 ~/Desktop/~/Documents/~/Downloads 를
#   백그라운드 에이전트(launchd)로부터 보호한다. 그래서 launchd 가 이 스크립트를
#   실행하면 "Operation not permitted" 로 exit 126 이 된다(수동 실행 `bash scripts/...`
#   는 터미널의 접근권한을 물려받아 정상).
#   해결(둘 중 하나):
#     (A) 시스템 설정 > 개인정보 보호 및 보안 > 전체 디스크 접근 권한 에 `/bin/bash` 추가
#     (B) 프로젝트를 보호 대상이 아닌 경로로 이동 (예: ~/security_db_project) 후 plist 경로 수정
#   스크립트/plist 자체는 정상이며, 접근권한만 확보되면 스케줄이 동작한다.
# =====================================================================
set -euo pipefail

DB="${PGDATABASE:-security_db}"
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKUP_DIR="$PROJECT_DIR/db_backups"
LOG="$BACKUP_DIR/backup.log"
RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-14}"
MIN_KEEP="${BACKUP_MIN_KEEP:-7}"

# launchd 는 PATH 가 최소라 절대경로 사용
PG_DUMP="/opt/homebrew/opt/postgresql@15/bin/pg_dump"
[ -x "$PG_DUMP" ] || PG_DUMP="$(command -v pg_dump)"
PG_DUMPALL="/opt/homebrew/opt/postgresql@15/bin/pg_dumpall"
[ -x "$PG_DUMPALL" ] || PG_DUMPALL="$(command -v pg_dumpall)"

mkdir -p "$BACKUP_DIR"
log() { echo "$(date '+%Y-%m-%d %H:%M:%S') $*" | tee -a "$LOG"; }

TS="$(date +%Y%m%d_%H%M%S)"
OUT="$BACKUP_DIR/${DB}_${TS}.dump"
ROLES_OUT="$BACKUP_DIR/roles_${TS}.sql"

log "=== 백업 시작  db=$DB  ->  $(basename "$OUT") ==="
if "$PG_DUMP" -d "$DB" --format=custom --no-owner -f "$OUT" 2>>"$LOG"; then
    SZ="$(stat -f%z "$OUT")"
    log "DB 백업 완료  (${SZ} bytes)"
else
    rc=$?
    log "!! DB 백업 실패  (pg_dump exit ${rc})"
    exit "$rc"
fi

# 클러스터 role/권한은 pg_dump(단일 DB)에 안 담긴다. 새 클러스터로 복구할 때
# GRANT/RLS 가 붙을 대상이 되도록 role 정의를 별도로 뜬다.
if "$PG_DUMPALL" --roles-only --no-role-passwords -f "$ROLES_OUT" 2>>"$LOG"; then
    log "role 정의 백업 완료  ($(basename "$ROLES_OUT"))"
else
    log "!! role 정의 백업 실패 (계속 진행) — 복구 시 role 을 수동 생성해야 함"
fi

# --- 보존정책 -------------------------------------------------------
# 최신순 목록. index < MIN_KEEP 이면 무조건 보존, 그 외 나이>=RETENTION_DAYS 면 삭제.
# DB 덤프(*.dump)와 role 덤프(roles_*.sql)에 각각 동일 정책 적용.
NOW="$(date +%s)"
prune() {  # $1 = glob 패턴
    local i=0 kept=0 deleted=0 f mtime age_days
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        if [ "$i" -lt "$MIN_KEEP" ]; then
            kept=$((kept + 1))
        else
            mtime="$(stat -f%m "$f")"
            age_days=$(( (NOW - mtime) / 86400 ))
            if [ "$age_days" -ge "$RETENTION_DAYS" ]; then
                rm -f "$f"; deleted=$((deleted + 1))
                log "보존정책 삭제: $(basename "$f")  (${age_days}일 경과)"
            else
                kept=$((kept + 1))
            fi
        fi
        i=$((i + 1))
    done < <(ls -1t $1 2>/dev/null)
    echo "$kept $deleted"
}
read d_kept d_deleted <<EOF
$(prune "$BACKUP_DIR/${DB}_*.dump")
EOF
read r_kept r_deleted <<EOF
$(prune "$BACKUP_DIR/roles_*.sql")
EOF

remain="$(ls -1 "$BACKUP_DIR"/${DB}_*.dump 2>/dev/null | wc -l | tr -d ' ')"
log "보존정책 적용: DB덤프 보존 ${d_kept}/삭제 ${d_deleted}, role덤프 보존 ${r_kept}/삭제 ${r_deleted} · 현재 DB백업 ${remain}개 (RETENTION_DAYS=${RETENTION_DAYS}, MIN_KEEP=${MIN_KEEP})"
log "=== 백업 종료 ==="

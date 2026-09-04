#!/usr/bin/env bash
# =========================================================
# 마이그레이션 6) 백업 / 복구 검증 스크립트 (backup_restore.sh)
#
#   1) pg_dump 로 security_db 전체(스키마+데이터)를 custom 포맷으로 백업
#   2) 별도 이름의 테스트 DB 를 새로 만들어 그 백업으로 복구 (pg_restore)
#   3) 원본과 복구본의 "테이블별 행 개수"를 비교해 완전 일치하는지 검증
#
#   같은 클러스터에 복구하므로 role(dept_infra 등)은 이미 존재한다고 가정한다.
#   (별도 클러스터로 옮길 때는 pg_dumpall --roles-only 로 role 도 함께 이관해야 함)
#
#   사용법:
#     ./backup_restore.sh                 # 백업 -> 복구 -> 검증, 끝나면 테스트 DB 삭제
#     KEEP_TESTDB=1 ./backup_restore.sh   # 테스트 DB 를 지우지 않고 남김
# =========================================================
set -euo pipefail

SRC_DB="${SRC_DB:-security_db}"
TEST_DB="${TEST_DB:-security_db_restore_test}"
BACKUP_DIR="${BACKUP_DIR:-$HOME/Downloads/db_backups}"
STAMP="$(date +%Y%m%d_%H%M%S)"
BACKUP_FILE="${BACKUP_DIR}/${SRC_DB}_${STAMP}.dump"

mkdir -p "$BACKUP_DIR"

echo "== 1) 백업: ${SRC_DB} -> ${BACKUP_FILE}"
pg_dump -d "$SRC_DB" --format=custom --no-owner --file="$BACKUP_FILE"
ls -lh "$BACKUP_FILE" | awk '{print "   백업 파일 크기:", $5}'

echo "== 2) 테스트 DB 재생성: ${TEST_DB}"
psql -d postgres -v ON_ERROR_STOP=1 -c "DROP DATABASE IF EXISTS ${TEST_DB};"
psql -d postgres -v ON_ERROR_STOP=1 -c "CREATE DATABASE ${TEST_DB};"

echo "== 3) 복구: ${BACKUP_FILE} -> ${TEST_DB}"
# --no-owner: 복구 실행 계정 소유로. 벤딩 확장/GRANT 는 그대로 재생성.
# 일부 비치명적 경고가 있을 수 있어 --exit-on-error 는 쓰지 않고, 대신 행수로 검증.
restore_log="$(mktemp)"
if pg_restore --no-owner --dbname="$TEST_DB" "$BACKUP_FILE" 2> "$restore_log"; then
    echo "   pg_restore 정상 종료"
else
    echo "   pg_restore 비정상 종료 코드 - 로그 확인:"
fi
if [ -s "$restore_log" ]; then
    echo "   --- pg_restore stderr ---"
    sed 's/^/   /' "$restore_log"
    echo "   -------------------------"
fi
rm -f "$restore_log"

echo "== 4) 행 개수 비교"
# 모든 base table 에 대해 'table|count' 목록을 동적으로 생성해 양쪽에서 실행
GEN_SQL="SELECT string_agg(format('SELECT %L AS t, count(*) AS c FROM %I', table_name, table_name), ' UNION ALL ')
         FROM information_schema.tables
         WHERE table_schema='public' AND table_type='BASE TABLE';"

COUNT_QUERY="$(psql -d "$SRC_DB" -At -c "$GEN_SQL")"

src_counts="$(psql -d "$SRC_DB"  -At -F '|' -c "${COUNT_QUERY} ORDER BY t")"
dst_counts="$(psql -d "$TEST_DB" -At -F '|' -c "${COUNT_QUERY} ORDER BY t")"

printf '%-26s | %10s | %10s | %s\n' "table" "source" "restored" "result"
printf '%s\n' "---------------------------+------------+------------+--------"
mismatch=0
while IFS='|' read -r t src_c <&3 && IFS='|' read -r _ dst_c <&4; do
    if [ "$src_c" = "$dst_c" ]; then
        res="OK"
    else
        res="MISMATCH"
        mismatch=1
    fi
    printf '%-26s | %10s | %10s | %s\n' "$t" "$src_c" "$dst_c" "$res"
done 3<<<"$src_counts" 4<<<"$dst_counts"

echo
src_total="$(psql -d "$SRC_DB"  -At -c "SELECT count(*) FROM information_schema.tables WHERE table_schema='public' AND table_type='BASE TABLE';")"
dst_total="$(psql -d "$TEST_DB" -At -c "SELECT count(*) FROM information_schema.tables WHERE table_schema='public' AND table_type='BASE TABLE';")"
echo "base table 수: source=${src_total}, restored=${dst_total}"

if [ "$mismatch" -eq 0 ] && [ "$src_total" = "$dst_total" ]; then
    echo "RESULT: PASS - 모든 테이블 행 개수 일치"
    rc=0
else
    echo "RESULT: FAIL - 불일치 발견"
    rc=1
fi

if [ "${KEEP_TESTDB:-0}" = "1" ]; then
    echo "테스트 DB(${TEST_DB}) 는 KEEP_TESTDB=1 이라 유지합니다."
else
    echo "테스트 DB(${TEST_DB}) 삭제"
    psql -d postgres -c "DROP DATABASE IF EXISTS ${TEST_DB};" >/dev/null
fi

exit "$rc"

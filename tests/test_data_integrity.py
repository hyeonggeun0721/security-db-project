"""
데이터 무결성 회귀 테스트 — 스크래치 DB(security_db_pytest)에서만 돈다.

옮겨온 검증절:
  1. V018  FK ON DELETE RESTRICT  — 이벤트가 걸린 asset / 대응이 걸린 staff 는 DELETE 거부
  2. V023  감사로그 해시체인       — 무결 상태 breaks=0, 한 행 조작 후 breaks>0, 롤백 후 다시 0
  3. V028  시간적 무결성 트리거     — responses.action_date < event.detected_at 인 INSERT/UPDATE 거부
  6. V033  event_threat_matches    — chk_etm_target CHECK 위반 거부, uq_etm_dedup ON CONFLICT DO NOTHING
  7. V036  SIM 정리                 — [SIM] 이벤트 발 THREAT_REPORT 매칭이 정리되고 0건 유지
"""
import psycopg2
import psycopg2.errors
import pytest

FK_VIOLATION = "23503"
CHECK_VIOLATION = "23514"


# ---------------------------------------------------------------------------
# 1) V018 — FK ON DELETE RESTRICT
# ---------------------------------------------------------------------------
def test_v018_restrict_delete_asset_that_has_events(su):
    """security_events.asset_id -> assets 는 ON DELETE RESTRICT. 이벤트가 있는 자산은 못 지운다."""
    cur = su.cursor()
    cur.execute("SELECT asset_id FROM security_events GROUP BY asset_id HAVING count(*) > 0 LIMIT 1")
    asset_id = cur.fetchone()[0]
    with pytest.raises(psycopg2.errors.ForeignKeyViolation) as ei:
        cur.execute("DELETE FROM assets WHERE asset_id = %s", (asset_id,))
    assert ei.value.pgcode == FK_VIOLATION


def test_v018_restrict_delete_staff_that_has_responses(su):
    """responses.staff_id -> staff 는 ON DELETE RESTRICT. 대응 이력이 있는 담당자는 못 지운다."""
    cur = su.cursor()
    cur.execute("SELECT staff_id FROM responses GROUP BY staff_id HAVING count(*) > 0 LIMIT 1")
    staff_id = cur.fetchone()[0]
    with pytest.raises(psycopg2.errors.ForeignKeyViolation) as ei:
        cur.execute("DELETE FROM staff WHERE staff_id = %s", (staff_id,))
    assert ei.value.pgcode == FK_VIOLATION


# ---------------------------------------------------------------------------
# 2) V023 — 감사로그 해시체인
# ---------------------------------------------------------------------------
def test_v023_hash_chain_detects_tampering(su):
    """정상 상태 breaks=0 → audit_log 한 행 UPDATE 조작 → breaks>0 → 롤백 → 다시 0."""
    cur = su.cursor()

    # 조작 대상 감사 행을 이 트랜잭션 안에서 만든다(사전 데이터 유무와 무관하게 결정적).
    cur.execute("SELECT asset_id FROM assets LIMIT 1")
    asset_id = cur.fetchone()[0]
    for i in range(3):
        cur.execute(
            "INSERT INTO security_events (asset_id, event_type, severity, detected_at, description) "
            "VALUES (%s, '침입시도', 'LOW', now(), %s)",
            (asset_id, f"pytest-chain-{i}"),
        )

    cur.execute("SELECT count(*) FROM fn_verify_audit_chain()")
    assert cur.fetchone()[0] == 0, "정상 INSERT 뒤인데 해시체인이 깨졌다고 나옴"

    # 슈퍼유저가 append-only 방어(트리거)를 끄고 한 행을 조작하는 상황을 흉내낸다.
    cur.execute("ALTER TABLE audit_log DISABLE TRIGGER trg_audit_log_no_update")
    cur.execute(
        "UPDATE audit_log SET changed_by = 'ATTACKER' "
        "WHERE audit_id = (SELECT audit_id FROM audit_log ORDER BY audit_id DESC "
        "                  OFFSET 1 LIMIT 1)"
    )
    cur.execute("SELECT count(*) FROM fn_verify_audit_chain()")
    broken = cur.fetchone()[0]
    assert broken >= 1, "행을 조작했는데 fn_verify_audit_chain() 이 깨진 지점을 못 잡음"

    su.rollback()  # ALTER TABLE(트리거 재활성) + UPDATE + INSERT 전부 원복

    cur = su.cursor()
    cur.execute("SELECT count(*) FROM fn_verify_audit_chain()")
    assert cur.fetchone()[0] == 0, "롤백했는데도 체인이 깨진 상태로 남음"


# ---------------------------------------------------------------------------
# 3) V028 — responses 시간적 무결성 트리거
# ---------------------------------------------------------------------------
def _make_event(cur, detected_at):
    cur.execute("SELECT asset_id FROM assets LIMIT 1")
    asset_id = cur.fetchone()[0]
    cur.execute(
        "INSERT INTO security_events (asset_id, event_type, severity, detected_at, description) "
        "VALUES (%s, '침입시도', 'HIGH', %s, 'pytest-v028') RETURNING event_id",
        (asset_id, detected_at),
    )
    return cur.fetchone()[0]


def test_v028_insert_response_before_detection_is_denied(su):
    cur = su.cursor()
    ev = _make_event(cur, "2025-06-01 12:00:00+09")
    with pytest.raises(psycopg2.errors.CheckViolation) as ei:
        cur.execute(
            "INSERT INTO responses (event_id, staff_id, action_taken, action_date) "
            "VALUES (%s, 1, 'pytest 조치', %s)",
            (ev, "2025-05-01 09:00:00+09"),
        )
    assert ei.value.pgcode == CHECK_VIOLATION


def test_v028_insert_response_after_detection_is_allowed(su):
    cur = su.cursor()
    ev = _make_event(cur, "2025-06-01 12:00:00+09")
    cur.execute(
        "INSERT INTO responses (event_id, staff_id, action_taken, action_date) "
        "VALUES (%s, 1, 'pytest 조치', %s) RETURNING response_id",
        (ev, "2025-06-02 09:00:00+09"),
    )
    assert cur.fetchone()[0] is not None


def test_v028_update_response_action_date_to_past_is_denied(su):
    cur = su.cursor()
    ev = _make_event(cur, "2025-06-01 12:00:00+09")
    cur.execute(
        "INSERT INTO responses (event_id, staff_id, action_taken, action_date) "
        "VALUES (%s, 1, 'pytest 조치', %s) RETURNING response_id",
        (ev, "2025-06-02 09:00:00+09"),
    )
    rid = cur.fetchone()[0]
    with pytest.raises(psycopg2.errors.CheckViolation) as ei:
        cur.execute(
            "UPDATE responses SET action_date = %s WHERE response_id = %s",
            ("2020-01-01 00:00:00+09", rid),
        )
    assert ei.value.pgcode == CHECK_VIOLATION


# ---------------------------------------------------------------------------
# 6) V033 — event_threat_matches 제약
# ---------------------------------------------------------------------------
def test_v033_chk_etm_target_rejects_both_targets_set(su):
    """match_type='THREAT_REPORT' 인데 matched_event_id 까지 채우면 chk_etm_target CHECK 로 거부."""
    cur = su.cursor()
    cur.execute("SELECT event_id FROM security_events ORDER BY event_id LIMIT 1")
    ev = cur.fetchone()[0]
    cur.execute("SELECT report_id FROM threat_reports ORDER BY report_id LIMIT 1")
    rpt = cur.fetchone()[0]
    with pytest.raises(psycopg2.errors.CheckViolation) as ei:
        cur.execute(
            "INSERT INTO event_threat_matches "
            "(event_id, match_type, matched_report_id, matched_event_id, similarity) "
            "VALUES (%s, 'THREAT_REPORT', %s, %s, 0.5)",
            (ev, rpt, ev),
        )
    assert ei.value.pgcode == CHECK_VIOLATION


def test_v033_uq_etm_dedup_on_conflict_do_nothing(su):
    """같은 (event_id, match_type, 대상) 을 두 번 INSERT — 두 번째는 ON CONFLICT DO NOTHING 으로 무시."""
    cur = su.cursor()
    cur.execute("SELECT event_id FROM security_events ORDER BY event_id LIMIT 1")
    ev = cur.fetchone()[0]
    cur.execute("SELECT report_id FROM threat_reports ORDER BY report_id LIMIT 1")
    rpt = cur.fetchone()[0]

    insert = (
        "INSERT INTO event_threat_matches (event_id, match_type, matched_report_id, similarity) "
        "VALUES (%s, 'THREAT_REPORT', %s, 0.5) "
        "ON CONFLICT (event_id, match_type, COALESCE(matched_report_id,-1), COALESCE(matched_event_id,-1)) "
        "DO NOTHING"
    )
    cur.execute(insert, (ev, rpt))
    assert cur.rowcount == 1, "첫 INSERT 는 1행 들어가야 함"
    cur.execute(insert, (ev, rpt))
    assert cur.rowcount == 0, "중복 INSERT 는 ON CONFLICT DO NOTHING 으로 0행이어야 함"

    cur.execute(
        "SELECT count(*) FROM event_threat_matches "
        "WHERE event_id = %s AND match_type = 'THREAT_REPORT' AND matched_report_id = %s",
        (ev, rpt),
    )
    assert cur.fetchone()[0] == 1, "중복 방지가 됐다면 행은 1개여야 함"


# ---------------------------------------------------------------------------
# 7) V036 — [SIM] 이벤트가 THREAT_REPORT 매칭에 섞이지 않음
# ---------------------------------------------------------------------------
def test_v036_sim_events_excluded_from_threat_report_matches(su):
    """[SIM] 이벤트와 실제 이벤트에 각각 THREAT_REPORT 매칭을 심고 V036 정리 쿼리를 돌리면
    [SIM] 발만 사라지고, 정리 후 'SIM 발 THREAT_REPORT 매칭' 카운트가 0이 된다."""
    cur = su.cursor()
    cur.execute("SELECT asset_id FROM assets LIMIT 1")
    asset_id = cur.fetchone()[0]
    cur.execute("SELECT report_id FROM threat_reports ORDER BY report_id LIMIT 1")
    rpt = cur.fetchone()[0]
    cur.execute("SELECT event_id FROM security_events WHERE description NOT LIKE '[SIM]%' ORDER BY event_id LIMIT 1")
    real_ev = cur.fetchone()[0]

    cur.execute(
        "INSERT INTO security_events (asset_id, event_type, severity, detected_at, description) "
        "VALUES (%s, '침입시도', 'LOW', now(), '[SIM] pytest v036') RETURNING event_id",
        (asset_id,),
    )
    sim_ev = cur.fetchone()[0]

    cur.execute(
        "INSERT INTO event_threat_matches (event_id, match_type, matched_report_id, similarity) "
        "VALUES (%s, 'THREAT_REPORT', %s, 0.5), (%s, 'THREAT_REPORT', %s, 0.5)",
        (sim_ev, rpt, real_ev, rpt),
    )

    # V036 검증절이 재현하는 정리 쿼리
    cur.execute(
        "DELETE FROM event_threat_matches "
        "WHERE match_type = 'THREAT_REPORT' "
        "  AND event_id IN (SELECT event_id FROM security_events WHERE description LIKE '[SIM]%')"
    )

    cur.execute("SELECT count(*) FROM event_threat_matches WHERE event_id = %s", (sim_ev,))
    assert cur.fetchone()[0] == 0, "[SIM] 이벤트 발 매칭이 정리되지 않음"
    cur.execute("SELECT count(*) FROM event_threat_matches WHERE event_id = %s", (real_ev,))
    assert cur.fetchone()[0] == 1, "실제 이벤트 발 매칭까지 지워짐(오버킬)"

    cur.execute(
        "SELECT count(*) FROM event_threat_matches m "
        "JOIN security_events e ON e.event_id = m.event_id "
        "WHERE m.match_type = 'THREAT_REPORT' AND e.description LIKE '[SIM]%'"
    )
    assert cur.fetchone()[0] == 0, "정리 후에도 SIM 발 THREAT_REPORT 매칭이 남아있음"

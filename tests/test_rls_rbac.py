"""
RLS / RBAC 회귀 테스트 — 스크래치 DB(security_db_pytest)에서만 돈다.

옮겨온 검증절:
  4. V029  svc_event_ingest RLS  — '[SIM]' 접두사 없는 description INSERT 는 WITH CHECK 로 거부,
                                   '[SIM]' 있으면 통과
  5. V015/V019 부서 스코프 RLS   — dept_infra 로 조회하면 '인프라팀' 자산의 이벤트만 보인다
"""
import psycopg2
import psycopg2.errors
import pytest

RLS_VIOLATION = "42501"  # new row violates row-level security policy


# ---------------------------------------------------------------------------
# 4) V029 — svc_event_ingest 는 '[SIM]' 태그가 있어야만 INSERT 가능
# ---------------------------------------------------------------------------
def test_v029_svc_ingest_rejects_non_sim_description(su, set_role):
    with set_role(su, "svc_event_ingest") as cur:
        with pytest.raises(psycopg2.errors.InsufficientPrivilege) as ei:
            cur.execute(
                "INSERT INTO security_events (event_id, asset_id, event_type, severity, description, detected_at) "
                "VALUES (nextval('security_events_event_id_seq'), 2, '비정상접근', 'LOW', "
                "        '태그 없는 실제처럼 보이는 이벤트', now())"
            )
        assert ei.value.pgcode == RLS_VIOLATION
        assert "row-level security" in str(ei.value).lower()


def test_v029_svc_ingest_allows_sim_description(su, set_role):
    with set_role(su, "svc_event_ingest") as cur:
        cur.execute(
            "INSERT INTO security_events (event_id, asset_id, event_type, severity, description, detected_at) "
            "VALUES (nextval('security_events_event_id_seq'), 2, '비정상접근', 'LOW', "
            "        '[SIM] pytest 합성 이벤트', now())"
        )
        assert cur.rowcount == 1


# ---------------------------------------------------------------------------
# 5) V015/V019 — 부서 스코프 RLS
# ---------------------------------------------------------------------------
def test_v015_dept_infra_sees_only_infra_department_events(su, set_role):
    cur = su.cursor()

    # 슈퍼유저는 RLS 우회 → 전체 / 인프라팀 기대치를 구한다
    cur.execute("SELECT count(*) FROM security_events")
    total = cur.fetchone()[0]
    cur.execute(
        "SELECT count(*) FROM security_events e "
        "JOIN assets a ON a.asset_id = e.asset_id "
        "WHERE a.department = '인프라팀'"
    )
    infra_expected = cur.fetchone()[0]

    assert infra_expected > 0, "인프라팀 자산에 이벤트가 없으면 이 테스트는 무의미"
    assert infra_expected < total, "인프라팀 외 이벤트가 없으면 '가려지는지'를 검증할 수 없음"
    su.rollback()

    # dept_infra 로는 app.department 세션변수 없이도 rls_role_department 매핑('인프라팀')만 보인다
    with set_role(su, "dept_infra") as cur:
        cur.execute("SELECT count(*) FROM security_events")
        visible = cur.fetchone()[0]
        cur.execute(
            "SELECT count(DISTINCT a.department) "
            "FROM security_events e JOIN assets a ON a.asset_id = e.asset_id"
        )
        distinct_depts_visible = cur.fetchone()[0]

    assert visible == infra_expected, (
        f"dept_infra 가 본 이벤트 수({visible}) != 인프라팀 실제 이벤트 수({infra_expected})"
    )
    assert distinct_depts_visible == 1, "dept_infra 에게 두 개 이상 부서의 이벤트가 보임(RLS 누수)"

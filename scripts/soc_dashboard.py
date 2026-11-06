"""
soc_dashboard.py - security_db SOC 대시보드 (Streamlit + psycopg2 + plotly.graph_objects)

■ 로그인 게이트 (앱 레벨 방어; DB 레벨 RBAC(security_manager)는 그대로 유지 = defense in depth)
    사전 준비:  pip install bcrypt --break-system-packages
    해시 생성:  python3 -c "import bcrypt; print(bcrypt.hashpw(b'비밀번호', bcrypt.gensalt()).decode())"
    실행 전 설정:  export SOC_DASHBOARD_AUTH_HASH='<위에서 생성한 bcrypt 해시>'
    - 비밀번호는 bcrypt 해시로만 다룬다(평문 비교 없음). 해시는 환경변수로만 주입, 코드에 넣지 않는다.
    - SOC_DASHBOARD_AUTH_HASH 가 없으면 대시보드를 열지 않고 에러 후 중단한다(fail-closed).

실행:
    export SOC_DASHBOARD_AUTH_HASH='...'
    streamlit run soc_dashboard.py
    # 헤드리스: streamlit run soc_dashboard.py --server.headless true --server.port 8502

DB 접속 계정 = security_manager :
    security_events / responses 에는 RLS(p_events_dept_scope 등)가 걸려 있어서
    부서 역할(dept_infra/dev/sales)로 붙으면 "그 부서 자산에서 난 이벤트/대응"만 보인다.
    SOC 대시보드는 전사(全社) 현황을 봐야 하므로, RBAC 상 전체 SELECT 권한이 있고
    p_events_rbac_all / p_responses_rbac_all 정책으로 RLS를 우회하는 security_manager 로
    접속한다. (security_manager 는 쓰기 권한이 없어 읽기 전용 대시보드에 딱 맞다.)

참고: 이 환경의 plotly.express 는 xarray/구버전 numpy 충돌로 import 불가라
      plotly.graph_objects 로 직접 그린다.
"""

import decimal
import os

import bcrypt
import pandas as pd
import psycopg2
import plotly.graph_objects as go
import streamlit as st

# 로컬 trust 인증이라 비밀번호 불필요. 운영에서 비밀번호 인증으로 전환하면
# 코드에 넣지 말고 PGPASSWORD 환경변수나 ~/.pgpass(chmod 600) 로 주입한다.
DB_DSN = dict(
    dbname=os.environ.get("PGDATABASE", "security_db"),
    user=os.environ.get("SOC_DASHBOARD_DB_USER", "security_manager"),
)

SEV_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
SEV_COLORS = {"LOW": "#3BA55D", "MEDIUM": "#E3B341", "HIGH": "#E8833A", "CRITICAL": "#D64045", "N/A": "#9AA0A6"}
RISK_COLORS = {"LOW": "#3BA55D", "MEDIUM": "#E3B341", "HIGH": "#E8833A", "CRITICAL": "#D64045"}

st.set_page_config(page_title="security_db SOC 대시보드", layout="wide")

# =====================================================================
# 로그인 게이트 — DB 접속/쿼리가 실행되기 전에 여기서 차단한다.
#   · 앱 레벨 방어. DB 레벨 RBAC(security_manager)는 그대로 유지 → defense in depth.
#   · 비밀번호는 bcrypt 해시로만 비교. 해시는 SOC_DASHBOARD_AUTH_HASH 환경변수로만 주입.
#   · 해시 미설정 시 fail-closed (그냥 열어주지 않는다).
# =====================================================================
_AUTH_HASH = os.environ.get("SOC_DASHBOARD_AUTH_HASH")

if not _AUTH_HASH:
    st.error(
        "SOC_DASHBOARD_AUTH_HASH 환경변수가 설정되지 않았습니다 — 아래 명령으로 해시를 "
        "생성한 뒤 설정하세요:\n\n"
        "```\n"
        "python3 -c \"import bcrypt; print(bcrypt.hashpw(b'비밀번호', bcrypt.gensalt()).decode())\"\n"
        "export SOC_DASHBOARD_AUTH_HASH='<생성된 해시>'\n"
        "```"
    )
    st.stop()

if not st.session_state.get("authenticated", False):
    st.title("🛡️ SOC 대시보드 로그인")
    _pw = st.text_input("비밀번호", type="password")
    if _pw:
        try:
            _ok = bcrypt.checkpw(_pw.encode("utf-8"), _AUTH_HASH.encode("utf-8"))
        except ValueError:
            st.error("SOC_DASHBOARD_AUTH_HASH 형식이 올바르지 않습니다 (bcrypt 해시가 아님).")
            _ok = False
        if _ok:
            st.session_state["authenticated"] = True
            st.rerun()
        else:
            st.error("비밀번호가 올바르지 않습니다.")
    st.stop()

with st.sidebar:
    if st.button("로그아웃"):
        st.session_state.clear()
        st.rerun()


@st.cache_resource
def get_conn():
    conn = psycopg2.connect(**DB_DSN)
    conn.set_session(readonly=True, autocommit=True)
    return conn


def q(sql):
    with get_conn().cursor() as cur:
        cur.execute(sql)
        cols = [c[0] for c in cur.description]
        rows = cur.fetchall()
    return pd.DataFrame(rows, columns=cols)


_TABLE_CSS = (
    "<style>.soc-table{border-collapse:collapse;width:100%;font-size:13px;"
    "font-family:-apple-system,Segoe UI,sans-serif}"
    ".soc-table th,.soc-table td{border:1px solid #e4e6eb;padding:5px 9px;text-align:left;"
    "white-space:nowrap}.soc-table th{background:#f3f4f6;font-weight:600}"
    ".soc-table tr:nth-child(even){background:#fafbfc}</style>"
)


def show(df, **_):
    """이 환경은 pyarrow 21 + pandas 1.4 조합이라 st.dataframe(내부적으로 pa.Table.from_pandas)
    이 깨진다(Input object was not a NumPy array). 그래서 pyarrow 를 안 타는
    df.to_html() 로 정적 테이블을 렌더한다. (읽기 전용 대시보드라 정렬/필터 UI는 불필요)"""
    d = df.reset_index(drop=True).copy()
    for c in d.columns:
        if d[c].dtype == object:
            d[c] = d[c].apply(lambda v: "" if v is None else str(v))
    st.markdown(_TABLE_CSS + d.to_html(index=False, escape=True, border=0, classes="soc-table"),
                unsafe_allow_html=True)


def bar(x, y, colors, horizontal=False, height=340, text=None):
    fig = go.Figure()
    if horizontal:
        fig.add_bar(y=x, x=y, orientation="h", marker_color=colors,
                    text=text if text is not None else y, textposition="auto")
        fig.update_layout(yaxis=dict(autorange="reversed"))
    else:
        fig.add_bar(x=x, y=y, marker_color=colors,
                    text=text if text is not None else y, textposition="auto")
    fig.update_layout(height=height, margin=dict(t=10, b=10, l=10, r=10), showlegend=False)
    return fig


st.title("🛡️ security_db · SOC 대시보드")

# --------------------------------------------------- 사이드바: 합성(SIM) 데이터 필터
# 기본값 OFF(제외). 이유: 이 대시보드는 "실제 프로젝트 데이터"(ATT&CK 매핑·의도된 급증
# 시나리오가 있는 큐레이션된 이벤트)를 보여주는 게 1차 목적이다. 합성 이벤트는
# 파이프라인이 살아있음을 보여주는 스캐폴딩이라 vuln_id/ATT&CK 가 없어 e/f 섹션을
# "(미매핑)" 으로 희석시킨다. 데모에서 "피드가 흐른다"를 보이고 싶을 때만 켠다.
with st.sidebar:
    st.header("표시 옵션")
    include_sim = st.checkbox(
        "합성(시뮬레이션) 데이터 포함 보기", value=False,
        help="끄면 description / action_taken 이 '[SIM]' 로 시작하는 행을 "
             "모든 집계·차트·표에서 제외합니다.")
    try:
        _sim_e = int(q("SELECT count(*) c FROM security_events WHERE description LIKE '[SIM]%'")["c"][0])
        _sim_r = int(q("SELECT count(*) c FROM responses WHERE action_taken LIKE '[SIM]%'")["c"][0])
        st.caption(f"합성 이벤트 {_sim_e}건 / 대응 {_sim_r}건 · 현재 "
                   + (":green[**포함**]" if include_sim else ":orange[**제외**]"))
    except Exception:
        pass

# 필터 조각 (description 은 NULL 가능 → coalesce 필수)
_EVT = "" if include_sim else " AND coalesce(e.description,'') NOT LIKE '[SIM]%'"
_EVT_BARE = "" if include_sim else " AND coalesce(description,'') NOT LIKE '[SIM]%'"
_EVT_W = "" if include_sim else " WHERE coalesce(description,'') NOT LIKE '[SIM]%'"
# audit_log: 대상이 SIM 이벤트/대응인 변경행을 제외 (현재 SIM 행은 삭제 안 됨)
_AUD_W = "" if include_sim else (
    " WHERE NOT (table_name='security_events' AND row_pk::int IN "
    "(SELECT event_id FROM security_events WHERE description LIKE '[SIM]%'))"
    "   AND NOT (table_name='responses' AND row_pk::int IN "
    "(SELECT response_id FROM responses WHERE action_taken LIKE '[SIM]%'))")

st.caption(f"접속 계정: `security_manager` (RLS 우회 · 읽기 전용) · "
           f"합성데이터 {'포함' if include_sim else '제외'} · "
           f"새로고침 {pd.Timestamp.now():%Y-%m-%d %H:%M:%S}")

# ------------------------------------------------------------------ a. 요약 카드
open_events = int(q(f"SELECT count(*) c FROM security_events WHERE status='OPEN'{_EVT_BARE}")["c"][0])
crit_assets = int(q("SELECT count(*) c FROM vw_asset_risk_score WHERE risk_label='CRITICAL'")["c"][0])
new_24h = int(q(f"SELECT count(*) c FROM security_events WHERE detected_at >= now() - interval '24 hours'{_EVT_BARE}")["c"][0])
try:
    audit_changes = int(q(f"SELECT count(*) c FROM audit_log{_AUD_W}")["c"][0])
    audit_label = "감사로그 변경 건수(누적)"
except Exception:
    audit_changes, audit_label = -1, "감사로그(권한 없음)"

c1, c2, c3, c4 = st.columns(4)
c1.metric("미해결(OPEN) 이벤트", open_events)
c2.metric("CRITICAL 위험 자산", crit_assets)
c3.metric("최근 24h 신규 이벤트", new_24h)
c4.metric(audit_label, audit_changes)
st.divider()

# ------------------------------------------------------- b, f  심각도 / ATT&CK
colb, colf = st.columns(2)
with colb:
    st.subheader("b. 심각도별 이벤트 분포")
    df = q(f"SELECT severity, count(*) AS events FROM security_events{_EVT_W} GROUP BY severity")
    df = df.set_index("severity").reindex(SEV_ORDER).fillna(0).reset_index()
    st.plotly_chart(bar(df["severity"].tolist(), df["events"].astype(int).tolist(),
                        [SEV_COLORS[s] for s in df["severity"]]), use_container_width=True)
with colf:
    st.subheader("f. MITRE ATT&CK 전술별 이벤트 분포")
    df = q(f"""
        SELECT COALESCE(v.attack_tactic, '(미매핑)') AS tactic, count(*) AS events
        FROM security_events e
        LEFT JOIN vulnerabilities v ON v.vuln_id = e.vuln_id
        WHERE true{_EVT}
        GROUP BY 1 ORDER BY events DESC
    """)
    st.plotly_chart(bar(df["tactic"].tolist(), df["events"].astype(int).tolist(),
                        "#E8833A", horizontal=True), use_container_width=True)
st.divider()

# --------------------------------------------------------- c. 자산 위험도 Top N
st.subheader("c. 자산별 위험도 Top N (vw_asset_risk_score)")
topn = st.slider("Top N", 5, 14, 10)
df = q("""
    SELECT asset_name, department, importance_level, open_vuln_count,
           max_open_cvss, risk_score, risk_label
    FROM vw_asset_risk_score
    ORDER BY risk_score DESC, asset_name
""").head(topn).iloc[::-1]
st.plotly_chart(
    bar(df["asset_name"].tolist(), df["risk_score"].astype(float).tolist(),
        [RISK_COLORS[l] for l in df["risk_label"]], horizontal=True,
        height=max(300, 42 * len(df))),
    use_container_width=True)
st.caption("색상: 🟩 LOW · 🟨 MEDIUM · 🟧 HIGH · 🟥 CRITICAL  (risk_score = importance_level × 미해결 최대 CVSS)")
show(df.iloc[::-1], use_container_width=True, hide_index=True)
st.divider()

# ----------------------------------------------------------- d. 일별 이벤트 추이
st.subheader("d. 일별 이벤트 추이 (detected_at)")
df = q(f"""
    SELECT date_trunc('day', detected_at)::date AS day, count(*) AS events
    FROM security_events{_EVT_W} GROUP BY 1 ORDER BY 1
""")
fig = go.Figure(go.Scatter(x=df["day"], y=df["events"], mode="lines+markers",
                           line=dict(color="#4C78A8", width=2)))
fig.update_layout(height=320, margin=dict(t=10, b=10))
st.plotly_chart(fig, use_container_width=True)
st.caption("※ 급증 구간(결제API서버 2025-08-14=8건, 사내DB서버 2025-09-01=5건)이 피크로 나타남")
st.divider()

# ------------------------------------------- e. CVSS-심각도 불일치 (내부 + NVD)
st.subheader("e. CVSS · 심각도 불일치")
st.markdown("**e-1. vw_cvss_severity_mismatch** — 내부 점수(cvss_score) ↔ 라벨(severity) 정합성")
df1 = q("""
    SELECT source_table, record_id, ref_code, cvss_score,
           labeled_severity, expected_severity, severity_gap
    FROM vw_cvss_severity_mismatch
    ORDER BY severity_gap DESC, source_table, record_id
""")
show(df1)
st.caption(f"{len(df1)}건")
st.markdown("**e-2. vw_cvss_nvd_mismatch** — 우리 평가치 ↔ NVD 공식값 (severity 불일치 또는 CVSS 0.5+ 차이)")
df2 = q("""
    SELECT cve_id, our_cvss, our_severity, nvd_cvss, nvd_severity,
           nvd_cvss_version, cvss_abs_diff, severity_gap
    FROM vw_cvss_nvd_mismatch
    ORDER BY cvss_abs_diff DESC, severity_gap DESC
""")
show(df2)
st.caption(f"{len(df2)}건 · 출처: nvd_cve_details (NVD REST API 2.0)")
st.divider()

# ----------------------------------------- h. EPSS 우선순위 (CVSS × EPSS)
st.subheader("h. EPSS 악용확률 기반 우선순위 (CVSS × EPSS)")
st.caption("priority_score = cvss_score × epss_score  ·  EPSS = 향후 30일 내 악용 활동 관측 확률(FIRST.org)  ·  "
           "🔴 epss_over_cvss = CVSS 는 LOW/MEDIUM 인데 EPSS 백분위 상위 10%")
dfp = q("""
    SELECT cve_id, source, cvss_score AS cvss, cvss_severity, epss_score, epss_percentile,
           priority_score, epss_band, epss_over_cvss, open_on_assets
    FROM vw_priority_vulnerabilities
""")
colh1, colh2 = st.columns(2)
with colh1:
    st.markdown("**h-1. priority(CVSS×EPSS) 상위** — '실제 악용' 반영")
    top_p = dfp.sort_values("priority_score", ascending=False).head(8).copy()
    top_p.insert(0, "", top_p["epss_over_cvss"].map(lambda b: "🔴" if b else ""))
    show(top_p[["", "cve_id", "cvss", "cvss_severity", "epss_score",
               "epss_band", "priority_score", "open_on_assets"]])
with colh2:
    st.markdown("**h-2. CVSS 상위** — 같은 데이터, CVSS 만으로 정렬(대조군)")
    top_c = dfp.sort_values(["cvss", "priority_score"], ascending=False).head(8)
    show(top_c[["cve_id", "cvss", "cvss_severity", "epss_score",
                "priority_score", "epss_band"]])
n_over = int(dfp["epss_over_cvss"].sum()) if len(dfp) else 0
if n_over:
    gems = dfp[dfp["epss_over_cvss"]].sort_values("epss_percentile", ascending=False)
    lines = " · ".join(f"{r.cve_id}(CVSS {r.cvss} {r.cvss_severity}, EPSS 백분위 {r.epss_percentile:.3f})"
                       for r in gems.itertuples())
    st.warning(f"🔴 CVSS 로는 후순위지만 실제 악용 상위인 취약점 {n_over}건: {lines}")
else:
    st.info("현재 데이터에 'CVSS 낮음 + EPSS 상위 10%' 케이스 없음. (EPSS 미제공/저 EPSS)")
st.caption(f"{len(dfp)}건 · 출처: nvd_cve_details.epss_* (FIRST.org EPSS API) · KISA SCAN 행은 CVE 없어 제외")
st.divider()

# ------------------------------------------------------- g. 최근 감사 로그 20건
st.subheader("g. 최근 감사 로그 20건 (audit_log)")
try:
    dfa = q(f"""
        SELECT changed_at, table_name, operation, row_pk, changed_by
        FROM audit_log{_AUD_W} ORDER BY changed_at DESC, audit_id DESC LIMIT 20
    """)
    if dfa.empty:
        st.info("audit_log 가 비어 있습니다 (트리거는 활성).")
    else:
        show(dfa, use_container_width=True, height=420, hide_index=True)
except Exception as ex:
    st.warning(f"audit_log 조회 불가: {ex}")

st.divider()

# --------------------------------------------- i. 유사 사례 매칭 (수동 링크 vs 모델 자동 매칭)
st.subheader("i. 유사 사례 매칭 — 수동 연결(ground truth) vs 자동 매칭(모델 예측)")
st.caption("i-0 은 threat_reports.related_event_id 로 **사람이 직접 확인해 이어 둔** 이벤트↔리포트 "
           "쌍(정답). i-1/i-2 는 event_threat_linker.py 가 임베딩 코사인 유사도로 **모델이 알아서 "
           "찾아낸** 매칭(event_threat_matches). i-0 표의 '자동매칭 재현' 컬럼이 정답 대비 모델 재현율을 "
           "보여준다. PAST_EVENT 유사도가 THREAT_REPORT 보다 구조적으로 높게 나오는 경향이 있어(같은 "
           "이벤트 카탈로그 안에서 비교) i-1/i-2 를 각자 상위 N건으로 나눠서 보여준다.")

# ---- i-0. 수동 연결 (ground truth) ----
st.markdown("**i-0. 수동 연결 (ground truth)** — `threat_reports.related_event_id` 로 사람이 확인한 정답 쌍")
try:
    df_gt = q("""
        SELECT tr.report_id, tr.title AS report_title,
               tr.related_event_id AS event_id,
               left(coalesce(e.description,''), 55) AS event_description,
               e.detected_at,
               CASE WHEN EXISTS (
                   SELECT 1 FROM event_threat_matches m
                   WHERE m.match_type = 'THREAT_REPORT'
                     AND m.event_id = tr.related_event_id
                     AND m.matched_report_id = tr.report_id
               ) THEN 'O' ELSE 'X' END AS "자동매칭_재현"
        FROM threat_reports tr
        LEFT JOIN security_events e ON e.event_id = tr.related_event_id
        WHERE tr.related_event_id IS NOT NULL
        ORDER BY tr.report_id
    """)
    if df_gt.empty:
        st.caption("related_event_id 가 채워진 리포트가 없습니다.")
    else:
        show(df_gt, use_container_width=True, height=320, hide_index=True)
        _hit = int((df_gt["자동매칭_재현"] == "O").sum())
        st.caption(f"정답 {len(df_gt)}쌍 중 i-1(모델 자동매칭)이 같은 리포트를 잡아낸 건 "
                   f"**{_hit}건** (재현율 {_hit/len(df_gt)*100:.0f}%). "
                   "X 는 사람은 이었지만 모델이 임계값·TOP_K 안에서 못 찾은 쌍.")
except Exception as ex:
    st.warning(f"i-0 조회 불가: {ex}")

st.markdown("---")
st.markdown("**자동 매칭 (모델 예측)** — 아래 i-1/i-2 는 `event_threat_matches` (모델이 찾아낸 것)")


def _etm_query(match_type, limit):
    return q(f"""
        SELECT m.event_id, e.detected_at, e.severity AS event_severity,
               left(coalesce(e.description,''), 60) AS event_description,
               CASE WHEN m.match_type = 'THREAT_REPORT' THEN m.matched_report_title
                    ELSE left(coalesce(m.matched_event_description,''), 60) END AS matched_with,
               round(m.similarity, 3) AS similarity
        FROM vw_event_threat_matches m
        JOIN security_events e ON e.event_id = m.event_id
        {_EVT_W}{" AND" if _EVT_W else " WHERE"} m.match_type = '{match_type}'
        ORDER BY m.similarity DESC
        LIMIT {limit}
    """)


try:
    df_report = _etm_query("THREAT_REPORT", 15)
    df_past = _etm_query("PAST_EVENT", 15)

    if df_report.empty and df_past.empty:
        st.info("아직 저장된 매칭이 없습니다. `python3 scripts/event_threat_linker.py` 를 먼저 실행하세요 "
                "(launchd 로 자동화하려면 `com.security-db.threatlink.plist`, 10분 주기).")
    else:
        st.markdown("**i-1. THREAT_REPORT** — 과거 위협 인텔리전스 리포트와의 매칭")
        if df_report.empty:
            st.caption("매칭 없음 (임계값 미만이거나 threat_reports 와 무관한 이벤트뿐).")
        else:
            show(df_report, use_container_width=True, height=300, hide_index=True)
            st.caption(f"상위 {len(df_report)}건 (유사도순)")

        st.markdown("**i-2. PAST_EVENT** — 이미 임베딩된 다른 이벤트와의 매칭 (반복/유사 패턴 탐지)")
        if df_past.empty:
            st.caption("매칭 없음.")
        else:
            show(df_past, use_container_width=True, height=300, hide_index=True)
            st.caption(f"상위 {len(df_past)}건 (유사도순) · 유사도 0.9+ 는 서로 다른 자산에서 같은 "
                       "공격 패턴이 반복됐다는 신호(실제 캠페인일 수도, 합성 데이터라면 템플릿 재사용일 수도). "
                       "V035(ko-sroberta) 이후 문장 평탄화로 인한 유사도 1.000 인위적 중복은 없음.")
except Exception as ex:
    st.warning(f"event_threat_matches 조회 불가 (V033 마이그레이션 적용 여부 확인): {ex}")
st.divider()

# ------------------------------------------- j. FDS 이상거래 탐지 (fds-integration 브랜치)
#   FDS 프로젝트(~/fds)가 같은 DB 의 fds 스키마에 저장한 채점 결과를 보여준다.
#   보안 이벤트(FRAUD_SUSPECT)는 위 b·d 집계에도 포함되고, 알림은 실행별 요약 1건(V039).
#   fds 스키마가 없는 DB(과제 원본)에서는 안내만 표시.
st.subheader("j. FDS 이상거래 탐지 — 경보 대기열 · 시간대별 성능 · 기준점 점검")
try:
    _has_fds = bool(q("SELECT to_regclass('fds.alert_events') IS NOT NULL AS ok")["ok"][0])
except Exception:
    _has_fds = False
if not _has_fds:
    st.caption("이 DB 에는 FDS 연동(fds 스키마 + V038/V039)이 없습니다.")
else:
    try:
        runs = q("""
            SELECT r.run_id, r.finished_at, r.threshold, r.code_version,
                   (SELECT count(*) FROM fds.alert_events ae WHERE ae.run_id = r.run_id) AS events
            FROM fds.model_runs r WHERE r.finished_at IS NOT NULL ORDER BY r.run_id DESC
        """)
        if runs.empty:
            st.caption("끝난 채점 실행이 없습니다.")
        else:
            _labels = {int(r.run_id): f"run {int(r.run_id)} · {r.finished_at:%m-%d %H:%M} · 코드 {r.code_version}"
                                       + ("" if r.events else " · 보안 이벤트 연동 전")
                       for r in runs.itertuples()}
            run_id = st.selectbox("채점 실행", list(_labels), format_func=_labels.get)   # 정수만 SQL 에 들어감
            _run = runs.set_index("run_id").loc[run_id]

            # j-0 요약 카드: 실행 전체 성능(vw_run_performance 의 ROLLUP 합계 행) + 이벤트 심각도
            perf = q(f"SELECT * FROM fds.vw_run_performance WHERE run_id = {int(run_id)} ORDER BY hour_since_start NULLS LAST")
            tot = perf[perf["hour_since_start"].isna()].iloc[0]
            sev = q(f"SELECT severity, count(*) c FROM fds.alert_events WHERE run_id = {int(run_id)} GROUP BY 1")
            _sev = dict(zip(sev["severity"], sev["c"].astype(int)))
            m1, m2, m3, m4, m5 = st.columns(5)
            m1.metric("채점 거래", f"{int(tot['scored']):,}")
            m2.metric("경보", int(tot["alerts"]),
                      help="보안 이벤트 연동 후 실행이면 경보 1건 = FRAUD_SUSPECT 이벤트 1건")
            m3.metric("CRITICAL / HIGH 이벤트", f"{_sev.get('CRITICAL', 0)} / {_sev.get('HIGH', 0)}")
            m4.metric("재현율 (확정 라벨)", f"{float(tot['recall']):.1%}",
                      help="사기 중 경보로 잡은 비율. 라벨이 확정된 거래 기준 사후 평가")
            m5.metric("정밀도 / 오경보", f"{float(tot['precision']):.1%} / {int(tot['false_alerts'])}건")
            st.caption(f"기준점 {float(_run['threshold']):.4f} (학습 구간 안쪽 교차검증으로 재현율 80% 목표) · "
                       "재현율·정밀도는 사기 라벨이 확정된 뒤에만 계산 가능")

            # j-1 경보 대기열 + 연결된 보안 이벤트 상태 (표가 넓어서 전체 폭)
            st.markdown("**j-1. 경보 대기열** (점수 순 · 판단 근거 = 사기 쪽으로 민 특성 상위 3개, SHAP)")
            dq = q(f"""
                SELECT a.queue_rank AS "순위", a.txn_id AS "거래", a.score AS "점수",
                       a.amount AS "금액", ae.severity AS "심각도", ae.event_id AS "이벤트",
                       e.status AS "처리상태", a.reasons_text AS "판단 근거"
                FROM fds.vw_alert_queue a
                LEFT JOIN fds.alert_events ae ON ae.run_id = a.run_id AND ae.txn_id = a.txn_id
                LEFT JOIN security_events e ON e.event_id = ae.event_id
                WHERE a.run_id = {int(run_id)}
                ORDER BY a.queue_rank LIMIT 20
            """)
            show(dq)
            st.caption(f"상위 {len(dq)}건 / 전체 경보 {int(tot['alerts'])}건 · 라벨(정답)은 표시하지 않음(운영 화면)")

            colj2, colj3 = st.columns(2)
            with colj2:
                # j-2 시간대별 재현율
                st.markdown("**j-2. 시간대별 재현율** (막대 위: 잡은 사기 / 전체 사기)")
                ph = perf[perf["hour_since_start"].notna()]
                _rec = [float(v) if v is not None else 0.0 for v in ph["recall"]]
                st.plotly_chart(bar([f"{int(h)}h" for h in ph["hour_since_start"]], _rec,
                                    ["#D64045" if r < 0.5 else "#E8833A" if r < 0.7 else "#3BA55D" for r in _rec],
                                    height=300,
                                    text=[f"{int(t)}/{int(f)}" for t, f in zip(ph["true_alerts"], ph["frauds"])]),
                                use_container_width=True)
                st.caption("시간대마다 사기가 몇 건뿐이라 한두 건으로 크게 출렁임 — 단독으로 성능 저하를 판단하지 말 것")
            with colj3:
                # j-3 기준점 점검: 목표 재현율을 맞추려면 기준점·경보·오경보가 어떻게 되나
                st.markdown("**j-3. 기준점 점검** — 확정 라벨로 보니, 목표 재현율을 맞추려면?")
                target = st.slider("목표 재현율", 0.60, 0.95, 0.80, 0.05)
                tc = q(f"SELECT * FROM fds.threshold_check({float(target):.2f}) WHERE run_id = {int(run_id)}")
                if tc.empty:
                    st.caption("계산할 수 없음 (라벨 확정된 사기 없음)")
                else:
                    t = tc.iloc[0]
                    k1, k2, k3 = st.columns(3)
                    k1.metric("필요한 기준점", f"{float(t['needed_threshold']):.4f}",
                              help=f"현재 기준점 {float(t['current_threshold']):.4f}")
                    k2.metric("경보 수", int(t["needed_alerts"]),
                              delta=int(t["needed_alerts"]) - int(t["current_alerts"]), delta_color="inverse")
                    k3.metric("오경보 수", int(t["needed_false_alerts"]),
                              delta=int(t["needed_false_alerts"]) - int(t["current_false_alerts"]), delta_color="inverse")
                    st.caption(f"현재 기준점 {float(t['current_threshold']):.4f} · 재현율 {float(t['current_recall']):.1%} "
                               f"→ 목표 {float(target):.0%}. 오경보가 급증하는 구간('절벽')이 있으면 "
                               "기준점을 그 앞에서 멈추는 것이 운영상 현실적")
    except Exception as ex:
        st.warning(f"FDS 섹션 조회 불가 (권한·F001~F003 적용 여부 확인): {ex}")
st.divider()

# ------------------------------------------- 부록. NVD 신규 CVE 워치 후보
with st.expander("부록 · NVD 신규 CVE 워치 후보 (nvd_watch_candidates)"):
    try:
        dfw = q("""
            SELECT cve_id, matched_keywords, nvd_cvss_score, nvd_severity,
                   nvd_published_date::date AS published, review_status
            FROM nvd_watch_candidates ORDER BY nvd_cvss_score DESC NULLS LAST
        """)
        show(dfw, use_container_width=True, height=300, hide_index=True)
        st.caption(f"{len(dfw)}건 · 분석가 검토 큐 (자동 병합 안 함)")
    except Exception as ex:
        st.warning(f"nvd_watch_candidates 조회 불가: {ex}")

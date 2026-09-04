import pathlib
from playwright.sync_api import sync_playwright

OUT = pathlib.Path(__file__).resolve().parent.parent / "screenshots"; OUT.mkdir(exist_ok=True)

with sync_playwright() as p:
    browser = p.chromium.launch(channel="chrome", headless=True, args=["--no-sandbox"])
    page = browser.new_page(viewport={"width": 1600, "height": 5600}, device_scale_factor=2)
    page.set_default_timeout(25000)
    page.goto("http://localhost:8502/", wait_until="domcontentloaded", timeout=30000)
    page.wait_for_selector('[data-testid="stAppViewContainer"]', timeout=25000)
    try:
        page.wait_for_selector('.soc-table', timeout=25000)
    except Exception as e:
        print("warn soc-table:", e)
    page.wait_for_timeout(8000)

    # 전체 (긴 뷰포트 한 장)
    page.screenshot(path=str(OUT / "soc_dashboard_full.png"))
    print("OK full (tall viewport)")

    # 섹션별
    for fname, heading in [
        ("a_summary_cards", "security_db · SOC 대시보드"),
        ("b_f_severity_attack", "b. 심각도별 이벤트 분포"),
        ("c_asset_risk", "c. 자산별 위험도 Top N"),
        ("d_daily_trend", "d. 일별 이벤트 추이"),
        ("e_mismatch", "e. CVSS · 심각도 불일치"),
        ("g_audit_log", "g. 최근 감사 로그 20건"),
    ]:
        try:
            page.set_viewport_size({"width": 1600, "height": 1400})
            loc = page.get_by_role("heading", name=heading, exact=False).first
            loc.scroll_into_view_if_needed(timeout=8000)
            page.wait_for_timeout(1200)
            page.screenshot(path=str(OUT / f"soc_{fname}.png"))
            print("OK", fname)
        except Exception as e:
            print("skip", fname, repr(e))
    browser.close()
print("DONE")

#!/usr/bin/env python3
"""
alert_notifier.py — 여러 채널로 알림을 시도하는 모듈 (+ CLI).

채널 (있는 것만, 순서대로 시도 — 하나 실패해도 다음 진행):
  1. macOS 네이티브 알림  (osascript display notification) — 기본, 외부 의존 없음
  2. Slack Incoming Webhook — 환경변수 SLACK_WEBHOOK_URL 있으면
  3. 이메일(SMTP)         — 환경변수 ALERT_SMTP_HOST / ALERT_SMTP_PORT / ALERT_SMTP_USER /
                             ALERT_SMTP_PASS / ALERT_SMTP_FROM / ALERT_SMTP_TO 있으면
어떤 채널을 썼든 항상 logs/alerts.log 에 기록한다.

프로그램에서:
    from alert_notifier import notify
    channels = notify("제목", "본문", subtitle="...", url="...")   # 실제 발송된 채널 리스트 반환

CLI:
    python3 scripts/alert_notifier.py --title "T" --message "M" [--subtitle S] [--url U]
"""
import argparse
import datetime as dt
import json
import logging
import os
import smtplib
import subprocess
import sys
from email.mime.text import MIMEText
from logging.handlers import RotatingFileHandler
from pathlib import Path

PROJ = Path(__file__).resolve().parent.parent
LOG_DIR = PROJ / "logs"
ALERT_LOG = LOG_DIR / "alerts.log"

# logs/alerts.log 에 항상 기록하되 무한 append 되지 않도록 5MB 씩 5개까지 회전한다
# (alerts.log, alerts.log.1 ... alerts.log.5). 라인 포맷/내용은 기존과 동일하게 유지.
LOG_DIR.mkdir(exist_ok=True)
_logger = logging.getLogger("alert_notifier")
_logger.setLevel(logging.INFO)
_logger.propagate = False
if not _logger.handlers:
    _h = RotatingFileHandler(ALERT_LOG, maxBytes=5_000_000, backupCount=5, encoding="utf-8")
    _h.setFormatter(logging.Formatter("%(message)s"))  # 타임스탬프는 메시지에 이미 포함
    _logger.addHandler(_h)


def _log(line):
    _logger.info(line)


def _macos(title, message, subtitle=None):
    if sys.platform != "darwin":
        return False
    # osascript 문자열 이스케이프 (따옴표/역슬래시)
    def esc(s):
        return (s or "").replace("\\", "\\\\").replace('"', '\\"')
    script = f'display notification "{esc(message)}" with title "{esc(title)}"'
    if subtitle:
        script += f' subtitle "{esc(subtitle)}"'
    script += ' sound name "Ping"'
    try:
        r = subprocess.run(["osascript", "-e", script], capture_output=True, text=True, timeout=10)
        return r.returncode == 0
    except Exception:
        return False


def _slack(title, message, url=None):
    hook = os.environ.get("SLACK_WEBHOOK_URL", "").strip()
    if not hook:
        return False
    try:
        import requests
    except ImportError:
        return False
    text = f"*{title}*\n{message}" + (f"\n<{url}|열기>" if url else "")
    try:
        r = requests.post(hook, json={"text": text}, timeout=10)
        return r.status_code // 100 == 2
    except Exception:
        return False


def _email(title, message):
    host = os.environ.get("ALERT_SMTP_HOST", "").strip()
    to = os.environ.get("ALERT_SMTP_TO", "").strip()
    if not host or not to:
        return False
    port = int(os.environ.get("ALERT_SMTP_PORT", "587"))
    user = os.environ.get("ALERT_SMTP_USER", "")
    pw = os.environ.get("ALERT_SMTP_PASS", "")
    frm = os.environ.get("ALERT_SMTP_FROM", user or "security-db@localhost")
    try:
        msg = MIMEText(message, "plain", "utf-8")
        msg["Subject"] = title
        msg["From"] = frm
        msg["To"] = to
        with smtplib.SMTP(host, port, timeout=15) as s:
            s.ehlo()
            try:
                s.starttls()
                s.ehlo()
            except Exception:
                pass
            if user:
                s.login(user, pw)
            s.sendmail(frm, [a.strip() for a in to.split(",")], msg.as_string())
        return True
    except Exception:
        return False


def notify(title, message, subtitle=None, url=None):
    """가능한 모든 채널로 알림. 실제 발송에 성공한 채널 이름 리스트 반환."""
    used = []
    if _macos(title, message, subtitle):
        used.append("macos")
    if _slack(title, message, url):
        used.append("slack")
    if _email(title, f"{message}" + (f"\n\n{url}" if url else "")):
        used.append("email")

    ts = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    _log(f"{ts}  channels={','.join(used) or 'NONE'}  title={title!r}  msg={message!r}")
    return used


def main():
    ap = argparse.ArgumentParser(description="알림 발송 (여러 채널 시도)")
    ap.add_argument("--title", required=True)
    ap.add_argument("--message", required=True)
    ap.add_argument("--subtitle", default=None)
    ap.add_argument("--url", default=None)
    a = ap.parse_args()
    used = notify(a.title, a.message, subtitle=a.subtitle, url=a.url)
    print(f"발송 채널: {', '.join(used) or '(없음)'}   로그: {ALERT_LOG}")
    return 0 if used else 1


if __name__ == "__main__":
    sys.exit(main())

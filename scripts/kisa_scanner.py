#!/usr/bin/env python3
"""
KISA 주요정보통신기반시설 기술적 취약점 분석·평가 - 리눅스 서버 진단 스크립트
대상 항목: U-01 ~ U-72 (전체)
생성 기준: KISA 상세가이드 (리눅스 서버 편)

주의:
  - 본 스크립트는 진단 전용이며 시스템 설정을 절대 변경하지 않습니다.
  - root 권한으로 실행을 권장합니다 (일부 항목은 /etc/shadow 등 root 전용 파일을 읽어야 합니다).
  - Linux가 아닌 환경(macOS/Darwin 등)에서 실행하면 systemctl / PAM / xinetd / SELinux /
    NIS / RPC 등 Linux 전용 메커니즘에 의존하는 항목은 자동으로 "해당없음(비Linux)"으로
    표시되고, 나머지는 파일이 없으면 자연스럽게 "점검불가"로 표시됩니다. 정확한 진단이
    필요하면 실제 Linux 서버/컨테이너/VM에서 실행하십시오.
"""
import os
import re
import csv
import json
import logging
import subprocess
import datetime
import socket
import platform
import argparse
import sys
from dataclasses import dataclass, asdict
from typing import Optional, List, Dict

logger = logging.getLogger("KISA-Scanner")


@dataclass
class CheckResult:
    item_code: str
    item_name: str
    result: str  # "양호" | "취약" | "점검불가"
    current_setting: str
    recommendation: str


class SecurityScanner:
    def __init__(self, output_dir=".", fmt="both", verbose=False):
        self.output_dir = output_dir
        self.fmt = fmt
        self.results = []  # type: List[CheckResult]
        self._large_files_written = []  # type: List[str]

        self.is_root = hasattr(os, "geteuid") and os.geteuid() == 0
        self.platform_name = platform.system()  # 'Linux' | 'Darwin' | 'Windows' 등
        self.is_linux = self.platform_name == "Linux"

        if not self.is_root:
            logger.warning("root 권한으로 실행되지 않았습니다. 일부 항목은 '점검불가'로 표시됩니다.")
        if not self.is_linux:
            logger.warning(
                "Linux 환경이 아닙니다(%s). systemctl/PAM/xinetd/NIS/RPC 등 Linux 전용 항목은 "
                "'해당없음(비Linux)'으로 표시됩니다. 정확한 진단은 실제 Linux 대상에서 실행하세요.",
                self.platform_name,
            )

        self.distro = self._detect_distro()

    # =========================================================
    # 헬퍼
    # =========================================================
    def _run_cmd(self, cmd):
        # type: (List[str]) -> Optional[str]
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if out.returncode != 0 and not out.stdout:
                logger.debug("명령어 실패(%s): rc=%s stderr=%s", cmd, out.returncode, out.stderr[:200])
            return out.stdout.strip()
        except FileNotFoundError:
            logger.debug("명령어 없음: %s", cmd)
            return None
        except Exception as e:
            logger.debug("명령어 실행 실패 %s: %s", cmd, e)
            return None

    def _read_file(self, path):
        # type: (str) -> Optional[str]
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                return f.read()
        except (FileNotFoundError, PermissionError, IsADirectoryError) as e:
            logger.debug("%s 읽기 실패: %s", path, e)
            return None
        except Exception as e:
            logger.debug("%s 읽기 중 예상치 못한 오류: %s", path, e)
            return None

    def _first_existing(self, paths):
        # type: (List[str]) -> Optional[str]
        for p in paths:
            if os.path.exists(p):
                return p
        return None

    def _file_perm(self, path):
        # type: (str) -> Optional[str]
        try:
            return oct(os.stat(path).st_mode)[-3:]
        except (FileNotFoundError, PermissionError):
            return None
        except Exception:
            return None

    def _file_owner_uid(self, path):
        # type: (str) -> Optional[int]
        try:
            return os.stat(path).st_uid
        except (FileNotFoundError, PermissionError):
            return None
        except Exception:
            return None

    def _file_owner_is_root(self, path):
        # type: (str) -> Optional[bool]
        uid = self._file_owner_uid(path)
        if uid is None:
            return None
        return uid == 0

    def _service_is_active(self, name):
        # type: (str) -> Optional[bool]
        if not self.is_linux:
            return None
        out = self._run_cmd(["systemctl", "is-active", name])
        if out is not None and out != "":
            return out.strip() == "active"
        out = self._run_cmd(["service", name, "status"])
        if out is None:
            return None
        low = out.lower()
        if "running" in low or "active" in low:
            return True
        if "stopped" in low or "not running" in low or "inactive" in low:
            return False
        return None

    def _detect_distro(self):
        # type: () -> Dict[str, object]
        if not self.is_linux:
            return {
                "family": "non-linux",
                "pretty_name": self.platform_name,
                "pam_auth_file": None,
                "pam_password_file": None,
                "package_manager": None,
            }
        content = self._read_file("/etc/os-release") or ""
        pretty = "unknown"
        m = re.search(r'^PRETTY_NAME="?([^"\n]+)"?', content, re.MULTILINE)
        if m:
            pretty = m.group(1)
        low = content.lower()
        if any(k in low for k in ("rhel", "centos", "rocky", "fedora", "almalinux")):
            family = "rhel"
        elif any(k in low for k in ("debian", "ubuntu")):
            family = "debian"
        else:
            family = "unknown"

        if family == "rhel":
            pam_auth = self._first_existing(["/etc/pam.d/system-auth", "/etc/pam.d/password-auth"])
            pam_pass = pam_auth
            pkg = "dnf" if self._run_cmd(["which", "dnf"]) else "yum"
        elif family == "debian":
            pam_auth = "/etc/pam.d/common-auth" if os.path.exists("/etc/pam.d/common-auth") else None
            pam_pass = "/etc/pam.d/common-password" if os.path.exists("/etc/pam.d/common-password") else None
            pkg = "apt"
        else:
            pam_auth = self._first_existing(
                ["/etc/pam.d/system-auth", "/etc/pam.d/common-auth", "/etc/pam.d/password-auth"]
            )
            pam_pass = self._first_existing(["/etc/pam.d/system-auth", "/etc/pam.d/common-password"])
            pkg = None

        return {
            "family": family,
            "pretty_name": pretty,
            "pam_auth_file": pam_auth,
            "pam_password_file": pam_pass,
            "package_manager": pkg,
        }

    def _all_accounts(self):
        # type: () -> List[Dict[str, object]]
        content = self._read_file("/etc/passwd")
        accounts = []
        if not content:
            return accounts
        for line in content.splitlines():
            if not line.strip() or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) < 7:
                continue
            try:
                accounts.append(
                    {
                        "name": parts[0],
                        "uid": int(parts[2]),
                        "gid": int(parts[3]),
                        "home": parts[5],
                        "shell": parts[6],
                    }
                )
            except ValueError:
                continue
        return accounts

    def _all_groups(self):
        # type: () -> List[Dict[str, object]]
        content = self._read_file("/etc/group")
        groups = []
        if not content:
            return groups
        for line in content.splitlines():
            if not line.strip() or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) < 4:
                continue
            try:
                groups.append({"name": parts[0], "gid": int(parts[2]), "members": [m for m in parts[3].split(",") if m]})
            except ValueError:
                continue
        return groups

    def _truncated(self, items, item_code, preview=20):
        # type: (List[str], str, int) -> str
        total = len(items)
        if total == 0:
            return "0건 발견"
        preview_items = items[:preview]
        summary = "총 {}건 발견 (상위 {}건 표시: {})".format(total, min(preview, total), "; ".join(preview_items))
        if total > preview:
            ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            fname = os.path.join(self.output_dir, "kisa_{}_full_list_{}.txt".format(item_code.lower(), ts))
            try:
                with open(fname, "w", encoding="utf-8") as f:
                    f.write("\n".join(items))
                self._large_files_written.append(fname)
                summary += " | 전체 목록: {}".format(fname)
            except Exception as e:
                logger.debug("전체 목록 파일 저장 실패: %s", e)
        return summary

    def _na(self, item_code, item_name, reason="해당없음(비Linux)"):
        return CheckResult(item_code, item_name, "점검불가", reason, "실제 Linux 대상 서버/컨테이너에서 재점검 필요")

    def _find_walk(self, roots, predicate, prune_virtual=True):
        # type: (List[str], "callable", bool) -> List[str]
        """-xdev 없이 실 파티션까지 포함해 탐색하되 /proc, /sys 등 가상 FS는 제외."""
        virtual = {"/proc", "/sys", "/dev", "/run"}
        hits = []
        for root in roots:
            for dirpath, dirnames, filenames in os.walk(root, onerror=lambda e: None):
                if prune_virtual and dirpath in virtual:
                    dirnames[:] = []
                    continue
                dirnames[:] = [d for d in dirnames if os.path.join(dirpath, d) not in virtual]
                for fname in filenames:
                    full = os.path.join(dirpath, fname)
                    try:
                        if predicate(full):
                            hits.append(full)
                    except (OSError, PermissionError):
                        continue
        return hits

    # =========================================================
    # 계정 관리
    # =========================================================
    def check_u01_root_remote_access(self):
        code, name = "U-01", "root 계정 원격 접속 제한"
        try:
            content = self._read_file("/etc/ssh/sshd_config")
            if content is None:
                return CheckResult(code, name, "점검불가", "sshd_config 접근 불가", "SSH 설정 파일 확인 필요")
            m = re.search(r"^\s*PermitRootLogin\s+(\S+)", content, re.MULTILINE | re.IGNORECASE)
            current = m.group(1) if m else "설정 없음(배포판 기본값 확인 필요, 보통 prohibit-password 또는 yes)"
            result = "양호" if (m and m.group(1).lower() == "no") else "취약"
            return CheckResult(
                code, name, result, "PermitRootLogin {}".format(current),
                "/etc/ssh/sshd_config 에서 'PermitRootLogin no' 설정 후 sshd 재시작 권고 "
                "(prohibit-password는 패스워드 인증만 차단, 완전 차단 아님에 유의)",
            )
        except Exception as e:
            logger.exception("%s 점검 중 오류", code)
            return CheckResult(code, name, "점검불가", "오류: {}".format(e), "수동 점검 필요")

    def check_u02_password_complexity(self):
        code, name = "U-02", "패스워드 복잡성 설정"
        try:
            if not self.is_linux:
                return self._na(code, name)
            candidates = [self.distro.get("pam_password_file"), "/etc/security/pwquality.conf"]
            found = []
            settings = {}
            for path in candidates:
                if not path:
                    continue
                content = self._read_file(path)
                if content is None:
                    continue
                found.append(path)
                for key in ("minlen", "dcredit", "ucredit", "lcredit", "ocredit"):
                    m = re.search(r"^\s*{}\s*=\s*(-?\d+)".format(key), content, re.MULTILINE)
                    if m:
                        settings[key] = int(m.group(1))
            if not found:
                return CheckResult(code, name, "점검불가", "pwquality/PAM 설정 파일 접근 불가", "PAM 설정 확인 필요")
            minlen = settings.get("minlen", 0)
            combo = sum(1 for k in ("dcredit", "ucredit", "lcredit", "ocredit") if settings.get(k, 0) < 0)
            ok = (combo >= 3 and minlen >= 8) or (combo >= 2 and minlen >= 10)
            return CheckResult(
                code, name, "양호" if ok else "취약",
                "파일: {} / minlen={} / 조합종류={}".format(", ".join(found), minlen, combo),
                "3종류 이상 조합 시 8자리 이상, 2종류 조합 시 10자리 이상 강제 설정 권고",
            )
        except Exception as e:
            logger.exception("%s 점검 중 오류", code)
            return CheckResult(code, name, "점검불가", "오류: {}".format(e), "수동 점검 필요")

    def check_u03_account_lockout(self):
        code, name = "U-03", "계정 잠금 임계값 설정"
        try:
            if not self.is_linux:
                return self._na(code, name)
            candidates = [self.distro.get("pam_auth_file"), "/etc/security/faillock.conf"]
            found = []
            deny = None
            for path in candidates:
                if not path:
                    continue
                content = self._read_file(path)
                if content is None:
                    continue
                found.append(path)
                m = re.search(r"deny\s*=\s*(\d+)", content)
                if m:
                    deny = int(m.group(1))
            if not found:
                return CheckResult(code, name, "점검불가", "PAM 파일 접근 불가", "PAM 설정 확인 필요")
            if deny is None:
                return CheckResult(code, name, "취약", "잠금 임계값(deny) 미설정: {}".format(", ".join(found)), "deny=5 이하로 설정 권고")
            return CheckResult(
                code, name, "양호" if deny <= 5 else "취약",
                "deny={} ({})".format(deny, ", ".join(found)), "실패 임계값 5회 이하 권고",
            )
        except Exception as e:
            logger.exception("%s 점검 중 오류", code)
            return CheckResult(code, name, "점검불가", "오류: {}".format(e), "수동 점검 필요")

    def check_u04_shadow_password_used(self):
        code, name = "U-04", "패스워드 파일 보호(shadow 사용)"
        try:
            content = self._read_file("/etc/passwd")
            if content is None:
                return CheckResult(code, name, "점검불가", "/etc/passwd 접근 불가", "파일 확인 필요")
            bad = []
            for line in content.splitlines():
                parts = line.split(":")
                if len(parts) < 2:
                    continue
                if parts[1] != "x" and parts[1] != "*":
                    bad.append(parts[0])
            result = "양호" if not bad else "취약"
            setting = "모든 계정 shadow 체계 사용 중" if not bad else "평문/구식 패스워드 필드 계정: {}".format(", ".join(bad))
            return CheckResult(code, name, result, setting, "/etc/passwd 2번째 필드를 'x'로, 실제 해시는 /etc/shadow에 보관")
        except Exception as e:
            logger.exception("%s 점검 중 오류", code)
            return CheckResult(code, name, "점검불가", "오류: {}".format(e), "수동 점검 필요")

    def check_u44_uid_zero_only_root(self):
        code, name = "U-44", "root 이외 UID '0' 금지"
        try:
            accounts = self._all_accounts()
            if not accounts:
                return CheckResult(code, name, "점검불가", "/etc/passwd 접근 불가", "계정 목록 확인 필요")
            bad = [a["name"] for a in accounts if a["uid"] == 0 and a["name"] != "root"]
            result = "양호" if not bad else "취약"
            return CheckResult(code, name, result, "UID 0 계정: {}".format(bad if bad else ["root"]), "root 외 UID 0 계정 제거 권고")
        except Exception as e:
            logger.exception("%s 점검 중 오류", code)
            return CheckResult(code, name, "점검불가", "오류: {}".format(e), "수동 점검 필요")

    def check_u45_root_su_restriction(self):
        code, name = "U-45", "root 계정 su 제한"
        try:
            if not self.is_linux:
                return self._na(code, name)
            content = self._read_file("/etc/pam.d/su")
            if content is None:
                return CheckResult(code, name, "점검불가", "/etc/pam.d/su 접근 불가", "PAM su 설정 확인 필요")
            has_wheel = bool(re.search(r"pam_wheel\.so.*use_uid", content))
            groups = self._all_groups()
            wheel = next((g for g in groups if g["name"] == "wheel"), None)
            members = wheel["members"] if wheel else []
            result = "양호" if has_wheel else "취약"
            return CheckResult(
                code, name, result, "pam_wheel use_uid={} / wheel 그룹 구성원={}".format(has_wheel, members),
                "/etc/pam.d/su 에 'auth required pam_wheel.so use_uid' 추가 및 wheel 그룹 최소화 권고",
            )
        except Exception as e:
            logger.exception("%s 점검 중 오류", code)
            return CheckResult(code, name, "점검불가", "오류: {}".format(e), "수동 점검 필요")

    def check_u46_password_min_length(self):
        code, name = "U-46", "패스워드 최소 길이 설정"
        try:
            content = self._read_file("/etc/login.defs")
            if content is None:
                return CheckResult(code, name, "점검불가", "/etc/login.defs 접근 불가(macOS는 해당 파일 없음)", "PAM minlen(U-02)과 함께 판단 필요")
            m = re.search(r"^\s*PASS_MIN_LEN\s+(\d+)", content, re.MULTILINE)
            val = int(m.group(1)) if m else None
            if val is None:
                return CheckResult(code, name, "점검불가", "PASS_MIN_LEN 미설정", "PAM minlen(U-02) 기준으로 판단 필요")
            return CheckResult(code, name, "양호" if val >= 8 else "취약", "PASS_MIN_LEN={}".format(val), "최소 8자리 이상 권고")
        except Exception as e:
            logger.exception("%s 점검 중 오류", code)
            return CheckResult(code, name, "점검불가", "오류: {}".format(e), "수동 점검 필요")

    def check_u47_password_max_days(self):
        code, name = "U-47", "패스워드 최대 사용기간 설정"
        try:
            content = self._read_file("/etc/login.defs")
            if content is None:
                return CheckResult(code, name, "점검불가", "/etc/login.defs 접근 불가", "파일 확인 필요")
            m = re.search(r"^\s*PASS_MAX_DAYS\s+(\d+)", content, re.MULTILINE)
            val = int(m.group(1)) if m else None
            if val is None:
                return CheckResult(code, name, "점검불가", "PASS_MAX_DAYS 미설정", "조직 정책에 따라 설정 필요")
            note = "NIST 800-63B 등 최신 지침은 강제 주기 변경 폐지를 권고하는 추세 - 조직 정책 우선"
            return CheckResult(code, name, "양호" if val <= 90 else "취약", "PASS_MAX_DAYS={}".format(val), note)
        except Exception as e:
            logger.exception("%s 점검 중 오류", code)
            return CheckResult(code, name, "점검불가", "오류: {}".format(e), "수동 점검 필요")

    def check_u48_password_min_days(self):
        code, name = "U-48", "패스워드 최소 사용기간 설정"
        try:
            content = self._read_file("/etc/login.defs")
            if content is None:
                return CheckResult(code, name, "점검불가", "/etc/login.defs 접근 불가", "파일 확인 필요")
            m = re.search(r"^\s*PASS_MIN_DAYS\s+(\d+)", content, re.MULTILINE)
            val = int(m.group(1)) if m else None
            if val is None:
                return CheckResult(code, name, "점검불가", "PASS_MIN_DAYS 미설정", "1일 이상 설정 권고")
            return CheckResult(code, name, "양호" if val >= 1 else "취약", "PASS_MIN_DAYS={}".format(val), "당일 재변경 통한 정책 우회 방지를 위해 1일 이상 권고")
        except Exception as e:
            logger.exception("%s 점검 중 오류", code)
            return CheckResult(code, name, "점검불가", "오류: {}".format(e), "수동 점검 필요")

    def check_u49_unnecessary_accounts(self):
        code, name = "U-49", "불필요한 계정 제거"
        try:
            accounts = self._all_accounts()
            if not accounts:
                return CheckResult(code, name, "점검불가", "/etc/passwd 접근 불가", "계정 목록 확인 필요")
            default_accts = {"lp", "uucp", "nuucp", "games", "gopher", "news", "ftp"}
            suspect = [a["name"] for a in accounts if a["name"] in default_accts and not re.search(r"nologin|false", a["shell"])]
            return CheckResult(
                code, name, "점검불가",
                "로그인 셸을 가진 기본 계정: {}".format(suspect if suspect else "없음"),
                "불필요 시 계정 삭제 또는 셸을 nologin으로 변경 (사용 여부는 수동 확인 필요)",
            )
        except Exception as e:
            logger.exception("%s 점검 중 오류", code)
            return CheckResult(code, name, "점검불가", "오류: {}".format(e), "수동 점검 필요")

    def check_u50_admin_group_minimal(self):
        code, name = "U-50", "관리자 그룹에 최소한의 계정 포함"
        try:
            groups = self._all_groups()
            admin_groups = [g for g in groups if g["name"] in ("wheel", "sudo", "admin")]
            sudoers = self._read_file("/etc/sudoers") or ""
            info = {g["name"]: g["members"] for g in admin_groups}
            return CheckResult(
                code, name, "점검불가", "관리자 그룹 구성원: {} / sudoers 라인수: {}".format(info, len(sudoers.splitlines())),
                "관리자 그룹/sudoers 구성원이 업무상 최소한인지 수동 검토 필요",
            )
        except Exception as e:
            logger.exception("%s 점검 중 오류", code)
            return CheckResult(code, name, "점검불가", "오류: {}".format(e), "수동 점검 필요")

    def check_u51_gid_exists(self):
        code, name = "U-51", "계정이 존재하지 않는 GID 금지"
        try:
            accounts = self._all_accounts()
            groups = self._all_groups()
            if not accounts or not groups:
                return CheckResult(code, name, "점검불가", "passwd/group 접근 불가", "파일 확인 필요")
            gid_set = {g["gid"] for g in groups}
            bad = [a["name"] for a in accounts if a["gid"] not in gid_set]
            return CheckResult(code, name, "양호" if not bad else "취약", "GID 미존재 계정: {}".format(bad if bad else "없음"), "/etc/group 에 해당 GID 그룹 추가 또는 계정 GID 수정")
        except Exception as e:
            logger.exception("%s 점검 중 오류", code)
            return CheckResult(code, name, "점검불가", "오류: {}".format(e), "수동 점검 필요")

    def check_u52_duplicate_uid(self):
        code, name = "U-52", "동일한 UID 금지"
        try:
            accounts = self._all_accounts()
            if not accounts:
                return CheckResult(code, name, "점검불가", "/etc/passwd 접근 불가", "파일 확인 필요")
            seen = {}
            dup = set()
            for a in accounts:
                if a["uid"] in seen:
                    dup.add(a["uid"])
                seen[a["uid"]] = a["name"]
            return CheckResult(code, name, "양호" if not dup else "취약", "중복 UID: {}".format(list(dup) if dup else "없음"), "계정별 고유 UID 부여 권고")
        except Exception as e:
            logger.exception("%s 점검 중 오류", code)
            return CheckResult(code, name, "점검불가", "오류: {}".format(e), "수동 점검 필요")

    def check_u53_user_shell(self):
        code, name = "U-53", "사용자 shell 점검"
        try:
            accounts = self._all_accounts()
            if not accounts:
                return CheckResult(code, name, "점검불가", "/etc/passwd 접근 불가", "파일 확인 필요")
            bad = [
                a["name"] for a in accounts
                if a["uid"] < 1000 and a["name"] != "root" and not re.search(r"nologin|false|/sbin/nologin", a["shell"])
            ]
            return CheckResult(code, name, "양호" if not bad else "취약", "대화형 셸을 가진 시스템 계정: {}".format(bad if bad else "없음"), "시스템/서비스 계정은 /sbin/nologin 또는 /bin/false 로 설정 권고")
        except Exception as e:
            logger.exception("%s 점검 중 오류", code)
            return CheckResult(code, name, "점검불가", "오류: {}".format(e), "수동 점검 필요")

    def check_u54_session_timeout(self):
        code, name = "U-54", "session timeout 설정"
        try:
            found = []
            tmout = None
            for path in ("/etc/profile", "/etc/bashrc", "/etc/bash.bashrc"):
                content = self._read_file(path)
                if content is None:
                    continue
                found.append(path)
                m = re.search(r"^\s*(?:export\s+)?TMOUT\s*=\s*(\d+)", content, re.MULTILINE)
                if m:
                    tmout = int(m.group(1))
            if not found:
                return CheckResult(code, name, "점검불가", "profile/bashrc 접근 불가", "파일 확인 필요")
            if tmout is None:
                return CheckResult(code, name, "취약", "TMOUT 미설정 ({})".format(", ".join(found)), "TMOUT=600 이하로 설정 후 export 권고")
            return CheckResult(code, name, "양호" if tmout <= 600 else "취약", "TMOUT={} ({})".format(tmout, ", ".join(found)), "600초 이하 권고")
        except Exception as e:
            logger.exception("%s 점검 중 오류", code)
            return CheckResult(code, name, "점검불가", "오류: {}".format(e), "수동 점검 필요")

    # =========================================================
    # 파일 및 디렉터리 관리
    # =========================================================
    def check_u05_root_home_path(self):
        code, name = "U-05", "root 홈, PATH 디렉터리 권한 및 설정"
        try:
            path_env = os.environ.get("PATH", "")
            elements = path_env.split(":")
            bad_path = any(e in ("", ".") for e in elements)
            perm = self._file_perm("/root")
            perm_ok = perm is not None and int(perm, 8) <= 0o750
            result = "양호" if (not bad_path and perm_ok) else "취약"
            return CheckResult(code, name, result, "PATH={} / /root 권한={}".format(path_env, perm), "PATH에 '.' 또는 빈 요소 제거, /root 권한 750 이하 권고")
        except Exception as e:
            logger.exception("%s 점검 중 오류", code)
            return CheckResult(code, name, "점검불가", "오류: {}".format(e), "수동 점검 필요")

    def check_u06_no_owner_files(self):
        code, name = "U-06", "파일 및 디렉터리 소유자 설정"
        try:
            if not self.is_root:
                return CheckResult(code, name, "점검불가", "root 권한 필요(전체 파일시스템 탐색)", "root로 재실행 필요")
            out = self._run_cmd(["find", "/", "(", "-nouser", "-o", "-nogroup", ")", "-not", "-path", "/proc/*"])
            items = [l for l in (out or "").splitlines() if l.strip()]
            setting = self._truncated(items, code)
            return CheckResult(code, name, "양호" if not items else "취약", setting, "소유자/그룹 없는 파일은 삭제하거나 올바른 소유자로 재설정 권고")
        except Exception as e:
            logger.exception("%s 점검 중 오류", code)
            return CheckResult(code, name, "점검불가", "오류: {}".format(e), "수동 점검 필요")

    def _perm_check(self, code, name, path, owner_uid, max_perm_octal, recommendation, allow_missing_ok=False):
        perm = self._file_perm(path)
        owner_root = self._file_owner_is_root(path)
        if perm is None:
            if allow_missing_ok:
                return CheckResult(code, name, "양호", "{} 파일 없음(해당 서비스 미사용)".format(path), recommendation)
            return CheckResult(code, name, "점검불가", "{} 접근 불가".format(path), recommendation)
        ok_perm = int(perm, 8) <= max_perm_octal
        ok_owner = owner_root is True if owner_uid == 0 else True
        result = "양호" if (ok_perm and ok_owner) else "취약"
        return CheckResult(code, name, result, "{} 권한={} 소유자root={}".format(path, perm, owner_root), recommendation)

    def check_u07_passwd_perm(self):
        return self._perm_check("U-07", "/etc/passwd 소유자 및 권한", "/etc/passwd", 0, 0o644, "권한 644 이하, 소유자 root 권고")

    def check_u08_shadow_perm(self):
        code, name = "U-08", "/etc/shadow 소유자 및 권한"
        if not os.path.exists("/etc/shadow"):
            return CheckResult(code, name, "점검불가", "/etc/shadow 없음(macOS 등은 shadow 파일 미사용, 별도 인증 체계)", "Linux 대상에서 재점검 필요")
        return self._perm_check(code, name, "/etc/shadow", 0, 0o400, "권한 400(또는 000) 이하, 소유자 root 권고")

    def check_u09_hosts_perm(self):
        return self._perm_check("U-09", "/etc/hosts 소유자 및 권한", "/etc/hosts", 0, 0o644, "권한 644 이하, 소유자 root 권고")

    def check_u10_inetd_perm(self):
        code, name = "U-10", "/etc/(x)inetd.conf 소유자 및 권한"
        path = self._first_existing(["/etc/xinetd.conf", "/etc/inetd.conf"])
        if not path:
            return CheckResult(code, name, "양호", "xinetd/inetd 미사용(systemd 소켓 방식 등)", "해당없음")
        return self._perm_check(code, name, path, 0, 0o640, "권한 600~640, 소유자 root 권고")

    def check_u11_syslog_conf_perm(self):
        code, name = "U-11", "/etc/syslog.conf 소유자 및 권한"
        path = self._first_existing(["/etc/rsyslog.conf", "/etc/syslog.conf"])
        if not path:
            return CheckResult(code, name, "점검불가", "rsyslog.conf/syslog.conf 없음", "로깅 설정 파일 확인 필요")
        return self._perm_check(code, name, path, 0, 0o640, "권한 640 이하, 소유자 root 권고")

    def check_u12_services_perm(self):
        return self._perm_check("U-12", "/etc/services 소유자 및 권한", "/etc/services", 0, 0o644, "권한 644 이하, 소유자 root 권고")

    def check_u13_suid_sgid(self):
        code, name = "U-13", "SUID/SGID/Sticky bit 설정 파일 점검"
        try:
            if not self.is_root:
                return CheckResult(code, name, "점검불가", "root 권한 필요(전체 파일시스템 탐색)", "root로 재실행 필요")
            out = self._run_cmd(["find", "/", "(", "-perm", "-4000", "-o", "-perm", "-2000", ")", "-type", "f"])
            items = [l for l in (out or "").splitlines() if l.strip()]
            setting = self._truncated(items, code)
            return CheckResult(code, name, "점검불가", setting, "목록을 수동 검토하여 불필요한 SUID/SGID 비트 제거 권고(자동 취약 판정 안 함, 오탐 방지)")
        except Exception as e:
            logger.exception("%s 점검 중 오류", code)
            return CheckResult(code, name, "점검불가", "오류: {}".format(e), "수동 점검 필요")

    def check_u14_startup_files_perm(self):
        code, name = "U-14", "시작파일 및 환경파일 소유자/권한"
        try:
            targets = ["/etc/profile", "/etc/bashrc"]
            for a in self._all_accounts():
                home = a["home"]
                for f in (".profile", ".bashrc", ".bash_profile"):
                    p = os.path.join(home, f)
                    if os.path.exists(p):
                        targets.append(p)
            bad = []
            checked = 0
            for t in targets:
                perm = self._file_perm(t)
                if perm is None:
                    continue
                checked += 1
                if int(perm, 8) > 0o644:
                    bad.append("{}({})".format(t, perm))
            if checked == 0:
                return CheckResult(code, name, "점검불가", "대상 파일 접근 불가", "파일 확인 필요")
            return CheckResult(code, name, "양호" if not bad else "취약", "권한 초과 파일: {}".format(bad if bad else "없음"), "시작파일 권한 644 이하 권고")
        except Exception as e:
            logger.exception("%s 점검 중 오류", code)
            return CheckResult(code, name, "점검불가", "오류: {}".format(e), "수동 점검 필요")

    def check_u15_world_writable(self):
        code, name = "U-15", "world writable 파일 점검"
        try:
            if not self.is_root:
                return CheckResult(code, name, "점검불가", "root 권한 필요(전체 파일시스템 탐색)", "root로 재실행 필요")
            out = self._run_cmd(["find", "/", "-type", "f", "-perm", "-0002"])
            items = [l for l in (out or "").splitlines() if l.strip()]
            setting = self._truncated(items, code)
            return CheckResult(code, name, "양호" if not items else "취약", setting, "world writable 권한 제거(chmod o-w) 권고")
        except Exception as e:
            logger.exception("%s 점검 중 오류", code)
            return CheckResult(code, name, "점검불가", "오류: {}".format(e), "수동 점검 필요")

    def check_u16_dev_fake_files(self):
        code, name = "U-16", "/dev 내 존재하지 않는 device 파일 점검"
        try:
            if not os.path.isdir("/dev"):
                return self._na(code, name, "/dev 없음")
            bad = []
            for fname in os.listdir("/dev"):
                full = os.path.join("/dev", fname)
                try:
                    st = os.lstat(full)
                    import stat as statmod
                    if statmod.S_ISREG(st.st_mode):
                        bad.append(full)
                except (OSError, PermissionError):
                    continue
            return CheckResult(code, name, "양호" if not bad else "취약", "/dev 내 일반 파일: {}".format(bad if bad else "없음"), "정상 디바이스 노드가 아닌 일반 파일은 삭제 권고")
        except Exception as e:
            logger.exception("%s 점검 중 오류", code)
            return CheckResult(code, name, "점검불가", "오류: {}".format(e), "수동 점검 필요")

    def check_u17_rhosts(self):
        code, name = "U-17", "$HOME/.rhosts, hosts.equiv 사용 금지"
        try:
            found = []
            for a in self._all_accounts():
                p = os.path.join(a["home"], ".rhosts")
                if os.path.exists(p):
                    found.append(p)
            if os.path.exists("/etc/hosts.equiv"):
                found.append("/etc/hosts.equiv")
            return CheckResult(code, name, "양호" if not found else "취약", "발견: {}".format(found if found else "없음"), "신뢰 호스트 기반 인증 파일은 삭제 권고 ('+' 와일드카드 포함 시 특히 위험)")
        except Exception as e:
            logger.exception("%s 점검 중 오류", code)
            return CheckResult(code, name, "점검불가", "오류: {}".format(e), "수동 점검 필요")

    def check_u18_ip_port_restriction(self):
        code, name = "U-18", "접속 IP 및 포트 제한"
        try:
            allow = self._read_file("/etc/hosts.allow")
            deny = self._read_file("/etc/hosts.deny")
            fw = self._run_cmd(["firewall-cmd", "--list-all"]) or self._run_cmd(["iptables", "-L", "-n"])
            summary = "hosts.allow={}줄 / hosts.deny={}줄 / 방화벽 규칙 확인={}".format(
                len((allow or "").splitlines()), len((deny or "").splitlines()), "가능" if fw else "불가/미사용"
            )
            return CheckResult(code, name, "점검불가", summary, "정책적 판단 필요 - 접근 허용 IP/포트가 최소화되어 있는지 수동 검토")
        except Exception as e:
            logger.exception("%s 점검 중 오류", code)
            return CheckResult(code, name, "점검불가", "오류: {}".format(e), "수동 점검 필요")

    def _simple_service_disabled_check(self, code, name, service_names, recommendation, xinetd_name=None):
        try:
            if not self.is_linux:
                return self._na(code, name)
            active_any = False
            details = []
            for svc in service_names:
                active = self._service_is_active(svc)
                details.append("{}={}".format(svc, active))
                if active:
                    active_any = True
            if xinetd_name:
                content = self._read_file("/etc/xinetd.d/{}".format(xinetd_name))
                if content:
                    m = re.search(r"disable\s*=\s*(yes|no)", content)
                    disabled = m and m.group(1) == "yes"
                    details.append("xinetd disable={}".format(m.group(1) if m else "미설정"))
                    if not disabled:
                        active_any = True
            result = "취약" if active_any else "양호"
            return CheckResult(code, name, result, "; ".join(details), recommendation)
        except Exception as e:
            logger.exception("%s 점검 중 오류", code)
            return CheckResult(code, name, "점검불가", "오류: {}".format(e), "수동 점검 필요")

    def check_u19_finger(self):
        return self._simple_service_disabled_check("U-19", "finger 서비스 비활성화", ["finger", "fingerd"], "finger 서비스 비활성화 권고", xinetd_name="finger")

    def check_u20_anonymous_ftp(self):
        code, name = "U-20", "Anonymous FTP 비활성화"
        try:
            content = self._read_file("/etc/vsftpd/vsftpd.conf") or self._read_file("/etc/vsftpd.conf") or self._read_file("/etc/proftpd/proftpd.conf")
            if content is None:
                return CheckResult(code, name, "양호", "FTP 데몬 설정파일 없음(FTP 미사용으로 추정)", "해당없음")
            m = re.search(r"anonymous_enable\s*=\s*(YES|NO)", content, re.IGNORECASE)
            enabled = m and m.group(1).upper() == "YES"
            return CheckResult(code, name, "취약" if enabled else "양호", "anonymous_enable={}".format(m.group(1) if m else "미설정"), "anonymous_enable=NO 설정 권고")
        except Exception as e:
            logger.exception("%s 점검 중 오류", code)
            return CheckResult(code, name, "점검불가", "오류: {}".format(e), "수동 점검 필요")

    def check_u21_r_services(self):
        return self._simple_service_disabled_check("U-21", "r계열 서비스(rsh/rlogin/rexec) 비활성화", ["rsh", "rlogin", "rexec"], "r계열 서비스 비활성화 및 패키지 제거 권고")

    def check_u22_cron_perm(self):
        code, name = "U-22", "cron 파일 소유자 및 권한"
        try:
            targets = ["/etc/crontab"]
            for d in ("/etc/cron.d", "/var/spool/cron"):
                if os.path.isdir(d):
                    for f in os.listdir(d):
                        targets.append(os.path.join(d, f))
            bad = []
            checked = 0
            for t in targets:
                perm = self._file_perm(t)
                owner_root = self._file_owner_is_root(t)
                if perm is None:
                    continue
                checked += 1
                if int(perm, 8) > 0o640 or owner_root is False:
                    bad.append("{}(perm={}, root={})".format(t, perm, owner_root))
            if checked == 0:
                return CheckResult(code, name, "점검불가", "cron 관련 파일 접근 불가", "파일 확인 필요")
            return CheckResult(code, name, "양호" if not bad else "취약", "위반 파일: {}".format(bad if bad else "없음"), "cron 관련 파일 소유자 root, 권한 640 이하 권고")
        except Exception as e:
            logger.exception("%s 점검 중 오류", code)
            return CheckResult(code, name, "점검불가", "오류: {}".format(e), "수동 점검 필요")

    def check_u23_dos_services(self):
        return self._simple_service_disabled_check("U-23", "DoS에 취약한 서비스 비활성화", ["echo", "discard", "daytime", "chargen"], "echo/discard/daytime/chargen 등 불필요 소규모 서비스 비활성화 권고")

    def check_u24_nfs_disabled(self):
        return self._simple_service_disabled_check("U-24", "NFS 서비스 비활성화", ["nfs-server", "rpcbind"], "불필요 시 NFS 서비스 비활성화 권고")

    def check_u25_nfs_access_control(self):
        code, name = "U-25", "NFS 접근 통제"
        try:
            content = self._read_file("/etc/exports")
            if content is None:
                return CheckResult(code, name, "양호", "/etc/exports 없음(NFS 미사용으로 추정)", "해당없음")
            lines = [l for l in content.splitlines() if l.strip() and not l.strip().startswith("#")]
            open_any = any(re.search(r"\*\(|no_root_squash", l) for l in lines)
            return CheckResult(code, name, "취약" if open_any else "양호", "exports 라인: {}".format(lines), "특정 호스트/대역으로 제한, no_root_squash 미사용 권고")
        except Exception as e:
            logger.exception("%s 점검 중 오류", code)
            return CheckResult(code, name, "점검불가", "오류: {}".format(e), "수동 점검 필요")

    def check_u26_automountd(self):
        return self._simple_service_disabled_check("U-26", "automountd 제거", ["autofs"], "불필요 시 autofs 서비스/패키지 제거 권고")

    def check_u27_rpc_services(self):
        code, name = "U-27", "RPC 서비스 확인"
        try:
            if not self.is_linux:
                return self._na(code, name)
            out = self._run_cmd(["rpcinfo", "-p"])
            if out is None:
                return CheckResult(code, name, "양호", "rpcinfo 명령 없음/RPC 미사용", "해당없음")
            risky = [l for l in out.splitlines() if re.search(r"rusersd|rwalld|sprayd|rstatd", l)]
            return CheckResult(code, name, "취약" if risky else "양호", "위험 RPC 서비스: {}".format(risky if risky else "없음"), "불필요한 RPC 서비스 비활성화 권고")
        except Exception as e:
            logger.exception("%s 점검 중 오류", code)
            return CheckResult(code, name, "점검불가", "오류: {}".format(e), "수동 점검 필요")

    def check_u28_nis(self):
        return self._simple_service_disabled_check("U-28", "NIS/NIS+ 점검", ["ypserv", "ypbind"], "NIS/NIS+ 미사용 시 비활성화 권고")

    def check_u29_tftp_talk(self):
        return self._simple_service_disabled_check("U-29", "tftp, talk 서비스 비활성화", ["tftp", "talk", "ntalk"], "tftp/talk 서비스 비활성화 권고", xinetd_name="tftp")

    def check_u30_sendmail_version(self):
        code, name = "U-30", "Sendmail 버전 점검"
        try:
            out = self._run_cmd(["sendmail", "-d0.1", "-bt"]) or self._run_cmd(["postconf", "mail_version"])
            if out is None:
                return CheckResult(code, name, "양호", "Sendmail/Postfix 미확인(미사용으로 추정)", "해당없음")
            return CheckResult(code, name, "점검불가", "버전 정보: {}".format(out[:200]), "최신 취약점 DB 대조 후 최신 버전 패치 여부 수동 확인 필요")
        except Exception as e:
            logger.exception("%s 점검 중 오류", code)
            return CheckResult(code, name, "점검불가", "오류: {}".format(e), "수동 점검 필요")

    def check_u31_relay_restriction(self):
        code, name = "U-31", "스팸 메일 릴레이 제한"
        try:
            content = self._read_file("/etc/mail/access")
            postfix_main = self._read_file("/etc/postfix/main.cf")
            if content is None and postfix_main is None:
                return CheckResult(code, name, "양호", "sendmail/postfix 설정 없음(미사용으로 추정)", "해당없음")
            open_relay = False
            detail = []
            if postfix_main:
                m = re.search(r"mynetworks\s*=\s*(.+)", postfix_main)
                detail.append("mynetworks={}".format(m.group(1) if m else "미설정"))
                if m and "0.0.0.0/0" in m.group(1):
                    open_relay = True
            return CheckResult(code, name, "취약" if open_relay else "점검불가", "; ".join(detail) if detail else "sendmail access 파일 존재", "오픈 릴레이 여부 수동 확인 필요")
        except Exception as e:
            logger.exception("%s 점검 중 오류", code)
            return CheckResult(code, name, "점검불가", "오류: {}".format(e), "수동 점검 필요")

    def check_u32_sendmail_restrictqrun(self):
        code, name = "U-32", "일반사용자 Sendmail 실행 방지"
        try:
            content = self._read_file("/etc/mail/sendmail.cf")
            if content is None:
                return CheckResult(code, name, "양호", "sendmail.cf 없음(미사용으로 추정)", "해당없음")
            has = "restrictqrun" in content
            return CheckResult(code, name, "양호" if has else "취약", "restrictqrun 포함={}".format(has), "PrivacyOptions 에 restrictqrun 추가 권고")
        except Exception as e:
            logger.exception("%s 점검 중 오류", code)
            return CheckResult(code, name, "점검불가", "오류: {}".format(e), "수동 점검 필요")

    def check_u33_dns_version(self):
        code, name = "U-33", "DNS 보안 버전 패치"
        try:
            out = self._run_cmd(["named", "-v"])
            if out is None:
                return CheckResult(code, name, "양호", "named(BIND) 미설치로 추정", "해당없음")
            return CheckResult(code, name, "점검불가", "BIND 버전: {}".format(out), "최신 취약점 DB 대조 후 패치 여부 수동 확인 필요")
        except Exception as e:
            logger.exception("%s 점검 중 오류", code)
            return CheckResult(code, name, "점검불가", "오류: {}".format(e), "수동 점검 필요")

    def check_u34_dns_zone_transfer(self):
        code, name = "U-34", "DNS Zone Transfer 설정"
        try:
            content = self._read_file("/etc/named.conf") or self._read_file("/etc/bind/named.conf.options")
            if content is None:
                return CheckResult(code, name, "양호", "named.conf 없음(DNS 서비스 미사용으로 추정)", "해당없음")
            m = re.search(r"allow-transfer\s*\{\s*([^}]*)\s*\}", content)
            val = m.group(1).strip() if m else "미설정"
            risky = (not m) or "any" in val
            return CheckResult(code, name, "취약" if risky else "양호", "allow-transfer={}".format(val), "특정 슬레이브 서버 IP로만 제한 권고")
        except Exception as e:
            logger.exception("%s 점검 중 오류", code)
            return CheckResult(code, name, "점검불가", "오류: {}".format(e), "수동 점검 필요")

    def _find_web_config(self):
        for p in ("/etc/httpd/conf/httpd.conf", "/etc/apache2/apache2.conf", "/etc/apache2/httpd.conf", "/usr/local/etc/apache2/httpd.conf"):
            if os.path.exists(p):
                return p, "apache"
        for p in ("/etc/nginx/nginx.conf", "/usr/local/etc/nginx/nginx.conf"):
            if os.path.exists(p):
                return p, "nginx"
        return None, None

    def check_u35_dir_listing(self):
        code, name = "U-35", "웹서비스 디렉토리 리스팅 제거"
        try:
            path, kind = self._find_web_config()
            if not path:
                return CheckResult(code, name, "양호", "웹서버 설정 파일 없음(미사용으로 추정)", "해당없음")
            content = self._read_file(path) or ""
            if kind == "apache":
                bad = bool(re.search(r"Options\s+[^\n]*Indexes", content))
            else:
                bad = bool(re.search(r"autoindex\s+on;", content))
            return CheckResult(code, name, "취약" if bad else "양호", "{}: Indexes/autoindex 사용={}".format(kind, bad), "디렉토리 리스팅(Indexes/autoindex) 비활성화 권고")
        except Exception as e:
            logger.exception("%s 점검 중 오류", code)
            return CheckResult(code, name, "점검불가", "오류: {}".format(e), "수동 점검 필요")

    def check_u36_web_process_user(self):
        code, name = "U-36", "웹서비스 프로세스 권한 제한"
        try:
            path, kind = self._find_web_config()
            if not path:
                return CheckResult(code, name, "양호", "웹서버 설정 파일 없음(미사용으로 추정)", "해당없음")
            content = self._read_file(path) or ""
            m = re.search(r"^\s*User\s+(\S+)", content, re.MULTILINE)
            user = m.group(1) if m else None
            bad = (user is None) or user.strip('"') == "root"
            return CheckResult(code, name, "취약" if bad else "양호", "웹서버 User={}".format(user), "웹서버 전용 비-root 계정으로 실행 권고")
        except Exception as e:
            logger.exception("%s 점검 중 오류", code)
            return CheckResult(code, name, "점검불가", "오류: {}".format(e), "수동 점검 필요")

    def check_u37_web_upper_dir(self):
        code, name = "U-37", "웹서비스 상위 디렉토리 접근 금지"
        path, kind = self._find_web_config()
        if not path:
            return CheckResult(code, name, "양호", "웹서버 설정 파일 없음(미사용으로 추정)", "해당없음")
        return CheckResult(code, name, "점검불가", "설정 파일 존재: {}".format(path), "DocumentRoot 밖 경로 이탈 가능 여부 수동 점검 권고(정적 분석 한계)")

    def check_u38_web_unnecessary_files(self):
        code, name = "U-38", "웹서비스 불필요한 파일 제거"
        try:
            path, kind = self._find_web_config()
            if not path:
                return CheckResult(code, name, "양호", "웹서버 설정 파일 없음(미사용으로 추정)", "해당없음")
            content = self._read_file(path) or ""
            m = re.search(r"DocumentRoot\s+\"?([^\"\n]+)\"?", content)
            docroot = m.group(1) if m else None
            found = []
            if docroot and os.path.isdir(docroot):
                for sample in ("manual", "icons", "cgi-bin/test-cgi", "phpinfo.php"):
                    p = os.path.join(docroot, sample)
                    if os.path.exists(p):
                        found.append(p)
            return CheckResult(code, name, "취약" if found else "양호", "DocumentRoot={} / 발견된 샘플 파일: {}".format(docroot, found if found else "없음"), "기본 설치 샘플/테스트 파일 제거 권고")
        except Exception as e:
            logger.exception("%s 점검 중 오류", code)
            return CheckResult(code, name, "점검불가", "오류: {}".format(e), "수동 점검 필요")

    def check_u39_web_symlink(self):
        code, name = "U-39", "웹서비스 심볼릭 링크 사용 금지"
        try:
            path, kind = self._find_web_config()
            if not path:
                return CheckResult(code, name, "양호", "웹서버 설정 파일 없음(미사용으로 추정)", "해당없음")
            content = self._read_file(path) or ""
            bad = bool(re.search(r"Options\s+[^\n]*(FollowSymLinks|SymLinksIfOwnerMatch)", content)) if kind == "apache" else False
            return CheckResult(code, name, "취약" if bad else "양호", "FollowSymLinks/SymLinksIfOwnerMatch 사용={}".format(bad), "심볼릭 링크 옵션 비활성화 권고")
        except Exception as e:
            logger.exception("%s 점검 중 오류", code)
            return CheckResult(code, name, "점검불가", "오류: {}".format(e), "수동 점검 필요")

    def check_u40_web_upload_download(self):
        code, name = "U-40", "웹서비스 파일 업로드/다운로드 제한"
        path, kind = self._find_web_config()
        if not path:
            return CheckResult(code, name, "양호", "웹서버 설정 파일 없음(미사용으로 추정)", "해당없음")
        return CheckResult(code, name, "점검불가", "설정 파일 존재: {}".format(path), "업로드 디렉토리 실행권한 제거(Options -ExecCGI, PHP engine off) 여부 애플리케이션 레벨 수동 점검 필요")

    def check_u41_web_zone_separation(self):
        code, name = "U-41", "웹서비스 영역 분리"
        try:
            path, kind = self._find_web_config()
            if not path:
                return CheckResult(code, name, "양호", "웹서버 설정 파일 없음(미사용으로 추정)", "해당없음")
            content = self._read_file(path) or ""
            m = re.search(r"DocumentRoot\s+\"?([^\"\n]+)\"?", content)
            docroot = m.group(1) if m else "미확인"
            mounts = self._run_cmd(["mount"]) or ""
            return CheckResult(code, name, "점검불가", "DocumentRoot={} / mount 정보 확보={}".format(docroot, bool(mounts)), "DocumentRoot가 시스템 루트/핵심 디렉터리와 물리적으로 분리되어 있는지 수동 검토 필요")
        except Exception as e:
            logger.exception("%s 점검 중 오류", code)
            return CheckResult(code, name, "점검불가", "오류: {}".format(e), "수동 점검 필요")

    def check_u55_hosts_lpd(self):
        code, name = "U-55", "hosts.lpd 소유자 및 권한"
        if not os.path.exists("/etc/hosts.lpd"):
            return CheckResult(code, name, "양호", "/etc/hosts.lpd 없음", "해당없음")
        return self._perm_check(code, name, "/etc/hosts.lpd", 0, 0o600, "권한 600, 소유자 root 권고")

    def check_u56_umask(self):
        code, name = "U-56", "UMASK 설정 관리"
        try:
            found = []
            vals = []
            for path in ("/etc/profile", "/etc/bashrc", "/etc/login.defs"):
                content = self._read_file(path)
                if content is None:
                    continue
                found.append(path)
                m = re.search(r"^\s*UMASK\s+(\d+)", content, re.MULTILINE | re.IGNORECASE)
                if m:
                    vals.append(int(m.group(1), 8))
            if not found:
                return CheckResult(code, name, "점검불가", "profile/login.defs 접근 불가", "파일 확인 필요")
            if not vals:
                return CheckResult(code, name, "취약", "UMASK 미설정 ({})".format(", ".join(found)), "umask 022 이상 설정 권고")
            ok = all(v >= 0o022 for v in vals)
            return CheckResult(code, name, "양호" if ok else "취약", "UMASK 값들: {}".format([oct(v) for v in vals]), "umask 022 이상 권고")
        except Exception as e:
            logger.exception("%s 점검 중 오류", code)
            return CheckResult(code, name, "점검불가", "오류: {}".format(e), "수동 점검 필요")

    def check_u57_home_dir_perm(self):
        code, name = "U-57", "홈디렉토리 소유자 및 권한"
        try:
            accounts = self._all_accounts()
            if not accounts:
                return CheckResult(code, name, "점검불가", "/etc/passwd 접근 불가", "파일 확인 필요")
            bad = []
            checked = 0
            for a in accounts:
                if not os.path.isdir(a["home"]):
                    continue
                checked += 1
                perm = self._file_perm(a["home"])
                uid = self._file_owner_uid(a["home"])
                if perm is None:
                    continue
                if int(perm, 8) > 0o750 or (uid is not None and uid != a["uid"]):
                    bad.append("{}(perm={}, owner_uid={}, expected_uid={})".format(a["home"], perm, uid, a["uid"]))
            if checked == 0:
                return CheckResult(code, name, "점검불가", "홈 디렉터리 확인 불가", "파일 확인 필요")
            return CheckResult(code, name, "양호" if not bad else "취약", "위반: {}".format(bad if bad else "없음"), "홈 디렉터리 소유자를 계정 본인으로, 권한 750 이하 권고")
        except Exception as e:
            logger.exception("%s 점검 중 오류", code)
            return CheckResult(code, name, "점검불가", "오류: {}".format(e), "수동 점검 필요")

    def check_u58_home_dir_exists(self):
        code, name = "U-58", "홈디렉토리 존재 여부 관리"
        try:
            accounts = self._all_accounts()
            if not accounts:
                return CheckResult(code, name, "점검불가", "/etc/passwd 접근 불가", "파일 확인 필요")
            missing = [a["name"] for a in accounts if a["home"] and not os.path.isdir(a["home"])]
            return CheckResult(code, name, "양호" if not missing else "취약", "홈 디렉터리 없는 계정: {}".format(missing if missing else "없음"), "홈 디렉터리 생성 또는 계정 정리 권고")
        except Exception as e:
            logger.exception("%s 점검 중 오류", code)
            return CheckResult(code, name, "점검불가", "오류: {}".format(e), "수동 점검 필요")

    def check_u59_hidden_files(self):
        code, name = "U-59", "숨겨진 파일 및 디렉토리 점검"
        try:
            if not self.is_root:
                return CheckResult(code, name, "점검불가", "root 권한 필요(전체 파일시스템 탐색)", "root로 재실행 필요")
            whitelist = {".bashrc", ".bash_profile", ".profile", ".ssh", ".gitignore", ".vimrc", ".zshrc", ".bash_history", ".viminfo"}
            out = self._run_cmd(["find", "/tmp", "/var/tmp", "-name", ".*"])
            items = [l for l in (out or "").splitlines() if l.strip() and os.path.basename(l) not in whitelist]
            setting = self._truncated(items, code)
            return CheckResult(code, name, "점검불가", setting, "/tmp, /var/tmp 등 world-writable 위치의 숨김 파일은 수동 검토 권고(정상 dotfile은 화이트리스트 처리됨)")
        except Exception as e:
            logger.exception("%s 점검 중 오류", code)
            return CheckResult(code, name, "점검불가", "오류: {}".format(e), "수동 점검 필요")

    # =========================================================
    # 서비스 관리
    # =========================================================
    def check_u60_ssh_remote_access(self):
        code, name = "U-60", "SSH 원격접속 허용"
        try:
            content = self._read_file("/etc/ssh/sshd_config")
            if content is None:
                return CheckResult(code, name, "점검불가", "sshd_config 접근 불가", "SSH 설정 확인 필요")
            m = re.search(r"^\s*Protocol\s+(\S+)", content, re.MULTILINE)
            proto = m.group(1) if m else "2(기본값)"
            active = self._service_is_active("sshd") if self.is_linux else None
            return CheckResult(
                code, name, "점검불가",
                "Protocol={} / sshd 활성={}".format(proto, active),
                "원격 접속이 SSH(Protocol 2)로 안전하게 통제되고 있는지, 불필요한 원격 접속 자체가 없는지 정책적으로 판단 필요",
            )
        except Exception as e:
            logger.exception("%s 점검 중 오류", code)
            return CheckResult(code, name, "점검불가", "오류: {}".format(e), "수동 점검 필요")

    def check_u61_ftp_service(self):
        code, name = "U-61", "FTP 서비스 확인"
        try:
            active = self._service_is_active("vsftpd") or self._service_is_active("proftpd")
            has_conf = bool(self._first_existing(["/etc/vsftpd/vsftpd.conf", "/etc/vsftpd.conf", "/etc/proftpd/proftpd.conf"]))
            result = "취약" if (active or has_conf) else "양호"
            return CheckResult(code, name, result, "FTP 활성={} / 설정파일존재={}".format(active, has_conf), "평문 프로토콜인 FTP는 불필요 시 비활성화, 필요 시 FTPS/SFTP 대체 권고")
        except Exception as e:
            logger.exception("%s 점검 중 오류", code)
            return CheckResult(code, name, "점검불가", "오류: {}".format(e), "수동 점검 필요")

    def check_u62_ftp_shell_restriction(self):
        code, name = "U-62", "FTP 계정 shell 제한"
        try:
            accounts = self._all_accounts()
            ftp = next((a for a in accounts if a["name"] == "ftp"), None)
            if not ftp:
                return CheckResult(code, name, "양호", "ftp 계정 없음", "해당없음")
            ok = bool(re.search(r"nologin|false", ftp["shell"]))
            return CheckResult(code, name, "양호" if ok else "취약", "ftp 계정 shell={}".format(ftp["shell"]), "ftp 계정 shell을 /sbin/nologin 등으로 제한 권고")
        except Exception as e:
            logger.exception("%s 점검 중 오류", code)
            return CheckResult(code, name, "점검불가", "오류: {}".format(e), "수동 점검 필요")

    def check_u63_ftpusers_perm(self):
        code, name = "U-63", "ftpusers 파일 소유자 및 권한"
        path = self._first_existing(["/etc/ftpusers", "/etc/vsftpd/ftpusers"])
        if not path:
            return CheckResult(code, name, "점검불가", "ftpusers 파일 없음", "FTP 미사용이면 해당없음, 사용 시 파일 확인 필요")
        return self._perm_check(code, name, path, 0, 0o640, "권한 640 이하, 소유자 root 권고")

    def check_u64_ftpusers_content(self):
        code, name = "U-64", "ftpusers 파일 설정"
        path = self._first_existing(["/etc/ftpusers", "/etc/vsftpd/ftpusers", "/etc/vsftpd/user_list"])
        if not path:
            return CheckResult(code, name, "점검불가", "ftpusers 파일 없음", "FTP 미사용이면 해당없음")
        content = self._read_file(path) or ""
        has_root = "root" in content
        return CheckResult(code, name, "양호" if has_root else "취약", "root 포함={}".format(has_root), "root 등 주요 관리 계정을 접속 거부 목록에 포함 권고")

    def check_u65_at_perm(self):
        code, name = "U-65", "at 파일 소유자 및 권한"
        found = False
        bad = []
        for path in ("/etc/at.allow", "/etc/at.deny"):
            if not os.path.exists(path):
                continue
            found = True
            perm = self._file_perm(path)
            owner_root = self._file_owner_is_root(path)
            if perm and (int(perm, 8) > 0o640 or owner_root is False):
                bad.append("{}(perm={}, root={})".format(path, perm, owner_root))
        if not found:
            return CheckResult(code, name, "점검불가", "at.allow/at.deny 없음", "at 서비스 미사용이면 해당없음")
        return CheckResult(code, name, "양호" if not bad else "취약", "위반: {}".format(bad if bad else "없음"), "권한 640 이하, 소유자 root 권고")

    def check_u66_snmp_active(self):
        return self._simple_service_disabled_check("U-66", "SNMP 서비스 구동 점검", ["snmpd"], "불필요 시 SNMP 서비스 비활성화 권고")

    def check_u67_snmp_community(self):
        code, name = "U-67", "SNMP 커뮤니티스트링 복잡성"
        try:
            content = self._read_file("/etc/snmp/snmpd.conf")
            if content is None:
                return CheckResult(code, name, "양호", "snmpd.conf 없음(SNMP 미사용으로 추정)", "해당없음")
            # 주석 라인 우선 제거
            lines = [l for l in content.splitlines() if not l.strip().startswith("#")]
            clean = "\n".join(lines)
            communities = []
            for m in re.finditer(r"^\s*(rocommunity6?|rwcommunity6?)\s+(\S+)", clean, re.MULTILINE):
                communities.append(m.group(2))
            for m in re.finditer(r"^\s*com2sec\s+\S+\s+\S+\s+(\S+)", clean, re.MULTILINE):
                communities.append(m.group(1))
            has_v3 = bool(re.search(r"^\s*(createUser|rouser|rwuser)\b", clean, re.MULTILINE))
            weak = [c for c in communities if c in ("public", "private")]
            result = "취약" if weak else ("양호" if (communities or has_v3) else "점검불가")
            return CheckResult(code, name, result, "커뮤니티스트링={} / SNMPv3사용={}".format(communities, has_v3), "public/private 등 기본값 대신 복잡한 문자열 사용, 가능하면 SNMPv3 전환 권고")
        except Exception as e:
            logger.exception("%s 점검 중 오류", code)
            return CheckResult(code, name, "점검불가", "오류: {}".format(e), "수동 점검 필요")

    def check_u68_login_banner(self):
        code, name = "U-68", "로그온 시 경고 메시지 제공"
        try:
            found = {}
            for path in ("/etc/motd", "/etc/issue", "/etc/issue.net"):
                content = self._read_file(path)
                found[path] = bool(content and content.strip())
            ok = any(found.values())
            return CheckResult(code, name, "양호" if ok else "취약", "배너 존재 여부: {}".format(found), "motd/issue/issue.net 에 경고 문구 설정 권고")
        except Exception as e:
            logger.exception("%s 점검 중 오류", code)
            return CheckResult(code, name, "점검불가", "오류: {}".format(e), "수동 점검 필요")

    def check_u69_nfs_conf_perm(self):
        code, name = "U-69", "NFS 설정파일 접근 제한"
        if not os.path.exists("/etc/exports"):
            return CheckResult(code, name, "양호", "/etc/exports 없음(NFS 미사용으로 추정)", "해당없음")
        return self._perm_check(code, name, "/etc/exports", 0, 0o644, "권한 644 이하, 소유자 root 권고")

    def check_u70_expn_vrfy(self):
        code, name = "U-70", "expn, vrfy 명령어 제한"
        try:
            content = self._read_file("/etc/mail/sendmail.cf")
            postfix = self._read_file("/etc/postfix/main.cf")
            if content is None and postfix is None:
                return CheckResult(code, name, "양호", "sendmail/postfix 설정 없음(미사용으로 추정)", "해당없음")
            ok = False
            detail = []
            if content:
                ok = ok or ("noexpn" in content and "novrfy" in content)
                detail.append("sendmail PrivacyOptions 확인")
            if postfix:
                m = re.search(r"disable_vrfy_command\s*=\s*(yes|no)", postfix)
                if m:
                    ok = ok or m.group(1) == "yes"
                    detail.append("postfix disable_vrfy_command={}".format(m.group(1)))
            return CheckResult(code, name, "양호" if ok else "취약", "; ".join(detail) if detail else "설정 확인됨", "noexpn,novrfy(sendmail) 또는 disable_vrfy_command=yes(postfix) 설정 권고")
        except Exception as e:
            logger.exception("%s 점검 중 오류", code)
            return CheckResult(code, name, "점검불가", "오류: {}".format(e), "수동 점검 필요")

    def check_u71_apache_info_hide(self):
        code, name = "U-71", "Apache 웹 서비스 정보 숨김"
        try:
            path, kind = self._find_web_config()
            if not path:
                return CheckResult(code, name, "양호", "웹서버 설정 파일 없음(미사용으로 추정)", "해당없음")
            content = self._read_file(path) or ""
            if kind == "apache":
                tokens_prod = bool(re.search(r"ServerTokens\s+Prod", content, re.IGNORECASE))
                sig_off = bool(re.search(r"ServerSignature\s+Off", content, re.IGNORECASE))
                ok = tokens_prod and sig_off
                detail = "ServerTokens Prod={} / ServerSignature Off={}".format(tokens_prod, sig_off)
            else:
                ok = bool(re.search(r"server_tokens\s+off;", content))
                detail = "server_tokens off={}".format(ok)
            return CheckResult(code, name, "양호" if ok else "취약", detail, "서버 버전/시그니처 정보 노출 최소화 설정 권고")
        except Exception as e:
            logger.exception("%s 점검 중 오류", code)
            return CheckResult(code, name, "점검불가", "오류: {}".format(e), "수동 점검 필요")

    # =========================================================
    # 패치 관리 / 로그 관리
    # =========================================================
    def check_u42_patch(self):
        code, name = "U-42", "최신 보안패치 및 벤더 권고사항 적용"
        try:
            pkg = self.distro.get("package_manager")
            count = None
            if pkg in ("dnf", "yum"):
                out = self._run_cmd([pkg, "check-update"])
                if out is not None:
                    count = len([l for l in out.splitlines() if l and not l.startswith(("Loaded", "Last", "Obsoleting"))])
            elif pkg == "apt":
                out = self._run_cmd(["apt", "list", "--upgradable"])
                if out is not None:
                    count = max(0, len(out.splitlines()) - 1)
            detail = "패키지관리자={} / 업데이트가능개수={}".format(pkg, count if count is not None else "확인불가")
            return CheckResult(code, name, "점검불가", detail, "정책적 판단(허용 가능한 미패치 기간 등) 필요 - 벤더 보안 공지와 대조한 수동 확인 권고")
        except Exception as e:
            logger.exception("%s 점검 중 오류", code)
            return CheckResult(code, name, "점검불가", "오류: {}".format(e), "수동 점검 필요")

    def check_u43_log_review(self):
        code, name = "U-43", "로그의 정기적 검토 및 보고"
        try:
            logs = ["/var/log/messages", "/var/log/syslog", "/var/log/secure", "/var/log/auth.log"]
            info = {}
            for p in logs:
                if os.path.exists(p):
                    try:
                        info[p] = datetime.datetime.fromtimestamp(os.path.getmtime(p)).isoformat()
                    except Exception:
                        info[p] = "확인불가"
            logrotate = os.path.exists("/etc/logrotate.conf") or os.path.isdir("/etc/logrotate.d")
            detail = "주요 로그 최종수정시각: {} / logrotate 설정존재={}".format(info, logrotate)
            return CheckResult(code, name, "점검불가", detail, "로그 검토 담당자·주기·보고 절차는 절차적 항목으로 별도 확인 필요(스크립트로 자동 판정 불가)")
        except Exception as e:
            logger.exception("%s 점검 중 오류", code)
            return CheckResult(code, name, "점검불가", "오류: {}".format(e), "수동 점검 필요")

    def check_u72_syslog_config(self):
        code, name = "U-72", "정책에 따른 시스템 로깅 설정"
        try:
            active = (self._service_is_active("rsyslog") or self._service_is_active("syslog-ng")) if self.is_linux else None
            content = self._read_file("/etc/rsyslog.conf") or ""
            facilities = [f for f in ("auth", "authpriv", "cron", "daemon", "kern") if f in content]
            return CheckResult(
                code, name, "점검불가",
                "rsyslog/syslog-ng 활성={} / 설정된 facility={}".format(active, facilities),
                "auth,authpriv,cron,daemon,kern 등 주요 facility 로깅 규칙이 조직 정책과 일치하는지 수동 확인 필요",
            )
        except Exception as e:
            logger.exception("%s 점검 중 오류", code)
            return CheckResult(code, name, "점검불가", "오류: {}".format(e), "수동 점검 필요")

    # =========================================================
    # 오케스트레이션 & 리포팅
    # =========================================================
    def scan_all(self):
        checks = [
            # 계정 관리
            self.check_u01_root_remote_access, self.check_u02_password_complexity, self.check_u03_account_lockout,
            self.check_u04_shadow_password_used, self.check_u44_uid_zero_only_root, self.check_u45_root_su_restriction,
            self.check_u46_password_min_length, self.check_u47_password_max_days, self.check_u48_password_min_days,
            self.check_u49_unnecessary_accounts, self.check_u50_admin_group_minimal, self.check_u51_gid_exists,
            self.check_u52_duplicate_uid, self.check_u53_user_shell, self.check_u54_session_timeout,
            # 파일 및 디렉터리 관리
            self.check_u05_root_home_path, self.check_u06_no_owner_files, self.check_u07_passwd_perm,
            self.check_u08_shadow_perm, self.check_u09_hosts_perm, self.check_u10_inetd_perm,
            self.check_u11_syslog_conf_perm, self.check_u12_services_perm, self.check_u13_suid_sgid,
            self.check_u14_startup_files_perm, self.check_u15_world_writable, self.check_u16_dev_fake_files,
            self.check_u17_rhosts, self.check_u18_ip_port_restriction, self.check_u19_finger,
            self.check_u20_anonymous_ftp, self.check_u21_r_services, self.check_u22_cron_perm,
            self.check_u23_dos_services, self.check_u24_nfs_disabled, self.check_u25_nfs_access_control,
            self.check_u26_automountd, self.check_u27_rpc_services, self.check_u28_nis,
            self.check_u29_tftp_talk, self.check_u30_sendmail_version, self.check_u31_relay_restriction,
            self.check_u32_sendmail_restrictqrun, self.check_u33_dns_version, self.check_u34_dns_zone_transfer,
            self.check_u35_dir_listing, self.check_u36_web_process_user, self.check_u37_web_upper_dir,
            self.check_u38_web_unnecessary_files, self.check_u39_web_symlink, self.check_u40_web_upload_download,
            self.check_u41_web_zone_separation, self.check_u55_hosts_lpd, self.check_u56_umask,
            self.check_u57_home_dir_perm, self.check_u58_home_dir_exists, self.check_u59_hidden_files,
            # 서비스 관리
            self.check_u60_ssh_remote_access, self.check_u61_ftp_service, self.check_u62_ftp_shell_restriction,
            self.check_u63_ftpusers_perm, self.check_u64_ftpusers_content, self.check_u65_at_perm,
            self.check_u66_snmp_active, self.check_u67_snmp_community, self.check_u68_login_banner,
            self.check_u69_nfs_conf_perm, self.check_u70_expn_vrfy, self.check_u71_apache_info_hide,
            # 패치/로그 관리
            self.check_u42_patch, self.check_u43_log_review, self.check_u72_syslog_config,
        ]
        for check in checks:
            try:
                res = check()
            except Exception:
                logger.exception("예상치 못한 오류로 항목을 건너뜁니다: %s", check)
                continue
            self.results.append(res)
            logger.info("[%s] %s: %s", res.item_code, res.item_name, res.result)
        self._write_reports()
        self._print_summary()
        return self.results

    def _write_reports(self):
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        os.makedirs(self.output_dir, exist_ok=True)
        # 항목코드 순 정렬(U-01 ~ U-72 순서 유지, 자연 정렬)
        def sort_key(r):
            m = re.search(r"(\d+)", r.item_code)
            return int(m.group(1)) if m else 999
        ordered = sorted(self.results, key=sort_key)

        if self.fmt in ("csv", "both"):
            csv_path = os.path.join(self.output_dir, "kisa_report_{}.csv".format(ts))
            with open(csv_path, "w", newline="", encoding="utf-8-sig") as f:
                writer = csv.writer(f)
                writer.writerow(["항목코드", "취약점명", "점검결과", "현재설정", "조치권고"])
                for r in ordered:
                    writer.writerow([r.item_code, r.item_name, r.result, r.current_setting, r.recommendation])
            logger.info("CSV 리포트 생성: %s", csv_path)

        if self.fmt in ("json", "both"):
            json_path = os.path.join(self.output_dir, "kisa_report_{}.json".format(ts))
            summary = {
                "scan_timestamp": datetime.datetime.now().isoformat(),
                "hostname": socket.gethostname(),
                "platform": self.platform_name,
                "is_linux": self.is_linux,
                "distro": self.distro,
                "is_root": self.is_root,
                "total": len(ordered),
                "양호": sum(1 for r in ordered if r.result == "양호"),
                "취약": sum(1 for r in ordered if r.result == "취약"),
                "점검불가": sum(1 for r in ordered if r.result == "점검불가"),
                "results": [asdict(r) for r in ordered],
            }
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(summary, f, ensure_ascii=False, indent=2)
            logger.info("JSON 리포트 생성: %s", json_path)

    def _print_summary(self):
        total = len(self.results)
        vuln = sum(1 for r in self.results if r.result == "취약")
        good = sum(1 for r in self.results if r.result == "양호")
        na = sum(1 for r in self.results if r.result == "점검불가")
        logger.info("===== 진단 완료: 총 %d건 (양호 %d / 취약 %d / 점검불가 %d) =====", total, good, vuln, na)


def main():
    parser = argparse.ArgumentParser(description="KISA 주요정보통신기반시설 리눅스 서버 취약점 진단 스크립트 (U-01~U-72)")
    parser.add_argument("--output-dir", default=".", help="리포트 저장 디렉터리 (기본값: 현재 디렉터리)")
    parser.add_argument("--format", choices=["csv", "json", "both"], default="both", help="리포트 출력 형식 (기본값: both)")
    parser.add_argument("--verbose", action="store_true", help="DEBUG 레벨 로그 출력")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    scanner = SecurityScanner(output_dir=args.output_dir, fmt=args.format, verbose=args.verbose)
    scanner.scan_all()


if __name__ == "__main__":
    main()

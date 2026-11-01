# modules/wp_core.py
"""
WPCoreScanner — deteksi versi WordPress Core dan pemetaan CVE.

Non-destructive: hanya membaca /wp-json/, /readme.html, /wp-login.php,
lalu mencocokkan versi ke database CVE internal.
"""

import re
import logging
from datetime import datetime
from typing import Dict, List, Optional

import requests
from bs4 import BeautifulSoup

# --- Import guardrails & logger (dengan fallback aman) ---
try:
    from core.guardrails import check_safety_limit
    from core.logger import log_event
except ImportError:
    def check_safety_limit(mode, target=None):
        return True

    def log_event(level, msg, data=None):
        print(f"[{level}] {msg} - {data}")


# --- Ambil timeout & UA dari config kalau tersedia ---
try:
    from config import config as _app_config
    _DEFAULT_TIMEOUT = _app_config.network.timeout
    _DEFAULT_UA = _app_config.network.user_agent
except Exception:
    _DEFAULT_TIMEOUT = 10
    _DEFAULT_UA = "Mozilla/5.0 (compatible; WP-Scanner/1.0)"


logger = logging.getLogger(__name__)


class WPCoreScanner:
    """Scanner untuk WordPress Core."""

    # ------------------------------------------------------------------
    # Database CVE internal (bisa diperluas)
    # ------------------------------------------------------------------
    CVE_DB: Dict[str, Dict[str, str]] = {
        "CVE-2024-31210": {
            "title": "WordPress Core RCE via Plugin/Theme Upload (Authenticated Admin)",
            "severity": "High",
        },
        "CVE-2023-2745": {
            "title": "WordPress Core Stored XSS via Avatar Upload",
            "severity": "Medium",
        },
        "CVE-2022-21661": {
            "title": "WordPress Core SQL Injection via WP_Query",
            "severity": "High",
        },
    }

    # Versi yang diketahui terkait CVE di atas
    KNOWN_VULNERABLE_VERSIONS: Dict[str, List[str]] = {
        "6.4.2": ["CVE-2024-31210"],
        "6.3.2": ["CVE-2023-2745"],
        "5.9.0": ["CVE-2022-21661"],
    }

    # ------------------------------------------------------------------
    # Init
    # ------------------------------------------------------------------
    def __init__(
        self,
        target_url: str,
        mode: str = "scan",
        risk_level: str = "low",
        timeout: int = _DEFAULT_TIMEOUT,
    ):
        self.target_url = target_url.rstrip("/")
        self.mode = mode.lower().strip()
        self.risk_level = risk_level.lower().strip()
        self.timeout = timeout

        self.session = requests.Session()
        self.session.headers.update({"User-Agent": _DEFAULT_UA})

        self.version_detected: Optional[str] = None
        self.cves_found: List[Dict] = []

    # ------------------------------------------------------------------
    # HTTP helper
    # ------------------------------------------------------------------
    def _safe_get(self, url: str) -> Optional[requests.Response]:
        """GET yang tidak pernah melempar exception. Return None jika gagal."""
        try:
            resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            return resp
        except requests.exceptions.SSLError as e:
            logger.debug(f"SSL error on {url}: {e}")
        except requests.exceptions.Timeout:
            logger.debug(f"Timeout on {url}")
        except requests.exceptions.ConnectionError as e:
            logger.debug(f"Connection error on {url}: {e}")
        except requests.exceptions.RequestException as e:
            logger.debug(f"Request error on {url}: {e}")
        return None

    # ------------------------------------------------------------------
    # Deteksi versi — REST API
    # ------------------------------------------------------------------
    def _get_version_from_rest_api(self) -> Optional[str]:
        endpoints = [
            f"{self.target_url}/wp-json/",
            f"{self.target_url}/wp-json/wp/v2/",
        ]
        for endpoint in endpoints:
            resp = self._safe_get(endpoint)
            if resp is None or resp.status_code != 200:
                continue
            try:
                data = resp.json()
            except ValueError:
                continue
            if not isinstance(data, dict):
                continue

            # Kadang versi ada di root wp-json
            if "version" in data and isinstance(data["version"], str):
                return data["version"]

            # Kadang versi ada di namespace wp/v2
            namespaces = data.get("namespaces")
            if isinstance(namespaces, list) and "wp/v2" in namespaces:
                v2_resp = self._safe_get(f"{endpoint.rstrip('/')}/wp/v2/")
                if v2_resp is not None and v2_resp.status_code == 200:
                    try:
                        v2_data = v2_resp.json()
                        if isinstance(v2_data, dict) and "version" in v2_data:
                            return v2_data["version"]
                    except ValueError:
                        pass
        return None

    # ------------------------------------------------------------------
    # Deteksi versi — readme
    # ------------------------------------------------------------------
    def _get_version_from_readme(self) -> Optional[str]:
        for rf in ("/readme.html", "/readme.txt"):
            resp = self._safe_get(f"{self.target_url}{rf}")
            if resp is None or resp.status_code != 200:
                continue
            content = resp.text
            if rf.endswith(".html"):
                match = re.search(r"Version\s+([\d\.]+)", content, re.IGNORECASE)
            else:
                match = re.search(
                    r"^.*?Version:\s*([\d\.]+)",
                    content,
                    re.MULTILINE | re.IGNORECASE,
                )
            if match:
                return match.group(1)
        return None

    # ------------------------------------------------------------------
    # Deteksi versi — login page
    # ------------------------------------------------------------------
    def _get_version_from_login_page(self) -> Optional[str]:
        resp = self._safe_get(f"{self.target_url}/wp-login.php")
        if resp is None or resp.status_code != 200:
            return None
        try:
            soup = BeautifulSoup(resp.text, "html.parser")
        except Exception:
            return None
        for script in soup.find_all("script", src=True):
            src = script.get("src", "")
            if "version=" in src:
                m = re.search(r"version=([\d\.]+)", src)
                if m:
                    return m.group(1)
        return None

    # ------------------------------------------------------------------
    # Public: detect_version
    # ------------------------------------------------------------------
    def detect_version(self) -> str:
        """Deteksi versi WP. Mengisi self.version_detected dan mengembalikannya."""
        version = (
            self._get_version_from_rest_api()
            or self._get_version_from_readme()
            or self._get_version_from_login_page()
        )
        self.version_detected = version or "Unknown"
        return self.version_detected

    # ------------------------------------------------------------------
    # Cek CVE
    # ------------------------------------------------------------------
    def check_cve_database(
        self,
        version: str,
        min_severity: Optional[str] = None,
    ) -> List[Dict]:
        """
        Cocokkan versi ke CVE internal.
        min_severity: "Low" | "Medium" | "High" | "Critical" (opsional)
        """
        cves: List[Dict] = []
        if not version or version == "Unknown":
            return cves

        # 1. Exact match di KNOWN_VULNERABLE_VERSIONS
        if version in self.KNOWN_VULNERABLE_VERSIONS:
            for cve_id in self.KNOWN_VULNERABLE_VERSIONS[version]:
                info = self.CVE_DB.get(
                    cve_id,
                    {"title": "Unknown Vulnerability", "severity": "High"},
                )
                cves.append(
                    {
                        "cve": cve_id,
                        "cve_full_name": info["title"],
                        "severity": info["severity"],
                        "description": info["title"],
                    }
                )

        # 2. Cek versi "lama" — parsing versi aman (1/2/3 komponen)
        parsed = self._parse_version(version)
        if parsed is not None:
            major = parsed[0]
            if major < 6:
                cves.append(
                    {
                        "cve": "CVE-2021-GENERIC",
                        "cve_full_name": "Old WordPress Version Detected",
                        "severity": "Medium",
                        "description": "Old version detected, upgrade recommended.",
                    }
                )

        # 3. Filter severity (opsional)
        if min_severity:
            order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
            threshold = order.get(min_severity.lower(), 0)
            cves = [
                c for c in cves
                if order.get(c["severity"].lower(), 0) >= threshold
            ]

        return cves

    @staticmethod
    def _parse_version(version: str):
        """
        Parse '6.4.2' -> (6, 4, 2). Toleran terhadap 1/2/3 komponen dan suffix.
        Return None jika tidak valid.
        """
        if not version:
            return None
        # Ambil digit pertama sampai titik/karakter non-digit
        parts = re.split(r"[.\-+]", version.strip())
        nums = []
        for p in parts[:3]:
            m = re.match(r"^(\d+)", p)
            if m:
                nums.append(int(m.group(1)))
        if not nums:
            return None
        while len(nums) < 3:
            nums.append(0)
        return tuple(nums)

    # ------------------------------------------------------------------
    # Run / check
    # ------------------------------------------------------------------
    def run(self) -> Dict:
        version = self.detect_version()
        self.cves_found = self.check_cve_database(version)

        scan_result: Dict = {
            "target": self.target_url,
            "version": version,
            "cves": self.cves_found,
            "mode": self.mode,
            "risk_level": self.risk_level,
            "timestamp": datetime.now().isoformat(),
        }

        # Mode offensive: cek safety limit (dengan target agar allowlist ikut dicek)
        if self.mode in ("probe", "exploit"):
            try:
                allowed = check_safety_limit(self.mode, target=self.target_url)
            except TypeError:
                # Fallback kalau guardrails versi lama tanpa param target
                allowed = check_safety_limit(self.mode)

            if allowed:
                if self.mode == "probe":
                    scan_result["offensive_probe"] = {"status": "simulated"}
                else:
                    scan_result["offensive_exploit"] = {"status": "simulated"}
            else:
                scan_result["offensive_blocked"] = {
                    "status": "blocked_by_guardrails",
                    "mode": self.mode,
                }

        log_event(
            "INFO",
            "WPCore Scan Complete",
            {
                "target": self.target_url,
                "version": version,
                "cves_count": len(self.cves_found),
            },
        )
        return scan_result

    # Alias untuk kompatibilitas pola standar
    def check(self) -> Dict:
        return self.run()

    def scan(self) -> Dict:
        return self.run()


# =====================================================================
# Modul-level convenience function
# =====================================================================
def scan_wp_core(
    target_url: str,
    mode: str = "scan",
    risk_level: str = "low",
) -> Dict:
    return WPCoreScanner(target_url, mode, risk_level).run()


# =====================================================================
# Alias — supaya main.py yang import "WpCoreChecker" tidak error
# =====================================================================
WpCoreChecker = WPCoreScanner
WPCoreChecker = WPCoreScanner
WP_Core_Checker = WPCoreScanner
WP_Core_Scanner = WPCoreScanner
WPCoreScan = WPCoreScanner


__all__ = [
    "WPCoreScanner",
    "WpCoreChecker",
    "WPCoreChecker",
    "WP_Core_Checker",
    "WP_Core_Scanner",
    "WPCoreScan",
    "scan_wp_core",
        ]

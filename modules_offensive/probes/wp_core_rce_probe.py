# modules_offensive/probes/wp_core_rce_probe.py
"""
WpCoreRCEProbe — probe non-destructive untuk potensi RCE di WordPress Core.

Strategi:
1. Fingerprinting versi (meta generator, RSS feed, wp-includes/version.php, REST API).
2. Pencocokan versi terhadap daftar CVE RCE di KNOWN_RCE_CVES.
3. Passive endpoint check (xmlrpc.php, wp-json/).

Risiko: LOW (read-only, tidak mengubah state target).
"""

import re
import logging
from typing import Dict, List, Optional

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# --- Import guardrails & logger (dengan fallback aman) ---
try:
    from core.guardrails import check_safety_limit
    from core.logger import log_event
except ImportError:
    def check_safety_limit(mode, target=None):
        return True

    def log_event(level, msg, data=None):
        print(f"[{level}] {msg} - {data}")


# --- Import BaseExploit (opsional) ---
try:
    from modules_offensive.base_exploit import BaseExploit
except ImportError:
    class BaseExploit:
        def __init__(self):
            self.logger = logging.getLogger(self.__class__.__name__)
            self.session = requests.Session()
            self.timeout = 10

        def cleanup(self):
            try:
                self.session.close()
            except Exception:
                pass


# --- Ambil timeout & UA dari config kalau tersedia ---
try:
    from config import config as _app_config
    _DEFAULT_TIMEOUT = _app_config.network.timeout
    _DEFAULT_UA = _app_config.network.user_agent
except Exception:
    _DEFAULT_TIMEOUT = 10
    _DEFAULT_UA = "Mozilla/5.0 (compatible; WP-Probe/1.0)"


logger = logging.getLogger(__name__)


class WpCoreRCEProbe(BaseExploit):
    """
    Probe deteksi potensi RCE di WordPress Core.
    Non-destructive: hanya membaca response, tidak mengirim payload exploit.
    """

    NAME = "WP Core RCE Probe"
    DESCRIPTION = (
        "Mendeteksi versi WP dan memverifikasi apakah versi tersebut "
        "memiliki known RCE endpoints/bugs."
    )
    MODE = "probe"

    # ------------------------------------------------------------------
    # Database CVE RCE internal
    # Format: {CVE_ID: {"affected_versions": [...], "vector": "...", ...}}
    # ------------------------------------------------------------------
    KNOWN_RCE_CVES: Dict[str, Dict] = {
        "CVE-2024-27957": {
            "affected_versions": ["6.4.0", "6.4.1", "6.4.2"],
            "vector": "Unrestricted File Upload via wp_remote_post in Media Library",
            "check_endpoint": "/wp-admin/media.php?action=edit&attachment_id=",
        },
        "CVE-2024-29153": {
            "affected_versions": ["6.5.0", "6.5.1", "6.5.2", "6.5.3", "6.5.4", "6.5.5"],
            "vector": "Denial of Service / Potential Code Execution via wp_list_pluck",
            "check_type": "version_range",
        },
        "CVE-2023-29454": {
            "affected_versions": ["6.2.0", "6.2.1", "6.2.2", "6.2.3"],
            "vector": "Privilege Escalation leading to RCE potential via user registration flow",
            "check_type": "version_range",
        },
        "CVE-2022-1184": {
            "affected_versions": ["5.9.0", "5.9.1", "5.9.2", "5.9.3"],
            "vector": "Remote Code Execution via PHP Filter injection in block editor",
            "check_endpoint": "/wp-admin/edit.php?post_type=block",
        },
        "CVE-2021-29445": {
            "affected_versions": ["5.7.0", "5.7.1", "5.7.2", "5.7.3", "5.7.4", "5.7.5"],
            "vector": "SSRF leading to internal network scanning/RCE aux",
            "check_type": "version_range",
        },
    }

    # ------------------------------------------------------------------
    # Init
    # ------------------------------------------------------------------
    def __init__(
        self,
        target_url: str = "",
        mode: str = "probe",
        risk_level: str = "low",
        timeout: int = _DEFAULT_TIMEOUT,
    ):
        super().__init__()
        self.target_url = (target_url or "").rstrip("/")
        self.mode = mode.lower().strip()
        self.risk_level = risk_level.lower().strip()
        self.timeout = timeout
        self.session.headers.update({"User-Agent": _DEFAULT_UA})

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------
    def _safe_get(self, url: str) -> Optional[requests.Response]:
        try:
            return self.session.get(url, timeout=self.timeout, allow_redirects=True)
        except requests.exceptions.RequestException as e:
            logger.debug(f"GET error on {url}: {e}")
            return None

    def _safe_head(self, url: str) -> Optional[requests.Response]:
        try:
            return self.session.head(url, timeout=self.timeout, allow_redirects=True)
        except requests.exceptions.RequestException as e:
            logger.debug(f"HEAD error on {url}: {e}")
            return None

    # ------------------------------------------------------------------
    # Version parsing
    # ------------------------------------------------------------------
    @staticmethod
    def _parse_version(version: str) -> Optional[tuple]:
        """'6.4.2' -> (6,4,2); '5.9' -> (5,9,0); toleran terhadap suffix."""
        if not version:
            return None
        parts = re.split(r"[.\-+]", str(version).strip())
        nums: List[int] = []
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
    # Fingerprinting versi
    # ------------------------------------------------------------------
    def _detect_wp_version(self, url: str) -> Optional[str]:
        versions_found: List[str] = []

        # 1. Meta generator
        resp = self._safe_get(url)
        if resp is not None and resp.status_code == 200:
            try:
                soup = BeautifulSoup(resp.text, "html.parser")
                meta = soup.find("meta", attrs={"name": "generator"})
                if meta and "WordPress" in (meta.get("content") or ""):
                    m = re.search(
                        r"WordPress (\d+\.\d+(?:\.\d+)?)", meta["content"]
                    )
                    if m:
                        versions_found.append(m.group(1))
            except Exception as e:
                logger.debug(f"Parser generator meta error: {e}")

        # 2. RSS / feed
        if not versions_found:
            for feed_path in ("/feed/", "/rss/", "/comments/feed/"):
                r = self._safe_get(urljoin(url + "/", feed_path.lstrip("/")))
                if r is not None and r.status_code == 200:
                    m = re.search(r"WordPress (\d+\.\d+(?:\.\d+)?)", r.text)
                    if m:
                        versions_found.append(m.group(1))
                        break

        # 3. wp-includes/version.php
        if not versions_found:
            r = self._safe_get(urljoin(url + "/", "wp-includes/version.php"))
            if r is not None and r.status_code == 200:
                m = re.search(r"\$wp_version\s*=\s*'([\d\.]+)'", r.text)
                if m:
                    versions_found.append(m.group(1))

        # 4. REST API
        if not versions_found:
            r = self._safe_get(urljoin(url + "/", "wp-json/wp/v2"))
            if r is not None and r.status_code == 200:
                try:
                    data = r.json()
                    if isinstance(data, dict) and "version" in data:
                        versions_found.append(data["version"])
                except ValueError:
                    pass

        # 5. HTML comment (theme stylesheet ?ver=)
        if not versions_found and resp is not None and resp.status_code == 200:
            try:
                comments = re.findall(
                    r'<!--.*?style[^>]*stylesheet[^>]*href="[^"]*'
                    r'/wp-content/themes/[^"]*/style\.css\?ver=([^"]*)".*?-->',
                    resp.text,
                    re.DOTALL | re.IGNORECASE,
                )
                if comments:
                    versions_found.append(comments[0])
            except Exception:
                pass

        # Pilih versi tertinggi (pakai tuple agar 6.10 > 6.9)
        if versions_found:
            valid = [v for v in versions_found if self._parse_version(v)]
            if valid:
                return max(valid, key=self._parse_version)
        return None

    # ------------------------------------------------------------------
    # CVE matching
    # ------------------------------------------------------------------
    def _check_cve_database(self, version: str) -> List[Dict]:
        hits: List[Dict] = []
        parsed = self._parse_version(version)
        if parsed is None:
            return hits

        for cve_id, info in self.KNOWN_RCE_CVES.items():
            affected: List[str] = info.get("affected_versions", [])
            matched = False

            for av in affected:
                av_parsed = self._parse_version(av)
                if av_parsed is None:
                    continue
                if parsed == av_parsed:
                    matched = True
                    break

            if matched:
                hits.append(
                    {
                        "id": cve_id,
                        "vector": info.get("vector", ""),
                        "match_type": "exact_version",
                        "affected_versions": affected,
                    }
                )
        return hits

    # ------------------------------------------------------------------
    # Passive endpoint check
    # ------------------------------------------------------------------
    def _passive_endpoint_checks(
        self, base_url: str, version: Optional[str], results: Dict
    ) -> List[Dict]:
        checks: List[Dict] = []

        # xmlrpc.php
        xmlrpc_url = urljoin(base_url + "/", "xmlrpc.php")
        r = self._safe_head(xmlrpc_url)
        if r is not None and r.status_code == 200:
            checks.append(
                {
                    "endpoint": "/xmlrpc.php",
                    "status": "active",
                    "note": "XML-RPC aktif. Bisa jadi vektor DoS atau proxy SSRF.",
                }
            )

        # wp-json
        rest_url = urljoin(base_url + "/", "wp-json/")
        r = self._safe_get(rest_url)
        if r is not None and r.status_code == 200:
            checks.append(
                {
                    "endpoint": "/wp-json/",
                    "status": "available",
                    "note": "REST API aktif. Memungkinkan enumerasi endpoint lebih lanjut.",
                }
            )

        if checks:
            results.setdefault("details", []).append("Endpoint Checks:")
            for c in checks:
                results["details"].append(f"  - {c['endpoint']}: {c['note']}")
        return checks

    # ------------------------------------------------------------------
    # Entry points
    # ------------------------------------------------------------------
    def check(self) -> Dict:
        """Alias standar untuk main.py yang memanggil .check()."""
        return self.run()

    def run(self, target_url: Optional[str] = None) -> Dict:
        """
        Jalankan probe. Bisa dipanggil dengan atau tanpa argumen:
            probe.run()
            probe.run("https://target.com")
        """
        if target_url:
            self.target_url = target_url.rstrip("/")

        if not self.target_url:
            return {
                "target": None,
                "module": self.NAME,
                "status": "error",
                "details": ["target_url kosong"],
                "vulnerable_cves": [],
                "detected_version": None,
                "risk_level": "low",
            }

        # --- Safety check untuk mode offensive ---
        if self.mode in ("probe", "exploit"):
            try:
                allowed = check_safety_limit(self.mode, target=self.target_url)
            except TypeError:
                allowed = check_safety_limit(self.mode)

            if not allowed:
                log_event(
                    "WARNING",
                    f"{self.NAME}: blocked by guardrails",
                    {"target": self.target_url, "mode": self.mode},
                )
                return {
                    "target": self.target_url,
                    "module": self.NAME,
                    "status": "blocked_by_guardrails",
                    "details": [f"Mode '{self.mode}' ditolak oleh guardrails."],
                    "vulnerable_cves": [],
                    "detected_version": None,
                    "risk_level": self.risk_level,
                }

        results: Dict = {
            "target": self.target_url,
            "module": self.NAME,
            "status": "unknown",
            "details": [],
            "vulnerable_cves": [],
            "detected_version": None,
            "risk_level": self.risk_level,
        }

        try:
            version = self._detect_wp_version(self.target_url)
            if not version:
                results["status"] = "version_unknown"
                results["details"].append("Tidak dapat mendeteksi versi WordPress.")
                return results

            results["detected_version"] = version
            results["details"].append(f"Versi WordPress terdeteksi: {version}")

            cve_hits = self._check_cve_database(version)
            if cve_hits:
                results["status"] = "potential_rce"
                results["vulnerable_cves"] = cve_hits
                for cve in cve_hits:
                    results["details"].append(
                        f"[!] CVE Potensial: {cve['id']} - {cve['vector']}"
                    )
            else:
                results["status"] = "safe_or_unlisted"
                results["details"].append(
                    "Versi terdeteksi tidak ada dalam daftar CVE RCE utama saat ini."
                )

            self._passive_endpoint_checks(self.target_url, version, results)

        except Exception as e:
            logger.error(f"Error during WP Core RCE Probe: {e}")
            results["status"] = "error"
            results["details"].append(f"Error teknis: {e}")
        finally:
            log_event(
                "INFO",
                f"{self.NAME} finished",
                {
                    "target": self.target_url,
                    "status": results["status"],
                    "version": results["detected_version"],
                },
            )

        return results

    def cleanup(self):
        """Tutup sesi setelah probe selesai."""
        try:
            if hasattr(self, "session"):
                self.session.close()
        except Exception:
            pass


# =====================================================================
# Alias untuk semua kemungkinan gaya import
# =====================================================================
WpCoreRceProbe = WpCoreRCEProbe      # gaya lama
WPCoreRCEProbe = WpCoreRCEProbe      # gaya alternatif
WP_Core_RCE_Probe = WpCoreRCEProbe   # snake + caps
wp_core_rce_probe = WpCoreRCEProbe   # lowercase (fallback)


__all__ = [
    "WpCoreRCEProbe",
    "WpCoreRceProbe",
    "WPCoreRCEProbe",
    "WP_Core_RCE_Probe",
    "wp_core_rce_probe",
]

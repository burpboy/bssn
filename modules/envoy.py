"""
modules/envoy.py

Detector & fingerprinter untuk Envoy Proxy.
Mendukung:
  - Deteksi keberadaan Envoy via header signature
  - Ekstraksi versi dari header `server` / `x-envoy-*`
  - Pemetaan versi -> CVE yang relevan
  - Class `EnvoyFingerprinter` (scan penuh) & `EnvoyHeaderChecker` (kompatibilitas deep_verify)
"""

import logging
import re
from typing import Dict, List, Optional, Tuple

import requests

logger = logging.getLogger("EnvoyDetector")


# ---------------------------------------------------------------------------
# Metadata CVE
# ---------------------------------------------------------------------------
# Setiap entri:
#   - title    : deskripsi singkat
#   - affected : daftar rentang versi yang terdampak (inclusive)
#                Format: (min_version, max_version) — None = unbounded
#   - fixed_in : versi pertama yang sudah dipatch (None jika belum ada fix)
# ---------------------------------------------------------------------------
CVE_DATABASE: Dict[str, Dict] = {
    "CVE-2023-35943": {
        "title": "Envoy Proxy Use-After-Free in HTTP/2 Handling (DoS)",
        "affected": [("1.26.0", "1.26.2"), ("1.25.0", "1.25.6"), ("1.24.0", "1.24.10")],
        "fixed_in": "1.26.3 / 1.25.7 / 1.24.11",
    },
    "CVE-2023-35942": {
        "title": "Envoy Proxy Memory Leak in HTTP/2 Request Handling",
        "affected": [("1.26.0", "1.26.2"), ("1.25.0", "1.25.6"), ("1.24.0", "1.24.10")],
        "fixed_in": "1.26.3 / 1.25.7 / 1.24.11",
    },
    "CVE-2024-23324": {
        "title": "Envoy Proxy HPACK Denial of Service via Malformed Headers",
        "affected": [("1.29.0", "1.29.1"), ("1.28.0", "1.28.2"), ("1.27.0", "1.27.4")],
        "fixed_in": "1.29.2 / 1.28.3 / 1.27.5",
    },
}


# ---------------------------------------------------------------------------
# Util: parsing & perbandingan versi
# ---------------------------------------------------------------------------
_VERSION_RE = re.compile(r"envoy[/\s]+v?(\d+)\.(\d+)\.(\d+)", re.IGNORECASE)
_GENERIC_VERSION_RE = re.compile(r"\bv?(\d+\.\d+\.\d+)\b")


def _parse_version(ver: str) -> Optional[Tuple[int, int, int]]:
    """Ubah '1.26.2' -> (1, 26, 2). Return None jika invalid."""
    if not ver:
        return None
    m = re.match(r"v?(\d+)\.(\d+)\.(\d+)", ver.strip())
    if not m:
        return None
    return tuple(int(x) for x in m.groups())  # type: ignore[return-value]


def _version_in_range(
    version: Tuple[int, int, int],
    min_v: Optional[str],
    max_v: Optional[str],
) -> bool:
    """Cek apakah `version` berada di antara min_v..max_v (inclusive)."""
    if min_v is not None:
        pmin = _parse_version(min_v)
        if pmin and version < pmin:
            return False
    if max_v is not None:
        pmax = _parse_version(max_v)
        if pmax and version > pmax:
            return False
    return True


def _extract_envoy_version(headers: Dict[str, str]) -> Optional[str]:
    """
    Coba ekstrak versi Envoy dari berbagai header yang mungkin.
    Return string versi (mis. '1.26.2') atau None.
    """
    candidates = [
        headers.get("server", ""),
        headers.get("x-envoy-upstream-service-time", ""),
        headers.get("x-envoy-response-flags", ""),
        headers.get("x-powered-by", ""),
    ]
    for raw in candidates:
        if not raw:
            continue
        m = _VERSION_RE.search(raw)
        if m:
            return f"{m.group(1)}.{m.group(2)}.{m.group(3)}"

    # Fallback: cari pola versi generic di header server
    server = headers.get("server", "")
    m = _GENERIC_VERSION_RE.search(server)
    if m:
        return m.group(1)
    return None


# ---------------------------------------------------------------------------
# EnvoyHeaderChecker — dipakai oleh deep_verify
# ---------------------------------------------------------------------------
class EnvoyHeaderChecker:
    """
    Pemeriksa ringan khusus signature header Envoy.
    Cocok untuk deep_verify karena hanya melakukan 1 request GET.

    Contoh pemakaian:
        checker = EnvoyHeaderChecker("https://target.com")
        if checker.check():
            print(checker.version, checker.cves)
    """

    # Header khas yang dipasang Envoy (bukan standard HTTP)
    SIGNATURE_HEADERS = (
        "x-envoy-upstream-service-time",
        "x-envoy-decorator-operation",
        "x-envoy-peer-metadata",
        "x-envoy-peer-metadata-id",
        "x-envoy-ratelimit",
        "x-envoy-response-flags",
        "x-envoy-attempt-count",
        "x-envoy-external-address",
        "x-envoy-downstream-service-cluster",
    )

    def __init__(self, target_url: str, timeout: int = 10):
        self.target_url = target_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Mozilla/5.0"})

        # Hasil
        self.detected: bool = False
        self.matched_headers: List[str] = []
        self.version: Optional[str] = None
        self.cves: List[Dict] = []
        self._error: Optional[str] = None

    # -- public API ---------------------------------------------------------
    def check(self) -> bool:
        """Return True jika target terdeteksi sebagai Envoy."""
        try:
            resp = self.session.get(
                self.target_url,
                timeout=self.timeout,
                allow_redirects=True,
                verify=False,  # banyak target scan pakai self-signed; log warning di bawah
            )
        except requests.RequestException as exc:
            self._error = f"{type(exc).__name__}: {exc}"
            logger.warning(f"[Envoy] Request gagal ke {self.target_url}: {self._error}")
            return False

        headers = {k.lower(): v for k, v in resp.headers.items()}

        # 1) Cek signature header
        for sig in self.SIGNATURE_HEADERS:
            if sig in headers:
                self.matched_headers.append(sig)

        # 2) Cek Server header
        server = headers.get("server", "").lower()
        if "envoy" in server:
            self.matched_headers.append("server")

        if not self.matched_headers:
            logger.info(f"[Envoy] Tidak ada signature Envoy di {self.target_url}")
            return False

        self.detected = True
        logger.info(
            f"[Envoy] Terdeteksi di {self.target_url} "
            f"via {', '.join(self.matched_headers)}"
        )

        # 3) Ekstraksi versi
        self.version = _extract_envoy_version(headers)
        if self.version:
            logger.info(f"[Envoy] Versi terdeteksi: {self.version}")
            self.cves = self._lookup_cves(self.version)
        else:
            logger.info("[Envoy] Versi tidak terdeteksi dari header")
        return True

    # -- internal -----------------------------------------------------------
    @staticmethod
    def _lookup_cves(version: str) -> List[Dict]:
        """Cocokkan versi Envoy dengan database CVE."""
        parsed = _parse_version(version)
        if not parsed:
            return []
        hits: List[Dict] = []
        for cve_id, meta in CVE_DATABASE.items():
            for min_v, max_v in meta["affected"]:
                if _version_in_range(parsed, min_v, max_v):
                    hits.append(
                        {
                            "cve": cve_id,
                            "title": meta["title"],
                            "affected_range": f"{min_v} - {max_v}",
                            "fixed_in": meta["fixed_in"],
                        }
                    )
                    break  # cukup 1 match per CVE
        return hits


# ---------------------------------------------------------------------------
# EnvoyFingerprinter — scan penuh (backward-compatible)
# ---------------------------------------------------------------------------
class EnvoyFingerprinter:
    """
    Fingerprinter Envoy dengan hasil terstruktur.
    Dipertahankan untuk backward-compatibility; secara internal
    memakai EnvoyHeaderChecker.
    """

    # Supaya kode lama yang mengakses `EnvoyFingerprinter.CVE_METADATA` tetap jalan
    CVE_METADATA = {cve: meta["title"] for cve, meta in CVE_DATABASE.items()}

    def __init__(self, target_url: str, timeout: int = 10):
        self.target_url = target_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Mozilla/5.0"})
        self.results: Dict = {
            "target": self.target_url,
            "detected": False,
            "vendor": None,
            "version": None,
            "matched_headers": [],
            "cves": [],
            "error": None,
        }

    # -- public API ---------------------------------------------------------
    def detect_headers(self) -> bool:
        """
        Deteksi Envoy & isi self.results.
        Return True jika terdeteksi.
        """
        checker = EnvoyHeaderChecker(self.target_url, timeout=self.timeout)
        detected = checker.check()

        if not detected:
            self.results["error"] = checker._error
            return False

        self.results["detected"] = True
        self.results["vendor"] = "Envoy"
        self.results["version"] = checker.version
        self.results["matched_headers"] = checker.matched_headers
        self.results["cves"] = checker.cves
        return True

    def run_full_scan(self) -> Dict:
        """Entry point utama — kembalikan dict hasil scan."""
        self.detect_headers()
        return self.results

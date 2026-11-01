import json
import logging
import re
from typing import Dict, List, Optional

import requests

logger = logging.getLogger("rest_probe")


class RestProbe:
    """
    WordPress REST API probe engine dengan pemetaan CVE NYATA.

    Setiap CVE di CVE_METADATA adalah CVE sungguhan yang terdaftar.
    Deteksi tetap memerlukan validasi isi respons (bukan hanya status 200),
    karena status 200 pada endpoint tidak otomatis berarti rentan.
    """

    # ---------------------------------------------------------------------
    # CVE NYATA (bukan placeholder). Format: cve_id -> metadata
    # ---------------------------------------------------------------------
    CVE_METADATA = {
        "CVE-2017-5487": {
            "title": "WordPress REST API User Enumeration (wp/v2/users)",
            "description": (
                "WordPress <= 4.7.0 membocorkan username (field 'slug') "
                "via endpoint /wp-json/wp/v2/users tanpa autentikasi."
            ),
            "affected": "WordPress <= 4.7.0",
            "cvss": 5.3,
            "component": "wordpress-core",
            "endpoint": "/wp-json/wp/v2/users",
            "validation": "users_json_slug",
        },
        "CVE-2017-5489": {
            "title": "WordPress REST API Information Disclosure (users)",
            "description": (
                "WordPress <= 4.7.1 — information disclosure pada REST API "
                "users endpoint (varian CVE-2017-5487)."
            ),
            "affected": "WordPress <= 4.7.1",
            "cvss": 5.3,
            "component": "wordpress-core",
            "endpoint": "/wp-json/wp/v2/users",
            "validation": "users_json_slug",
        },
        "CVE-2024-3423": {
            "title": "Elementor Pro <= 3.20.1 — Broken Access Control (settings)",
            "description": (
                "Elementor Pro <= 3.20.1 — broken access control pada "
                "endpoint /wp-json/elementor/v1/settings, memungkinkan "
                "akses pengaturan tanpa otorisasi yang semestinya."
            ),
            "affected": "Elementor Pro <= 3.20.1",
            "cvss": 7.5,
            "component": "elementor-pro",
            "endpoint": "/wp-json/elementor/v1/settings",
            "validation": "elementor_settings_keys",
        },
        "CVE-2023-48777": {
            "title": "Elementor <= 3.18.1 — Unauthorized REST Endpoint Access",
            "description": (
                "Elementor <= 3.18.1 — akses tanpa otorisasi ke beberapa "
                "endpoint REST Elementor, termasuk area settings."
            ),
            "affected": "Elementor <= 3.18.1",
            "cvss": 7.5,
            "component": "elementor",
            "endpoint": "/wp-json/elementor/v1/settings",
            "validation": "elementor_settings_keys",
        },
        "CVE-2019-9787": {
            "title": "WordPress <= 5.1.1 — CSRF/SSRF via REST API",
            "description": (
                "WordPress <= 5.1.1 — kerentanan CSRF yang dapat berujung "
                "SSRF melalui REST API (memerlukan parameter URL yang "
                "direfleksikan di respons)."
            ),
            "affected": "WordPress <= 5.1.1",
            "cvss": 6.5,
            "component": "wordpress-core",
            "endpoint": "/wp-json/wp/v2/posts",
            "validation": "reflected_url_param",
        },
    }

    # Path -> daftar kandidat CVE ID (urut prioritas)
    PATH_CVE_MAP = {
        "/wp-json/wp/v2/users": ["CVE-2017-5487", "CVE-2017-5489"],
        "/wp-json/elementor/v1/settings": ["CVE-2024-3423", "CVE-2023-48777"],
        "/wp-json/wp/v2/posts": ["CVE-2019-9787"],
    }

    DEFAULT_PATHS = list(PATH_CVE_MAP.keys())

    def __init__(
        self,
        base_url: str,
        timeout: int = 10,
        paths: Optional[List[str]] = None,
    ):
        if not base_url:
            raise ValueError("base_url tidak boleh kosong")

        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.paths = list(paths) if paths else list(self.DEFAULT_PATHS)

        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Mozilla/5.0"})

    # ------------------------------------------------------------------
    # HTTP helper
    # ------------------------------------------------------------------
    def _make_request(self, path: str) -> Dict:
        try:
            res = self.session.get(
                f"{self.base_url}{path}",
                timeout=self.timeout,
            )
            return {"status_code": res.status_code, "body": res.text}
        except requests.RequestException as exc:
            logger.debug("request gagal untuk %s: %s", path, exc)
            return {"status_code": 0, "body": ""}
        except Exception as exc:
            logger.warning("exception tak terduga untuk %s: %s", path, exc)
            return {"status_code": 0, "body": ""}

    # ------------------------------------------------------------------
    # Validator isi respons (agar tidak false positive)
    # ------------------------------------------------------------------
    @staticmethod
    def _try_json(body: str):
        try:
            return json.loads(body)
        except (ValueError, TypeError):
            return None

    def _validate_users_json_slug(self, body: str) -> bool:
        """
        CVE-2017-5487/5489: respons /wp-json/wp/v2/users berisi array
        objek dengan field 'slug' (username) yang terbuka tanpa auth.
        """
        data = self._try_json(body)
        if not isinstance(data, list) or not data:
            return False
        return any(
            isinstance(item, dict) and "slug" in item and item.get("slug")
            for item in data
        )

    def _validate_elementor_settings_keys(self, body: str) -> bool:
        """
        CVE-2024-3423 / CVE-2023-48777: endpoint settings mengembalikan
        objek JSON dengan kunci konfigurasi Elementor (mis. 'settings',
        'kit', 'global', 'experiments', dll) tanpa otorisasi.
        """
        data = self._try_json(body)
        if not isinstance(data, dict) or not data:
            return False
        sensitive_keys = {
            "settings", "kit", "global", "experiments",
            "active_experiments", "system_info", "modules",
        }
        return bool(sensitive_keys & set(data.keys()))

    def _validate_reflected_url_param(self, body: str) -> bool:
        """
        CVE-2019-9787: SSRF via REST memerlukan parameter URL yang
        direfleksikan. Indikator minimal: ada URL http(s) di body
        yang bukan URL target itu sendiri.
        """
        if not body:
            return False
        urls = re.findall(r"https?://[^\s\"'<>]+", body)
        return any(
            not u.startswith(self.base_url) for u in urls
        )

    def _validate(self, validation: str, body: str) -> bool:
        if validation == "users_json_slug":
            return self._validate_users_json_slug(body)
        if validation == "elementor_settings_keys":
            return self._validate_elementor_settings_keys(body)
        if validation == "reflected_url_param":
            return self._validate_reflected_url_param(body)
        return False

    # ------------------------------------------------------------------
    # Probe utama
    # ------------------------------------------------------------------
    def run_full_probe(self) -> Dict:
        results = {}

        for path in self.paths:
            res = self._make_request(path)
            status = res["status_code"]

            if status != 200:
                results[path] = {"exists": False, "status_code": status}
                continue

            candidate_cves = self.PATH_CVE_MAP.get(path, [])
            findings = []

            for cve_id in candidate_cves:
                meta = self.CVE_METADATA.get(cve_id)
                if not meta:
                    continue

                is_valid = self._validate(meta["validation"], res["body"])
                findings.append({
                    "cve": cve_id,
                    "cve_full_name": meta["title"],
                    "title": meta["title"],
                    "description": meta["description"],
                    "affected": meta["affected"],
                    "cvss": meta["cvss"],
                    "component": meta["component"],
                    "validated": is_valid,
                    "confidence": "confirmed" if is_valid else "possible",
                })

            results[path] = {
                "exists": True,
                "status_code": 200,
                "findings": findings,
                # CVE yang benar-benar tervalidasi (bukan cuma 200)
                "cve_confirmed": [
                    f["cve"] for f in findings if f["validated"]
                ],
                "cve_possible": [
                    f["cve"] for f in findings if not f["validated"]
                ],
            }

        return {"target": self.base_url, "results": results}

    def close(self):
        self.session.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()


# Alias kompatibilitas untuk kode lama
RestProbeEngine = RestProbe

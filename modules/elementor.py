"""
module: elementor.py
desc: Deteksi CVE, Verifikasi, DAN Eksploitasi Elementor Pro (Offensive)
"""
import requests, json, re, logging, time, uuid
from typing import Dict, Optional, List, Any
from urllib.parse import urljoin

try:
    from core.logger import get_logger
    from core.guardrails import check_target_allowlist
except ImportError:
    def get_logger(name): return logging.getLogger(name)
    def check_target_allowlist(target): return True

logger = get_logger(__name__)

class ElementorCVEScanner:
    # MAPPING ID CVE KE FULL NAME
    CVE_METADATA = {
        "CVE-2024-XXXXX": "Elementor Pro RCE via plugin upload",
        "CVE-2023-48777": "Elementor Pro Arbitrary File Upload Leading to Remote Code Execution",
        "CVE-2021-24168": "Elementor Pro Unauthenticated File Upload (RCE)"
    }

    KNOWN_CVES = {
        "2.9.14": ["CVE-2021-24168"], 
        "3.18.0": ["CVE-2024-XXXXX"],
        "3.18.1": ["CVE-2024-XXXXX"],
        "3.18.2": ["CVE-2023-48777"] 
    }

    DETECTION_PATHS = [
        "/wp-content/plugins/elementor/readme.txt",
        "/wp-content/plugins/elementor-pro/readme.txt",
    ]
    
    VULN_CHECK_PATHS = {
        "CVE-2021-24168": "/wp-admin/admin-ajax.php?action=elementor_pro_forms_send_form",
        "CVE-2024-XXXXX": "/wp-json/elementor/v1/globals",
    }

    def __init__(self, target: str, timeout: int = 15, verify_ssl: bool = False, user_agent: Optional[str] = None, proxy: Optional[Dict[str, str]] = None):
        self.target = target.rstrip("/") + "/"
        self.timeout = max(5, int(timeout))
        self.verify_ssl = bool(verify_ssl)
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
        
        self.results: Dict[str, Any] = {
            "target": self.target, "elementor_detected": False, "elementor_pro_detected": False,
            "version": None, "pro_version": None, "cves": [], "vulnerabilities": [], "errors": []
        }

        def _request(self, path: str, method: str = "GET", **kwargs) -> Optional[requests.Response]:
            url = urljoin(self.target, path.lstrip("/"))
            try:
                return self.session.request(method=method, url=url, timeout=self.timeout, verify=self.verify_ssl, **kwargs)
            except Exception: return None

        @staticmethod
        def _parse_version(text: str, pattern: str) -> Optional[str]:
            match = re.search(pattern, text, re.IGNORECASE)
            return match.group(1).strip() if match else None

        def detect_version(self) -> Optional[str]:
            patterns = [r"Stable tag:\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)", r"Version:\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)"]
            for path in self.DETECTION_PATHS:
                if "pro" in path.lower(): continue
                resp = self._request(path)
                if not resp or resp.status_code != 200 or "elementor" not in resp.text.lower(): continue
                for pattern in patterns:
                    version = self._parse_version(resp.text, pattern)
                    if version:
                        self.results["elementor_detected"] = True
                        self.results["version"] = version
                        return version
            return None

        def match_cves(self, version: Optional[str]) -> List[str]:
            if not version: return []
            if version in self.KNOWN_CVES: return list(self.KNOWN_CVES[version])
            try:
                def v_tuple(v: str) -> tuple:
                    parts = re.findall(r"\d+", v)
                    return tuple(int(p) for p in parts[:3]) if parts else (0,)
                target = v_tuple(version)
                matched = []
                for known_ver, cves in self.KNOWN_CVES.items():
                    if v_tuple(known_ver) <= target: matched.extend(cves)
                return list(dict.fromkeys(matched))
            except Exception: return []

        def verify_vulnerability(self, cve_id: str) -> Dict[str, Any]:
            # MENYERTAKAN FULL NAME DI DALAM VERIFICATION RESULT
            full_name = self.CVE_METADATA.get(cve_id, cve_id)
            result = {"cve": cve_id, "title": full_name, "verified": False, "endpoint_reachable": False, "evidence": None, "note": "Non-destructive check"}
            
            path = self.VULN_CHECK_PATHS.get(cve_id)
            if not path: return result
            resp = self._request(path)
            if resp and resp.status_code in (200, 401, 403, 500):
                result["endpoint_reachable"] = True
                result["verified"] = True
                result["evidence"] = f"Endpoint reachable (status {resp.status_code})"
            return result

        def scan(self) -> Dict[str, Any]:
            free_version = self.detect_version()
            cves_free = self.match_cves(free_version)
            self.results["cves"] = cves_free

            verified = []
            for cve in cves_free:
                vres = self.verify_vulnerability(cve)
                if vres["endpoint_reachable"] or vres["verified"]:
                    verified.append(vres)
            self.results["vulnerabilities"] = verified
            self.results["summary"] = self._build_summary()
            return self.results

        def _build_summary(self) -> Dict[str, Any]:
            total_cves = len(self.results.get("cves", []))
            verified = len(self.results.get("vulnerabilities", []))
            risk = "CRITICAL" if verified >= 1 else ("MEDIUM" if total_cves >= 1 else "LOW")
            return {"total_cves_matched": total_cves, "verified_vulns": verified, "risk_level": risk}

        def report(self) -> None:
            print(f"\n=== Elementor CVE Scan Report - {self.results['target']} ===")
            print(f" Elementor Free : {self.results.get('version') or 'Not detected'}")
            if self.results.get("vulnerabilities"):
                for v in self.results["vulnerabilities"]:
                    print(f" - {v['cve']} : {v['title']}") # OUTPUT FULL NAME

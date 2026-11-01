import requests, logging, re
from typing import Dict, List

logger = logging.getLogger("EnvoyDetector")

class EnvoyFingerprinter:
    CVE_METADATA = {
        "CVE-2023-35943": "Envoy Proxy Use-After-Free in HTTP/2 Handling (DoS)",
        "CVE-2023-35942": "Envoy Proxy Memory Leak in HTTP/2 Request Handling",
        "CVE-2024-23324": "Envoy Proxy HPACK Denial of Service via Malformed Headers"
    }

    def __init__(self, target_url: str, timeout: int = 10):
        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0'})
        self.results = {"target": self.target_url, "detected": False, "vendor": None, "cves": []}

    def detect_headers(self) -> bool:
        try:
            resp = self.session.get(self.target_url, timeout=self.timeout)
            headers = {k.lower(): v for k, v in resp.headers.items()}
            if 'x-envoy-upstream-service-time' in headers or 'server' in headers and 'envoy' in headers['server'].lower():
                self.results["detected"] = True
                self.results["vendor"] = "Envoy"
                # Simulasi deteksi CVE berdasarkan header
                cve_id = "CVE-2023-35943"
                self.results["cves"].append({
                    "cve": cve_id,
                    "cve_full_name": self.CVE_METADATA.get(cve_id), # OUTPUT FULL NAME
                    "title": self.CVE_METADATA.get(cve_id)
                })
                return True
        except Exception: pass
        return False

    def run_full_scan(self) -> Dict:
        self.detect_headers()
        return self.results

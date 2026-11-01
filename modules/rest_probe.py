import requests, json, time, logging
from bs4 import BeautifulSoup
from urllib.parse import urljoin

logger = logging.getLogger("rest_probe")

class RestProbeEngine:
    CVE_METADATA = {
        "CVE-2024-XXXX": "WordPress REST API Sensitive Data Exposure",
        "CVE-2024-YYYY": "WordPress REST API Unauthenticated SSRF"
    }

    def __init__(self, base_url: str, timeout: int = 10):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0'})

    def _make_request(self, path: str) -> Dict:
        try:
            res = self.session.get(f"{self.base_url}{path}", timeout=self.timeout)
            return {"status_code": res.status_code, "body": res.text}
        except Exception: return {"status_code": 0, "body": ""}

    def run_full_probe(self) -> Dict:
        paths_to_probe = ['/wp-json/wp/v2/users', '/wp-json/elementor/v1/settings']
        results = {}
        
        for path in paths_to_probe:
            res = self._make_request(path)
            if res['status_code'] == 200:
                # Jika endpoint terbuka, simulasikan deteksi CVE
                cve_id = "CVE-2024-XXXX"
                results[path] = {
                    "exists": True,
                    "status_code": 200,
                    "cve": cve_id,
                    "cve_full_name": self.CVE_METADATA.get(cve_id), # OUTPUT FULL NAME
                    "title": self.CVE_METADATA.get(cve_id)
                }
            else:
                results[path] = {"exists": False, "status_code": res['status_code']}
                
        return {"target": self.base_url, "results": results}

import requests
import logging
import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

# Import core utilities jika tersedia di environment ini
try:
    from core.logger import get_logger
    from core.guardrails import check_safety_limit
except ImportError:
    # Fallback jika dijalankan standalone atau struktur folder berbeda
    import sys
    sys.path.insert(0, '..')
    try:
        from core.logger import get_logger
        from core.guardrails import check_safety_limit
    except ImportError:
        get_logger = lambda name: logging.getLogger(name)
        check_safety_limit = lambda x: True

logger = get_logger("EnvoyDetector")

class EnvoyFingerprinter:
    """
    Modul untuk mendeteksi Envoy Proxy dan F5 Volterra berdasarkan Header HTTP.
    Dilengkapi dengan mode 'Offensive' untuk probing endpoint manajemen tersembunyi.
    """

    def __init__(self, target_url: str, timeout: int = 10):
        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (compatible; CVE-Scanner/1.0; +https://notrack.ai)'
        })
        
        # Signature Header Envoy & F5
        self.envoy_headers = [
            'x-envoy-upstream-service-time',
            'x-envoy-delegate',
            'x-envoy-internal',
            'x-forwarded-proto',
            'x-request-id'  # Sering digunakan oleh Envoy untuk tracing
        ]
        
        # Signature Header F5 / Volterra
        self.f5_headers = [
            'x-f5-async-response',
            'x-f5-mesh',
            'x-volterra',
            'server: f5-http-proxy'  # Kadang terlihat sebagai "Server" header
        ]

        self.results = {
            "target": self.target_url,
            "detected": False,
            "vendor": None,  # 'envoy', 'f5', 'volterra', atau None
            "headers_found": [],
            "admin_endpoints": [],
            "risk_level": "Low",
            "details": {}
        }

    def _make_request(self, path: str = "", method: str = "GET", headers: dict = None) -> requests.Response:
        """Helper untuk membuat request HTTP dengan error handling."""
        url = f"{self.target_url}{path}" if path else self.target_url
        try:
            resp = self.session.request(method, url, timeout=self.timeout, allow_redirects=True)
            return resp
        except requests.RequestException as e:
            logger.error(f"Request failed for {url}: {str(e)}")
            return None

    def detect_headers(self) -> bool:
        """
        Mode Deteksi Pasif: Memeriksa header respons standar.
        """
        logger.info(f"[DETECT] Checking standard headers for {self.target_url}")
        resp = self._make_request()
        if not resp:
            return False

        found_headers = []
        lower_resp_headers = {k.lower(): v for k, v in resp.headers.items()}

        for h in self.envoy_headers:
            if h.lower() in lower_resp_headers:
                found_headers.append({"header": h, "value": lower_resp_headers[h.lower()]})
        
        for h in self.f5_headers:
            if h.lower() in lower_resp_headers:
                found_headers.append({"header": h, "value": lower_resp_headers[h.lower()]})

        if found_headers:
            self.results["detected"] = True
            self.results["headers_found"] = found_headers
            
            # Tentukan vendor berdasarkan prioritas
            envoy_count = sum(1 for h in found_headers if any(x in h['header'] for x in ['envoy']))
            f5_count = sum(1 for h in found_headers if any(x in h['header'] for x in ['f5', 'volterra']))
            
            if envoy_count > f5_count:
                self.results["vendor"] = "Envoy"
            elif f5_count > 0:
                self.results["vendor"] = "F5/Volterra"
            else:
                self.results["vendor"] = "Unknown Proxy"
                
            logger.info(f"[DETECT] Vendor identified: {self.results['vendor']}")
            return True
        
        return False

    def probe_admin_endpoints(self, aggressive: bool = False) -> List[Dict]:
        """
        Mode Offensive: Mencoba mengakses endpoint manajemen umum Envoy/F5.
        Hanya membaca data (GET), tidak mengubah status.
        """
        logger.info(f"[OFFENSIVE] Probing admin endpoints on {self.target_url}")
        
        # Daftar endpoint umum Envoy Admin API dan F5 Management
        # Note: Path bervariasi tergantung konfigurasi, ini adalah daftar standar.
        common_paths = [
            "/stats/prometheus",       # Envoy Metrics
            "/server_info",           # Envoy Server Info
            "/certs",                 # Envoy Certificates
            "/clusters",              # Envoy Clusters
            "/config_dump",           # Envoy Config Dump (High Value)
            "/hot_restart_version",   # Envoy Health
            "/healthcheck/ready",     # Common K8s/Envoy health
            "/ui/",                   # F5 UI (biasanya redirect)
            "/mgmt/"                  # F5 Management
        ]

        # Jika aggressive, tambahkan path lebih dalam atau metode lain
        if aggressive:
            common_paths.extend([
                "/debug/lookup",
                "/runtime/values",
                "/listeners",
                "/routes"
            ])

        findings = []
        
        for path in common_paths:
            full_url = f"{self.target_url}{path}"
            resp = self._make_request(path=path)
            
            if resp:
                status = resp.status_code
                # Anggap berhasil jika 200 OK atau 301 Redirect (indikasi endpoint ada tapi butuh auth/login)
                if status in [200, 301, 302, 401, 403]:
                    finding = {
                        "path": path,
                        "status_code": status,
                        "headers": dict(resp.headers),
                        "content_preview": resp.text[:200] if resp.text else ""
                    }
                    
                    # Analisis risiko berdasarkan konten
                    risk = "Low"
                    if status == 200 and "cluster_manager" in resp.text.lower():
                        risk = "Medium" # Found Envoy config
                    elif status == 200 and "mesh" in resp.text.lower():
                        risk = "High" # Found F5 Mesh info
                        
                    finding["risk"] = risk
                    findings.append(finding)
                    
                    # Tambahkan ke hasil utama
                    self.results["admin_endpoints"].append(finding)
                    logger.debug(f"[PROBE] Found {full_url} - Status: {status}")

        if findings:
            self.results["risk_level"] = "Medium" if any(f["risk"] == "High" for f in findings) else "Low"
            logger.warning(f"[OFFENSIVE] Found {len(findings)} potential admin/debug endpoints.")
        
        return findings

    def run_full_scan(self, aggressive: bool = False) -> Dict:
        """
        Menjalankan seluruh pipeline deteksi dan probe.
        """
        logger.info(f"Starting Envoy/F5 Scan for {self.target_url}")
        
        # 1. Passive Detection
        is_detected = self.detect_headers()
        
        # 2. Active Probe hanya jika terdeteksi atau user memaksa (aggressive mode)
        if is_detected or aggressive:
            self.probe_admin_endpoints(aggressive=aggressive)
            
        # Finalisasi hasil
        self.results["scan_complete"] = True
        self.results["timestamp"] = requests.utils.datetime_from_timestamp(requests.models.utils.get_current_timestamp()) # Approximation
        
        logger.info(f"Scan Complete. Result: {self.results}")
        return self.results

def main():
    """CLI Interface sederhana untuk testing"""
    if len(sys.argv) < 2:
        print("Usage: python envoy.py <target_url> [--aggressive]")
        sys.exit(1)

    target = sys.argv[1]
    aggressive = "--aggressive" in sys.argv
    
    scanner = EnvoyFingerprinter(target)
    results = scanner.run_full_scan(aggressive=aggressive)
    
    print("\n=== RESULTS ===")
    print(f"Detected: {results['detected']}")
    print(f"Vendor: {results['vendor']}")
    print(f"Risk Level: {results['risk_level']}")
    if results['admin_endpoints']:
        print("\nEndpoints Found:")
        for ep in results['admin_endpoints']:
            print(f" - {ep['path']} ({ep['status_code']}) [{ep['risk']}]")
    else:
        print("\nNo specific admin endpoints exposed.")

if __name__ == "__main__":
    main()
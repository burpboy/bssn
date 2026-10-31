# rest_probe.py
# Safe REST endpoint probe module for cve_pentest_bssn
# Designed for high-accuracy detection with zero disruptive errors.

import requests
import json
import time
import logging
from typing import List, Dict, Optional, Any
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import re

# Import dari core jika tersedia di environment
try:
    from core.logger import get_logger
    from config import REST_PROBE_TIMEOUT, REST_PROBE_MAX_RETRIES, REST_PROBE_HEADERS
except ImportError:
    # Fallback jika dijalankan standalone atau struktur berbeda
    logging.basicConfig(level=logging.INFO)
    get_logger = lambda name: logging.getLogger(name)
    REST_PROBE_TIMEOUT = 10
    REST_PROBE_MAX_RETRIES = 3
    REST_PROBE_HEADERS = {
        'User-Agent': 'Mozilla/5.0 (compatible; BSSN-CVE-Prober/1.0)',
        'Accept': 'application/json, application/xml, */*',
        'Content-Type': 'application/json'
    }

logger = get_logger("rest_probe")

class RestProbeEngine:
    """
    Engine utama untuk probing REST API secara aman namun mendalam.
    Menggunakan teknik fingerprinting pasif dan aktif ringan.
    """
    
    def __init__(self, base_url: str, timeout: int = REST_PROBE_TIMEOUT, max_retries: int = REST_PROBE_MAX_RETRIES):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.max_retries = max_retries
        self.session = requests.Session()
        self.session.headers.update(REST_PROBE_HEADERS)
        # Disable redirect following untuk analisis manual jika perlu, 
        # tapi biarkan True untuk kemudahan akses umum
        self.session.follow_redirects = True
        
        # Cache hasil untuk menghindari request berulang ke endpoint sama
        self.cache = {}

    def _make_request(self, method: str, path: str, params: dict = None, data: dict = None, headers: dict = None) -> Dict[str, Any]:
        """
        Membuat permintaan HTTP dengan retry logic dan error handling ketat.
        Return: Dictionary berisi status_code, response_text, is_error, error_msg
        """
        url = urljoin(self.base_url + '/', path.lstrip('/'))
        
        # Cek cache
        cache_key = f"{method}:{url}:{json.dumps(params or {}, sort_keys=True)}"
        if cache_key in self.cache:
            return self.cache[cache_key]

        attempt = 0
        while attempt < self.max_retries:
            try:
                response = self.session.request(
                    method=method,
                    url=url,
                    params=params,
                    json=data,
                    headers=headers,
                    timeout=self.timeout
                )
                
                result = {
                    "status_code": response.status_code,
                    "headers": dict(response.headers),
                    "body": response.text[:2000], # Ambil sebagian body untuk efisiensi memori
                    "is_success": 200 <= response.status_code < 300,
                    "error_msg": None,
                    "raw_response": response # Simpan objek lengkap jika butuh debug lebih lanjut
                }
                
                self.cache[cache_key] = result
                return result

            except requests.exceptions.Timeout:
                logger.warning(f"Timeout pada {method} {path}")
                attempt += 1
                time.sleep(0.5 * attempt) # Exponential backoff sederhana
            except requests.exceptions.ConnectionError as e:
                logger.error(f"Connection Error pada {path}: {str(e)}")
                return {"status_code": 0, "body": "", "is_success": False, "error_msg": "Connection Error", "headers": {}}
            except Exception as e:
                logger.error(f"Unexpected Error pada {path}: {str(e)}")
                return {"status_code": 0, "body": "", "is_success": False, "error_msg": str(e), "headers": {}}

        # Jika semua retry gagal
        return {"status_code": 0, "body": "", "is_success": False, "error_msg": "Max Retries Reached", "headers": {}}

    def discover_endpoints(self) -> List[str]:
        """
        Teknik Passive Recon: Menemukan endpoint tersembunyi melalui:
        1. Parsing sitemap.xml
        2. Parsing robots.txt
        3. Mencari referensi JS files
        """
        endpoints = set()
        
        # 1. Sitemap XML
        sitemap_paths = ['/sitemap.xml', '/wp-sitemap.xml']
        for sp in sitemap_paths:
            res = self._make_request('GET', sp)
            if res['status_code'] == 200 and 'xml' in res.get('headers', {}).get('Content-Type', ''):
                soup = BeautifulSoup(res['body'], 'xml')
                locs = soup.find_all('loc')
                for loc in locs:
                    parsed = urlparse(loc.text)
                    if parsed.path:
                        endpoints.add(parsed.path)
                logger.info(f"Discovered {len(locs)} URLs from sitemap.")

        # 2. Robots.txt
        res = self._make_request('GET', '/robots.txt')
        if res['status_code'] == 200:
            lines = res['body'].split('\n')
            for line in lines:
                if line.lower().startswith('disallow:') or line.lower().startswith('allow:'):
                    path = line.split(':', 1)[1].strip()
                    if path and path != '/':
                        endpoints.add(path)
            logger.info("Parsed robots.txt for directives.")

        # 3. JS Files Reference (Simple heuristic)
        # Kita coba fetch homepage dan cari link ke .js files
        res_home = self._make_request('GET', '/')
        if res_home['is_success']:
            soup = BeautifulSoup(res_home['body'], 'html.parser')
            scripts = soup.find_all('script', src=True)
            for script in scripts:
                js_path = urlparse(script['src']).path
                if js_path:
                    endpoints.add(js_path)
                    
        # Normalisasi path
        clean_endpoints = [ep for ep in endpoints if ep.startswith('/')]
        logger.info(f"Total unique endpoints discovered: {len(clean_endpoints)}")
        return sorted(list(set(clean_endpoints)))

    def probe_common_rest_paths(self) -> Dict[str, Dict]:
        """
        Offensive Probe: Menguji path-path umum REST API yang sering memiliki CVE.
        Fokus pada WordPress, Elementor, AIOSEO, dll sesuai struktur toolkit.
        """
        results = {}
        
        # Daftar path umum berdasarkan modul lain di toolkit
        common_paths = [
            # WordPress Core
            '/wp-json/wp/v2/users',
            '/wp-json/wp/v2/posts?per_page=100',
            '/wp-json/wp/v2/settings',
            '/wp-json/rest_api/v1/config',
            
            # Elementor
            '/wp-json/elementor/v1/settings/general',
            '/wp-json/elementor/v1/revisions',
            
            # AIOSEO
            '/wp-json/aioseo/v1/settings',
            
            # Generic/Jetpack
            '/wp-json/jetpack/v4/search',
            '/wp-json/oembed/1.0/proxy?url=http://example.com', # SSRF potential
            
            # Debug/Info
            '/wp-json/', # Root endpoint
            '/index.php/wp-json/',
        ]

        for path in common_paths:
            # Coba GET dulu
            res_get = self._make_request('GET', path)
            
            # Jika 200 atau 405 (Method Not Allowed - artinya ada endpointnya tapi salah method), itu positif
            is_active = res_get['status_code'] in [200, 405, 403]
            
            # Jika 200, coba cek payload spesifik untuk WP
            details = {}
            if res_get['status_code'] == 200:
                try:
                    data = json.loads(res_get['body'])
                    # Cek apakah respons adalah JSON valid yang mengandung data sensitif
                    if isinstance(data, dict) and ('rest_route' in data or 'version' in data or 'users' in data):
                        details['type'] = 'JSON API Detected'
                    elif isinstance(data, list):
                        details['type'] = 'Array Response'
                    else:
                        details['type'] = 'Unknown JSON Structure'
                except json.JSONDecodeError:
                    details['type'] = 'Non-JSON Body'
            
            results[path] = {
                "exists": is_active,
                "status_code": res_get['status_code'],
                "details": details,
                "sample_body": res_get['body'][:500]
            }
            
            # Rate limiting halus agar tidak dianggap DDoS
            time.sleep(0.1) 
            
        return results

    def detect_cve_indicators(self, path: str, response: Dict) -> List[str]:
        """
        Menganalisis respons untuk indikasi CVE spesifik.
        Contoh: Header X-Powered-By, versi di JSON, error messages unik.
        """
        indicators = []
        
        # 1. Check Headers
        headers = response.get('headers', {})
        server_header = headers.get('Server', '').lower()
        x_powered_by = headers.get('X-Powered-By', '').lower()
        
        if 'apache' in server_header:
            indicators.append("Apache Web Server Detected")
        if 'nginx' in server_header:
            indicators.append("Nginx Web Server Detected")
        if 'php' in x_powered_by or 'zend' in x_powered_by:
            indicators.append("PHP Backend Detected")
            
        # 2. Check Body for Version Numbers (Regex)
        body = response.get('body', '')
        version_pattern = re.compile(r'version["\s:=]+([0-9]+\.[0-9]+\.[0-9]+)')
        matches = version_pattern.findall(body)
        if matches:
            indicators.append(f"Version String Found: {matches[0]}")
            
        # 3. Specific WP Indicators
        if 'wordpress' in x_powered_by or 'wp-json' in path:
            indicators.append("WordPress REST API Active")
            if 'rest_route' in body:
                indicators.append("WP REST API Route Discovery Possible")
                
        return indicators

    def run_full_probe(self) -> Dict[str, Any]:
        """
        Eksekusi penuh: Discover -> Probe Common Paths -> Analyze Indicators.
        Return format JSON siap laporan.
        """
        logger.info("Starting REST Endpoint Probe...")
        
        # 1. Discovery
        discovered_endpoints = self.discover_endpoints()
        
        # 2. Probing
        common_results = self.probe_common_rest_paths()
        
        # 3. Analysis & Enrichment
        enriched_results = {}
        for path, data in common_results.items():
            if data['exists']:
                indicators = self.detect_cve_indicators(path, data)
                enriched_results[path] = {
                    **data,
                    "cve_indicators": indicators,
                    "discovery_source": "common_list"
                }
            else:
                enriched_results[path] = {**data, "cve_indicators": [], "discovery_source": "common_list"}
                
        # Tambahkan endpoint yang ditemukan lewat discovery jika belum ada di common paths
        for ep in discovered_endpoints:
            if ep not in enriched_results:
                res = self._make_request('GET', ep)
                indicators = self.detect_cve_indicators(ep, res)
                enriched_results[ep] = {
                    "exists": res['status_code'] != 404,
                    "status_code": res['status_code'],
                    "details": {},
                    "cve_indicators": indicators,
                    "discovery_source": "discovery"
                }

        final_report = {
            "target": self.base_url,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "discovered_endpoints_count": len(discovered_endpoints),
            "probed_endpoints_count": len(enriched_results),
            "active_endpoints": {k:v for k,v in enriched_results.items() if v.get('exists', False)},
            "inactive_endpoints": {k:v for k,v in enriched_results.items() if not v.get('exists', False)}
        }
        
        logger.info(f"Probe finished. Active endpoints: {len(final_report['active_endpoints'])}")
        return final_report

    def close(self):
        self.session.close()

def run_probe(target_url: str) -> Dict:
    """
    Fungsi helper untuk dipanggil oleh main.py atau scanner_engine.py
    """
    engine = RestProbeEngine(base_url=target_url)
    try:
        report = engine.run_full_probe()
        return report
    finally:
        engine.close()

if __name__ == "__main__":
    # Demo standalone
    import sys
    
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = "https://example.com"
        
    print(f"[*] Probing REST API for: {target}")
    try:
        result = run_probe(target)
        print(json.dumps(result, indent=2))
    except Exception as e:
        logger.error(f"Fatal error during probe: {e}")
        sys.exit(1)
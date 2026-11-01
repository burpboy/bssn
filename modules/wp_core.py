# cve_pentest_bssn/modules/wp_core.py
import requests
from bs4 import BeautifulSoup
import re
import json
import logging
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

try:
    from core.guardrails import check_safety_limit
    from core.logger import log_event
except ImportError:
    def check_safety_limit(mode): return True
    def log_event(level, msg, data=None): print(f"[{level}] {msg} - {data}")

logger = logging.getLogger(__name__)

class WPCoreScanner:
    def __init__(self, target_url: str, mode: str = "scan", risk_level: str = "low"):
        self.target_url = target_url.rstrip('/')
        self.mode = mode
        self.risk_level = risk_level
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0 (compatible; WP-Scanner/1.0)'})
        self.version_detected = None
        self.cves_found = []
        
    # MAPPING CVE FULL NAME UNTUK WORDPRESS CORE
    CVE_DB = {
        "CVE-2024-XXXXX": {"title": "WordPress Core RCE via Plugin/Theme Upload (Authenticated Admin)", "severity": "High"},
        "CVE-2023-YYYYY": {"title": "WordPress Core Stored XSS via Avatar Upload", "severity": "Medium"},
        "CVE-2022-ZZZZZ": {"title": "WordPress Core SQL Injection via WP_Query", "severity": "High"}
    }

    def _get_version_from_rest_api(self) -> Optional[str]:
        try:
            endpoints = [f"{self.target_url}/wp-json/", f"{self.target_url}/wp-json/wp/v2/"]
            for endpoint in endpoints:
                resp = self.session.get(endpoint, timeout=10)
                if resp.status_code == 200:
                    data = resp.json()
                    if 'version' in data: return data['version']
        except Exception: pass
        return None

    def _get_version_from_readme(self) -> Optional[str]:
        for rf in ['/readme.html', '/readme.txt']:
            try:
                resp = self.session.get(f"{self.target_url}{rf}", timeout=10)
                if resp.status_code == 200:
                    content = resp.text
                    if rf.endswith('.html'):
                        match = re.search(r'Version\s+([\d\.]+)', content, re.IGNORECASE)
                        if match: return match.group(1)
                    elif rf.endswith('.txt'):
                        match = re.search(r'^.*?Version:\s*([\d\.]+)', content, re.MULTILINE | re.IGNORECASE)
                        if match: return match.group(1)
            except Exception: pass
        return None

    def _get_version_from_login_page(self) -> Optional[str]:
        try:
            resp = self.session.get(f"{self.target_url}/wp-login.php", timeout=10)
            if resp.status_code == 200:
                soup = BeautifulSoup(resp.text, 'html.parser')
                for script in soup.find_all('script', src=True):
                    if 'version=' in script['src']:
                        ver_match = re.search(r'version=([\d\.]+)', script['src'])
                        if ver_match: return ver_match.group(1)
        except Exception: pass
        return None

    def detect_version(self) -> str:
        version = self._get_version_from_rest_api() or self._get_version_from_readme() or self._get_version_from_login_page()
        self.version_detected = version or "Unknown"
        return self.version_detected

    def check_cve_database(self, version: str) -> List[Dict]:
        cves = []
        if not version or version == "Unknown": return cves
            
        # Simulasi database CVE (Menghubungkan ID Dummy ke Full Name)
        known_vulnerable_versions = {
            "6.4.2": ["CVE-2024-XXXXX"],
            "6.3.2": ["CVE-2023-YYYYY"],
            "5.9.0": ["CVE-2022-ZZZZZ"]
        }
        
        if version in known_vulnerable_versions:
            for cve_id in known_vulnerable_versions[version]:
                cve_info = self.CVE_DB.get(cve_id, {"title": "Unknown Vulnerability", "severity": "High"})
                cves.append({
                    "cve": cve_id, 
                    "cve_full_name": cve_info["title"], # <-- FULL NAME
                    "severity": cve_info["severity"], 
                    "description": cve_info["title"]
                })
            
        try:
            major, minor, patch = map(int, version.split('.'))
            if major < 6:
                cves.append({"cve": "CVE-2021-GENERIC", "cve_full_name": "Old WordPress Version Detected", "severity": "Medium", "description": "Old version detected"})
        except ValueError: pass
            
        return cves

    def run(self) -> Dict:
        version = self.detect_version()
        cves = self.check_cve_database(version)
        
        scan_result = {
            "target": self.target_url,
            "version": version,
            "cves": cves, # cves list sekarang berisi cve_full_name
            "mode": self.mode,
            "timestamp": __import__('datetime').datetime.now().isoformat()
        }
        
        if self.mode in ['probe', 'exploit'] and check_safety_limit(self.mode):
            if self.mode == 'probe': scan_result["offensive_probe"] = {"status": "simulated"}
            elif self.mode == 'exploit': scan_result["offensive_exploit"] = {"status": "simulated"}
                
        log_event("INFO", f"WPCore Scan Complete", {"target": self.target_url, "version": version})
        return scan_result

def scan_wp_core(target_url: str, mode: str = "scan") -> Dict:
    return WPCoreScanner(target_url, mode).run()

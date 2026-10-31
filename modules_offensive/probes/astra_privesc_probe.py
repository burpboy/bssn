#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
astra_privesc_probe.py
Module Probe untuk mendeteksi potensi Privilege Escalation / Open Access pada plugin/theme Astra WordPress.

Fokus:
- Memeriksa apakah panel admin Astra dapat diakses oleh user non-admin atau guest.
- Mendeteksi kebocoran informasi versi/config yang bisa membantu eksploitasi lebih lanjut.
- Low Risk: Hanya membaca (GET requests), tidak menulis data.

Author: Dwi Joko Purwanto 
Compatible with: cve_pentest_bssn framework
"""

import sys
import os
import json
import time
import logging
from typing import Dict, Any, Optional, List

# Pastikan path modul tersedia jika dijalankan standalone atau via framework
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from core.scanner_engine import ScannerBase
    from core.guardrails import SafetyGuard
except ImportError:
    # Fallback untuk testing lokal
    class ScannerBase:
        def __init__(self, target_url, config=None):
            self.target_url = target_url.rstrip('/')
            self.config = config or {}
            self.session = None
            
        def log_info(self, msg):
            print(f"[INFO] {msg}")
            
        def log_warn(self, msg):
            print(f"[WARN] {msg}")
            
        def log_error(self, msg):
            print(f"[ERROR] {msg}")

class AstraPrivescProbe(ScannerBase):
    """
    Probe untuk mendeteksi kerentanan privilege escalation pada Astra Theme/Plugin.
    
    Strategi:
    1. Cek akses langsung ke endpoint admin Astra tanpa login (jika allowlist/public).
    2. Cek versi Astra untuk mencocokkan dengan CVE known RCE/PrivEsc.
    3. Cek headers dan body response untuk kebocoran info.
    """

    NAME = "Astra Privesc Probe"
    VERSION = "1.0.0"
    CATEGORY = "privesc"
    RISK_LEVEL = "LOW"  # Karena hanya probe/read-only

    # Endpoint umum admin Astra
    ASTR_ADMIN_ENDPOINTS = [
        "/wp-admin/admin.php?page=astra-options",
        "/wp-admin/admin.php?page=astra-settings",
        "/wp-admin/admin.php?page=astra-pro",
        "/wp-json/astra-rest/v1/settings",
        "/wp-content/themes/astra/inc/changelog.json" # Sering berisi info versi detail
    ]

    # String penanda bahwa halaman Astra terlihat/bisa diakses
    POSITIVE_INDICATORS = [
        "astra-options",
        "astra-settings",
        "astra-pro",
        "astra-logo",
        "wp-astra",
        "class=" and "astra-",  # CSS class unik Astra
        "data-astra-"           # Data attribute unik Astra
    ]

    # String penanda error atau access denied yang justru mengonfirmasi keberadaan fitur
    ACCESS_DENIED_INDICATORS = [
        "You do not have sufficient permissions",
        "access_denied",
        "403 Forbidden",
        "Unauthorized"
    ]

    def __init__(self, target_url: str, config: Optional[Dict[str, Any]] = None):
        super().__init__(target_url, config)
        self.results = {
            "probe_name": self.NAME,
            "version": self.VERSION,
            "target": self.target_url,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "findings": [],
            "is_vulnerable": False,
            "details": {}
        }
        self.logger = logging.getLogger(__name__)
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)

    def run(self) -> Dict[str, Any]:
        """
        Eksekusi utama probe.
        """
        self.log_info(f"Starting Astra Privesc Probe on {self.target_url}")
        
        try:
            # 1. Cek Versi Astra dari changelog atau header
            version_info = self.check_astra_version()
            if version_info:
                self.results["details"]["detected_version"] = version_info
                self.log_info(f"Astra Version Detected: {version_info}")

            # 2. Probe Akses Admin Panel
            admin_access_results = self.probe_admin_endpoints()
            self.results["details"]["admin_endpoint_access"] = admin_access_results

            # 3. Analisis Hasil
            if self._analyze_findings(admin_access_results, version_info):
                self.results["is_vulnerable"] = True
                self.results["findings"].append({
                    "type": "PRIVESC_POSSIBLE",
                    "severity": "MEDIUM",
                    "description": "Panel admin Astra dapat diakses atau versi memiliki known vulnerability.",
                    "evidence": admin_access_results.get('accessible_endpoints', [])
                })
            
            self.log_info(f"Probe finished. Vulnerable: {self.results['is_vulnerable']}")
            
        except Exception as e:
            self.log_error(f"Error during probe: {str(e)}")
            self.results["error"] = str(e)

        return self.results

    def check_astra_version(self) -> Optional[str]:
        """
        Mencoba mendeteksi versi Astra melalui endpoint publik atau header.
        """
        urls_to_check = [
            f"{self.target_url}/wp-content/themes/astra/inc/changelog.json",
            f"{self.target_url}/wp-content/themes/astra/style.css",
            f"{self.target_url}/wp-json/wp/v2/settings" # Kadang mengandung info theme
        ]
        
        for url in urls_to_check:
            try:
                resp = self.http_get(url)
                if resp.status_code == 200:
                    content_type = resp.headers.get('Content-Type', '')
                    body = resp.text
                    
                    # Cek JSON Changelog
                    if 'json' in content_type:
                        try:
                            data = resp.json()
                            if isinstance(data, list) and len(data) > 0:
                                # Ambil versi terbaru dari changelog
                                latest_version = data[0].get('version', 'unknown')
                                return latest_version
                        except ValueError:
                            pass
                    
                    # Cek Style.css
                    elif 'css' in content_type:
                        match = re.search(r'Version:\s*(\d+\.\d+\.\d+)', body)
                        if match:
                            return match.group(1)
                            
            except Exception:
                continue
                
        return None

    def probe_admin_endpoints(self) -> Dict[str, Any]:
        """
        Melakukan request GET ke endpoint admin Astra untuk melihat apakah bisa diakses.
        """
        accessible_endpoints = []
        responses = {}
        
        for endpoint in self.ASTR_ADMIN_ENDPOINTS:
            full_url = f"{self.target_url}{endpoint}"
            try:
                resp = self.http_get(full_url)
                status = resp.status_code
                body = resp.text
                
                is_accessible = False
                reason = ""
                
                # Logika deteksi akses
                if status == 200:
                    # Jika konten mengandung indikator Astra, berarti akses berhasil atau halaman ada
                    if any(ind in body.lower() for ind in self.POSITIVE_INDICATORS):
                        is_accessible = True
                        reason = "Content indicates Astra interface is visible."
                    else:
                        # Mungkin redirect ke login?
                        if '/wp-login.php' in resp.url or 'login' in resp.url.lower():
                            reason = "Redirected to login page (Secure)."
                        else:
                            reason = "Page returned 200 but no Astra content detected."
                elif status == 302:
                    if '/wp-login.php' in resp.headers.get('Location', ''):
                        reason = "Redirected to login (Secure)."
                    else:
                        reason = f"Redirected to {resp.headers.get('Location', 'unknown')}"
                elif status == 403:
                    reason = "Forbidden (Access Denied)"
                    # Jika 403 tapi ada logo Astra kecil, itu masih bisa jadi indikasi existensi
                    if any(ind in body.lower() for ind in self.POSITIVE_INDICATORS):
                        is_accessible = True # Dalam artian halaman ada, cuma dikunci
                        reason += " But Astra UI elements found."
                else:
                    reason = f"Status {status}"

                responses[endpoint] = {
                    "status": status,
                    "url": resp.url,
                    "accessible": is_accessible,
                    "reason": reason
                }
                
                if is_accessible:
                    accessible_endpoints.append(endpoint)
                    
            except Exception as e:
                responses[endpoint] = {"error": str(e)}
                
        return {
            "accessible_endpoints": accessible_endpoints,
            "all_responses": responses
        }

    def _analyze_findings(self, admin_access: Dict, version: Optional[str]) -> bool:
        """
        Menganalisis hasil probe untuk menentukan apakah target rentan.
        """
        # Kondisi 1: Endpoint admin bisa diakses langsung (tanpa login)
        if admin_access.get("accessible_endpoints"):
            return True
            
        # Kondisi 2: Versi diketahui dan termasuk dalam daftar CVE known privesc/rce
        # (Ini bisa diperluas dengan database CVE eksternal)
        if version:
            # Contoh sederhana: jika versi < 4.0.0 mungkin ada bug lama
            # Kita bisa cek ke API CVE jika ada
            known_vulnerable_versions = ["3.9.5", "3.9.4", "3.9.3"] # Contoh
            if version in known_vulnerable_versions:
                return True
                
        return False

    def http_get(self, url: str) -> Any:
        """
        Helper method untuk melakukan HTTP GET.
        Menggunakan library requests jika tersedia, atau urllib fallback.
        """
        try:
            import requests
            timeout = self.config.get("timeout", 10)
            session = requests.Session()
            # Disable SSL warning jika perlu
            session.verify = self.config.get("verify_ssl", True)
            resp = session.get(url, timeout=timeout, allow_redirects=True)
            return resp
        except ImportError:
            import urllib.request
            import urllib.error
            try:
                req = urllib.request.Request(url)
                with urllib.request.urlopen(req, timeout=10) as response:
                    class MockResp:
                        def __init__(self, data, url):
                            self.status_code = 200
                            self.text = data.decode('utf-8', errors='ignore')
                            self.headers = dict(response.headers)
                            self.url = url
                    return MockResp(response.read(), url)
            except urllib.error.HTTPError as e:
                class MockResp:
                    def __init__(self, code, url):
                        self.status_code = code
                        self.text = ""
                        self.headers = dict(e.headers)
                        self.url = url
                return MockResp(e.code, url)

# Fungsi factory untuk kemudahan integrasi
def create_probe(target_url, config=None):
    return AstraPrivescProbe(target_url, config)

if __name__ == "__main__":
    # Contoh penggunaan standalone
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = "http://localhost/testsite"
        
    probe = AstraPrivescProbe(target)
    results = probe.run()
    print(json.dumps(results, indent=2))
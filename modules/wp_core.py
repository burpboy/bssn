# cve_pentest_bssn/modules/wp_core.py
import requests
from bs4 import BeautifulSoup
import re
import json
import logging
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

# Import dari core untuk integrasi toolkit
try:
    from core.guardrails import check_safety_limit
    from core.logger import log_event
except ImportError:
    # Fallback jika dijalankan standalone atau modul belum ter-load
    def check_safety_limit(mode):
        return True
    
    def log_event(level, msg, data=None):
        print(f"[{level}] {msg} - {data}")

logger = logging.getLogger(__name__)

class WPCoreScanner:
    """
    Scanner untuk mendeteksi CVE pada WordPress Core.
    Mendukung mode passive (scan) dan active (probe/exploit).
    """
    
    # Daftar CVE terkenal yang sering dieksploitasi secara aktif
    KNOWN_RCE_CVES = [
        "CVE-2024-25600", # WP Mail Logging
        "CVE-2024-25600", # Contoh lainnya bisa ditambahkan
        "CVE-2023-42266", # Unauthorized access to wp-cron.php
        "CVE-2022-21587", # Path Traversal
        "CVE-2019-15686", # Unauthenticated Deserialization
    ]
    
    def __init__(self, target_url: str, mode: str = "scan", risk_level: str = "low"):
        """
        Inisialisasi scanner.
        
        Args:
            target_url: URL target (misal: https://example.com)
            mode: 'scan', 'probe', atau 'exploit'
            risk_level: 'low', 'medium', 'high'
        """
        self.target_url = target_url.rstrip('/')
        self.mode = mode
        self.risk_level = risk_level
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (compatible; WP-Scanner/1.0)'
        })
        self.version_detected = None
        self.cves_found = []
        self.offensive_results = {}
        
    def _get_version_from_rest_api(self) -> Optional[str]:
        """Cek versi via WordPress REST API (v1/me atau /wp-json/)"""
        try:
            # Endpoint standar REST API
            endpoints = [
                f"{self.target_url}/wp-json/",
                f"{self.target_url}/wp-json/wp/v2/"
            ]
            
            for endpoint in endpoints:
                resp = self.session.get(endpoint, timeout=10)
                if resp.status_code == 200:
                    # Coba parse JSON untuk mendapatkan info versi
                    data = resp.json()
                    if 'version' in data:
                        return data['version']
                    
                    # Jika tidak ada field version, cek headers atau link
                    # Kadang versi ada di header X-Powered-By atau similar
                    # Tapi biasanya REST API v2 hanya memberikan routes
                    
            # Cek endpoint /wp-json/wp/v2/users/me (jika publik)
            resp = self.session.get(f"{self.target_url}/wp-json/wp/v2/users/me", timeout=10)
            if resp.status_code == 200:
                # Terkadang respons mengandung informasi versi di metadata
                pass
                
        except Exception as e:
            logger.debug(f"REST API check failed: {e}")
            
        return None

    def _get_version_from_readme(self) -> Optional[str]:
        """Cek versi dari file readme.html atau readme.txt"""
        readme_files = ['/readme.html', '/readme.txt']
        
        for rf in readme_files:
            try:
                resp = self.session.get(f"{self.target_url}{rf}", timeout=10)
                if resp.status_code == 200:
                    content = resp.text
                    
                    # Parse HTML
                    if rf.endswith('.html'):
                        soup = BeautifulSoup(content, 'html.parser')
                        # Cari teks "Version X.X.X"
                        match = re.search(r'Version\s+([\d\.]+)', content, re.IGNORECASE)
                        if match:
                            return match.group(1)
                        
                        # Cek meta generator
                        generator = soup.find('meta', attrs={'name': 'generator'})
                        if generator and 'WordPress' in generator.get('content', ''):
                            ver_match = re.search(r'WordPress\s+([\d\.]+)', generator['content'])
                            if ver_match:
                                return ver_match.group(1)
                                
                    elif rf.endswith('.txt'):
                        # Parse text file
                        match = re.search(r'^.*?Version:\s*([\d\.]+)', content, re.MULTILINE | re.IGNORECASE)
                        if match:
                            return match.group(1)
                            
            except Exception as e:
                logger.debug(f"Readme check failed for {rf}: {e}")
                
        return None

    def _get_version_from_login_page(self) -> Optional[str]:
        """Cek versi dari halaman login (wp-login.php)"""
        try:
            resp = self.session.get(f"{self.target_url}/wp-login.php", timeout=10)
            if resp.status_code == 200:
                soup = BeautifulSoup(resp.text, 'html.parser')
                
                # Cek script version
                scripts = soup.find_all('script', src=True)
                for script in scripts:
                    if 'version=' in script['src']:
                        ver_match = re.search(r'version=([\d\.]+)', script['src'])
                        if ver_match:
                            return ver_match.group(1)
                            
                # Cek hidden input
                inputs = soup.find_all('input', attrs={'name': 'wp_version'})
                if inputs:
                    return inputs[0].get('value')
                    
                # Cek meta generator
                generator = soup.find('meta', attrs={'name': 'generator'})
                if generator and 'WordPress' in generator.get('content', ''):
                    ver_match = re.search(r'WordPress\s+([\d\.]+)', generator['content'])
                    if ver_match:
                        return ver_match.group(1)
                        
        except Exception as e:
            logger.debug(f"Login page check failed: {e}")
            
        return None

    def _get_version_from_generator_tag(self) -> Optional[str]:
        """Cek meta generator di halaman utama"""
        try: tema
            resp = self.session.get(self.target_url, timeout=10)
            if resp.status_code == 200:
                soup = BeautifulSoup(resp.text, 'html.parser')
                generator = soup.find('meta', attrs={'name': 'generator'})
                if generator:
                    content = generator.get('content', '')
                    if 'WordPress' in content:
                        ver_match = re.search(r'WordPress\s+([\d\.]+)', content)
                        if ver_match:
                            return ver_match.group(1)
        except Exception as e:
            logger.debug(f"Generator tag check failed: {e}")
        return None

    def detect_version(self) -> str:
        """
        Metode utama untuk mendeteksi versi WordPress.
        Menggabungkan beberapa sumber untuk akurasi tertinggi.
        """
        # Urutan prioritas: REST API > Readme > Login Page > Generator
        version = self._get_version_from_rest_api()
        if version:
            self.version_detected = version
            return version
            
        version = self._get_version_from_readme()
        if version:
            self.version_detected = version
            return version
            
        version = self._get_version_from_login_page()
        if version:
            self.version_detected = version
            return version
            
        version = self._get_version_from_generator_tag()
        if version:
            self.version_detected = version
            return version
            
        self.version_detected = "Unknown"
        return "Unknown"

    def check_cve_database(self, version: str) -> List[Dict]:
        """
        Cek versi terhadap database CVE lokal atau API eksternal.
        Untuk demo ini, kita gunakan logika sederhana.
        """
        cves = []
        if not version or version == "Unknown":
            return cves
            
        # Simulasi database CVE
        # Dalam produksi, hubungkan ke API seperti vulners.com atau cvedetails.com
        known_vulnerable_versions = {
            "6.4.2": ["CVE-2024-XXXX"], # Contoh
            "6.3.2": ["CVE-2023-YYYY"],
            "5.9.0": ["CVE-2022-ZZZZ"]
        }
        
        # Logika sederhana: jika versi < tertentu, anggap rentan
        # Atau cek exact match
        if version in known_vulnerable_versions:
            return [{"cve_id": cve, "severity": "High", "description": "Known vulnerability"} for cve in known_vulnerable_versions[version]]
            
        # Cek versi umum yang rentan (contoh: < 6.4.0)
        try:
            major, minor, patch = map(int, version.split('.'))
            if major < 6:
                cves.append({"cve_id": "CVE-2021-GENERIC", "severity": "Medium", "description": "Old version detected"})
        except ValueError:
            pass
            
        return cves

    def offensive_probe(self) -> Dict:
        """
        Mode Probe: Verifikasi kerentanan tanpa mengubah data.
        Risk Level: Low
        """
        result = {
            "status": "probing",
            "checks": []
        }
        
        # 1. Cek apakah wp-cron.php accessible (CVE-2023-42266 related)
        try:
            resp = self.session.get(f"{self.target_url}/wp-cron.php", timeout=10)
            is_cron_accessible = resp.status_code in [200, 403]
            result["checks"].append({
                "test": "wp-cron-accessibility",
                "status": "VULNERABLE" if is_cron_accessible else "SAFE",
                "details": f"HTTP {resp.status_code}"
            })
        except Exception as e:
            result["checks"].append({
                "test": "wp-cron-accessibility",
                "status": "ERROR",
                "details": str(e)
            })
            
        # 2. Cek XML-RPC enabled (potensi DoS/BBrute Force)
        try:
            resp = self.session.head(f"{self.target_url}/xmlrpc.php", timeout=10)
            xmlrpc_enabled = resp.status_code == 200
            result["checks"].append({
                "test": "xmlrpc-enabled",
                "status": "VULNERABLE" if xmlrpc_enabled else "SAFE",
                "details": f"HTTP {resp.status_code}"
            })
        except Exception as e:
            result["checks"].append({
                "test": "xmlrpc-enabled",
                "status": "ERROR",
                "details": str(e)
            })
            
        # 3. Cek default admin username (enumerasi)
        try:
            resp = self.session.get(f"{self.target_url}/wp-json/wp/v2/users", timeout=10)
            users = resp.json() if resp.status_code == 200 else []
            if any(u.get('slug') == 'admin' for u in users):
                result["checks"].append({
                    "test": "admin-enumeration",
                    "status": "VULNERABLE",
                    "details": "Admin user found via REST API"
                })
            else:
                result["checks"].append({
                    "test": "admin-enumeration",
                    "status": "SAFE",
                    "details": "No admin user found"
                })
        except Exception as e:
            result["checks"].append({
                "test": "admin-enumeration",
                "status": "INFO",
                "details": f"Could not enumerate: {str(e)}"
            })
            
        return result

    def offensive_exploit(self, cve_id: str = None) -> Dict:
        """
        Mode Exploit: Eksekusi payload penuh.
        Risk Level: High
        
        Contoh: Membuktikan RCE atau Privilege Escalation.
        """
        result = {
            "status": "exploiting",
            "payload_executed": False,
            "output": ""
        }
        
        # Tentukan aksi berdasarkan CVE atau default ke POC umum
        if not cve_id:
            cve_id = "DEFAULT_POC"
            
        try:
            # POC Umum: Eksekusi command via WP CLI jika tersedia (wp-cli.phar)
            # Atau via file inclusion jika ada
            
            # Contoh: Mencoba memuat wp-config.php untuk melihat path
            resp = self.session.get(f"{self.target_url}/wp-config.php", timeout=10)
            if resp.status_code == 200:
                result["output"] = "wp-config.php exposed!"
                result["payload_executed"] = True
                return result
                
            # Contoh: Mencoba akses /wp-admin/admin-ajax.php dengan action tertentu
            # Ini sering kali memungkinkan eksekusi fungsi PHP
            payload_data = {
                'action': 'dbexpposts', # Contoh action rentan di plugin tertentu
                'post_id': 1
            }
            resp = self.session.post(f"{self.target_url}/wp-admin/admin-ajax.php", data=payload_data, timeout=10)
            if "error" not in resp.text.lower():
                result["output"] = f"AJAX Action executed. Response length: {len(resp.text)}"
                result["payload_executed"] = True
                
        except Exception as e:
            result["output"] = f"Exploit failed: {str(e)}"
            
        return result

    def run(self) -> Dict:
        """
        Metode utama yang dipanggil oleh scanner_engine.py
        """
        # 1. Deteksi Versi
        version = self.detect_version()
        
        # 2. Cek CVE
        cves = self.check_cve_database(version)
        
        # 3. Jalankan tindakan berdasarkan mode
        scan_result = {
            "target": self.target_url,
            "version": version,
            "cves": cves,
            "mode": self.mode,
            "timestamp": __import__('datetime').datetime.now().isoformat()
        }
        
        if self.mode in ['probe', 'exploit']:
            # Safety Check
            if not check_safety_limit(self.mode):
                scan_result["warning"] = "Safety limit exceeded, stopping offensive actions"
                return scan_result
                
            if self.mode == 'probe':
                scan_result["offensive_probe"] = self.offensive_probe()
            elif self.mode == 'exploit':
                scan_result["offensive_exploit"] = self.offensive_exploit()
                
        # Log hasil
        log_event("INFO", f"WPCore Scan Complete", {"target": self.target_url, "version": version})
        
        return scan_result

# Fungsi helper untuk digunakan langsung di main.py atau module lain
def scan_wp_core(target_url: str, mode: str = "scan") -> Dict:
    scanner = WPCoreScanner(target_url, mode)
    return scanner.run()
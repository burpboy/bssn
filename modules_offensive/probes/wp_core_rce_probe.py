import requests
import re
import logging
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# Import dari core/offensive base class jika ada, atau definisikan sederhana
try:
    from modules_offensive.base_exploit import BaseExploit
except ImportError:
    class BaseExploit:
        def __init__(self):
            self.logger = logging.getLogger(__name__)
            self.session = requests.Session()
            self.timeout = 10

logger = logging.getLogger(__name__)

class WpCoreRceProbe(BaseExploit):
    """
    Modul Probe untuk WordPress Core RCE.
    
    Strategi:
    1. Fingerprinting Versi (Header, Readme, Generator Meta Tag).
    2. Verifikasi Kerentanan berdasarkan CVE Database lokal (hardcoded list CVEs terkenal).
    3. Passive Check terhadap endpoint yang biasanya dieksploitasi (misal: /wp-json/, /xmlrpc.php jika relevan dengan vector tertentu).
    
    Risiko: LOW (Hanya membaca response, tidak mengubah state).
    """

    NAME = "WP Core RCE Probe"
    DESCRIPTION = "Mendeteksi versi WP dan memverifikasi apakah versi tersebut memiliki known RCE endpoints/bugs."
    MODE = "probe" # Mode probe hanya konfirmasi, tidak exploit penuh

    # Daftar CVE Utama yang menyebabkan RCE di WordPress Core
    # Format: {CVE_ID: {'min_version': 'x.x.x', 'max_version': 'y.y.y', 'vector': 'description'}}
    KNOWN_RCE_CVES = {
        "CVE-2024-27957": {
            "affected_versions": ["6.4.0", "6.4.1", "6.4.2"],
            "vector": "Unrestricted File Upload via wp_remote_post in Media Library",
            "check_endpoint": "/wp-admin/media.php?action=edit&attachment_id=" # Indirect check
        },
        "CVE-2024-29153": {
            "affected_versions": ["6.5.0", "6.5.1", "6.5.2", "6.5.3", "6.5.4", "6.5.5"],
            "vector": "Denial of Service / Potential Code Execution via wp_list_pluck",
            "check_type": "version_range"
        },
        "CVE-2023-29454": {
            "affected_versions": ["6.2.0", "6.2.1", "6.2.2", "6.2.3"],
            "vector": "Privilege Escalation leading to RCE potential via user registration flow",
            "check_type": "version_range"
        },
        "CVE-2022-1184": {
            "affected_versions": ["5.9.0", "5.9.1", "5.9.2", "5.9.3"],
            "vector": "Remote Code Execution via PHP Filter injection in block editor",
            "check_endpoint": "/wp-admin/edit.php?post_type=block"
        },
        "CVE-2021-29445": {
            "affected_versions": ["5.7.0", "5.7.1", "5.7.2", "5.7.3", "5.7.4", "5.7.5"],
            "vector": "Server-side Request Forgery (SSRF) leading to internal network scanning/RCE aux",
            "check_type": "version_range"
        }
    }

    def run(self, target_url):
        """
        Menjalankan probe deteksi RCE pada target WordPress.
        
        Args:
            target_url (str): URL dasar target (contoh: https://example.com)
            
        Returns:
            dict: Hasil deteksi dengan status vulnerability.
        """
        results = {
            "target": target_url,
            "module": self.NAME,
            "status": "unknown",
            "details": [],
            "vulnerable_cves": [],
            "detected_version": None,
            "risk_level": "low" # Karena ini probe
        }

        try:
            # 1. Deteksi Versi WordPress
            detected_version = self._detect_wp_version(target_url)
            if not detected_version:
                results["status"] = "version_unknown"
                results["details"].append("Tidak dapat mendeteksi versi WordPress.")
                return results
            
            results["detected_version"] = detected_version
            results["details"].append(f"Versi WordPress terdeteksi: {detected_version}")

            # 2. Cek against Known CVEs
            cve_hits = self._check_cve_database(detected_version)
            
            if cve_hits:
                results["status"] = "potential_rce"
                results["vulnerable_cves"] = cve_hits
                for cve_info in cve_hits:
                    results["details"].append(
                        f"[!] CVE Potensial Terdeteksi: {cve_info['id']} - {cve_info['vector']}"
                    )
            else:
                results["status"] = "safe_or_unlisted"
                results["details"].append("Versi terdeteksi tidak ada dalam daftar CVE RCE utama yang diketahui saat ini.")

            # 3. Passive Endpoint Checks (Optional Deep Probe)
            # Cek apakah endpoint umum yang rentan dapat diakses atau menunjukkan error/version info
            self._passive_endpoint_checks(target_url, detected_version, results)

        except Exception as e:
            logger.error(f"Error during WP Core RCE Probe: {e}")
            results["status"] = "error"
            results["details"].append(f"Error teknis: {str(e)}")

        return results

    def _detect_wp_version(self, url):
        """
        Mendeteksi versi WordPress melalui berbagai metode passive.
        """
        versions_found = []
        
        # Metode 1: Generator Meta Tag
        try:
            resp = self.session.get(url, timeout=self.timeout, headers={'User-Agent': 'Mozilla/5.0'})
            soup = BeautifulSoup(resp.text, 'html.parser')
            meta_tag = soup.find('meta', attrs={'name': 'generator'})
            if meta_tag and 'WordPress' in meta_tag.get('content', ''):
                match = re.search(r'WordPress (\d+\.\d+(?:\.\d+)?)', meta_tag['content'])
                if match:
                    versions_found.append(match.group(1))
        except Exception:
            pass

        # Metode 2: README/RSS Feed
        if not versions_found:
            try:
                # Cek feed RSS umum
                for feed_path in ['/feed/', '/rss/', '/comments/feed/']:
                    resp = self.session.get(urljoin(url, feed_path), timeout=self.timeout)
                    if resp.status_code == 200:
                        match = re.search(r'WordPress (-?\d+\.\d+(?:\.\d+)?)', resp.text)
                        if match:
                            ver = match.group(1)
                            # Handle negative version numbers often found in feeds
                            if ver.startswith('-'):
                                ver = ver[1:]
                            versions_found.append(ver)
                            break
            except Exception:
                pass

        # Metode 3: Style Sheets & Scripts (WP-includes)
        if not versions_found:
            try:
                resp = self.session.get(urljoin(url, 'wp-includes/version.php'), timeout=self.timeout)
                if resp.status_code == 200:
                    match = re.search(r"\$wp_version\s*=\s*'([\d\.]+)'", resp.text)
                    if match:
                        versions_found.append(match.group(1))
            except Exception:
                pass
        
        # Metode 4: REST API
        if not versions_found:
            try:
                resp = self.session.get(urljoin(url, 'wp-json/wp/v2'), timeout=self.timeout)
                if resp.status_code == 200:
                    # Header X-WP-Embed-Signature atau body JSON kadang mengandung versi
                    # Tapi lebih aman cek header server jika tersedia
                    server_header = resp.headers.get('X-Powered-By', '')
                    if 'WordPress' in server_header:
                         # Kadang header menyertakan versi, tapi tidak selalu
                         pass 
                    
                    # Cek body JSON untuk versi
                    json_data = resp.json()
                    if 'version' in json_data:
                        versions_found.append(json_data['version'])
                        
            except Exception:
                pass

        # Metode 5: HTML Comments <!-- style/css -->
        if not versions_found:
            try:
                resp = self.session.get(url, timeout=self.timeout)
                comments = re.findall(r'<!--.*?style[^>]*stylesheet[^>]*href="[^"]*/wp-content/themes/[^"]*/style\.css\?ver=([^"]*)".*?-->', resp.text, re.DOTALL | re.IGNORECASE)
                if comments:
                    # Ambil yang pertama ditemukan
                    versions_found.append(comments[0])
            except Exception:
                pass

        # Kembalikan versi tertinggi yang ditemukan atau None
        if versions_found:
            # Urutkan secara semantik (sederhana)
            # Untuk akurasi tinggi, gunakan library packaging.version
            return sorted(versions_found)[-1]
        
        return None

    def _check_cve_database(self, version):
        """
        Membandingkan versi yang terdeteksi dengan daftar CVE RCE.
        """
        hits = []
        
        # Parsing versi menjadi tuple integer untuk perbandingan
        try:
            current_ver_parts = [int(x) for x in version.split('.')]
            while len(current_ver_parts) < 3:
                current_ver_parts.append(0)
            current_ver_tuple = tuple(current_ver_parts)
        except ValueError:
            return hits

        for cve_id, info in self.KNOWN_RCE_CVES.items():
            affected = info['affected_versions']
            
            # Jika formatnya range sederhana (array versi eksak atau range string)
            # Di sini kita asumsikan kita punya daftar versi eksak yang rentan
            if version in affected:
                hits.append({
                    "id": cve_id,
                    "vector": info['vector'],
                    "match_type": "exact_version"
                })
            else:
                # Coba cek range jika formatnya lebih kompleks di masa depan
                # Untuk saat ini, kita hanya cocokkan eksak berdasarkan array 'affected_versions'
                pass
                
        return hits

    def _passive_endpoint_checks(self, base_url, version, results):
        """
        Melakukan pengecekan pasif pada endpoint yang sering menjadi vektor RCE.
        """
        checks_performed = []
        
        # Contoh: Cek apakah xmlrpc.php aktif (sering digunakan untuk brute force/RCE via method system.multicall)
        xmlrpc_url = urljoin(base_url, 'xmlrpc.php')
        try:
            resp = self.session.head(xmlrpc_url, timeout=self.timeout)
            if resp.status_code == 200:
                checks_performed.append({
                    "endpoint": "/xmlrpc.php",
                    "status": "active",
                    "note": "XML-RPC aktif. Bisa menjadi vektor untuk DoS atau proxy SSRF."
                })
        except Exception:
            pass

        # Contoh: Cek REST API availability
        rest_url = urljoin(base_url, 'wp-json/')
        try:
            resp = self.session.get(rest_url, timeout=self.timeout)
            if resp.status_code == 200:
                checks_performed.append({
                    "endpoint": "/wp-json/",
                    "status": "available",
                    "note": "REST API aktif. Memungkinkan enumerasi endpoint lebih lanjut."
                })
        except Exception:
            pass

        # Tambahkan ke hasil jika ada temuan menarik
        if checks_performed:
            results["details"].append("Endpoint Checks:")
            for check in checks_performed:
                results["details"].append(f"  - {check['endpoint']}: {check['note']}")

        return checks_performed

    def cleanup(self):
        """
        Bersihkan sesi setelah probe selesai.
        """
        if hasattr(self, 'session'):
            self.session.close()
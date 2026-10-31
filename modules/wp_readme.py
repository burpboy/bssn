import re
import logging
from typing import Optional, Dict, Any
from bs4 import BeautifulSoup
import requests
from requests.exceptions import RequestException, Timeout

# Import dari core jika ada utilitas umum, atau gunakan standar library
# Asumsi: config.py tersedia di root project
try:
    from config import TIMEOUT_REQUEST, USER_AGENT
except ImportError:
    TIMEOUT_REQUEST = 10
    USER_AGENT = "Mozilla/5.0 (compatible; BSSN-CVE-Scanner/1.0)"

logger = logging.getLogger(__name__)

class WpReadmeParser:
    """
    Parser khusus untuk README.md atau readme.html WordPress.
    Fokus: Mengekstrak versi core/plugins/themes secara akurat.
    
    Mengapa penting?
    - Versi yang salah di readme sering kali lebih baru daripada versi file index.php.
    - Membantu mendeteksi false positive pada scan versi file biasa.
    """

    def __init__(self, target_url: str):
        self.target_url = target_url.rstrip('/')
        self.readme_url = f"{self.target_url}/readme.html" # Standar WP Core
        self.readme_md_url = f"{self.target_url}/readme.md"
        self.version: Optional[str] = None
        self.source: Optional[str] = None # 'readme.html', 'readme.md', atau 'header'
        self.soup: Optional[BeautifulSoup] = None
        self.raw_content: str = ""
        
    def fetch_content(self) -> bool:
        """Mengambil konten readme.html atau readme.md"""
        urls_to_try = [self.readme_url, self.readme_md_url]
        
        for url in urls_to_try:
            try:
                logger.debug(f"[WP_README] Fetching: {url}")
                headers = {'User-Agent': USER_AGENT}
                response = requests.get(url, headers=headers, timeout=TIMEOUT_REQUEST)
                
                if response.status_code == 200:
                    self.raw_content = response.text
                    self.source = url.split('/')[-1]
                    self._parse_html()
                    return True
                elif response.status_code == 404:
                    continue
                else:
                    logger.warning(f"[WP_README] Status code {response.status_code} for {url}")
                    
            except RequestException as e:
                logger.error(f"[WP_README] Error fetching {url}: {e}")
                continue
                
        return False

    def _parse_html(self):
        """Parsing HTML content untuk mencari string versi."""
        try:
            self.soup = BeautifulSoup(self.raw_content, 'html.parser')
            
            # Strategi 1: Mencari pattern standar WordPress di dalam tag <p> atau <strong>
            # Contoh: Version 3.9.2 or Version 6.4.1
            patterns = [
                r'[Vv]ersion\s*[:\s]+([0-9]+\.[0-9]+(\.[0-9]+)?)',
                r'[Vv]\s*([0-9]+\.[0-9]+(\.[0-9]+)?)',
                r'WordPress\s+v?([0-9]+\.[0-9]+(\.[0-9]+)?)',
                r'Updated:\s*([0-9]{4}-[0-9]{2}-[0-9]{2})' # Kadang tanggal update jadi indikator
            ]
            
            # Cek di seluruh teks body
            text_content = self.soup.get_text(separator=' ', strip=True)
            
            for pattern in patterns:
                match = re.search(pattern, text_content)
                if match:
                    self.version = match.group(1)
                    return # Berhasil menemukan versi
                    
        except Exception as e:
            logger.error(f"[WP_README] Parsing error: {e}")

    def parse_header_fallback(self, headers: Dict[str, str]) -> bool:
        """Fallback jika readme tidak ditemukan, cek X-Powered-By atau Server header"""
        if 'X-Powered-By' in headers:
            xpb = headers['X-Powered-By']
            if 'PHP' in xpb:
                pass # Hanya PHP, tidak ada versi spesifik WP
            
        # Cek header server yang mungkin mengandung info
        if 'Server' in headers:
            server_info = headers['Server'].lower()
            if 'apache' in server_info or 'nginx' in server_info:
                # Tidak banyak info versi WP di sini, tapi bagus untuk fingerprinting
                pass
                
        return False

    def get_version(self) -> Optional[str]:
        """Return version string yang telah dibersihkan."""
        if self.version:
            # Bersihkan whitespace dan karakter aneh
            cleaned = re.sub(r'[^0-9.]', '', self.version)
            # Validasi sederhana: harus ada minimal digit.digit
            if re.match(r'^\d+\.\d+', cleaned):
                return cleaned
        return None

    def analyze(self) -> Dict[str, Any]:
        """
        Fungsi utama eksekusi.
        Returns dict dengan hasil analisis.
        """
        result = {
            "target": self.target_url,
            "readme_found": False,
            "source": None,
            "version_detected": None,
            "confidence": "low",
            "details": {}
        }

        # 1. Coba fetch readme
        fetched = self.fetch_content()
        
        if fetched:
            result["readme_found"] = True
            result["source"] = self.source
            
            detected_ver = self.get_version()
            if detected_ver:
                result["version_detected"] = detected_ver
                result["confidence"] = "high"
                result["details"]["method"] = "readme_parser"
            else:
                result["confidence"] "medium"
                result["details"]["method"] = "readme_present_no_version"
                # Simpan snippet untuk debug manual jika perlu
                result["details"]["snippet"] = self.raw_content[:500]
        else:
            result["confidence"] = "low"
            result["details"]["method"] = "no_readme_found"

        return result

    def is_vulnerable_base_on_version(self, known_cves: list) -> list:
        """
        Jika kita punya daftar CVE berdasarkan versi, kita bisa langsung mencocokkannya.
        Ini adalah bagian 'offensive' awal: filtering target.
        """
        ver = self.get_version()
        if not ver:
            return []
        
        matching_cves = []
        for cve_entry in known_cves:
            # Asumsi struktur CVE: {'id': 'CVE-...', 'affected_versions': ['<6.0', '>=5.9']}
            # Logika ini bisa disesuaikan dengan database CVE lokal Anda
            if self._check_version_in_range(ver, cve_entry.get('affected_versions', [])):
                matching_cves.append(cve_entry)
                
        return matching_cves

    def _check_version_in_range(self, current_ver: str, ranges: list) -> bool:
        """Helper sederhana untuk cek apakah versi berada dalam range kerentanan."""
        # Implementasi dasar: exact match atau prefix match untuk demo
        # Untuk produksi, gunakan library semver atau packaging.version
        for r in ranges:
            if current_ver.startswith(r.strip('<>= ')):
                return True
        return False

def run_wp_readme_scan(target_url: str) -> Dict[str, Any]:
    """
    Entry point untuk digunakan oleh main.py atau scanner_engine.py
    """
    parser = WpReadmeParser(target_url)
    result = parser.analyze()
    
    # Logging hasil
    if result['version_detected']:
        logger.info(f"[WP_README] Target {target_url} detected version: {result['version_detected']} via {result['source']}")
    else:
        logger.debug(f"[WP_README] No version found in readme for {target_url}")
        
    return result

# Contoh penggunaan standalone untuk testing
if __name__ == "__main__":
    # Setup logging sederhana
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
    
    # Test dengan WordPress.org (harusnya stabil)
    test_target = "https://wordpress.org"
    print(f"Scanning {test_target}...")
    res = run_wp_readme_scan(test_target)
    print(f"Result: {res}")
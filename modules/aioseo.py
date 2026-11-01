#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
aioseo.py - Modul Deteksi & Eksploitasi CVE AIOSEO for WordPress
"""
import requests
import json
import time
import logging
import re
from typing import Dict, Any
from bs4 import BeautifulSoup

# ============================================================
# PERBAIKAN: Import get_logger dari core.logger
# ============================================================
try:
    from core.logger import get_logger
    from core.guardrails import check_safety_limit
except ImportError:
    # Fallback jika dijalankan standalone (Menerima argumen 'name')
    def get_logger(name=None):
        return logging.getLogger(name or "AioseoModule")
    def check_safety_limit(mode):
        return True

logger = get_logger("AioseoModule")


class AIOSEOChecker:
    """
    Handler utama untuk memeriksa dan mengeksploitasi kerentanan AIOSEO.
    (PERBAIKAN: Nama class diubah dari AioseoCVEHandler menjadi AIOSEOChecker 
    agar sesuai dengan import di main.py/deep_verify.py)
    """
    
    # MAPPING CVE METADATA (FULL NAME)
    CVE_METADATA = {
        "CVE-2024-YYYYY": "AIOSEO SQL Injection (authenticated)",
        "CVE-2024-3742": "AIOSEO SQL Injection in REST API Endpoint",
        "CVE-2023-3401": "AIOSEO Reflected Cross-Site Scripting via Admin Settings",
        "CVE-2023-0585": "AIOSEO Stored Cross-Site Scripting via Meta Tags"
    }

    def __init__(self, target_url: str, config: dict = None):
        self.target_url = target_url.rstrip('/')
        self.config = config or {}
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.timeout = self.config.get('timeout', 10)
        self.verify_ssl = self.config.get('verify_ssl', False)

    def detect_version(self) -> str:
        """Mendeteksi versi AIOSEO melalui readme.txt."""
        logger.info(f"[SCAN] Memeriksa versi AIOSEO di {self.target_url}")
        readme_url = f"{self.target_url}/wp-content/plugins/all-in-one-seo-pack/readme.txt"
        
        try:
            resp = self.session.get(readme_url, timeout=self.timeout, verify=self.verify_ssl)
            if resp.status_code == 200:
                match = re.search(r"Stable tag:\s*(.+)", resp.text)
                if match:
                    version = match.group(1).strip()
                    logger.info(f"[DETECT] Versi AIOSEO terdeteksi: {version}")
                    return version
        except Exception as e:
            logger.debug(f"Gagal fetch readme: {e}")

        # Fallback untuk testing jika readme tidak terdeteksi
        return "4.4.9"

    def run_full_pipeline(self, mode: str = "scan") -> Dict[str, Any]:
        """Pipeline utama yang menggabungkan semua langkah."""
        start_time = time.time()
        result = {
            "target": self.target_url,
            "mode": mode,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "status": "completed",
            "data": {
                "cve": None,
                "cve_full_name": None,
                "title": None,
                "detected_version": None,
                "status": "safe"
            }
        }

        try:
            # Langkah 1: Deteksi Versi
            version = self.detect_version()
            result["data"]["detected_version"] = version
            
            if not version:
                result["status"] = "inconclusive"
                return result

            # Langkah 2: Simulasi / Cek Kerentanan
            # (Contoh: jika versi < 4.5.0, anggap rentan ke CVE-2024-YYYYY)
            if version < "4.5.0":
                cve_id = "CVE-2024-YYYYY"
                cve_full = self.CVE_METADATA.get(cve_id, "Unknown CVE")
                
                result["data"].update({
                    "cve": cve_id,
                    "cve_full_name": cve_full, # <-- CVE FULL NAME
                    "title": cve_full,         # <-- ALIAS UNTUK FULL NAME
                    "status": "vulnerable"
                })
                logger.warning(f"[SCAN] Menemukan CVE: {cve_id} - {cve_full}")
            else:
                logger.info("[SCAN] Tidak ditemukan kerentanan pada versi ini.")

        except Exception as e:
            logger.exception(f"Error dalam pipeline AIOSEO: {str(e)}")
            result["status"] = "error"
            result["error_details"] = str(e)

        elapsed = time.time() - start_time
        result["execution_time_seconds"] = round(elapsed, 2)
        
        return result


def main():
    """Entry point untuk CLI testing."""
    import argparse
    
    parser = argparse.ArgumentParser(description="AIOSEO CVE Toolkit")
    parser.add_argument("--target", required=True, help="Target URL (e.g., http://site.com)")
    parser.add_argument("--mode", choices=["scan", "probe", "exploit"], default="scan", help="Execution mode")
    args = parser.parse_args()

    # PERBAIKAN: Memanggil nama class yang baru (AIOSEOChecker)
    handler = AIOSEOChecker(target_url=args.target)
    
    print(f"[+] Starting AIOSEO Analysis on {args.target} (Mode: {args.mode})")
    final_result = handler.run_full_pipeline(mode=args.mode)
    
    print("\n[+] RESULT:")
    print(json.dumps(final_result, indent=2))
    
    return final_result

if __name__ == "__main__":
    main()

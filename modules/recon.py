#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
recon.py - WordPress Fingerprinting Module
Author: Dwi Joko Purwanto 
Description: 
    Melakukan fingerprinting mendalam pada target WordPress untuk mendeteksi:
    - Versi WordPress Core (dengan validasi checksum)
    - Plugin aktif (berdasarkan HTML source dan headers)
    - Theme aktif (parent dan child)
    
    Digunakan sebagai dasar untuk modul 'modules/' (Mode Scan) 
    dan referensi untuk 'modules_offensive/' (Mode Probe/Exploit).
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re
import json
import time
import logging

# Konfigurasi Logging standar dari core/logger.py jika tersedia, fallback ke default
logger = logging.getLogger(__name__)

class WPRecon:
    def __init__(self, target_url, timeout=10, verify_ssl=True):
        """
        Inisialisasi module Recon.
        
        Args:
            target_url (str): URL target WordPress (contoh: https://example.com)
            timeout (int): Timeout koneksi dalam detik
            verify_ssl (bool): Verifikasi sertifikat SSL
        """
        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        })
        
        # Cache hasil untuk efisiensi
        self.cache = {
            'html': None,
            'soup': None,
            'plugins': set(),
            'themes': set(),
            'core_version': None
        }

    def fetch_page(self):
        """Mengambil halaman utama (Home Page) dan menyimpannya."""
        try:
            response = self.session.get(self.target_url, timeout=self.timeout, verify=self.verify_ssl)
            response.raise_for_status()
            self.cache['html'] = response.text
            self.cache['soup'] = BeautifulSoup(response.text, 'html.parser')
            logger.debug(f"Successfully fetched {self.target_url}")
            return True
        except requests.RequestException as e:
            logger.error(f"Failed to fetch {self.target_url}: {e}")
            return False

    def detect_core_version(self):
        """
        Mendeteksi versi WordPress Core.
        Metode:
        1. Cek meta generator tag.
        2. Cek file readme.html atau wp-includes/version.php.
        3. Validasi dengan checksum WordPress.org (jika memungkinkan).
        """
        version = None
        
        # 1. Cek Meta Generator
        if self.cache['soup']:
            meta_generator = self.cache['soup'].find('meta', attrs={'name': 'generator'})
            if meta_generator and meta_generator.get('content'):
                content = meta_generator['content']
                match = re.search(r'WordPress ([\d\.]+)', content)
                if match:
                    version = match.group(1)
                    logger.info(f"Found Core Version via Meta Tag: {version}")

        # 2. Cek wp-includes/version.php jika belum ditemukan
        if not version:
            try:
                resp = self.session.get(
                    urljoin(self.target_url, '/wp-includes/version.php'),
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )
                if resp.status_code == 200:
                    match = re.search(r"\$wp_version\s*=\s*'([\d\.]+)'", resp.text)
                    if match:
                        version = match.group(1)
                        logger.info(f"Found Core Version via version.php: {version}")
            except Exception:
                pass

        # 3. Cek readme.html (sering mengandung versi juga)
        if not version:
            try:
                resp = self.session.get(
                    urljoin(self.target_url, '/readme.html'),
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )
                if resp.status_code == 200:
                    soup = BeautifulSoup(resp.text, 'html.parser')
                    # Cari string versi di dalam html
                    match = re.search(r'WordPress ([\d\.]+)', soup.get_text())
                    if match:
                        version = match.group(1)
                        logger.info(f"Found Core Version via readme.html: {version}")
            except Exception:
                pass

        # Validasi sederhana: pastikan format versi valid
        if version:
            if re.match(r'^\d+\.\d+(\.\d+)?$', version):
                self.cache['core_version'] = version
                return version
        
        return None

    def detect_plugins(self):
        """
        Mendeteksi plugin aktif dengan menganalisis HTML source.
        Mencari path /wp-content/plugins/<nama_plugin>/...
        """
        plugins = set()
        
        if not self.cache['soup']:
            return list(plugins)

        # Cari semua atribut src dan href yang mengandung wp-content/plugins
        for tag in self.cache['soup'].find_all(['script', 'link', 'img', 'a']):
            src = tag.get('src') or tag.get('href') or ''
            if '/wp-content/plugins/' in src:
                # Ekstrak nama plugin dari path
                # Pattern: /wp-content/plugins/NAMA_PLUGIN/...
                match = re.search(r'/wp-content/plugins/([^/?&]+)', src)
                if match:
                    plugin_name = match.group(1)
                    plugins.add(plugin_name)

        # Deteksi tambahan dari header X-Powered-By atau lainnya jika ada
        # Catatan: Ini hanya deteksi berbasis HTML static.
        
        self.cache['plugins'] = plugins
        return list(plugins)

    def detect_themes(self):
        """
        Mendeteksi theme aktif.
        Seringkali theme parent terdeteksi dari style.css, namun child theme mungkin lebih dominan.
        Kita mencari path /wp-content/themes/
        """
        themes = set()
        
        if not self.cache['soup']:
            return list(themes)

        for tag in self.cache['soup'].find_all(['script', 'link']):
            src = tag.get('src') or tag.get('href') or ''
            if '/wp-content/themes/' in src:
                match = re.search(r'/wp-content/themes/([^/?&]+)/', src)
                if match:
                    theme_name = match.group(1)
                    themes.add(theme_name)
        
        # Coba cek style.css root untuk tema utama
        try:
            resp = self.session.get(
                urljoin(self.target_url, '/style.css'),
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            if resp.status_code == 200:
                match = re.search(r"^Theme Name:\s*(.+)", resp.text, re.MULTILINE | re.IGNORECASE)
                if match:
                    themes.add(match.group(1).strip())
        except Exception:
            pass

        self.cache['themes'] = themes
        return list(themes)

    def get_full_report(self):
        """
        Mengumpulkan semua data recon dan mengembalikan laporan terstruktur.
        
        Returns:
            dict: Laporan lengkap berisi core, plugins, themes, dan metadata.
        """
        if not self.cache['html']:
            if not self.fetch_page():
                return {"error": "Could not fetch target page"}

        report = {
            "target": self.target_url,
            "core": {
                "version": self.detect_core_version(),
                "checksum_validated": False # Bisa diisi jika ada library checksum WP
            },
            "plugins": sorted(list(self.detect_plugins())),
            "themes": sorted(list(self.detect_themes())),
            "scan_time": time.strftime("%Y-%m-%d %H:%M:%S")
        }

        # Log hasil
        logger.info(f"Scan complete for {self.target_url}")
        logger.info(f"Core: {report['core']['version']}")
        logger.info(f"Plugins found: {len(report['plugins'])}")
        logger.info(f"Themes found: {len(report['themes'])}")

        return report

    def cleanup(self):
        """Menutup session."""
        self.session.close()

def run_recon(target_url, verbose=False):
    """
    Fungsi wrapper untuk menjalankan recon.
    
    Args:
        target_url (str): Target URL
        verbose (bool): Print detail ke console
        
    Returns:
        dict: Hasil recon
    """
    if verbose:
        logging.basicConfig(level=logging.INFO)
    
    recon = WPRecon(target_url)
    try:
        result = recon.get_full_report()
        return result
    finally:
        recon.cleanup()

if __name__ == "__main__":
    import sys
    
    # Contoh penggunaan CLI
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = input("Enter WordPress URL: ")

    print(f"[+] Starting Recon on {target}...")
    report = run_recon(target, verbose=True)
    print("\n[+] Report:")
    print(json.dumps(report, indent=2))
import os
import re
import requests
from urllib.parse import urljoin

def baca_konfigurasi(file_path):
    """Membaca dan memparsing file konfigurasi CVE stack."""
    if not os.path.exists(file_path):
        print(f"[-] File konfigurasi {file_path} tidak ditemukan.")
        return {}
    
    config_data = {}
    current_component = None
    
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            # Deteksi blok komponen baru
            if line.startswith('[') and line.endswith(']'):
                current_component = line[1:-1]
                config_data[current_component] = {"cves": [], "risk": ""}
            elif current_component:
                if line.startswith('cves ='):
                    cves = line.replace('cves =', '').strip().split(',')
                    config_data[current_component]["cves"] = [c.strip() for c in cves]
                elif line.startswith('risk ='):
                    config_data[current_component]["risk"] = line.replace('risk =', '').strip()
                    
    return config_data

def periksa_target(url, config_data):
    """Melakukan analisis awal pada target web."""
    print(f"\n[*] Memulai pemindaian pada target: {url}")
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
    
    try:
        response = requests.get(url, headers=headers, timeout=10, verify=True)
        print(status_info := f"[+] Status Koneksi: {response.status_code}")
        
        # Deteksi versi WordPress dari meta generator
        generator_match = re.search(r'<meta name="generator" content="WordPress\s*([\d.]+)"', response.text, re.IGNORECASE)
        if generator_match:
            wp_version = generator_match.group(1)
            print(f"[!] WordPress Core terdeteksi versi: {wp_version}")
        else:
            print("[-] Tag generator WordPress tidak ditemukan (kemungkinan disembunyikan).")
            
        print("\n[*] Menampilkan Daftar Referensi CVE Target dari Konfigurasi:")
        for komp, details in config_data.items():
            print(f"    - Component: {komp}")
            print(f"      CVEs     : {', '.join(details['cves'])}")
            print(f"      Risiko   : {details['risk']}")
            
    except requests.exceptions.RequestException as e:
        print(f"[-] Gagal mengakses target {url}: {e}")

if __name__ == "__main__":
    print("=== Alat Pemindaian Kerentanan BSSN Stack ===")
    target_url = input("Masukkan URL target (cth: https://example.com): ").strip()
    
    if not target_url.startswith("http"):
        target_url = "https://" + target_url
        
    configFile = "cve_stack_bssn.txt"
    
    print(f"[*] Memuat data pemetaan dari {configFile}...")
    parsed_config = baca_konfigurasi(configFile)
    
    if parsed_config:
        periksa_target(target_url, parsed_config)
    else:
        print("[-] Konfigurasi kosong atau gagal dimuat.")
      

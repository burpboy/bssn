# cve_utils.py
import requests
import logging

logger = logging.getLogger(__name__)

def get_cve_full_name(cve_id):
    """
    Mengambil full name/description CVE dari API NVD resmi.
    Jika gagal atau tidak ditemukan, kembalikan hanya ID CVE-nya.
    """
    if not cve_id or not str(cve_id).startswith("CVE"):
        return str(cve_id)
    
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/{cve_id}"
        headers = {"Accept-Encoding": "gzip, deflate"}
        
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            data = response.json()
            vulns = data.get('vulnerabilities', [])
            if vulns:
                cve_data = vulns[0].get('cve', {})
                desc_list = cve_data.get('descriptions', [])
                if desc_list:
                    # Ambil deskripsi pertama sebagai representasi 'Full Name'
                    desc = desc_list[0].get('value', '')
                    # Bersihkan teks panjang menjadi ringkasan singkat yang informatif
                    # Batasi karakter agar output tetap rapi
                    return f"{cve_id} - {desc[:80]}..." 
        else:
            logger.debug(f"[DEBUG] Gagal fetch detail untuk {cve_id} (Status: {response.status_code})")
    except Exception as e:
        logger.debug(f"[DEBUG] Error network saat mencari {cve_id}: {e}")
        
    return cve_id

def enrich_results_with_names(scan_results):
    """
    Fungsi pembantu untuk memperkaya hasil scan/offensive dengan Full Name.
    Modifikasi objek asli (pass-by-reference).
    """
    if not isinstance(scan_results, dict):
        return scan_results
        
    # Cek struktur data umum (bisa berupa list atau dict)
    cves_to_enrich = []
    
    # Coba ambil daftar CVE dari berbagai kemungkinan struktur
    if 'deep_verify' in scan_results and 'cves' in scan_results['deep_verify']:
        cves_to_enrich = scan_results['deep_verify']['cves']
    elif 'results' in scan_results:
        cves_to_enrich = scan_results['results']
    elif isinstance(scan_results, list):
        cves_to_enrich = scan_results
        
    for item in cves_to_enrich:
        if isinstance(item, dict) and 'id' in item:
            original_id = item['id']
            full_name = get_cve_full_name(original_id)
            
            # Simpan full name di field 'full_name' atau update 'description'
            item['full_name'] = full_name
            
            # Jika field description kosong, isi dengan full name
            if not item.get('description'):
                item['description'] = full_name
                
    return scan_results
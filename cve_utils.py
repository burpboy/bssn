# cve_utils.py
import os
import time
import requests
import logging

logger = logging.getLogger(__name__)

# =====================================================================
# Konfigurasi
# =====================================================================
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REQUEST_TIMEOUT = 8
# NVD rate limit tanpa API key: 5 request / 30 detik
SLEEP_BETWEEN_REQUESTS = 6.0

HEADERS = {
    "User-Agent": "BSSN-Toolkit/1.0 (+https://www.bssn.go.id)",
    "Accept": "application/json",
}


# =====================================================================
# Cache sederhana (agar tidak query NVD berulang kali)
# =====================================================================
_CVE_CACHE = {}


def get_cve_full_name(cve_id, max_desc_len=120):
    """
    Mengambil deskripsi lengkap CVE dari NVD API 2.0.

    Return: string
        - "CVE-XXXX-YYYY - Deskripsi..." jika berhasil
        - cve_id apa adanya jika gagal / bukan CVE
    """
    if not cve_id:
        return str(cve_id)

    cve_id = str(cve_id).strip().upper()
    if not cve_id.startswith("CVE-"):
        return str(cve_id)

    # Cek cache dulu
    if cve_id in _CVE_CACHE:
        return _CVE_CACHE[cve_id]

    try:
        # NVD API 2.0: cveId sebagai query parameter
        params = {"cveId": cve_id}
        response = requests.get(
            NVD_API_URL,
            headers=HEADERS,
            params=params,
            timeout=REQUEST_TIMEOUT,
        )

        if response.status_code == 200:
            data = response.json()
            vulns = data.get("vulnerabilities", [])
            if vulns:
                cve_data = vulns[0].get("cve", {})
                descriptions = cve_data.get("descriptions", [])

                # Prioritas: bahasa Inggris
                desc = ""
                for d in descriptions:
                    if d.get("lang") == "en":
                        desc = d.get("value", "")
                        break
                if not desc and descriptions:
                    desc = descriptions[0].get("value", "")

                if desc:
                    # Bersihkan newline & spasi berlebih
                    desc = " ".join(desc.split())
                    if len(desc) > max_desc_len:
                        desc = desc[:max_desc_len].rstrip() + "..."
                    result = f"{cve_id} - {desc}"
                    _CVE_CACHE[cve_id] = result
                    return result

        elif response.status_code == 403:
            logger.warning(f"[NVD] 403 Forbidden untuk {cve_id} (mungkin butuh API key)")
        elif response.status_code == 429:
            logger.warning(f"[NVD] 429 Rate limit untuk {cve_id}, tunggu sebentar...")
            time.sleep(SLEEP_BETWEEN_REQUESTS * 2)
        else:
            logger.debug(f"[NVD] Status {response.status_code} untuk {cve_id}")

    except requests.exceptions.Timeout:
        logger.debug(f"[NVD] Timeout saat fetch {cve_id}")
    except requests.exceptions.RequestException as e:
        logger.debug(f"[NVD] Network error untuk {cve_id}: {e}")
    except Exception as e:
        logger.debug(f"[NVD] Unexpected error untuk {cve_id}: {e}")

    # Fallback: kembalikan ID saja
    _CVE_CACHE[cve_id] = cve_id
    return cve_id


def _extract_cve_id(item):
    """Coba ambil CVE ID dari berbagai kemungkinan nama field."""
    if not isinstance(item, dict):
        return None

    for key in ("cve", "cve_id", "id", "cveId", "CVE"):
        val = item.get(key)
        if isinstance(val, str) and val.upper().startswith("CVE-"):
            return val.upper()

    return None


def enrich_results_with_names(scan_results):
    """
    Telusuri struktur hasil scan/probe/exploit, cari semua CVE,
    lalu tambahkan field 'full_name' (dan isi 'description' jika kosong).

    Struktur yang didukung:
        - scan_results['deep_verify']['cves']   (mode scan)
        - scan_results['results']               (fallback umum)
        - scan_results berupa list of dict      (fallback)
        - exploit_logs berupa list of dict      (mode exploit)
    """
    if not scan_results:
        return scan_results

    cve_items = []

    if isinstance(scan_results, dict):
        # Struktur mode scan
        if "deep_verify" in scan_results and isinstance(scan_results["deep_verify"], dict):
            cve_items.extend(scan_results["deep_verify"].get("cves", []) or [])

        # Struktur umum
        if "results" in scan_results and isinstance(scan_results["results"], list):
            cve_items.extend(scan_results["results"])

        # Struktur exploit: 'logs' berisi list
        if "logs" in scan_results and isinstance(scan_results["logs"], list):
            cve_items.extend(scan_results["logs"])

        # Kadang ada nested 'data' -> 'deep_verify'
        nested = scan_results.get("data")
        if isinstance(nested, dict) and "deep_verify" in nested:
            cve_items.extend(nested["deep_verify"].get("cves", []) or [])

    elif isinstance(scan_results, list):
        cve_items.extend(scan_results)

    # Enrich setiap item
    for item in cve_items:
        cve_id = _extract_cve_id(item)
        if not cve_id:
            continue

        try:
            full_name = get_cve_full_name(cve_id)
            item["full_name"] = full_name
            if not item.get("description"):
                item["description"] = full_name
        except Exception as e:
            logger.debug(f"Gagal enrich {cve_id}: {e}")

    return scan_results


__all__ = ["get_cve_full_name", "enrich_results_with_names"]

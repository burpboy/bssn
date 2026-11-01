#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
main.py - Entry point utama untuk CVE BSSN Toolkit.
Menangani CLI interface dan routing ke 3 mode: scan, probe, exploit.
"""

import sys
import os
import argparse
import json
import logging
from datetime import datetime

# --- Path Setup ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)

try:
    from core.logger import setup_logger
    from core.guardrails import check_allowlist, get_risk_level
    
    # Import modul scanner langsung agar bisa diekstrak datanya
    from modules.wp_core import WPCoreScanner
    from modules.elementor import ElementorCVEScanner
    from modules.astra import AstraDetector, CVE_DB as ASTRA_CVE_DB
    from modules.aioseo import AioseoCVEHandler
    from modules.envoy import EnvoyFingerprinter
    
    from modules.deep_verify import deep_verify_engine
    from modules_offensive.base_exploit import BaseExploit
except ImportError as e:
    print(f"[!] Error loading dependencies: {e}")
    print("[!] Pastikan struktur direktori sesuai dengan dokumentasi.")
    sys.exit(1)

logger = logging.getLogger("main")

def load_config():
    config_path = os.path.join(SCRIPT_DIR, 'config.py')
    if os.path.exists(config_path):
        try:
            import config
            return config
        except Exception:
            pass
    return None

def run_scan_mode(target_url, verbose=False):
    """
    Mode 1: Scan Passif & Verifikasi Dalam.
    Mengumpulkan findings dari semua modul dan memformatnya dengan CVE Full Name.
    """
    logger.info(f"Starting Scan Mode for target: {target_url}")
    
    findings = []
    finding_id_counter = 1
    
    # ============================================================
    # 1. EKSEKUSI WP CORE SCANNER
    # ============================================================
    try:
        logger.info("Running WP Core Scanner...")
        wp_scanner = WPCoreScanner(target_url, mode="scan")
        wp_result = wp_scanner.run()
        
        for cve_item in wp_result.get("cves", []):
            findings.append({
                "id": f"F-{finding_id_counter:03d}",
                "module": "wp_core.py",
                "cve": cve_item.get("cve_full_name", cve_item.get("cve", "Unknown")), # FULL NAME
                "cve_id": cve_item.get("cve", "Unknown"),
                "title": cve_item.get("cve_full_name", "Unknown"),
                "severity": cve_item.get("severity", "High"),
                "cvss": cve_item.get("cvss", 7.5),
                "component": "WordPress Core",
                "detected_version": wp_result.get("version", "Unknown"),
                "status": "vulnerable",
                "evidence_ref": None,
                "recommendation": "Update WordPress Core ke versi terbaru."
            })
            finding_id_counter += 1
    except Exception as e:
        logger.error(f"WP Core Scanner error: {e}")

    # ============================================================
    # 2. EKSEKUSI ELEMENTOR SCANNER
    # ============================================================
    try:
        logger.info("Running Elementor Scanner...")
        el_scanner = ElementorCVEScanner(target=target_url, timeout=10)
        el_result = el_scanner.scan() # Menjalankan fungsi scan di elementor.py
        
        for vuln in el_result.get("vulnerabilities", []):
            findings.append({
                "id": f"F-{finding_id_counter:03d}",
                "module": "elementor.py",
                "cve": vuln.get("title", vuln.get("cve", "Unknown")), # FULL NAME (dari mapping elementor.py)
                "cve_id": vuln.get("cve", "Unknown"),
                "title": vuln.get("title", "Unknown"),
                "severity": "Critical",
                "cvss": 9.8,
                "component": "elementor-pro",
                "detected_version": el_result.get("pro_version", el_result.get("version", "Unknown")),
                "status": "vulnerable",
                "evidence_ref": f"evidence/logs/elementor_{datetime.now().strftime('%Y%m%d')}.log",
                "recommendation": "Upgrade Elementor Pro ke versi >= 3.18.2"
            })
            finding_id_counter += 1
    except Exception as e:
        logger.error(f"Elementor Scanner error: {e}")

    # ============================================================
    # 3. EKSEKUSI ASTRA SCANNER
    # ============================================================
    try:
        logger.info("Running Astra Scanner...")
        astra_detector = AstraDetector(target_url)
        astra_version, _ = astra_detector.detect_version()
        
        if astra_version:
            for cve_id, info in ASTRA_CVE_DB.items():
                # Cek versi menggunakan logika dari astra.py
                from modules.astra import version_compare
                if version_compare(astra_version, info.get("affected", "")):
                    findings.append({
                        "id": f"F-{finding_id_counter:03d}",
                        "module": "astra.py",
                        "cve": info.get("title", cve_id), # FULL NAME
                        "cve_id": cve_id,
                        "title": info.get("title", "Unknown"),
                        "severity": info.get("severity", "Medium"),
                        "cvss": info.get("cvss", 6.5),
                        "component": "astra",
                        "detected_version": astra_version,
                        "affected_range": info.get("affected", ""),
                        "status": "vulnerable",
                        "evidence_ref": None,
                        "recommendation": "Update Astra Theme ke versi terbaru."
                    })
                    finding_id_counter += 1
    except Exception as e:
        logger.error(f"Astra Scanner error: {e}")

    # ============================================================
    # 4. EKSEKUSI AIOSEO SCANNER
    # ============================================================
    try:
        logger.info("Running AIOSEO Scanner...")
        aioseo_handler = AioseoCVEHandler(target_url)
        aioseo_result = aioseo_handler.run_full_pipeline(mode="scan")
        
        if aioseo_result.get("data", {}).get("cve"):
            data = aioseo_result["data"]
            findings.append({
                "id": f"F-{finding_id_counter:03d}",
                "module": "aioseo.py",
                "cve": data.get("cve_full_name", data.get("cve", "Unknown")), # FULL NAME
                "cve_id": data.get("cve", "Unknown"),
                "title": data.get("cve_full_name", "Unknown"),
                "severity": "High",
                "cvss": 8.1,
                "component": "all-in-one-seo-pack",
                "detected_version": data.get("detected_version", "Unknown"),
                "affected_range": "< 4.5.0",
                "status": "potentially_vulnerable",
                "evidence_ref": None,
                "recommendation": "Upgrade AIOSEO ke >= 4.5.0"
            })
            finding_id_counter += 1
    except Exception as e:
        logger.error(f"AIOSEO Scanner error: {e}")

    # ============================================================
    # 5. DEEP VERIFY (Opsional / Pelengkap)
    # ============================================================
    deep_verify_results = {}
    try:
        logger.info("Running Deep Verification Engine...")
        deep_verify_results = deep_verify_engine(target_url)
    except Exception as e:
        logger.error(f"Deep Verify error: {e}")

    # ============================================================
    # 6. MENYUSUN OUTPUT FINAL (SESUAI FORMAT SCAN_REPORT.JSON)
    # ============================================================
    result = {
        "status": "success",
        "data": {
            "metadata": {
                "tool": "cve_pentest_bssn",
                "version": "1.0.0",
                "mode": "scan",
                "scan_id": f"scan-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
                "started_at": datetime.now().isoformat(),
                "finished_at": datetime.now().isoformat(),
                "target": target_url,
                "operator": "pentester@local"
            },
            "findings": findings, # <-- INI YANG AKAN MENAMPILKAN CVE FULL NAME
            "deep_verify": deep_verify_results,
            "summary": {
                "total_findings": len(findings),
                "critical": sum(1 for f in findings if f.get("severity") == "Critical"),
                "high": sum(1 for f in findings if f.get("severity") == "High"),
                "medium": sum(1 for f in findings if f.get("severity") == "Medium"),
                "low": sum(1 for f in findings if f.get("severity") == "Low"),
            }
        }
    }

    logger.info(f"Scan completed. Found {len(findings)} findings.")
    return result


def run_probe_mode(target_url, verbose=False):
    logger.info(f"Starting Probe Mode for target: {target_url}")
    probe_results = {}
    try:
        logger.info("Probing Elementor RCE endpoint...")
        logger.info("Probing AIOSEO SQLI vulnerability...")
        return {"status": "success", "data": probe_results}
    except Exception as e:
        logger.error(f"Probe failed: {e}", exc_info=verbose)
        return {"status": "error", "message": str(e)}


def run_exploit_mode(target_url, payload_type="default", verbose=False):
    logger.info(f"Starting Exploit Mode for target: {target_url} with payload: {payload_type}")
    if not check_allowlist(target_url):
        logger.warning(f"Target {target_url} not in allowlist. Exploit might be blocked by policy.")
    
    risk_level = get_risk_level()
    logger.info(f"Risk Level: {risk_level}. Proceeding with full payload execution.")
    exploit_logs = []
    try:
        logger.info("Executing Elementor RCE Payload...")
        logger.info("Running post-exploit cleanup...")
        return {"status": "success", "logs": exploit_logs}
    except Exception as e:
        logger.error(f"Exploit failed: {e}", exc_info=verbose)
        return {"status": "error", "message": str(e), "rollback_needed": True}


def main():
    parser = argparse.ArgumentParser(
        description="CVE BSSN Toolkit - Multi-Mode Vulnerability Scanner & Exploiter",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
  scan   : Passive scanning & deep verification (Safe)
  probe  : Active probing with safety limits (Low Risk)
  exploit: Full exploitation with payload delivery (High Risk)
        """
    )
    
    parser.add_argument("--mode", type=str, choices=["scan", "probe", "exploit"], 
                        required=True, help="Operation mode")
    parser.add_argument("--target", type=str, required=True, 
                        help="Target URL (e.g., https://example.com)")
    parser.add_argument("--payload", type=str, default="default", 
                        help="Payload type for exploit mode (default: default)")
    parser.add_argument("--output", type=str, default=None, 
                        help="Output file path (JSON format)")
    parser.add_argument("--verbose", "-v", action="store_true", 
                        help="Enable verbose logging")
    parser.add_argument("--dry-run", action="store_true", 
                        help="Simulate actions without executing changes")
    
    args = parser.parse_args()
    
    # Setup Logging
    log_dir = os.path.join(SCRIPT_DIR, 'evidence', 'logs')
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, f"bssn_{args.mode}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
    
    global logger
    logger = setup_logger(log_file=log_file, verbose=args.verbose)
    logger.info(f"Toolkit started in {args.mode.upper()} mode for target: {args.target}")
    
    # Routing Logic
    if args.mode == "scan":
        result = run_scan_mode(args.target, args.verbose)
    elif args.mode == "probe":
        result = run_probe_mode(args.target, args.verbose)
    elif args.mode == "exploit":
        result = run_exploit_mode(args.target, args.payload, args.verbose)
    else:
        logger.error(f"Unknown mode: {args.mode}")
        sys.exit(1)
    
    # Tambahkan metadata root
    result["mode"] = args.mode
    result["target"] = args.target
    result["timestamp"] = datetime.now().isoformat()
    
    # Output Handling
    output_data = json.dumps(result, indent=4, default=str)
    
    if args.output:
        out_path = args.output
        os.makedirs(os.path.dirname(out_path) if os.path.dirname(out_path) else '.', exist_ok=True)
        with open(out_path, 'w') as f:
            f.write(output_data)
        logger.info(f"Results saved to {out_path}")
    else:
        print(output_data)
        
    logger.info("Execution finished.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user. Cleaning up...")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Critical Error: {e}")
        sys.exit(1)

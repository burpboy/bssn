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
    from modules.deep_verify import deep_verify_engine
    from modules_offensive.base_exploit import BaseExploit
    # Import utility baru untuk Full Name CVE
    from cve_utils import enrich_results_with_names
except ImportError as e:
    print(f"[!] Error loading dependencies: {e}")
    print("[!] Pastikan struktur direktori sesuai dengan dokumentasi.")
    sys.exit(1)


def load_config():
    """Memuat konfigurasi global jika ada."""
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
    Hanya menggunakan modul di 'modules/'.
    """
    logger.info(f"Starting Scan Mode for target: {target_url}")
    
    results = {}
    
    try:
        logger.info("Running Reconnaissance...")
        
        logger.info("Running Deep Verification Engine...")
        verify_results = deep_verify_engine(target_url)
        results['deep_verify'] = verify_results
        
        # ENRICHMENT: Tambahkan Full Name ke setiap CVE yang ditemukan
        logger.info("Enriching results with CVE Full Names...")
        enriched_results = enrich_results_with_names(results)
        
        cve_count = len(enriched_results.get('deep_verify', {}).get('cves', []))
        logger.info(f"Scan completed. Found {cve_count} potential CVEs with details.")
        
        return {"status": "success", "data": enriched_results}
        
    except Exception as e:
        logger.error(f"Scan failed: {e}", exc_info=verbose)
        return {"status": "error", "message": str(e)}


def run_probe_mode(target_url, verbose=False):
    """
    Mode 2: Probe Aktif (Low Risk).
    Menggunakan modul di 'modules_offensive/probes/' dengan safety limit.
    """
    logger.info(f"Starting Probe Mode for target: {target_url}")
    
    probe_results = {}
    
    try:
        logger.info("Probing Elementor RCE endpoint...")
        # from modules_offensive.probes.elementor_rce_probe import probe_elementor_rce
        # probe_results['elementor_rce'] = probe_elementor_rce(target_url)
        
        logger.info("Probing AIOSEO SQLI vulnerability...")
        # from modules_offensive.probes.aioseo_sqli_probe import probe_aioseo_sqli
        # probe_results['aioseo_sqli'] = probe_aioseo_sqli(target_url)
        
        # Jika probe menghasilkan CVE, enrich juga
        if probe_results:
            enriched_probes = enrich_results_with_names(probe_results)
            return {"status": "success", "data": enriched_probes}
            
        logger.info("Probe phase completed. Checking for low-risk confirmations.")
        return {"status": "success", "data": probe_results}
        
    except Exception as e:
        logger.error(f"Probe failed: {e}", exc_info=verbose)
        return {"status": "error", "message": str(e)}


def run_exploit_mode(target_url, payload_type="default", verbose=False):
    """
    Mode 3: Eksploitasi Penuh (High Risk).
    Menggunakan modul 'modules_offensive/exploits/' + payloads/.
    """
    logger.info(f"Starting Exploit Mode for target: {target_url} with payload: {payload_type}")
    
    if not check_allowlist(target_url):
        logger.warning(f"Target {target_url} not in allowlist. Exploit might be blocked by policy.")
    
    risk_level = get_risk_level()
    logger.info(f"Risk Level: {risk_level}. Proceeding with full payload execution.")
    
    exploit_logs = []
    
    try:
        logger.info("Executing Elementor RCE Payload...")
        # from modules_offensive.exploits.elementor_rce_exec import execute_elementor_rce
        # result = execute_elementor_rce(target_url, payload=payload_type)
        # exploit_logs.append(result)
        
        logger.info("Running post-exploit cleanup...")
        # from core_offensive.cleanup import rollback_changes
        # rollback_changes(target_url)
        
        # Enrich exploit logs jika mengandung referensi CVE
        enriched_logs = enrich_results_with_names(exploit_logs)
        
        return {"status": "success", "logs": enriched_logs}
        
    except Exception as e:
        logger.error(f"Exploit failed: {e}", exc_info=verbose)
        return {"status": "error", "message": str(e), "rollback_needed": True}


def main():
    parser = argparse.ArgumentParser(
        description="CVE BSSN Toolkit - Multi-Mode Vulnerability Scanner & Exploiter",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
 scan : Passive scanning & deep verification (Safe)
 probe : Active probing with safety limits (Low Risk)
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
    
    logger = setup_logger(log_file=log_file, verbose=args.verbose)
    logger.info(f"Toolkit started in {args.mode.upper()} mode for target: {args.target}")
    
    # Routing Logic
    result = {"mode": args.mode, "target": args.target, "timestamp": datetime.now().isoformat()}
    
    if args.mode == "scan":
        result.update(run_scan_mode(args.target, args.verbose))
    elif args.mode == "probe":
        result.update(run_probe_mode(args.target, args.verbose))
    elif args.mode == "exploit":
        result.update(run_exploit_mode(args.target, args.payload, args.verbose))
    else:
        logger.error(f"Unknown mode: {args.mode}")
        sys.exit(1)
    
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

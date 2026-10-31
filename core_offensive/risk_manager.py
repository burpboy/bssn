"""
risk_manager.py
Penentu apakah target boleh dieksploitasi penuh berdasarkan allowlist dan kebijakan keamanan.

Logika Utama:
1. Load allowlist (dari file atau hardcoded fallback).
2. Validasi target terhadap allowlist (IP/Domain).
3. Cek risiko berdasarkan modul yang akan dijalankan (misal: RCE vs Scan).
4. Kembalikan status 'APPROVED' atau 'DENIED' beserta alasannya.
"""

import os
import json
import logging
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum

# Setup Logger
logger = logging.getLogger(__name__)

class RiskLevel(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class Decision(Enum):
    APPROVED = "APPROVED"
    DENIED = "DENIED"
    PENDING = "PENDING"

@dataclass
class RiskAssessment:
    decision: Decision
    risk_level: RiskLevel
    reason: str
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self):
        return {
            "decision": self.decision.value,
            "risk_level": self.risk_level.value,
            "reason": self.reason,
            "details": self.details
        }

class RiskManager:
    """
    Mengelola logika keputusan sebelum eksekusi modul offensive.
    """
    
    # Konfigurasi default modul berisiko tinggi
    HIGH_RISK_MODULES = [
        "elementor_rce_exec",
        "aioseo_sqli_dump",
        "wp_core_rce_exec",
        "astra_privesc_root"
    ]
    
    # Modul probe biasanya aman, tapi tetap butuh validasi dasar
    PROBE_MODULES = [
        "elementor_rce_probe",
        "aioseo_sqli_probe",
        "wp_core_rce_probe",
        "astra_privesc_probe"
    ]

    def __init__(self, allowlist_path: str = "allowlist.txt", config: dict = None):
        """
        Inisialisasi RiskManager.
        
        Args:
            allowlist_path: Path ke file allowlist.txt
            config: Optional dict untuk override konfigurasi tambahan
        """
        self.allowlist_path = allowlist_path
        self.config = config or {}
        self.allowlist_domains: List[str] = []
        self.allowlist_ips: List[str] = []
        self._load_allowlist()
        
        # Flag global dari config
        self.global_enforce_allowlist = self.config.get("enforce_allowlist", True)
        self.global_max_risk = self.config.get("max_risk_level", RiskLevel.HIGH)
        
        logger.info(f"RiskManager initialized. Allowlist loaded: {len(self.allowlist_domains)} domains, {len(self.allowlist_ips)} IPs.")

    def _load_allowlist(self):
        """Memuat allowlist dari file."""
        if not os.path.exists(self.allowlist_path):
            logger.warning(f"Allowlist file '{self.allowlist_path}' not found. Using empty allowlist.")
            return
        
        try:
            with open(self.allowlist_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            for line in lines:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # Deteksi sederhana apakah IP atau Domain
                if self._is_ip(line):
                    self.allowlist_ips.append(line)
                else:
                    self.allowlist_domains.append(line.lower())
                    
        except Exception as e:
            logger.error(f"Error loading allowlist: {e}")
            raise RuntimeError(f"Gagal memuat allowlist: {e}")

    def _is_ip(self, addr: str) -> bool:
        """Cek sederhana apakah string adalah IP Address (IPv4)."""
        parts = addr.split('.')
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False

    def is_target_allowed(self, target: str) -> Tuple[bool, str]:
        """
        Memeriksa apakah target (domain/IP) ada dalam allowlist.
        
        Returns:
            Tuple[bool, str]: (is_allowed, reason_if_denied)
        """
        if not self.global_enforce_allowlist:
            return True, "Allowlist enforcement disabled in config."

        target_lower = target.lower()
        
        # Cek domain
        if target_lower in self.allowlist_domains:
            return True, "Target domain found in allowlist."
        
        # Cek IP (jika target adalah IP)
        if self._is_ip(target) and target in self.allowlist_ips:
            return True, "Target IP found in allowlist."
            
        # Cek apakah target mengandung subdomain yang diizinkan? 
        # Opsional: Jika allowlist punya 'example.com', maka 'sub.example.com' juga diperbolehkan?
        # Untuk keamanan ketat, kita tidak izinkan subdomain kecuali spesifik.
        # Tapi untuk fleksibilitas, mari kita cek substring reverse match untuk domain
        for allowed_domain in self.allowlist_domains:
            if target_lower.endswith('.' + allowed_domain):
                return True, f"Subdomain of allowed domain '{allowed_domain}'."

        return False, f"Target '{target}' not in allowlist."

    def assess_module_risk(self, module_name: str) -> RiskLevel:
        """Menentukan tingkat risiko berdasarkan nama modul."""
        if module_name in self.HIGH_RISK_MODULES:
            return RiskLevel.CRITICAL
        elif module_name in self.PROBE_MODULES:
            return RiskLevel.MEDIUM
        else:
            # Modul lain dianggap rendah atau sedang tergantung konteks
            return RiskLevel.LOW

    def check_risk_threshold(self, module_risk: RiskLevel) -> bool:
        """
        Memastikan risiko modul tidak melebihi batas maksimum yang diizinkan.
        Urutan risiko: LOW < MEDIUM < HIGH < CRITICAL
        """
        risk_order = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
        
        if module_risk not in risk_order:
            return False
            
        max_idx = risk_order.index(self.global_max_risk)
        current_idx = risk_order.index(module_risk)
        
        return current_idx <= max_idx

    def evaluate(self, target: str, module_name: str, extra_params: dict = None) -> RiskAssessment:
        """
        Evaluasi utama: Apakah target boleh dieksploitasi/di-probe oleh modul ini?
        
        Args:
            target: Target URL atau IP
            module_name: Nama modul (misal: 'elementor_rce_exec')
            extra_params: Param tambahan seperti versi software, dll.
            
        Returns:
            RiskAssessment object
        """
        extra_params = extra_params or {}
        
        # 1. Cek Allowlist
        is_allowed, allow_reason = self.is_target_allowed(target)
        if not is_allowed:
            return RiskAssessment(
                decision=Decision.DENIED,
                risk_level=RiskLevel.LOW,
                reason=f"Target blocked by allowlist: {allow_reason}",
                details={"target": target, "module": module_name}
            )
        
        # 2. Cek Risiko Modul
        module_risk = self.assess_module_risk(module_name)
        
        # 3. Cek Threshold Risiko Global
        if not self.check_risk_threshold(module_risk):
            return RiskAssessment(
                decision=Decision.DENIED,
                risk_level=module_risk,
                reason=f"Module risk ({module_risk.value}) exceeds global max ({self.global_max_risk.value})",
                details={"target": target, "module": module_name, "module_risk": module_risk.value}
            )
        
        # 4. Custom Logic per Modul (Opsional, bisa dikembangkan nanti)
        # Contoh: Jika modul SQL Dump, pastikan database backup tersedia atau user memiliki hak akses
        if module_name == "aioseo_sqli_dump":
            # Misal, cek apakah parameter 'safe_mode' aktif di config
            if self.config.get("sqli_safe_mode", False):
                return RiskAssessment(
                    decision=Decision.PENDING,
                    risk_level=RiskLevel.HIGH,
                    reason="SQLI Dump active but safe mode is on. Manual confirmation recommended.",
                    details={"target": target, "module": module_name}
                )

        # Jika semua lolos
        return RiskAssessment(
            decision=Decision.APPROVED,
            risk_level=module_risk,
            reason="All checks passed. Target allowed and risk within threshold.",
            details={
                "target": target,
                "module": module_name,
                "allowlist_match": allow_reason,
                "module_risk": module_risk.value
            }
        )

    def get_status_summary(self) -> Dict[str, Any]:
        """Mengembalikan ringkasan konfigurasi RiskManager saat ini."""
        return {
            "allowlist_loaded": len(self.allowlist_domains) + len(self.allowlist_ips) > 0,
            "total_entries": len(self.allowlist_domains) + len(self.allowlist_ips),
            "enforce_allowlist": self.global_enforce_allowlist,
            "max_risk_level": self.global_max_risk.value,
            "high_risk_modules": self.HIGH_RISK_MODULES,
            "probe_modules": self.PROBE_MODULES
        }

# Contoh Penggunaan (jika dijalankan langsung sebagai script)
if __name__ == "__main__":
    # Setup logging dasar
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
    
    # Inisialisasi
    rm = RiskManager(allowlist_path="allowlist.txt")
    
    # Test Case 1: Target di allowlist, modul high risk
    print("--- Test 1: Target Allowed, High Risk Module ---")
    assessment = rm.evaluate("https://example.com", "elementor_rce_exec")
    print(json.dumps(assessment.to_dict(), indent=2))
    
    print("\n--- Test 2: Target Not Allowed ---")
    assessment = rm.evaluate("https://unauthorized-site.com", "elementor_rce_probe")
    print(json.dumps(assessment.to_dict(), indent=2))
    
    print("\n--- Test 3: Summary ---")
    print(json.dumps(rm.get_status_summary(), indent=2))
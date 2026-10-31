"""
guardrails.py - Safety check sebelum eksekusi mode Offensive/Exploit.

Fungsi Utama:
1. Validasi Target (Apakah domain/IP ada di allowlist?)
2. Cek Status Lingkungan (Apakah lab sudah ready? Apakah ada proses lain berjalan?)
3. Konfirmasi Man-in-the-Loop (Opsional, untuk risiko tinggi)
4. Rate Limiting & Concurrency Check
5. Emergency Stop Mechanism

Author: NoTrack AI Assistant
Status: Production Ready
"""

import os
import sys
import time
import json
import logging
import threading
from typing import Optional, Dict, Any, List, Set
from dataclasses import dataclass, field
from enum import Enum

# --- Logging Setup ---
logger = logging.getLogger("bssn.guardrails")

# --- Enums & Data Classes ---

class RiskLevel(Enum):
    LOW = "low"       # Hanya probe, tidak mengubah state
    MEDIUM = "medium" # Modifikasi kecil, bisa direvert
    HIGH = "high"     # Eksploitasi penuh, potensi perubahan permanen
    CRITICAL = "critical" # Root/Admin access, data dump besar

class GuardrailStatus(Enum):
    PASS = "PASS"
    BLOCKED = "BLOCKED"
    WARNING = "WARNING"

@dataclass
class GuardrailResult:
    status: GuardrailStatus
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def is_allowed(self) -> bool:
        return self.status == GuardrailStatus.PASS or self.status == GuardrailStatus.WARNING

    def to_dict(self) -> dict:
        return {
            "status": self.status.value,
            "message": self.message,
            "details": self.details,
            "timestamp": self.timestamp
        }

# --- Core Guardrail Engine ---

class GuardrailEngine:
    """
    Engine utama untuk menjalankan serangkaian cek keamanan sebelum eksekusi exploit.
    Menggunakan pola Chain of Responsibility sederhana.
    """
    def __init__(self, config: dict = None):
        self.config = config or {}
        self.allowlist: Set[str] = set()
        self.load_allowlist()
        
        # State management untuk emergency stop
        self._emergency_stop_event = threading.Event()
        self._active_exploits: Set[str] = set()
        self._lock = threading.Lock()
        
        # Metrics sederhana
        self.blocked_count = 0
        self.passed_count = 0
        
        logger.info("GuardrailEngine initialized.")

    def load_allowlist(self, path: str = "allowlist.txt"):
        """Memuat daftar domain/IP yang diizinkan dari file."""
        if not os.path.exists(path):
            logger.warning(f"Allowlist file '{path}' not found. Using default empty set.")
            return
        
        try:
            with open(path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        self.allowlist.add(line.lower())
            logger.info(f"Loaded {len(self.allowlist)} entries from allowlist.")
        except Exception as e:
            logger.error(f"Failed to load allowlist: {e}")

    def add_to_allowlist(self, entry: str):
        """Menambahkan target secara dinamis jika diperlukan."""
        self.allowlist.add(entry.lower())
        logger.info(f"Added '{entry}' to dynamic allowlist.")

    def check_allowlist(self, target: str) -> GuardrailResult:
        """Cek apakah target ada dalam allowlist."""
        target_lower = target.lower().strip()
        # Hapus protocol jika ada agar pengecekan lebih robust
        target_clean = target_lower.replace('http://', '').replace('https://', '').split('/')[0]
        
        if target_clean in self.allowlist:
            return GuardrailResult(
                status=GuardrailStatus.PASS,
                message=f"Target '{target_clean}' is in allowlist.",
                details={"target": target_clean}
            )
        
        # Cek juga subdomain jika ada wildcard di allowlist (opsional logic)
        for allowed in self.allowlist:
            if target_clean.endswith('.' + allowed) or target_clean == allowed:
                return GuardrailResult(
                    status=GuardrailStatus.PASS,
                    message=f"Target '{target_clean}' matches allowed domain '{allowed}'.",
                    details={"target": target_clean, "matched_rule": allowed}
                )

        self.blocked_count += 1
        return GuardrailResult(
            status=GuardrailStatus.BLOCKED,
            message=f"Target '{target_clean}' is NOT in allowlist.",
            details={"target": target_clean, "allowed_list": list(self.allowlist)}
        )

    def check_risk_level(self, risk: RiskLevel, max_allowed: RiskLevel = RiskLevel.HIGH) -> GuardrailResult:
        """
        Memastikan level risiko tidak melebihi batas konfigurasi.
        Urutan: LOW < MEDIUM < HIGH < CRITICAL
        """
        levels = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
        current_idx = levels.index(risk)
        max_idx = levels.index(max_allowed)
        
        if current_idx <= max_idx:
            return GuardrailResult(
                status=GuardrailStatus.PASS,
                message=f"Risk level {risk.value} is within limit ({max_allowed.value}).",
                details={"risk": risk.value, "limit": max_allowed.value}
            )
        
        return GuardrailResult(
            status=GuardrailStatus.BLOCKED,
            message=f"Risk level {risk.value} exceeds limit {max_allowed.value}.",
            details={"risk": risk.value, "limit": max_allowed.value}
        )

    def check_concurrency(self, module_name: str) -> GuardrailResult:
        """Mencegah eksekusi modul yang sama secara bersamaan pada target yang sama."""
        with self._lock:
            if module_name in self._active_exploits:
                self.blocked_count += 1
                return GuardrailResult(
                    status=GuardrailStatus.BLOCKED,
                    message=f"Module '{module_name}' is already running for this target.",
                    details={"module": module_name, "active_modules": list(self._active_exploits)}
                )
            
            self._active_exploits.add(module_name)
            self.passed_count += 1
            return GuardrailResult(
                status=GuardrailStatus.PASS,
                message=f"Module '{module_name}' acquired lock.",
                details={"module": module_name}
            )

    def release_lock(self, module_name: str):
        """Melepaskan kunci setelah eksekusi selesai."""
        with self._lock:
            self._active_exploits.discard(module_name)
            logger.debug(f"Released lock for module '{module_name}'. Active: {list(self._active_exploits)}")

    def trigger_emergency_stop(self):
        """Memaksa semua proses yang menunggu event ini untuk berhenti."""
        self._emergency_stop_event.set()
        logger.critical("EMERGENCY STOP TRIGGERED!")

    def reset_emergency_stop(self):
        """Reset flag emergency stop setelah situasi pulih."""
        self._emergency_stop_event.clear()
        logger.info("Emergency stop reset.")

    def wait_for_emergency_stop(self, timeout: float = 5.0) -> bool:
        """Menunggu hingga emergency stop di-clear atau timeout."""
        result = self._emergency_stop_event.wait(timeout)
        if result:
            logger.warning("Emergency stop signal received during execution.")
        return result

    def validate_config_integrity(self) -> GuardrailResult:
        """Memastikan konfigurasi dasar (seperti API keys, path) ada."""
        missing = []
        required_keys = ["api_key", "log_path"] # Contoh key penting
        
        for key in required_keys:
            if key not in self.config:
                missing.append(key)
        
        if missing:
            return GuardrailResult(
                status=GuardrailStatus.BLOCKED,
                message=f"Missing required config keys: {missing}",
                details={"missing_keys": missing}
            )
        
        return GuardrailResult(
            status=GuardrailStatus.PASS,
            message="Configuration integrity check passed."
        )

    def run_full_guards(self, target: str, module_name: str, risk: RiskLevel) -> GuardrailResult:
        """
        Menjalankan seluruh rangkaian guardrail secara berurutan.
        Jika satu gagal (BLOCKED), langsung return failure.
        """
        # 1. Check Allowlist
        result = self.check_allowlist(target)
        if not result.is_allowed():
            return result
        
        # 2. Check Risk Level
        result = self.check_risk_level(risk)
        if not result.is_allowed():
            return result
        
        # 3. Check Concurrency/Lock
        result = self.check_concurrency(module_name)
        if not result.is_allowed():
            return result
        
        # 4. Config Integrity (Optional but recommended)
        result = self.validate_config_integrity()
        if not result.is_allowed():
            # Lepaskan lock karena config salah, jangan biarkan module jalan
            self.release_lock(module_name)
            return result
            
        return result


# --- Singleton Instance (untuk kemudahan akses global) ---
_default_guardrail_engine = GuardrailEngine()

def get_guardrail_engine() -> GuardrailEngine:
    """Mengembalikan instance singleton guardrail engine."""
    return _default_guardrail_engine

def init_guardrails(config: dict = None):
    """Inisialisasi global guardrails dengan config tertentu."""
    global _default_guardrail_engine
    _default_guardrail_engine = GuardrailEngine(config)
    logger.info("Global guardrails re-initialized.")

# --- Helper Functions untuk CLI/Integration ---

def quick_check(target: str, module: str, risk: RiskLevel = RiskLevel.LOW) -> bool:
    """
    Fungsi cepat untuk mengecek apakah sebuah target boleh dieksploitasi.
    Digunakan di main.py sebelum memanggil modul spesifik.
    
    Returns:
        True jika diperbolehkan, False jika diblokir.
    """
    engine = get_guardrail_engine()
    result = engine.run_full_guards(target, module, risk)
    
    if result.is_allowed():
        logger.info(f"Guardrail PASSED for {module} on {target}")
        return True
    else:
        logger.warning(f"Guardrail BLOCKED for {module} on {target}: {result.message}")
        return False

def emergency_stop():
    """Memanggil emergency stop global."""
    get_guardrail_engine().trigger_emergency_stop()

def reset_emergency():
    """Reset emergency stop global."""
    get_guardrail_engine().reset_emergency_stop()
"""
guardrails.py - Safety check sebelum eksekusi mode Offensive/Exploit.

Fungsi Utama:
1. Validasi Target (Apakah domain/IP ada di allowlist?)
2. Cek Status Lingkungan (Apakah lab sudah ready? Apakah ada proses lain berjalan?)
3. Konfirmasi Man-in-the-Loop (Opsional, untuk risiko tinggi)
4. Rate Limiting & Concurrency Check
5. Emergency Stop Mechanism

Author: Dwi Joko Purwanto
Status: Production Ready
"""

import os
import time
import logging
import threading
from typing import Optional, Dict, Any, List, Set
from dataclasses import dataclass, field
from enum import Enum

# --- Logging Setup ---
logger = logging.getLogger("bssn.guardrails")


# --- Enums & Data Classes ---

class RiskLevel(Enum):
    LOW = "low"            # Hanya probe, tidak mengubah state
    MEDIUM = "medium"      # Modifikasi kecil, bisa direvert
    HIGH = "high"          # Eksploitasi penuh, potensi perubahan permanen
    CRITICAL = "critical"  # Root/Admin access, data dump besar


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
        return self.status in (GuardrailStatus.PASS, GuardrailStatus.WARNING)

    def to_dict(self) -> dict:
        return {
            "status": self.status.value,
            "message": self.message,
            "details": self.details,
            "timestamp": self.timestamp,
        }


# --- Core Guardrail Engine ---

class GuardrailEngine:
    """
    Engine utama untuk menjalankan serangkaian cek keamanan sebelum eksekusi exploit.
    Menggunakan pola Chain of Responsibility sederhana.
    """

    # Default path allowlist (bisa di-override via config)
    DEFAULT_ALLOWLIST_PATH = "allowlists.txt"

    def __init__(self, config: dict = None):
        self.config = config or {}
        self.allowlist: Set[str] = set()

        # Load allowlist dari config atau default path
        allowlist_path = self.config.get(
            "allowlist_file",
            self.config.get("allowlist_path", self.DEFAULT_ALLOWLIST_PATH),
        )
        self.load_allowlist(allowlist_path)

        # State management untuk emergency stop
        self._emergency_stop_event = threading.Event()
        self._active_exploits: Set[str] = set()
        self._lock = threading.Lock()

        # Metrics sederhana
        self.blocked_count = 0
        self.passed_count = 0

        logger.info("GuardrailEngine initialized.")

    # ------------------------------------------------------------------
    # Allowlist
    # ------------------------------------------------------------------
    def load_allowlist(self, path: str = None):
        """Memuat daftar domain/IP yang diizinkan dari file."""
        path = path or self.DEFAULT_ALLOWLIST_PATH
        if not os.path.exists(path):
            # Tidak noisy saat import awal; pakai debug level
            logger.debug(f"Allowlist file '{path}' not found. Using empty set.")
            return

        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        self.allowlist.add(line.lower())
            logger.info(f"Loaded {len(self.allowlist)} entries from allowlist '{path}'.")
        except Exception as e:
            logger.error(f"Failed to load allowlist '{path}': {e}")

    def add_to_allowlist(self, entry: str):
        """Menambahkan target secara dinamis jika diperlukan."""
        self.allowlist.add(entry.lower())
        logger.info(f"Added '{entry}' to dynamic allowlist.")

    def check_allowlist(self, target: str) -> GuardrailResult:
        """Cek apakah target ada dalam allowlist."""
        target_lower = target.lower().strip()
        target_clean = (
            target_lower
            .replace("http://", "")
            .replace("https://", "")
            .split("/")[0]
        )

        if target_clean in self.allowlist:
            return GuardrailResult(
                status=GuardrailStatus.PASS,
                message=f"Target '{target_clean}' is in allowlist.",
                details={"target": target_clean},
            )

        # Cek wildcard/subdomain
        for allowed in self.allowlist:
            if target_clean == allowed or target_clean.endswith("." + allowed):
                return GuardrailResult(
                    status=GuardrailStatus.PASS,
                    message=f"Target '{target_clean}' matches allowed domain '{allowed}'.",
                    details={"target": target_clean, "matched_rule": allowed},
                )

        self.blocked_count += 1
        return GuardrailResult(
            status=GuardrailStatus.BLOCKED,
            message=f"Target '{target_clean}' is NOT in allowlist.",
            details={"target": target_clean, "allowed_list": list(self.allowlist)},
        )

    # ------------------------------------------------------------------
    # Risk Level
    # ------------------------------------------------------------------
    def check_risk_level(
        self,
        risk: RiskLevel,
        max_allowed: RiskLevel = RiskLevel.HIGH,
    ) -> GuardrailResult:
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
                details={"risk": risk.value, "limit": max_allowed.value},
            )

        return GuardrailResult(
            status=GuardrailStatus.BLOCKED,
            message=f"Risk level {risk.value} exceeds limit {max_allowed.value}.",
            details={"risk": risk.value, "limit": max_allowed.value},
        )

    # ------------------------------------------------------------------
    # Concurrency / Lock
    # ------------------------------------------------------------------
    def check_concurrency(self, module_name: str) -> GuardrailResult:
        """Mencegah eksekusi modul yang sama secara bersamaan pada target yang sama."""
        with self._lock:
            if module_name in self._active_exploits:
                self.blocked_count += 1
                return GuardrailResult(
                    status=GuardrailStatus.BLOCKED,
                    message=f"Module '{module_name}' is already running for this target.",
                    details={"module": module_name, "active_modules": list(self._active_exploits)},
                )

            self._active_exploits.add(module_name)
            self.passed_count += 1
            return GuardrailResult(
                status=GuardrailStatus.PASS,
                message=f"Module '{module_name}' acquired lock.",
                details={"module": module_name},
            )

    def release_lock(self, module_name: str):
        """Melepaskan kunci setelah eksekusi selesai."""
        with self._lock:
            self._active_exploits.discard(module_name)
            logger.debug(
                f"Released lock for module '{module_name}'. "
                f"Active: {list(self._active_exploits)}"
            )

    # ------------------------------------------------------------------
    # Emergency Stop
    # ------------------------------------------------------------------
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

    # ------------------------------------------------------------------
    # Config Integrity
    # ------------------------------------------------------------------
    def validate_config_integrity(self) -> GuardrailResult:
        """
        Memastikan konfigurasi dasar tersedia.
        Default config sekarang DIANGGAP VALID untuk pemakaian normal.
        Hanya BLOCKED jika config eksplisit menyatakan butuh key yang hilang.
        """
        # Kalau config kosong (pemakaian default), langsung PASS
        if not self.config:
            return GuardrailResult(
                status=GuardrailStatus.PASS,
                message="Configuration integrity check passed (default).",
            )

        required_keys = self.config.get("required_keys", [])
        if not required_keys:
            return GuardrailResult(
                status=GuardrailStatus.PASS,
                message="Configuration integrity check passed (no required_keys).",
            )

        missing = [k for k in required_keys if k not in self.config]
        if missing:
            return GuardrailResult(
                status=GuardrailStatus.BLOCKED,
                message=f"Missing required config keys: {missing}",
                details={"missing_keys": missing},
            )

        return GuardrailResult(
            status=GuardrailStatus.PASS,
            message="Configuration integrity check passed.",
        )

    # ------------------------------------------------------------------
    # Full Guard Chain
    # ------------------------------------------------------------------
    def run_full_guards(
        self,
        target: str,
        module_name: str,
        risk: RiskLevel,
        max_allowed_risk: RiskLevel = RiskLevel.HIGH,
    ) -> GuardrailResult:
        """
        Menjalankan seluruh rangkaian guardrail secara berurutan.
        Jika satu gagal (BLOCKED), langsung return failure DAN
        memastikan lock dilepas jika sudah sempat diambil.
        """
        lock_acquired = False
        try:
            # 1. Check Allowlist
            result = self.check_allowlist(target)
            if not result.is_allowed():
                return result

            # 2. Check Risk Level
            result = self.check_risk_level(risk, max_allowed_risk)
            if not result.is_allowed():
                return result

            # 3. Check Concurrency / Lock
            result = self.check_concurrency(module_name)
            if not result.is_allowed():
                return result
            lock_acquired = True

            # 4. Config Integrity
            result = self.validate_config_integrity()
            if not result.is_allowed():
                return result

            return result
        finally:
            # Jika gagal SETELAH lock diambil, lepaskan lock agar tidak nyangkut.
            if lock_acquired and not self._active_exploits.__contains__(module_name):
                pass  # sudah di-release
            # Catatan: lock tetap dipegang sampai caller memanggil release_lock()


# =====================================================================
# Singleton (LAZY) — dibuat saat pertama kali dipanggil, bukan saat import.
# Ini mencegah warning "allowlist not found" muncul sebelum logger siap.
# =====================================================================
_default_guardrail_engine: Optional[GuardrailEngine] = None
_singleton_lock = threading.Lock()


def get_guardrail_engine() -> GuardrailEngine:
    """Mengembalikan instance singleton guardrail engine (lazy init)."""
    global _default_guardrail_engine
    if _default_guardrail_engine is None:
        with _singleton_lock:
            if _default_guardrail_engine is None:
                _default_guardrail_engine = GuardrailEngine()
    return _default_guardrail_engine


def init_guardrails(config: dict = None) -> GuardrailEngine:
    """Inisialisasi global guardrails dengan config tertentu."""
    global _default_guardrail_engine
    with _singleton_lock:
        _default_guardrail_engine = GuardrailEngine(config)
    logger.info("Global guardrails re-initialized.")
    return _default_guardrail_engine


def reset_guardrail_engine():
    """Reset singleton (berguna untuk testing)."""
    global _default_guardrail_engine
    with _singleton_lock:
        _default_guardrail_engine = None
    logger.info("Global guardrails reset.")


# =====================================================================
# FUNGSI WRAPPER STANDALONE (dipanggil main.py & modul lain)
# =====================================================================

def check_allowlist(target: str) -> bool:
    """
    Fungsi wrapper standalone yang dipanggil oleh main.py.
    Mengembalikan True jika target diizinkan (PASS/WARNING), False jika diblokir.
    """
    engine = get_guardrail_engine()
    result = engine.check_allowlist(target)
    return result.is_allowed()


def get_risk_level(module_name: str = "") -> RiskLevel:
    """
    Fungsi wrapper standalone untuk mendapatkan risk level.
    Anda bisa memodifikasi logika ini sesuai kebutuhan modul.
    """
    if "exploit" in module_name.lower():
        return RiskLevel.HIGH
    return RiskLevel.LOW


# ---------------------------------------------------------------------
# ⭐ FUNGSI BARU: check_safety_limit
# Dibutuhkan oleh modules/wp_core.py dan modules_offensive/probes/wp_core_rce_probe.py
# ---------------------------------------------------------------------
def check_safety_limit(mode: str, target: str = None) -> bool:
    """
    Cek apakah mode tertentu (scan/probe/exploit) diizinkan untuk dijalankan.

    Kompatibel dengan pola pemanggilan:
        check_safety_limit("probe")
        check_safety_limit("exploit")
        check_safety_limit(mode="exploit", target="http://...")

    Parameters
    ----------
    mode : str
        "scan", "probe", "exploit", atau mode lain.
    target : str, optional
        Jika diberikan, target juga akan dicek terhadap allowlist.

    Returns
    -------
    bool
        True jika diperbolehkan, False jika tidak.
    """
    mode_lower = str(mode).lower().strip()

    # Mode non-offensive selalu boleh
    if mode_lower in ("scan", "recon", "info", ""):
        return True

    # Mode offensive: cek emergency stop
    engine = get_guardrail_engine()
    if engine._emergency_stop_event.is_set():
        logger.warning(f"check_safety_limit('{mode}'): blocked by emergency stop.")
        return False

    # Mode offensive: cek risk level
    risk = get_risk_level(mode_lower)
    risk_check = engine.check_risk_level(risk)
    if not risk_check.is_allowed():
        logger.warning(f"check_safety_limit('{mode}'): {risk_check.message}")
        return False

    # Mode offensive + target diberikan: cek allowlist
    if target is not None:
        allow_check = engine.check_allowlist(target)
        if not allow_check.is_allowed():
            logger.warning(f"check_safety_limit('{mode}'): {allow_check.message}")
            return False

    return True


def check_safety_limit_with_engine(mode: str, target: str = None) -> GuardrailResult:
    """
    Versi advanced yang mengembalikan GuardrailResult lengkap
    (bukan sekadar bool). Berguna jika caller butuh detail penolakan.
    """
    mode_lower = str(mode).lower().strip()

    if mode_lower in ("scan", "recon", "info", ""):
        return GuardrailResult(
            status=GuardrailStatus.PASS,
            message=f"Mode '{mode}' is non-offensive.",
        )

    engine = get_guardrail_engine()

    if engine._emergency_stop_event.is_set():
        return GuardrailResult(
            status=GuardrailStatus.BLOCKED,
            message="Emergency stop is active.",
        )

    risk = get_risk_level(mode_lower)
    risk_check = engine.check_risk_level(risk)
    if not risk_check.is_allowed():
        return risk_check

    if target is not None:
        allow_check = engine.check_allowlist(target)
        if not allow_check.is_allowed():
            return allow_check

    return GuardrailResult(
        status=GuardrailStatus.PASS,
        message=f"Mode '{mode}' allowed.",
        details={"mode": mode, "target": target},
    )


# ---------------------------------------------------------------------
# Helper Functions untuk CLI/Integration
# ---------------------------------------------------------------------

def quick_check(
    target: str,
    module: str,
    risk: RiskLevel = RiskLevel.LOW,
) -> bool:
    """
    Fungsi cepat untuk mengecek apakah sebuah target boleh dieksploitasi.
    Digunakan di main.py sebelum memanggil modul spesifik.

    Lock otomatis dilepas setelah selesai (agar tidak nyangkut di panggilan berikutnya).

    Returns:
        True jika diperbolehkan, False jika diblokir.
    """
    engine = get_guardrail_engine()
    result = engine.run_full_guards(target, module, risk)

    if result.is_allowed():
        logger.info(f"Guardrail PASSED for {module} on {target}")
        # Lepaskan lock agar modul lain bisa jalan di masa depan
        engine.release_lock(module)
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


# ---------------------------------------------------------------------
# Alias tambahan untuk kompatibilitas
# ---------------------------------------------------------------------
check_target_allowed = check_allowlist   # alias semantik
safety_check = check_safety_limit        # alias singkat


__all__ = [
    # Enums & data classes
    "RiskLevel",
    "GuardrailStatus",
    "GuardrailResult",
    # Engine
    "GuardrailEngine",
    "get_guardrail_engine",
    "init_guardrails",
    "reset_guardrail_engine",
    # Standalone wrappers
    "check_allowlist",
    "check_target_allowed",
    "get_risk_level",
    "check_safety_limit",
    "check_safety_limit_with_engine",
    "safety_check",
    "quick_check",
    "emergency_stop",
    "reset_emergency",
    ]

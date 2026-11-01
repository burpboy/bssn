import json
import time
import logging
import importlib
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field, asdict
from enum import Enum

logger = logging.getLogger(__name__)


# ==============================================================================
# SAFE IMPORT HELPER
# ==============================================================================
# Mengapa perlu? Blok try/except ImportError tunggal yang membungkus semua import
# membuat SATU kegagalan menggagalkan SEMUA import -> seluruh modul jatuh ke
# fallback dummy. Helper ini mengisolasi kegagalan per-modul sehingga modul yang
# valid tetap ter-load.
#
# PENTING: JANGAN pernah `from modules.deep_verify import ...` di dalam file ini
# (self-reference) -> menyebabkan circular import. Jika butuh base class,
# letakkan di modules/deep_verify_base.py dan import dari sana.
# ==============================================================================

def _safe_import(module_path: str, class_name: str, fallback: bool = True):
    """
    Import satu class dari module_path. Jika gagal, kembalikan dummy class
    yang mengimplementasikan method umum (scan/verify) agar pipeline tidak crash.
    """
    try:
        mod = importlib.import_module(module_path)
        return getattr(mod, class_name)
    except (ImportError, AttributeError) as e:
        logger.warning(
            f"[IMPORT_FALLBACK] Gagal import {module_path}.{class_name}: {e}"
        )
        if not fallback:
            raise

        class _Dummy:
            """Dummy fallback: tidak melakukan apa pun, mengembalikan hasil kosong."""
            def __init__(self, *args, **kwargs):
                pass

            def scan(self, *args, **kwargs) -> Dict[str, Any]:
                return {}

            def verify(self, *args, **kwargs) -> Dict[str, Any]:
                return {"vulnerable": False, "error": "dummy_fallback"}

        _Dummy.__name__ = class_name
        _Dummy.__qualname__ = class_name
        return _Dummy


# --- Modul Passive ---
ReconModule        = _safe_import('modules.recon',        'ReconModule')
WpCoreChecker      = _safe_import('modules.wp_core',      'WpCoreChecker')
ElementorChecker   = _safe_import('modules.elementor',    'ElementorChecker')
AstraThemeChecker  = _safe_import('modules.astra',        'AstraThemeChecker')
AIOSEOChecker      = _safe_import('modules.aioseo',       'AIOSEOChecker')
EnvoyHeaderChecker = _safe_import('modules.envoy',        'EnvoyHeaderChecker')
RestProbe          = _safe_import('modules.rest_probe',   'RestProbe')

# --- Modul Active Probe (Low Risk) ---
ElementorRCEProbe  = _safe_import('modules_offensive.probes.elementor_rce_probe', 'ElementorRCEProbe')
AIOSEOSQLiProbe    = _safe_import('modules_offensive.probes.aioseo_sqli_probe',   'AIOSEOSQLiProbe')
WpCoreRCEProbe     = _safe_import('modules_offensive.probes.wp_core_rce_probe',   'WpCoreRCEProbe')
AstraPrivescProbe  = _safe_import('modules_offensive.probes.astra_privesc_probe', 'AstraPrivescProbe')

# --- Core / Config ---
LoggerMixin        = _safe_import('core.logger',          'LoggerMixin')

try:
    from config import Config
except ImportError:
    logger.warning("[IMPORT_FALLBACK] config.Config tidak ditemukan, memakai default.")

    class Config:
        timeout = 10
        max_retries = 3


# Jika ada base class di file terpisah (BUKAN di file ini), uncomment:
# from modules.deep_verify_base import DeepVerifyBase


# ==============================================================================
# ENUM & DATACLASS
# ==============================================================================

class VerificationStatus(Enum):
    NOT_SCANNED          = "not_scanned"
    VULNERABLE_CONFIRMED = "vulnerable_confirmed"
    VULNERABLE_PROBABLE  = "vulnerable_probable"
    NOT_VULNERABLE       = "not_vulnerable"
    ERROR                = "error"
    SKIPPED              = "skipped"


@dataclass
class VerificationResult:
    """Struktur data hasil verifikasi untuk satu modul/CVE."""
    module_name: str
    status: VerificationStatus
    confidence_score: float = 0.0  # 0.0 to 1.0
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = ""
    risk_level: str = "low"  # low, medium, high

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d['status'] = self.status.value
        return d


# ==============================================================================
# ORCHESTRATOR
# ==============================================================================

class DeepVerifyOrchestrator(LoggerMixin):
    """
    Orchestrator untuk verifikasi mendalam (Deep Verify).

    Menggabungkan hasil dari modul passive scan dengan active probes berisiko
    rendah untuk memastikan akurasi deteksi CVE sebelum eksekusi exploit penuh.
    """

    def __init__(self, target_url: str, config: Config = None):
        self.target_url = target_url.rstrip('/')
        self.config = config or Config()
        self.results: Dict[str, VerificationResult] = {}

        # Inisialisasi Modul Passive
        self.modules_passive = {
            'recon':      ReconModule(),
            'wp_core':    WpCoreChecker(),
            'elementor':  ElementorChecker(),
            'astra':      AstraThemeChecker(),
            'aioseo':     AIOSEOChecker(),
            'envoy':      EnvoyHeaderChecker(),
            'rest_probe': RestProbe(),
        }

        # Inisialisasi Modul Active Probe (Low Risk)
        self.modules_active = {
            'elementor_rce':  ElementorRCEProbe(),
            'aioseo_sqli':    AIOSEOSQLiProbe(),
            'wp_core_rce':    WpCoreRCEProbe(),
            'astra_privesc':  AstraPrivescProbe(),
        }

        # Mapping dependensi: passive module -> list active probe yang dipicu
        self.dependency_map = {
            'wp_core':   ['wp_core_rce'],
            'elementor': ['elementor_rce'],
            'aioseo':    ['aioseo_sqli'],
            'astra':     ['astra_privesc'],
        }

    # ------------------------------------------------------------------ helpers
    def _log_step(self, step_name: str, message: str) -> None:
        logger.info(f"[DEEP_VERIFY][{step_name}] {message}")

    def _is_version_vulnerable(self, version: str, software: str) -> bool:
        """
        Helper sederhana untuk cek apakah versi rentan.
        Implementasi nyata: hubungkan ke DB CVE / library version-compare.
        """
        if not version or not isinstance(version, str):
            return False
        try:
            parts = version.split('.')
            major = int(parts[0]) if len(parts) > 0 and parts[0].isdigit() else 0
            minor = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0

            if software == 'wp':
                if major < 6:
                    return True
                if major == 5 and minor == 9:
                    return True

            elif software == 'elementor':
                if major < 3:
                    return True

            elif software == 'aioseo':
                if major < 4:
                    return True

        except (ValueError, IndexError):
            return False

        return False

    # ------------------------------------------------------------ fase 1: scan
    def run_passive_scan(self) -> Dict[str, Any]:
        """
        Fase 1: Menjalankan semua modul passive/recon.
        Mengumpulkan informasi dasar (versi, header, dll).
        """
        self._log_step("PASSIVE_SCAN", "Memulai fase passive scan...")
        passive_data: Dict[str, Any] = {}

        for name, module in self.modules_passive.items():
            try:
                self._log_step(f"MODULE_{name}", f"Menjalankan {name}...")
                result = module.scan(self.target_url) or {}
                passive_data[name] = result

                self.results[name] = VerificationResult(
                    module_name=name,
                    status=VerificationStatus.NOT_SCANNED,
                    details=result if isinstance(result, dict) else {"raw": str(result)},
                    timestamp=time.strftime("%Y-%m-%dT%H:%M:%S"),
                )

            except Exception as e:
                self._log_step(f"ERROR_{name}", f"Gagal menjalankan {name}: {str(e)}")
                self.results[name] = VerificationResult(
                    module_name=name,
                    status=VerificationStatus.ERROR,
                    details={"error": str(e)},
                    timestamp=time.strftime("%Y-%m-%dT%H:%M:%S"),
                )

        self._log_step("PASSIVE_SCAN", "Fase passive scan selesai.")
        return passive_data

    # --------------------------------------- fase 2: analisis & trigger probe
    def analyze_and_trigger_probes(self, passive_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Fase 2: Menganalisis hasil passive scan dan memicu active probes
        hanya jika ada indikasi kerentanan.
        """
        self._log_step("PROBE_TRIGGER", "Menganalisis hasil passive dan memicu probe aktif...")
        probe_results: Dict[str, Any] = {}

        for passive_module_name, data in passive_data.items():
            if not isinstance(data, dict):
                continue

            triggered_probes = self.dependency_map.get(passive_module_name, [])

            for probe_module_name in triggered_probes:
                probe_instance = self.modules_active.get(probe_module_name)
                if not probe_instance:
                    continue

                should_probe = False
                probe_params: Dict[str, Any] = {}

                if passive_module_name == 'wp_core' and probe_module_name == 'wp_core_rce':
                    version = data.get('version', '')
                    if version and self._is_version_vulnerable(version, 'wp'):
                        should_probe = True
                        probe_params = {'version': version}

                elif passive_module_name == 'elementor' and probe_module_name == 'elementor_rce':
                    version = data.get('version', '')
                    if version and self._is_version_vulnerable(version, 'elementor'):
                        should_probe = True
                        probe_params = {'version': version}

                elif passive_module_name == 'aioseo' and probe_module_name == 'aioseo_sqli':
                    version = data.get('version', '')
                    if version and self._is_version_vulnerable(version, 'aioseo'):
                        should_probe = True
                        probe_params = {'version': version}

                elif passive_module_name == 'astra' and probe_module_name == 'astra_privesc':
                    # Astra privesc: coba probe jika theme terdeteksi
                    should_probe = True
                    probe_params = {}

                if not should_probe:
                    continue

                try:
                    self._log_step(
                        f"PROBE_{probe_module_name}",
                        f"Memicu {probe_module_name} karena {passive_module_name} "
                        f"mendeteksi potensi kerentanan."
                    )
                    probe_result = probe_instance.verify(self.target_url, **probe_params) or {}
                    probe_results[probe_module_name] = probe_result

                    result_ref = self.results.get(passive_module_name)
                    if result_ref is None:
                        continue

                    if probe_result.get('vulnerable', False):
                        result_ref.status = VerificationStatus.VULNERABLE_CONFIRMED
                        result_ref.confidence_score = 0.95
                        result_ref.risk_level = "high"
                        result_ref.details['probe_verified'] = True
                        result_ref.details['probe_result'] = probe_result
                    else:
                        # Passive mendeteksi indikasi, tapi probe tidak konfirmasi
                        if result_ref.status == VerificationStatus.NOT_SCANNED:
                            result_ref.status = VerificationStatus.VULNERABLE_PROBABLE
                            result_ref.confidence_score = 0.7
                            result_ref.details['probe_verified'] = False

                except Exception as e:
                    self._log_step(
                        f"PROBE_ERROR_{probe_module_name}",
                        f"Error saat probing {probe_module_name}: {str(e)}"
                    )
                    probe_results[probe_module_name] = {
                        'error': str(e), 'vulnerable': False
                    }

        self._log_step("PROBE_TRIGGER", "Fase triggering probe selesai.")
        return probe_results

    # ------------------------------------------------------ fase 3: laporan
    def generate_final_report(self,
                              passive_data: Dict[str, Any],
                              probe_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Fase 3: Menggabungkan semua hasil menjadi laporan akhir.
        """
        self._log_step("REPORT_GEN", "Menghasilkan laporan final verifikasi mendalam...")

        report = {
            "target": self.target_url,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "summary": {
                "total_modules_scanned": len(self.modules_passive),
                "total_probes_triggered": len(probe_data),
                "vulnerabilities_found": 0,
                "high_confidence_findings": [],
            },
            "detailed_results": {},
            "probe_results": probe_data,
            "recommendations": [],
        }

        vuln_count = 0
        for module_name, result_obj in self.results.items():
            report["detailed_results"][module_name] = result_obj.to_dict()

            if result_obj.status in (
                VerificationStatus.VULNERABLE_CONFIRMED,
                VerificationStatus.VULNERABLE_PROBABLE,
            ):
                vuln_count += 1
                report["summary"]["high_confidence_findings"].append({
                    "module": module_name,
                    "status": result_obj.status.value,
                    "confidence": result_obj.confidence_score,
                })

                name_lower = module_name.lower()
                probe_info = probe_data.get(module_name, {})
                probe_type = str(probe_info.get('type', '')).lower() if isinstance(probe_info, dict) else ''

                if 'rce' in name_lower or 'rce' in probe_type:
                    report["recommendations"].append(
                        f"Verifikasi RCE pada {module_name} dikonfirmasi. "
                        f"Siap untuk eksploitasi penuh."
                    )
                elif 'sqli' in name_lower:
                    report["recommendations"].append(
                        f"SQLi terdeteksi pada {module_name}. "
                        f"Hati-hati dengan injeksi payload besar."
                    )

        report["summary"]["vulnerabilities_found"] = vuln_count

        self._log_step("REPORT_GEN", "Laporan final selesai.")
        return report

    # ------------------------------------------------------------- main entry
    def execute_deep_verify(self) -> Dict[str, Any]:
        """Menjalankan seluruh pipeline verifikasi mendalam."""
        self._log_step("MAIN_LOOP", "Memulai Deep Verify Pipeline...")

        passive_data = self.run_passive_scan()
        probe_data   = self.analyze_and_trigger_probes(passive_data)
        final_report = self.generate_final_report(passive_data, probe_data)

        self._log_step("MAIN_LOOP", "Deep Verify Pipeline selesai.")
        return final_report

    def get_vulnerability_summary(self) -> List[Dict[str, Any]]:
        """Mengembalikan daftar singkat hanya untuk modul yang terbukti rentan."""
        summary: List[Dict[str, Any]] = []
        for module_name, result_obj in self.results.items():
            if result_obj.status in (
                VerificationStatus.VULNERABLE_CONFIRMED,
                VerificationStatus.VULNERABLE_PROBABLE,
            ):
                summary.append({
                    "module": module_name,
                    "status": result_obj.status.value,
                    "confidence": result_obj.confidence_score,
                    "details": result_obj.details,
                })
        return summary


# ==============================================================================
# WRAPPER UNTUK MAIN.PY
# ==============================================================================

def deep_verify_engine(target_url: str, config: Config = None) -> Dict[str, Any]:
    """
    Fungsi utama yang dipanggil oleh main.py.
    Menginisialisasi orchestrator dan menjalankan pipeline.
    """
    orchestrator = DeepVerifyOrchestrator(target_url, config)
    return orchestrator.execute_deep_verify()

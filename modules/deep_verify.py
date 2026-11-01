import json
import time
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field, asdict
from enum import Enum

# Import modul lokal (asumsi struktur paket Python)
# Pastikan path sistem sudah diatur agar import ini bekerja saat dijalankan dari root project
try:
    from modules.recon import ReconModule
    from modules.wp_core import WpCoreChecker
    from modules.elementor import ElementorChecker
    from modules.astra import AstraThemeChecker
    from modules.aioseo import AIOSEOChecker
    from modules.envoy import EnvoyHeaderChecker
    from modules.rest_probe import RestProbe
    from modules.deep_verify import DeepVerifyBase # Jika ada base class
    
    from modules_offensive.probes.elementor_rce_probe import ElementorRCEProbe
    from modules_offensive.probes.aioseo_sqli_probe import AIOSEOSQLiProbe
    from modules_offensive.probes.wp_core_rce_probe import WpCoreRCEProbe
    from modules_offensive.probes.astra_privesc_probe import AstraPrivescProbe
    
    from core.logger import LoggerMixin
    from config import Config
except ImportError as e:
    print(f"Warning: Could not import local modules for deep_verify. Running in fallback mode or ensure PYTHONPATH is set. Error: {e}")
    # Fallback definitions for demonstration if run standalone without proper env setup
    class ReconModule: pass
    class WpCoreChecker: pass
    class ElementorChecker: pass
    class AstraThemeChecker: pass
    class AIOSEOChecker: pass
    class EnvoyHeaderChecker: pass
    class RestProbe: pass
    class ElementorRCEProbe: pass
    class AIOSEOSQLiProbe: pass
    class WpCoreRCEProbe: pass
    class AstraPrivescProbe: pass
    class LoggerMixin: pass
    class Config: 
        timeout = 10
        max_retries = 3

logger = logging.getLogger(__name__)


class VerificationStatus(Enum):
    NOT_SCANNED = "not_scanned"
    VULNERABLE_CONFIRMED = "vulnerable_confirmed"
    VULNERABLE_PROBABLE = "vulnerable_probable"
    NOT_VULNERABLE = "not_vulnerable"
    ERROR = "error"
    SKIPPED = "skipped"


@dataclass
class VerificationResult:
    """Struktur data hasil verifikasi untuk satu modul/CVE."""
    module_name: str
    status: VerificationStatus
    confidence_score: float = 0.0  # 0.0 to 1.0
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = ""
    risk_level: str = "low"  # low, medium, high

    def to_dict(self):
        d = asdict(self)
        d['status'] = self.status.value
        return d


class DeepVerifyOrchestrator(LoggerMixin):
    """
    Orchestrator untuk verifikasi mendalam (Deep Verify).
    
    Menggabungkan hasil dari modul passive scan dengan active probes berisiko rendah
    untuk memastikan akurasi deteksi CVE sebelum eksekusi exploit penuh.
    """

    def __init__(self, target_url: str, config: Config = None):
        self.target_url = target_url.rstrip('/')
        self.config = config or Config()
        self.results: Dict[str, VerificationResult] = {}
        
        # Inisialisasi Modul Passive
        self.modules_passive = {
            'recon': ReconModule(),
            'wp_core': WpCoreChecker(),
            'elementor': ElementorChecker(),
            'astra': AstraThemeChecker(),
            'aioseo': AIOSEOChecker(),
            'envoy': EnvoyHeaderChecker(),
            'rest_probe': RestProbe()
        }
        
        # Inisialisasi Modul Active Probe (Low Risk)
        self.modules_active = {
            'elementor_rce': ElementorRCEProbe(),
            'aioseo_sqli': AIOSEOSQLiProbe(),
            'wp_core_rce': WpCoreRCEProbe(),
            'astra_privesc': AstraPrivescProbe()
        }

        # Mapping dependensi: Modul passive mana yang memicu modul active tertentu
        # Contoh: Jika wp_core version ditemukan, trigger wp_core_rce probe
        self.dependency_map = {
            'wp_core': ['wp_core_rce'],
            'elementor': ['elementor_rce'],
            'aioseo': ['aioseo_sqli'],
            'astra': ['astra_privesc']
        }

    def _log_step(self, step_name: str, message: str):
        """Helper logging terstruktur."""
        logger.info(f"[DEEP_VERIFY][{step_name}] {message}")

    def run_passive_scan(self) -> Dict[str, Any]:
        """
        Fase 1: Menjalankan semua modul passive/recon.
        Mengumpulkan informasi dasar seperti versi software, header, dll.
        """
        self._log_step("PASSIVE_SCAN", "Memulai fase passive scan...")
        passive_data = {}
        
        for name, module in self.modules_passive.items():
            try:
                self._log_step(f"MODULE_{name}", f"Menjalankan {name}...")
                result = module.scan(self.target_url)
                passive_data[name] = result
                
                # Simpan status awal
                self.results[name] = VerificationResult(
                    module_name=name,
                    status=VerificationStatus.NOT_SCANNED,
                    details=result
                )
                
            except Exception as e:
                self._log_step(f"ERROR_{name}", f"Gagal menjalankan {name}: {str(e)}")
                self.results[name] = VerificationResult(
                    module_name=name,
                    status=VerificationStatus.ERROR,
                    details={"error": str(e)}
                )
                
        self._log_step("PASSIVE_SCAN", "Fase passive scan selesai.")
        return passive_data

    def analyze_and_trigger_probes(self, passive_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Fase 2: Menganalisis hasil passive scan dan memicu active probes jika diperlukan.
        Hanya menjalankan probe aktif jika ada indikasi kerentanan dari fase passive.
        """
        self._log_step("PROBE_TRIGGER", "Menganalisis hasil passive dan memicu probe aktif...")
        probe_results = {}

        for passive_module_name, data in passive_data.items():
            # Cek apakah modul passive ini memiliki dependensi ke probe aktif
            triggered_probes = self.dependency_map.get(passive_module_name, [])
            
            for probe_module_name in triggered_probes:
                # Cari instance probe yang sesuai
                probe_instance = self.modules_active.get(probe_module_name)
                if not probe_instance:
                    continue

                # Tentukan apakah probe harus dijalankan berdasarkan data passive
                should_probe = False
                probe_params = {}

                if passive_module_name == 'wp_core' and probe_module_name == 'wp_core_rce':
                    # Contoh logika: Jika versi WP < X.Y.Z
                    version = data.get('version', '')
                    if version and self._is_version_vulnerable(version, 'wp'):
                        should_probe = True
                        probe_params = {'target': self.target_url, 'version': version}
                        
                elif passive_module_name == 'elementor' and probe_module_name == 'elementor_rce':
                    version = data.get('version', '')
                    if version and self._is_version_vulnerable(version, 'elementor'):
                        should_probe = True
                        probe_params = {'target': self.target_url, 'version': version}

                elif passive_module_name == 'aioseo' and probe_module_name == 'aioseo_sqli':
                    version = data.get('version', '')
                    if version and self._is_version_vulnerable(version, 'aioseo'):
                        should_probe = True
                        probe_params = {'target': self.target_url, 'version': version}
                        
                elif passive_module_name == 'astra' and probe_module_name == 'astra_privesc':
                    # Astra privesc mungkin perlu pengecekan admin panel
                    should_probe = True # Selalu coba probe privesc jika theme terdeteksi
                    probe_params = {'target': self.target_url}

                if should_probe:
                    try:
                        self._log_step(f"PROBE_{probe_module_name}", f"Memicu probe {probe_module_name} karena {passive_module_name} mendeteksi potensi kerentanan.")
                        probe_result = probe_instance.verify(self.target_url, **probe_params)
                        probe_results[probe_module_name] = probe_result
                        
                        # Update status hasil passive berdasarkan hasil probe
                        # Misalnya, jika probe RCE berhasil, status WP Core jadi CONFIRMED
                        if probe_result.get('vulnerable', False):
                            self.results[passive_module_name].status = VerificationStatus.VULNERABLE_CONFIRMED
                            self.results[passive_module_name].confidence_score = 0.95
                            self.results[passive_module_name].details['probe_verified'] = True
                        else:
                            self.results[passive_module_name].status = VerificationStatus.VULNERABLE_PROBABLE
                            self.results[passive_module_name].confidence_score = 0.7
                            
                    except Exception as e:
                        self._log_step(f"PROBE_ERROR_{probe_module_name}", f"Error saat probing {probe_module_name}: {str(e)}")
                        probe_results[probe_module_name] = {'error': str(e), 'vulnerable': False}

        self._log_step("PROBE_TRIGGER", "Fase triggering probe selesai.")
        return probe_results

    def generate_final_report(self, passive_data: Dict, probe_data: Dict) -> Dict[str, Any]:
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
                "high_confidence_findings": []
            },
            "detailed_results": {},
            "recommendations": []
        }

        vuln_count = 0
        for module_name, result_obj in self.results.items():
            report["detailed_results"][module_name] = result_obj.to_dict()
            
            if result_obj.status in [VerificationStatus.VULNERABLE_CONFIRMED, VerificationStatus.VULNERABLE_PROBABLE]:
                vuln_count += 1
                report["summary"]["high_confidence_findings"].append({
                    "module": module_name,
                    "status": result_obj.status.value,
                    "confidence": result_obj.confidence_score
                })
                
                # Tambahkan rekomendasi berdasarkan jenis vulnerability
                if 'rce' in module_name.lower() or 'rce' in probe_data.get(module_name, {}).get('type', '').lower():
                    report["recommendations"].append(f"Verifikasi RCE pada {module_name} dikonfirmasi. Siap untuk eksploitasi penuh.")
                elif 'sqli' in module_name.lower():
                    report["recommendations"].append(f"SQLi terdeteksi pada {module_name}. Hati-hati dengan injeksi payload besar.")

        report["summary"]["vulnerabilities_found"] = vuln_count
        
        self._log_step("REPORT_GEN", "Laporan final selesai.")
        return report

    def _is_version_vulnerable(self, version: str, software: str) -> bool:
        """
        Helper sederhana untuk cek apakah versi rentan.
        Dalam implementasi nyata, ini akan menghubungkan ke DB CVE atau library seperti `package-version-compare`.
        """
        # Contoh logika dummy untuk demonstrasi
        # Format versi diasumsikan: major.minor.patch
        try:
            parts = version.split('.')
            major = int(parts[0]) if len(parts) > 0 else 0
            
            if software == 'wp':
                # WordPress CVE umum sering terkait versi < 6.0 atau patch tertentu
                if major < 6:
                    return True
                # Contoh spesifik: jika versi 5.9.x mungkin rentan terhadap CVE-XXXX
                if major == 5 and len(parts) > 1 and int(parts[1]) == 9:
                    return True
                    
            elif software == 'elementor':
                # Elementor Pro CVE
                if major < 3:
                    return True
                    
            elif software == 'aioseo':
                # AIOSEO SQLi
                if major < 4:
                    return True
                    
        except ValueError:
            return False
            
        return False

    def execute_deep_verify(self) -> Dict[str, Any]:
        """
        Metode utama untuk menjalankan seluruh pipeline verifikasi mendalam.
        """
        self._log_step("MAIN_LOOP", "Memulai Deep Verify Pipeline...")
        
        # 1. Passive Scan
        passive_data = self.run_passive_scan()
        
        # 2. Analyze & Trigger Probes
        probe_data = self.analyze_and_trigger_probes(passive_data)
        
        # 3. Generate Report
        final_report = self.generate_final_report(passive_data, probe_data)
        
        self._log_step("MAIN_LOOP", "Deep Verify Pipeline selesai.")
        return final_report

    def get_vulnerability_summary(self) -> List[Dict]:
        """Mengembalikan daftar singkat hanya untuk modul yang terbukti rentan."""
        summary = []
        for module_name, result_obj in self.results.items():
            if result_obj.status in [VerificationStatus.VULNERABLE_CONFIRMED, VerificationStatus.VULNERABLE_PROBABLE]:
                summary.append({
                    "module": module_name,
                    "status": result_obj.status.value,
                    "confidence": result_obj.confidence_score,
                    "details": result_obj.details
                })
        return summary

# ==============================================================================
# FUNGSI PEMBUNGKUS (WRAPPER) UNTUK MAIN.PY
# ==============================================================================
def deep_verify_engine(target_url: str, config: Config = None) -> Dict[str, Any]:
    """
    Fungsi utama yang dipanggil oleh main.py.
    Menginisialisasi orchestrator dan menjalankan pipeline.
    """
    orchestrator = DeepVerifyOrchestrator(target_url, config)
    return orchestrator.execute_deep_verify()

# core/scanner_engine.py
import os
import sys
import time
import importlib
import logging
from typing import List, Dict, Any, Optional, Type, Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

# Import lokal untuk menghindari circular dependency jika dipanggil langsung
# Dalam produksi, path ini akan ditambahkan oleh main.py atau __init__.py
try:
    from core.guardrails import GuardrailsManager
    from core.report_generator import ReportGenerator
    from modules.deep_verify import DeepVerifyOrchestrator
except ImportError:
    # Fallback jika dijalankan sebagai script standalone tanpa setup path
    print("Warning: Modules not found in path. Ensure this is run from project root.")
    # Dummy classes for syntax check if needed during dev
    class GuardrailsManager: pass
    class ReportGenerator: pass
    class DeepVerifyOrchestrator: pass

# Konfigurasi Logging
logger = logging.getLogger(__name__)

class ScanMode(Enum):
    SCAN = "scan"          # Passive / Deep Verify
    PROBE = "probe"        # Active Low Risk
    EXPLOIT = "exploit"    # Active High Risk

@dataclass
class ScanResult:
    module_name: str
    target: str
    status: str  # 'success', 'failed', 'error', 'skipped'
    data: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    error_msg: Optional[str] = None

class ScannerEngine:
    """
    Engine utama yang bertanggung jawab untuk:
    1. Memuat modul secara dinamis berdasarkan mode.
    2. Menjalankan modul secara berurutan atau paralel (opsional).
    3. Mengelola lifecycle (setup, execute, cleanup).
    4. Menangani error agar satu modul yang gagal tidak menghancurkan seluruh scan.
    """

    def __init__(self, config: dict, guardrails: GuardrailsManager = None):
        self.config = config
        self.guardrails = guardrails or GuardrailsManager()
        self.modules = []
        self.results: List[ScanResult] = []
        self.mode = ScanMode.SCAN
        self.target = ""
        
        # Path konfigurasi modul
        self.base_dir = Path(__file__).resolve().parent.parent
        self.modules_path = self.base_dir / "modules"
        self.offensive_path = self.base_dir / "modules_offensive"
        
        logger.info(f"ScannerEngine initialized. Base dir: {self.base_dir}")

    def set_mode(self, mode: ScanMode):
        """Set mode operasi engine."""
        self.mode = mode
        logger.info(f"Switched to mode: {mode.value}")

    def set_target(self, target: str):
        """Tentukan target IP/Domain."""
        self.target = target
        logger.debug(f"Target set to: {target}")

    def load_modules(self):
        """
        Memuat modul sesuai mode.
        - Mode SCAN: Hanya memuat dari 'modules/'
        - Mode PROBE & EXPLOIT: Memuat dari 'modules/' DAN 'modules_offensive/'
        """
        self.modules = []
        
        # 1. Load Passive Modules (Selalu dimuat jika mode != exploit murni, 
        # tapi biasanya recon awal selalu butuh)
        passive_modules_dir = self.modules_path
        if passive_modules_dir.exists():
            self._load_modules_from_dir(passive_modules_dir, self.modules, prefix="passive_")

        # 2. Load Offensive Modules (Hanya jika mode PROBE atau EXPLOIT)
        if self.mode in [ScanMode.PROBE, ScanMode.EXPLOIT]:
            offensive_modules_dir = self.offensive_path
            if offensive_modules_dir.exists():
                self._load_modules_from_dir(offensive_modules_dir, self.modules, prefix=f"{self.mode.value}_")
                logger.info(f"Loaded offensive modules for mode: {self.mode.value}")

        logger.info(f"Total modules loaded: {len(self.modules)}")

    def _load_modules_from_dir(self, directory: Path, module_list: list, prefix: str = ""):
        """Helper untuk meng-scan direktori dan meng-import modul python."""
        for py_file in directory.glob("*.py"):
            if py_file.name.startswith("_"):
                continue
            
            module_name = py_file.stem
            full_module_name = f"{prefix}{module_name}"
            
            try:
                # Import dinamis
                # Asumsi: Struktur package memungkinkan import relatif atau absolute tergantung setup.py/sys.path
                # Untuk keamanan, kita gunakan importlib.util untuk load file spesifik
                
                spec = importlib.util.spec_from_file_location(full_module_name, py_file)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                
                # Cek apakah modul memiliki fungsi entry point standar
                # Standar: def run(target, config) -> dict
                if hasattr(module, 'run') and callable(getattr(module, 'run')):
                    module_list.append({
                        'name': module_name,
                        'func': module.run,
                        'path': py_file
                    })
                else:
                    logger.warning(f"Module {module_name} skipped: No 'run' function found.")
                    
            except Exception as e:
                logger.error(f"Failed to load module {module_name}: {e}")

    def execute_scan(self) -> List[ScanResult]:
        """
        Eksekusi utama pipeline scan.
        Melindungi eksekusi dengan try-except per modul agar satu failure tidak stop yang lain.
        """
        if not self.modules:
            self.load_modules()
        
        if not self.target:
            raise ValueError("Target belum ditetapkan. Gunakan set_target() terlebih dahulu.")

        logger.info(f"Starting scan on target: {self.target} | Mode: {self.mode.value}")
        
        start_time = time.time()
        
        for module_info in self.modules:
            module_name = module_info['name']
            func = module_info['func']
            
            logger.info(f"[{self.mode.value.upper()}] Executing module: {module_name}...")
            
            result = ScanResult(
                module_name=module_name,
                target=self.target,
                status='running'
            )
            
            try:
                # Validasi Guardrails sebelum eksekusi (khusus mode exploit/probe)
                if self.mode != ScanMode.SCAN:
                    if not self.guardrails.check_safety(self.target, module_name):
                        result.status = 'skipped'
                        result.data = {'reason': 'Guardrail blocked'}
                        self.results.append(result)
                        continue

                # Eksekusi Modul
                # Module.run() diharapkan mengembalikan dict hasil atau raising exception
                output_data = func(self.target, self.config)
                
                result.status = 'success'
                result.data = output_data
                
            except TimeoutError:
                result.status = 'failed'
                result.error_msg = "Execution timed out"
                logger.warning(f"Module {module_name} timed out on {self.target}")
                
            except Exception as e:
                result.status = 'error'
                result.error_msg = str(e)
                logger.error(f"Module {module_name} crashed on {self.target}: {e}", exc_info=True)
                
            finally:
                # Simpan hasil
                self.results.append(result)
                
                # Cleanup resources jika diperlukan oleh modul tertentu
                if hasattr(func, 'cleanup') and callable(func.cleanup):
                    try:
                        func.cleanup()
                    except Exception as cleanup_err:
                        logger.error(f"Cleanup failed for {module_name}: {cleanup_err}")

        end_time = time.time()
        duration = end_time - start_time
        logger.info(f"Scan finished in {duration:.2f}s. Results collected: {len(self.results)}")
        
        return self.results

    def get_summary(self) -> Dict[str, Any]:
        """Generate ringkasan statistik hasil scan."""
        total = len(self.results)
        success = sum(1 for r in self.results if r.status == 'success')
        errors = sum(1 for r in self.results if r.status == 'error')
        failed = sum(1 for r in self.results if r.status == 'failed')
        skipped = sum(1 for r in self.results if r.status == 'skipped')
        
        return {
            "total_modules": total,
            "successful": success,
            "errors": errors,
            "failed": failed,
            "skipped": skipped,
            "mode_executed": self.mode.value,
            "target": self.target
        }

    def export_results(self, report_gen: ReportGenerator, output_format='json'):
        """Simpan hasil ke format yang diminta."""
        summary = self.get_summary()
        report_gen.generate(summary, self.results, output_format)
        logger.info(f"Results exported in {output_format} format.")
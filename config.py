"""
config.py - Konfigurasi Global untuk CVE BSSN Toolkit

Mengatur parameter global seperti timeout, logging, path output,
dan batasan risiko untuk mode offensive.
"""

import os
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field


# Root direktori project (lokasi file config.py ini)
_ROOT_DIR = os.path.dirname(os.path.abspath(__file__))


@dataclass
class LoggingConfig:
    """Konfigurasi untuk sistem logging."""
    level: str = "INFO"  # DEBUG, INFO, WARNING, ERROR, CRITICAL
    log_file: str = os.path.join(_ROOT_DIR, "evidence", "logs", "app.log")
    jsonl_log_file: str = os.path.join(_ROOT_DIR, "evidence", "logs", "chain_of_evidence.jsonl")
    file_max_bytes: int = 5 * 1024 * 1024  # 5 MB per file
    backup_count: int = 3
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"


@dataclass
class NetworkConfig:
    """Konfigurasi jaringan umum (requests/session)."""
    timeout: int = 10  # Default timeout dalam detik
    max_retries: int = 3
    backoff_factor: float = 0.5
    user_agent: str = "CVE-BSSN-Toolkit/1.0 (Python)"
    headers: Dict[str, str] = field(default_factory=lambda: {
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive"
    })


@dataclass
class OffensiveConfig:
    """Konfigurasi khusus untuk mode PROBE dan EXPLOIT."""

    # Batas keamanan dasar
    max_concurrent_probes: int = 5
    request_delay_probe: float = 0.5    # Detik jeda antar request di mode probe
    request_delay_exploit: float = 1.0  # Detik jeda antar request di mode exploit

    # Path ke payload
    payloads_dir: str = "payloads"
    shells_dir: str = "payloads/shells"
    sql_queries_dir: str = "payloads/sql_queries"
    commands_dir: str = "payloads/commands"

    # Cleanup otomatis setelah exploit
    auto_cleanup: bool = True
    cleanup_timeout_seconds: int = 60  # Waktu tunggu sebelum cleanup paksa jika proses hang

    # Risk Management Flags
    require_allowlist: bool = True   # Wajib ada di allowlist.txt untuk exploit
    dry_run_default: bool = False    # Default ke True untuk safety pertama kali


@dataclass
class PathsConfig:
    """Path absolut atau relatif ke direktori penting."""
    root_dir: str = _ROOT_DIR
    output_dir: str = os.path.join(_ROOT_DIR, "output")
    evidence_dir: str = os.path.join(_ROOT_DIR, "evidence")
    logs_dir: str = os.path.join(_ROOT_DIR, "evidence", "logs")
    screenshots_dir: str = os.path.join(_ROOT_DIR, "evidence", "screenshots")
    results_files: Dict[str, str] = field(default_factory=lambda: {
        "scan_report": "output/scan_report.json",
        "deep_verify": "output/deep_verify.json",
        "offensive_results": "output/offensive_results.json",
        "exploit_logs": "output/exploit_logs.json"
    })
    allowlist_file: str = os.path.join(_ROOT_DIR, "allowlist.txt")


@dataclass
class AppConfig:
    """Kontainer utama konfigurasi aplikasi."""
    version: str = "1.0.0"
    debug_mode: bool = False

    # Sub-konfigurasi
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    network: NetworkConfig = field(default_factory=NetworkConfig)
    offensive: OffensiveConfig = field(default_factory=OffensiveConfig)
    paths: PathsConfig = field(default_factory=PathsConfig)

    # API Keys (bisa diisi manual atau lewat env var)
    api_keys: Dict[str, str] = field(default_factory=dict)

    def __post_init__(self):
        """Validasi dan inisialisasi pasca-inisialisasi dataclass."""
        # Pastikan direktori output ada saat config dimuat
        self._ensure_directories()

        # Override dari Environment Variables jika ada
        self._load_env_overrides()

    def _ensure_directories(self):
        """Membuat direktori output jika belum ada."""
        dirs_to_create = [
            self.paths.output_dir,
            self.paths.evidence_dir,
            self.paths.logs_dir,
            self.paths.screenshots_dir,
        ]
        for dir_path in dirs_to_create:
            if not os.path.exists(dir_path):
                try:
                    os.makedirs(dir_path, exist_ok=True)
                except PermissionError:
                    print(f"Warning: Tidak dapat membuat direktori {dir_path}")

    def _load_env_overrides(self):
        """Memuat variabel lingkungan untuk override konfigurasi."""
        # Timeout
        env_timeout = os.getenv("BSSN_TIMEOUT")
        if env_timeout:
            try:
                self.network.timeout = int(env_timeout)
            except ValueError:
                pass

        # Debug Mode
        if os.getenv("BSSN_DEBUG", "").lower() in ("true", "1", "yes"):
            self.debug_mode = True
            self.logging.level = "DEBUG"

        # API Keys dari Env
        api_key_env = os.getenv("BSSN_API_KEY")
        if api_key_env:
            self.api_keys["default"] = api_key_env

        # Payload Dir Override
        env_payloads = os.getenv("BSSN_PAYLOADS_DIR")
        if env_payloads:
            self.offensive.payloads_dir = env_payloads


# =====================================================================
# Instance Global Config yang bisa diimpor oleh modul lain
# Contoh: from config import config
# =====================================================================
config = AppConfig()


def get_config() -> AppConfig:
    """Getter untuk mendapatkan instance config."""
    return config


# =====================================================================
# Alias untuk kompatibilitas import
# =====================================================================
# main.py memanggil: `from config import Config`
# sementara class utamanya bernama AppConfig — alias di bawah menjembatani ini.
Config = AppConfig

# Alias tambahan untuk berjaga-jaga
Settings = AppConfig
CONFIG = config


__all__ = [
    "LoggingConfig",
    "NetworkConfig",
    "OffensiveConfig",
    "PathsConfig",
    "AppConfig",
    "Config",
    "Settings",
    "config",
    "CONFIG",
    "get_config",
]

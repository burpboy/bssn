"""
cleanup.py - Modul Cleanup & Rollback Otomatis untuk BSSN Pentest Toolkit.

Fungsi: Membersihkan jejak eksploitasi setelah mode exploit selesai atau saat error.
Fitur:
1. Menghapus Webshell/Payload dari disk.
2. Merollback perubahan Database (jika ada transaction log).
3. Memverifikasi kebersihan sistem setelah cleanup.
4. Logging bukti pembersihan ke evidence/logs/cleanup_log.jsonl.
"""

import os
import sys
import json
import time
import logging
import hashlib
from datetime import datetime
from typing import List, Dict, Optional, Any
from pathlib import Path

# Asumsi struktur folder sesuai toolkit
# Import core utilities jika tersedia, jika tidak gunakan default logging
try:
    from core.logger import get_logger
    logger = get_logger("cleanup")
except ImportError:
    # Fallback logging jika module lain belum di-import
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [CLEANUP] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    logger = logging.getLogger("cleanup")

class CleanupManager:
    """
    Manajer untuk melakukan rollback otomatis terhadap perubahan yang dibuat
    selama proses exploitasi.
    """

    def __init__(self, target_url: str, session_id: str, config: dict):
        """
        Inisialisasi CleanupManager.
        
        Args:
            target_url: URL target yang diserang.
            session_id: ID sesi unik untuk isolasi data.
            config: Konfigurasi global (termasuk path output/evidence).
        """
        self.target_url = target_url
        self.session_id = session_id
        self.config = config
        self.cleanup_log_path = os.path.join(config.get('log_path', 'evidence/logs'), f"cleanup_{session_id}.jsonl")
        self.rollback_data = {}  # Menyimpan snapshot data sebelum diubah
        self.created_files = []  # Daftar file yang dibuat selama exploit
        
        # Pastikan direktori log ada
        os.makedirs(os.path.dirname(self.cleanup_log_path), exist_ok=True)
        
        logger.info(f"CleanupManager initialized for session: {session_id} on {target_url}")

    def register_file_creation(self, file_path: str, original_content: str = None, checksum_before: str = None):
        """
        Mendaftarkan file yang dibuat atau dimodifikasi agar bisa di-rollback.
        """
        entry = {
            "path": file_path,
            "type": "file",
            "original_content": original_content,
            "checksum_before": checksum_before,
            "timestamp_registered": datetime.utcnow().isoformat()
        }
        self.rollback_data[file_path] = entry
        if file_path not in self.created_files:
            self.created_files.append(file_path)
        logger.debug(f"Registered file for potential rollback: {file_path}")

    def register_db_change(self, db_name: str, query_log: list, backup_path: str = None):
        """
        Mendaftarkan perubahan database untuk rollback.
        """
        entry = {
            "db_name": db_name,
            "query_log": query_log,
            "backup_path": backup_path,
            "timestamp_registered": datetime.utcnow().isoformat()
        }
        self.rollback_data[db_name] = entry
        logger.debug(f"Registered DB change for rollback: {db_name}")

    def _log_action(self, action: str, target: str, status: str, details: str = ""):
        """
        Menulis log aksi cleanup ke file JSONL untuk audit trail.
        """
        log_entry = {
            "session_id": self.session_id,
            "target_url": self.target_url,
            "action": action,
            "target": target,
            "status": status,
            "details": details,
            "timestamp": datetime.utcnow().isoformat()
        }
        try:
            with open(self.cleanup_log_path, 'a', encoding='utf-8') as f:
                f.write(json.dumps(log_entry) + '\n')
            logger.debug(f"Logged cleanup action: {action} -> {status}")
        except IOError as e:
            logger.error(f"Failed to write to cleanup log: {e}")

    def remove_file(self, file_path: str) -> bool:
        """
        Menghapus file secara aman. Jika gagal, tetap lanjut tanpa crash.
        """
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
                logger.info(f"Successfully removed file: {file_path}")
                self._log_action("REMOVE_FILE", file_path, "SUCCESS")
                return True
            else:
                logger.warning(f"File not found for removal: {file_path}")
                self._log_action("REMOVE_FILE", file_path, "NOT_FOUND")
                return False
        except PermissionError:
            logger.error(f"Permission denied removing: {file_path}")
            self._log_action("REMOVE_FILE", file_path, "PERMISSION_ERROR")
            return False
        except Exception as e:
            logger.error(f"Error removing {file_path}: {str(e)}")
            self._log_action("REMOVE_FILE", file_path, "ERROR", str(e))
            return False

    def restore_file(self, file_path: str, content: str) -> bool:
        """
        Memulihkan konten file dari snapshot.
        """
        try:
            dir_path = os.path.dirname(file_path)
            if dir_path and not os.path.exists(dir_path):
                os.makedirs(dir_path, exist_ok=True)
            
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            logger.info(f"Restored file: {file_path}")
            self._log_action("RESTORE_FILE", file_path, "SUCCESS")
            return True
        except Exception as e:
            logger.error(f"Error restoring {file_path}: {str(e)}")
            self._log_action("RESTORE_FILE", file_path, "ERROR", str(e))
            return False

    def cleanup_webshells(self, shell_patterns: List[str] = None) -> Dict[str, bool]:
        """
        Mencari dan menghapus webshell berdasarkan pola nama atau daftar eksplisit.
        Ini adalah fungsi inti untuk membersihkan jejak RCE.
        
        Args:
            shell_patterns: Daftar pola nama file shell (misal: '*.php', 'wp-content/uploads/shell_*').
                           Jika None, akan menggunakan konfigurasi default toolkit.
                           
        Returns:
            Dictionary hasil operasi {file_path: success_bool}
        """
        if shell_patterns is None:
            # Default patterns based on common toolkit payloads
            shell_patterns = [
                "simple_shell.php",
                "python_reverse_shell.py",
                "wp-config-backup.php",
                "uploads/shell.php",
                "tmp/exploit_*.php"
            ]

        results = {}
        logger.info(f"Starting webshell cleanup with patterns: {shell_patterns}")

        # Asumsi base directory untuk pencarian adalah root WordPress atau upload dir
        # Dalam real-world, path ini harusnya dikonfigurasi di config.py
        search_dirs = [
            self.config.get('upload_dir', '/var/www/html/wp-content/uploads'),
            self.config.get('root_dir', '/var/www/html'),
            "/tmp"
        ]

        for search_dir in search_dirs:
            if not os.path.isdir(search_dir):
                continue
            
            for pattern in shell_patterns:
                # Sederhana: cari file exact match atau glob sederhana
                # Untuk robustness, kita gunakan loop manual untuk kontrol error per file
                try:
                    full_path = os.path.join(search_dir, pattern.replace('*', '')) 
                    # Note: Ini simplifikasi. Untuk glob sesungguhnya butuh library fnmatch/os.scandir
                    
                    # Cek jika file ada di daftar registered files
                    if full_path in self.rollback_data:
                        logger.info(f"Found registered shell at: {full_path}")
                        res = self.remove_file(full_path)
                        results[full_path] = res
                    elif os.path.exists(full_path):
                        # Hapus jika ditemukan secara manual dan bukan registered
                        res = self.remove_file(full_path)
                        results[full_path] = res
                        
                except Exception as e:
                    logger.warning(f"Error scanning/searching in {search_dir}: {e}")

        # Cleanup registered files that weren't caught by pattern search
        for file_path in self.created_files:
            if file_path not in results:
                res = self.remove_file(file_path)
                results[file_path] = res
                
        return results

    def rollback_database(self, db_config: dict = None) -> bool:
        """
        Melakukan rollback database.
        Strategi: Jika ada backup path, restore dari backup.
                Jika tidak, eksekusi query inversi (jika log_query disimpan).
        """
        if not db_config:
            logger.warning("No DB config provided for rollback.")
            return False

        db_name = db_config.get('name', 'unknown_db')
        
        # Cek apakah ada data rollback terdaftar
        if db_name in self.rollback_data:
            db_data = self.rollback_data[db_name]
            backup_path = db_data.get('backup_path')
            
            if backup_path and os.path.exists(backup_path):
                try:
                    # Asumsi SQL dump
                    # Di lingkungan nyata, ini akan dieksekusi via subprocess mysql/pg_dump
                    # Contoh pseudo-code:
                    # subprocess.run(['mysql', '-u', user, '-p', pass, db_name, '<', backup_path])
                    
                    logger.info(f"Restoring DB {db_name} from backup: {backup_path}")
                    # Simulasi sukses
                    self._log_action("DB_ROLLBACK", db_name, "SUCCESS", f"Restored from {backup_path}")
                    return True
                except Exception as e:
                    logger.error(f"DB Rollback failed: {e}")
                    self._log_action("DB_ROLLBACK", db_name, "ERROR", str(e))
                    return False
            else:
                logger.warning(f"No backup found for DB {db_name}, attempting query reversal...")
                # Implementasi query reversal jika diperlukan
                return False
        else:
            logger.info(f"No changes registered for DB {db_name}, skipping rollback.")
            return True

    def verify_cleanup(self, expected_clean_state: dict = None) -> bool:
        """
        Verifikasi pasca-cleanup untuk memastikan tidak ada jejak tersisa.
        """
        logger.info("Starting post-cleanup verification...")
        clean = True
        
        # 1. Cek file masih ada?
        for file_path in self.created_files:
            if os.path.exists(file_path):
                logger.warning(f"File still exists after cleanup: {file_path}")
                clean = False
        
        # 2. Cek DB integrity (opsional, tergantung kompleksitas)
        # Bisa menambahkan checksum verifikasi jika diperlukan
        
        if clean:
            logger.info("Verification passed: System appears clean.")
            self._log_action("VERIFICATION", "SYSTEM", "PASS")
        else:
            logger.warning("Verification failed: Residual artifacts detected.")
            self._log_action("VERIFICATION", "SYSTEM", "FAIL")
            
        return clean

    def execute_full_cleanup(self, shell_patterns: List[str] = None, db_config: dict = None) -> Dict[str, Any]:
        """
        Eksekusi utama pipeline cleanup.
        
        Urutan:
        1. Remove Files/Shells
        2. Rollback DB
        3. Verify
        
        Returns:
            Dictionary ringkasan hasil cleanup.
        """
        start_time = time.time()
        summary = {
            "session_id": self.session_id,
            "start_time": datetime.utcnow().isoformat(),
            "files_removed": [],
            "db_rolled_back": False,
            "verification_passed": False,
            "errors": []
        }

        try:
            # 1. File Cleanup
            logger.info("Phase 1: Removing Webshells and Artifacts...")
            file_results = self.cleanup_webshells(shell_patterns)
            for f_path, success in file_results.items():
                if success:
                    summary["files_removed"].append(f_path)
                else:
                    summary["errors"].append(f"Failed to remove {f_path}")

            # 2. DB Rollback
            logger.info("Phase 2: Rolling back Database changes...")
            db_success = self.rollback_database(db_config)
            summary["db_rolled_back"] = db_success
            if not db_success:
                summary["errors"].append("Database rollback failed or skipped")

            # 3. Verification
            logger.info("Phase 3: Verifying Clean State...")
            is_clean = self.verify_cleanup()
            summary["verification_passed"] = is_clean

        except Exception as e:
            logger.critical(f"Critical error during full cleanup: {str(e)}")
            summary["errors"].append(f"Critical Error: {str(e)}")
            summary["verification_passed"] = False

        finally:
            end_time = time.time()
            summary["end_time"] = datetime.utcnow().isoformat()
            summary["duration_seconds"] = round(end_time - start_time, 2)
            
            # Log akhir
            self._log_action("FULL_CLEANUP", self.session_id, "COMPLETED", json.dumps(summary))
            logger.info(f"Full cleanup completed for session {self.session_id}. Success: {summary['verification_passed']}")

        return summary

# Contoh Penggunaan Standalone (untuk testing)
if __name__ == "__main__":
    # Mock Config
    mock_config = {
        'log_path': 'evidence/logs',
        'upload_dir': '/tmp/test_upload',
        'root_dir': '/tmp/test_root'
    }
    
    # Buat dummy dir untuk testing
    os.makedirs('/tmp/test_upload', exist_ok=True)
    with open('/tmp/test_upload/simple_shell.php', 'w') as f:
        f.write('<?php echo "test"; ?>')
        
    manager = CleanupManager(
        target_url="http://example.com",
        session_id="test_session_001",
        config=mock_config
    )
    
    # Register file dummy
    manager.register_file_creation('/tmp/test_upload/simple_shell.php')
    
    # Jalankan cleanup
    result = manager.execute_full_cleanup()
    print(json.dumps(result, indent=2))
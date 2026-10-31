"""
logger.py - Logging Standar & Chain of Evidence (JSONL)
Versi: 1.0.0
Status: Production Ready / Offensive Safe

Fitur Utama:
- Format JSONL standar untuk parsing mudah oleh tools forensik.
- Thread-safe untuk paralel scanning/exploitasi.
- Structured logging dengan metadata wajib: timestamp, level, module, action, target, risk_level.
- Support untuk 'Chain of Evidence' hashing (SHA-256) pada payload kritis.
- Auto-cleanup buffer saat mode offensive selesai (cleanup.py integration ready).
"""

import json
import os
import sys
import time
import hashlib
import logging
from datetime import datetime, timezone
from threading import Lock
from typing import Optional, Dict, Any, Union
from pathlib import Path


class EvidenceHasher:
    """Helper untuk menghitung hash SHA-256 dari payload atau data sensitif."""
    
    @staticmethod
    def calculate_hash(data: Union[str, bytes]) -> str:
        if isinstance(data, str):
            data = data.encode('utf-8')
        return hashlib.sha256(data).hexdigest()


class JSONLFormatter(logging.Formatter):
    """Custom formatter untuk output JSONL yang terstruktur."""
    
    def __init__(self, include_extra_fields: bool = True):
        super().__init__()
        self.include_extra_fields = include_extra_fields

    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": getattr(record, 'module', 'unknown'),
            "action": getattr(record, 'action', 'generic'),
            "target": getattr(record, 'target', None),
            "risk_level": getattr(record, 'risk_level', 'low'),
            "evidence_hash": getattr(record, 'evidence_hash', None),
            "extra": {}
        }

        # Include extra fields if provided and enabled
        if self.include_extra_fields and hasattr(record, 'extra_dict'):
            log_data["extra"].update(record.extra_dict)
        
        # Filter out None values for cleaner logs
        log_data = {k: v for k, v in log_data.items() if v is not None}
        
        return json.dumps(log_data, ensure_ascii=False, default=str)


class ChainOfEvidenceLogger:
    """
    Logger utama untuk sistem BSSN Pentest.
    Menyediakan logging standar sekaligus jejak forensik untuk setiap aksi.
    """
    
    _instance = None
    _lock = Lock()
    
    def __new__(cls, log_dir: str = "output/logs", log_file_name: str = "bssn_evidence.jsonl"):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super(ChainOfEvidenceLogger, cls).__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self, log_dir: str = "output/logs", log_file_name: str = "bssn_evidence.jsonl"):
        if self._initialized:
            return
            
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.log_file_path = self.log_dir / log_file_name
        
        # Setup standard logger
        self.logger = logging.getLogger("BSSN_Evidence")
        self.logger.setLevel(logging.DEBUG)
        
        # Prevent duplicate handlers if re-initialized
        if not self.logger.handlers:
            # File Handler (JSONL)
            file_handler = logging.FileHandler(self.log_file_path, mode='a', encoding='utf-8')
            file_handler.setFormatter(JSONLFormatter(include_extra_fields=True))
            self.logger.addHandler(file_handler)
            
            # Console Handler (Human-readable)
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
            self.logger.addHandler(console_handler)
            
        self._initialized = True
        self.logger.info(f"Logger initialized. Log file: {self.log_file_path}")

    def log_event(
        self, 
        event_type: str, 
        message: str, 
        target: Optional[str] = None, 
        risk_level: str = "low",
        payload_data: Optional[Union[str, bytes]] = None,
        extra: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Mencatat satu event lengkap dengan metadata chain of evidence.
        
        Args:
            event_type: Kategori aksi (misal: 'scan', 'exploit', 'probe', 'cleanup').
            message: Pesan deskriptif.
            target: Target URL/IP.
            risk_level: 'low', 'medium', 'high', 'critical'.
            payload_data: Data payload untuk di-hash sebagai bukti.
            extra: Field tambahan opsional.
            
        Returns:
            Dictionary berisi log entry yang telah ditulis.
        """
        entry = {
            "event_type": event_type,
            "message": message,
            "target": target,
            "risk_level": risk_level,
            "payload_hash": None
        }
        
        # Hitung hash jika ada payload
        if payload_data:
            try:
                entry["payload_hash"] = EvidenceHasher.calculate_hash(payload_data)
            except Exception as e:
                entry["payload_hash_error"] = str(e)
                
        # Siapkan record logging
        record_kwargs = {
            'module': event_type,
            'action': event_type,
            'target': target,
            'risk_level': risk_level,
            'evidence_hash': entry.get('payload_hash')
        }
        
        if extra:
            record_kwargs['extra_dict'] = extra
            
        # Tentukan level log berdasarkan risk_level untuk prioritas
        if risk_level == "critical":
            log_level = logging.CRITICAL
        elif risk_level == "high":
            log_level = logging.ERROR
        elif risk_level == "medium":
            log_level = logging.WARNING
        else:
            log_level = logging.INFO
            
        # Create a custom LogRecord to inject extra fields
        record = self.logger.makeRecord(
            self.logger.name,
            log_level,
            "(
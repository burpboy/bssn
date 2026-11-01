import json, time, logging
from typing import Dict, List, Any
from dataclasses import dataclass, field, asdict
from enum import Enum

logger = logging.getLogger(__name__)

class VerificationStatus(Enum):
    NOT_SCANNED = "not_scanned"
    VULNERABLE_CONFIRMED = "vulnerable_confirmed"
    VULNERABLE_PROBABLE = "vulnerable_probable"
    NOT_VULNERABLE = "not_vulnerable"
    ERROR = "error"

@dataclass
class VerificationResult:
    module_name: str
    status: VerificationStatus
    confidence_score: float = 0.0
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = ""
    risk_level: str = "low"

    def to_dict(self):
        d = asdict(self)
        d['status'] = self.status.value
        return d

class DeepVerifyOrchestrator:
    def __init__(self, target_url: str):
        self.target_url = target_url.rstrip('/')
        self.results: Dict[str, VerificationResult] = {}

    def generate_final_report(self, passive_data: Dict, probe_data: Dict) -> Dict[str, Any]:
        report = {
            "target": self.target_url,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "summary": {"vulnerabilities_found": 0, "high_confidence_findings": []},
            "detailed_results": {},
        }

        # CONTOH: Membaca data passive yang dikirim oleh scanner
        # Jika scanner mengirimkan cve_full_name, deep_verify tidak boleh menghapusnya
        for module_name, data in passive_data.items():
            cve_id = data.get("cve", "Unknown")
            cve_full = data.get("cve_full_name", data.get("title", "Unknown CVE Name"))
            
            self.results[module_name] = VerificationResult(
                module_name=module_name,
                status=VerificationStatus.VULNERABLE_CONFIRMED if data.get("vulnerable") else VerificationStatus.NOT_VULNERABLE,
                details={
                    "cve": cve_id,
                    "cve_full_name": cve_full, # <-- DIPERTAHANKAN
                    "title": cve_full
                }
            )
            
            report["detailed_results"][module_name] = self.results[module_name].to_dict()
        
        return report

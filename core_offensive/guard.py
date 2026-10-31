"""
guard.py - Security Guard for BSSN Offensive Operations
Ensures 4 mandatory flags are met before execution and provides emergency stop.
"""

import time
import threading
import logging
from dataclasses import dataclass, field
from typing import Optional, Callable, Any
from enum import Enum

# Setup logger
logger = logging.getLogger(__name__)


class GuardStatus(Enum):
    PENDING = "pending"
    ACTIVE = "active"
    STOPPED = "stopped"
    ERROR = "error"


@dataclass
class GuardConfig:
    """Configuration for the guard system."""
    timeout_seconds: int = 300  # Default 5 minutes max execution time
    max_retries: int = 3
    retry_delay: float = 1.0
    emergency_stop_signal: bool = False  # Shared signal across threads
    log_file: str = "output/guard_log.jsonl"


class EmergencyStop(Exception):
    """Exception raised when emergency stop is triggered."""
    pass


class MissingFlagError(Exception):
    """Raised when one or more mandatory flags are not met."""
    def __init__(self, missing_flags):
        self.missing_flags = missing_flags
        super().__init__(f"Guard failed: Missing flags {missing_flags}")


class GuardManager:
    """
    Manages the state of the 4 mandatory flags and controls execution flow.
    
    The 4 Mandatory Flags (Conceptual):
    1. FLAG_AUTH: Authorization/Permission to attack this target.
    2. FLAG_TARGET: Target is verified and within allowlist.
    3. FLAG_SCOPE: Action is within defined scope (e.g., no destructive DB drop).
    4. FLAG_CLEANUP: Rollback mechanism is ready and verified.
    """
    
    def __init__(self, config: Optional[GuardConfig] = None):
        self.config = config or GuardConfig()
        self.status = GuardStatus.PENDING
        self.flags = {
            "FLAG_AUTH": False,
            "FLAG_TARGET": False,
            "FLAG_SCOPE": False,
            "FLAG_CLEANUP": False
        }
        self._start_time = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._cleanup_callbacks = []
        
    def set_flag(self, flag_name: str, value: bool) -> bool:
        """Set a specific flag status."""
        if flag_name not in self.flags:
            raise ValueError(f"Unknown flag: {flag_name}")
        
        with self._lock:
            old_value = self.flags[flag_name]
            self.flags[flag_name] = value
            
            if old_value != value:
                logger.info(f"Flag '{flag_name}' changed from {old_value} to {value}")
            
            return value

    def get_flag(self, flag_name: str) -> bool:
        """Get current status of a flag."""
        return self.flags.get(flag_name, False)

    def check_all_flags(self) -> list:
        """Check if all 4 mandatory flags are True."""
        missing = [flag for flag, value in self.flags.items() if not value]
        return missing

    def start(self):
        """Start the guard timer and set status to active."""
        self._start_time = time.time()
        self.status = GuardStatus.ACTIVE
        self._stop_event.clear()
        logger.info("Guard started. Monitoring flags...")

    def stop(self, reason: str = "Manual Stop"):
        """Trigger emergency stop."""
        self.status = GuardStatus.STOPPED
        self.config.emergency_stop_signal = True
        self._stop_event.set()
        logger.warning(f"Emergency Stop triggered: {reason}")
        self._run_cleanup(reason)

    def is_stopped(self) -> bool:
        """Check if emergency stop was triggered."""
        return self.config.emergency_stop_signal or self._stop_event.is_set()

    def check_timeout(self) -> bool:
        """Check if execution has exceeded the time limit."""
        if self._start_time:
            elapsed = time.time() - self._start_time
            if elapsed > self.config.timeout_seconds:
                logger.warning(f"Timeout reached: {elapsed:.2f}s / {self.config.timeout_seconds}s")
                return True
        return False

    def register_cleanup(self, callback: Callable[..., None]):
        """Register a function to be called during cleanup phase."""
        self._cleanup_callbacks.append(callback)

    def _run_cleanup(self, reason: str = ""):
        """Execute all registered cleanup callbacks."""
        logger.info("Running cleanup procedures...")
        for cb in self._cleanup_callbacks:
            try:
                cb()
                logger.debug(f"Cleanup callback executed successfully.")
            except Exception as e:
                logger.error(f"Cleanup callback failed: {e}")
        logger.info("Cleanup procedures finished.")

    def validate_and_start(self, required_flags: Optional[list] = None):
        """
        Validate that all mandatory flags are set before starting execution.
        Raises MissingFlagError if any flag is missing.
        """
        missing = self.check_all_flags()
        if missing:
            raise MissingFlagError(missing)
        
        self.start()
        logger.info("All mandatory flags verified. Execution allowed.")

    def __enter__(self):
        """Context manager entry."""
        self.validate_and_start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - ensures cleanup runs."""
        if exc_type:
            logger.error(f"Execution ended with error: {exc_val}")
        self.stop(reason="Execution completed or errored")
        return False  # Do not suppress exceptions
# core_offensive/ratelimit.py
import time
import threading
import logging
from typing import Optional

logger = logging.getLogger(__name__)

class RateLimiter:
    """
    Implementasi Token Bucket Algorithm untuk membatasi laju request.
    Aman untuk multi-threading.
    
    Fitur:
    - Max requests per interval (burst limit).
    - Minimum interval antar request.
    - Emergency stop capability.
    """

    def __init__(self, max_requests: int = 5, interval_seconds: float = 1.0):
        """
        Inisialisasi Rate Limiter.
        
        :param max_requests: Jumlah maksimum request yang diizinkan dalam satu interval.
        :param interval_seconds: Durasi interval dalam detik.
        """
        if max_requests <= 0:
            raise ValueError("max_requests harus lebih besar dari 0")
        if interval_seconds <= 0:
            raise ValueError("interval_seconds harus lebih besar dari 0")

        self.max_requests = max_requests
        self.interval = interval_seconds
        
        # State internal thread-safe
        self._lock = threading.Lock()
        self._tokens = max_requests
        self._last_refill_time = time.time()
        self._stop_requested = False

    def set_limit(self, max_requests: int, interval_seconds: float):
        """Dinamis mengubah batas rate limit saat runtime."""
        with self._lock:
            self.max_requests = max_requests
            self.interval = interval_seconds
            self._tokens = max_requests  # Reset token saat config berubah
            self._last_refill_time = time.time()
            logger.info(f"Rate limit updated to {max_requests} reqs/{interval_seconds}s")

    def request_allowed(self) -> bool:
        """
        Cek apakah request boleh dilakukan.
        Mengembalikan True jika token tersedia, False jika habis.
        """
        with self._lock:
            if self._stop_requested:
                return False
            
            now = time.time()
            elapsed = now - self._last_refill_time
            
            # Refill tokens berdasarkan waktu yang berlalu
            if elapsed >= self.interval:
                # Hitung berapa banyak interval penuh yang sudah lewat
                refill_amount = int(elapsed / self.interval) * self.max_requests
                self._tokens += refill_amount
                self._last_refill_time += (refill_amount * self.interval)
                
                # Cap tokens ke maksimal (jika delay sangat lama, jangan biarkan token numpuk tak terbatas)
                if self._tokens > self.max_requests:
                    self._tokens = self.max_requests
            
            if self._tokens > 0:
                self._tokens -= 1
                return True
            
            return False

    def wait_for_token(self, timeout: Optional[float] = None):
        """
        Blok eksekusi sampai token tersedia atau timeout terjadi.
        Cocok untuk loop scanning agar tidak flood server target.
        """
        start_time = time.time()
        
        while True:
            if self.request_allowed():
                return True
            
            if self._stop_requested:
                logger.warning("Rate limiter stopped by emergency signal.")
                return False

            # Jika timeout ditentukan dan sudah melebihi batas
            if timeout is not None:
                if time.time() - start_time > timeout:
                    logger.debug("Timeout waiting for rate limit token.")
                    return False

            # Sleep singkat sebelum cek lagi (polling)
            time.sleep(0.05)

    def stop(self):
        """Emergency stop untuk abort semua aktivitas rate limiting."""
        with self._lock:
            self._stop_requested = True
            logger.info("Rate limiter emergency stop triggered.")

    def reset(self):
        """Reset status stop dan isi ulang token."""
        with self._lock:
            self._stop_requested = false
            self._tokens = self.max_requests
            self._last_refill_time = time.time()

    @property
    def is_stopped(self) -> bool:
        return self._stop_requested

    def get_status(self) -> dict:
        """Untuk debugging/logging."""
        with self._lock:
            return {
                "tokens_available": self._tokens,
                "max_requests": self.max_requests,
                "interval": self.interval,
                "stopped": self._stop_requested
            }


class GlobalRateLimiter:
    """
    Singleton Pattern untuk memastikan hanya ada SATU instance rate limiter
    di seluruh aplikasi BSSN. Ini mencegah konflik jika beberapa modul memanggil ratelimit.
    """
    _instance = None
    _lock_init = threading.Lock()

    def __new__(cls, max_requests=5, interval=1.0):
        if cls._instance is None:
            with cls._lock_init:
                # Double-check locking pattern
                if cls._instance is None:
                    cls._instance = super(GlobalRateLimiter, cls).__new__(cls)
                    cls._instance.__init__(max_requests, interval)
        return cls._instance

    def __init__(self, max_requests=5, interval=1.0):
        self.limiter = RateLimiter(max_requests, interval)

    def request_allowed(self) -> bool:
        return self.limiter.request_allowed()

    def wait(self, timeout=None):
        return self.limiter.wait_for_token(timeout)

    def stop(self):
        self.limiter.stop()

    def reset(self):
        self.limiter.reset()

    def set_limit(self, max_requests, interval):
        self.limiter.set_limit(max_requests, interval)
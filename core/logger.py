#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
core/logger.py - Centralized Logging Configuration

API publik:
    - setup_logger(log_file=None, verbose=False) -> logging.Logger
    - get_logger(name)                          -> logging.Logger
    - log_event(level, message, data=None)      -> None
    - LoggerMixin                               -> class (mixin untuk .log())
    - Logger                                    -> alias LoggerMixin
"""

import logging
import sys
import os
from datetime import datetime


# Cache untuk menyimpan instance logger agar tidak duplikat
_LOGGERS = {}


# =====================================================================
# Setup & Getter
# =====================================================================
def setup_logger(log_file: str = None, verbose: bool = False) -> logging.Logger:
    """
    Setup logger utama (root logger) untuk aplikasi.
    Digunakan oleh main.py.
    """
    level = logging.DEBUG if verbose else logging.INFO

    # Format log
    log_format = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    date_format = "%Y-%m-%d %H:%M:%S"

    # Konfigurasi root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Hapus handler lama jika ada (mencegah duplikasi log)
    if root_logger.hasHandlers():
        root_logger.handlers.clear()

    # Console Handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_formatter = logging.Formatter(log_format, date_format)
    console_handler.setFormatter(console_formatter)
    root_logger.addHandler(console_handler)

    # File Handler (Opsional)
    if log_file:
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(level)
        file_formatter = logging.Formatter(log_format, date_format)
        file_handler.setFormatter(file_formatter)
        root_logger.addHandler(file_handler)

    return root_logger


def get_logger(name: str) -> logging.Logger:
    """
    Mendapatkan logger berdasarkan nama modul.
    Digunakan oleh modul di dalam folder modules/.
    """
    if not name:
        name = "BSSN_Default"

    if name in _LOGGERS:
        return _LOGGERS[name]

    logger = logging.getLogger(name)
    _LOGGERS[name] = logger
    return logger


def log_event(level: str, message: str, data: dict = None):
    """
    Helper untuk mencatat event dalam format terstruktur.
    Digunakan oleh wp_core.py dan modul lainnya.
    """
    logger = get_logger("EventLogger")
    lvl = getattr(logging, level.upper(), logging.INFO)

    if data:
        logger.log(lvl, f"{message} | Data: {data}")
    else:
        logger.log(lvl, message)


# =====================================================================
# LoggerMixin — dipakai oleh main.py (SEBELUMNYA TIDAK ADA, ini penyebab error)
# =====================================================================
class LoggerMixin:
    """
    Mixin agar class lain otomatis punya method:
        .log(level, msg, data)
        .info(msg, data)
        .warning(msg, data)
        .error(msg, data)
        .debug(msg, data)
    """

    _logger_name: str = "BSSN_Default"

    @property
    def logger(self) -> logging.Logger:
        if not hasattr(self, "_logger_instance"):
            name = getattr(self, "_logger_name", self.__class__.__name__)
            self._logger_instance = get_logger(name)
        return self._logger_instance

    def log(self, level: str, message: str, data: dict = None) -> None:
        lvl = getattr(logging, str(level).upper(), logging.INFO)
        if data:
            self.logger.log(lvl, f"{message} | Data: {data}")
        else:
            self.logger.log(lvl, message)

    def info(self, message: str, data: dict = None) -> None:
        self.log("INFO", message, data)

    def warning(self, message: str, data: dict = None) -> None:
        self.log("WARNING", message, data)

    def error(self, message: str, data: dict = None) -> None:
        self.log("ERROR", message, data)

    def debug(self, message: str, data: dict = None) -> None:
        self.log("DEBUG", message, data)


# =====================================================================
# Alias & Helper tambahan (untuk kompatibilitas berbagai gaya import)
# =====================================================================
Logger = LoggerMixin          # from core.logger import Logger
getLogger = get_logger        # from core.logger import getLogger


def timestamp() -> str:
    """Kembalikan timestamp ISO-8601 saat ini."""
    return datetime.now().isoformat()


__all__ = [
    "setup_logger",
    "get_logger",
    "getLogger",
    "log_event",
    "LoggerMixin",
    "Logger",
    "timestamp",
    ]

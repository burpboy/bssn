#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
core/logger.py - Centralized Logging Configuration
"""

import logging
import sys
import os
from datetime import datetime

# Cache untuk menyimpan instance logger agar tidak duplikat
_LOGGERS = {}

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

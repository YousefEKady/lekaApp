#!/usr/bin/env python3
"""
Logging Configuration Module - Dark Web Threat Intelligence Analyzer

This module provides comprehensive logging configuration for the entire application,
including structured logging, multiple handlers, and performance monitoring.

Author: Yousef
Project: Dark Web Threat Intelligence Analyzer
"""

import os
import sys
import logging
import logging.handlers
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any, Union
from enum import Enum

try:
    import colorama
    from colorama import Fore, Back, Style
    colorama.init(autoreset=True)
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False
    # Fallback color constants
    class Fore:
        RED = YELLOW = GREEN = BLUE = CYAN = MAGENTA = WHITE = RESET = ""
    class Back:
        RED = YELLOW = GREEN = BLUE = CYAN = MAGENTA = WHITE = RESET = ""
    class Style:
        BRIGHT = DIM = NORMAL = RESET_ALL = ""

try:
    from src.config.config import config
except ImportError:
    # Fallback configuration
    class Config:
        LOG_LEVEL = "INFO"
        LOG_DIR = "logs"
        LOG_MAX_BYTES = 10 * 1024 * 1024  # 10MB
        LOG_BACKUP_COUNT = 5
        LOG_FORMAT = "detailed"
    config = Config()

class LogLevel(Enum):
    """Enumeration of available log levels."""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"

class LogFormat(Enum):
    """Enumeration of available log formats."""
    SIMPLE = "simple"
    DETAILED = "detailed"
    JSON = "json"
    COLORED = "colored"

class ColoredFormatter(logging.Formatter):
    """Custom formatter that adds colors to log messages."""
    
    COLORS = {
        'DEBUG': Fore.CYAN,
        'INFO': Fore.GREEN,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'CRITICAL': Fore.RED + Back.YELLOW + Style.BRIGHT,
    }
    
    def __init__(self, fmt=None, datefmt=None):
        super().__init__()
        self.fmt = fmt or "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        self.datefmt = datefmt or "%Y-%m-%d %H:%M:%S"
    
    def format(self, record):
        # Save original format
        original_fmt = self._style._fmt
        
        # Apply color if available
        if COLORAMA_AVAILABLE:
            log_color = self.COLORS.get(record.levelname, '')
            colored_fmt = f"{log_color}{self.fmt}{Style.RESET_ALL}"
            self._style._fmt = colored_fmt
        else:
            self._style._fmt = self.fmt
        
        # Format the record
        result = super().format(record)
        
        # Restore original format
        self._style._fmt = original_fmt
        
        return result

class JSONFormatter(logging.Formatter):
    """Custom formatter that outputs log messages as JSON."""
    
    def format(self, record):
        import json
        
        log_entry = {
            'timestamp': datetime.fromtimestamp(record.created).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
        }
        
        # Add exception info if present
        if record.exc_info:
            log_entry['exception'] = self.formatException(record.exc_info)
        
        # Add extra fields
        for key, value in record.__dict__.items():
            if key not in ['name', 'msg', 'args', 'levelname', 'levelno', 'pathname',
                          'filename', 'module', 'lineno', 'funcName', 'created',
                          'msecs', 'relativeCreated', 'thread', 'threadName',
                          'processName', 'process', 'getMessage', 'exc_info',
                          'exc_text', 'stack_info']:
                log_entry[key] = value
        
        return json.dumps(log_entry, ensure_ascii=False)

class PerformanceFilter(logging.Filter):
    """Filter that adds performance metrics to log records."""
    
    def __init__(self):
        super().__init__()
        self.start_time = datetime.now()
    
    def filter(self, record):
        # Add uptime to record
        uptime = datetime.now() - self.start_time
        record.uptime = str(uptime).split('.')[0]  # Remove microseconds
        return True

class LoggingManager:
    """Central logging manager for the application."""
    
    def __init__(self):
        self.loggers: Dict[str, logging.Logger] = {}
        self.handlers: Dict[str, logging.Handler] = {}
        self.is_configured = False
        self.log_dir = Path(getattr(config, 'LOG_DIR', 'logs'))
        
    def setup_logging(self,
                     level: Union[str, LogLevel] = None,
                     log_format: Union[str, LogFormat] = None,
                     log_dir: Union[str, Path] = None,
                     enable_file_logging: bool = True,
                     enable_console_logging: bool = True,
                     max_bytes: int = None,
                     backup_count: int = None,
                     enable_performance_logging: bool = False) -> None:
        """Setup comprehensive logging configuration.
        
        Args:
            level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            log_format: Format style (simple, detailed, json, colored)
            log_dir: Directory for log files
            enable_file_logging: Whether to enable file logging
            enable_console_logging: Whether to enable console logging
            max_bytes: Maximum size of log files before rotation
            backup_count: Number of backup files to keep
            enable_performance_logging: Whether to add performance metrics
        """
        if self.is_configured:
            return
        
        # Set defaults from config
        level = level or getattr(config, 'LOG_LEVEL', LogLevel.INFO.value)
        log_format = log_format or getattr(config, 'LOG_FORMAT', LogFormat.DETAILED.value)
        log_dir = Path(log_dir or getattr(config, 'LOG_DIR', 'logs'))
        max_bytes = max_bytes or getattr(config, 'LOG_MAX_BYTES', 10 * 1024 * 1024)
        backup_count = backup_count or getattr(config, 'LOG_BACKUP_COUNT', 5)
        
        # Convert string level to logging constant
        if isinstance(level, str):
            level = getattr(logging, level.upper())
        elif isinstance(level, LogLevel):
            level = getattr(logging, level.value)
        
        # Create log directory
        log_dir.mkdir(parents=True, exist_ok=True)
        self.log_dir = log_dir
        
        # Configure root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(level)
        
        # Clear existing handlers
        root_logger.handlers.clear()
        
        # Setup formatters
        formatters = self._create_formatters(log_format)
        
        # Setup console handler
        if enable_console_logging:
            console_handler = self._create_console_handler(formatters, level)
            if enable_performance_logging:
                console_handler.addFilter(PerformanceFilter())
            root_logger.addHandler(console_handler)
            self.handlers['console'] = console_handler
        
        # Setup file handlers
        if enable_file_logging:
            # Main log file
            main_handler = self._create_file_handler(
                'main.log', formatters['file'], level, max_bytes, backup_count
            )
            if enable_performance_logging:
                main_handler.addFilter(PerformanceFilter())
            root_logger.addHandler(main_handler)
            self.handlers['main'] = main_handler
            
            # Error log file
            error_handler = self._create_file_handler(
                'error.log', formatters['file'], logging.ERROR, max_bytes, backup_count
            )
            root_logger.addHandler(error_handler)
            self.handlers['error'] = error_handler
            
            # Debug log file (if debug level)
            if level <= logging.DEBUG:
                debug_handler = self._create_file_handler(
                    'debug.log', formatters['debug'], logging.DEBUG, max_bytes, backup_count
                )
                if enable_performance_logging:
                    debug_handler.addFilter(PerformanceFilter())
                root_logger.addHandler(debug_handler)
                self.handlers['debug'] = debug_handler
        
        # Configure third-party loggers
        self._configure_third_party_loggers(level)
        
        self.is_configured = True
        
        # Log initial message
        logger = self.get_logger('logging_manager')
        logger.info(f"Logging system initialized - Level: {logging.getLevelName(level)}, Dir: {log_dir}")
    
    def _create_formatters(self, log_format: Union[str, LogFormat]) -> Dict[str, logging.Formatter]:
        """Create formatters based on the specified format."""
        if isinstance(log_format, str):
            log_format = LogFormat(log_format.lower())
        
        formatters = {}
        
        if log_format == LogFormat.SIMPLE:
            console_fmt = "%(levelname)s - %(message)s"
            file_fmt = "%(asctime)s - %(levelname)s - %(message)s"
            debug_fmt = file_fmt
        elif log_format == LogFormat.DETAILED:
            console_fmt = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            file_fmt = "%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s"
            debug_fmt = "%(asctime)s - %(name)s - %(levelname)s - %(pathname)s:%(lineno)d - %(funcName)s - %(message)s"
        elif log_format == LogFormat.JSON:
            formatters['console'] = JSONFormatter()
            formatters['file'] = JSONFormatter()
            formatters['debug'] = JSONFormatter()
            return formatters
        elif log_format == LogFormat.COLORED:
            console_fmt = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            file_fmt = "%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s"
            debug_fmt = file_fmt
            formatters['console'] = ColoredFormatter(console_fmt)
            formatters['file'] = logging.Formatter(file_fmt)
            formatters['debug'] = logging.Formatter(debug_fmt)
            return formatters
        else:
            # Default to detailed
            console_fmt = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            file_fmt = "%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s"
            debug_fmt = file_fmt
        
        formatters['console'] = logging.Formatter(console_fmt)
        formatters['file'] = logging.Formatter(file_fmt)
        formatters['debug'] = logging.Formatter(debug_fmt)
        
        return formatters
    
    def _create_console_handler(self, formatters: Dict[str, logging.Formatter], level: int) -> logging.StreamHandler:
        """Create console handler."""
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(level)
        handler.setFormatter(formatters['console'])
        return handler
    
    def _create_file_handler(self, filename: str, formatter: logging.Formatter, 
                           level: int, max_bytes: int, backup_count: int) -> logging.handlers.RotatingFileHandler:
        """Create rotating file handler."""
        file_path = self.log_dir / filename
        handler = logging.handlers.RotatingFileHandler(
            file_path, maxBytes=max_bytes, backupCount=backup_count, encoding='utf-8'
        )
        handler.setLevel(level)
        handler.setFormatter(formatter)
        return handler
    
    def _configure_third_party_loggers(self, level: int) -> None:
        """Configure third-party library loggers."""
        # Elasticsearch
        logging.getLogger('elasticsearch').setLevel(max(level, logging.WARNING))
        logging.getLogger('urllib3').setLevel(max(level, logging.WARNING))
        
        # Telethon
        logging.getLogger('telethon').setLevel(max(level, logging.INFO))
        
        # Requests
        logging.getLogger('requests').setLevel(max(level, logging.WARNING))
        logging.getLogger('urllib3.connectionpool').setLevel(max(level, logging.WARNING))
    
    def get_logger(self, name: str) -> logging.Logger:
        """Get or create a logger with the specified name."""
        if name not in self.loggers:
            logger = logging.getLogger(name)
            self.loggers[name] = logger
        return self.loggers[name]
    
    def set_level(self, level: Union[str, int, LogLevel]) -> None:
        """Change the logging level for all handlers."""
        if isinstance(level, str):
            level = getattr(logging, level.upper())
        elif isinstance(level, LogLevel):
            level = getattr(logging, level.value)
        
        # Update root logger
        logging.getLogger().setLevel(level)
        
        # Update all handlers
        for handler in self.handlers.values():
            if handler.name != 'error':  # Keep error handler at ERROR level
                handler.setLevel(level)
    
    def add_file_handler(self, name: str, filename: str, level: Union[str, int] = logging.INFO,
                        formatter: Optional[logging.Formatter] = None) -> logging.Handler:
        """Add a custom file handler."""
        if isinstance(level, str):
            level = getattr(logging, level.upper())
        
        file_path = self.log_dir / filename
        handler = logging.handlers.RotatingFileHandler(
            file_path, 
            maxBytes=getattr(config, 'LOG_MAX_BYTES', 10 * 1024 * 1024),
            backupCount=getattr(config, 'LOG_BACKUP_COUNT', 5),
            encoding='utf-8'
        )
        handler.setLevel(level)
        
        if formatter is None:
            formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s"
            )
        handler.setFormatter(formatter)
        
        # Add to root logger
        logging.getLogger().addHandler(handler)
        self.handlers[name] = handler
        
        return handler
    
    def get_log_files(self) -> Dict[str, Path]:
        """Get paths to all log files."""
        log_files = {}
        for name, handler in self.handlers.items():
            if hasattr(handler, 'baseFilename'):
                log_files[name] = Path(handler.baseFilename)
        return log_files
    
    def cleanup_old_logs(self, days: int = 30) -> int:
        """Remove log files older than specified days."""
        if not self.log_dir.exists():
            return 0
        
        import time
        cutoff_time = time.time() - (days * 24 * 60 * 60)
        removed_count = 0
        
        for log_file in self.log_dir.glob('*.log*'):
            try:
                if log_file.stat().st_mtime < cutoff_time:
                    log_file.unlink()
                    removed_count += 1
            except OSError:
                pass  # File might be in use
        
        return removed_count

# Global logging manager instance
_logging_manager = LoggingManager()

# Convenience functions
def setup_logging(**kwargs) -> None:
    """Setup logging configuration."""
    _logging_manager.setup_logging(**kwargs)

def get_logger(name: str) -> logging.Logger:
    """Get a logger instance."""
    return _logging_manager.get_logger(name)

def set_log_level(level: Union[str, int, LogLevel]) -> None:
    """Change the logging level."""
    _logging_manager.set_level(level)

def add_file_handler(name: str, filename: str, **kwargs) -> logging.Handler:
    """Add a custom file handler."""
    return _logging_manager.add_file_handler(name, filename, **kwargs)

def get_log_files() -> Dict[str, Path]:
    """Get paths to all log files."""
    return _logging_manager.get_log_files()

def cleanup_old_logs(days: int = 30) -> int:
    """Remove old log files."""
    return _logging_manager.cleanup_old_logs(days)

# Context manager for temporary log level changes
class temporary_log_level:
    """Context manager for temporarily changing log level."""
    
    def __init__(self, level: Union[str, int, LogLevel]):
        self.new_level = level
        self.old_level = None
    
    def __enter__(self):
        self.old_level = logging.getLogger().level
        set_log_level(self.new_level)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.old_level is not None:
            set_log_level(self.old_level)

# Performance logging decorator
def log_performance(logger_name: str = None):
    """Decorator to log function execution time."""
    def decorator(func):
        import functools
        import time
        
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            logger = get_logger(logger_name or func.__module__)
            start_time = time.time()
            
            try:
                result = func(*args, **kwargs)
                execution_time = time.time() - start_time
                logger.debug(f"{func.__name__} executed in {execution_time:.4f} seconds")
                return result
            except Exception as e:
                execution_time = time.time() - start_time
                logger.error(f"{func.__name__} failed after {execution_time:.4f} seconds: {e}")
                raise
        
        return wrapper
    return decorator

if __name__ == '__main__':
    # Example usage
    setup_logging(
        level=LogLevel.DEBUG,
        log_format=LogFormat.COLORED,
        enable_performance_logging=True
    )
    
    logger = get_logger('test')
    logger.debug("This is a debug message")
    logger.info("This is an info message")
    logger.warning("This is a warning message")
    logger.error("This is an error message")
    
    # Test performance logging
    @log_performance('test')
    def test_function():
        import time
        time.sleep(0.1)
        return "done"
    
    test_function()
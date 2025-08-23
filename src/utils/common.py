#!/usr/bin/env python3
"""
Common Utilities Module - Dark Web Threat Intelligence Analyzer

This module contains common utility functions and classes used throughout the application.

Author: Yousef
Project: Dark Web Threat Intelligence Analyzer
"""

import os
import re
import hashlib
import json
import time
import functools
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Union, Callable, Iterator, Tuple
from urllib.parse import urlparse, urljoin
from contextlib import contextmanager

try:
    import validators
except ImportError:
    validators = None

from .logging_config import get_logger

logger = get_logger(__name__)

class FileUtils:
    """Utility class for file operations."""
    
    @staticmethod
    def ensure_directory(path: Union[str, Path]) -> Path:
        """Ensure directory exists, create if it doesn't.
        
        Args:
            path: Directory path
            
        Returns:
            Path object of the directory
        """
        path_obj = Path(path)
        path_obj.mkdir(parents=True, exist_ok=True)
        return path_obj
    
    @staticmethod
    def safe_filename(filename: str, max_length: int = 255) -> str:
        """Create a safe filename by removing/replacing invalid characters.
        
        Args:
            filename: Original filename
            max_length: Maximum filename length
            
        Returns:
            Safe filename
        """
        # Remove or replace invalid characters
        safe_chars = re.sub(r'[<>:"/\\|?*]', '_', filename)
        safe_chars = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', safe_chars)
        
        # Remove leading/trailing dots and spaces
        safe_chars = safe_chars.strip('. ')
        
        # Ensure not empty
        if not safe_chars:
            safe_chars = 'unnamed_file'
        
        # Truncate if too long
        if len(safe_chars) > max_length:
            name, ext = os.path.splitext(safe_chars)
            max_name_length = max_length - len(ext)
            safe_chars = name[:max_name_length] + ext
        
        return safe_chars
    
    @staticmethod
    def calculate_file_hash(file_path: Union[str, Path], algorithm: str = 'sha256') -> str:
        """Calculate hash of a file.
        
        Args:
            file_path: Path to file
            algorithm: Hash algorithm (md5, sha1, sha256, sha512)
            
        Returns:
            Hex digest of file hash
        """
        hash_obj = hashlib.new(algorithm)
        
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_obj.update(chunk)
            return hash_obj.hexdigest()
        except Exception as e:
            logger.error(f"Error calculating hash for {file_path}: {e}")
            return ""
    
    @staticmethod
    def get_file_size_human(file_path: Union[str, Path]) -> str:
        """Get human-readable file size.
        
        Args:
            file_path: Path to file
            
        Returns:
            Human-readable size string
        """
        try:
            size = Path(file_path).stat().st_size
            return StringUtils.format_bytes(size)
        except Exception:
            return "Unknown"
    
    @staticmethod
    def find_files(directory: Union[str, Path], 
                  pattern: str = "*", 
                  recursive: bool = True,
                  max_files: Optional[int] = None) -> List[Path]:
        """Find files matching pattern in directory.
        
        Args:
            directory: Directory to search
            pattern: File pattern (glob style)
            recursive: Whether to search recursively
            max_files: Maximum number of files to return
            
        Returns:
            List of matching file paths
        """
        directory = Path(directory)
        if not directory.exists():
            return []
        
        if recursive:
            files = list(directory.rglob(pattern))
        else:
            files = list(directory.glob(pattern))
        
        # Filter only files (not directories)
        files = [f for f in files if f.is_file()]
        
        # Limit results if specified
        if max_files:
            files = files[:max_files]
        
        return files
    
    @staticmethod
    def backup_file(file_path: Union[str, Path], backup_dir: Optional[Union[str, Path]] = None) -> Optional[Path]:
        """Create a backup of a file.
        
        Args:
            file_path: Path to file to backup
            backup_dir: Directory for backup (default: same directory)
            
        Returns:
            Path to backup file or None if failed
        """
        file_path = Path(file_path)
        if not file_path.exists():
            return None
        
        if backup_dir:
            backup_dir = Path(backup_dir)
            backup_dir.mkdir(parents=True, exist_ok=True)
            backup_path = backup_dir / f"{file_path.stem}_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}{file_path.suffix}"
        else:
            backup_path = file_path.with_name(f"{file_path.stem}_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}{file_path.suffix}")
        
        try:
            import shutil
            shutil.copy2(file_path, backup_path)
            return backup_path
        except Exception as e:
            logger.error(f"Error creating backup of {file_path}: {e}")
            return None

class StringUtils:
    """Utility class for string operations."""
    
    @staticmethod
    def format_bytes(bytes_value: int) -> str:
        """Format bytes into human-readable string.
        
        Args:
            bytes_value: Number of bytes
            
        Returns:
            Human-readable string (e.g., '1.5 MB')
        """
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.1f} {unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.1f} PB"
    
    @staticmethod
    def format_duration(seconds: float) -> str:
        """Format duration in seconds to human-readable string.
        
        Args:
            seconds: Duration in seconds
            
        Returns:
            Human-readable duration string
        """
        if seconds < 60:
            return f"{seconds:.1f}s"
        elif seconds < 3600:
            minutes = seconds / 60
            return f"{minutes:.1f}m"
        else:
            hours = seconds / 3600
            return f"{hours:.1f}h"
    
    @staticmethod
    def truncate_string(text: str, max_length: int, suffix: str = "...") -> str:
        """Truncate string to maximum length.
        
        Args:
            text: Text to truncate
            max_length: Maximum length
            suffix: Suffix to add when truncated
            
        Returns:
            Truncated string
        """
        if len(text) <= max_length:
            return text
        return text[:max_length - len(suffix)] + suffix
    
    @staticmethod
    def clean_text(text: str, remove_extra_spaces: bool = True) -> str:
        """Clean text by removing unwanted characters.
        
        Args:
            text: Text to clean
            remove_extra_spaces: Whether to remove extra whitespace
            
        Returns:
            Cleaned text
        """
        # Remove control characters
        cleaned = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x84\x86-\x9f]', '', text)
        
        if remove_extra_spaces:
            # Replace multiple whitespace with single space
            cleaned = re.sub(r'\s+', ' ', cleaned)
            cleaned = cleaned.strip()
        
        return cleaned
    
    @staticmethod
    def extract_domain(url: str) -> Optional[str]:
        """Extract domain from URL.
        
        Args:
            url: URL string
            
        Returns:
            Domain name or None if invalid
        """
        try:
            # Add protocol if missing
            if not url.startswith(('http://', 'https://')):
                url = f'http://{url}'
            
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            # Remove port if present
            if ':' in domain:
                domain = domain.split(':')[0]
            
            return domain if domain else None
        except Exception:
            return None
    
    @staticmethod
    def is_valid_email(email: str) -> bool:
        """Check if email address is valid.
        
        Args:
            email: Email address to validate
            
        Returns:
            True if valid, False otherwise
        """
        if validators:
            return validators.email(email) is True
        
        # Fallback regex validation
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    @staticmethod
    def is_valid_url(url: str) -> bool:
        """Check if URL is valid.
        
        Args:
            url: URL to validate
            
        Returns:
            True if valid, False otherwise
        """
        if validators:
            return validators.url(url) is True
        
        # Fallback validation
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False

class DataUtils:
    """Utility class for data operations."""
    
    @staticmethod
    def safe_json_load(file_path: Union[str, Path]) -> Optional[Union[Dict, List]]:
        """Safely load JSON file.
        
        Args:
            file_path: Path to JSON file
            
        Returns:
            Parsed JSON data or None if failed
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error loading JSON from {file_path}: {e}")
            return None
    
    @staticmethod
    def safe_json_save(data: Union[Dict, List], file_path: Union[str, Path], indent: int = 2) -> bool:
        """Safely save data to JSON file.
        
        Args:
            data: Data to save
            file_path: Path to save file
            indent: JSON indentation
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Ensure directory exists
            Path(file_path).parent.mkdir(parents=True, exist_ok=True)
            
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=indent, ensure_ascii=False)
            return True
        except Exception as e:
            logger.error(f"Error saving JSON to {file_path}: {e}")
            return False
    
    @staticmethod
    def merge_dicts(dict1: Dict, dict2: Dict, deep: bool = True) -> Dict:
        """Merge two dictionaries.
        
        Args:
            dict1: First dictionary
            dict2: Second dictionary
            deep: Whether to perform deep merge
            
        Returns:
            Merged dictionary
        """
        if not deep:
            result = dict1.copy()
            result.update(dict2)
            return result
        
        result = dict1.copy()
        for key, value in dict2.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = DataUtils.merge_dicts(result[key], value, deep=True)
            else:
                result[key] = value
        return result
    
    @staticmethod
    def flatten_dict(data: Dict, separator: str = '.', prefix: str = '') -> Dict:
        """Flatten nested dictionary.
        
        Args:
            data: Dictionary to flatten
            separator: Separator for nested keys
            prefix: Prefix for keys
            
        Returns:
            Flattened dictionary
        """
        result = {}
        for key, value in data.items():
            new_key = f"{prefix}{separator}{key}" if prefix else key
            
            if isinstance(value, dict):
                result.update(DataUtils.flatten_dict(value, separator, new_key))
            else:
                result[new_key] = value
        
        return result
    
    @staticmethod
    def chunk_list(data: List, chunk_size: int) -> Iterator[List]:
        """Split list into chunks.
        
        Args:
            data: List to chunk
            chunk_size: Size of each chunk
            
        Yields:
            List chunks
        """
        for i in range(0, len(data), chunk_size):
            yield data[i:i + chunk_size]
    
    @staticmethod
    def deduplicate_list(data: List, key_func: Optional[Callable] = None) -> List:
        """Remove duplicates from list while preserving order.
        
        Args:
            data: List to deduplicate
            key_func: Function to extract comparison key
            
        Returns:
            Deduplicated list
        """
        seen = set()
        result = []
        
        for item in data:
            key = key_func(item) if key_func else item
            if key not in seen:
                seen.add(key)
                result.append(item)
        
        return result

class TimeUtils:
    """Utility class for time operations."""
    
    @staticmethod
    def get_timestamp(format_str: str = "%Y-%m-%d %H:%M:%S") -> str:
        """Get current timestamp as string.
        
        Args:
            format_str: Timestamp format
            
        Returns:
            Formatted timestamp string
        """
        return datetime.now().strftime(format_str)
    
    @staticmethod
    def parse_timestamp(timestamp_str: str, format_str: str = "%Y-%m-%d %H:%M:%S") -> Optional[datetime]:
        """Parse timestamp string to datetime object.
        
        Args:
            timestamp_str: Timestamp string
            format_str: Expected format
            
        Returns:
            Datetime object or None if parsing failed
        """
        try:
            return datetime.strptime(timestamp_str, format_str)
        except ValueError:
            return None
    
    @staticmethod
    def time_ago(timestamp: datetime) -> str:
        """Get human-readable time difference.
        
        Args:
            timestamp: Datetime to compare
            
        Returns:
            Human-readable time difference
        """
        now = datetime.now()
        diff = now - timestamp
        
        if diff.days > 0:
            return f"{diff.days} day{'s' if diff.days != 1 else ''} ago"
        elif diff.seconds > 3600:
            hours = diff.seconds // 3600
            return f"{hours} hour{'s' if hours != 1 else ''} ago"
        elif diff.seconds > 60:
            minutes = diff.seconds // 60
            return f"{minutes} minute{'s' if minutes != 1 else ''} ago"
        else:
            return "Just now"
    
    @staticmethod
    def is_recent(timestamp: datetime, hours: int = 24) -> bool:
        """Check if timestamp is within recent hours.
        
        Args:
            timestamp: Datetime to check
            hours: Number of hours to consider recent
            
        Returns:
            True if recent, False otherwise
        """
        cutoff = datetime.now() - timedelta(hours=hours)
        return timestamp > cutoff

class RateLimiter:
    """Simple rate limiter implementation."""
    
    def __init__(self, max_calls: int, time_window: int):
        """Initialize rate limiter.
        
        Args:
            max_calls: Maximum number of calls allowed
            time_window: Time window in seconds
        """
        self.max_calls = max_calls
        self.time_window = time_window
        self.calls = []
    
    def is_allowed(self) -> bool:
        """Check if call is allowed.
        
        Returns:
            True if allowed, False if rate limited
        """
        now = time.time()
        
        # Remove old calls outside time window
        self.calls = [call_time for call_time in self.calls if now - call_time < self.time_window]
        
        # Check if we can make another call
        if len(self.calls) < self.max_calls:
            self.calls.append(now)
            return True
        
        return False
    
    def wait_time(self) -> float:
        """Get time to wait before next call is allowed.
        
        Returns:
            Seconds to wait
        """
        if not self.calls:
            return 0.0
        
        oldest_call = min(self.calls)
        return max(0.0, self.time_window - (time.time() - oldest_call))
    
    @contextmanager
    def acquire(self, wait: bool = True):
        """Context manager for rate limiting.
        
        Args:
            wait: Whether to wait if rate limited
        """
        if not self.is_allowed():
            if wait:
                wait_time = self.wait_time()
                if wait_time > 0:
                    time.sleep(wait_time)
                    self.calls.append(time.time())
            else:
                raise RuntimeError("Rate limit exceeded")
        
        yield

# Decorators
def retry(max_attempts: int = 3, delay: float = 1.0, backoff: float = 2.0, exceptions: Tuple = (Exception,)):
    """Retry decorator with exponential backoff.
    
    Args:
        max_attempts: Maximum number of retry attempts
        delay: Initial delay between retries
        backoff: Backoff multiplier
        exceptions: Tuple of exceptions to catch
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            current_delay = delay
            last_exception = None
            
            for attempt in range(max_attempts):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    if attempt < max_attempts - 1:
                        logger.warning(f"Attempt {attempt + 1} failed for {func.__name__}: {e}. Retrying in {current_delay}s...")
                        time.sleep(current_delay)
                        current_delay *= backoff
                    else:
                        logger.error(f"All {max_attempts} attempts failed for {func.__name__}: {e}")
            
            raise last_exception
        return wrapper
    return decorator

def timeout(seconds: int):
    """Timeout decorator.
    
    Args:
        seconds: Timeout in seconds
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            import signal
            
            def timeout_handler(signum, frame):
                raise TimeoutError(f"Function {func.__name__} timed out after {seconds} seconds")
            
            # Set timeout
            old_handler = signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(seconds)
            
            try:
                result = func(*args, **kwargs)
                return result
            finally:
                # Restore old handler and cancel alarm
                signal.signal(signal.SIGALRM, old_handler)
                signal.alarm(0)
        
        return wrapper
    return decorator

# Context managers
@contextmanager
def timer(description: str = "Operation"):
    """Context manager for timing operations.
    
    Args:
        description: Description of the operation
    """
    start_time = time.time()
    try:
        yield
    finally:
        elapsed = time.time() - start_time
        logger.info(f"{description} completed in {StringUtils.format_duration(elapsed)}")

@contextmanager
def suppress_errors(*exceptions, log_errors: bool = True):
    """Context manager to suppress specified exceptions.
    
    Args:
        exceptions: Exception types to suppress
        log_errors: Whether to log suppressed errors
    """
    try:
        yield
    except exceptions as e:
        if log_errors:
            logger.warning(f"Suppressed error: {e}")

if __name__ == '__main__':
    # Example usage
    from .logging_config import setup_logging
    
    setup_logging()
    
    # Test file utilities
    print("Testing FileUtils...")
    print(f"Safe filename: {FileUtils.safe_filename('test<>file.txt')}")
    print(f"File size: {FileUtils.get_file_size_human(__file__)}")
    
    # Test string utilities
    print("\nTesting StringUtils...")
    print(f"Format bytes: {StringUtils.format_bytes(1536)}")
    print(f"Extract domain: {StringUtils.extract_domain('https://example.com/path')}")
    
    # Test time utilities
    print("\nTesting TimeUtils...")
    print(f"Current timestamp: {TimeUtils.get_timestamp()}")
    
    # Test rate limiter
    print("\nTesting RateLimiter...")
    limiter = RateLimiter(max_calls=3, time_window=5)
    for i in range(5):
        if limiter.is_allowed():
            print(f"Call {i+1}: Allowed")
        else:
            print(f"Call {i+1}: Rate limited")
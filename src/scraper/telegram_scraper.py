#!/usr/bin/env python3
"""
Telegram Scraper Module - Dark Web Threat Intelligence Analyzer

This module handles secure downloading of files from Telegram channels
with comprehensive rate limiting, error handling, and security features.

Author: Yousef
Project: Dark Web Threat Intelligence Analyzer
"""

import os
import re
import json
import asyncio
import hashlib
import logging
import mimetypes
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Optional, Set, Tuple
from dataclasses import dataclass, asdict
from contextlib import asynccontextmanager

try:
    from telethon import TelegramClient
    from telethon.tl.types import MessageMediaDocument, DocumentAttributeFilename
    from telethon.errors import (
        FloodWaitError, AuthKeyUnregisteredError, UserDeactivatedError,
        SessionPasswordNeededError, PhoneCodeInvalidError, ApiIdInvalidError
    )
except ImportError:
    raise ImportError("telethon is required. Install with: pip install telethon")

from tqdm import tqdm

try:
    from src.config.config import config
except ImportError:
    # Fallback for standalone execution
    class Config:
        TELEGRAM_API_ID = None
        TELEGRAM_API_HASH = None
        TELEGRAM_CHANNEL_ID = None
        DOWNLOAD_ROOT = "downloads"
        TELEGRAM_SESSION_NAME = "telegram_session"
        TELEGRAM_RATE_LIMIT_DELAY = 1.0
        TELEGRAM_MAX_FILE_SIZE = None  # No file size limit for large leak files
    config = Config()

# Configure logging
logger = logging.getLogger(__name__)

@dataclass
class DownloadedFile:
    """Data class representing a downloaded file with metadata."""
    message_id: int
    original_name: str
    downloaded_path: str
    file_size: int
    download_date: str
    channel_id: str
    has_password: bool = False
    password_file: Optional[str] = None
    file_hash: Optional[str] = None
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)

class RateLimiter:
    """Rate limiter for Telegram API calls to prevent flooding."""
    
    def __init__(self, delay: float = 1.0, burst_limit: int = 5):
        """Initialize rate limiter.
        
        Args:
            delay: Minimum delay between requests in seconds
            burst_limit: Maximum number of requests in burst
        """
        self.delay = delay
        self.burst_limit = burst_limit
        self.last_request_time = 0.0
        self.request_count = 0
        self.burst_start_time = 0.0
    
    async def wait(self):
        """Wait if necessary to respect rate limits."""
        current_time = datetime.now().timestamp()
        
        # Reset burst counter if enough time has passed
        if current_time - self.burst_start_time > 60:  # 1 minute window
            self.request_count = 0
            self.burst_start_time = current_time
        
        # Check burst limit
        if self.request_count >= self.burst_limit:
            wait_time = 60 - (current_time - self.burst_start_time)
            if wait_time > 0:
                logger.info(f"Rate limit: waiting {wait_time:.1f}s for burst reset")
                await asyncio.sleep(wait_time)
                self.request_count = 0
                self.burst_start_time = datetime.now().timestamp()
        
        # Check minimum delay
        time_since_last = current_time - self.last_request_time
        if time_since_last < self.delay:
            wait_time = self.delay - time_since_last
            await asyncio.sleep(wait_time)
        
        self.last_request_time = datetime.now().timestamp()
        self.request_count += 1

class PasswordExtractor:
    """Utility class for extracting passwords from message text."""
    
    # Comprehensive password patterns
    PASSWORD_PATTERNS = [
        r'Password\s*[:=]\s*([^\s\n]+)',
        r'Pwd\s*[:=]\s*([^\s\n]+)',
        r'Pass\s*[:=]\s*([^\s\n]+)',
        r'Archive\s+password\s*[:=]\s*([^\s\n]+)',
        r'Zip\s+password\s*[:=]\s*([^\s\n]+)',
        r'Extract\s+password\s*[:=]\s*([^\s\n]+)',
        r'Unpack\s+password\s*[:=]\s*([^\s\n]+)',
        r'Key\s*[:=]\s*([^\s\n]+)',
        r'Code\s*[:=]\s*([^\s\n]+)',
    ]
    
    @classmethod
    def extract_password(cls, message_text: str) -> Optional[str]:
        """Extract password from message text using multiple patterns."""
        if not message_text or not isinstance(message_text, str):
            return None
        
        # Clean message text
        text = message_text.strip()
        
        for pattern in cls.PASSWORD_PATTERNS:
            match = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
            if match:
                password = match.group(1).strip()
                # Validate password (basic checks)
                if cls._is_valid_password(password):
                    return password
        
        return None
    
    @classmethod
    def _is_valid_password(cls, password: str) -> bool:
        """Basic validation for extracted passwords."""
        if not password or len(password) < 3 or len(password) > 100:
            return False
        
        # Skip obvious non-passwords
        invalid_patterns = [
            r'^(none|null|empty|n/a|na)$',
            r'^[\s\-_]+$',
            r'^\d{1,3}$',  # Simple numbers
        ]
        
        for pattern in invalid_patterns:
            if re.match(pattern, password, re.IGNORECASE):
                return False
        
        return True

class FileValidator:
    """Utility class for validating downloaded files."""
    
    # Allowed file extensions for security
    ALLOWED_EXTENSIONS = {
        '.txt', '.log', '.csv', '.json', '.xml',
        '.zip', '.rar', '.7z', '.tar', '.gz',
        '.sql', '.db', '.sqlite', '.mdb'
    }
    
    # Dangerous extensions to avoid
    DANGEROUS_EXTENSIONS = {
        '.exe', '.bat', '.cmd', '.scr', '.pif',
        '.com', '.dll', '.sys', '.vbs', '.js'
    }
    
    @classmethod
    def is_safe_file(cls, filename: str, file_size: int, max_size: Optional[int] = None) -> Tuple[bool, str]:
        """Validate if file is safe to download.
        
        Returns:
            Tuple of (is_safe, reason)
        """
        if not filename:
            return False, "No filename provided"
        
        # Skip file size check for large leak files (max_size can be None)
        if max_size is not None and file_size > max_size:
            logger.warning(f"Large file detected: {file_size} bytes for {filename}")
            # Don't reject large files, just log them
        
        # Get file extension
        ext = Path(filename).suffix.lower()
        
        # Check dangerous extensions
        if ext in cls.DANGEROUS_EXTENSIONS:
            return False, f"Dangerous file extension: {ext}"
        
        # Check if extension is allowed (if whitelist is used)
        # For now, we'll be permissive but log warnings
        if ext and ext not in cls.ALLOWED_EXTENSIONS:
            logger.warning(f"Uncommon file extension: {ext} for file {filename}")
        
        return True, "File appears safe"
    
    @classmethod
    def sanitize_filename(cls, filename: str, max_length: int = 200) -> str:
        """Sanitize filename for safe storage."""
        if not filename:
            return "unknown_file"
        
        # Remove or replace dangerous characters
        safe_chars = re.sub(r'[<>:"/\\|?*]', '_', filename)
        safe_chars = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', safe_chars)  # Remove control chars
        
        # Limit length
        if len(safe_chars) > max_length:
            name, ext = os.path.splitext(safe_chars)
            safe_chars = name[:max_length-len(ext)] + ext
        
        return safe_chars or "unknown_file"

class TelegramScraper:
    """Main class for scraping files from Telegram channels."""
    
    def __init__(self, api_id: str = None, api_hash: str = None, 
                 session_name: str = None, download_root: str = None):
        """Initialize the Telegram scraper.
        
        Args:
            api_id: Telegram API ID
            api_hash: Telegram API hash
            session_name: Session file name
            download_root: Root directory for downloads
        """
        # Configuration
        self.api_id = api_id or config.TELEGRAM_API_ID
        self.api_hash = api_hash or config.TELEGRAM_API_HASH
        self.session_name = session_name or config.TELEGRAM_SESSION_NAME
        self.download_root = Path(download_root or config.DOWNLOAD_ROOT)
        
        # Validate configuration
        if not self.api_id or not self.api_hash:
            raise ValueError(
                "Telegram API credentials not found. "
                "Please set TELEGRAM_API_ID and TELEGRAM_API_HASH in configuration."
            )
        
        # Initialize components
        self.rate_limiter = RateLimiter(
            delay=getattr(config, 'TELEGRAM_RATE_LIMIT_DELAY', 1.0)
        )
        self.max_file_size = getattr(config, 'TELEGRAM_MAX_FILE_SIZE', None)  # No size limit
        
        # Statistics
        self.stats = {
            'files_found': 0,
            'files_downloaded': 0,
            'files_skipped': 0,
            'files_failed': 0,
            'passwords_extracted': 0,
            'total_size': 0
        }
        
        # Downloaded files tracking
        self.downloaded_files: List[DownloadedFile] = []
        self.download_log_file = self.download_root / "download_log.json"
        
        # Ensure download directory exists
        self.download_root.mkdir(parents=True, exist_ok=True)
        
        # Load existing download log
        self._load_download_log()
        
        logger.info(f"Telegram scraper initialized: {self.download_root}")
    
    def _load_download_log(self):
        """Load existing download log to avoid re-downloading files."""
        if self.download_log_file.exists():
            try:
                with open(self.download_log_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.downloaded_files = [
                        DownloadedFile(**item) for item in data.get('files', [])
                    ]
                logger.info(f"Loaded {len(self.downloaded_files)} previously downloaded files")
            except Exception as e:
                logger.error(f"Error loading download log: {e}")
                self.downloaded_files = []
    
    def _save_download_log(self):
        """Save download log to file."""
        try:
            data = {
                'last_updated': datetime.now().isoformat(),
                'stats': self.stats,
                'files': [file.to_dict() for file in self.downloaded_files]
            }
            with open(self.download_log_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"Error saving download log: {e}")
    
    def _is_already_downloaded(self, message_id: int, channel_id: str) -> bool:
        """Check if file was already downloaded."""
        return any(
            file.message_id == message_id and file.channel_id == str(channel_id)
            for file in self.downloaded_files
        )
    
    def _calculate_file_hash(self, file_path: Path) -> str:
        """Calculate SHA256 hash of downloaded file."""
        try:
            hash_sha256 = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception as e:
            logger.error(f"Error calculating hash for {file_path}: {e}")
            return ""
    
    @asynccontextmanager
    async def get_client(self):
        """Context manager for Telegram client with proper cleanup."""
        client = TelegramClient(self.session_name, int(self.api_id), self.api_hash)
        
        try:
            await client.start()
            logger.info("Telegram client connected successfully")
            yield client
        except AuthKeyUnregisteredError:
            logger.error("Telegram session is invalid. Please delete session file and re-authenticate.")
            raise
        except ApiIdInvalidError:
            logger.error("Invalid Telegram API ID. Please check your configuration.")
            raise
        except Exception as e:
            logger.error(f"Error connecting to Telegram: {e}")
            raise
        finally:
            try:
                await client.disconnect()
                logger.info("Telegram client disconnected")
            except Exception as e:
                logger.error(f"Error disconnecting client: {e}")
    
    async def download_from_channel(self, channel_id: str, limit: int = None, 
                                  date_filter: datetime = None) -> Dict:
        """Download files from a Telegram channel.
        
        Args:
            channel_id: Channel ID or username
            limit: Maximum number of files to download
            date_filter: Only download files newer than this date
        
        Returns:
            Dictionary with download statistics
        """
        logger.info(f"Starting download from channel: {channel_id}")
        
        async with self.get_client() as client:
            try:
                # Get channel entity
                channel = await client.get_entity(channel_id)
                logger.info(f"Connected to channel: {channel.title} (ID: {channel.id})")
                
                # Create channel-specific directory
                channel_name = FileValidator.sanitize_filename(channel.title)
                channel_dir = self.download_root / channel_name
                channel_dir.mkdir(exist_ok=True)
                
                # Collect messages with files
                messages_with_files = []
                async for message in client.iter_messages(channel, limit=limit):
                    if (message.media and 
                        isinstance(message.media, MessageMediaDocument) and
                        message.file):
                        
                        # Apply date filter
                        if date_filter and message.date < date_filter:
                            continue
                        
                        # Skip if already downloaded
                        if self._is_already_downloaded(message.id, channel.id):
                            continue
                        
                        messages_with_files.append(message)
                
                self.stats['files_found'] = len(messages_with_files)
                logger.info(f"Found {len(messages_with_files)} new files to download")
                
                if not messages_with_files:
                    logger.info("No new files to download")
                    return self.stats
                
                # Download files with progress bar
                with tqdm(total=len(messages_with_files), desc="Downloading", unit="file") as pbar:
                    for message in messages_with_files:
                        try:
                            await self._download_single_file(message, channel_dir, str(channel.id))
                        except FloodWaitError as e:
                            logger.warning(f"Rate limited, waiting {e.seconds} seconds")
                            await asyncio.sleep(e.seconds)
                            # Retry the download
                            try:
                                await self._download_single_file(message, channel_dir, str(channel.id))
                            except Exception as retry_e:
                                logger.error(f"Retry failed for message {message.id}: {retry_e}")
                                self.stats['files_failed'] += 1
                        except Exception as e:
                            logger.error(f"Error downloading message {message.id}: {e}")
                            self.stats['files_failed'] += 1
                        
                        pbar.update(1)
                        
                        # Apply rate limiting
                        await self.rate_limiter.wait()
                
                # Save download log
                self._save_download_log()
                
                logger.info("Download completed")
                logger.info(f"Files downloaded: {self.stats['files_downloaded']}")
                logger.info(f"Files skipped: {self.stats['files_skipped']}")
                logger.info(f"Files failed: {self.stats['files_failed']}")
                logger.info(f"Passwords extracted: {self.stats['passwords_extracted']}")
                logger.info(f"Total size: {self.stats['total_size'] / (1024*1024):.1f} MB")
                
                return self.stats
                
            except Exception as e:
                logger.error(f"Error accessing channel {channel_id}: {e}")
                raise
    
    async def _download_single_file(self, message, channel_dir: Path, channel_id: str):
        """Download a single file from a message."""
        try:
            # Get file information
            file_name = "unknown_file"
            if message.file.name:
                file_name = message.file.name
            elif hasattr(message.media.document, 'attributes'):
                for attr in message.media.document.attributes:
                    if isinstance(attr, DocumentAttributeFilename):
                        file_name = attr.file_name
                        break
            
            file_size = message.file.size or 0
            
            # Validate file safety
            is_safe, reason = FileValidator.is_safe_file(file_name, file_size, self.max_file_size)
            if not is_safe:
                logger.warning(f"Skipping unsafe file {file_name}: {reason}")
                self.stats['files_skipped'] += 1
                return
            
            # Create safe filename
            safe_name = FileValidator.sanitize_filename(file_name)
            unique_name = f"{message.id}_{safe_name}"
            target_path = channel_dir / unique_name
            
            # Download file
            try:
                file_path = await message.download_media(file=str(target_path))
                
                if not file_path or not Path(file_path).exists():
                    raise Exception("Download failed - file not created")
                
                # Calculate file hash
                file_hash = self._calculate_file_hash(Path(file_path))
                
                # Extract password if present
                password = None
                password_file = None
                if message.message:
                    password = PasswordExtractor.extract_password(message.message)
                    if password:
                        password_file = str(target_path) + ".pwd.txt"
                        try:
                            with open(password_file, 'w', encoding='utf-8') as pf:
                                pf.write(password)
                            self.stats['passwords_extracted'] += 1
                        except Exception as e:
                            logger.error(f"Failed to save password file: {e}")
                            password_file = None
                
                # Record download
                downloaded_file = DownloadedFile(
                    message_id=message.id,
                    original_name=file_name,
                    downloaded_path=str(file_path),
                    file_size=file_size,
                    download_date=datetime.now().isoformat(),
                    channel_id=channel_id,
                    has_password=password is not None,
                    password_file=password_file,
                    file_hash=file_hash
                )
                
                self.downloaded_files.append(downloaded_file)
                self.stats['files_downloaded'] += 1
                self.stats['total_size'] += file_size
                
                logger.debug(f"Downloaded: {file_name} ({file_size} bytes)")
                
            except Exception as e:
                logger.error(f"Error downloading file from message {message.id}: {e}")
                self.stats['files_failed'] += 1
                
        except Exception as e:
            logger.error(f"Error processing message {message.id}: {e}")
            self.stats['files_failed'] += 1

def main():
    """Main entry point for standalone execution."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Download files from Telegram channels",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        "channel",
        help="Channel ID or username to download from"
    )
    
    parser.add_argument(
        "--limit", "-l",
        type=int,
        help="Maximum number of files to download"
    )
    
    parser.add_argument(
        "--days", "-d",
        type=int,
        help="Only download files from last N days"
    )
    
    parser.add_argument(
        "--output", "-o",
        default="downloads",
        help="Output directory (default: downloads)"
    )
    
    parser.add_argument(
        "--session", "-s",
        default="telegram_session",
        help="Session name (default: telegram_session)"
    )
    
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Set logging level (default: INFO)"
    )
    
    args = parser.parse_args()
    
    # Configure logging
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    
    # Calculate date filter
    date_filter = None
    if args.days:
        date_filter = datetime.now() - timedelta(days=args.days)
    
    # Initialize scraper
    scraper = TelegramScraper(
        session_name=args.session,
        download_root=args.output
    )
    
    # Run download
    async def run_download():
        try:
            stats = await scraper.download_from_channel(
                channel_id=args.channel,
                limit=args.limit,
                date_filter=date_filter
            )
            
            # Print summary
            print("\n" + "=" * 50)
            print("DOWNLOAD SUMMARY")
            print("=" * 50)
            print(f"Files found: {stats['files_found']}")
            print(f"Files downloaded: {stats['files_downloaded']}")
            print(f"Files skipped: {stats['files_skipped']}")
            print(f"Files failed: {stats['files_failed']}")
            print(f"Passwords extracted: {stats['passwords_extracted']}")
            print(f"Total size: {stats['total_size'] / (1024*1024):.1f} MB")
            print("=" * 50)
            
        except Exception as e:
            logger.error(f"Download failed: {e}")
            return 1
        
        return 0
    
    # Run the async function
    exit_code = asyncio.run(run_download())
    exit(exit_code)

if __name__ == '__main__':
    main()

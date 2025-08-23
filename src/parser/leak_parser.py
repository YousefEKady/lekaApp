#!/usr/bin/env python3
"""
Leak Parser Module - Dark Web Threat Intelligence Analyzer

This module parses leaked credential files and extracts structured data.
Supports multiple formats:
- Key-Value format (URL: ..., USER: ..., PASS: ...)
- Colon-separated format (url:user:pass)
- Mixed formats within the same file

Author: Yousef
Project: Dark Web Threat Intelligence Analyzer
"""

import os
import re
import json
import hashlib
import logging
import mimetypes
from pathlib import Path
from typing import List, Dict, Optional, Set, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
from tqdm import tqdm
import urllib.parse

try:
    from src.config.config import config
except ImportError:
    # Fallback for standalone execution
    class Config:
        DOWNLOAD_ROOT = "downloads"
        PARSED_OUTPUT_DIR = "parsed_leaked_json"
    config = Config()

# Configure logging
logger = logging.getLogger(__name__)

@dataclass
class ParsedCredential:
    """Data class representing a parsed credential entry."""
    url: str
    username: str
    password: str
    source_file: str
    line_number: Optional[int] = None
    format_type: Optional[str] = None
    parsed_at: Optional[str] = None
    
    def __post_init__(self):
        """Post-initialization validation and normalization."""
        if not self.parsed_at:
            self.parsed_at = datetime.now().isoformat()
        
        # Validate required fields
        if not all([self.url, self.username, self.password]):
            raise ValueError("URL, username, and password are required")
        
        # Normalize URL
        self.url = URLValidator.normalize_url(self.url)
        
        # Validate URL format
        if not URLValidator.is_valid_url(self.url):
            logger.warning(f"Potentially invalid URL: {self.url}")
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "URL": self.url,
            "USER": self.username,
            "PASS": self.password,
            "source_file": self.source_file,
            "line_number": self.line_number,
            "format_type": self.format_type,
            "parsed_at": self.parsed_at
        }

class URLValidator:
    """Utility class for URL validation and normalization."""
    
    # Common URL schemes
    VALID_SCHEMES = {'http', 'https', 'ftp', 'ftps', 'ssh', 'telnet'}
    
    # Regex patterns for URL validation
    DOMAIN_PATTERN = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+'  # Domain
        r'[a-zA-Z]{2,}$'  # TLD
    )
    
    IP_PATTERN = re.compile(
        r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'  # IPv4
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    )
    
    @classmethod
    def normalize_url(cls, url: str) -> str:
        """Normalize URL by cleaning and standardizing format."""
        if not url or not isinstance(url, str):
            return ""
        
        # Remove common unwanted characters
        url = url.strip().replace("(", "").replace(")", "").replace("[", "").replace("]", "")
        
        # Fix multiple slashes (but preserve protocol slashes)
        url = re.sub(r'(?<!:)/{2,}', '/', url)
        
        # Add protocol if missing
        if not url.startswith(('http://', 'https://', 'ftp://', 'ftps://')):
            # Check if it looks like a domain or IP
            if cls._is_probable_domain_or_ip(url):
                url = "https://" + url
        
        # Remove trailing slashes from domain-only URLs
        parsed = urllib.parse.urlparse(url)
        if parsed.path == '/' and not parsed.query and not parsed.fragment:
            url = url.rstrip('/')
        
        return url
    
    @classmethod
    def is_valid_url(cls, url: str) -> bool:
        """Validate if URL has proper format."""
        try:
            parsed = urllib.parse.urlparse(url)
            
            # Check scheme
            if parsed.scheme.lower() not in cls.VALID_SCHEMES:
                return False
            
            # Check netloc (domain/IP)
            if not parsed.netloc:
                return False
            
            # Extract hostname (remove port if present)
            hostname = parsed.hostname
            if not hostname:
                return False
            
            # Validate domain or IP
            return (cls.DOMAIN_PATTERN.match(hostname) or 
                   cls.IP_PATTERN.match(hostname))
            
        except Exception:
            return False
    
    @classmethod
    def _is_probable_domain_or_ip(cls, text: str) -> bool:
        """Check if text looks like a domain or IP address."""
        # Remove common prefixes that might confuse detection
        text = text.lstrip('www.')
        
        # Check for domain pattern
        if cls.DOMAIN_PATTERN.match(text):
            return True
        
        # Check for IP pattern
        if cls.IP_PATTERN.match(text):
            return True
        
        # Fallback: simple heuristic
        return bool(re.search(r'\w+\.\w+', text))

class CredentialValidator:
    """Utility class for validating usernames and passwords."""
    
    # Common patterns that indicate invalid credentials
    INVALID_PATTERNS = {
        'username': [
            re.compile(r'^(null|none|empty|test|admin|user|guest)$', re.IGNORECASE),
            re.compile(r'^[\s\-_]*$'),  # Only whitespace or separators
            re.compile(r'^.{100,}$'),  # Extremely long usernames
        ],
        'password': [
            re.compile(r'^[\s\-_]*$'),  # Only whitespace or separators
            re.compile(r'^.{200,}$'),  # Extremely long passwords
        ]
    }
    
    @classmethod
    def is_valid_credential(cls, username: str, password: str) -> bool:
        """Validate if username and password seem legitimate."""
        if not username or not password:
            return False
        
        # Check username patterns
        for pattern in cls.INVALID_PATTERNS['username']:
            if pattern.match(username):
                return False
        
        # Check password patterns
        for pattern in cls.INVALID_PATTERNS['password']:
            if pattern.match(password):
                return False
        
        return True

class LeakParser:
    """Main parser class for processing leaked credential files."""
    
    # Supported file extensions
    SUPPORTED_EXTENSIONS = {'.txt', '.log', '.csv', '.dat'}
    
    # Regex patterns for different formats
    KEY_VALUE_PATTERN = re.compile(
        r'^(URL|USER|PASS|USERNAME|PASSWORD|SITE|LOGIN|EMAIL)\s*[:=]\s*(.+)$',
        re.IGNORECASE
    )
    
    def __init__(self, input_dir: str = None, output_dir: str = None, 
                 validate_credentials: bool = True, max_file_size: int = 100 * 1024 * 1024):
        """Initialize the parser with configuration."""
        self.input_dir = Path(input_dir or config.DOWNLOAD_ROOT)
        self.output_dir = Path(output_dir or config.PARSED_OUTPUT_DIR)
        self.validate_credentials = validate_credentials
        self.max_file_size = max_file_size  # 100MB default
        
        # Statistics tracking
        self.stats = {
            'files_processed': 0,
            'files_skipped': 0,
            'credentials_found': 0,
            'credentials_valid': 0,
            'errors': 0
        }
        
        # Ensure output directory exists
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"Parser initialized: {self.input_dir} -> {self.output_dir}")
    
    def parse_colon_format(self, line: str, line_number: int) -> Optional[ParsedCredential]:
        """Parse colon-separated format: url:user:pass"""
        try:
            # Split by colon but be careful with URLs that contain colons
            parts = [p.strip() for p in line.split(":") if p.strip()]
            
            if len(parts) < 3:
                return None
            
            # Handle special case: protocol:domain:port:user:pass
            if (len(parts) >= 4 and 
                parts[0].lower() in ["http", "https"] and 
                URLValidator._is_probable_domain_or_ip(parts[1])):
                
                # Reconstruct URL
                if parts[2].isdigit():  # Has port
                    url = f"{parts[0]}://{parts[1]}:{parts[2]}"
                    credentials = parts[3:]
                else:  # No port
                    url = f"{parts[0]}://{parts[1]}"
                    credentials = parts[2:]
                
                if len(credentials) != 2:
                    return None
                
                username, password = credentials
            else:
                # Find URL part
                url_idx = -1
                for i, part in enumerate(parts):
                    if (part.startswith(("http", "https", "ftp")) or 
                        URLValidator._is_probable_domain_or_ip(part)):
                        url_idx = i
                        break
                
                if url_idx == -1:
                    return None
                
                url = parts[url_idx]
                remaining = parts[:url_idx] + parts[url_idx+1:]
                
                if len(remaining) != 2:
                    return None
                
                username, password = remaining
            
            # Validate credentials if enabled
            if (self.validate_credentials and 
                not CredentialValidator.is_valid_credential(username, password)):
                return None
            
            return ParsedCredential(
                url=url,
                username=username,
                password=password,
                source_file=str(self.current_file),
                line_number=line_number,
                format_type="colon_separated"
            )
            
        except Exception as e:
            logger.debug(f"Error parsing colon format line {line_number}: {e}")
            return None
    
    def parse_key_value_format(self, lines: List[Tuple[str, int]]) -> List[ParsedCredential]:
        """Parse key-value format across multiple lines."""
        credentials = []
        buffer = {"URL": None, "USER": None, "PASS": None}
        buffer_lines = {}
        
        for line, line_number in lines:
            line = line.strip()
            if not line:
                continue
            
            match = self.KEY_VALUE_PATTERN.match(line)
            if not match:
                continue
            
            key = match.group(1).upper()
            value = match.group(2).strip()
            
            # Normalize key names
            if key in ["USERNAME", "LOGIN", "EMAIL"]:
                key = "USER"
            elif key in ["PASSWORD", "SITE"]:
                if key == "SITE":
                    key = "URL"
                else:
                    key = "PASS"
            
            if key in buffer:
                buffer[key] = value
                buffer_lines[key] = line_number
                
                # Check if we have all required fields
                if all(buffer.values()):
                    try:
                        # Validate credentials if enabled
                        if (not self.validate_credentials or 
                            CredentialValidator.is_valid_credential(buffer["USER"], buffer["PASS"])):
                            
                            credential = ParsedCredential(
                                url=buffer["URL"],
                                username=buffer["USER"],
                                password=buffer["PASS"],
                                source_file=str(self.current_file),
                                line_number=buffer_lines.get("URL", line_number),
                                format_type="key_value"
                            )
                            credentials.append(credential)
                            self.stats['credentials_valid'] += 1
                        
                        self.stats['credentials_found'] += 1
                        
                    except Exception as e:
                        logger.debug(f"Error creating credential from buffer: {e}")
                        self.stats['errors'] += 1
                    
                    # Reset buffer
                    buffer = {"URL": None, "USER": None, "PASS": None}
                    buffer_lines = {}
        
        return credentials
    
    def parse_file(self, file_path: Path) -> List[ParsedCredential]:
        """Parse a single file and extract credentials."""
        self.current_file = file_path
        credentials = []
        
        try:
            # Check file size
            if file_path.stat().st_size > self.max_file_size:
                logger.warning(f"Skipping large file: {file_path} ({file_path.stat().st_size} bytes)")
                self.stats['files_skipped'] += 1
                return []
            
            # Check if file is text-based
            mime_type, _ = mimetypes.guess_type(str(file_path))
            if mime_type and not mime_type.startswith('text'):
                logger.debug(f"Skipping non-text file: {file_path}")
                self.stats['files_skipped'] += 1
                return []
            
            # Read file with multiple encoding attempts
            encodings = ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1']
            lines_with_numbers = []
            
            for encoding in encodings:
                try:
                    with open(file_path, 'r', encoding=encoding, errors='ignore') as f:
                        lines_with_numbers = [(line, i+1) for i, line in enumerate(f)]
                    break
                except UnicodeDecodeError:
                    continue
            
            if not lines_with_numbers:
                logger.error(f"Could not read file with any encoding: {file_path}")
                self.stats['errors'] += 1
                return []
            
            # Try key-value format first (more structured)
            kv_credentials = self.parse_key_value_format(lines_with_numbers)
            credentials.extend(kv_credentials)
            
            # Try colon format for remaining lines
            for line, line_number in lines_with_numbers:
                line = line.strip()
                if not line or self.KEY_VALUE_PATTERN.match(line):
                    continue
                
                colon_credential = self.parse_colon_format(line, line_number)
                if colon_credential:
                    credentials.append(colon_credential)
                    self.stats['credentials_found'] += 1
                    self.stats['credentials_valid'] += 1
            
            self.stats['files_processed'] += 1
            logger.debug(f"Parsed {len(credentials)} credentials from {file_path}")
            
        except Exception as e:
            logger.error(f"Error parsing file {file_path}: {e}")
            self.stats['errors'] += 1
        
        return credentials
    
    def generate_unique_filename(self, source_file: Path) -> str:
        """Generate unique JSON filename based on source file."""
        # Create hash from full path for uniqueness
        path_hash = hashlib.sha256(str(source_file).encode('utf-8')).hexdigest()[:12]
        base_name = source_file.stem
        
        # Sanitize filename
        safe_name = re.sub(r'[^\w\-_.]', '_', base_name)[:50]  # Limit length
        
        return f"{safe_name}_{path_hash}.json"
    
    def save_credentials(self, credentials: List[ParsedCredential], source_file: Path) -> bool:
        """Save parsed credentials to JSON file."""
        if not credentials:
            return True
        
        try:
            output_filename = self.generate_unique_filename(source_file)
            output_path = self.output_dir / output_filename
            
            # Convert to dictionaries for JSON serialization
            data = [cred.to_dict() for cred in credentials]
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            logger.debug(f"Saved {len(credentials)} credentials to {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error saving credentials for {source_file}: {e}")
            self.stats['errors'] += 1
            return False
    
    def get_files_to_process(self) -> List[Path]:
        """Get list of files to process from input directory."""
        files = []
        
        if not self.input_dir.exists():
            logger.error(f"Input directory does not exist: {self.input_dir}")
            return files
        
        for file_path in self.input_dir.rglob('*'):
            if (file_path.is_file() and 
                file_path.suffix.lower() in self.SUPPORTED_EXTENSIONS):
                files.append(file_path)
        
        logger.info(f"Found {len(files)} files to process")
        return files
    
    def parse_directory(self) -> Dict:
        """Parse all supported files in the input directory."""
        logger.info(f"Starting directory parsing: {self.input_dir}")
        
        files = self.get_files_to_process()
        if not files:
            logger.warning("No files found to process")
            return self.stats
        
        # Process files with progress bar
        for file_path in tqdm(files, desc="Parsing files", unit="file"):
            try:
                credentials = self.parse_file(file_path)
                if credentials:
                    self.save_credentials(credentials, file_path)
                
            except Exception as e:
                logger.error(f"Unexpected error processing {file_path}: {e}")
                self.stats['errors'] += 1
        
        # Log final statistics
        logger.info("Parsing completed")
        logger.info(f"Files processed: {self.stats['files_processed']}")
        logger.info(f"Files skipped: {self.stats['files_skipped']}")
        logger.info(f"Credentials found: {self.stats['credentials_found']}")
        logger.info(f"Valid credentials: {self.stats['credentials_valid']}")
        logger.info(f"Errors: {self.stats['errors']}")
        
        return self.stats

def main():
    """Main entry point for standalone execution."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Parse leaked credential files",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        "--input", "-i",
        default="downloads",
        help="Input directory containing leaked files (default: downloads)"
    )
    
    parser.add_argument(
        "--output", "-o",
        default="parsed_leaked_json",
        help="Output directory for JSON files (default: parsed_leaked_json)"
    )
    
    parser.add_argument(
        "--no-validation",
        action="store_true",
        help="Disable credential validation"
    )
    
    parser.add_argument(
        "--max-size",
        type=int,
        default=100,
        help="Maximum file size in MB (default: 100)"
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
    
    # Initialize and run parser
    leak_parser = LeakParser(
        input_dir=args.input,
        output_dir=args.output,
        validate_credentials=not args.no_validation,
        max_file_size=args.max_size * 1024 * 1024
    )
    
    stats = leak_parser.parse_directory()
    
    # Print summary
    print("\n" + "=" * 50)
    print("PARSING SUMMARY")
    print("=" * 50)
    print(f"Files processed: {stats['files_processed']}")
    print(f"Files skipped: {stats['files_skipped']}")
    print(f"Credentials found: {stats['credentials_found']}")
    print(f"Valid credentials: {stats['credentials_valid']}")
    print(f"Errors: {stats['errors']}")
    print("=" * 50)

if __name__ == "__main__":
    main()

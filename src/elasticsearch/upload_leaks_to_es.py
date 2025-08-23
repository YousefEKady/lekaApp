#!/usr/bin/env python3
"""
Elasticsearch Upload Module - Dark Web Threat Intelligence Analyzer

This module handles uploading leak data to Elasticsearch with batch processing,
duplication detection, comprehensive error handling, and performance optimization.

Author: Yousef
Project: Dark Web Threat Intelligence Analyzer
"""

import os
import json
import hashlib
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple, Generator
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from elasticsearch.exceptions import NotFoundError, ConflictError, RequestError
    from elasticsearch.helpers import bulk, BulkIndexError
except ImportError:
    raise ImportError("elasticsearch is required. Install with: pip install elasticsearch")

from tqdm import tqdm

try:
    from src.elasticsearch.es import get_elasticsearch_manager, ElasticsearchManager
    from src.config.config import config
except ImportError:
    # Fallback for standalone execution
    from .es import get_elasticsearch_manager, ElasticsearchManager
    class Config:
        ELASTICSEARCH_INDEX = "leaks"
        ELASTICSEARCH_BATCH_SIZE = 1000
        ELASTICSEARCH_MAX_WORKERS = 4
    config = Config()

# Configure logging
logger = logging.getLogger(__name__)

@dataclass
class LeakRecord:
    """Data class representing a leak record with metadata."""
    user: str
    password: str
    url: str
    email: Optional[str] = None
    domain: Optional[str] = None
    source_file: Optional[str] = None
    timestamp: Optional[str] = None
    file_hash: Optional[str] = None
    
    def __post_init__(self):
        """Post-initialization processing."""
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()
        
        # Extract domain from URL if not provided
        if self.domain is None and self.url:
            try:
                from urllib.parse import urlparse
                parsed = urlparse(self.url if self.url.startswith(('http://', 'https://')) else f'http://{self.url}')
                self.domain = parsed.netloc.lower()
            except Exception:
                self.domain = None
        
        # Extract domain from email if not provided
        if self.email and '@' in self.email:
            email_domain = self.email.split('@')[-1].lower()
            if self.domain is None:
                self.domain = email_domain
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for Elasticsearch indexing."""
        return {
            'USER': self.user,
            'PASS': self.password,
            'URL': self.url,
            'EMAIL': self.email,
            'DOMAIN': self.domain,
            'source_file': self.source_file,
            'timestamp': self.timestamp,
            'file_hash': self.file_hash
        }
    
    def get_document_id(self) -> str:
        """Generate unique document ID based on user+password+url."""
        base = f"{self.user}:{self.password}:{self.url}"
        return hashlib.sha256(base.encode('utf-8')).hexdigest()
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any], source_file: str = None, file_hash: str = None) -> Optional['LeakRecord']:
        """Create LeakRecord from dictionary data."""
        try:
            # Handle different field name variations
            user = data.get('USER') or data.get('user') or data.get('username')
            password = data.get('PASS') or data.get('password') or data.get('pass')
            url = data.get('URL') or data.get('url') or data.get('domain')
            email = data.get('EMAIL') or data.get('email')
            domain = data.get('DOMAIN') or data.get('domain')
            
            if not all([user, password, url]):
                return None
            
            # Convert to strings and strip whitespace
            user_str = str(user).strip()
            password_str = str(password).strip()
            url_str = str(url).strip()
            
            # Basic validation at creation time
            if not user_str or not password_str or not url_str:
                return None
            
            # Filter out obvious header rows or invalid data
            if (user_str.lower() in ['user', 'username', 'login'] and 
                password_str.lower() in ['password', 'pass', 'pwd'] and 
                url_str.lower() in ['url', 'domain', 'site']):
                return None
            
            # Filter out file:// URLs and other invalid patterns
            if (config.FILTER_INVALID_URLS and 
                (url_str.lower().startswith(('file://', 'file:')) or url_str.lower() == 'url')):
                return None
            
            # Check for control characters in URL
            if (config.FILTER_CONTROL_CHARACTERS and 
                ('\t' in url_str or any(ord(c) < 32 for c in url_str if c != '\n'))):
                return None
            
            return cls(
                user=user_str,
                password=password_str,
                url=url_str,
                email=str(email).strip() if email else None,
                domain=str(domain).strip() if domain else None,
                source_file=source_file,
                file_hash=file_hash
            )
        except Exception as e:
            logger.error(f"Error creating LeakRecord from data: {e}")
            return None

class LeakValidator:
    """Utility class for validating leak data."""
    
    MIN_PASSWORD_LENGTH = 1
    MAX_PASSWORD_LENGTH = 200
    MIN_USER_LENGTH = 1
    MAX_USER_LENGTH = 100
    MIN_URL_LENGTH = 3
    MAX_URL_LENGTH = 500
    
    @classmethod
    def is_valid_leak(cls, leak: LeakRecord) -> Tuple[bool, str]:
        """Validate leak record.
        
        Returns:
            Tuple of (is_valid, reason)
        """
        # Check user
        if not leak.user or len(leak.user) < cls.MIN_USER_LENGTH:
            return False, "User too short"
        if len(leak.user) > cls.MAX_USER_LENGTH:
            return False, "User too long"
        
        # Check password
        if not leak.password or len(leak.password) < cls.MIN_PASSWORD_LENGTH:
            return False, "Password too short"
        if len(leak.password) > cls.MAX_PASSWORD_LENGTH:
            return False, "Password too long"
        
        # Check URL
        if not leak.url or len(leak.url) < cls.MIN_URL_LENGTH:
            return False, "URL too short"
        if len(leak.url) > cls.MAX_URL_LENGTH:
            return False, "URL too long"
        
        # Enhanced URL validation
        url_stripped = leak.url.strip()
        
        # Filter out invalid URL patterns
        if config.FILTER_INVALID_URLS:
            invalid_url_patterns = [
                'file://',  # File protocol URLs
                'file:',    # Incomplete file URLs
                'Username', # Header text
                'Password', # Header text
                'URL',      # Header text
            ]
            
            # Check for malformed URLs with local paths
            if ('\\Users\\' in url_stripped or 
                '\\AppData\\' in url_stripped or
                '\\Temp\\' in url_stripped or
                url_stripped.endswith('.exe') or
                url_stripped.endswith('.tmp')):
                return False, "URL contains local file path"
            
            # Check for URLs that are just numbers with protocol
            import re
            if re.match(r'^https?://\d+\.\d+$', url_stripped):
                return False, "URL appears to be malformed (protocol + numbers only)"
            
            # Check for incomplete protocols (exact match only)
            incomplete_protocols = ['https', 'http', 'ftp']
            
            for pattern in invalid_url_patterns:
                if url_stripped.lower().startswith(pattern.lower()) or url_stripped == pattern:
                    return False, f"Invalid URL pattern: {pattern}"
            
            # Check for incomplete protocols (exact match only, not startswith)
            if url_stripped.lower() in incomplete_protocols:
                return False, f"Incomplete protocol: {url_stripped}"
            
            # Check for swapped fields - URL in password field, protocol in URL field
            if (len(leak.password) > 20 and 
                ('/' in leak.password or '?' in leak.password or '=' in leak.password) and
                leak.url.lower() in ['http', 'https', 'ftp']):
                return False, "Fields appear to be swapped (URL data in password field)"
        
        # Check for malformed URLs with tab characters or control characters
        if (config.FILTER_CONTROL_CHARACTERS and 
            ('\t' in leak.url or any(ord(c) < 32 for c in leak.url if c != '\n'))):
            return False, "URL contains invalid control characters"
        
        # Check for suspiciously long tokens (like the Google example)
        if (config.FILTER_LONG_TOKENS and 
            len(leak.user) > config.MAX_TOKEN_LENGTH and 
            not '@' in leak.user):  # Likely a token, not username
            return False, "User appears to be a token rather than username"
        
        # Check for obvious test/dummy data and metadata
        dummy_patterns = [
            'test', 'example', 'dummy', 'sample', 'placeholder',
            '123456', 'password', 'admin', 'user'
        ]
        
        # Check for metadata/header terms
        metadata_patterns = [
            'title', 'name', 'description', 'header', 'column',
            'field', 'data', 'info', 'metadata', 'label'
        ]
        
        user_lower = leak.user.lower()
        pass_lower = leak.password.lower()
        url_lower = leak.url.lower()
        
        # Filter out metadata terms used as usernames
        if user_lower in metadata_patterns:
            return False, f"Username appears to be metadata: {leak.user}"
        
        # Skip obvious test data (but be conservative)
        if (user_lower in dummy_patterns and 
            pass_lower in dummy_patterns and 
            'example' in url_lower):
            return False, "Appears to be test data"
        
        # Filter out empty or whitespace-only fields
        if not leak.user.strip() or not leak.password.strip() or not leak.url.strip():
            return False, "Contains empty or whitespace-only fields"
        
        return True, "Valid"

class ElasticsearchUploader:
    """Main class for uploading leak data to Elasticsearch."""
    
    def __init__(self, 
                 es_manager: ElasticsearchManager = None,
                 index_name: str = None,
                 batch_size: int = None,
                 max_workers: int = None):
        """Initialize the uploader.
        
        Args:
            es_manager: Elasticsearch manager instance
            index_name: Target index name
            batch_size: Batch size for bulk operations
            max_workers: Maximum number of worker threads
        """
        self.es_manager = es_manager or get_elasticsearch_manager()
        self.index_name = index_name or getattr(config, 'ELASTICSEARCH_INDEX', 'leaks')
        self.batch_size = batch_size or getattr(config, 'ELASTICSEARCH_BATCH_SIZE', 1000)
        self.max_workers = max_workers or getattr(config, 'ELASTICSEARCH_MAX_WORKERS', 4)
        
        # Statistics
        self.stats = {
            'files_processed': 0,
            'records_found': 0,
            'records_valid': 0,
            'records_uploaded': 0,
            'records_skipped': 0,
            'records_failed': 0,
            'duplicates_found': 0
        }
        
        logger.info(f"Elasticsearch uploader initialized: index='{self.index_name}', batch_size={self.batch_size}")
    
    def _calculate_file_hash(self, file_path: Path) -> str:
        """Calculate SHA256 hash of file."""
        try:
            hash_sha256 = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception as e:
            logger.error(f"Error calculating hash for {file_path}: {e}")
            return ""
    
    def _load_json_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """Load and parse JSON file."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Ensure data is a list
            if isinstance(data, dict):
                data = [data]
            elif not isinstance(data, list):
                logger.error(f"Invalid JSON structure in {file_path}: expected list or dict")
                return []
            
            return data
            
        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error in {file_path}: {e}")
            return []
        except Exception as e:
            logger.error(f"Error reading {file_path}: {e}")
            return []
    
    def _process_file_data(self, file_path: Path) -> List[LeakRecord]:
        """Process a single file and extract leak records."""
        logger.debug(f"Processing file: {file_path}")
        
        # Load JSON data
        raw_data = self._load_json_file(file_path)
        if not raw_data:
            return []
        
        # Calculate file hash
        file_hash = self._calculate_file_hash(file_path)
        
        # Convert to LeakRecord objects
        leak_records = []
        for item in raw_data:
            self.stats['records_found'] += 1
            
            leak = LeakRecord.from_dict(item, str(file_path), file_hash)
            if leak is None:
                self.stats['records_failed'] += 1
                continue
            
            # Validate leak
            is_valid, reason = LeakValidator.is_valid_leak(leak)
            if not is_valid:
                logger.debug(f"Invalid leak record: {reason}")
                self.stats['records_failed'] += 1
                continue
            
            leak_records.append(leak)
            self.stats['records_valid'] += 1
        
        self.stats['files_processed'] += 1
        logger.debug(f"Processed {file_path}: {len(leak_records)} valid records")
        return leak_records
    
    def _check_existing_documents(self, leak_records: List[LeakRecord]) -> List[LeakRecord]:
        """Filter out existing documents to avoid duplicates."""
        if not leak_records:
            return []
        
        new_records = []
        
        try:
            with self.es_manager.get_client() as client:
                # Check existence in batches
                for i in range(0, len(leak_records), self.batch_size):
                    batch = leak_records[i:i + self.batch_size]
                    
                    # Prepare multi-get request
                    docs = [
                        {'_index': self.index_name, '_id': leak.get_document_id()}
                        for leak in batch
                    ]
                    
                    # Execute multi-get
                    response = self.es_manager.execute_with_retry(
                        client.mget, body={'docs': docs}
                    )
                    
                    # Filter out existing documents
                    for leak, doc_response in zip(batch, response['docs']):
                        if doc_response.get('found', False):
                            self.stats['duplicates_found'] += 1
                        else:
                            new_records.append(leak)
        
        except Exception as e:
            logger.error(f"Error checking existing documents: {e}")
            # If check fails, proceed with all records (duplicates will be handled by ES)
            return leak_records
        
        logger.debug(f"Filtered {len(leak_records) - len(new_records)} duplicates")
        return new_records
    
    def _bulk_upload_records(self, leak_records: List[LeakRecord]) -> int:
        """Upload records using bulk API."""
        if not leak_records:
            return 0
        
        uploaded_count = 0
        
        try:
            with self.es_manager.get_client() as client:
                # Prepare bulk actions
                actions = []
                for leak in leak_records:
                    action = {
                        '_index': self.index_name,
                        '_id': leak.get_document_id(),
                        '_source': leak.to_dict()
                    }
                    actions.append(action)
                
                # Execute bulk upload
                success_count, failed_items = self.es_manager.execute_with_retry(
                    bulk, client, actions, chunk_size=self.batch_size
                )
                
                uploaded_count = success_count
                
                # Handle failed items
                if failed_items:
                    logger.warning(f"Failed to upload {len(failed_items)} records")
                    for item in failed_items:
                        logger.debug(f"Failed item: {item}")
                        self.stats['records_failed'] += 1
                
        except BulkIndexError as e:
            logger.error(f"Bulk index error: {e}")
            # Count successful uploads from the error
            for error in e.errors:
                if error.get('index', {}).get('status') in [200, 201]:
                    uploaded_count += 1
                else:
                    self.stats['records_failed'] += 1
        
        except Exception as e:
            logger.error(f"Error during bulk upload: {e}")
            self.stats['records_failed'] += len(leak_records)
        
        return uploaded_count
    
    def upload_file(self, file_path: Path, check_duplicates: bool = True) -> int:
        """Upload leaks from a single file.
        
        Args:
            file_path: Path to JSON file
            check_duplicates: Whether to check for existing documents
        
        Returns:
            Number of records uploaded
        """
        logger.info(f"Uploading file: {file_path}")
        
        # Ensure index exists
        if not self.es_manager.create_index_if_not_exists(self.index_name):
            logger.error(f"Failed to create/verify index: {self.index_name}")
            return 0
        
        # Process file
        leak_records = self._process_file_data(file_path)
        if not leak_records:
            logger.warning(f"No valid records found in {file_path}")
            return 0
        
        # Check for duplicates if requested
        if check_duplicates:
            leak_records = self._check_existing_documents(leak_records)
        
        if not leak_records:
            logger.info(f"All records in {file_path} already exist")
            return 0
        
        # Upload records
        uploaded_count = self._bulk_upload_records(leak_records)
        self.stats['records_uploaded'] += uploaded_count
        
        logger.info(f"Uploaded {uploaded_count} records from {file_path}")
        return uploaded_count
    
    def upload_directory(self, directory_path: Path, 
                        pattern: str = "*.json",
                        check_duplicates: bool = True,
                        parallel: bool = True) -> int:
        """Upload leaks from all JSON files in a directory.
        
        Args:
            directory_path: Path to directory containing JSON files
            pattern: File pattern to match
            check_duplicates: Whether to check for existing documents
            parallel: Whether to process files in parallel
        
        Returns:
            Total number of records uploaded
        """
        logger.info(f"Uploading directory: {directory_path}")
        
        # Find JSON files
        json_files = list(directory_path.glob(pattern))
        if not json_files:
            logger.warning(f"No JSON files found in {directory_path}")
            return 0
        
        logger.info(f"Found {len(json_files)} JSON files")
        
        total_uploaded = 0
        
        if parallel and len(json_files) > 1:
            # Parallel processing
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                # Submit tasks
                future_to_file = {
                    executor.submit(self.upload_file, file_path, check_duplicates): file_path
                    for file_path in json_files
                }
                
                # Process results with progress bar
                with tqdm(total=len(json_files), desc="Uploading files", unit="file") as pbar:
                    for future in as_completed(future_to_file):
                        file_path = future_to_file[future]
                        try:
                            uploaded = future.result()
                            total_uploaded += uploaded
                        except Exception as e:
                            logger.error(f"Error processing {file_path}: {e}")
                        finally:
                            pbar.update(1)
        else:
            # Sequential processing
            with tqdm(json_files, desc="Uploading files", unit="file") as pbar:
                for file_path in pbar:
                    try:
                        uploaded = self.upload_file(file_path, check_duplicates)
                        total_uploaded += uploaded
                    except Exception as e:
                        logger.error(f"Error processing {file_path}: {e}")
        
        logger.info(f"Total uploaded: {total_uploaded} records from {len(json_files)} files")
        return total_uploaded
    
    def upload_path(self, path: str, check_duplicates: bool = True) -> int:
        """Upload leaks from a file or directory path.
        
        Args:
            path: Path to file or directory
            check_duplicates: Whether to check for existing documents
        
        Returns:
            Number of records uploaded
        """
        path_obj = Path(path)
        
        if not path_obj.exists():
            logger.error(f"Path does not exist: {path}")
            return 0
        
        if path_obj.is_file():
            if path_obj.suffix.lower() == '.json':
                return self.upload_file(path_obj, check_duplicates)
            else:
                logger.error(f"File is not a JSON file: {path}")
                return 0
        elif path_obj.is_dir():
            return self.upload_directory(path_obj, check_duplicates=check_duplicates)
        else:
            logger.error(f"Invalid path type: {path}")
            return 0
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get upload statistics."""
        return self.stats.copy()
    
    def print_statistics(self):
        """Print formatted statistics."""
        print("\n" + "=" * 50)
        print("ELASTICSEARCH UPLOAD STATISTICS")
        print("=" * 50)
        print(f"Files processed: {self.stats['files_processed']}")
        print(f"Records found: {self.stats['records_found']}")
        print(f"Records valid: {self.stats['records_valid']}")
        print(f"Records uploaded: {self.stats['records_uploaded']}")
        print(f"Records skipped: {self.stats['records_skipped']}")
        print(f"Records failed: {self.stats['records_failed']}")
        print(f"Duplicates found: {self.stats['duplicates_found']}")
        print("=" * 50)

# Convenience functions for backward compatibility
def should_upload(leak: Dict[str, Any]) -> bool:
    """Check if leak should be uploaded (backward compatibility)."""
    return bool(leak.get('USER')) and bool(leak.get('PASS')) and bool(leak.get('URL'))

def make_doc_id(leak: Dict[str, Any]) -> str:
    """Create document ID from leak data (backward compatibility)."""
    base = f"{leak['USER']}:{leak['PASS']}:{leak['URL']}"
    return hashlib.sha256(base.encode('utf-8')).hexdigest()

def process_file(file_path: str, index_name: str = 'leaks') -> int:
    """Process single file (backward compatibility)."""
    uploader = ElasticsearchUploader(index_name=index_name)
    return uploader.upload_file(Path(file_path))

def upload_leaks(path: str, index_name: str = 'leaks') -> int:
    """Upload leaks from path (backward compatibility)."""
    uploader = ElasticsearchUploader(index_name=index_name)
    uploaded = uploader.upload_path(path)
    uploader.print_statistics()
    return uploaded

def main():
    """Main entry point for standalone execution."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Upload leak data to Elasticsearch",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        "path",
        help="Path to JSON file or directory containing JSON files"
    )
    
    parser.add_argument(
        "--index", "-i",
        default="leaks",
        help="Elasticsearch index name (default: leaks)"
    )
    
    parser.add_argument(
        "--batch-size", "-b",
        type=int,
        default=1000,
        help="Batch size for bulk operations (default: 1000)"
    )
    
    parser.add_argument(
        "--workers", "-w",
        type=int,
        default=4,
        help="Number of worker threads (default: 4)"
    )
    
    parser.add_argument(
        "--no-duplicate-check",
        action="store_true",
        help="Skip duplicate checking (faster but may create duplicates)"
    )
    
    parser.add_argument(
        "--sequential",
        action="store_true",
        help="Process files sequentially instead of in parallel"
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
    
    # Initialize uploader
    uploader = ElasticsearchUploader(
        index_name=args.index,
        batch_size=args.batch_size,
        max_workers=args.workers
    )
    
    # Upload data
    try:
        path_obj = Path(args.path)
        
        if path_obj.is_file():
            uploaded = uploader.upload_file(
                path_obj, 
                check_duplicates=not args.no_duplicate_check
            )
        elif path_obj.is_dir():
            uploaded = uploader.upload_directory(
                path_obj,
                check_duplicates=not args.no_duplicate_check,
                parallel=not args.sequential
            )
        else:
            logger.error(f"Invalid path: {args.path}")
            return 1
        
        # Print results
        uploader.print_statistics()
        
        if uploaded > 0:
            logger.info(f"Successfully uploaded {uploaded} records")
            return 0
        else:
            logger.warning("No records were uploaded")
            return 1
            
    except Exception as e:
        logger.error(f"Upload failed: {e}")
        return 1

if __name__ == '__main__':
    exit(main())

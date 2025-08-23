#!/usr/bin/env python3
"""
Elasticsearch Client Module - Dark Web Threat Intelligence Analyzer

This module provides a robust Elasticsearch client with connection pooling,
retry logic, health monitoring, and comprehensive error handling.

Author: Yousef
Project: Dark Web Threat Intelligence Analyzer
"""

import logging
import time
from typing import Optional, Dict, Any, List
from contextlib import contextmanager
from urllib3.util.retry import Retry
from urllib3.exceptions import MaxRetryError

try:
    from elasticsearch import Elasticsearch, ConnectionError, TransportError
    from elasticsearch.exceptions import (
        NotFoundError, ConflictError, RequestError, 
        AuthenticationException, AuthorizationException
    )
except ImportError:
    raise ImportError("elasticsearch is required. Install with: pip install elasticsearch")

try:
    from src.config.config import config
except ImportError:
    # Fallback for standalone execution
    class Config:
        ELASTICSEARCH_HOST = "localhost"
        ELASTICSEARCH_PORT = 9200
        ELASTICSEARCH_INDEX = "leaks"
        ELASTICSEARCH_TIMEOUT = 30
        ELASTICSEARCH_MAX_RETRIES = 3
        ELASTICSEARCH_RETRY_DELAY = 1
    config = Config()

# Configure logging
logger = logging.getLogger(__name__)

class ElasticsearchManager:
    """Enhanced Elasticsearch client with connection management and retry logic."""
    
    def __init__(self, 
                 host: str = None,
                 port: int = None,
                 timeout: int = None,
                 max_retries: int = None,
                 retry_delay: float = None,
                 **kwargs):
        """Initialize Elasticsearch manager.
        
        Args:
            host: Elasticsearch host
            port: Elasticsearch port
            timeout: Request timeout in seconds
            max_retries: Maximum number of retry attempts
            retry_delay: Delay between retries in seconds
            **kwargs: Additional Elasticsearch client parameters
        """
        # Configuration
        self.host = host or getattr(config, 'ELASTICSEARCH_HOST', 'localhost')
        self.port = port or getattr(config, 'ELASTICSEARCH_PORT', 9200)
        self.timeout = timeout or getattr(config, 'ELASTICSEARCH_TIMEOUT', 30)
        self.max_retries = max_retries or getattr(config, 'ELASTICSEARCH_MAX_RETRIES', 3)
        self.retry_delay = retry_delay or getattr(config, 'ELASTICSEARCH_RETRY_DELAY', 1)
        
        # Build connection URL
        self.url = f"http://{self.host}:{self.port}"
        
        # Client configuration
        client_config = {
            'hosts': [self.url],
            'timeout': self.timeout,
            'max_retries': self.max_retries,
            'retry_on_timeout': True,
            'retry_on_status': [429, 502, 503, 504],  # Retry on these HTTP status codes
            **kwargs
        }
        
        # Initialize client
        self._client = None
        self._client_config = client_config
        self._connection_verified = False
        
        logger.info(f"Elasticsearch manager initialized: {self.url}")
    
    @property
    def client(self) -> Elasticsearch:
        """Get Elasticsearch client with lazy initialization."""
        if self._client is None:
            self._client = Elasticsearch(**self._client_config)
            logger.debug("Elasticsearch client created")
        return self._client
    
    def verify_connection(self) -> bool:
        """Verify Elasticsearch connection and cluster health."""
        try:
            # Test basic connectivity
            if not self.client.ping():
                logger.error("Elasticsearch ping failed")
                return False
            
            # Check cluster health
            health = self.client.cluster.health()
            status = health.get('status', 'unknown')
            
            if status == 'red':
                logger.warning(f"Elasticsearch cluster health is RED: {health}")
            elif status == 'yellow':
                logger.info(f"Elasticsearch cluster health is YELLOW: {health}")
            else:
                logger.info(f"Elasticsearch cluster health is GREEN")
            
            # Log cluster info
            info = self.client.info()
            version = info.get('version', {}).get('number', 'unknown')
            logger.info(f"Connected to Elasticsearch {version}")
            
            self._connection_verified = True
            return True
            
        except ConnectionError as e:
            logger.error(f"Elasticsearch connection error: {e}")
            return False
        except Exception as e:
            logger.error(f"Elasticsearch verification failed: {e}")
            return False
    
    def ensure_connection(self) -> bool:
        """Ensure connection is established and verified."""
        if not self._connection_verified:
            return self.verify_connection()
        return True
    
    def create_index_if_not_exists(self, index_name: str, mapping: Dict = None) -> bool:
        """Create index with optional mapping if it doesn't exist."""
        try:
            if self.client.indices.exists(index=index_name):
                logger.debug(f"Index '{index_name}' already exists")
                return True
            
            # Default mapping for leak data
            if mapping is None:
                mapping = {
                    "mappings": {
                        "properties": {
                            "USER": {"type": "keyword"},
                            "PASS": {"type": "keyword"},
                            "URL": {"type": "keyword"},
                            "EMAIL": {"type": "keyword"},
                            "DOMAIN": {"type": "keyword"},
                            "timestamp": {"type": "date"},
                            "source_file": {"type": "keyword"},
                            "file_hash": {"type": "keyword"}
                        }
                    },
                    "settings": {
                        "number_of_shards": 1,
                        "number_of_replicas": 0
                    }
                }
            
            self.client.indices.create(index=index_name, body=mapping)
            logger.info(f"Created index '{index_name}'")
            return True
            
        except ConflictError:
            # Index was created by another process
            logger.debug(f"Index '{index_name}' already exists (race condition)")
            return True
        except Exception as e:
            logger.error(f"Failed to create index '{index_name}': {e}")
            return False
    
    def execute_with_retry(self, operation, *args, **kwargs):
        """Execute Elasticsearch operation with retry logic."""
        last_exception = None
        
        for attempt in range(self.max_retries + 1):
            try:
                return operation(*args, **kwargs)
            except (ConnectionError, TransportError, MaxRetryError) as e:
                last_exception = e
                if attempt < self.max_retries:
                    wait_time = self.retry_delay * (2 ** attempt)  # Exponential backoff
                    logger.warning(
                        f"Elasticsearch operation failed (attempt {attempt + 1}/{self.max_retries + 1}): {e}. "
                        f"Retrying in {wait_time:.1f}s..."
                    )
                    time.sleep(wait_time)
                    # Reset connection verification on connection errors
                    self._connection_verified = False
                else:
                    logger.error(f"Elasticsearch operation failed after {self.max_retries + 1} attempts: {e}")
            except (AuthenticationException, AuthorizationException) as e:
                logger.error(f"Elasticsearch authentication/authorization error: {e}")
                raise
            except RequestError as e:
                logger.error(f"Elasticsearch request error: {e}")
                raise
            except Exception as e:
                logger.error(f"Unexpected Elasticsearch error: {e}")
                raise
        
        # If we get here, all retries failed
        raise last_exception
    
    @contextmanager
    def get_client(self):
        """Context manager for getting Elasticsearch client with connection verification."""
        try:
            if not self.ensure_connection():
                raise ConnectionError("Failed to establish Elasticsearch connection")
            yield self.client
        except Exception as e:
            logger.error(f"Error in Elasticsearch context manager: {e}")
            raise
    
    def get_cluster_stats(self) -> Dict[str, Any]:
        """Get comprehensive cluster statistics."""
        try:
            with self.get_client() as client:
                stats = {
                    'health': client.cluster.health(),
                    'stats': client.cluster.stats(),
                    'nodes': client.nodes.info(),
                }
                return stats
        except Exception as e:
            logger.error(f"Failed to get cluster stats: {e}")
            return {}
    
    def close(self):
        """Close Elasticsearch client connection."""
        if self._client:
            try:
                self._client.close()
                logger.info("Elasticsearch client connection closed")
            except Exception as e:
                logger.error(f"Error closing Elasticsearch client: {e}")
            finally:
                self._client = None
                self._connection_verified = False

# Global instance for backward compatibility
_es_manager = None

def get_elasticsearch_manager() -> ElasticsearchManager:
    """Get global Elasticsearch manager instance."""
    global _es_manager
    if _es_manager is None:
        _es_manager = ElasticsearchManager()
    return _es_manager

def get_elasticsearch_client() -> Elasticsearch:
    """Get Elasticsearch client (backward compatibility)."""
    return get_elasticsearch_manager().client

# Backward compatibility
es = get_elasticsearch_client()
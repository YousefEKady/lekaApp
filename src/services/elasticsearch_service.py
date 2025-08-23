#!/usr/bin/env python3
"""
Elasticsearch Service - Leka-App SaaS Edition

Service for managing Elasticsearch operations including leak search,
data indexing, and query management for the Leka-App SaaS platform.

Author: Yousef
Project: Leka-App SaaS Edition
"""

import logging
import json
import os
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from elasticsearch import Elasticsearch, exceptions as es_exceptions
from elasticsearch.helpers import bulk, scan
from src.config.config import config

logger = logging.getLogger(__name__)


class ElasticsearchService:
    """
    Service for managing Elasticsearch operations for leak data.
    """
    
    def __init__(
        self,
        hosts: List[str] = None,
        username: str = None,
        password: str = None,
        use_ssl: bool = False,
        verify_certs: bool = True,
        ca_certs: str = None,
        timeout: int = 30
    ):
        """
        Initialize Elasticsearch service.
        
        Args:
            hosts: List of Elasticsearch hosts
            username: Username for authentication
            password: Password for authentication
            use_ssl: Whether to use SSL
            verify_certs: Whether to verify SSL certificates
            ca_certs: Path to CA certificates
            timeout: Request timeout in seconds
        """
        # Default configuration
        if hosts is None:
            hosts = [config.get_elasticsearch_url()]
        
        if username is None:
            username = os.getenv('ELASTICSEARCH_USERNAME')
        
        if password is None:
            password = os.getenv('ELASTICSEARCH_PASSWORD')
        
        # Initialize Elasticsearch client
        try:
            es_config = {
                'hosts': hosts,
                'timeout': timeout,
                'max_retries': 3,
                'retry_on_timeout': True
            }
            
            # Add authentication if provided
            if username and password:
                es_config['http_auth'] = (username, password)
            
            # Add SSL configuration
            if use_ssl:
                es_config['use_ssl'] = True
                es_config['verify_certs'] = verify_certs
                if ca_certs:
                    es_config['ca_certs'] = ca_certs
            
            self.es = Elasticsearch(**es_config)
            
            # Test connection
            if self.es.ping():
                logger.info("Successfully connected to Elasticsearch")
            else:
                logger.error("Failed to connect to Elasticsearch")
                raise ConnectionError("Cannot connect to Elasticsearch")
            
        except Exception as e:
            logger.error(f"Failed to initialize Elasticsearch: {e}")
            raise
        
        # Index configuration
        self.leak_index = config.ELASTICSEARCH_INDEX
        self.company_index = "leka_companies"
        
        logger.info(f"Elasticsearch service initialized with index: {self.leak_index}")
    
    async def create_indices(self) -> bool:
        """
        Create Elasticsearch indices with proper mappings.
        
        Returns:
            True if successful, False otherwise
        """
        try:
            # Leak index mapping
            leak_mapping = {
                "mappings": {
                    "properties": {
                        "email": {
                            "type": "keyword",
                            "fields": {
                                "text": {
                                    "type": "text",
                                    "analyzer": "standard"
                                }
                            }
                        },
                        "password": {
                            "type": "keyword",
                            "index": False  # Don't index passwords for security
                        },
                        "domain": {
                            "type": "keyword",
                            "fields": {
                                "text": {
                                    "type": "text",
                                    "analyzer": "standard"
                                }
                            }
                        },
                        "username": {
                            "type": "keyword",
                            "fields": {
                                "text": {
                                    "type": "text",
                                    "analyzer": "standard"
                                }
                            }
                        },
                        "source": {
                            "type": "keyword"
                        },
                        "breach_date": {
                            "type": "date"
                        },
                        "upload_date": {
                            "type": "date"
                        },
                        "metadata": {
                            "type": "object",
                            "enabled": True
                        },
                        "hash": {
                            "type": "keyword"
                        },
                        "verified": {
                            "type": "boolean"
                        }
                    }
                },
                "settings": {
                    "number_of_shards": 3,
                    "number_of_replicas": 1,
                    "analysis": {
                        "analyzer": {
                            "email_analyzer": {
                                "type": "custom",
                                "tokenizer": "keyword",
                                "filter": ["lowercase"]
                            }
                        }
                    }
                }
            }
            
            # Create leak index
            if not self.es.indices.exists(index=self.leak_index):
                self.es.indices.create(index=self.leak_index, body=leak_mapping)
                logger.info(f"Created leak index: {self.leak_index}")
            
            # Company index mapping
            company_mapping = {
                "mappings": {
                    "properties": {
                        "company_id": {
                            "type": "integer"
                        },
                        "domains": {
                            "type": "keyword"
                        },
                        "last_scan": {
                            "type": "date"
                        },
                        "alert_count": {
                            "type": "integer"
                        },
                        "status": {
                            "type": "keyword"
                        }
                    }
                }
            }
            
            # Create company index
            if not self.es.indices.exists(index=self.company_index):
                self.es.indices.create(index=self.company_index, body=company_mapping)
                logger.info(f"Created company index: {self.company_index}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to create indices: {e}")
            return False
    
    async def search_leaks_by_domain(
        self,
        domain: str,
        limit: int = 100,
        offset: int = 0,
        date_from: Optional[datetime] = None,
        date_to: Optional[datetime] = None,
        source_filter: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Search for leaks by domain.
        
        Args:
            domain: Domain to search for
            limit: Maximum number of results
            offset: Offset for pagination
            date_from: Start date filter
            date_to: End date filter
            source_filter: Source filter
        
        Returns:
            Dictionary containing search results and metadata
        """
        try:
            # Build query
            query = {
                "bool": {
                    "must": [
                        {
                            "wildcard": {
                                "email": f"*@{domain}"
                            }
                        }
                    ]
                }
            }
            
            # Add date filters
            if date_from or date_to:
                date_range = {}
                if date_from:
                    date_range["gte"] = date_from.isoformat()
                if date_to:
                    date_range["lte"] = date_to.isoformat()
                
                query["bool"]["must"].append({
                    "range": {
                        "upload_date": date_range
                    }
                })
            
            # Add source filter
            if source_filter:
                query["bool"]["must"].append({
                    "term": {
                        "source": source_filter
                    }
                })
            
            # Execute search
            search_body = {
                "query": query,
                "sort": [
                    {"upload_date": {"order": "desc"}}
                ],
                "from": offset,
                "size": limit,
                "_source": {
                    "excludes": ["password"]  # Exclude passwords from results
                }
            }
            
            response = self.es.search(
                index=self.leak_index,
                body=search_body
            )
            
            # Process results
            hits = response["hits"]
            results = {
                "total": hits["total"]["value"] if isinstance(hits["total"], dict) else hits["total"],
                "leaks": [],
                "aggregations": {},
                "query_time": response["took"]
            }
            
            for hit in hits["hits"]:
                leak_data = hit["_source"]
                leak_data["id"] = hit["_id"]
                leak_data["score"] = hit["_score"]
                results["leaks"].append(leak_data)
            
            logger.info(f"Found {results['total']} leaks for domain: {domain}")
            return results
            
        except Exception as e:
            logger.error(f"Failed to search leaks for domain {domain}: {e}")
            raise
    
    async def search_leaks_by_email(
        self,
        email: str,
        exact_match: bool = True
    ) -> Dict[str, Any]:
        """
        Search for leaks by email address.
        
        Args:
            email: Email address to search for
            exact_match: Whether to use exact match or fuzzy search
        
        Returns:
            Dictionary containing search results
        """
        try:
            if exact_match:
                query = {
                    "term": {
                        "email": email.lower()
                    }
                }
            else:
                query = {
                    "fuzzy": {
                        "email": {
                            "value": email.lower(),
                            "fuzziness": "AUTO"
                        }
                    }
                }
            
            search_body = {
                "query": query,
                "sort": [
                    {"upload_date": {"order": "desc"}}
                ],
                "_source": {
                    "excludes": ["password"]
                }
            }
            
            response = self.es.search(
                index=self.leak_index,
                body=search_body
            )
            
            # Process results
            hits = response["hits"]
            results = {
                "total": hits["total"]["value"] if isinstance(hits["total"], dict) else hits["total"],
                "leaks": [],
                "query_time": response["took"]
            }
            
            for hit in hits["hits"]:
                leak_data = hit["_source"]
                leak_data["id"] = hit["_id"]
                leak_data["score"] = hit["_score"]
                results["leaks"].append(leak_data)
            
            logger.info(f"Found {results['total']} leaks for email: {email}")
            return results
            
        except Exception as e:
            logger.error(f"Failed to search leaks for email {email}: {e}")
            raise
    
    async def bulk_index_leaks(self, leaks: List[Dict[str, Any]]) -> Tuple[int, List[str]]:
        """
        Bulk index leak data.
        
        Args:
            leaks: List of leak documents to index
        
        Returns:
            Tuple of (successful_count, error_list)
        """
        try:
            # Prepare documents for bulk indexing
            actions = []
            for leak in leaks:
                # Add metadata
                leak["upload_date"] = datetime.utcnow().isoformat()
                
                # Extract domain from email
                if "email" in leak and "@" in leak["email"]:
                    leak["domain"] = leak["email"].split("@")[1].lower()
                
                action = {
                    "_index": self.leak_index,
                    "_source": leak
                }
                
                # Add ID if provided
                if "id" in leak:
                    action["_id"] = leak["id"]
                    del leak["id"]
                
                actions.append(action)
            
            # Execute bulk indexing
            success_count, errors = bulk(
                self.es,
                actions,
                chunk_size=1000,
                request_timeout=60
            )
            
            error_messages = []
            for error in errors:
                if "error" in error:
                    error_messages.append(str(error["error"]))
            
            logger.info(f"Bulk indexed {success_count} leaks with {len(error_messages)} errors")
            return success_count, error_messages
            
        except Exception as e:
            logger.error(f"Failed to bulk index leaks: {e}")
            raise
    
    async def get_leak_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about the leak database.
        
        Returns:
            Dictionary containing various statistics
        """
        try:
            # Get total count
            total_response = self.es.count(index=self.leak_index)
            total_leaks = total_response["count"]
            
            # Get aggregations
            agg_body = {
                "size": 0,
                "aggs": {
                    "domains": {
                        "terms": {
                            "field": "domain",
                            "size": 10
                        }
                    },
                    "sources": {
                        "terms": {
                            "field": "source",
                            "size": 10
                        }
                    },
                    "upload_dates": {
                        "date_histogram": {
                            "field": "upload_date",
                            "calendar_interval": "day",
                            "format": "yyyy-MM-dd"
                        }
                    }
                }
            }
            
            agg_response = self.es.search(
                index=self.leak_index,
                body=agg_body
            )
            
            aggregations = agg_response["aggregations"]
            
            statistics = {
                "total_leaks": total_leaks,
                "top_domains": [
                    {"domain": bucket["key"], "count": bucket["doc_count"]}
                    for bucket in aggregations["domains"]["buckets"]
                ],
                "top_sources": [
                    {"source": bucket["key"], "count": bucket["doc_count"]}
                    for bucket in aggregations["sources"]["buckets"]
                ],
                "daily_uploads": [
                    {"date": bucket["key_as_string"], "count": bucket["doc_count"]}
                    for bucket in aggregations["upload_dates"]["buckets"]
                ],
                "index_size": self._get_index_size(),
                "last_updated": datetime.utcnow().isoformat()
            }
            
            return statistics
            
        except Exception as e:
            logger.error(f"Failed to get leak statistics: {e}")
            raise
    
    def _get_index_size(self) -> str:
        """
        Get the size of the leak index.
        
        Returns:
            Human-readable size string
        """
        try:
            stats = self.es.indices.stats(index=self.leak_index)
            size_bytes = stats["indices"][self.leak_index]["total"]["store"]["size_in_bytes"]
            
            # Convert to human-readable format
            for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
                if size_bytes < 1024.0:
                    return f"{size_bytes:.1f} {unit}"
                size_bytes /= 1024.0
            
            return f"{size_bytes:.1f} PB"
            
        except Exception as e:
            logger.warning(f"Failed to get index size: {e}")
            return "Unknown"
    
    async def health_check(self) -> Dict[str, Any]:
        """
        Check Elasticsearch health.
        
        Returns:
            Dictionary containing health information
        """
        try:
            # Check cluster health
            cluster_health = self.es.cluster.health()
            
            # Check if indices exist
            leak_index_exists = self.es.indices.exists(index=self.leak_index)
            company_index_exists = self.es.indices.exists(index=self.company_index)
            
            # Get node info
            nodes_info = self.es.nodes.info()
            
            health_info = {
                "status": "healthy" if cluster_health["status"] in ["green", "yellow"] else "unhealthy",
                "cluster_name": cluster_health["cluster_name"],
                "cluster_status": cluster_health["status"],
                "number_of_nodes": cluster_health["number_of_nodes"],
                "number_of_data_nodes": cluster_health["number_of_data_nodes"],
                "active_primary_shards": cluster_health["active_primary_shards"],
                "active_shards": cluster_health["active_shards"],
                "indices": {
                    "leak_index_exists": leak_index_exists,
                    "company_index_exists": company_index_exists
                },
                "nodes": len(nodes_info["nodes"]),
                "timestamp": datetime.utcnow().isoformat()
            }
            
            return health_info
            
        except Exception as e:
            logger.error(f"Elasticsearch health check failed: {e}")
            return {
                "status": "unhealthy",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
    
    async def delete_leak(self, leak_id: str) -> bool:
        """
        Delete a specific leak by ID.
        
        Args:
            leak_id: ID of the leak to delete
        
        Returns:
            True if successful, False otherwise
        """
        try:
            response = self.es.delete(
                index=self.leak_index,
                id=leak_id
            )
            
            logger.info(f"Deleted leak: {leak_id}")
            return response["result"] == "deleted"
            
        except es_exceptions.NotFoundError:
            logger.warning(f"Leak not found for deletion: {leak_id}")
            return False
        except Exception as e:
            logger.error(f"Failed to delete leak {leak_id}: {e}")
            return False
    
    async def close(self):
        """
        Close the Elasticsearch connection.
        """
        try:
            if hasattr(self.es, 'transport'):
                self.es.transport.close()
            logger.info("Elasticsearch connection closed")
        except Exception as e:
            logger.error(f"Error closing Elasticsearch connection: {e}")
"""Leak Service for Leka-App SaaS Edition.

Handles leak data processing, searching, and management operations.
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
import json
import hashlib

from sqlalchemy.orm import Session
from elasticsearch import AsyncElasticsearch

from src.database.models import User, Company, Domain, AuditLog
from src.database.connection import get_db
from .elasticsearch_service import ElasticsearchService
from .notification_service import get_notification_service, LeakAlert
from src.config.config import config

logger = logging.getLogger(__name__)


class LeakData:
    """Represents a single leak entry."""
    
    def __init__(self, email: str, password: str, source: str = "unknown", 
                 metadata: Optional[Dict[str, Any]] = None):
        self.email = email
        self.password = password
        self.source = source
        self.metadata = metadata or {}
        self.domain = self._extract_domain(email)
        self.hash_id = self._generate_hash()
        self.created_at = datetime.utcnow()
    
    def _extract_domain(self, email: str) -> str:
        """Extract domain from email address."""
        try:
            return email.split('@')[1].lower()
        except (IndexError, AttributeError):
            return "unknown"
    
    def _generate_hash(self) -> str:
        """Generate unique hash for the leak entry."""
        content = f"{self.email}:{self.password}:{self.source}"
        return hashlib.sha256(content.encode()).hexdigest()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert leak data to dictionary for Elasticsearch indexing."""
        return {
            "email": self.email,
            "password": self.password,
            "domain": self.domain,
            "source": self.source,
            "hash_id": self.hash_id,
            "created_at": self.created_at.isoformat(),
            "metadata": self.metadata
        }


class LeakSearchFilter:
    """Filter options for leak searches."""
    
    def __init__(self, 
                 domains: Optional[List[str]] = None,
                 emails: Optional[List[str]] = None,
                 sources: Optional[List[str]] = None,
                 date_from: Optional[datetime] = None,
                 date_to: Optional[datetime] = None,
                 limit: int = 100,
                 offset: int = 0):
        self.domains = domains or []
        self.emails = emails or []
        self.sources = sources or []
        self.date_from = date_from
        self.date_to = date_to
        self.limit = min(limit, 1000)  # Cap at 1000 results
        self.offset = offset


class LeakSearchResult:
    """Result of a leak search operation."""
    
    def __init__(self, leaks: List[Dict[str, Any]], total_count: int, 
                 search_time_ms: float, filters_applied: LeakSearchFilter):
        self.leaks = leaks
        self.total_count = total_count
        self.search_time_ms = search_time_ms
        self.filters_applied = filters_applied
        self.has_more = (filters_applied.offset + len(leaks)) < total_count


class LeakUploadResult:
    """Result of a leak upload operation."""
    
    def __init__(self, success: bool, processed_count: int = 0, 
                 failed_count: int = 0, errors: Optional[List[str]] = None,
                 upload_id: Optional[str] = None):
        self.success = success
        self.processed_count = processed_count
        self.failed_count = failed_count
        self.errors = errors or []
        self.upload_id = upload_id
        self.total_count = processed_count + failed_count


class LeakService:
    """Service for managing leak data and operations."""
    
    def __init__(self, elasticsearch_service: ElasticsearchService):
        self.es_service = elasticsearch_service
        self.notification_service = None
        
    async def initialize(self):
        """Initialize the leak service."""
        try:
            # Initialize Elasticsearch service
            await self.es_service.initialize()
            
            # Get notification service
            try:
                self.notification_service = get_notification_service()
            except RuntimeError:
                logger.warning("Notification service not available")
                
            logger.info("Leak service initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize leak service: {str(e)}")
            raise
    
    async def upload_leaks_from_file(self, file_path: str, source: str = "manual_upload", 
                                   user_id: Optional[int] = None) -> LeakUploadResult:
        """Upload leaks from a file."""
        try:
            start_time = datetime.utcnow()
            upload_id = hashlib.sha256(f"{file_path}:{start_time.isoformat()}".encode()).hexdigest()[:16]
            
            logger.info(f"Starting leak upload from file: {file_path} (ID: {upload_id})")
            
            # Parse file and extract leaks
            leaks = await self._parse_leak_file(file_path, source)
            
            if not leaks:
                return LeakUploadResult(
                    success=False,
                    errors=["No valid leaks found in file"]
                )
            
            # Upload to Elasticsearch
            upload_result = await self._bulk_upload_leaks(leaks)
            
            # Log upload activity
            if user_id:
                await self._log_upload_activity(
                    user_id=user_id,
                    upload_id=upload_id,
                    file_path=file_path,
                    result=upload_result
                )
            
            # Check for new alerts
            if upload_result.success and upload_result.processed_count > 0:
                await self._check_and_send_alerts(leaks)
            
            logger.info(f"Leak upload completed: {upload_result.processed_count} processed, {upload_result.failed_count} failed")
            
            return LeakUploadResult(
                success=upload_result.success,
                processed_count=upload_result.processed_count,
                failed_count=upload_result.failed_count,
                errors=upload_result.errors,
                upload_id=upload_id
            )
            
        except Exception as e:
            logger.error(f"Failed to upload leaks from file {file_path}: {str(e)}")
            return LeakUploadResult(
                success=False,
                errors=[f"Upload failed: {str(e)}"]
            )
    
    async def search_leaks(self, search_filter: LeakSearchFilter, 
                          user_id: Optional[int] = None) -> LeakSearchResult:
        """Search for leaks based on filter criteria."""
        try:
            start_time = datetime.utcnow()
            
            # Build Elasticsearch query
            query = await self._build_search_query(search_filter)
            
            # Execute search
            results = await self.es_service.search_leaks(
                query=query,
                size=search_filter.limit,
                from_=search_filter.offset
            )
            
            # Process results
            leaks = []
            for hit in results.get('hits', {}).get('hits', []):
                leak_data = hit['_source']
                leak_data['_id'] = hit['_id']
                leak_data['_score'] = hit['_score']
                leaks.append(leak_data)
            
            total_count = results.get('hits', {}).get('total', {}).get('value', 0)
            search_time = (datetime.utcnow() - start_time).total_seconds() * 1000
            
            # Log search activity
            if user_id:
                await self._log_search_activity(user_id, search_filter, len(leaks), total_count)
            
            return LeakSearchResult(
                leaks=leaks,
                total_count=total_count,
                search_time_ms=search_time,
                filters_applied=search_filter
            )
            
        except Exception as e:
            logger.error(f"Failed to search leaks: {str(e)}")
            return LeakSearchResult(
                leaks=[],
                total_count=0,
                search_time_ms=0,
                filters_applied=search_filter
            )
    
    async def get_leak_statistics(self, company_id: Optional[int] = None) -> Dict[str, Any]:
        """Get leak statistics for a company or overall system."""
        try:
            if company_id:
                # Get company domains
                async with get_db() as db:
                    company = db.query(Company).filter(Company.id == company_id).first()
                    if not company:
                        return {"error": "Company not found"}
                    
                    domains = [domain.domain_name for domain in company.domains]
                    
                    if not domains:
                        return {
                            "total_leaks": 0,
                            "domains_monitored": 0,
                            "recent_leaks": 0,
                            "top_sources": [],
                            "domain_breakdown": {}
                        }
                    
                    # Get statistics for company domains
                    stats = await self.es_service.get_leak_statistics(domains=domains)
            else:
                # Get overall system statistics
                stats = await self.es_service.get_leak_statistics()
            
            return stats
            
        except Exception as e:
            logger.error(f"Failed to get leak statistics: {str(e)}")
            return {"error": str(e)}
    
    async def delete_leak(self, leak_id: str, user_id: int) -> bool:
        """Delete a specific leak entry."""
        try:
            success = await self.es_service.delete_leak(leak_id)
            
            if success:
                # Log deletion activity
                await self._log_deletion_activity(user_id, leak_id)
                logger.info(f"Leak {leak_id} deleted by user {user_id}")
            
            return success
            
        except Exception as e:
            logger.error(f"Failed to delete leak {leak_id}: {str(e)}")
            return False
    
    async def _parse_leak_file(self, file_path: str, source: str) -> List[LeakData]:
        """Parse leak file and extract leak data."""
        leaks = []
        file_path_obj = Path(file_path)
        
        if not file_path_obj.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                for line_num, line in enumerate(file, 1):
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    # Try different formats
                    leak_data = self._parse_leak_line(line, source, line_num)
                    if leak_data:
                        leaks.append(leak_data)
                    
                    # Limit processing for very large files
                    if len(leaks) >= 100000:  # 100k limit
                        logger.warning(f"Reached maximum leak limit (100k) for file {file_path}")
                        break
            
            logger.info(f"Parsed {len(leaks)} leaks from {file_path}")
            return leaks
            
        except Exception as e:
            logger.error(f"Failed to parse leak file {file_path}: {str(e)}")
            raise
    
    def _parse_leak_line(self, line: str, source: str, line_num: int) -> Optional[LeakData]:
        """Parse a single line from leak file."""
        try:
            # Try colon-separated format: email:password
            if ':' in line:
                parts = line.split(':', 1)
                if len(parts) == 2:
                    email, password = parts
                    email = email.strip()
                    password = password.strip()
                    
                    # Basic email validation
                    if '@' in email and '.' in email.split('@')[1]:
                        return LeakData(
                            email=email,
                            password=password,
                            source=source,
                            metadata={"line_number": line_num}
                        )
            
            # Try JSON format
            elif line.startswith('{'):
                data = json.loads(line)
                if 'email' in data and 'password' in data:
                    return LeakData(
                        email=data['email'],
                        password=data['password'],
                        source=data.get('source', source),
                        metadata={**data, "line_number": line_num}
                    )
            
            return None
            
        except Exception as e:
            logger.debug(f"Failed to parse line {line_num}: {str(e)}")
            return None
    
    async def _bulk_upload_leaks(self, leaks: List[LeakData]) -> LeakUploadResult:
        """Upload leaks to Elasticsearch in bulk."""
        try:
            # Convert to documents
            documents = [leak.to_dict() for leak in leaks]
            
            # Upload in batches
            batch_size = 1000
            total_processed = 0
            total_failed = 0
            errors = []
            
            for i in range(0, len(documents), batch_size):
                batch = documents[i:i + batch_size]
                
                try:
                    result = await self.es_service.bulk_index_leaks(batch)
                    
                    if result.get('errors'):
                        # Count failed items
                        failed_items = [item for item in result['items'] if 'error' in item.get('index', {})]
                        total_failed += len(failed_items)
                        total_processed += len(batch) - len(failed_items)
                        
                        # Collect error messages
                        for item in failed_items:
                            error_msg = item.get('index', {}).get('error', {}).get('reason', 'Unknown error')
                            errors.append(f"Batch {i//batch_size + 1}: {error_msg}")
                    else:
                        total_processed += len(batch)
                    
                except Exception as e:
                    total_failed += len(batch)
                    errors.append(f"Batch {i//batch_size + 1} failed: {str(e)}")
                    logger.error(f"Failed to upload batch {i//batch_size + 1}: {str(e)}")
            
            success = total_processed > 0
            
            return LeakUploadResult(
                success=success,
                processed_count=total_processed,
                failed_count=total_failed,
                errors=errors[:10]  # Limit error messages
            )
            
        except Exception as e:
            logger.error(f"Failed to bulk upload leaks: {str(e)}")
            return LeakUploadResult(
                success=False,
                failed_count=len(leaks),
                errors=[str(e)]
            )
    
    async def _build_search_query(self, search_filter: LeakSearchFilter) -> Dict[str, Any]:
        """Build Elasticsearch query from search filter."""
        query = {
            "bool": {
                "must": [],
                "filter": []
            }
        }
        
        # Domain filters
        if search_filter.domains:
            query["bool"]["filter"].append({
                "terms": {"domain": search_filter.domains}
            })
        
        # Email filters
        if search_filter.emails:
            query["bool"]["filter"].append({
                "terms": {"email": search_filter.emails}
            })
        
        # Source filters
        if search_filter.sources:
            query["bool"]["filter"].append({
                "terms": {"source": search_filter.sources}
            })
        
        # Date range filter
        if search_filter.date_from or search_filter.date_to:
            date_range = {}
            if search_filter.date_from:
                date_range["gte"] = search_filter.date_from.isoformat()
            if search_filter.date_to:
                date_range["lte"] = search_filter.date_to.isoformat()
            
            query["bool"]["filter"].append({
                "range": {"created_at": date_range}
            })
        
        # If no filters, match all
        if not query["bool"]["must"] and not query["bool"]["filter"]:
            return {"match_all": {}}
        
        return query
    
    async def _check_and_send_alerts(self, leaks: List[LeakData]) -> None:
        """Check for new leaks and send alerts to affected companies."""
        if not self.notification_service:
            return
        
        try:
            # Group leaks by domain
            domain_leaks = {}
            for leak in leaks:
                domain = leak.domain
                if domain not in domain_leaks:
                    domain_leaks[domain] = []
                domain_leaks[domain].append(leak)
            
            # Check each domain against monitored companies
            async with get_db() as db:
                for domain, domain_leak_list in domain_leaks.items():
                    # Find companies monitoring this domain
                    monitored_domains = (
                        db.query(Domain)
                        .filter(Domain.domain_name == domain)
                        .all()
                    )
                    
                    for monitored_domain in monitored_domains:
                        company = monitored_domain.company
                        users = company.users
                        
                        # Create leak alert
                        leak_alert = LeakAlert(
                            company_name=company.name,
                            domain=domain,
                            leak_count=len(domain_leak_list),
                            leak_details=[leak.to_dict() for leak in domain_leak_list[:5]],  # Limit details
                            detected_at=datetime.utcnow(),
                            severity="high" if len(domain_leak_list) > 10 else "medium"
                        )
                        
                        # Send alerts to all company users
                        for user in users:
                            try:
                                await self.notification_service.send_leak_alert(
                                    user_email=user.email,
                                    company_name=company.name,
                                    leak_alert=leak_alert
                                )
                            except Exception as e:
                                logger.error(f"Failed to send alert to {user.email}: {str(e)}")
            
        except Exception as e:
            logger.error(f"Failed to check and send alerts: {str(e)}")
    
    async def _log_upload_activity(self, user_id: int, upload_id: str, 
                                 file_path: str, result: LeakUploadResult) -> None:
        """Log upload activity to audit log."""
        try:
            async with get_db() as db:
                audit_log = AuditLog(
                    user_id=user_id,
                    action="leak_upload",
                    resource_type="leak_file",
                    resource_id=upload_id,
                    details={
                        "file_path": file_path,
                        "processed_count": result.processed_count,
                        "failed_count": result.failed_count,
                        "success": result.success,
                        "errors": result.errors[:5]  # Limit error details
                    }
                )
                
                db.add(audit_log)
                db.commit()
                
        except Exception as e:
            logger.error(f"Failed to log upload activity: {str(e)}")
    
    async def _log_search_activity(self, user_id: int, search_filter: LeakSearchFilter, 
                                 results_count: int, total_count: int) -> None:
        """Log search activity to audit log."""
        try:
            async with get_db() as db:
                audit_log = AuditLog(
                    user_id=user_id,
                    action="leak_search",
                    resource_type="leak_data",
                    details={
                        "domains": search_filter.domains,
                        "sources": search_filter.sources,
                        "results_count": results_count,
                        "total_count": total_count,
                        "limit": search_filter.limit,
                        "offset": search_filter.offset
                    }
                )
                
                db.add(audit_log)
                db.commit()
                
        except Exception as e:
            logger.error(f"Failed to log search activity: {str(e)}")
    
    async def _log_deletion_activity(self, user_id: int, leak_id: str) -> None:
        """Log leak deletion activity to audit log."""
        try:
            async with get_db() as db:
                audit_log = AuditLog(
                    user_id=user_id,
                    action="leak_delete",
                    resource_type="leak_entry",
                    resource_id=leak_id,
                    details={"leak_id": leak_id}
                )
                
                db.add(audit_log)
                db.commit()
                
        except Exception as e:
            logger.error(f"Failed to log deletion activity: {str(e)}")


# Global leak service instance
leak_service: Optional[LeakService] = None


def get_leak_service() -> LeakService:
    """Get leak service instance."""
    global leak_service
    if leak_service is None:
        raise RuntimeError("Leak service not initialized")
    return leak_service


def initialize_leak_service(elasticsearch_service: ElasticsearchService) -> None:
    """Initialize leak service with Elasticsearch service."""
    global leak_service
    leak_service = LeakService(elasticsearch_service)
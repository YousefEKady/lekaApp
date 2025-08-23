"""Company Service for Leka-App SaaS Edition.

Handles company management, domain operations, and user management.
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, func

from ..database.models import (
    User, Company, Domain, AuditLog, Notification,
    UserRole, CompanyStatus, NotificationStatus
)
from ..database.connection import get_db
from ..api.auth import PasswordManager
from .notification_service import get_notification_service
from src.config.config import config

logger = logging.getLogger(__name__)


class CompanyRegistrationData:
    """Data structure for company registration."""
    
    def __init__(self, name: str, email: str, password: str, 
                 contact_person: str, phone: Optional[str] = None,
                 initial_domains: Optional[List[str]] = None):
        self.name = name
        self.email = email
        self.password = password
        self.contact_person = contact_person
        self.phone = phone
        self.initial_domains = initial_domains or []


class CompanyUpdateData:
    """Data structure for company updates."""
    
    def __init__(self, name: Optional[str] = None, 
                 contact_person: Optional[str] = None,
                 phone: Optional[str] = None,
                 status: Optional[CompanyStatus] = None):
        self.name = name
        self.contact_person = contact_person
        self.phone = phone
        self.status = status


class DomainData:
    """Data structure for domain information."""
    
    def __init__(self, domain_name: str, description: Optional[str] = None,
                 monitoring_enabled: bool = True):
        self.domain_name = domain_name.lower().strip()
        self.description = description
        self.monitoring_enabled = monitoring_enabled


class CompanyStats:
    """Company statistics data structure."""
    
    def __init__(self, total_domains: int = 0, active_domains: int = 0,
                 total_leaks: int = 0, recent_leaks: int = 0,
                 total_notifications: int = 0, unread_notifications: int = 0):
        self.total_domains = total_domains
        self.active_domains = active_domains
        self.total_leaks = total_leaks
        self.recent_leaks = recent_leaks
        self.total_notifications = total_notifications
        self.unread_notifications = unread_notifications


class CompanyService:
    """Service for managing company operations."""
    
    def __init__(self):
        self.password_manager = PasswordManager()
        self.notification_service = None
        
    async def initialize(self):
        """Initialize the company service."""
        try:
            # Get notification service
            try:
                self.notification_service = get_notification_service()
            except RuntimeError:
                logger.warning("Notification service not available")
                
            logger.info("Company service initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize company service: {str(e)}")
            raise
    
    async def register_company(self, registration_data: CompanyRegistrationData,
                             admin_user_id: Optional[int] = None) -> Tuple[bool, str, Optional[int]]:
        """Register a new company with initial user."""
        try:
            async with get_db() as db:
                # Check if company email already exists
                existing_user = db.query(User).filter(User.email == registration_data.email).first()
                if existing_user:
                    return False, "Email already registered", None
                
                # Check if company name already exists
                existing_company = db.query(Company).filter(Company.name == registration_data.name).first()
                if existing_company:
                    return False, "Company name already exists", None
                
                # Create company
                company = Company(
                    name=registration_data.name,
                    contact_person=registration_data.contact_person,
                    phone=registration_data.phone,
                    status=CompanyStatus.ACTIVE
                )
                
                db.add(company)
                db.flush()  # Get company ID
                
                # Create admin user for the company
                hashed_password = self.password_manager.hash_password(registration_data.password)
                
                user = User(
                    email=registration_data.email,
                    password_hash=hashed_password,
                    company_id=company.id,
                    role=UserRole.COMPANY_ADMIN,
                    is_active=True
                )
                
                db.add(user)
                db.flush()  # Get user ID
                
                # Add initial domains if provided
                for domain_name in registration_data.initial_domains:
                    if self._is_valid_domain(domain_name):
                        domain = Domain(
                            domain_name=domain_name.lower().strip(),
                            company_id=company.id,
                            added_by_user_id=user.id,
                            monitoring_enabled=True
                        )
                        db.add(domain)
                
                # Log registration activity
                if admin_user_id:
                    audit_log = AuditLog(
                        user_id=admin_user_id,
                        action="company_register",
                        resource_type="company",
                        resource_id=str(company.id),
                        details={
                            "company_name": company.name,
                            "admin_email": user.email,
                            "initial_domains": registration_data.initial_domains
                        }
                    )
                    db.add(audit_log)
                
                db.commit()
                
                # Send welcome notification
                if self.notification_service:
                    try:
                        await self.notification_service.send_welcome_notification(
                            user_email=user.email,
                            company_name=company.name
                        )
                    except Exception as e:
                        logger.error(f"Failed to send welcome notification: {str(e)}")
                
                logger.info(f"Company {company.name} registered successfully with ID {company.id}")
                return True, "Company registered successfully", company.id
                
        except Exception as e:
            logger.error(f"Failed to register company: {str(e)}")
            return False, f"Registration failed: {str(e)}", None
    
    async def get_company(self, company_id: int) -> Optional[Dict[str, Any]]:
        """Get company information by ID."""
        try:
            async with get_db() as db:
                company = (
                    db.query(Company)
                    .filter(Company.id == company_id)
                    .first()
                )
                
                if not company:
                    return None
                
                # Get company statistics
                stats = await self._get_company_statistics(db, company_id)
                
                return {
                    "id": company.id,
                    "name": company.name,
                    "contact_person": company.contact_person,
                    "phone": company.phone,
                    "status": company.status.value,
                    "created_at": company.created_at.isoformat(),
                    "updated_at": company.updated_at.isoformat(),
                    "statistics": {
                        "total_domains": stats.total_domains,
                        "active_domains": stats.active_domains,
                        "total_users": len(company.users),
                        "total_notifications": stats.total_notifications,
                        "unread_notifications": stats.unread_notifications
                    },
                    "domains": [
                        {
                            "id": domain.id,
                            "domain_name": domain.domain_name,
                            "description": domain.description,
                            "monitoring_enabled": domain.monitoring_enabled,
                            "added_at": domain.created_at.isoformat()
                        }
                        for domain in company.domains
                    ],
                    "users": [
                        {
                            "id": user.id,
                            "email": user.email,
                            "role": user.role.value,
                            "is_active": user.is_active,
                            "last_login": user.last_login.isoformat() if user.last_login else None,
                            "created_at": user.created_at.isoformat()
                        }
                        for user in company.users
                    ]
                }
                
        except Exception as e:
            logger.error(f"Failed to get company {company_id}: {str(e)}")
            return None
    
    async def update_company(self, company_id: int, update_data: CompanyUpdateData,
                           admin_user_id: int) -> Tuple[bool, str]:
        """Update company information."""
        try:
            async with get_db() as db:
                company = db.query(Company).filter(Company.id == company_id).first()
                if not company:
                    return False, "Company not found"
                
                # Store original values for audit log
                original_values = {
                    "name": company.name,
                    "contact_person": company.contact_person,
                    "phone": company.phone,
                    "status": company.status.value
                }
                
                # Update fields
                updated_fields = []
                if update_data.name is not None:
                    company.name = update_data.name
                    updated_fields.append("name")
                
                if update_data.contact_person is not None:
                    company.contact_person = update_data.contact_person
                    updated_fields.append("contact_person")
                
                if update_data.phone is not None:
                    company.phone = update_data.phone
                    updated_fields.append("phone")
                
                if update_data.status is not None:
                    company.status = update_data.status
                    updated_fields.append("status")
                
                company.updated_at = datetime.utcnow()
                
                # Log update activity
                audit_log = AuditLog(
                    user_id=admin_user_id,
                    action="company_update",
                    resource_type="company",
                    resource_id=str(company.id),
                    details={
                        "updated_fields": updated_fields,
                        "original_values": original_values,
                        "new_values": {
                            "name": company.name,
                            "contact_person": company.contact_person,
                            "phone": company.phone,
                            "status": company.status.value
                        }
                    }
                )
                db.add(audit_log)
                
                db.commit()
                
                logger.info(f"Company {company_id} updated successfully")
                return True, "Company updated successfully"
                
        except Exception as e:
            logger.error(f"Failed to update company {company_id}: {str(e)}")
            return False, f"Update failed: {str(e)}"
    
    async def delete_company(self, company_id: int, admin_user_id: int) -> Tuple[bool, str]:
        """Delete a company and all associated data."""
        try:
            async with get_db() as db:
                company = db.query(Company).filter(Company.id == company_id).first()
                if not company:
                    return False, "Company not found"
                
                # Store company info for audit log
                company_info = {
                    "name": company.name,
                    "contact_person": company.contact_person,
                    "user_count": len(company.users),
                    "domain_count": len(company.domains)
                }
                
                # Delete associated data (cascading should handle this, but explicit for clarity)
                # Delete notifications
                db.query(Notification).filter(Notification.company_id == company_id).delete()
                
                # Delete audit logs for company users
                user_ids = [user.id for user in company.users]
                if user_ids:
                    db.query(AuditLog).filter(AuditLog.user_id.in_(user_ids)).delete()
                
                # Delete domains
                db.query(Domain).filter(Domain.company_id == company_id).delete()
                
                # Delete users
                db.query(User).filter(User.company_id == company_id).delete()
                
                # Delete company
                db.delete(company)
                
                # Log deletion activity
                audit_log = AuditLog(
                    user_id=admin_user_id,
                    action="company_delete",
                    resource_type="company",
                    resource_id=str(company_id),
                    details=company_info
                )
                db.add(audit_log)
                
                db.commit()
                
                logger.info(f"Company {company_id} deleted successfully")
                return True, "Company deleted successfully"
                
        except Exception as e:
            logger.error(f"Failed to delete company {company_id}: {str(e)}")
            return False, f"Deletion failed: {str(e)}"
    
    async def list_companies(self, limit: int = 50, offset: int = 0,
                           status_filter: Optional[CompanyStatus] = None) -> Dict[str, Any]:
        """List companies with pagination and filtering."""
        try:
            async with get_db() as db:
                query = db.query(Company)
                
                # Apply status filter
                if status_filter:
                    query = query.filter(Company.status == status_filter)
                
                # Get total count
                total_count = query.count()
                
                # Apply pagination
                companies = (
                    query.order_by(Company.created_at.desc())
                    .offset(offset)
                    .limit(limit)
                    .all()
                )
                
                # Format results
                company_list = []
                for company in companies:
                    stats = await self._get_company_statistics(db, company.id)
                    
                    company_list.append({
                        "id": company.id,
                        "name": company.name,
                        "contact_person": company.contact_person,
                        "phone": company.phone,
                        "status": company.status.value,
                        "created_at": company.created_at.isoformat(),
                        "updated_at": company.updated_at.isoformat(),
                        "statistics": {
                            "total_domains": stats.total_domains,
                            "active_domains": stats.active_domains,
                            "total_users": len(company.users),
                            "total_notifications": stats.total_notifications
                        }
                    })
                
                return {
                    "companies": company_list,
                    "total_count": total_count,
                    "limit": limit,
                    "offset": offset,
                    "has_more": (offset + len(company_list)) < total_count
                }
                
        except Exception as e:
            logger.error(f"Failed to list companies: {str(e)}")
            return {
                "companies": [],
                "total_count": 0,
                "limit": limit,
                "offset": offset,
                "has_more": False,
                "error": str(e)
            }
    
    async def add_domain(self, company_id: int, domain_data: DomainData,
                        user_id: int) -> Tuple[bool, str, Optional[int]]:
        """Add a domain to a company."""
        try:
            if not self._is_valid_domain(domain_data.domain_name):
                return False, "Invalid domain format", None
            
            async with get_db() as db:
                # Check if company exists
                company = db.query(Company).filter(Company.id == company_id).first()
                if not company:
                    return False, "Company not found", None
                
                # Check if domain already exists for this company
                existing_domain = (
                    db.query(Domain)
                    .filter(
                        and_(
                            Domain.company_id == company_id,
                            Domain.domain_name == domain_data.domain_name
                        )
                    )
                    .first()
                )
                
                if existing_domain:
                    return False, "Domain already exists for this company", None
                
                # Create domain
                domain = Domain(
                    domain_name=domain_data.domain_name,
                    description=domain_data.description,
                    company_id=company_id,
                    added_by_user_id=user_id,
                    monitoring_enabled=domain_data.monitoring_enabled
                )
                
                db.add(domain)
                db.flush()  # Get domain ID
                
                # Log activity
                audit_log = AuditLog(
                    user_id=user_id,
                    action="domain_add",
                    resource_type="domain",
                    resource_id=str(domain.id),
                    details={
                        "domain_name": domain.domain_name,
                        "company_id": company_id,
                        "monitoring_enabled": domain.monitoring_enabled
                    }
                )
                db.add(audit_log)
                
                db.commit()
                
                logger.info(f"Domain {domain_data.domain_name} added to company {company_id}")
                return True, "Domain added successfully", domain.id
                
        except Exception as e:
            logger.error(f"Failed to add domain: {str(e)}")
            return False, f"Failed to add domain: {str(e)}", None
    
    async def update_domain(self, domain_id: int, domain_data: DomainData,
                          user_id: int) -> Tuple[bool, str]:
        """Update domain information."""
        try:
            async with get_db() as db:
                domain = db.query(Domain).filter(Domain.id == domain_id).first()
                if not domain:
                    return False, "Domain not found"
                
                # Store original values
                original_values = {
                    "description": domain.description,
                    "monitoring_enabled": domain.monitoring_enabled
                }
                
                # Update fields
                domain.description = domain_data.description
                domain.monitoring_enabled = domain_data.monitoring_enabled
                domain.updated_at = datetime.utcnow()
                
                # Log activity
                audit_log = AuditLog(
                    user_id=user_id,
                    action="domain_update",
                    resource_type="domain",
                    resource_id=str(domain.id),
                    details={
                        "domain_name": domain.domain_name,
                        "original_values": original_values,
                        "new_values": {
                            "description": domain.description,
                            "monitoring_enabled": domain.monitoring_enabled
                        }
                    }
                )
                db.add(audit_log)
                
                db.commit()
                
                logger.info(f"Domain {domain_id} updated successfully")
                return True, "Domain updated successfully"
                
        except Exception as e:
            logger.error(f"Failed to update domain {domain_id}: {str(e)}")
            return False, f"Update failed: {str(e)}"
    
    async def delete_domain(self, domain_id: int, user_id: int) -> Tuple[bool, str]:
        """Delete a domain from a company."""
        try:
            async with get_db() as db:
                domain = db.query(Domain).filter(Domain.id == domain_id).first()
                if not domain:
                    return False, "Domain not found"
                
                domain_info = {
                    "domain_name": domain.domain_name,
                    "company_id": domain.company_id,
                    "monitoring_enabled": domain.monitoring_enabled
                }
                
                # Delete domain
                db.delete(domain)
                
                # Log activity
                audit_log = AuditLog(
                    user_id=user_id,
                    action="domain_delete",
                    resource_type="domain",
                    resource_id=str(domain_id),
                    details=domain_info
                )
                db.add(audit_log)
                
                db.commit()
                
                logger.info(f"Domain {domain_id} deleted successfully")
                return True, "Domain deleted successfully"
                
        except Exception as e:
            logger.error(f"Failed to delete domain {domain_id}: {str(e)}")
            return False, f"Deletion failed: {str(e)}"
    
    async def get_company_domains(self, company_id: int) -> List[Dict[str, Any]]:
        """Get all domains for a company."""
        try:
            async with get_db() as db:
                domains = (
                    db.query(Domain)
                    .filter(Domain.company_id == company_id)
                    .order_by(Domain.created_at.desc())
                    .all()
                )
                
                return [
                    {
                        "id": domain.id,
                        "domain_name": domain.domain_name,
                        "description": domain.description,
                        "monitoring_enabled": domain.monitoring_enabled,
                        "created_at": domain.created_at.isoformat(),
                        "updated_at": domain.updated_at.isoformat(),
                        "added_by": {
                            "id": domain.added_by_user.id,
                            "email": domain.added_by_user.email
                        } if domain.added_by_user else None
                    }
                    for domain in domains
                ]
                
        except Exception as e:
            logger.error(f"Failed to get domains for company {company_id}: {str(e)}")
            return []
    
    def _is_valid_domain(self, domain: str) -> bool:
        """Validate domain format."""
        import re
        
        # Basic domain validation regex
        domain_pattern = re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+'  # Subdomains
            r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'  # Main domain
        )
        
        return bool(domain_pattern.match(domain)) and len(domain) <= 253
    
    async def _get_company_statistics(self, db: Session, company_id: int) -> CompanyStats:
        """Get statistics for a company."""
        try:
            # Get domain statistics
            total_domains = db.query(Domain).filter(Domain.company_id == company_id).count()
            active_domains = (
                db.query(Domain)
                .filter(
                    and_(
                        Domain.company_id == company_id,
                        Domain.monitoring_enabled == True
                    )
                )
                .count()
            )
            
            # Get notification statistics
            total_notifications = (
                db.query(Notification)
                .filter(Notification.company_id == company_id)
                .count()
            )
            
            unread_notifications = (
                db.query(Notification)
                .filter(
                    and_(
                        Notification.company_id == company_id,
                        Notification.status == NotificationStatus.SENT
                    )
                )
                .count()
            )
            
            return CompanyStats(
                total_domains=total_domains,
                active_domains=active_domains,
                total_notifications=total_notifications,
                unread_notifications=unread_notifications
            )
            
        except Exception as e:
            logger.error(f"Failed to get company statistics: {str(e)}")
            return CompanyStats()


# Global company service instance
company_service: Optional[CompanyService] = None


def get_company_service() -> CompanyService:
    """Get company service instance."""
    global company_service
    if company_service is None:
        raise RuntimeError("Company service not initialized")
    return company_service


def initialize_company_service() -> None:
    """Initialize company service."""
    global company_service
    company_service = CompanyService()
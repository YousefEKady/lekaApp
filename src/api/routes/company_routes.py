#!/usr/bin/env python3
"""
Company Routes - Leka-App SaaS Edition

API endpoints for company users including domain management,
leak search, dashboard data, and notification settings.

Author: Yousef
Project: Leka-App SaaS Edition
"""

import logging
from datetime import datetime
from typing import List, Dict, Any, Optional

from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from sqlalchemy.orm import Session
from pydantic import BaseModel, validator

try:
    from src.api.auth import get_current_company_user, TokenData
    from src.database.connection import get_db
    from src.database.models import Domain, Company, Notification, AuditLog, DomainStatus
    from src.services.company_service import get_company_service, DomainData
    from src.services.elasticsearch_service import get_elasticsearch_service
except ImportError as e:
    logging.error(f"Import error in company_routes: {e}")
    # Create placeholder classes for development
    class TokenData(BaseModel):
        user_id: int
        email: str
        role: str
        company_id: Optional[int] = None
    
    # Placeholder function for get_db
    def get_db():
        raise HTTPException(status_code=500, detail="Database not configured")
    
    # Placeholder function for get_current_company_user
    def get_current_company_user():
        raise HTTPException(status_code=500, detail="Auth not configured")
    
    # Placeholder classes
    class Domain:
        pass
    class Company:
        pass
    class Notification:
        pass
    class AuditLog:
        pass
    class DomainStatus:
        ACTIVE = "active"
        INACTIVE = "inactive"
    
    class DomainData:
        pass
    
    # Placeholder services
    def get_company_service():
        raise HTTPException(status_code=500, detail="Company service not configured")
    
    def get_elasticsearch_service(request: Request = None):
        """Get Elasticsearch service from app state."""
        if request and hasattr(request.app.state, 'elasticsearch_service'):
            return request.app.state.elasticsearch_service
        raise HTTPException(status_code=500, detail="Elasticsearch service not configured")

logger = logging.getLogger(__name__)

# Create router
router = APIRouter(prefix="/company", tags=["Company Management"])


class DomainAddRequest(BaseModel):
    """Domain addition request model."""
    domain_name: str
    monitor_subdomains: bool = True
    
    @validator('domain_name')
    def validate_domain_name(cls, v):
        # Basic domain validation
        domain = v.strip().lower()
        if not domain:
            raise ValueError('Domain name cannot be empty')
        if len(domain) > 255:
            raise ValueError('Domain name too long')
        if domain.startswith('http://') or domain.startswith('https://'):
            raise ValueError('Domain name should not include protocol')
        if '/' in domain:
            raise ValueError('Domain name should not include path')
        return domain


class DomainUpdateRequest(BaseModel):
    """Domain update request model."""
    monitor_subdomains: Optional[bool] = None
    status: Optional[str] = None
    
    @validator('status')
    def validate_status(cls, v):
        if v and v not in ['active', 'inactive', 'pending']:
            raise ValueError('Invalid status')
        return v


class LeakSearchRequest(BaseModel):
    """Leak search request model."""
    domain: Optional[str] = None
    email: Optional[str] = None
    username: Optional[str] = None
    limit: int = 50
    offset: int = 0
    
    @validator('limit')
    def validate_limit(cls, v):
        if v < 1 or v > 1000:
            raise ValueError('Limit must be between 1 and 1000')
        return v


class NotificationSettingsRequest(BaseModel):
    """Notification settings request model."""
    email_notifications: bool = True
    telegram_notifications: bool = False
    telegram_chat_id: Optional[str] = None


@router.get("/dashboard")
async def get_dashboard_data(
    current_user: TokenData = Depends(get_current_company_user),
    db: Session = Depends(get_db)
):
    """Get company dashboard data including domains, recent leaks, and statistics."""
    try:
        logger.info(f"Dashboard data request from company user: {current_user.email}")
        
        if not current_user.company_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User not associated with a company"
            )
        
        # Get company service
        company_service = get_company_service()
        
        # Get company information
        company_info = await company_service.get_company(current_user.company_id)
        if not company_info:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Company not found"
            )
        
        # Get recent domains (limit to 5 for dashboard)
        domains = await company_service.get_company_domains(current_user.company_id)
        recent_domains = domains[:5]  # Show only first 5 domains
        
        # Get recent notifications (limit to 5 for dashboard)
        recent_notifications = (
            db.query(Notification)
            .filter(Notification.company_id == current_user.company_id)
            .order_by(Notification.created_at.desc())
            .limit(5)
            .all()
        )
        
        dashboard_data = {
            "company_info": {
                "id": company_info["id"],
                "name": company_info["name"],
                "status": company_info["status"],
                "created_at": company_info["created_at"]
            },
            "statistics": company_info["statistics"],
            "recent_domains": [
                {
                    "id": domain["id"],
                    "domain_name": domain["domain_name"],
                    "monitoring_enabled": domain["monitoring_enabled"],
                    "created_at": domain["created_at"]
                }
                for domain in recent_domains
            ],
            "recent_notifications": [
                {
                    "id": notification.id,
                    "title": notification.title,
                    "message": notification.message,
                    "status": notification.status.value,
                    "created_at": notification.created_at.isoformat()
                }
                for notification in recent_notifications
            ]
        }
        
        return dashboard_data
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Dashboard data error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get dashboard data"
        )


@router.get("/domains")
async def get_domains(
    current_user: TokenData = Depends(get_current_company_user),
    db: Session = Depends(get_db),
    status_filter: Optional[str] = Query(None, description="Filter by domain status"),
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0)
):
    """Get company domains with optional filtering."""
    try:
        logger.info(f"Domains request from company user: {current_user.email}")
        
        if not current_user.company_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User not associated with a company"
            )
        
        # Get company service
        company_service = get_company_service()
        
        # Get all domains for the company
        all_domains = await company_service.get_company_domains(current_user.company_id)
        
        # Apply status filter if provided
        if status_filter:
            filtered_domains = [
                domain for domain in all_domains 
                if domain.get("monitoring_enabled") == (status_filter == "active")
            ]
        else:
            filtered_domains = all_domains
        
        # Apply pagination
        total_count = len(filtered_domains)
        paginated_domains = filtered_domains[offset:offset + limit]
        
        return {
            "domains": paginated_domains,
            "total_count": total_count,
            "limit": limit,
            "offset": offset,
            "has_more": (offset + len(paginated_domains)) < total_count
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get domains error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get domains"
        )


@router.post("/domains")
async def add_domain(
    request: Request,
    domain_data: DomainAddRequest,
    current_user: TokenData = Depends(get_current_company_user),
    db: Session = Depends(get_db)
):
    """Add a new domain for monitoring."""
    try:
        logger.info(f"Add domain request: {domain_data.domain_name} from user: {current_user.email}")
        
        if not current_user.company_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User not associated with a company"
            )
        
        # Get company service
        company_service = get_company_service()
        
        # Create domain data object
        domain_obj = DomainData(
            domain_name=domain_data.domain_name,
            description=None,
            monitoring_enabled=domain_data.monitor_subdomains
        )
        
        # Add domain using company service
        success, message, domain_id = await company_service.add_domain(
            company_id=current_user.company_id,
            domain_data=domain_obj,
            user_id=current_user.user_id
        )
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=message
            )
        
        # Get the created domain details
        domains = await company_service.get_company_domains(current_user.company_id)
        created_domain = next((d for d in domains if d["id"] == domain_id), None)
        
        if not created_domain:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Domain created but could not retrieve details"
            )
        
        logger.info(f"Domain added successfully: {domain_data.domain_name}")
        return {
            "id": created_domain["id"],
            "domain_name": created_domain["domain_name"],
            "description": created_domain["description"],
            "monitoring_enabled": created_domain["monitoring_enabled"],
            "created_at": created_domain["created_at"],
            "message": message
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Add domain error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to add domain"
        )


@router.put("/domains/{domain_id}")
async def update_domain(
    request: Request,
    domain_id: int,
    domain_data: DomainUpdateRequest,
    current_user: TokenData = Depends(get_current_company_user),
    db: Session = Depends(get_db)
):
    """Update domain settings."""
    try:
        logger.info(f"Update domain request: {domain_id} from user: {current_user.email}")
        
        if not current_user.company_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User not associated with a company"
            )
        
        # Get company service
        company_service = get_company_service()
        
        # First, verify the domain belongs to the user's company
        domains = await company_service.get_company_domains(current_user.company_id)
        domain = next((d for d in domains if d["id"] == domain_id), None)
        
        if not domain:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Domain not found or does not belong to your company"
            )
        
        # Create domain data object with updates
        domain_obj = DomainData(
            domain_name=domain["domain_name"],  # Keep existing domain name
            description=domain.get("description"),  # Keep existing description
            monitoring_enabled=domain_data.monitor_subdomains if domain_data.monitor_subdomains is not None else domain["monitoring_enabled"]
        )
        
        # Update domain using company service
        success, message = await company_service.update_domain(
            domain_id=domain_id,
            domain_data=domain_obj,
            user_id=current_user.user_id
        )
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=message
            )
        
        logger.info(f"Domain updated successfully: {domain_id}")
        return {"message": message, "domain_id": domain_id}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Update domain error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update domain"
        )


@router.delete("/domains/{domain_id}")
async def delete_domain(
    request: Request,
    domain_id: int,
    current_user: TokenData = Depends(get_current_company_user),
    db: Session = Depends(get_db)
):
    """Delete a domain from monitoring."""
    try:
        logger.info(f"Delete domain request: {domain_id} from user: {current_user.email}")
        
        if not current_user.company_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User not associated with a company"
            )
        
        # Get company service
        company_service = get_company_service()
        
        # First, verify the domain belongs to the user's company
        domains = await company_service.get_company_domains(current_user.company_id)
        domain = next((d for d in domains if d["id"] == domain_id), None)
        
        if not domain:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Domain not found or does not belong to your company"
            )
        
        # Delete domain using company service
        success, message = await company_service.delete_domain(
            domain_id=domain_id,
            user_id=current_user.user_id
        )
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=message
            )
        
        logger.info(f"Domain deleted successfully: {domain_id}")
        return {"message": message, "domain_id": domain_id}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Delete domain error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete domain"
        )


@router.post("/search-leaks")
async def search_leaks(
    search_data: LeakSearchRequest,
    current_user: TokenData = Depends(get_current_company_user),
    db: Session = Depends(get_db)
):
    """Search for leaks containing company domains or specific criteria."""
    try:
        logger.info(f"Leak search request from user: {current_user.email}")
        
        if not current_user.company_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User not associated with a company"
            )
        
        # Get company service to retrieve company domains
        company_service = get_company_service()
        company_domains = await company_service.get_company_domains(current_user.company_id)
        
        # Extract domain names for search filtering
        allowed_domains = [domain["domain_name"] for domain in company_domains]
        
        # If no specific domain is provided, search across all company domains
        search_domains = [search_data.domain] if search_data.domain else allowed_domains
        
        # Validate that the requested domain belongs to the company
        if search_data.domain and search_data.domain not in allowed_domains:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You can only search for leaks in your company's domains"
            )
        
        # Get Elasticsearch service
        es_service = get_elasticsearch_service()
        
        # Perform the search
        search_results = await es_service.search_leaks(
            domains=search_domains,
            email=search_data.email,
            username=search_data.username,
            limit=search_data.limit,
            offset=search_data.offset
        )
        
        # Add search criteria to response
        search_results["search_criteria"] = {
            "domain": search_data.domain,
            "email": search_data.email,
            "username": search_data.username
        }
        
        logger.info(f"Leak search completed for user: {current_user.email}, found {search_results.get('total_results', 0)} results")
        return search_results
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Leak search error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to search leaks"
        )


@router.get("/notifications")
async def get_notifications(
    current_user: TokenData = Depends(get_current_company_user),
    db: Session = Depends(get_db),
    unread_only: bool = Query(False, description="Get only unread notifications"),
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0)
):
    """Get company notifications and alerts."""
    try:
        logger.info(f"Notifications request from user: {current_user.email}")
        
        if not current_user.company_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User not associated with a company"
            )
        
        # Build query for notifications
        query = db.query(Notification).filter(
            Notification.company_id == current_user.company_id
        )
        
        # Apply unread filter if requested
        if unread_only:
            query = query.filter(Notification.read_at.is_(None))
        
        # Get total count before pagination
        total = query.count()
        
        # Get unread count
        unread_count = db.query(Notification).filter(
            Notification.company_id == current_user.company_id,
            Notification.read_at.is_(None)
        ).count()
        
        # Apply pagination and ordering
        notifications_db = query.order_by(
            Notification.created_at.desc()
        ).offset(offset).limit(limit).all()
        
        # Convert to response format
        notifications = []
        for notif in notifications_db:
            notifications.append({
                "id": notif.id,
                "title": notif.title,
                "message": notif.message,
                "notification_type": notif.notification_type,
                "status": "read" if notif.read_at else "unread",
                "domain_affected": notif.domain_affected,
                "created_at": notif.created_at.isoformat() if notif.created_at else None,
                "read_at": notif.read_at.isoformat() if notif.read_at else None
            })
        
        return {
            "notifications": notifications,
            "total": total,
            "unread_count": unread_count,
            "limit": limit,
            "offset": offset
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get notifications error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get notifications"
        )


@router.put("/notifications/{notification_id}/read")
async def mark_notification_read(
    notification_id: int,
    current_user: TokenData = Depends(get_current_company_user),
    db: Session = Depends(get_db)
):
    """Mark a notification as read."""
    try:
        logger.info(f"Mark notification read: {notification_id} from user: {current_user.email}")
        
        if not current_user.company_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User not associated with a company"
            )
        
        # Find the notification and verify it belongs to the user's company
        notification = db.query(Notification).filter(
            Notification.id == notification_id,
            Notification.company_id == current_user.company_id
        ).first()
        
        if not notification:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Notification not found or does not belong to your company"
            )
        
        # Mark as read if not already read
        if not notification.read_at:
            notification.read_at = datetime.utcnow()
            db.commit()
            logger.info(f"Notification marked as read: {notification_id}")
            return {"message": "Notification marked as read"}
        else:
            return {"message": "Notification was already read"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Mark notification read error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to mark notification as read"
        )


@router.get("/settings")
async def get_notification_settings(
    current_user: TokenData = Depends(get_current_company_user),
    db: Session = Depends(get_db)
):
    """Get company notification settings."""
    try:
        if not current_user.company_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User not associated with a company"
            )
        
        # Get company from database
        company = db.query(Company).filter(Company.id == current_user.company_id).first()
        
        if not company:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Company not found"
            )
        
        settings = {
            "email_notifications": company.email_notifications,
            "telegram_notifications": company.telegram_notifications,
            "telegram_chat_id": company.telegram_chat_id,
            "notification_frequency": "immediate",  # Default value
            "alert_threshold": 1  # Default value
        }
        
        return settings
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get notification settings error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get notification settings"
        )


@router.put("/settings")
async def update_notification_settings(
    request: Request,
    settings_data: NotificationSettingsRequest,
    current_user: TokenData = Depends(get_current_company_user),
    db: Session = Depends(get_db)
):
    """Update company notification settings."""
    try:
        logger.info(f"Update notification settings from user: {current_user.email}")
        
        if not current_user.company_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User not associated with a company"
            )
        
        # Get company from database
        company = db.query(Company).filter(Company.id == current_user.company_id).first()
        
        if not company:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Company not found"
            )
        
        # Update company notification settings
        company.email_notifications = settings_data.email_notifications
        company.telegram_notifications = settings_data.telegram_notifications
        company.telegram_chat_id = settings_data.telegram_chat_id
        
        # Validate Telegram chat ID if Telegram notifications are enabled
        if settings_data.telegram_notifications and not settings_data.telegram_chat_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Telegram chat ID is required when Telegram notifications are enabled"
            )
        
        db.commit()
        
        # Create audit log
        try:
            audit_log = AuditLog(
                action="settings_update",
                resource_type="company",
                resource_id=current_user.company_id,
                user_id=current_user.user_id,
                details=settings_data.dict(),
                ip_address=request.client.host if request.client else None,
                user_agent=request.headers.get("user-agent")
            )
            db.add(audit_log)
            db.commit()
        except Exception as e:
            logger.warning(f"Failed to create audit log: {e}")
        
        logger.info(f"Notification settings updated for user: {current_user.email}")
        return {"message": "Notification settings updated successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Update notification settings error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update notification settings"
        )
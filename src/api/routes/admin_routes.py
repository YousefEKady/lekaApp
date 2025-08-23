#!/usr/bin/env python3
"""
Admin Routes - Leka-App SaaS Edition

API endpoints for super admin users including company management,
leak upload, automation control, and system analytics.

Author: Yousef
Project: Leka-App SaaS Edition
"""

import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional

from fastapi import APIRouter, Depends, HTTPException, status, Query, Request, UploadFile, File
from sqlalchemy.orm import Session
from sqlalchemy import func
from pydantic import BaseModel, EmailStr, validator

try:
    from src.api.auth import get_current_admin, TokenData
    from src.database.connection import get_db
    from src.database.models import User, Company, Domain, AuditLog, SystemSettings, CompanyStatus
except ImportError as e:
    logging.error(f"Import error in admin_routes: {e}")
    # Create placeholder classes for development
    class TokenData(BaseModel):
        user_id: int
        email: str
        role: str
        company_id: Optional[int] = None
    
    # Placeholder function for get_db
    def get_db():
        raise HTTPException(status_code=500, detail="Database not configured")
    
    # Placeholder function for get_current_admin
    def get_current_admin():
        raise HTTPException(status_code=500, detail="Auth not configured")
    
    # Placeholder classes
    class User:
        pass
    class Company:
        pass
    class Domain:
        pass
    class AuditLog:
        pass
    class SystemSettings:
        pass
    class CompanyStatus:
        ACTIVE = "active"
        INACTIVE = "inactive"
        SUSPENDED = "suspended"

logger = logging.getLogger(__name__)

# Create router
router = APIRouter(prefix="/admin", tags=["Super Admin"])


class CompanyCreateRequest(BaseModel):
    """Company creation request model."""
    name: str
    description: str = ""
    contact_email: EmailStr
    status: str = "active"
    
    @validator('name')
    def validate_name(cls, v):
        if len(v.strip()) < 2:
            raise ValueError('Company name must be at least 2 characters long')
        return v.strip()
    
    @validator('status')
    def validate_status(cls, v):
        if v not in ['active', 'suspended', 'pending', 'deleted']:
            raise ValueError('Invalid status')
        return v


class CompanyUpdateRequest(BaseModel):
    """Company update request model."""
    name: Optional[str] = None
    description: Optional[str] = None
    contact_email: Optional[EmailStr] = None
    status: Optional[str] = None
    email_notifications: Optional[bool] = None
    telegram_notifications: Optional[bool] = None
    
    @validator('status')
    def validate_status(cls, v):
        if v and v not in ['active', 'suspended', 'pending', 'deleted']:
            raise ValueError('Invalid status')
        return v


class UserCreateRequest(BaseModel):
    """User creation request model."""
    email: EmailStr
    full_name: str
    role: str
    company_id: Optional[int] = None
    password: str
    
    @validator('role')
    def validate_role(cls, v):
        if v not in ['company_user', 'super_admin']:
            raise ValueError('Invalid role')
        return v
    
    @validator('password')
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        return v


class SystemSettingRequest(BaseModel):
    """System setting request model."""
    key: str
    value: str
    description: Optional[str] = None


class AutomationControlRequest(BaseModel):
    """Automation control request model."""
    automation_type: str  # 'telegram', 'dark_web', 'all'
    action: str  # 'start', 'stop', 'restart'
    
    @validator('automation_type')
    def validate_automation_type(cls, v):
        if v not in ['telegram', 'dark_web', 'all']:
            raise ValueError('Invalid automation type')
        return v
    
    @validator('action')
    def validate_action(cls, v):
        if v not in ['start', 'stop', 'restart']:
            raise ValueError('Invalid action')
        return v


@router.get("/dashboard")
async def get_admin_dashboard(
    current_user: TokenData = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """Get admin dashboard with system statistics and overview."""
    try:
        logger.info(f"Admin dashboard request from user: {current_user.email}")
        
        # Get actual system statistics from database
        total_companies = db.query(Company).count()
        active_companies = db.query(Company).filter(Company.status == CompanyStatus.ACTIVE).count()
        suspended_companies = db.query(Company).filter(Company.status == CompanyStatus.SUSPENDED).count()
        pending_companies = db.query(Company).filter(Company.status == CompanyStatus.PENDING).count()
        
        total_users = db.query(User).count()
        total_domains = db.query(Domain).count()
        
        # Calculate leaks this month (placeholder - would need actual leak data)
        current_month_start = datetime.now().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        
        # Get recent audit logs for activity feed
        recent_logs = db.query(AuditLog).join(User, AuditLog.user_id == User.id).order_by(AuditLog.created_at.desc()).limit(10).all()
        
        recent_activity = []
        for log in recent_logs:
            activity = {
                "id": log.id,
                "action": log.action,
                "details": log.details or f"{log.action} on {log.resource_type}",
                "timestamp": log.created_at.isoformat(),
                "user": log.user.email if log.user else "System"
            }
            recent_activity.append(activity)
        
        dashboard_data = {
            "system_stats": {
                "total_companies": total_companies,
                "active_companies": active_companies,
                "suspended_companies": suspended_companies,
                "pending_companies": pending_companies,
                "total_users": total_users,
                "total_domains": total_domains,
                "total_leaks": 0,  # Placeholder - would need leak database
                "leaks_this_month": 0,  # Placeholder - would need leak database
                "system_uptime": "Running",  # Placeholder
                "last_backup": datetime.now().isoformat()
            },
            "recent_activity": recent_activity,
            "automation_status": {
                "telegram_scraping": {
                    "status": "running",
                    "last_run": "2024-01-15T10:00:00Z",
                    "next_run": "2024-01-15T11:00:00Z",
                    "items_processed": 45
                },
                "dark_web_monitoring": {
                    "status": "stopped",
                    "last_run": "2024-01-14T22:00:00Z",
                    "next_run": None,
                    "items_processed": 0
                }
            },
            "alerts": [
                {
                    "type": "warning",
                    "message": "Elasticsearch storage is 85% full",
                    "timestamp": "2024-01-15T08:00:00Z"
                }
            ]
        }
        
        return dashboard_data
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Admin dashboard error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get admin dashboard"
        )


@router.get("/companies")
async def get_companies(
    current_user: TokenData = Depends(get_current_admin),
    db: Session = Depends(get_db),
    status_filter: Optional[str] = Query(None, description="Filter by company status"),
    search: Optional[str] = Query(None, description="Search by company name or email"),
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0)
):
    """Get all companies with filtering and pagination."""
    try:
        logger.info(f"Get companies request from admin: {current_user.email}")
        
        # Build query with filters
        query = db.query(Company)
        
        # Apply status filter
        if status_filter:
            try:
                status_enum = CompanyStatus(status_filter)
                query = query.filter(Company.status == status_enum)
            except ValueError:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid status filter: {status_filter}"
                )
        
        # Apply search filter
        if search:
            search_term = f"%{search}%"
            query = query.filter(
                (Company.name.ilike(search_term)) |
                (Company.contact_email.ilike(search_term))
            )
        
        # Get total count before pagination
        total = query.count()
        
        # Apply pagination and get results
        companies_db = query.offset(offset).limit(limit).all()
        
        # Format response
        companies = []
        for company in companies_db:
            # Count domains and users for this company
            domains_count = db.query(Domain).filter(Domain.company_id == company.id).count()
            users_count = db.query(User).filter(User.company_id == company.id).count()
            
            company_data = {
                "id": company.id,
                "name": company.name,
                "description": company.description or "",
                "contact_email": company.contact_email,
                "status": company.status.value,
                "email_notifications": company.email_notifications,
                "telegram_notifications": company.telegram_notifications,
                "domains_count": domains_count,
                "users_count": users_count,
                "created_at": company.created_at.isoformat(),
                "updated_at": company.updated_at.isoformat()
            }
            companies.append(company_data)
        
        return {
            "companies": companies,
            "total": total,
            "limit": limit,
            "offset": offset
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get companies error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get companies"
        )


@router.post("/companies")
async def create_company(
    request: Request,
    company_data: CompanyCreateRequest,
    current_user: TokenData = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """Create a new company."""
    try:
        logger.info(f"Create company request: {company_data.name} from admin: {current_user.email}")
        
        # Check if company name already exists
        existing_company = db.query(Company).filter(
            (Company.name == company_data.name) |
            (Company.contact_email == company_data.contact_email)
        ).first()
        
        if existing_company:
            if existing_company.name == company_data.name:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Company with this name already exists"
                )
            else:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Company with this contact email already exists"
                )
        
        # Create company record
        try:
            status_enum = CompanyStatus(company_data.status)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid status: {company_data.status}"
            )
        
        new_company = Company(
            name=company_data.name,
            description=company_data.description,
            contact_email=company_data.contact_email,
            status=status_enum,
            email_notifications=True,
            telegram_notifications=False
        )
        
        db.add(new_company)
        db.commit()
        db.refresh(new_company)
        
        # Create audit log
        try:
            audit_log = AuditLog(
                action="company_create",
                resource_type="company",
                resource_id=new_company.id,
                user_id=current_user.user_id,
                details=company_data.dict(),
                ip_address=request.client.host if request.client else None,
                user_agent=request.headers.get("user-agent")
            )
            db.add(audit_log)
            db.commit()
        except Exception as e:
            logger.warning(f"Failed to create audit log: {e}")
        
        # Format response
        company_response = {
            "id": new_company.id,
            "name": new_company.name,
            "description": new_company.description or "",
            "contact_email": new_company.contact_email,
            "status": new_company.status.value,
            "email_notifications": new_company.email_notifications,
            "telegram_notifications": new_company.telegram_notifications,
            "domains_count": 0,
            "users_count": 0,
            "created_at": new_company.created_at.isoformat(),
            "updated_at": new_company.updated_at.isoformat()
        }
        
        logger.info(f"Company created successfully: {company_data.name}")
        return company_response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Create company error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create company"
        )


@router.put("/companies/{company_id}")
async def update_company(
    request: Request,
    company_id: int,
    company_data: CompanyUpdateRequest,
    current_user: TokenData = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """Update company information."""
    try:
        logger.info(f"Update company request: {company_id} from admin: {current_user.email}")
        
        # Check if company exists
        company = db.query(Company).filter(Company.id == company_id).first()
        if not company:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Company not found"
            )
        
        # Store original status for notification check
        original_status = company.status
        
        # Update company fields
        update_data = company_data.dict(exclude_unset=True)
        for field, value in update_data.items():
            if hasattr(company, field):
                setattr(company, field, value)
        
        # Validate status if provided
        if company_data.status and company_data.status not in ["active", "suspended", "pending"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid status. Must be 'active', 'suspended', or 'pending'"
            )
        
        # Check for duplicate name or email if being updated
        if company_data.name:
            existing_company = db.query(Company).filter(
                Company.name == company_data.name,
                Company.id != company_id
            ).first()
            if existing_company:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Company name already exists"
                )
        
        if company_data.contact_email:
            existing_company = db.query(Company).filter(
                Company.contact_email == company_data.contact_email,
                Company.id != company_id
            ).first()
            if existing_company:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Contact email already exists"
                )
        
        # Update timestamp
        company.updated_at = datetime.utcnow()
        
        # If company status is being changed to 'active', update user verification status
        if company_data.status and company_data.status == "active" and original_status != "active":
            # Find all users associated with this company and verify them
            company_users = db.query(User).filter(User.company_id == company_id).all()
            for user in company_users:
                user.is_verified = True
            logger.info(f"Verified {len(company_users)} users for company {company_id}")
        
        # If company status is being changed from 'active' to something else, unverify users
        elif company_data.status and company_data.status != "active" and original_status == "active":
            # Find all users associated with this company and unverify them
            company_users = db.query(User).filter(User.company_id == company_id).all()
            for user in company_users:
                user.is_verified = False
            logger.info(f"Unverified {len(company_users)} users for company {company_id}")
        
        # Commit changes
        db.commit()
        db.refresh(company)
        
        # Create audit log
        try:
            audit_log = AuditLog(
                action="company_update",
                resource_type="company",
                resource_id=company_id,
                user_id=current_user.user_id,
                details=company_data.dict(exclude_unset=True),
                ip_address=request.client.host if request.client else None,
                user_agent=request.headers.get("user-agent")
            )
            db.add(audit_log)
            db.commit()
        except Exception as e:
            logger.warning(f"Failed to create audit log: {e}")
        
        # TODO: Send notification if status changed
        if company_data.status and original_status != company.status:
            logger.info(f"Company status changed from {original_status} to {company.status}")
        
        logger.info(f"Company updated successfully: {company_id}")
        return {
            "message": "Company updated successfully",
            "company": {
                "id": company.id,
                "name": company.name,
                "status": company.status,
                "contact_email": company.contact_email,
                "updated_at": company.updated_at.isoformat()
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Update company error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update company"
        )


@router.delete("/companies/{company_id}")
async def delete_company(
    request: Request,
    company_id: int,
    current_user: TokenData = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """Delete a company and all related data."""
    try:
        logger.info(f"Delete company request: {company_id} from admin: {current_user.email}")
        
        # Check if company exists
        company = db.query(Company).filter(Company.id == company_id).first()
        if not company:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Company not found"
            )
        
        # Store company info for audit log
        company_info = {
            "id": company.id,
            "name": company.name,
            "contact_email": company.contact_email,
            "status": company.status
        }
        
        # Delete related data in proper order to avoid foreign key constraints
        
        # 1. Delete domains associated with the company
        domains_deleted = db.query(Domain).filter(Domain.company_id == company_id).delete()
        
        # 2. Delete users associated with the company
        users_deleted = db.query(User).filter(User.company_id == company_id).delete()
        
        # 3. Delete the company itself
        db.delete(company)
        
        # Commit all deletions
        db.commit()
        
        # Create audit log
        try:
            audit_log = AuditLog(
                action="company_delete",
                resource_type="company",
                resource_id=company_id,
                user_id=current_user.user_id,
                details={
                    "company_info": company_info,
                    "domains_deleted": domains_deleted,
                    "users_deleted": users_deleted
                },
                ip_address=request.client.host if request.client else None,
                user_agent=request.headers.get("user-agent")
            )
            db.add(audit_log)
            db.commit()
        except Exception as e:
            logger.warning(f"Failed to create audit log: {e}")
        
        logger.info(f"Company deleted successfully: {company_id} (domains: {domains_deleted}, users: {users_deleted})")
        return {
            "message": "Company deleted successfully",
            "deleted_data": {
                "company": company_info,
                "domains_count": domains_deleted,
                "users_count": users_deleted
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Delete company error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete company"
        )


@router.post("/leaks/upload")
async def upload_leak_file(
    request: Request,
    file: UploadFile = File(...),
    source_name: str = Query(..., description="Name of the leak source"),
    description: str = Query("", description="Description of the leak"),
    current_user: TokenData = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """Upload and process a leak file."""
    try:
        logger.info(f"Leak upload request from admin: {current_user.email}, file: {file.filename}")
        
        # Validate file
        if not file.filename:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No file provided"
            )
        
        # Check file extension
        allowed_extensions = ['.txt', '.csv', '.json', '.sql']
        file_ext = '.' + file.filename.split('.')[-1].lower() if '.' in file.filename else ''
        if file_ext not in allowed_extensions:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid file format. Allowed: {', '.join(allowed_extensions)}"
            )
        
        # Read file content for basic validation
        content = await file.read()
        file_size = len(content)
        
        # Basic size validation (max 100MB)
        max_size = 100 * 1024 * 1024  # 100MB
        if file_size > max_size:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="File too large. Maximum size is 100MB"
            )
        
        # Reset file pointer for potential future processing
        await file.seek(0)
        
        # Generate upload ID
        upload_id = f"upload_{int(datetime.utcnow().timestamp())}"
        
        # TODO: Implement actual leak file processing
        # 1. Parse leak data using existing parser
        # 2. Upload to Elasticsearch
        # 3. Trigger company notifications
        
        # Create audit log
        try:
            audit_log = AuditLog(
                action="leak_upload",
                resource_type="leak",
                user_id=current_user.user_id,
                details={
                    "upload_id": upload_id,
                    "filename": file.filename,
                    "source_name": source_name,
                    "description": description,
                    "file_size": file_size,
                    "file_extension": file_ext
                },
                ip_address=request.client.host if request.client else None,
                user_agent=request.headers.get("user-agent")
            )
            db.add(audit_log)
            db.commit()
        except Exception as e:
            logger.warning(f"Failed to create audit log: {e}")
        
        # Response with validated data
        upload_response = {
            "message": "Leak file uploaded successfully",
            "upload_id": upload_id,
            "filename": file.filename,
            "source_name": source_name,
            "file_size": file_size,
            "file_extension": file_ext,
            "status": "pending_processing",
            "uploaded_at": datetime.utcnow().isoformat() + "Z",
            "note": "File validation completed. Processing will begin shortly."
        }
        
        logger.info(f"Leak file uploaded successfully: {file.filename} ({file_size} bytes)")
        return upload_response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Leak upload error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to upload leak file"
        )


@router.get("/leaks/uploads")
async def get_upload_history(
    current_user: TokenData = Depends(get_current_admin),
    db: Session = Depends(get_db),
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0)
):
    """Get leak upload history."""
    try:
        logger.info(f"Upload history request from admin: {current_user.email}")
        
        # Get upload history from audit logs
        upload_logs_query = db.query(AuditLog).filter(
            AuditLog.action == "leak_upload",
            AuditLog.resource_type == "leak"
        ).order_by(AuditLog.created_at.desc())
        
        # Get total count
        total = upload_logs_query.count()
        
        # Apply pagination
        upload_logs = upload_logs_query.offset(offset).limit(limit).all()
        
        # Format upload history
        uploads = []
        for log in upload_logs:
            # Get user info
            user = db.query(User).filter(User.id == log.user_id).first()
            user_email = user.email if user else "Unknown"
            
            # Extract details from audit log
            details = log.details or {}
            
            upload_info = {
                "id": details.get("upload_id", f"upload_{log.id}"),
                "filename": details.get("filename", "Unknown"),
                "source_name": details.get("source_name", "Unknown Source"),
                "description": details.get("description", ""),
                "file_size": details.get("file_size", 0),
                "file_extension": details.get("file_extension", ""),
                "status": "completed",  # Since it's in audit log, upload was successful
                "uploaded_by": user_email,
                "uploaded_at": log.created_at.isoformat() + "Z",
                "ip_address": log.ip_address,
                "user_agent": log.user_agent
            }
            uploads.append(upload_info)
        
        return {
            "uploads": uploads,
            "total": total,
            "limit": limit,
            "offset": offset
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get upload history error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get upload history"
        )


@router.post("/automation/control")
async def control_automation(
    request: Request,
    control_data: AutomationControlRequest,
    current_user: TokenData = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """Control automation systems (start/stop/restart)."""
    try:
        logger.info(f"Automation control request from admin: {current_user.email}, type: {control_data.automation_type}, action: {control_data.action}")
        
        # TODO: Implement actual automation control
        # 1. Connect to automation services
        # 2. Execute control commands
        # 3. Update system settings
        
        # Create audit log
        try:
            audit_log = AuditLog(
                action="automation_control",
                resource_type="system",
                user_id=current_user.user_id,
                details=control_data.dict(),
                ip_address=request.client.host if request.client else None,
                user_agent=request.headers.get("user-agent")
            )
            db.add(audit_log)
            db.commit()
        except Exception as e:
            logger.warning(f"Failed to create audit log: {e}")
        
        # Mock response for development
        control_response = {
            "message": f"Automation {control_data.action} command executed successfully",
            "automation_type": control_data.automation_type,
            "action": control_data.action,
            "status": "running" if control_data.action == "start" else "stopped",
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        
        logger.info(f"Automation control executed: {control_data.automation_type} - {control_data.action}")
        return control_response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Automation control error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to control automation"
        )


@router.get("/automation/status")
async def get_automation_status(
    current_user: TokenData = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """Get current automation system status."""
    try:
        logger.info(f"Automation status request from admin: {current_user.email}")
        
        # TODO: Implement actual automation status retrieval
        # This is a placeholder implementation
        
        # Mock automation status for development
        automation_status = {
            "telegram_scraping": {
                "status": "running",
                "last_run": "2024-01-15T10:00:00Z",
                "next_run": "2024-01-15T11:00:00Z",
                "items_processed_today": 45,
                "errors_today": 2,
                "uptime": "2 days, 5 hours"
            },
            "dark_web_monitoring": {
                "status": "stopped",
                "last_run": "2024-01-14T22:00:00Z",
                "next_run": None,
                "items_processed_today": 0,
                "errors_today": 0,
                "uptime": "0 minutes"
            },
            "notification_system": {
                "status": "running",
                "emails_sent_today": 15,
                "telegram_messages_sent_today": 8,
                "failed_notifications_today": 1
            }
        }
        
        return automation_status
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get automation status error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get automation status"
        )


@router.get("/analytics")
async def get_system_analytics(
    current_user: TokenData = Depends(get_current_admin),
    db: Session = Depends(get_db),
    period: str = Query("30d", description="Analytics period: 7d, 30d, 90d, 1y")
):
    """Get system analytics and statistics."""
    try:
        logger.info(f"Analytics request from admin: {current_user.email}, period: {period}")
        
        # Calculate date range based on period
        now = datetime.utcnow()
        if period == "7d":
            start_date = now - timedelta(days=7)
        elif period == "30d":
            start_date = now - timedelta(days=30)
        elif period == "90d":
            start_date = now - timedelta(days=90)
        elif period == "1y":
            start_date = now - timedelta(days=365)
        else:
            start_date = now - timedelta(days=30)  # Default to 30 days
        
        # Get company statistics
        total_companies = db.query(Company).count()
        new_companies = db.query(Company).filter(Company.created_at >= start_date).count()
        active_companies = db.query(Company).filter(Company.status == CompanyStatus.ACTIVE).count()
        
        # Get user statistics
        total_users = db.query(User).count()
        new_users = db.query(User).filter(User.created_at >= start_date).count()
        
        # Get domain statistics
        total_domains = db.query(Domain).count()
        new_domains = db.query(Domain).filter(Domain.created_at >= start_date).count()
        
        # Get audit log statistics
        total_audit_logs = db.query(AuditLog).count()
        recent_activities = db.query(AuditLog).filter(AuditLog.created_at >= start_date).count()
        
        # Get top domains by count
        top_domains = db.query(Domain.domain_name, func.count(Domain.id).label('count')).group_by(Domain.domain_name).order_by(func.count(Domain.id).desc()).limit(5).all()
        
        analytics_data = {
            "period": period,
            "generated_at": now.isoformat() + "Z",
            "date_range": {
                "start": start_date.isoformat() + "Z",
                "end": now.isoformat() + "Z"
            },
            "company_stats": {
                "total_companies": total_companies,
                "new_companies_this_period": new_companies,
                "active_companies": active_companies,
                "inactive_companies": total_companies - active_companies
            },
            "user_stats": {
                "total_users": total_users,
                "new_users_this_period": new_users
            },
            "domain_stats": {
                "total_domains": total_domains,
                "new_domains_this_period": new_domains,
                "top_domains": [{"domain": domain, "count": count} for domain, count in top_domains]
            },
            "activity_stats": {
                "total_audit_logs": total_audit_logs,
                "recent_activities": recent_activities
            },
            "system_info": {
                "leak_processing": "Not implemented",
                "notification_system": "Not implemented",
                "elasticsearch_status": "Not configured"
            }
        }
        
        return analytics_data
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get analytics error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get analytics"
        )


@router.get("/audit-logs")
async def get_audit_logs(
    current_user: TokenData = Depends(get_current_admin),
    db: Session = Depends(get_db),
    action: Optional[str] = Query(None, description="Filter by action"),
    resource_type: Optional[str] = Query(None, description="Filter by resource type"),
    user_id: Optional[int] = Query(None, description="Filter by user ID"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0)
):
    """Get system audit logs with filtering."""
    try:
        logger.info(f"Audit logs request from admin: {current_user.email}")
        
        # Build query with filters
        query = db.query(AuditLog).join(User, AuditLog.user_id == User.id)
        
        if action:
            query = query.filter(AuditLog.action == action)
        if resource_type:
            query = query.filter(AuditLog.resource_type == resource_type)
        if user_id:
            query = query.filter(AuditLog.user_id == user_id)
        
        # Get total count
        total = query.count()
        
        # Apply pagination and ordering
        audit_logs_db = query.order_by(AuditLog.created_at.desc()).offset(offset).limit(limit).all()
        
        # Format audit logs
        audit_logs = []
        for log in audit_logs_db:
            audit_logs.append({
                "id": log.id,
                "action": log.action,
                "resource_type": log.resource_type,
                "resource_id": log.resource_id,
                "user_id": log.user_id,
                "user_email": log.user.email,
                "details": log.details or {},
                "ip_address": log.ip_address,
                "user_agent": log.user_agent,
                "timestamp": log.created_at.isoformat() + "Z"
            })
        
        return {
            "audit_logs": audit_logs,
            "total": total,
            "limit": limit,
            "offset": offset
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get audit logs error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get audit logs"
        )


@router.get("/system/health")
async def get_system_health(
    current_user: TokenData = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """Get comprehensive system health status."""
    try:
        logger.info(f"System health request from admin: {current_user.email}")
        
        # Check database health
        db_status = "healthy"
        db_response_time = "N/A"
        try:
            start_time = datetime.utcnow()
            db.execute("SELECT 1")
            end_time = datetime.utcnow()
            db_response_time = f"{(end_time - start_time).total_seconds() * 1000:.1f}ms"
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            db_status = "unhealthy"
        
        # Get database statistics
        total_companies = db.query(Company).count()
        total_users = db.query(User).count()
        total_domains = db.query(Domain).count()
        total_audit_logs = db.query(AuditLog).count()
        
        # Determine overall status
        overall_status = "healthy" if db_status == "healthy" else "degraded"
        
        health_data = {
            "overall_status": overall_status,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "components": {
                "database": {
                    "status": db_status,
                    "response_time": db_response_time,
                    "statistics": {
                        "companies": total_companies,
                        "users": total_users,
                        "domains": total_domains,
                        "audit_logs": total_audit_logs
                    }
                },
                "elasticsearch": {
                    "status": "not_configured",
                    "note": "Elasticsearch integration pending"
                },
                "automation_services": {
                    "status": "not_implemented",
                    "note": "Automation services pending implementation"
                }
            },
            "system_info": {
                "uptime": "System monitoring not implemented",
                "version": "1.0.0",
                "environment": "development"
            }
        }
        
        return health_data
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get system health error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get system health"
        )
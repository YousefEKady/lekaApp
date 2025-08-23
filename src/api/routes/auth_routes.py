#!/usr/bin/env python3
"""
Authentication Routes - Leka-App SaaS Edition

API endpoints for user authentication, registration, and token management.
Includes routes for both company users and super admins.

Author: Yousef
Project: Leka-App SaaS Edition
"""

import logging
from datetime import datetime
from typing import Dict, Any

from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr, validator

try:
    from src.api.auth import (
        auth_service, get_current_user, UserRole,
        LoginRequest, TokenResponse, TokenData
    )
    from src.database.connection import get_db
    from src.database.models import User, Company, AuditLog
except ImportError as e:
    logging.error(f"Import error in auth_routes: {e}")
    # Create placeholder classes for development
    class LoginRequest(BaseModel):
        email: EmailStr
        password: str
    
    class TokenResponse(BaseModel):
        access_token: str
        refresh_token: str
        token_type: str = "bearer"
        expires_in: int
        user_info: Dict[str, Any]
    
    # Placeholder function for get_db
    def get_db():
        raise HTTPException(status_code=500, detail="Database not configured")
    
    # Placeholder classes
    class User:
        pass
    class Company:
        pass
    class AuditLog:
        pass
    class UserRole:
        COMPANY_USER = "company_user"
        SUPER_ADMIN = "super_admin"
    
    # Placeholder auth service
    class AuthService:
        def authenticate_user(self, *args, **kwargs):
            raise HTTPException(status_code=500, detail="Auth service not configured")
    auth_service = AuthService()
    
    def get_current_user():
        raise HTTPException(status_code=500, detail="Auth not configured")
    
    class TokenData:
        pass

logger = logging.getLogger(__name__)

# Create router
router = APIRouter(prefix="/auth", tags=["Authentication"])


class CompanyRegistrationRequest(BaseModel):
    """Company registration request model."""
    # User information
    email: EmailStr
    password: str
    full_name: str
    
    # Company information
    company_name: str
    company_description: str = ""
    contact_email: EmailStr
    
    @validator('password')
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(c.islower() for c in v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain at least one digit')
        return v
    
    @validator('company_name')
    def validate_company_name(cls, v):
        if len(v.strip()) < 2:
            raise ValueError('Company name must be at least 2 characters long')
        return v.strip()


class AdminRegistrationRequest(BaseModel):
    """Super admin registration request model."""
    email: EmailStr
    password: str
    full_name: str
    admin_secret: str  # Secret key for admin registration
    
    @validator('password')
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        return v


class RefreshTokenRequest(BaseModel):
    """Refresh token request model."""
    refresh_token: str


class PasswordChangeRequest(BaseModel):
    """Password change request model."""
    current_password: str
    new_password: str
    
    @validator('new_password')
    def validate_new_password(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        return v


@router.post("/login", response_model=TokenResponse)
async def login(
    request: Request,
    login_data: LoginRequest,
    db: Session = Depends(get_db)
):
    """Authenticate user and return JWT tokens."""
    try:
        logger.info(f"Login attempt for email: {login_data.email}")
        
        # Authenticate user with database
        user_data = auth_service.authenticate_user(
            email=login_data.email,
            password=login_data.password,
            db_session=db
        )
        
        if not user_data:
            # Log failed login attempt
            audit_log = AuditLog(
                action="login_failed",
                resource_type="user",
                details={
                    "email": login_data.email,
                    "reason": "invalid_credentials"
                },
                ip_address=request.client.host if request.client else None,
                user_agent=request.headers.get("user-agent")
            )
            db.add(audit_log)
            db.commit()
            
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password"
            )
        
        # Check if user is verified
        if not user_data.get("is_verified", True):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account not verified. Please contact administrator."
            )
        
        # Create tokens
        tokens = auth_service.create_tokens(user_data)
        
        # Log successful login
        audit_log = AuditLog(
            action="login_success",
            resource_type="user",
            resource_id=user_data["id"],
            user_id=user_data["id"],
            details={
                "email": user_data["email"],
                "role": user_data["role"]
            },
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent")
        )
        db.add(audit_log)
        db.commit()
        
        logger.info(f"Login successful for user: {login_data.email}")
        return tokens
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Login failed"
        )


@router.post("/register/company", response_model=Dict[str, str])
async def register_company(
    request: Request,
    registration_data: CompanyRegistrationRequest,
    db: Session = Depends(get_db)
):
    """Register a new company and company user."""
    try:
        from src.api.auth import PasswordManager
        from src.database.models import CompanyStatus
        
        logger.info(f"Company registration attempt: {registration_data.email}")
        
        # Check if user already exists
        existing_user = db.query(User).filter(User.email == registration_data.email).first()
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="User with this email already exists"
            )
        
        # Check if company name already exists
        existing_company = db.query(Company).filter(Company.name == registration_data.company_name).first()
        if existing_company:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Company with this name already exists"
            )
        
        # Create company
        new_company = Company(
            name=registration_data.company_name,
            description=registration_data.company_description,
            contact_email=registration_data.contact_email,
            status=CompanyStatus.PENDING  # Requires admin approval
        )
        db.add(new_company)
        db.flush()  # Get the company ID
        
        # Hash password
        hashed_password = PasswordManager.hash_password(registration_data.password)
        
        # Create user
        new_user = User(
            email=registration_data.email,
            hashed_password=hashed_password,
            full_name=registration_data.full_name,
            role=UserRole.COMPANY_USER,
            company_id=new_company.id,
            is_active=True,
            is_verified=False  # Requires verification
        )
        db.add(new_user)
        db.flush()  # Get the user ID
        
        # Log company registration
        audit_log = AuditLog(
            action="company_registered",
            resource_type="company",
            resource_id=new_company.id,
            details={
                "company_name": new_company.name,
                "user_email": new_user.email,
                "contact_email": new_company.contact_email
            },
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent")
        )
        db.add(audit_log)
        db.commit()
        
        logger.info(f"Company registration successful: {registration_data.company_name}")
        
        return {
            "message": "Company registration successful. Awaiting admin approval.",
            "status": "pending_verification",
            "email": registration_data.email,
            "company_id": new_company.id
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Company registration error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Registration failed"
        )


@router.post("/register/admin", response_model=Dict[str, str])
async def register_admin(
    request: Request,
    registration_data: AdminRegistrationRequest,
    db: Session = Depends(get_db)
):
    """Register a new super admin (requires admin secret)."""
    try:
        from src.api.auth import PasswordManager
        from src.config.config import config
        
        logger.info(f"Admin registration attempt: {registration_data.email}")
        
        # Verify admin secret key
        admin_secret = getattr(config, 'ADMIN_SECRET_KEY', 'default_admin_secret_2024')
        if registration_data.admin_secret != admin_secret:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid admin secret key"
            )
        
        # Check if user already exists
        existing_user = db.query(User).filter(User.email == registration_data.email).first()
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="User with this email already exists"
            )
        
        # Hash password
        hashed_password = PasswordManager.hash_password(registration_data.password)
        
        # Create admin user
        new_admin = User(
            email=registration_data.email,
            hashed_password=hashed_password,
            full_name=registration_data.full_name,
            role=UserRole.SUPER_ADMIN,
            company_id=None,  # Admins don't belong to companies
            is_active=True,
            is_verified=True  # Auto-verify admins
        )
        db.add(new_admin)
        db.flush()  # Get the user ID
        
        # Log admin registration
        audit_log = AuditLog(
            action="admin_registered",
            resource_type="user",
            resource_id=new_admin.id,
            details={
                "admin_email": new_admin.email,
                "role": new_admin.role.value
            },
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent")
        )
        db.add(audit_log)
        db.commit()
        
        logger.info(f"Admin registration successful: {registration_data.email}")
        
        return {
            "message": "Admin registration successful",
            "email": registration_data.email,
            "user_id": new_admin.id
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Admin registration error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Admin registration failed"
        )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    request: Request,
    refresh_data: RefreshTokenRequest,
    db: Session = Depends(get_db)
):
    """Refresh access token using refresh token."""
    try:
        from src.api.auth import JWTManager
        
        logger.info("Token refresh attempt")
        
        # Verify refresh token
        try:
            payload = JWTManager.verify_token(refresh_data.refresh_token)
            if payload.get("type") != "refresh":
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token type"
                )
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token"
            )
        
        # Get user from database
        user_id = payload.get("sub")
        user = db.query(User).filter(User.id == user_id).first()
        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or inactive"
            )
        
        # Prepare user data for token creation
        user_data = {
            "id": user.id,
            "email": user.email,
            "role": user.role.value,
            "company_id": user.company_id,
            "company_name": user.company.name if user.company else None
        }
        
        # Create new tokens
        tokens = auth_service.create_tokens(user_data)
        
        # Log token refresh
        audit_log = AuditLog(
            action="token_refreshed",
            resource_type="user",
            resource_id=user.id,
            details={"user_email": user.email},
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent")
        )
        db.add(audit_log)
        db.commit()
        
        logger.info("Token refresh successful")
        return tokens
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Token refresh error: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token refresh failed"
        )


@router.post("/logout")
async def logout(
    request: Request,
    current_user: TokenData = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Logout user (invalidate tokens)."""
    try:
        logger.info(f"Logout request from user: {current_user.email}")
        
        # TODO: Implement token blacklisting in future
        # For now, just log the logout
        
        # Create audit log
        audit_log = AuditLog(
            action="user_logout",
            resource_type="user",
            resource_id=current_user.user_id,
            user_id=current_user.user_id,
            details={"email": current_user.email},
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent")
        )
        db.add(audit_log)
        db.commit()
        
        logger.info(f"Logout successful for user: {current_user.email}")
        
        return {"message": "Logout successful"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Logout error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Logout failed"
        )


@router.get("/me")
async def get_current_user_info(
    current_user: TokenData = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get current user information."""
    try:
        # Fetch actual user data from database
        user = db.query(User).filter(User.id == current_user.user_id).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        user_info = {
            "id": user.id,
            "email": user.email,
            "full_name": user.full_name,
            "role": user.role.value,
            "company_id": user.company_id,
            "company_name": user.company.name if user.company else None,
            "is_active": user.is_active,
            "is_verified": user.is_verified,
            "created_at": user.created_at.isoformat(),
            "last_login": user.last_login.isoformat() if user.last_login else None
        }
        
        return user_info
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get user info error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get user information"
        )


@router.post("/change-password")
async def change_password(
    request: Request,
    password_data: PasswordChangeRequest,
    current_user: TokenData = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Change user password."""
    try:
        from src.api.auth import PasswordManager
        
        logger.info(f"Password change request from user: {current_user.email}")
        
        # Get user from database
        user = db.query(User).filter(User.id == current_user.user_id).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Verify current password
        if not PasswordManager.verify_password(password_data.current_password, user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Current password is incorrect"
            )
        
        # Hash new password
        new_hashed_password = PasswordManager.hash_password(password_data.new_password)
        
        # Update password in database
        user.hashed_password = new_hashed_password
        user.updated_at = datetime.utcnow()
        
        # Create audit log
        audit_log = AuditLog(
            action="password_changed",
            resource_type="user",
            resource_id=current_user.user_id,
            user_id=current_user.user_id,
            details={"email": current_user.email},
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent")
        )
        db.add(audit_log)
        db.commit()
        
        logger.info(f"Password change successful for user: {current_user.email}")
        
        return {"message": "Password changed successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Password change error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Password change failed"
        )


@router.get("/verify-token")
async def verify_token(
    current_user: TokenData = Depends(get_current_user)
):
    """Verify if the current token is valid."""
    return {
        "valid": True,
        "user_id": current_user.user_id,
        "email": current_user.email,
        "role": current_user.role,
        "expires_at": current_user.exp.isoformat()
    }
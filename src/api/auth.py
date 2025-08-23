#!/usr/bin/env python3
"""
Authentication Module - Leka-App SaaS Edition

Handles JWT token generation, validation, password hashing,
and user authentication for both company users and super admins.

Author: Yousef
Project: Leka-App SaaS Edition
"""

import os
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Union

import jwt
from jwt.exceptions import InvalidTokenError, ExpiredSignatureError
from passlib.context import CryptContext
from fastapi import HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr

from src.config.config import config

logger = logging.getLogger(__name__)

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT configuration
JWT_SECRET_KEY = config.JWT_SECRET_KEY
JWT_ALGORITHM = config.JWT_ALGORITHM
ACCESS_TOKEN_EXPIRE_MINUTES = config.JWT_ACCESS_TOKEN_EXPIRE_MINUTES
REFRESH_TOKEN_EXPIRE_DAYS = 7

# Security
security = HTTPBearer()


class UserRole:
    """User role constants."""
    COMPANY_USER = "company_user"
    SUPER_ADMIN = "super_admin"


class TokenData(BaseModel):
    """Token data structure."""
    user_id: int
    email: str
    role: str
    company_id: Optional[int] = None
    is_verified: bool = False
    exp: datetime


class LoginRequest(BaseModel):
    """Login request model."""
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    """Token response model."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user_info: Dict[str, Any]


class PasswordManager:
    """Password hashing and verification manager."""
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash a password using bcrypt."""
        return pwd_context.hash(password)
    
    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """Verify a password against its hash."""
        return pwd_context.verify(plain_password, hashed_password)


class JWTManager:
    """JWT token management."""
    
    @staticmethod
    def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
        """Create a JWT access token."""
        to_encode = data.copy()
        
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        
        to_encode.update({"exp": expire, "type": "access"})
        
        try:
            encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
            logger.info(f"Access token created for user: {data.get('email')}")
            return encoded_jwt
        except Exception as e:
            logger.error(f"Failed to create access token: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create access token"
            )
    
    @staticmethod
    def create_refresh_token(data: Dict[str, Any]) -> str:
        """Create a JWT refresh token."""
        to_encode = data.copy()
        expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
        to_encode.update({"exp": expire, "type": "refresh"})
        
        try:
            encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
            logger.info(f"Refresh token created for user: {data.get('email')}")
            return encoded_jwt
        except Exception as e:
            logger.error(f"Failed to create refresh token: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create refresh token"
            )
    
    @staticmethod
    def verify_token(token: str, token_type: str = "access") -> TokenData:
        """Verify and decode a JWT token."""
        try:
            payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
            
            # Check token type
            if payload.get("type") != token_type:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=f"Invalid token type. Expected {token_type}"
                )
            
            # Extract token data
            token_data = TokenData(
                user_id=payload.get("user_id"),
                email=payload.get("email"),
                role=payload.get("role"),
                company_id=payload.get("company_id"),
                is_verified=payload.get("is_verified", False),
                exp=datetime.fromtimestamp(payload.get("exp"))
            )
            
            return token_data
            
        except ExpiredSignatureError:
            logger.warning(f"Expired {token_type} token")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired"
            )
        except InvalidTokenError as e:
            logger.warning(f"Invalid {token_type} token: {e}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )
        except Exception as e:
            logger.error(f"Token verification error: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Token verification failed"
            )


class AuthenticationService:
    """Authentication service for user login and token management."""
    
    def __init__(self):
        self.password_manager = PasswordManager()
        self.jwt_manager = JWTManager()
    
    def authenticate_user(self, email: str, password: str, db_session) -> Optional[Dict[str, Any]]:
        """Authenticate user with email and password."""
        from src.database.models import User
        
        try:
            # Find user by email
            user = db_session.query(User).filter(User.email == email).first()
            if not user:
                logger.warning(f"Authentication failed: User not found for email {email}")
                return None
            
            # Check if user is active
            if not user.is_active:
                logger.warning(f"Authentication failed: User {email} is inactive")
                return None
            
            # Verify password
            if not PasswordManager.verify_password(password, user.hashed_password):
                logger.warning(f"Authentication failed: Invalid password for user {email}")
                return None
            
            # Update last login
            user.last_login = datetime.utcnow()
            db_session.commit()
            
            # Return user data
            user_data = {
                "id": user.id,
                "email": user.email,
                "role": user.role.value,
                "full_name": user.full_name,
                "company_id": user.company_id,
                "company_name": user.company.name if user.company else None,
                "is_verified": user.is_verified
            }
            
            logger.info(f"User {email} authenticated successfully")
            return user_data
            
        except Exception as e:
            logger.error(f"Authentication error for user {email}: {e}")
            db_session.rollback()
            return None
    
    def create_tokens(self, user_data: Dict[str, Any]) -> TokenResponse:
        """Create access and refresh tokens for a user."""
        token_data = {
            "user_id": user_data["id"],
            "email": user_data["email"],
            "role": user_data["role"],
            "company_id": user_data.get("company_id"),
            "is_verified": user_data.get("is_verified", False)
        }
        
        access_token = self.jwt_manager.create_access_token(token_data)
        refresh_token = self.jwt_manager.create_refresh_token(token_data)
        
        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            user_info={
                "id": user_data["id"],
                "email": user_data["email"],
                "role": user_data["role"],
                "company_id": user_data.get("company_id"),
                "company_name": user_data.get("company_name"),
                "is_verified": user_data.get("is_verified", False)
            }
        )


# Dependency functions
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> TokenData:
    """Get current authenticated user from JWT token."""
    jwt_manager = JWTManager()
    return jwt_manager.verify_token(credentials.credentials)


async def get_current_company_user(current_user: TokenData = Depends(get_current_user)) -> TokenData:
    """Get current company user with verification check."""
    if current_user.role != UserRole.COMPANY_USER:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied. Company user role required."
        )
    
    # Check if user is verified (company approved)
    if not current_user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied. User not verified or company not approved."
        )
    
    return current_user


async def get_current_admin(current_user: TokenData = Depends(get_current_user)) -> TokenData:
    """Get current admin user (requires super_admin role)."""
    if current_user.role != UserRole.SUPER_ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Super admin access required"
        )
    return current_user


# Initialize authentication service
auth_service = AuthenticationService()
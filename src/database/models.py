#!/usr/bin/env python3
"""
Database Models - Leka-App SaaS Edition

SQLAlchemy models for PostgreSQL database including:
- Users (company users and super admins)
- Companies and their domains
- System logs and audit trails
- Leak notifications and alerts

Author: Yousef
Project: Leka-App SaaS Edition
"""

import logging
from datetime import datetime
from typing import List, Optional

from sqlalchemy import (
    Column, Integer, String, Text, Boolean, DateTime, ForeignKey,
    UniqueConstraint, Index, Enum as SQLEnum, JSON
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, Session
from sqlalchemy.sql import func
from enum import Enum

logger = logging.getLogger(__name__)

Base = declarative_base()


class UserRole(str, Enum):
    """User role enumeration."""
    COMPANY_USER = "company_user"
    SUPER_ADMIN = "super_admin"


class CompanyStatus(str, Enum):
    """Company status enumeration."""
    ACTIVE = "active"
    SUSPENDED = "suspended"
    PENDING = "pending"
    DELETED = "deleted"


class DomainStatus(str, Enum):
    """Domain monitoring status."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    PENDING = "pending"


class NotificationStatus(str, Enum):
    """Notification status enumeration."""
    PENDING = "pending"
    SENT = "sent"
    FAILED = "failed"
    READ = "read"


class User(Base):
    """User model for both company users and super admins."""
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255), nullable=False)
    role = Column(SQLEnum(UserRole), nullable=False, default=UserRole.COMPANY_USER)
    is_active = Column(Boolean, default=True, nullable=False)
    is_verified = Column(Boolean, default=False, nullable=False)
    
    # Company relationship (only for company users)
    company_id = Column(Integer, ForeignKey("companies.id"), nullable=True)
    company = relationship("Company", back_populates="users")
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    last_login = Column(DateTime(timezone=True), nullable=True)
    
    # Relationships
    notifications = relationship("Notification", back_populates="user", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="user")
    
    def __repr__(self):
        return f"<User(id={self.id}, email='{self.email}', role='{self.role}')>"
    
    def to_dict(self):
        """Convert user to dictionary."""
        return {
            "id": self.id,
            "email": self.email,
            "full_name": self.full_name,
            "role": self.role.value,
            "is_active": self.is_active,
            "is_verified": self.is_verified,
            "company_id": self.company_id,
            "company_name": self.company.name if self.company else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_login": self.last_login.isoformat() if self.last_login else None
        }


class Company(Base):
    """Company model for organizations using the platform."""
    __tablename__ = "companies"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False, index=True)
    description = Column(Text, nullable=True)
    contact_email = Column(String(255), nullable=False)
    status = Column(SQLEnum(CompanyStatus), nullable=False, default=CompanyStatus.PENDING)
    
    # Settings
    email_notifications = Column(Boolean, default=True, nullable=False)
    telegram_notifications = Column(Boolean, default=False, nullable=False)
    telegram_chat_id = Column(String(255), nullable=True)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    
    # Relationships
    users = relationship("User", back_populates="company")
    domains = relationship("Domain", back_populates="company", cascade="all, delete-orphan")
    notifications = relationship("Notification", back_populates="company")
    
    def __repr__(self):
        return f"<Company(id={self.id}, name='{self.name}', status='{self.status}')>"
    
    def to_dict(self):
        """Convert company to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "contact_email": self.contact_email,
            "status": self.status.value,
            "email_notifications": self.email_notifications,
            "telegram_notifications": self.telegram_notifications,
            "telegram_chat_id": self.telegram_chat_id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "domains_count": len(self.domains) if self.domains else 0,
            "users_count": len(self.users) if self.users else 0
        }


class Domain(Base):
    """Domain model for monitoring company domains."""
    __tablename__ = "domains"
    
    id = Column(Integer, primary_key=True, index=True)
    domain_name = Column(String(255), nullable=False, index=True)
    status = Column(SQLEnum(DomainStatus), nullable=False, default=DomainStatus.ACTIVE)
    
    # Company relationship
    company_id = Column(Integer, ForeignKey("companies.id"), nullable=False)
    company = relationship("Company", back_populates="domains")
    
    # Monitoring settings
    monitor_subdomains = Column(Boolean, default=True, nullable=False)
    last_checked = Column(DateTime(timezone=True), nullable=True)
    leaks_found = Column(Integer, default=0, nullable=False)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    
    # Constraints
    __table_args__ = (
        UniqueConstraint('domain_name', 'company_id', name='unique_domain_per_company'),
        Index('idx_domain_company', 'domain_name', 'company_id'),
    )
    
    def __repr__(self):
        return f"<Domain(id={self.id}, domain='{self.domain_name}', company_id={self.company_id})>"
    
    def to_dict(self):
        """Convert domain to dictionary."""
        return {
            "id": self.id,
            "domain_name": self.domain_name,
            "status": self.status.value,
            "company_id": self.company_id,
            "company_name": self.company.name if self.company else None,
            "monitor_subdomains": self.monitor_subdomains,
            "last_checked": self.last_checked.isoformat() if self.last_checked else None,
            "leaks_found": self.leaks_found,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None
        }


class Notification(Base):
    """Notification model for leak alerts and system messages."""
    __tablename__ = "notifications"
    
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    message = Column(Text, nullable=False)
    notification_type = Column(String(50), nullable=False)  # 'leak_alert', 'system', 'security'
    status = Column(SQLEnum(NotificationStatus), nullable=False, default=NotificationStatus.PENDING)
    
    # Recipients
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    user = relationship("User", back_populates="notifications")
    
    company_id = Column(Integer, ForeignKey("companies.id"), nullable=True)
    company = relationship("Company", back_populates="notifications")
    
    # Leak information (for leak alerts)
    leak_data = Column(JSON, nullable=True)  # Store leak details as JSON
    domain_affected = Column(String(255), nullable=True)
    
    # Delivery tracking
    email_sent = Column(Boolean, default=False, nullable=False)
    telegram_sent = Column(Boolean, default=False, nullable=False)
    read_at = Column(DateTime(timezone=True), nullable=True)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    sent_at = Column(DateTime(timezone=True), nullable=True)
    
    def __repr__(self):
        return f"<Notification(id={self.id}, type='{self.notification_type}', status='{self.status}')>"
    
    def to_dict(self):
        """Convert notification to dictionary."""
        return {
            "id": self.id,
            "title": self.title,
            "message": self.message,
            "notification_type": self.notification_type,
            "status": self.status.value,
            "user_id": self.user_id,
            "company_id": self.company_id,
            "leak_data": self.leak_data,
            "domain_affected": self.domain_affected,
            "email_sent": self.email_sent,
            "telegram_sent": self.telegram_sent,
            "read_at": self.read_at.isoformat() if self.read_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "sent_at": self.sent_at.isoformat() if self.sent_at else None
        }


class AuditLog(Base):
    """Audit log model for tracking system activities."""
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    action = Column(String(100), nullable=False, index=True)
    resource_type = Column(String(50), nullable=False)  # 'user', 'company', 'domain', 'leak'
    resource_id = Column(Integer, nullable=True)
    
    # User who performed the action
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    user = relationship("User", back_populates="audit_logs")
    
    # Action details
    details = Column(JSON, nullable=True)  # Store action details as JSON
    ip_address = Column(String(45), nullable=True)  # Support IPv6
    user_agent = Column(String(500), nullable=True)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    
    # Indexes
    __table_args__ = (
        Index('idx_audit_action_resource', 'action', 'resource_type'),
        Index('idx_audit_user_created', 'user_id', 'created_at'),
    )
    
    def __repr__(self):
        return f"<AuditLog(id={self.id}, action='{self.action}', resource='{self.resource_type}')>"
    
    def to_dict(self):
        """Convert audit log to dictionary."""
        return {
            "id": self.id,
            "action": self.action,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "user_id": self.user_id,
            "user_email": self.user.email if self.user else None,
            "details": self.details,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }


class SystemSettings(Base):
    """System settings model for global configuration."""
    __tablename__ = "system_settings"
    
    id = Column(Integer, primary_key=True, index=True)
    key = Column(String(100), unique=True, nullable=False, index=True)
    value = Column(Text, nullable=True)
    description = Column(Text, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    
    def __repr__(self):
        return f"<SystemSettings(key='{self.key}', value='{self.value}')>"
    
    def to_dict(self):
        """Convert system setting to dictionary."""
        return {
            "id": self.id,
            "key": self.key,
            "value": self.value,
            "description": self.description,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None
        }


# Database utility functions
def create_tables(engine):
    """Create all database tables."""
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables created successfully")
    except Exception as e:
        logger.error(f"Failed to create database tables: {e}")
        raise


def drop_tables(engine):
    """Drop all database tables."""
    try:
        Base.metadata.drop_all(bind=engine)
        logger.info("Database tables dropped successfully")
    except Exception as e:
        logger.error(f"Failed to drop database tables: {e}")
        raise
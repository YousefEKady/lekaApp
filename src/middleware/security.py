#!/usr/bin/env python3
"""
Security Middleware - Leka-App SaaS Edition

Security middleware for adding security headers, CSRF protection,
and other security measures to the FastAPI application.

Author: Yousef
Project: Leka-App SaaS Edition
"""

import logging
import time
import secrets
from typing import Callable, Dict, Any
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
from src.config.config import config

logger = logging.getLogger(__name__)


class SecurityMiddleware(BaseHTTPMiddleware):
    """
    Security middleware that adds various security headers and protections.
    """
    
    def __init__(
        self,
        app: ASGIApp,
        add_security_headers: bool = True,
        enable_csrf_protection: bool = False,
        max_request_size: int = 10 * 1024 * 1024,  # 10MB
        trusted_hosts: list = None
    ):
        super().__init__(app)
        self.add_security_headers = add_security_headers
        self.enable_csrf_protection = enable_csrf_protection
        self.max_request_size = max_request_size
        self.trusted_hosts = trusted_hosts or []
        
        logger.info("Security middleware initialized")
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Process the request and add security measures.
        """
        start_time = time.time()
        
        try:
            # Check request size
            if hasattr(request, 'headers') and 'content-length' in request.headers:
                content_length = int(request.headers.get('content-length', 0))
                if content_length > self.max_request_size:
                    logger.warning(f"Request too large: {content_length} bytes from {request.client.host if request.client else 'unknown'}")
                    return JSONResponse(
                        status_code=413,
                        content={"detail": "Request entity too large"}
                    )
            
            # Check trusted hosts
            if self.trusted_hosts and hasattr(request, 'headers'):
                host = request.headers.get('host')
                if host and host not in self.trusted_hosts:
                    logger.warning(f"Untrusted host: {host} from {request.client.host if request.client else 'unknown'}")
                    return JSONResponse(
                        status_code=400,
                        content={"detail": "Invalid host header"}
                    )
            
            # CSRF protection for state-changing methods
            if self.enable_csrf_protection and request.method in ['POST', 'PUT', 'PATCH', 'DELETE']:
                csrf_token = request.headers.get('X-CSRF-Token')
                if not csrf_token:
                    logger.warning(f"Missing CSRF token from {request.client.host if request.client else 'unknown'}")
                    return JSONResponse(
                        status_code=403,
                        content={"detail": "CSRF token required"}
                    )
            
            # Process the request
            response = await call_next(request)
            
            # Add security headers
            if self.add_security_headers:
                self._add_security_headers(response)
            
            # Add processing time header
            process_time = time.time() - start_time
            response.headers["X-Process-Time"] = str(process_time)
            
            return response
            
        except Exception as e:
            logger.error(f"Security middleware error: {e}")
            return JSONResponse(
                status_code=500,
                content={"detail": "Internal server error"}
            )
    
    def _add_security_headers(self, response: Response) -> None:
        """
        Add security headers to the response.
        """
        # Prevent clickjacking
        response.headers["X-Frame-Options"] = "DENY"
        
        # Prevent MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"
        
        # Enable XSS protection
        response.headers["X-XSS-Protection"] = "1; mode=block"
        
        # Referrer policy
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        # Content Security Policy (basic)
        csp_policy = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "font-src 'self' https:; "
            "connect-src 'self' https:; "
            "frame-ancestors 'none';"
        )
        response.headers["Content-Security-Policy"] = csp_policy
        
        # Strict Transport Security (HTTPS only)
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        
        # Permissions Policy
        response.headers["Permissions-Policy"] = (
            "geolocation=(), "
            "microphone=(), "
            "camera=(), "
            "payment=(), "
            "usb=(), "
            "magnetometer=(), "
            "gyroscope=(), "
            "accelerometer=()"
        )
        
        # Server header
        response.headers["Server"] = "Leka-App SaaS"
        
        # Remove potentially sensitive headers
        response.headers.pop("X-Powered-By", None)


def generate_csrf_token() -> str:
    """
    Generate a CSRF token.
    
    Returns:
        A secure random CSRF token
    """
    return secrets.token_urlsafe(32)


def validate_csrf_token(token: str, expected_token: str) -> bool:
    """
    Validate a CSRF token.
    
    Args:
        token: The token to validate
        expected_token: The expected token value
    
    Returns:
        True if the token is valid, False otherwise
    """
    if not token or not expected_token:
        return False
    
    return secrets.compare_digest(token, expected_token)


def get_security_config() -> Dict[str, Any]:
    """
    Get security configuration for documentation or debugging.
    
    Returns:
        Dictionary containing security configuration
    """
    return {
        "description": "Security middleware configuration for Leka-App SaaS Edition",
        "features": {
            "security_headers": {
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
                "X-XSS-Protection": "1; mode=block",
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "Content-Security-Policy": "Configured for secure operation",
                "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
                "Permissions-Policy": "Restrictive permissions"
            },
            "protections": {
                "csrf_protection": "Optional CSRF token validation",
                "request_size_limit": "10MB maximum request size",
                "trusted_hosts": "Host header validation",
                "processing_time": "Request processing time tracking"
            }
        },
        "recommendations": [
            "Enable HTTPS in production",
            "Configure trusted hosts for production",
            "Enable CSRF protection for sensitive operations",
            "Review and customize Content Security Policy",
            "Monitor security headers with security scanners"
        ]
    }
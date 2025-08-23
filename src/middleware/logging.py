#!/usr/bin/env python3
"""
Request Logging Middleware - Leka-App SaaS Edition

Middleware for logging HTTP requests and responses, including
performance metrics and security monitoring.

Author: Yousef
Project: Leka-App SaaS Edition
"""

import logging
import time
import json
import uuid
from typing import Callable, Dict, Any, Optional
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

logger = logging.getLogger(__name__)


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """
    Middleware for logging HTTP requests and responses with detailed information.
    """
    
    def __init__(
        self,
        app: ASGIApp,
        log_requests: bool = True,
        log_responses: bool = True,
        log_request_body: bool = False,
        log_response_body: bool = False,
        exclude_paths: list = None,
        sensitive_headers: list = None
    ):
        super().__init__(app)
        self.log_requests = log_requests
        self.log_responses = log_responses
        self.log_request_body = log_request_body
        self.log_response_body = log_response_body
        self.exclude_paths = exclude_paths or ['/health', '/metrics', '/favicon.ico']
        self.sensitive_headers = sensitive_headers or [
            'authorization', 'cookie', 'x-api-key', 'x-csrf-token'
        ]
        
        logger.info("Request logging middleware initialized")
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Process the request and log relevant information.
        """
        # Generate unique request ID
        request_id = str(uuid.uuid4())
        start_time = time.time()
        
        # Skip logging for excluded paths
        if request.url.path in self.exclude_paths:
            return await call_next(request)
        
        # Log request
        if self.log_requests:
            await self._log_request(request, request_id)
        
        try:
            # Process the request
            response = await call_next(request)
            
            # Calculate processing time
            process_time = time.time() - start_time
            
            # Add request ID to response headers
            response.headers["X-Request-ID"] = request_id
            response.headers["X-Process-Time"] = f"{process_time:.4f}"
            
            # Log response
            if self.log_responses:
                await self._log_response(request, response, request_id, process_time)
            
            return response
            
        except Exception as e:
            # Log error
            process_time = time.time() - start_time
            await self._log_error(request, e, request_id, process_time)
            raise
    
    async def _log_request(self, request: Request, request_id: str) -> None:
        """
        Log incoming request details.
        """
        try:
            # Get client information
            client_ip = self._get_client_ip(request)
            user_agent = request.headers.get('user-agent', 'Unknown')
            
            # Get user information if available
            user_info = await self._get_user_info(request)
            
            # Prepare request data
            request_data = {
                "request_id": request_id,
                "method": request.method,
                "url": str(request.url),
                "path": request.url.path,
                "query_params": dict(request.query_params),
                "client_ip": client_ip,
                "user_agent": user_agent,
                "headers": self._sanitize_headers(dict(request.headers)),
                "user_info": user_info,
                "timestamp": time.time()
            }
            
            # Add request body if enabled
            if self.log_request_body and request.method in ['POST', 'PUT', 'PATCH']:
                try:
                    body = await self._get_request_body(request)
                    if body:
                        request_data["body"] = body
                except Exception as e:
                    logger.warning(f"Failed to read request body: {e}")
            
            logger.info(f"Request: {json.dumps(request_data, default=str)}")
            
        except Exception as e:
            logger.error(f"Failed to log request: {e}")
    
    async def _log_response(self, request: Request, response: Response, request_id: str, process_time: float) -> None:
        """
        Log response details.
        """
        try:
            # Prepare response data
            response_data = {
                "request_id": request_id,
                "status_code": response.status_code,
                "headers": self._sanitize_headers(dict(response.headers)),
                "process_time": process_time,
                "timestamp": time.time()
            }
            
            # Add response body if enabled and not too large
            if self.log_response_body and hasattr(response, 'body'):
                try:
                    body = await self._get_response_body(response)
                    if body and len(str(body)) < 1000:  # Limit body size
                        response_data["body"] = body
                except Exception as e:
                    logger.warning(f"Failed to read response body: {e}")
            
            # Log with appropriate level based on status code
            if response.status_code >= 500:
                logger.error(f"Response: {json.dumps(response_data, default=str)}")
            elif response.status_code >= 400:
                logger.warning(f"Response: {json.dumps(response_data, default=str)}")
            else:
                logger.info(f"Response: {json.dumps(response_data, default=str)}")
            
        except Exception as e:
            logger.error(f"Failed to log response: {e}")
    
    async def _log_error(self, request: Request, error: Exception, request_id: str, process_time: float) -> None:
        """
        Log error details.
        """
        try:
            error_data = {
                "request_id": request_id,
                "method": request.method,
                "url": str(request.url),
                "error_type": type(error).__name__,
                "error_message": str(error),
                "process_time": process_time,
                "client_ip": self._get_client_ip(request),
                "timestamp": time.time()
            }
            
            logger.error(f"Request Error: {json.dumps(error_data, default=str)}")
            
        except Exception as e:
            logger.error(f"Failed to log error: {e}")
    
    def _get_client_ip(self, request: Request) -> str:
        """
        Get the client IP address from the request.
        """
        # Check for forwarded headers (proxy/load balancer)
        forwarded_for = request.headers.get('x-forwarded-for')
        if forwarded_for:
            return forwarded_for.split(',')[0].strip()
        
        real_ip = request.headers.get('x-real-ip')
        if real_ip:
            return real_ip
        
        # Fallback to direct client IP
        if request.client:
            return request.client.host
        
        return 'unknown'
    
    async def _get_user_info(self, request: Request) -> Optional[Dict[str, Any]]:
        """
        Extract user information from the request if available.
        """
        try:
            # Check for authorization header
            auth_header = request.headers.get('authorization')
            if auth_header and auth_header.startswith('Bearer '):
                # In a real implementation, you would decode the JWT token here
                return {
                    "authenticated": True,
                    "auth_type": "bearer"
                }
            
            # Check for API key
            api_key = request.headers.get('x-api-key')
            if api_key:
                return {
                    "authenticated": True,
                    "auth_type": "api_key"
                }
            
            return {
                "authenticated": False,
                "auth_type": None
            }
            
        except Exception as e:
            logger.warning(f"Failed to extract user info: {e}")
            return None
    
    def _sanitize_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """
        Remove or mask sensitive headers.
        """
        sanitized = {}
        
        for key, value in headers.items():
            key_lower = key.lower()
            
            if key_lower in self.sensitive_headers:
                # Mask sensitive headers
                if key_lower == 'authorization' and value.startswith('Bearer '):
                    sanitized[key] = 'Bearer ***'
                else:
                    sanitized[key] = '***'
            else:
                sanitized[key] = value
        
        return sanitized
    
    async def _get_request_body(self, request: Request) -> Optional[str]:
        """
        Get request body content.
        """
        try:
            body = await request.body()
            if body:
                # Try to decode as JSON first
                try:
                    return json.loads(body.decode('utf-8'))
                except (json.JSONDecodeError, UnicodeDecodeError):
                    # Return as string if not JSON
                    return body.decode('utf-8', errors='ignore')[:1000]  # Limit size
            return None
        except Exception:
            return None
    
    async def _get_response_body(self, response: Response) -> Optional[str]:
        """
        Get response body content.
        """
        try:
            if hasattr(response, 'body') and response.body:
                body = response.body
                if isinstance(body, bytes):
                    try:
                        return json.loads(body.decode('utf-8'))
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        return body.decode('utf-8', errors='ignore')[:1000]
                return str(body)[:1000]
            return None
        except Exception:
            return None


def get_logging_config() -> Dict[str, Any]:
    """
    Get logging configuration for documentation or debugging.
    
    Returns:
        Dictionary containing logging configuration
    """
    return {
        "description": "Request logging middleware configuration for Leka-App SaaS Edition",
        "features": {
            "request_logging": "Log incoming HTTP requests with details",
            "response_logging": "Log HTTP responses with status and timing",
            "error_logging": "Log errors and exceptions with context",
            "performance_tracking": "Track request processing time",
            "security_monitoring": "Monitor authentication and client information",
            "header_sanitization": "Remove or mask sensitive headers"
        },
        "logged_information": {
            "request": [
                "Request ID", "HTTP method", "URL and path", "Query parameters",
                "Client IP", "User agent", "Headers (sanitized)", "User info", "Timestamp"
            ],
            "response": [
                "Request ID", "Status code", "Headers (sanitized)", 
                "Processing time", "Timestamp"
            ],
            "error": [
                "Request ID", "HTTP method", "URL", "Error type", 
                "Error message", "Processing time", "Client IP", "Timestamp"
            ]
        },
        "privacy": {
            "sensitive_headers": ["authorization", "cookie", "x-api-key", "x-csrf-token"],
            "excluded_paths": ["/health", "/metrics", "/favicon.ico"],
            "body_logging": "Optional and size-limited"
        }
    }
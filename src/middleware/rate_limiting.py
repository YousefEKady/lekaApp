#!/usr/bin/env python3
"""
Rate Limiting Middleware - Leka-App SaaS Edition

Rate limiting middleware to protect the API from abuse and ensure
fair usage across all users and companies.

Author: Yousef
Project: Leka-App SaaS Edition
"""

import logging
import time
import json
from typing import Callable, Dict, Any, Optional, Tuple
from collections import defaultdict, deque
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
from src.config.config import config

logger = logging.getLogger(__name__)


class RateLimitingMiddleware(BaseHTTPMiddleware):
    """
    Rate limiting middleware using sliding window algorithm.
    """
    
    def __init__(
        self,
        app: ASGIApp,
        default_requests_per_minute: int = 60,
        default_requests_per_hour: int = 1000,
        burst_requests: int = 10,
        exclude_paths: list = None,
        rate_limit_by_user: bool = True,
        rate_limit_by_ip: bool = True,
        custom_limits: Dict[str, Dict[str, int]] = None
    ):
        super().__init__(app)
        self.default_requests_per_minute = default_requests_per_minute
        self.default_requests_per_hour = default_requests_per_hour
        self.burst_requests = burst_requests
        self.exclude_paths = exclude_paths or ['/health', '/metrics', '/docs', '/openapi.json']
        self.rate_limit_by_user = rate_limit_by_user
        self.rate_limit_by_ip = rate_limit_by_ip
        self.custom_limits = custom_limits or {}
        
        # In-memory storage for rate limiting (use Redis in production)
        self.request_counts = defaultdict(lambda: {
            'minute': deque(),
            'hour': deque(),
            'burst': deque()
        })
        
        logger.info("Rate limiting middleware initialized")
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Process the request and apply rate limiting.
        """
        # Skip rate limiting for excluded paths
        if request.url.path in self.exclude_paths:
            return await call_next(request)
        
        # Get client identifier
        client_id = await self._get_client_identifier(request)
        
        # Check rate limits
        is_allowed, limit_info = await self._check_rate_limits(request, client_id)
        
        if not is_allowed:
            logger.warning(f"Rate limit exceeded for client: {client_id}, path: {request.url.path}")
            return self._create_rate_limit_response(limit_info)
        
        # Record the request
        await self._record_request(client_id)
        
        # Process the request
        response = await call_next(request)
        
        # Add rate limit headers
        self._add_rate_limit_headers(response, client_id, limit_info)
        
        return response
    
    async def _get_client_identifier(self, request: Request) -> str:
        """
        Get a unique identifier for the client.
        """
        identifiers = []
        
        # Add user ID if authenticated
        if self.rate_limit_by_user:
            user_id = await self._get_user_id(request)
            if user_id:
                identifiers.append(f"user:{user_id}")
        
        # Add IP address
        if self.rate_limit_by_ip:
            client_ip = self._get_client_ip(request)
            identifiers.append(f"ip:{client_ip}")
        
        # Combine identifiers
        if identifiers:
            return "|".join(identifiers)
        
        # Fallback to IP only
        return f"ip:{self._get_client_ip(request)}"
    
    async def _get_user_id(self, request: Request) -> Optional[str]:
        """
        Extract user ID from the request if available.
        """
        try:
            # Check for authorization header
            auth_header = request.headers.get('authorization')
            if auth_header and auth_header.startswith('Bearer '):
                # In a real implementation, you would decode the JWT token here
                # For now, return a placeholder
                token = auth_header.split(' ')[1]
                # TODO: Decode JWT and extract user ID
                return f"token_user_{hash(token) % 10000}"
            
            return None
            
        except Exception as e:
            logger.warning(f"Failed to extract user ID: {e}")
            return None
    
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
    
    async def _check_rate_limits(self, request: Request, client_id: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Check if the request is within rate limits.
        
        Returns:
            Tuple of (is_allowed, limit_info)
        """
        current_time = time.time()
        
        # Get rate limits for this client/endpoint
        limits = self._get_rate_limits(request)
        
        # Clean old entries
        self._cleanup_old_entries(client_id, current_time)
        
        # Get current counts
        counts = self.request_counts[client_id]
        
        # Check burst limit (last 10 seconds)
        burst_count = len([t for t in counts['burst'] if current_time - t <= 10])
        
        # Check minute limit
        minute_count = len([t for t in counts['minute'] if current_time - t <= 60])
        
        # Check hour limit
        hour_count = len([t for t in counts['hour'] if current_time - t <= 3600])
        
        # Prepare limit info
        limit_info = {
            'limits': limits,
            'current_counts': {
                'burst': burst_count,
                'minute': minute_count,
                'hour': hour_count
            },
            'reset_times': {
                'burst': current_time + 10,
                'minute': current_time + 60,
                'hour': current_time + 3600
            }
        }
        
        # Check limits
        if burst_count >= limits['burst']:
            limit_info['exceeded'] = 'burst'
            return False, limit_info
        
        if minute_count >= limits['minute']:
            limit_info['exceeded'] = 'minute'
            return False, limit_info
        
        if hour_count >= limits['hour']:
            limit_info['exceeded'] = 'hour'
            return False, limit_info
        
        return True, limit_info
    
    def _get_rate_limits(self, request: Request) -> Dict[str, int]:
        """
        Get rate limits for the current request.
        """
        # Check for custom limits based on path or method
        path = request.url.path
        method = request.method
        
        # Check custom limits
        for pattern, limits in self.custom_limits.items():
            if pattern in path or pattern == method:
                return {
                    'burst': limits.get('burst', self.burst_requests),
                    'minute': limits.get('minute', self.default_requests_per_minute),
                    'hour': limits.get('hour', self.default_requests_per_hour)
                }
        
        # Return default limits
        return {
            'burst': self.burst_requests,
            'minute': self.default_requests_per_minute,
            'hour': self.default_requests_per_hour
        }
    
    def _cleanup_old_entries(self, client_id: str, current_time: float) -> None:
        """
        Remove old entries from the request counts.
        """
        counts = self.request_counts[client_id]
        
        # Clean burst entries (older than 10 seconds)
        while counts['burst'] and current_time - counts['burst'][0] > 10:
            counts['burst'].popleft()
        
        # Clean minute entries (older than 60 seconds)
        while counts['minute'] and current_time - counts['minute'][0] > 60:
            counts['minute'].popleft()
        
        # Clean hour entries (older than 3600 seconds)
        while counts['hour'] and current_time - counts['hour'][0] > 3600:
            counts['hour'].popleft()
    
    async def _record_request(self, client_id: str) -> None:
        """
        Record a request for the client.
        """
        current_time = time.time()
        counts = self.request_counts[client_id]
        
        # Add to all time windows
        counts['burst'].append(current_time)
        counts['minute'].append(current_time)
        counts['hour'].append(current_time)
    
    def _create_rate_limit_response(self, limit_info: Dict[str, Any]) -> JSONResponse:
        """
        Create a rate limit exceeded response.
        """
        exceeded_limit = limit_info.get('exceeded', 'unknown')
        reset_time = limit_info['reset_times'].get(exceeded_limit, time.time() + 60)
        
        headers = {
            "X-RateLimit-Limit": str(limit_info['limits'][exceeded_limit]),
            "X-RateLimit-Remaining": "0",
            "X-RateLimit-Reset": str(int(reset_time)),
            "Retry-After": str(int(reset_time - time.time()))
        }
        
        return JSONResponse(
            status_code=429,
            content={
                "detail": f"Rate limit exceeded. Too many requests per {exceeded_limit}.",
                "error": "rate_limit_exceeded",
                "limit_type": exceeded_limit,
                "retry_after": int(reset_time - time.time())
            },
            headers=headers
        )
    
    def _add_rate_limit_headers(self, response: Response, client_id: str, limit_info: Dict[str, Any]) -> None:
        """
        Add rate limit headers to the response.
        """
        try:
            # Add headers for minute limit (most commonly used)
            minute_limit = limit_info['limits']['minute']
            minute_remaining = minute_limit - limit_info['current_counts']['minute']
            minute_reset = limit_info['reset_times']['minute']
            
            response.headers["X-RateLimit-Limit"] = str(minute_limit)
            response.headers["X-RateLimit-Remaining"] = str(max(0, minute_remaining))
            response.headers["X-RateLimit-Reset"] = str(int(minute_reset))
            
            # Add burst limit headers
            burst_limit = limit_info['limits']['burst']
            burst_remaining = burst_limit - limit_info['current_counts']['burst']
            
            response.headers["X-RateLimit-Burst-Limit"] = str(burst_limit)
            response.headers["X-RateLimit-Burst-Remaining"] = str(max(0, burst_remaining))
            
        except Exception as e:
            logger.warning(f"Failed to add rate limit headers: {e}")


def get_rate_limiting_config() -> Dict[str, Any]:
    """
    Get rate limiting configuration for documentation or debugging.
    
    Returns:
        Dictionary containing rate limiting configuration
    """
    return {
        "description": "Rate limiting middleware configuration for Leka-App SaaS Edition",
        "default_limits": {
            "requests_per_minute": 60,
            "requests_per_hour": 1000,
            "burst_requests": 10
        },
        "features": {
            "sliding_window": "Uses sliding window algorithm for accurate rate limiting",
            "multiple_time_windows": "Supports burst, minute, and hour limits",
            "user_based_limiting": "Rate limits per authenticated user",
            "ip_based_limiting": "Rate limits per IP address",
            "custom_limits": "Supports custom limits per endpoint or method",
            "excluded_paths": "Excludes health checks and documentation from limits"
        },
        "headers": {
            "X-RateLimit-Limit": "Maximum requests allowed per minute",
            "X-RateLimit-Remaining": "Remaining requests in current window",
            "X-RateLimit-Reset": "Unix timestamp when limit resets",
            "X-RateLimit-Burst-Limit": "Maximum burst requests allowed",
            "X-RateLimit-Burst-Remaining": "Remaining burst requests",
            "Retry-After": "Seconds to wait before retrying (when limit exceeded)"
        },
        "response_codes": {
            "429": "Too Many Requests - Rate limit exceeded"
        },
        "recommendations": [
            "Use Redis for distributed rate limiting in production",
            "Configure custom limits for different API endpoints",
            "Monitor rate limit metrics for capacity planning",
            "Implement exponential backoff in client applications",
            "Consider implementing API keys for higher limits"
        ]
    }


# Example custom limits configuration
EXAMPLE_CUSTOM_LIMITS = {
    "/api/auth/login": {
        "burst": 5,
        "minute": 10,
        "hour": 100
    },
    "/api/admin/leaks/upload": {
        "burst": 2,
        "minute": 5,
        "hour": 50
    },
    "POST": {
        "burst": 8,
        "minute": 40,
        "hour": 800
    }
}
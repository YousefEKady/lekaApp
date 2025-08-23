#!/usr/bin/env python3
"""
CORS Middleware - Leka-App SaaS Edition

CORS (Cross-Origin Resource Sharing) configuration for the FastAPI application.
Handles cross-origin requests from frontend applications.

Author: Yousef
Project: Leka-App SaaS Edition
"""

import logging
from typing import List
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from src.config.config import config

logger = logging.getLogger(__name__)


def setup_cors(app: FastAPI, allowed_origins: List[str] = None) -> None:
    """
    Setup CORS middleware for the FastAPI application.
    
    Args:
        app: FastAPI application instance
        allowed_origins: List of allowed origins. If None, uses default development origins.
    """
    
    # Get origins from config or use provided ones
    if allowed_origins is None:
        allowed_origins = config.CORS_ORIGINS
    
    logger.info(f"Setting up CORS with allowed origins: {allowed_origins}")
    
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=[
            "GET",
            "POST", 
            "PUT",
            "DELETE",
            "PATCH",
            "OPTIONS",
            "HEAD"
        ],
        allow_headers=[
            "Accept",
            "Accept-Language",
            "Content-Language",
            "Content-Type",
            "Authorization",
            "X-Requested-With",
            "X-CSRF-Token",
            "X-API-Key",
            "Cache-Control",
            "Pragma",
            "Expires"
        ],
        expose_headers=[
            "X-Total-Count",
            "X-Page-Count",
            "X-Rate-Limit-Remaining",
            "X-Rate-Limit-Reset"
        ],
        max_age=86400  # 24 hours
    )
    
    logger.info("CORS middleware configured successfully")


def get_cors_config() -> dict:
    """
    Get CORS configuration for documentation or debugging.
    
    Returns:
        Dictionary containing CORS configuration
    """
    return {
        "description": "CORS configuration for Leka-App SaaS Edition",
        "allowed_methods": ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"],
        "allowed_headers": [
            "Accept", "Accept-Language", "Content-Language", "Content-Type",
            "Authorization", "X-Requested-With", "X-CSRF-Token", "X-API-Key",
            "Cache-Control", "Pragma", "Expires"
        ],
        "expose_headers": [
            "X-Total-Count", "X-Page-Count", 
            "X-Rate-Limit-Remaining", "X-Rate-Limit-Reset"
        ],
        "max_age": 86400,
        "allow_credentials": True
    }
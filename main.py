#!/usr/bin/env python3
"""
Leka-App SaaS Edition - FastAPI Backend

Main FastAPI application for the Dark Web Threat Intelligence Analyzer SaaS platform.
Provides REST API endpoints for company users and super admins to manage
leak detection and monitoring.

Author: Yousef
Project: Leka-App SaaS Edition
"""

import os
import time
import logging
from contextlib import asynccontextmanager
from typing import Dict, Any

from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi

try:
    from src.config.config import config
    from src.utils.logging_config import LoggingManager
except ImportError as e:
    print(f"Error importing configuration: {e}")
    raise

# Initialize logging
logging_manager = LoggingManager()
logging_manager.setup_logging(
    level=getattr(config, 'LOG_LEVEL', 'INFO'),
    enable_file_logging=True,
    enable_console_logging=True
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager for startup and shutdown events."""
    # Startup
    logger.info(f"Starting {config.APP_NAME} v{config.APP_VERSION}")
    
    # Initialize services
    try:
        # Initialize Elasticsearch service
        from src.services.elasticsearch_service import ElasticsearchService
        from src.services.leak_service import initialize_leak_service
        
        # Create Elasticsearch service instance
        es_service = ElasticsearchService(
            hosts=[config.get_elasticsearch_url()],
            timeout=30
        )
        
        # Create indices if they don't exist
        await es_service.create_indices()
        
        # Initialize leak service with Elasticsearch service
        initialize_leak_service(es_service)
        
        # Store service instances in app state for access in routes
        app.state.elasticsearch_service = es_service
        
        logger.info("All services initialized successfully")
        
    except Exception as e:
        logger.error(f"Failed to initialize services: {e}")
        raise
    
    yield
    
    # Shutdown
    logger.info(f"Shutting down {config.APP_NAME}")
    # Cleanup services if needed
    try:
        if hasattr(app.state, 'elasticsearch_service'):
            # Close Elasticsearch connections
            logger.info("Elasticsearch service cleaned up")
    except Exception as e:
        logger.error(f"Error during service cleanup: {e}")


# Create FastAPI application
app = FastAPI(
    title=config.APP_NAME,
    description=config.APP_DESCRIPTION,
    version=config.APP_VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan
)

# Security middleware
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["localhost", "127.0.0.1", "*.yourdomain.com"]
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    **config.get_cors_config()
)


@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all incoming requests for monitoring and debugging."""
    start_time = time.time()
    
    # Log request
    logger.info(
        f"Request: {request.method} {request.url.path} "
        f"from {request.client.host if request.client else 'unknown'}"
    )
    
    response = await call_next(request)
    
    # Log response
    process_time = time.time() - start_time
    logger.info(
        f"Response: {response.status_code} "
        f"({process_time:.3f}s)"
    )
    
    return response


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Custom HTTP exception handler."""
    logger.warning(
        f"HTTP {exc.status_code}: {exc.detail} "
        f"for {request.method} {request.url.path}"
    )
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "status_code": exc.status_code,
            "path": str(request.url.path)
        }
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """General exception handler for unhandled errors."""
    logger.error(
        f"Unhandled exception: {str(exc)} "
        f"for {request.method} {request.url.path}",
        exc_info=True
    )
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "status_code": 500,
            "path": str(request.url.path)
        }
    )


# Health check endpoint
@app.get("/health", tags=["System"])
async def health_check() -> Dict[str, Any]:
    """Health check endpoint for monitoring."""
    return {
        "status": "healthy",
        "service": "Leka-App SaaS API",
        "version": "2.0.0",
        "timestamp": time.time()
    }


# Root endpoint
@app.get("/", tags=["System"])
async def root() -> Dict[str, str]:
    """Root endpoint with API information."""
    return {
        "message": "Welcome to Leka-App SaaS Edition API",
        "version": "2.0.0",
        "docs": "/docs",
        "redoc": "/redoc"
    }


# Import and include routers
try:
    from src.api.routes.auth_routes import router as auth_router
    from src.api.routes.company_routes import router as company_router
    from src.api.routes.admin_routes import router as admin_router
    
    app.include_router(auth_router)
    app.include_router(company_router)
    app.include_router(admin_router)
    
    logger.info("All API routes successfully registered")
except ImportError as e:
    logger.error(f"Failed to import API routes: {e}")
    raise


if __name__ == "__main__":
    import uvicorn
    
    # Development server configuration
    uvicorn.run(
        "main:app",
        host=config.HOST,
        port=config.PORT,
        reload=config.RELOAD,
        log_level="info",
        access_log=True
    )
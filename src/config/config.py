import os
import logging
from typing import Optional, List
from dotenv import load_dotenv
from pydantic import Field, validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Load environment variables from .env file
load_dotenv()

# Configure logging for configuration module
logger = logging.getLogger(__name__)

class ConfigurationError(Exception):
    """Custom exception for configuration-related errors."""
    pass

class Config:
    """Configuration management class with validation and defaults."""
    
    def __init__(self):
        """Initialize configuration with validation."""
        self._validate_and_set_config()
        self._validate_and_set_fastapi_config()
    
    def _validate_and_set_config(self) -> None:
        """Validate and set all configuration parameters."""
        try:
            # Elasticsearch Configuration
            self.ELASTICSEARCH_HOST = self._get_env_var(
                "ELASTICSEARCH_HOST", 
                default="localhost",  # TODO: Change to production Elasticsearch host in production
                description="Elasticsearch host address"
            )
            
            self.ELASTICSEARCH_PORT = self._get_int_env_var(
                "ELASTICSEARCH_PORT", 
                default=9200,
                min_value=1,
                max_value=65535,
                description="Elasticsearch port number"
            )
            
            self.ELASTICSEARCH_INDEX = self._get_env_var(
                "ELASTICSEARCH_INDEX", 
                default="leaks",
                description="Elasticsearch index name"
            )
            
            self.ELASTICSEARCH_USERNAME = self._get_env_var(
                "ELASTICSEARCH_USERNAME", 
                required=False,
                description="Elasticsearch username for authentication"
            )
            
            self.ELASTICSEARCH_PASSWORD = self._get_env_var(
                "ELASTICSEARCH_PASSWORD", 
                required=False,
                description="Elasticsearch password for authentication"
            )
            
            self.ELASTICSEARCH_USE_SSL = self._get_bool_env_var(
                "ELASTICSEARCH_USE_SSL",
                default=False,
                description="Enable SSL for Elasticsearch connection"
            )
            
            self.ELASTICSEARCH_VERIFY_CERTS = self._get_bool_env_var(
                "ELASTICSEARCH_VERIFY_CERTS",
                default=True,
                description="Verify SSL certificates for Elasticsearch"
            )
            
            self.ELASTICSEARCH_TIMEOUT = self._get_int_env_var(
                "ELASTICSEARCH_TIMEOUT",
                default=30,
                min_value=5,
                max_value=300,
                description="Elasticsearch request timeout in seconds"
            )
            
            # Data Filtering Configuration
            self.FILTER_INVALID_URLS = self._get_bool_env_var(
                "FILTER_INVALID_URLS",
                default=True,
                description="Enable filtering of invalid URL patterns"
            )
            
            self.FILTER_CONTROL_CHARACTERS = self._get_bool_env_var(
                "FILTER_CONTROL_CHARACTERS",
                default=True,
                description="Enable filtering of records with control characters"
            )
            
            self.FILTER_LONG_TOKENS = self._get_bool_env_var(
                "FILTER_LONG_TOKENS",
                default=True,
                description="Enable filtering of suspiciously long user tokens"
            )
            
            self.MAX_TOKEN_LENGTH = self._get_int_env_var(
                "MAX_TOKEN_LENGTH",
                default=80,
                min_value=20,
                max_value=200,
                description="Maximum length for usernames before considering them tokens"
            )
            
            # Telegram Configuration (optional)
            self.TELEGRAM_API_ID = self._get_env_var(
                "TELEGRAM_API_ID", 
                required=False,
                description="Telegram API ID"
            )
            
            self.TELEGRAM_API_HASH = self._get_env_var(
                "TELEGRAM_API_HASH", 
                required=False,
                description="Telegram API Hash"
            )
            
            self.TELEGRAM_CHANNEL_ID = self._get_env_var(
                "TELEGRAM_CHANNEL_ID", 
                required=False,
                description="Telegram Channel ID"
            )
            
            # File paths
            self.DOWNLOAD_ROOT = self._get_env_var(
                "TELEGRAM_DOWNLOAD_ROOT", 
                default="downloads",
                description="Root directory for downloads"
            )
            
            self.PARSED_OUTPUT_DIR = self._get_env_var(
                "PARSED_OUTPUT_DIR", 
                default="parsed_leaked_json",
                description="Directory for parsed JSON files"
            )
            
            # Telegram download settings
            self.TELEGRAM_MAX_FILE_SIZE = self._get_env_var(
                "TELEGRAM_MAX_FILE_SIZE", 
                default=None,
                required=False,
                description="Maximum file size for downloads (None for no limit)"
            )
            
            # Logging configuration
            self.LOG_LEVEL = self._get_env_var(
                "LOG_LEVEL", 
                default="INFO",
                description="Logging level"
            ).upper()
            
            self.LOG_FILE = self._get_env_var(
                "LOG_FILE", 
                default="leak_analyzer.log",
                description="Log file path"
            )
            
            logger.info("Configuration loaded successfully")
            
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            raise ConfigurationError(f"Configuration initialization failed: {e}")
    
    def _validate_and_set_fastapi_config(self) -> None:
        """Validate and set FastAPI-specific configuration parameters."""
        try:
            # FastAPI Application Settings
            self.APP_NAME = self._get_env_var(
                "APP_NAME",
                default="Leka-App SaaS Edition",
                required=False,
                description="Application name"
            )
            
            self.APP_VERSION = self._get_env_var(
                "APP_VERSION",
                default="2.0.0",
                required=False,
                description="Application version"
            )
            
            self.APP_DESCRIPTION = self._get_env_var(
                "APP_DESCRIPTION",
                default="Advanced leak detection and monitoring platform",
                required=False,
                description="Application description"
            )
            
            # Server Settings
            self.HOST = self._get_env_var(
                "HOST",
                default="0.0.0.0",
                required=False,
                description="Server host"
            )
            
            self.PORT = self._get_int_env_var(
                "PORT",
                default=8000,
                min_value=1,
                max_value=65535,
                description="Server port"
            )
            
            self.DEBUG = self._get_bool_env_var(
                "DEBUG",
                default=False,
                description="Debug mode"
            )
            
            self.RELOAD = self._get_bool_env_var(
                "RELOAD",
                default=False,
                description="Auto-reload on code changes"
            )
            
            # Environment
            self.ENVIRONMENT = self._get_env_var(
                "ENVIRONMENT",
                default="development",
                required=False,
                description="Environment (development/staging/production)"
            ).lower()
            
            # Database Settings (PostgreSQL)
            self.POSTGRES_HOST = self._get_env_var(
                "POSTGRES_HOST",
                default="localhost",  # TODO: Change to production database host in production
                required=False,
                description="PostgreSQL host"
            )
            
            self.POSTGRES_PORT = self._get_int_env_var(
                "POSTGRES_PORT",
                default=5432,
                min_value=1,
                max_value=65535,
                description="PostgreSQL port"
            )
            
            self.POSTGRES_USER = self._get_env_var(
                "POSTGRES_USER",
                default="postgres",
                required=False,
                description="PostgreSQL username"
            )
            
            self.POSTGRES_PASSWORD = self._get_env_var(
                "POSTGRES_PASSWORD",
                default="",
                required=False,
                description="PostgreSQL password"
            )
            
            self.POSTGRES_DB = self._get_env_var(
                "POSTGRES_DB",
                default="leka_app",
                required=False,
                description="PostgreSQL database name"
            )
            
            # JWT Settings
            self.JWT_SECRET_KEY = self._get_env_var(
                "JWT_SECRET_KEY",
                default="your-secret-key-change-in-production",  # TODO: Change to secure random key in production
                required=False,
                description="JWT secret key"
            )
            
            self.JWT_ALGORITHM = self._get_env_var(
                "JWT_ALGORITHM",
                default="HS256",
                required=False,
                description="JWT algorithm"
            )
            
            self.JWT_ACCESS_TOKEN_EXPIRE_MINUTES = self._get_int_env_var(
                "JWT_ACCESS_TOKEN_EXPIRE_MINUTES",
                default=30,
                min_value=1,
                description="Access token expiration in minutes"
            )
            
            # CORS Settings
            cors_origins_str = self._get_env_var(
                "CORS_ORIGINS",
                default="http://localhost:3000,http://localhost:8080",  # TODO: Change to production frontend URLs in production
                required=False,
                description="CORS allowed origins (comma-separated)"
            )
            self.CORS_ORIGINS = [origin.strip() for origin in cors_origins_str.split(",") if origin.strip()]
            
            # Email Settings
            self.SMTP_HOST = self._get_env_var(
                "SMTP_HOST",
                default="smtp.gmail.com",  # TODO: Change to production SMTP server in production
                required=False,
                description="SMTP host"
            )
            
            self.SMTP_PORT = self._get_int_env_var(
                "SMTP_PORT",
                default=587,
                min_value=1,
                max_value=65535,
                description="SMTP port"
            )
            
            self.SMTP_USERNAME = self._get_env_var(
                "SMTP_USERNAME",
                default="",
                required=False,
                description="SMTP username"
            )
            
            self.SMTP_PASSWORD = self._get_env_var(
                "SMTP_PASSWORD",
                default="",
                required=False,
                description="SMTP password"
            )
            
            self.FROM_EMAIL = self._get_env_var(
                "FROM_EMAIL",
                default="noreply@leka-app.com",
                required=False,
                description="From email address"
            )
            
            # Redis Settings
            self.REDIS_HOST = self._get_env_var(
                "REDIS_HOST",
                default="localhost",
                required=False,
                description="Redis host"
            )
            
            self.REDIS_PORT = self._get_int_env_var(
                "REDIS_PORT",
                default=6379,
                min_value=1,
                max_value=65535,
                description="Redis port"
            )
            
            self.REDIS_PASSWORD = self._get_env_var(
                "REDIS_PASSWORD",
                default=None,
                required=False,
                description="Redis password"
            )
            
            # Rate Limiting
            self.RATE_LIMIT_REQUESTS = self._get_int_env_var(
                "RATE_LIMIT_REQUESTS",
                default=100,
                min_value=1,
                description="Rate limit requests per window"
            )
            
            self.RATE_LIMIT_WINDOW_SECONDS = self._get_int_env_var(
                "RATE_LIMIT_WINDOW_SECONDS",
                default=60,
                min_value=1,
                description="Rate limit window in seconds"
            )
            
            # File Upload Settings
            self.MAX_UPLOAD_SIZE = self._get_int_env_var(
                "MAX_UPLOAD_SIZE",
                default=104857600,  # 100MB
                min_value=1024,
                description="Max upload size in bytes"
            )
            
            logger.info("FastAPI configuration loaded successfully")
            
        except Exception as e:
            logger.error(f"Failed to load FastAPI configuration: {e}")
            raise ConfigurationError(f"FastAPI configuration initialization failed: {e}")
    
    def _get_env_var(self, key: str, default: Optional[str] = None, 
                     required: bool = True, description: str = "") -> str:
        """Get environment variable with validation."""
        value = os.getenv(key, default)
        
        if required and not value:
            raise ConfigurationError(
                f"Required environment variable '{key}' is not set. {description}"
            )
        
        if value:
            logger.debug(f"Loaded {key}: {value[:10]}{'...' if len(str(value)) > 10 else ''}")
        
        return value or ""
    
    def _get_int_env_var(self, key: str, default: int, min_value: int = None, 
                        max_value: int = None, description: str = "") -> int:
        """Get integer environment variable with validation."""
        value_str = os.getenv(key, str(default))
        
        try:
            value = int(value_str)
        except ValueError:
            raise ConfigurationError(
                f"Environment variable '{key}' must be an integer. Got: {value_str}"
            )
        
        if min_value is not None and value < min_value:
            raise ConfigurationError(
                f"Environment variable '{key}' must be >= {min_value}. Got: {value}"
            )
        
        if max_value is not None and value > max_value:
            raise ConfigurationError(
                f"Environment variable '{key}' must be <= {max_value}. Got: {value}"
            )
        
        logger.debug(f"Loaded {key}: {value}")
        return value
    
    def _get_bool_env_var(self, key: str, default: bool = False, description: str = "") -> bool:
        """Get boolean environment variable with validation."""
        value_str = os.getenv(key, str(default)).lower()
        
        if value_str in ('true', '1', 'yes', 'on'):
            value = True
        elif value_str in ('false', '0', 'no', 'off'):
            value = False
        else:
            raise ConfigurationError(
                f"Environment variable '{key}' must be a boolean value. Got: {value_str}"
            )
        
        logger.debug(f"Loaded {key}: {value}")
        return value
    
    def get_elasticsearch_url(self) -> str:
        """Get complete Elasticsearch URL."""
        return f"http://{self.ELASTICSEARCH_HOST}:{self.ELASTICSEARCH_PORT}"  # TODO: Change to https:// and production URL in production
    
    def get_postgres_url(self, async_mode: bool = False) -> str:
        """Get PostgreSQL connection URL."""
        driver = "postgresql+asyncpg" if async_mode else "postgresql"
        return (
            f"{driver}://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"  # TODO: Change to production database URL in production
        )
    
    def get_redis_url(self) -> str:
        """Get Redis connection URL."""
        if self.REDIS_PASSWORD:
            return f"redis://:{self.REDIS_PASSWORD}@{self.REDIS_HOST}:{self.REDIS_PORT}/0"  # TODO: Change to production Redis URL in production
        return f"redis://{self.REDIS_HOST}:{self.REDIS_PORT}/0"  # TODO: Change to production Redis URL in production
    
    def validate_telegram_config(self) -> bool:
        """Check if Telegram configuration is complete."""
        return bool(self.TELEGRAM_API_ID and self.TELEGRAM_API_HASH and self.TELEGRAM_CHANNEL_ID)
    
    def is_development(self) -> bool:
        """Check if running in development mode."""
        return self.ENVIRONMENT == "development"
    
    def is_production(self) -> bool:
        """Check if running in production mode."""
        return self.ENVIRONMENT == "production"
    
    def get_cors_config(self) -> dict:
        """Get CORS configuration dictionary."""
        return {
            "allow_origins": self.CORS_ORIGINS,
            "allow_credentials": True,
            "allow_methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            "allow_headers": ["*"],
        }
    
    def get_email_config(self) -> dict:
        """Get email configuration dictionary."""
        return {
            "smtp_host": self.SMTP_HOST,
            "smtp_port": self.SMTP_PORT,
            "smtp_username": self.SMTP_USERNAME,
            "smtp_password": self.SMTP_PASSWORD,
            "from_email": self.FROM_EMAIL,
            "use_tls": True,
            "use_ssl": False,
        }
    
    def __str__(self) -> str:
        """String representation of configuration (without sensitive data)."""
        return f"Config(elasticsearch={self.get_elasticsearch_url()}, index={self.ELASTICSEARCH_INDEX})"

# Global configuration instance
config = Config()

# Backward compatibility exports
ELASTICSEARCH_HOST = config.ELASTICSEARCH_HOST
ELASTICSEARCH_PORT = config.ELASTICSEARCH_PORT
ELASTICSEARCH_INDEX = config.ELASTICSEARCH_INDEX

# Telegram API exports
TELEGRAM_API_ID = config.TELEGRAM_API_ID
TELEGRAM_API_HASH = config.TELEGRAM_API_HASH
TELEGRAM_CHANNEL_ID = config.TELEGRAM_CHANNEL_ID
TELEGRAM_DOWNLOAD_ROOT = config.DOWNLOAD_ROOT
TELEGRAM_MAX_FILE_SIZE = config.TELEGRAM_MAX_FILE_SIZE
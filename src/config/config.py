import os
import logging
from typing import Optional
from dotenv import load_dotenv

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
    
    def _validate_and_set_config(self) -> None:
        """Validate and set all configuration parameters."""
        try:
            # Elasticsearch Configuration
            self.ELASTICSEARCH_HOST = self._get_env_var(
                "ELASTICSEARCH_HOST", 
                default="localhost",
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
        return f"http://{self.ELASTICSEARCH_HOST}:{self.ELASTICSEARCH_PORT}"
    
    def validate_telegram_config(self) -> bool:
        """Check if Telegram configuration is complete."""
        return bool(self.TELEGRAM_API_ID and self.TELEGRAM_API_HASH and self.TELEGRAM_CHANNEL_ID)
    
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
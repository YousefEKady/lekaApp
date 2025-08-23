# Dark Web Threat Intelligence Analyzer

A comprehensive, production-ready threat intelligence platform designed to collect, parse, and analyze leaked credential data from various sources. The system provides automated data processing, secure storage in Elasticsearch, and advanced analytics capabilities for cybersecurity professionals.

## Recent Improvements

### Critical Fixes
- **Elasticsearch Upload Fix**: Resolved "path argument required" error in upload process
- **Enhanced Data Filtering**: Multi-level filtering system prevents problematic records
- **Configuration Management**: Comprehensive environment variable support
- **Error Handling**: Improved exception handling and logging throughout

### New Features
- **Advanced URL Filtering**: Blocks file://, incomplete protocols, local paths
- **Metadata Detection**: Filters header rows and test data automatically
- **Field Swapping Detection**: Prevents data corruption from swapped fields
- **Configurable Filtering**: All filtering rules can be enabled/disabled
- **Comprehensive Testing**: Complete test suite for filtering validation

## Key Features

### Data Collection & Processing
- **Multi-source data collection**: Telegram channels, file uploads, and various messaging platforms
- **Advanced parsing engine**: Supports multiple credential formats with intelligent pattern recognition
- **Real-time processing**: Asynchronous file processing with progress tracking
- **Duplicate detection**: Prevents data duplication with hash-based validation

### Security & Validation
- **Comprehensive input validation**: Protects against malicious files and data
- **Advanced data filtering**: Multi-level filtering system for data quality
- **File type detection**: Automatic filtering of non-text and dangerous files
- **Credential validation**: Filters out invalid, test, or suspicious credentials
- **URL pattern filtering**: Blocks malformed URLs, file paths, and incomplete protocols
- **Rate limiting**: Prevents API abuse and ensures stable operation

### Performance & Scalability
- **Bulk operations**: Optimized batch processing for large datasets
- **Parallel processing**: Multi-threaded operations for improved performance
- **Memory management**: Efficient handling of large files and datasets
- **Connection pooling**: Optimized database connections

### Monitoring & Analytics
- **Comprehensive logging**: Structured logging with multiple output formats
- **Performance metrics**: Real-time monitoring of processing statistics
- **Error tracking**: Detailed error reporting and recovery mechanisms
- **Progress visualization**: Real-time progress bars and status updates

## System Requirements

### Core Requirements
- **Python 3.10+** (recommended: Python 3.11+)
- **Docker & Docker Compose** (for Elasticsearch and Kibana)
### Python Dependencies
All dependencies are managed through `requirements.txt` with version pinning.

---

## Installation & Setup

### 1. Clone the Repository

```bash
git clone https://github.com/YousefEKady/leakApp.git
cd leakApp
```

### 2. Install Python Dependencies

```bash
# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Environment Configuration

Create a `.env` file in the project root:

```env
# Elasticsearch
ELASTICSEARCH_HOST=localhost
ELASTICSEARCH_PORT=9200
ELASTICSEARCH_INDEX=leaks

# Telegram API
TELEGRAM_API_ID=YOUR_API_ID
TELEGRAM_API_HASH=YOUR_API_HASH
TELEGRAM_CHANNEL_ID=-100XXXXXXXXX
TELEGRAM_DOWNLOAD_ROOT=downloads

# Enable / Disable Filter
FILTER_INVALID_URLS=true    # Filter file:// URLs and invalid patterns
FILTER_CONTROL_CHARACTERS=true # Filter records with tab/characters
FILTER_LONG_TOKENS=true        # Filter suspiciously long usernames
MAX_TOKEN_LENGTH=80

# File Processing Configuration
DOWNLOAD_ROOT=./downloads
PARSED_ROOT=./parsed
LOG_LEVEL=INFO
```

### 4. Start Infrastructure

```bash
# Start Elasticsearch and Kibana
docker-compose up -d

# Verify services are running
docker-compose ps
```

### 5. Initialize Application

```bash
# Create necessary directories
mkdir -p downloads parsed_leaked_json logs
```

## Usage Guide

### Quick Start - Full Pipeline

```bash
# Run the complete pipeline (recommended for most users)
python run_parse_and_upload.py

# Automated mode (no prompts)
python run_parse_and_upload.py --batch

# With custom configuration
python run_parse_and_upload.py --log-level DEBUG --max-workers 8
```

### Individual Components

#### 1. Telegram Data Collection

```bash
# Download from Telegram channels
python -m src.scraper.telegram_scraper

# With date filtering
python -m src.scraper.telegram_scraper --start-date 2024-01-01 --end-date 2024-01-31

# Custom download directory
python -m src.scraper.telegram_scraper --output-dir custom_downloads/
```

#### 2. Data Parsing & Processing

```bash
# Parse all files in downloads directory
python -m src.parser.leak_parser

# Parse specific directory
python -m src.parser.leak_parser --input-dir custom_downloads/ --output-dir custom_parsed/

# With performance optimization
python -m src.parser.leak_parser --max-workers 8 --batch-size 500

# Verbose output with statistics
python -m src.parser.leak_parser --verbose --stats
```

#### 3. Elasticsearch Upload

```bash
# Upload all parsed files
python -m src.elasticsearch.upload_leaks_to_es

# Upload specific file
python -m src.elasticsearch.upload_leaks_to_es parsed_leaked_json/specific_file.json

# Bulk upload with custom settings
python -m src.elasticsearch.upload_leaks_to_es --batch-size 2000 --workers 6

# Skip duplicate checking for faster uploads
python -m src.elasticsearch.upload_leaks_to_es --no-duplicate-check
```

### Advanced Usage

#### Logging and Monitoring

```bash
# Enable debug logging
export LOG_LEVEL=DEBUG
python run_parse_and_upload.py

# Monitor log files
tail -f logs/app.log
tail -f logs/error.log
```

#### Performance Tuning

```bash
# High-performance mode
python run_parse_and_upload.py --max-workers 16 --batch-size 5000

# Memory-conscious mode
python run_parse_and_upload.py --max-workers 2 --batch-size 100
```

## Architecture Overview

### System Components

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Data Sources  │    │   Processing    │    │    Storage      │
│                 │    │                 │    │                 │
│ • Telegram      │───▶│ • Parser        │───▶│ • Elasticsearch │
│ • File Upload   │    │ • Validator     │    │ • Kibana        │
│ • Manual Input  │    │ • Transformer   │    │ • File System   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### Core Modules

- **`src/scraper/`**: Data collection from various sources
- **`src/parser/`**: Intelligent parsing and data extraction
- **`src/elasticsearch/`**: Data storage and search capabilities
- **`src/config/`**: Centralized configuration management
- **`src/utils/`**: Common utilities and helper functions

### Data Flow

1. **Collection**: Raw data gathered from Telegram channels or file uploads
2. **Validation**: Files checked for safety and format compatibility
3. **Parsing**: Credentials extracted using intelligent pattern matching
4. **Transformation**: Data normalized and enriched with metadata
5. **Storage**: Processed data indexed in Elasticsearch
6. **Analysis**: Data searchable and analyzable through Kibana

## Data Filtering System

The application includes a comprehensive multi-level filtering system to ensure data quality and prevent problematic records from being uploaded to Elasticsearch.

### Filtering Levels
1. **Record Creation Level**: Initial filtering during data parsing
2. **Validation Level**: Secondary filtering before Elasticsearch upload

### Filter Types

#### URL Pattern Filtering (`FILTER_INVALID_URLS`)
- **File protocols**: Blocks `file://` URLs
- **Incomplete protocols**: Filters incomplete `https`, `http`, `ftp`
- **Local file paths**: Rejects URLs containing:
  - `\Users\`, `\AppData\`, `\Temp\` directories
  - `.exe`, `.tmp` file extensions
- **Malformed URLs**: Blocks protocol + numbers only (e.g., `https://21.847`)

#### Content Filtering (`FILTER_CONTROL_CHARACTERS`)
- Removes records with control characters
- Filters non-printable characters
- Blocks suspicious character sequences

#### Token Length Filtering (`FILTER_LONG_TOKENS`)
- Configurable maximum username/password length
- Default limit: 80 characters
- Prevents extremely long suspicious tokens

#### Metadata Detection
- Filters records with metadata as usernames:
  - `TITLE`, `NAME`, `USER`, `PASS`, `URL`
  - Header column names
  - Test data indicators

#### Field Swapping Detection
- Identifies swapped field data
- Detects URL data in wrong fields
- Prevents data corruption

### Configuration

```env
# Enable/disable filtering (default: true)
FILTER_INVALID_URLS=true
FILTER_CONTROL_CHARACTERS=true
FILTER_LONG_TOKENS=true

# Customize filtering behavior
MAX_TOKEN_LENGTH=80
```

## Security Features

### Input Validation
- File type and extension validation
- Content scanning for malicious patterns
- Size limits to prevent resource exhaustion
- Path traversal protection

### Data Protection
- SHA256 hashing for file integrity
- Secure credential handling
- Input sanitization and validation
- Rate limiting for API protection

### Access Control
- Environment-based configuration
- Secure API key management
- Logging of all access attempts
- Error handling without information disclosure

## Monitoring & Logging

### Logging Levels
- **DEBUG**: Detailed diagnostic information
- **INFO**: General operational messages
- **WARNING**: Important notices and recoverable errors
- **ERROR**: Error conditions that need attention
- **CRITICAL**: Serious errors that may cause system failure

### Log Files
- `logs/app.log`: Main application log
- `logs/error.log`: Error-specific logging
- `logs/debug.log`: Detailed debugging information
- `logs/performance.log`: Performance metrics and timing

### Metrics Tracked
- Files processed per minute
- Parsing success/failure rates
- Elasticsearch indexing performance
- Memory and CPU usage
- Error rates and types

## 🔧 Configuration Options

### Environment Variables

| Variable                    | Description                      | Default     | Required |
| --------------------------- | -------------------------------- | ----------- | -------- |
| `ELASTICSEARCH_HOST`        | Elasticsearch server host        | `localhost` | Yes      |
| `ELASTICSEARCH_PORT`        | Elasticsearch server port        | `9200`      | Yes      |
| `ELASTICSEARCH_INDEX`       | Index name for storing data      | `leaks`     | Yes      |
| `TELEGRAM_API_ID`           | Telegram API ID                  | -           | Yes*     |
| `TELEGRAM_API_HASH`         | Telegram API Hash                | -           | Yes*     |
| `TELEGRAM_CHANNEL_ID`       | Target channel ID                | -           | Yes*     |
| `MAX_WORKERS`               | Processing thread count          | `4`         | No       |
| `BATCH_SIZE`                | Elasticsearch batch size         | `1000`      | No       |
| `LOG_LEVEL`                 | Logging verbosity                | `INFO`      | No       |
| `MAX_FILE_SIZE_MB`          | Maximum file size limit          | `100`       | No       |
| `FILTER_INVALID_URLS`       | Enable URL pattern filtering     | `true`      | No       |
| `FILTER_CONTROL_CHARACTERS` | Filter control characters        | `true`      | No       |
| `FILTER_LONG_TOKENS`        | Filter long suspicious tokens    | `true`      | No       |
| `MAX_TOKEN_LENGTH`          | Maximum username/password length | `80`        | No       |

## Troubleshooting

### Common Issues

#### Elasticsearch Connection Failed
```bash
# Check if Elasticsearch is running
docker-compose ps
curl -X GET "localhost:9200/_cluster/health"

# Restart services
docker-compose restart elasticsearch
```

#### Telegram API Errors
```bash
# Verify API credentials
python -c "from src.config.config import Config; print(f'API ID: {Config().TELEGRAM_API_ID}')"

# Check rate limiting
# Wait 60 seconds between requests if rate limited
```

#### Parsing Errors
```bash
# Enable debug logging
export LOG_LEVEL=DEBUG
python -m src.parser.leak_parser --verbose

# Check file encoding
file -i your_file.txt
```

### Log Analysis

```bash
# Check recent errors
tail -n 100 logs/error.log

# Monitor real-time logs
tail -f logs/app.log | grep ERROR

# Performance analysis
grep "Processing time" logs/performance.log
```

## Development

### Setting Up Development Environment

```bash
# Install development dependencies
pip install -r requirements.txt
pip install pytest black flake8 mypy

# Set up pre-commit hooks
pre-commit install
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src

# Run specific test file
pytest tests/test_parser.py
```

### Code Quality

```bash
# Format code
black src/

# Lint code
flake8 src/

# Type checking
mypy src/
```

### Project Structure

```
leakApp/
├── src/
│   ├── config/          # Configuration management
│   ├── elasticsearch/   # ES integration and upload
│   ├── parser/          # Data parsing and extraction
│   ├── scraper/         # Data collection (Telegram, etc.)
│   └── utils/           # Common utilities and helpers
├── tests/               # Test suite
├── logs/                # Application logs
├── downloads/           # Raw downloaded files
├── parsed_leaked_json/  # Processed JSON files
├── docker-compose.yml   # Infrastructure setup
├── requirements.txt     # Python dependencies
├── run_parse_and_upload.py  # Main pipeline script
└── README.md           # This file
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

**⚠️ Disclaimer**: This tool is intended for cybersecurity research and threat intelligence purposes only. Users are responsible for ensuring compliance with applicable laws and regulations. The authors are not responsible for any misuse of this software.
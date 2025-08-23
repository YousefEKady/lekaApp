# Leka-App: Dark Web Threat Intelligence Platform

A comprehensive SaaS platform for collecting, analyzing, and monitoring leaked credential data from dark web sources. The system provides automated data processing, secure storage, and advanced analytics capabilities for cybersecurity professionals.

## Overview

Leka-App is a multi-tenant threat intelligence platform that enables organizations to:

- Monitor their domains for leaked credentials across dark web sources
- Process and analyze large datasets of compromised data
- Receive real-time alerts for new security breaches
- Generate comprehensive security reports and analytics
- Manage multiple companies and users through a centralized admin panel

## Architecture

The platform consists of several key components:

- **FastAPI Backend**: RESTful API with JWT authentication and role-based access control
- **Database Layer**: PostgreSQL for relational data
- **Search Engine**: Elasticsearch for fast full-text search and analytics
- **Caching Layer**: Redis for session management and performance optimization
- **Data Processing**: Automated parsers for various leak file formats
- **Web Scraping**: Telegram and other source scrapers for data collection

## Prerequisites

- Docker and Docker Compose
- Python 3.11+ (for local development)
- Git

## Quick Start with Docker

### 1. Clone the Repository

```bash
git clone https://github.com/YousefEKady/lekaApp.git
cd leakApp
```

### 2. Environment Configuration

Create a `.env` file in the project root:

```env
# Application Settings
APP_NAME=Leka-App SaaS Edition
APP_VERSION=2.0.0
APP_DESCRIPTION=Advanced leak detection and monitoring platform
ENVIRONMENT=development
DEBUG=true

# Server Configuration
HOST=0.0.0.0
PORT=8000
RELOAD=true

# Database Configuration (PostgreSQL)
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_USER=postgres
POSTGRES_PASSWORD=postgres123
POSTGRES_DB=leka_app
# Alternative: Use DATABASE_URL instead of individual settings
# DATABASE_URL=postgresql://postgres:postgres123@localhost:5432/leka_app

# Elasticsearch Configuration
ELASTICSEARCH_HOST=localhost
ELASTICSEARCH_PORT=9200
ELASTICSEARCH_INDEX=leaks
# Alternative: Use ELASTICSEARCH_URL instead
# ELASTICSEARCH_URL=http://localhost:9200

# Redis Configuration
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=
# Alternative: Use REDIS_URL instead
# REDIS_URL=redis://localhost:6379

# Rate Limiting
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW_SECONDS=60

# File Upload
MAX_UPLOAD_SIZE=1073741824

# Data Filtering
FILTER_INVALID_URLS=true
FILTER_CONTROL_CHARACTERS=true
FILTER_LONG_TOKENS=true
MAX_TOKEN_LENGTH=80

# Telegram Configuration (Optional - for scraping)
TELEGRAM_API_ID=your-telegram-api-id
TELEGRAM_API_HASH=your-telegram-api-hash
TELEGRAM_CHANNEL_ID=your-channel-id
TELEGRAM_DOWNLOAD_ROOT=downloads
```

### 3. Start the Platform

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop all services
docker-compose down
```

### 4. Access the Application

- **API Documentation**: http://localhost:8000/docs
- **Alternative API Docs**: http://localhost:8000/redoc
- **Elasticsearch**: http://localhost:9200
- **Kibana**: http://localhost:15601
- **PostgreSQL Admin**: http://localhost:8080

## Local Development Setup

### 1. Install Dependencies

```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows
venv\Scripts\activate
# Linux/Mac
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Start External Services

```bash
# Start only external services (without the app)
docker-compose up -d elasticsearch kibana postgres redis pgadmin
```

### 3. Run the Application

```bash
# Start the FastAPI server
python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

## API Endpoints

### Authentication
- `POST /auth/register` - User registration
- `POST /auth/login` - User login
- `POST /auth/logout` - User logout
- `GET /auth/me` - Get current user info

### Admin Panel
- `GET /admin/companies` - List all companies
- `POST /admin/companies` - Create new company
- `GET /admin/users` - List all users
- `POST /admin/upload-leaks` - Upload leak files

### Company Dashboard
- `GET /company/dashboard` - Company overview
- `GET /company/domains` - List company domains
- `POST /company/domains` - Add new domain
- `GET /company/search-leaks` - Search for leaks

### System
- `GET /health` - System health check
- `GET /docs` - API documentation

## Data Processing

### Supported File Formats
- CSV files with email:password format
- TXT files with various delimiters
- JSON files with structured data
- Compressed archives (ZIP, RAR)

### Processing Pipeline
1. File upload and validation
2. Format detection and parsing
3. Data cleaning and normalization
4. Duplicate detection and removal
5. Elasticsearch indexing
6. Notification generation

## Security Features

- JWT-based authentication
- Role-based access control (Admin, Company User)
- Rate limiting on API endpoints
- CORS protection
- SQL injection prevention
- Input validation and sanitization
- Audit logging for all operations

## Monitoring and Logging

- Comprehensive application logging
- Elasticsearch query logging
- User activity audit trails
- System health monitoring
- Performance metrics collection

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|----------|
| `DATABASE_URL` | PostgreSQL connection string | Required |
| `ELASTICSEARCH_URL` | Elasticsearch endpoint | Required |
| `REDIS_URL` | Redis connection string | Required |
| `SECRET_KEY` | Application secret key | Required |
| `JWT_SECRET_KEY` | JWT signing key | Required |
| `ENVIRONMENT` | Application environment | development |
| `DEBUG` | Enable debug mode | false |


## Deployment

### Docker Production Build

```bash
# Build production image
docker build -t leka-app:latest .

# Run production container
docker run -d \
  --name leka-app \
  -p 8000:8000 \
  --env-file .env.production \
  leka-app:latest
```

## Troubleshooting

### Common Issues

1. **Database Connection Error**
   - Ensure PostgreSQL is running
   - Check DATABASE_URL configuration
   - Verify network connectivity

2. **Elasticsearch Connection Error**
   - Ensure Elasticsearch is running on port 9200
   - Check ELASTICSEARCH_URL configuration
   - Verify cluster health

3. **Import Errors**
   - Check Python path configuration
   - Ensure all dependencies are installed
   - Verify virtual environment activation

### Logs Location

- Application logs: `logs/` directory
- Docker logs: `docker-compose logs <service-name>`
- Elasticsearch logs: Available through Kibana

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## License

This project is proprietary software. All rights reserved.

## Support

For technical support or questions, please contact the development team or create an issue in the project repository.
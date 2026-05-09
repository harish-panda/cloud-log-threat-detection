# Cloud Log Threat Detection Framework - Setup Guide

## Overview
Intelligent Cloud Log Threat Detection Framework using ML to detect threats in SSH logs with real-time processing and visualization.

## Prerequisites
- Python 3.12.6
- Docker & Docker Compose
- Git

## Quick Setup

### 1. Clone and Setup
```bash
git clone <repository-url>
cd cloud-log-threat-detection

# Setup virtual environment
python3.12 -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements.txt
```

### 2. Environment Configuration
```bash
# Copy environment template
cp .env.example .env

# Edit .env with your settings
DATABASE_URL=postgresql://postgres:password@localhost:5432/threat_detection
LOG_LEVEL=INFO
```

### 3. Start Services
```bash
# Start all services (PostgreSQL, App, Grafana)
docker-compose up -d

# Check services status
docker-compose ps
```

### 4. Generate Test Data
```bash
# Generate realistic SSH logs with attacks
python scripts/generate_test_logs.py --count 10000 --output data/test_logs.log

# Test log parsing
python -c "
from src.parsers.ssh_parser import SSHLogParser
parser = SSHLogParser()
with open('data/test_logs.log') as f:
    logs = f.readlines()[:5]
    for log in logs:
        parsed = parser.parse(log.strip())
        if parsed:
            print(f'Event: {parsed.event_type}, User: {parsed.username}, IP: {parsed.ip_address}')
"
```

### 5. Start Application
```bash
# Start FastAPI application
uvicorn src.main:app --host 0.0.0.0 --port 8000

# Or in development mode
uvicorn src.main:app --host 0.0.0.0 --port 8000 --reload
```

### 6. Train ML Model
```bash
# Train anomaly detection model
curl -X POST "http://localhost:8000/api/v1/ml/train" \
  -H "Content-Type: application/json" \
  -d '{"days_back": 7}'
```

### 7. Ingest Logs & Detect Threats
```bash
# Ingest test logs
curl -X POST "http://localhost:8000/api/v1/logs/ingest/batch" \
  -H "Content-Type: application/json" \
  -d '{"logs": ["Apr 07 00:58:03 server sshd[3329]: Failed password for root from 192.168.1.10 port 22"]}'

# Detect threats
curl "http://localhost:8000/api/v1/threats/detect?hours=1"
```

## Services URLs

### Application
- **FastAPI App**: http://localhost:8000
- **API Docs**: http://localhost:8000/docs
- **Health Check**: http://localhost:8000/health

### Database
- **PostgreSQL**: localhost:5432
- **Database**: threat_detection
- **User**: postgres
- **Password**: password

### Visualization
- **Grafana**: http://localhost:3000
- **Default Login**: admin/admin

## Key API Endpoints

### Logs
- `POST /api/v1/logs/parse` - Parse SSH logs
- `POST /api/v1/logs/ingest` - Store single log
- `POST /api/v1/logs/ingest/batch` - Store multiple logs
- `GET /api/v1/logs/recent` - Get recent logs

### ML & Threats
- `POST /api/v1/ml/train` - Train ML model
- `GET /api/v1/ml/status` - Model status
- `GET /api/v1/threats/detect` - Detect threats
- `GET /api/v1/threats/alerts` - Get threat alerts

### System
- `GET /health` - Health check
- `GET /api/v1/stats/summary` - System statistics
- `GET /api/v1/system/status` - System status

## Testing

### Unit Tests
```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src

# Run specific test file
pytest tests/unit/test_ssh_parser.py -v
```

### Security Checks
```bash
# Security vulnerability scanner
bandit -r src/

# Dependency vulnerability check
safety check

# Type checking
mypy src/
```

## Troubleshooting

### Database Issues
```bash
# Reset database
docker-compose down postgres
docker volume rm cloud-log-threat-detection_postgres_data
docker-compose up -d postgres
```

### Application Issues
```bash
# Check logs
docker-compose logs app

# Restart application
docker-compose restart app
```

### Environment Issues
```bash
# Verify environment variables
python -c "import os; print(os.getenv('DATABASE_URL'))"
```

## Architecture

```
SSH Logs -> Parser -> Database -> ML Model -> Threat Detection -> Alerts -> Grafana Dashboard
```

### Components
- **SSH Parser**: Extracts structured data from logs
- **PostgreSQL**: Stores logs and threat alerts
- **ML Detector**: Isolation Forest anomaly detection
- **FastAPI**: REST API for log processing
- **Grafana**: Visualization dashboard (TODO - dashboards not yet implemented)

## Development

### Project Structure
```
cloud-log-threat-detection/
|
|-- src/                    # Source code
|   |-- parsers/            # Log parsers
|   |-- ml/                 # ML models
|   |-- database/           # Database layer
|   |-- core/               # Core utilities (config, versioning)
|   `-- main.py             # FastAPI app
|
|-- tests/                  # Tests
|   |-- unit/               # Unit tests
|   |-- integration/        # Integration tests (TODO)
|   `-- e2e/                # End-to-end tests (TODO)
|
|-- scripts/                # Utility scripts
|-- database/               # Database schema
|-- data/                   # Test data
|-- logs/                   # Application logs
|-- requirements.txt        # Dependencies
|-- .env.example           # Environment template
|-- docker-compose.yml     # Docker setup
`-- SETUP.md               # This file
```

### Adding New Features
1. Add parsers in `src/parsers/`
2. Update schema in `database/schema.sql`
3. Add API endpoints in `src/main.py`
4. Create tests in `tests/`
5. Implement alert system in `src/alerts/` (TODO)
6. Implement monitoring in `src/monitoring/` (TODO)

## Production Deployment

### Environment Variables
```bash
# Production settings
ENVIRONMENT=production
DEBUG=false
LOG_LEVEL=WARNING
SECRET_KEY=<strong-secret-key>
DATABASE_URL=<production-db-url>
```

### Security
- Use strong passwords
- Enable SSL/TLS
- Configure firewall rules
- Regular security updates
- Monitor with Grafana alerts

## Support

### Common Issues
1. **Port conflicts**: Change ports in docker-compose.yml
2. **Memory issues**: Increase Docker memory limits
3. **Database connection**: Check DATABASE_URL in .env
4. **ML training**: Ensure sufficient log data

### Performance Tuning
- Database indexing for frequent queries
- Connection pooling for database
- Batch processing for log ingestion
- Model retraining schedule optimization

## Monitoring & Alerts (TODO)

The following monitoring and alerting features are planned but not yet implemented:

### Grafana Dashboards (TODO)
- **Threat Detection Overview**: Real-time threat metrics
- **Log Analysis**: Log volume and patterns
- **System Health**: Application performance
- **ML Performance**: Model accuracy and predictions

### Alert Channels (TODO)
- Slack notifications for high-severity threats
- Email alerts for system issues
- Grafana alerting for dashboard thresholds

### Implementation Status
- `src/alerts/` - Directory exists but not implemented
- `src/monitoring/` - Directory exists but not implemented
- `monitoring/grafana/dashboards/` - Directory exists but no dashboards configured
- `monitoring/grafana/provisioning/` - Directory exists but no provisioning configured

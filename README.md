# Cloud Log Threat Detection Framework

## Quick Start

### 1. Setup Environment
```bash
# Copy environment configuration
cp .env.example .env

# Edit .env with your database credentials
# DATABASE_URL=postgresql://postgres:password@localhost:5432/threat_detection
```

### 2. Install Dependencies
```bash
# Create virtual environment
python3.12 -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate   # Windows

# Install all dependencies (includes testing tools)
pip install -r requirements.txt
```

### 3. Start Services
```bash
# Start with Docker (recommended)
docker-compose up -d

# Or start PostgreSQL manually and run:
uvicorn src.main:app --host 0.0.0.0 --port 8000
```

### 4. Generate Test Data
```bash
python scripts/generate_test_logs.py --count 10000 --output data/test_logs.log
```

### 5. Train Machine Learning Model
```bash
curl -X POST "http://localhost:8000/api/v1/ml/train" \
  -H "Content-Type: application/json" \
  -d '{"days_back": 7}'
```

### 6. Ingest Logs
```bash
curl -X POST "http://localhost:8000/api/v1/logs/ingest/batch" \
  -H "Content-Type: application/json" \
  -d '{"logs": ["Dec 10 10:15:30 server sshd[1234]: Failed password for root from 192.168.1.10 port 22"]}'
```

### 7. Detect Threats
```bash
curl "http://localhost:8000/api/v1/threats/detect?hours=1"
```

## API Documentation

Visit `http://localhost:8000/docs` for interactive API documentation.

## Key Endpoints

- `GET /health` - System health check
- `POST /api/v1/logs/parse` - Parse SSH logs
- `POST /api/v1/logs/ingest` - Store logs in the database
- `POST /api/v1/ml/train` - Train machine learning model
- `GET /api/v1/threats/detect` - Detect threats
- `GET /api/v1/stats/summary` - System statistics

## Architecture

```
SSH Logs -> Parser -> Database -> Machine Learning Model -> Threat Detection -> Grafana Dashboard
```

**Note:** Alert system is planned but not yet implemented (see SETUP.md for current status). Grafana dashboards are configured and available.

## Testing

```bash
# Run all tests (included in requirements.txt)
pytest

# Run with coverage
pytest --cov=src

# Run security checks (included in requirements.txt)
bandit -r src/
safety check
```

## Technology Stack

- **Python 3.12 (python:3.12-slim)** - Main language
- **FastAPI 0.135.3** - Web framework
- **PostgreSQL 17** - Database
- **scikit-learn 1.8.0** - Machine learning
- **Docker** - Containerization

## Project Structure

```
cloud-log-threat-detection/
|
|-- src/                    # Source code
|   |-- parsers/            # Log parsers (SSH)
|   |-- ml/                 # Machine learning models (anomaly detection)
|   |-- database/           # Database layer
|   |-- core/               # Core utilities (config, versioning)
|   `-- main.py             # FastAPI app
|
|-- tests/                  # Tests
|   |-- unit/               # Unit tests (implemented)
|   |-- integration/        # Integration tests (TODO)
|   `-- e2e/                # End-to-end tests (TODO)
|
|-- scripts/                # Utility scripts
|-- database/               # Database schema
|-- data/                   # Data files
|-- logs/                   # Log files
|-- requirements.txt        # All dependencies
|-- .env.example           # Configuration template
|-- docker-compose.yml     # Docker setup
|-- SETUP.md               # Detailed setup guide
`-- README.md              # This file
```

## Implementation Status

**Implemented:**
- SSH log parsing
- PostgreSQL database storage
- ML anomaly detection (Isolation Forest)
- FastAPI REST API
- Unit tests
- Docker deployment
- Grafana dashboards configuration

**Planned/TODO:**
- Alert system (`src/alerts/`)
- Monitoring dashboards (`src/monitoring/`)
- Integration tests
- End-to-end tests

See `SETUP.md` for current detailed status and setup instructions.

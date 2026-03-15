# AI Honeypot - Quick Start with Docker

## Prerequisites
- Docker
- Docker Compose

## Quick Start

### 1. Build and Run
```bash
docker-compose up --build
```

### 2. Access the Honeypot
- Main application: http://localhost:8000
- Dashboard: http://localhost:8000/dashboard
- Demo dashboard: http://localhost:8000/demo

### 3. Stop the Honeypot
```bash
docker-compose down
```

## Manual Docker Build

```bash
# Build image
docker build -t ai-honeypot .

# Run container
docker run -p 8000:8000 -v $(pwd)/attacks.log:/app/attacks.log ai-honeypot
```

## Development Mode

For development, run without Docker:

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run
python app.py
```

## Testing

```bash
python test_honeypot.py
```

## Logs

Logs are stored in:
- `attacks.log` - Human-readable attack log
- `attacks.json` - Structured JSON log

When using Docker, these files are mounted as volumes and persist on the host.

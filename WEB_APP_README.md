# Web Application Guide

## Overview

The web application provides a user-friendly interface for the WebSecV scanner with:

- **Dashboard**: Overview of scans and vulnerabilities
- **Scan Management**: Create, view, and manage security scans
- **Vulnerability Browser**: View and manage discovered vulnerabilities
- **Proxy Interface**: HTTP/HTTPS proxy management
- **Repeater Tool**: Manual request editing and replay
- **Intruder Tool**: Fuzzing interface

## Database

The application uses SQLite by default (can be configured for PostgreSQL, MySQL, etc.).

**Database Models:**
- `Scan`: Scan records with status and metadata
- `Vulnerability`: Vulnerability findings with severity and details
- `Request`: HTTP request records
- `Response`: HTTP response records
- `Endpoint`: Discovered endpoints
- `ScanHistory`: Scan execution history

## Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Initialize database (automatically done on first run)

## Running the Application

### Development Mode

```bash
python -m scanner.web.run
```

Or:

```bash
cd scanner/web
python run.py
```

The application will be available at: http://127.0.0.1:5000

### Production Mode

Using Gunicorn (recommended):

```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 scanner.web.wsgi:app
```

Using uWSGI:

```bash
pip install uwsgi
uwsgi --http :5000 --module scanner.web.wsgi:app --processes 4
```

## Configuration

Set environment variables:

```bash
export DATABASE_URL="sqlite:///scanner.db"
export SECRET_KEY="your-secret-key-here"
export HOST="0.0.0.0"
export PORT="5000"
export DEBUG="False"
```

Or use a `.env` file (requires `python-dotenv`):

```env
DATABASE_URL=sqlite:///scanner.db
SECRET_KEY=your-secret-key-change-in-production
HOST=127.0.0.1
PORT=5000
DEBUG=True
```

## API Endpoints

### Scans
- `GET /api/scans` - List all scans
- `POST /api/scans` - Create new scan
- `GET /api/scans/<id>` - Get scan details
- `DELETE /api/scans/<id>` - Delete scan

### Vulnerabilities
- `GET /api/vulnerabilities` - List vulnerabilities
- `GET /api/vulnerabilities/<id>` - Get vulnerability details
- `PATCH /api/vulnerabilities/<id>` - Update vulnerability

### Statistics
- `GET /api/stats` - Get statistics

### Crawler
- `POST /api/crawl` - Start crawling a target

### Health
- `GET /api/health` - Health check

## Features

### Dashboard
- Real-time statistics
- Recent scans and vulnerabilities
- Quick scan creation

### Scan Management
- View all scans with filters
- Start new scans
- View scan details
- Delete scans

### Vulnerability Browser
- View all vulnerabilities
- Filter by severity
- Filter by scan
- Mark as verified/false positive

### Proxy
- Start/stop proxy server
- View request history
- Configure proxy settings

### Repeater
- Edit HTTP requests
- Send and view responses
- Compare responses

### Intruder
- Configure fuzzing attacks
- Set payload positions
- View attack results

## Database Schema

```sql
-- Scans
CREATE TABLE scans (
    id INTEGER PRIMARY KEY,
    target_url VARCHAR(500),
    scan_type VARCHAR(50),
    status VARCHAR(20),
    started_at DATETIME,
    completed_at DATETIME,
    created_by VARCHAR(100)
);

-- Vulnerabilities
CREATE TABLE vulnerabilities (
    id INTEGER PRIMARY KEY,
    scan_id INTEGER,
    request_id INTEGER,
    title VARCHAR(500),
    description TEXT,
    severity VARCHAR(20),
    confidence FLOAT,
    cwe_id INTEGER,
    cvss_score FLOAT,
    evidence TEXT,
    remediation TEXT,
    created_at DATETIME,
    verified BOOLEAN,
    false_positive BOOLEAN
);

-- Requests
CREATE TABLE requests (
    id INTEGER PRIMARY KEY,
    scan_id INTEGER,
    method VARCHAR(10),
    url VARCHAR(2000),
    headers JSON,
    body TEXT,
    timestamp DATETIME
);

-- Responses
CREATE TABLE responses (
    id INTEGER PRIMARY KEY,
    request_id INTEGER UNIQUE,
    status_code INTEGER,
    headers JSON,
    body TEXT,
    timestamp DATETIME
);
```

## Development

### Adding New Endpoints

Edit `scanner/web/routes.py`:

```python
@api_bp.route('/custom', methods=['GET'])
def custom_endpoint():
    return jsonify({'message': 'Hello'})
```

### Adding New Templates

Create template in `scanner/web/templates/`:

```html
{% extends "base.html" %}
{% block content %}
<!-- Your content -->
{% endblock %}
```

### Customizing Styles

Edit `scanner/web/static/css/style.css`

## Troubleshooting

### Database Issues

If database errors occur:
```bash
# Delete existing database
rm scanner.db

# Restart application (will recreate database)
python -m scanner.web.run
```

### Port Already in Use

Change port:
```bash
export PORT=5001
python -m scanner.web.run
```

### CORS Issues

CORS is enabled by default. To restrict:
```python
from flask_cors import CORS
CORS(app, origins=['http://localhost:3000'])
```

## Next Steps

- Add authentication/authorization
- Add WebSocket for real-time updates
- Add export functionality
- Add scheduled scans
- Add scan templates
- Add team collaboration features


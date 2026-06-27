# Live DDoS Simulation

Live DDoS Simulation is an interactive threat-intelligence dashboard that visualizes suspicious IP activity on a 3D globe. It combines live threat feeds, geolocation enrichment, heuristic scoring, and a modern frontend to provide a high-level view of hostile traffic patterns and potential DDoS-related infrastructure.

The project is designed as a practical example of how to build a lightweight security observability experience with a FastAPI backend and a Vite-powered frontend.

## What the project does

- Pulls threat data from multiple sources such as AbuseIPDB and blocklist.de
- Enriches IP addresses with approximate geolocation data
- Scores threats using a heuristic engine that considers confidence, category, freshness, and location
- Renders the results on an interactive globe with animated overlays and severity summaries
- Exposes a simple API for health checks and threat feed retrieval

## Architecture

The application is split into three main parts:

- Frontend: a Vite + JavaScript app using Globe.gl and Three.js to render the 3D experience
- Backend: a FastAPI service that aggregates threat data, enriches it, scores it, and serves it to the UI
- Data layer: optional GeoLite2 database support for approximate geolocation and a local data directory for supporting assets

### High-level flow

1. The frontend requests threat data from the backend.
2. The backend fetches data from external threat feeds.
3. Threats are merged, geolocated, and scored.
4. The scored threat payload is returned to the UI.
5. The frontend renders points, arcs, and severity panels on the globe.

## Tech stack

### Backend
- Python 3.10+
- FastAPI
- Uvicorn
- httpx
- geoip2
- pytest

### Frontend
- Vite
- Vanilla JavaScript
- Globe.gl
- Three.js

## Project structure

```text
backend/
  app/
    main.py
    config.py
    models/
    routers/
    services/
  tests/
  requirements.txt
frontend/
  src/
  index.html
  package.json
  vite.config.js
data/
```

## Prerequisites

Before running the app locally, make sure you have:

- Python 3.10 or newer
- Node.js 18+ and npm
- Optional: a valid AbuseIPDB API key for richer live data
- Optional: a GeoLite2 City database file for coordinate enrichment

## Quick start

### 1. Clone the repository

```bash
git clone https://github.com/raviteja-core/Live-DDOS-simmulation.git
cd Live-DDOS-simmulation
```

### 2. Set up the backend

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 3. Configure environment variables

Create a file named `.env` inside the backend folder if you want to customize behavior.

Example:

```env
ABUSEIPDB_API_KEY=your_api_key_here
ALLOWED_ORIGINS=http://localhost:5173,http://127.0.0.1:5173
GEOLITE2_DB_PATH=../data/GeoLite2-City.mmdb
SCORING_MODE=heuristic
```

> If you do not provide an AbuseIPDB key, the backend can still run and will fall back to other sources or mock data.

### 4. Start the backend

```bash
cd backend
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

The API will be available at:

- http://127.0.0.1:8000/health
- http://127.0.0.1:8000/threats?limit=100

### 5. Start the frontend

In a second terminal:

```bash
cd frontend
npm install
npm run dev -- --host 0.0.0.0
```

Open the frontend at:

- http://127.0.0.1:5173

If your backend runs on a different URL, pass it through the query string:

```text
http://127.0.0.1:5173/?api=http://127.0.0.1:8000
```

## API overview

### Health check

```http
GET /health
```

Returns a simple status response.

### Threat feed

```http
GET /threats?limit=100
```

Returns a paged threat response containing:

- threat data
- metadata about the source and generation time
- counts for total and mapped threats

## How the scoring works

Threats are assigned a heuristic score based on a combination of:

- AbuseIPDB confidence score
- category-based signal weighting
- recency of the report
- whether geolocation data is available
- severity thresholds for ranking and calibration

The resulting score is mapped into one of three levels:

- Critical
- Elevated
- Observed

## Data sources

The backend can combine multiple feeds:

- AbuseIPDB blacklist data
- blocklist.de recent attackers
- optional local mock data if upstream feeds fail

## Running tests

Backend tests are included under the backend/tests directory.

```bash
cd backend
pytest -q
```

## Development notes

- The frontend expects the backend to be reachable at the configured API base URL.
- If GeoLite2 data is not present, the map may still load, but some threat points may remain unmapped.
- The frontend uses polling-based refresh behavior to keep the dashboard current.

## License

This project is intended for educational and experimental use in demonstrating threat visualization and security telemetry concepts.

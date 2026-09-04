# CVE Explorer

A vulnerability intelligence platform with risk scoring, asset correlation, SBOM support, and remediation tracking.

## Architecture

```
React Dashboard → FastAPI Backend → PostgreSQL
                         ↓
              ┌──────────┼──────────┐
              ↓          ↓          ↓
         CVE Service  Risk Engine  AI Service
              ↓          ↓          ↓
         CIRCL/NVD    EPSS/KEV    Assets
              └──────────┬──────────┘
                         ↓
                  Correlation Engine
                         ↓
               Remediation + Alerts
```

## Quick Start

### Docker (recommended)

```bash
docker-compose up -d
```

- Frontend: http://localhost:5173
- Backend API: http://localhost:8000
- API docs: http://localhost:8000/docs

### Manual Setup

**Backend:**
```bash
cd backend
pip install -r requirements.txt
# Set DATABASE_URL in .env
alembic upgrade head
uvicorn app.main:app --reload --port 8000
```

**Frontend:**
```bash
npm install
npm run dev
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/cve/{id}` | Full CVE lookup with enrichment + risk |
| GET | `/api/cve/{id}/enrichments` | EPSS, KEV, exploit data |
| GET | `/api/cve/{id}/assets` | Affected assets |
| GET | `/api/assets/` | List all assets |
| POST | `/api/assets/` | Create asset |
| GET | `/api/assets/summary` | Asset statistics |
| GET | `/api/remediation/{cve_id}` | Remediation records |
| POST | `/api/remediation/` | Create record |
| PATCH | `/api/remediation/{id}` | Update status |
| GET | `/api/alerts/` | List alerts |
| GET | `/api/alerts/unread-count` | Unread count |
| GET | `/api/analytics/dashboard` | Dashboard stats |
| GET | `/api/health` | Health check |

## Features

- **Multi-source CVE intelligence** (CIRCL, NVD, EPSS, CISA KEV)
- **Explainable risk scoring** with factor breakdown
- **Asset inventory** with CVE-to-asset correlation
- **SBOM scanning** (CycloneDX, SPDX, package.json, requirements.txt)
- **Remediation lifecycle** tracking (Open → Closed)
- **Alerting** for KEV, EPSS changes, new exploits
- **Analytics dashboard** with severity/risk distributions
- **Background workers** for continuous monitoring
- **Docker** deployment ready

## Development

```bash
npm test          # Run frontend tests
npm run lint      # Check code quality
npm run build     # Production build
```

## Tech Stack

- **Frontend:** React 19 + Vite + Tailwind CSS
- **Backend:** FastAPI + Python 3.12
- **Database:** PostgreSQL 16
- **Cache:** Redis 7
- **Workers:** Celery
- **Deployment:** Docker Compose

# VigiLock Production Deployment Architecture on Render

## Architecture Diagram

```
User Browser (Client)
        │  HTTPS
        ▼
[1] Vite/React Frontend (Static Site - Public)
        │  HTTPS REST API (`VITE_API_BASE_URL`)
        ▼
[2] Plain Java Backend (Web Service - Public/Private)
        │
        ├──────────────────────────────────────────┐
        │ HTTP REST (`ML_API_URL`)                 │ JDBC (`jdbc:mysql://...`)
        ▼                                          ▼
[3] FastAPI ML Service (Web/Private Service)   [5] MySQL Database (Private Service)
        │                                          │
        ▼                                          ▼
[4] ML Models (Trained PKL Artifacts)      [6] Persistent Disk (`/var/lib/mysql`)
```

---

## Service Breakdown

### 1. Vite/React Frontend
- **Render Type**: Static Site (Public)
- **Exposure**: Public HTTPS URL (e.g., `https://vigilock.onrender.com`)
- **Responsibility**: User Interface, dashboard visualization, interactive threat analysis forms, and Sentinel AI chat UI.
- **Communicates With**: Java Backend only via HTTPS (`VITE_API_BASE_URL`).

### 2. Plain Java Backend
- **Render Type**: Web Service (Docker runtime)
- **Exposure**: Public HTTPS URL (e.g., `https://vigilock-backend.onrender.com`)
- **Responsibility**:
  - Exposes REST API endpoints (`/api/v1/dashboard/metrics`, `/api/v1/entity/*`, `/api/v1/search/*`, `/api/v1/detect/*`, `/api/chat`).
  - Queries and aggregates threat intelligence from MySQL.
  - Forwards real-time detection requests to FastAPI ML service.
  - Mediates Cyber Sentinel conversations with Google Gemini securely using backend API keys.
- **Communicates With**:
  - FastAPI ML Service (via HTTP or Internal Render DNS: `http://fastapi-service:8000` / `ML_API_URL`).
  - MySQL Database (via JDBC: `jdbc:mysql://mysql-service:3306/threat_intelligence_db`).
  - External APIs (Gemini, IPQS, Truecaller).

### 3. FastAPI ML Service
- **Render Type**: Web Service or Private Service (Python 3.10/3.11)
- **Exposure**: Internal Render URL (`http://vigilock-ml:8000`) or Public HTTPS URL (`https://vigilock-ml.onrender.com`)
- **Responsibility**: Loads pre-trained ML classifier models and vectorizers, performs multi-model threat inference, calculates confidence scores and threat levels.
- **Communicates With**:
  - Local ML model files (`ML/models/*.pkl`).

### 4. ML Models & Preprocessor Bundles
- **Storage**: In-container filesystem under `ML/models/`.
- **Loaded**: Memory-resident during service startup via FastAPI `lifespan`.

### 5. MySQL Database
- **Render Type**: Private Service (Docker with `FROM mysql:8.0`)
- **Exposure**: Internal Render Network only (port 3306).
- **Persistent Disk**: Mounted at `/var/lib/mysql` to guarantee data persistence.
- **Responsibility**: Stores and indexes all CTI threat feeds, phone records, message samples, and scam indicators.

---

## Communication Matrix

| Source | Destination | Protocol | Network Scope | Configured By |
|---|---|---|---|---|
| User Browser | React Frontend | HTTPS | Public Internet | Browser URL |
| React Frontend | Java Backend | HTTPS | Public Internet | `VITE_API_BASE_URL` |
| Java Backend | FastAPI Service | HTTP / HTTPS | Internal / Public | `ML_API_URL` |
| Java Backend | MySQL Database | JDBC / TCP | Internal Render Network | `DatabaseConfig` / `DB_PASSWORD` |
| Java Backend | Gemini AI API | HTTPS | Public Internet | `GEMINI_API_KEY` |
| FastAPI Service | ML Model Artifacts | File I/O | Local Container Storage | `ML/fastapi_app.py` |

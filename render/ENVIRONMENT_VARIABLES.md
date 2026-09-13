# Environment Variables Reference for Render

This reference documents every environment variable required or supported across all VigiLock services. Real secrets, keys, or passwords must never be stored in Git. Values are represented with `<SET_IN_RENDER>` placeholders.

---

## 1. MYSQL (Private Database Service)

| Variable | Service | Purpose | Required | Example Format |
|---|---|---|---|---|
| `MYSQL_DATABASE` | MySQL | Database name created on container startup | Yes | `threat_intelligence_db` |
| `MYSQL_USER` | MySQL | Non-root application database user | Yes | `vigilock_user` |
| `MYSQL_PASSWORD` | MySQL | Password for application database user | Yes | `<SET_IN_RENDER>` |
| `MYSQL_ROOT_PASSWORD` | MySQL | Administrator root password for MySQL | Yes | `<SET_IN_RENDER>` |

---

## 2. FASTAPI (ML Inference Service)

| Variable | Service | Purpose | Required | Example Format |
|---|---|---|---|---|
| `PORT` | FastAPI | Port for Uvicorn web server (automatically provided by Render) | Yes | `8000` |
| `CORS_ORIGINS` | FastAPI | Comma-separated allowed frontend origins | Optional | `https://vigilock-frontend.onrender.com,*` |

---

## 3. JAVA BACKEND (Plain Java / Maven Service)

| Variable | Service | Purpose | Required | Example Format |
|---|---|---|---|---|
| `PORT` | Java Backend | Web server listen port (automatically injected by Render) | Yes | `8081` |
| `DB_PASSWORD` | Java Backend | MySQL database password | Yes | `<SET_IN_RENDER>` |
| `ML_API_URL` | Java Backend | Base URL pointing to deployed FastAPI ML service | Yes | `https://vigilock-ml.onrender.com` |
| `GEMINI_API_KEY` | Java Backend | Google Gemini API key for Cyber Sentinel assistant | Optional | `<SET_IN_RENDER>` |
| `GEMINI_MODEL` | Java Backend | Specific Gemini model identifier | Optional | `gemini-2.0-flash` |
| `IPQS_API_KEY` | Java Backend | IPQualityScore API key for phone fraud checks | Optional | `<SET_IN_RENDER>` |
| `TRUECALLER_CLIENT_ID` | Java Backend | Truecaller API Client ID | Optional | `<SET_IN_RENDER>` |
| `TRUECALLER_CLIENT_SECRET` | Java Backend | Truecaller API Client Secret | Optional | `<SET_IN_RENDER>` |
| `TRUECALLER_REDIRECT_URI` | Java Backend | Truecaller OAuth redirect URI | Optional | `https://vigilock-api.onrender.com/callback` |

---

## 4. FRONTEND (Vite / React Static Site)

| Variable | Service | Purpose | Required | Example Format |
|---|---|---|---|---|
| `VITE_API_BASE_URL` | Frontend | Public URL of the Java Backend service | Yes | `https://vigilock-backend.onrender.com` |
| `VITE_JAVA_BASE_URL` | Frontend | Fallback URL variable for Java Backend | Optional | `https://vigilock-backend.onrender.com` |
| `VITE_ML_API_URL` | Frontend | Public URL of FastAPI ML service (direct calls) | Optional | `https://vigilock-ml.onrender.com` |
| `VITE_API_URL` | Frontend | Fallback URL variable for API | Optional | `https://vigilock-backend.onrender.com` |
| `VITE_ABSTRACT_PHONE_API_KEY` | Frontend | AbstractAPI Phone Validation client key | Optional | `<SET_IN_RENDER>` |

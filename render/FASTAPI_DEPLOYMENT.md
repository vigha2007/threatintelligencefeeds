# FastAPI ML Service Deployment on Render

## 1. Render Service Overview
- **Render Service Type**: Web Service (or Private Service if accessed strictly via Java backend)
- **Environment**: Python 3 (Python 3.10 or 3.11)
- **Repository**: Root repository
- **Root Directory**: `ML` (or repository root `.`)

## 2. Actual Source Code & Application Structure
- **Entry-Point File**: `ML/fastapi_app.py`
- **FastAPI Application Object**: `app` (defined as `app = FastAPI(...)` in `ML/fastapi_app.py`)
- **Requirements File**: `ML/requirements.txt`
  - Core dependencies: `pandas`, `numpy`, `scikit-learn`, `xgboost`, `catboost`, `joblib`, `tldextract`, `requests`, `fastapi`, `uvicorn[standard]`
- **Python Version**: `3.10.x` or `3.11.x`

## 3. Machine Learning Models & Runtime Artifacts
During FastAPI lifespan startup (`lifespan` context manager in `ML/fastapi_app.py`), the service loads 5 dataset-specific ML classifiers and preprocessor bundles from `ML/models/`:
- **Phishing URLs**:
  - `ML/models/best_phishing_urls_model.pkl` (XGBoost)
  - `ML/models/best_phishing_urls_preprocessor.pkl` (TF-IDF 5000 + 38 lexical features)
- **Scam Messages / SMS**:
  - `ML/models/best_scam_messages_model.pkl` (XGBoost)
  - `ML/models/best_scam_messages_preprocessor.pkl` (TF-IDF 3000 + 38 lexical features)
- **Email Scams**:
  - `ML/models/best_email_scams_model.pkl` (CatBoost)
  - `ML/models/best_email_scams_preprocessor.pkl` (TF-IDF 3000 + 38 lexical features)
- **Suspicious Calls**:
  - `ML/models/best_suspicious_calls_model.pkl` (Random Forest)
  - `ML/models/best_suspicious_calls_preprocessor.pkl` (40 phone structural features)
- **Malicious IPs**:
  - `ML/models/best_malicious_ips_model.pkl` (XGBoost)
  - `ML/models/best_malicious_ips_preprocessor.pkl` (TF-IDF 1000 + 38 lexical features)

## 4. API Endpoints

### Inference Endpoint
- **Method & Path**: `POST /predict`
- **Request Format** (`ThreatPredictionRequest`):
  ```json
  {
    "content": "http://suspicious-login-portal.com/update",
    "type": "url"
  }
  ```
  *(Supported `type` values: `url`, `sms`/`message`, `email`, `call`/`phone`, `ip`)*
- **Response Format** (`ThreatPredictionResponse`):
  ```json
  {
    "prediction": "MALICIOUS",
    "classification": "MALICIOUS",
    "attack_type": "Phishing URL",
    "confidence": 0.9842,
    "classes": ["LEGITIMATE", "MALICIOUS"],
    "probabilities": {"LEGITIMATE": 0.0158, "MALICIOUS": 0.9842},
    "malicious_prob": 0.9842,
    "severity": "CRITICAL",
    "threat_level": "CRITICAL",
    "data_type": "url",
    "dataset": "phishing_urls",
    "model_class": "XGBClassifier",
    "recommended_action": "Block immediately and isolate network traffic."
  }
  ```

### Alias & Utility Endpoints
- `POST /predict/call`: Dedicated alias for suspicious phone call detection
- `GET /health`: Health check verifying all 5 model bundles are active and memory-resident
- `GET /`: Returns service status and loaded model inventory
- `GET /docs`: OpenAPI / Swagger interactive documentation UI

## 5. Render Build & Start Commands

### Option A: Root Directory set to `.`
- **Build Command**:
  ```bash
  pip install -r ML/requirements.txt fastapi uvicorn
  ```
- **Start Command**:
  ```bash
  uvicorn ML.fastapi_app:app --host 0.0.0.0 --port $PORT
  ```

### Option B: Root Directory set to `ML`
- **Build Command**:
  ```bash
  pip install -r requirements.txt fastapi uvicorn
  ```
- **Start Command**:
  ```bash
  uvicorn fastapi_app:app --host 0.0.0.0 --port $PORT
  ```

## 6. Environment Variables
- `PORT`: Injected dynamically by Render (defaults to `8000` in code). The server binds to `0.0.0.0:$PORT`.
- `CORS_ORIGINS`: Comma-separated allowed origins (defaults to `*`).

## 7. CORS Configuration
CORS is actively configured using FastAPI's `CORSMiddleware`. For production security, set `CORS_ORIGINS` in Render to match the frontend static site URL.

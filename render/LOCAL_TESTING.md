# Local Testing & Verification Commands

This guide provides the exact commands to test each component locally before or during Render deployment.

---

## 1. FastAPI ML Service
Start the FastAPI server from the workspace root:

```bash
# Using Python / Uvicorn from root
python -m uvicorn ML.fastapi_app:app --host 0.0.0.0 --port 8000 --reload
```
*(Or from within the `ML` directory: `python fastapi_app.py`)*

### Verify FastAPI Health & Endpoints
```bash
# Health Check
curl -X GET http://localhost:8000/health

# Status & Inventory
curl -X GET http://localhost:8000/

# Test Phishing URL Prediction
curl -X POST http://localhost:8000/predict \
  -H "Content-Type: application/json" \
  -d "{\"content\": \"http://secure-paypal-login-attempt.info\", \"type\": \"url\"}"

# Test Suspicious Phone Call Prediction
curl -X POST http://localhost:8000/predict/call \
  -H "Content-Type: application/json" \
  -d "{\"content\": \"+919876543210\", \"type\": \"call\"}"
```

---

## 2. Plain Java Backend (`java-threat-intel`)
From the `java-threat-intel` directory:

```bash
cd java-threat-intel

# Clean and package the Maven project
mvn clean package

# Run the Java application
java -cp "target/java-threat-intel-1.0-SNAPSHOT.jar;target/dependency/*" com.threatintel.Main
```
*(On Linux/macOS or Docker, replace semicolon `;` with colon `:`)*

### Verify Java Backend Endpoints
```bash
# Dashboard metrics
curl -X GET http://localhost:8081/api/v1/dashboard/metrics

# Global search
curl -X GET "http://localhost:8081/api/v1/search/all?q=phishing"

# URL Detection test (proxies to FastAPI and checks DB)
curl -X POST http://localhost:8081/api/v1/detect/url \
  -H "Content-Type: application/json" \
  -d "{\"url\": \"http://example.com/login-verify\"}"
```

---

## 3. Frontend Application (Vite / React)
From the workspace root:

```bash
# Install dependencies
npm install

# Run Vite development server
npm run dev

# Build production bundle to verify compilation
npm run build

# Preview production build locally
npm run preview
```

---

## 4. MySQL Connectivity
To verify local or remote MySQL connectivity:

```bash
# Connect using MySQL client
mysql -h localhost -P 3306 -u root -p threat_intelligence_db -e "SHOW TABLES;"
```
*(Or verify via Java Schema Initializer: `java -cp "target/java-threat-intel-1.0-SNAPSHOT.jar;target/dependency/*" com.threatintel.Main --init-db`)*

# Java Backend Deployment on Render

## 1. Render Service Overview
- **Render Service Type**: Web Service
- **Runtime Environment**: Docker (Render uses Docker for Java applications)
- **Repository**: Root repository
- **Root Directory**: `java-threat-intel` (or repository root `.`)
- **Docker Context**: `java-threat-intel`
- **Dockerfile**: `java-threat-intel/Dockerfile` (or `render/java/Dockerfile`)

## 2. Architecture & Implementation
- **Application Type**: Plain Java / Maven web application (**NO Spring Boot**)
- **Build Tool**: Apache Maven (`pom.xml`)
- **Java Version**: Java 17 (`<maven.compiler.release>17</maven.compiler.release>`)
- **Server Implementation**: `com.sun.net.httpserver.HttpServer` wrapped in `com.threatintel.server.AppServer`
- **Main Class**: `com.threatintel.Main`
- **Core Dependencies**:
  - `mysql-connector-j` (8.0.33) — MySQL 8 JDBC driver
  - `HikariCP` (5.1.0) — High-performance JDBC connection pooling
  - `slf4j-simple` (2.0.9) — Logging framework
  - `gson` (2.10.1) — JSON serialization and deserialization

## 3. Dynamic Port Configuration
The Java backend dynamically respects the `PORT` environment variable injected by Render, defaulting to port `8081` for local development:
```java
int port = 8081;
String portEnv = System.getenv("PORT");
if (portEnv != null && !portEnv.trim().isEmpty()) {
    try {
        port = Integer.parseInt(portEnv.trim());
    } catch (NumberFormatException ignored) {}
}
AppServer server = new AppServer(port);
server.start();
```

## 4. Build & Start Commands (Docker / Local)
- **Maven Build Command**:
  ```bash
  mvn clean package
  ```
  *(Compiles code to `target/java-threat-intel-1.0-SNAPSHOT.jar` and unpacks runtime dependencies to `target/dependency/`)*

- **Java Start Command**:
  ```bash
  java -cp "target/java-threat-intel-1.0-SNAPSHOT.jar:target/dependency/*" com.threatintel.Main
  ```

## 5. Integrations & Communications

### MySQL Database Connection
Configured in `com.threatintel.db.DatabaseConfig`:
- **Database Name**: `threat_intelligence_db`
- **Environment Variables**:
  - `DB_PASSWORD`: Password for the MySQL database user.
- **Connection Pool**: HikariCP with 30 max connections, batch rewrites enabled, and optimized packet sizes for high-throughput queries.

### FastAPI ML Service Integration
Configured in `com.threatintel.server.ThreatDetectHandler` and `com.threatintel.server.CallDetectHandler`:
- **Environment Variable**: `ML_API_URL`
- **Purpose**: Base URL of the deployed FastAPI ML Service (e.g., `https://vigilock-ml.onrender.com` or internal URL `http://fastapi-service:8000`).
- **Default Fallback**: `http://localhost:8000`

### Cyber Sentinel AI & External Intelligence Integrations
Configured in `com.threatintel.server.GeminiChatHandler` and `com.threatintel.server.CallDetectHandler`:
- `GEMINI_API_KEY`: API key for Google Gemini AI assistant (kept strictly backend-side)
- `GEMINI_MODEL`: Model name (default: `gemini-2.0-flash`)
- `IPQS_API_KEY`: IPQualityScore API key for phone fraud scoring (optional)
- `TRUECALLER_CLIENT_ID`, `TRUECALLER_CLIENT_SECRET`, `TRUECALLER_REDIRECT_URI`: Truecaller OAuth credentials (optional)

## 6. Endpoints Served
- `GET /api/v1/dashboard/metrics`: Real-time dashboard KPI metrics and threat statistics
- `GET /api/v1/entity/{entity}?limit=50&offset=0`: Paginated access to threat feeds
- `GET /api/v1/search/all?q={query}`: Cross-feed search across all intelligence data
- `POST /api/v1/detect/call` (or `/api/detect/call`): Phone number intelligence and scam score
- `POST /api/v1/detect/email` (or `/api/detect/email`): Email scam analysis
- `POST /api/v1/detect/url` (or `/api/detect/url`): Phishing URL analysis
- `POST /api/v1/detect/ip` (or `/api/detect/ip`): Malicious IP intelligence
- `POST /api/v1/detect/sms` (or `/api/detect/sms`): SMS message analysis
- `POST /api/chat`: Cyber Sentinel assistant chat endpoint

# Deployment Blocker & Readiness Report

This report evaluates the readiness of the VigiLock repository for deployment on Render, categorizing findings into Blockers, Required Actions Before Deployment, and Optional Improvements.

---

## A. BLOCKER
*Issues that would prevent successful deployment if unaddressed:*

- **NONE (Resolved)**:
  - The Java backend server previously had a hardcoded port `8081` in `Main.java`. This has been updated to dynamically read `PORT` (injected by Render) with a fallback to `8081`.
  - Dockerfiles and build definitions are properly in place.

---

## B. REQUIRED BEFORE DEPLOYMENT
*Operational steps and configuration required in the Render dashboard during provisioning:*

1. **Deployment Sequence**:
   - **Step 1**: Provision MySQL Private Service with a persistent disk mounted at `/var/lib/mysql`.
   - **Step 2**: Provision FastAPI ML Service (Web Service or Private Service) running `ML/fastapi_app.py`.
   - **Step 3**: Provision Java Backend (Web Service via Docker) and supply `ML_API_URL` (URL of step 2) and `DB_PASSWORD`.
   - **Step 4**: Provision Frontend (Static Site) and supply `VITE_API_BASE_URL` (URL of step 3).

2. **FastAPI Dependencies**:
   - Ensure the Render build command includes `fastapi` and `uvicorn`:
     `pip install -r ML/requirements.txt fastapi uvicorn`

3. **Data Migration**:
   - The large existing dataset in `threat_intelligence_db` will need to be imported into the Render MySQL instance post-provisioning.

---

## C. OPTIONAL IMPROVEMENT
*Non-blocking improvements that can be considered for future optimization:*

1. **Configurable Database Host & User**:
   - `com.threatintel.db.DatabaseConfig` currently connects to `localhost:3306` with user `root` and reads `DB_PASSWORD`. For flexible cloud database routing, adding `DB_HOST` and `DB_USER` environment variable support can be considered.
2. **Private Networking (Zero Egress)**:
   - Configuring FastAPI and MySQL as Render Private Services within the same region reduces latency and avoids public internet exposure for internal microservice communication.

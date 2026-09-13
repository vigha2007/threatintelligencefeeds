# Frontend Deployment on Render

## 1. Render Service Overview
- **Render Service Type**: Static Site
- **Runtime Environment**: Static / Node (Build time)
- **Repository**: Root repository
- **Root Directory**: `.` (Repository root)
- **Node Version**: Node 18+ or 20+

## 2. Build & Publish Settings
- **Install Command**:
  ```bash
  npm install
  ```
- **Build Command**:
  ```bash
  npm run build
  ```
- **Publish / Output Directory**:
  ```
  dist
  ```
  *(Configured in `vite.config.ts` under `build.outDir: "dist"`)*

## 3. Environment Variables (Vite)
Render Static Sites inject environment variables during `npm run build`. Set the following in the Render Environment Variables tab:

| Variable | Purpose | Required | Example Value |
|---|---|---|---|
| `VITE_API_BASE_URL` | Public URL of the deployed Java Backend | Yes | `https://YOUR-JAVA-SERVICE.onrender.com` |
| `VITE_JAVA_BASE_URL` | Alias fallback for Java Backend URL | Optional | `https://YOUR-JAVA-SERVICE.onrender.com` |
| `VITE_ML_API_URL` | Direct URL to FastAPI ML Service (if needed) | Optional | `https://YOUR-FASTAPI-SERVICE.onrender.com` |
| `VITE_ABSTRACT_PHONE_API_KEY` | Client-side AbstractAPI phone key | Optional | `<SET_IN_RENDER>` |

> **Note**: Do not hardcode localhost or real Render URLs in source code. Supply `VITE_API_BASE_URL` in the Render Static Site dashboard once your Java backend service is deployed.

## 4. Frontend Routing & SPA Rewrites
Because the application uses TanStack Router for client-side SPA routing, configure a Rewrite rule in Render:
- **Source**: `/*`
- **Destination**: `/index.html`
- **Action**: Rewrite

## 5. Architectural Communication
- The React frontend connects directly to the Java backend via `VITE_API_BASE_URL`.
- The Java backend then orchestrates requests to the MySQL database and forwards inference requests to the FastAPI ML service.
- This keeps backend API keys (such as `GEMINI_API_KEY` and `IPQS_API_KEY`) completely hidden from the browser.

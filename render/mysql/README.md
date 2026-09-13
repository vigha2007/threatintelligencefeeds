# MySQL Database Deployment on Render

## Service Overview
- **Service Type**: Private Service (or Web Service if external direct admin access is required)
- **Environment**: Docker
- **Docker Context**: `render/mysql`
- **Dockerfile**: `render/mysql/Dockerfile` (`FROM mysql:8.0`)
- **Database Engine**: MySQL Community Server 8.0

## Persistent Storage Configuration
MySQL requires persistent storage on Render so that database state, schemas, and indexed threat intelligence feeds persist across redeployments, restarts, and instance updates:
- **Disk Name**: `mysql-data` (or custom name)
- **Mount Path**: `/var/lib/mysql`
- **Recommended Initial Size**: 10 GB to 50 GB (scalable based on threat intelligence feed volume)

## Region & Latency Considerations
- Deploy MySQL in the **same Render region** (e.g., Oregon, Frankfurt, Ohio, Singapore) as the Java Backend and FastAPI ML services.
- Placing all services in the same region ensures low-latency private networking and zero egress bandwidth costs between internal services.

## Environment Variables
The following environment variables must be defined in the Render Service settings:

| Variable | Description | Required | Example Format |
|---|---|---|---|
| `MYSQL_DATABASE` | Initial database name created on startup | Yes | `threat_intelligence_db` |
| `MYSQL_USER` | Dedicated application database user | Yes | `vigilock_user` |
| `MYSQL_PASSWORD` | Password for the application database user | Yes | `<SET_IN_RENDER>` |
| `MYSQL_ROOT_PASSWORD` | Administrative root password for MySQL | Yes | `<SET_IN_RENDER>` |

> **Security Note**: Never commit actual database passwords or credentials to GitHub. Set them exclusively within the Render environment variables dashboard.

## Internal Service Connection (Java Backend → MySQL)
When deployed as a Render Private Service, Render automatically assigns an internal hostname (e.g. `mysql-service` or `threat-intelligence-db:3306`).
- **Internal Host**: `<service-name>.render.internal` or `<service-name>`
- **Internal Port**: `3306`
- **JDBC Connection String**:
  ```
  jdbc:mysql://<mysql-service-name>:3306/threat_intelligence_db?createDatabaseIfNotExist=true&useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC&rewriteBatchedStatements=true
  ```

## Database Schema & Data Migration
- The Java backend includes `com.threatintel.db.SchemaInitializer` which can automatically execute `schema.sql` to initialize database tables on startup when invoked with `--init-db`.
- **Large Dataset Migration**: The existing historical database data will be migrated separately to the Render MySQL instance after service provisioning using standard migration scripts or MySQL client connections.
- Local MySQL data is NOT modified during this deployment preparation.

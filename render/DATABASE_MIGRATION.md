# Safe Database Migration Guide (Local MySQL → Cloud MySQL)

This document provides a strictly non-destructive migration procedure to transfer the 622.8 MB `threat_intelligence_db` database (~1.29M rows) to your free cloud MySQL instance (e.g. TiDB Cloud Serverless or Aiven MySQL) without modifying, dropping, or truncating your local database.

---

## 1. Prerequisites & Tool Paths

The following local binaries are used:
- **MySQL Client**: `C:\Program Files\MySQL\MySQL Server 8.0\bin\mysql.exe`
- **MySQL Dump**: `C:\Program Files\MySQL\MySQL Server 8.0\bin\mysqldump.exe`

---

## 2. Non-Destructive Step 1: Create a Local Read-Only Backup
Export the local database into a standalone SQL dump file. This command performs only `SELECT` operations on the local database and will **never** alter, drop, or truncate local tables.

Run from PowerShell:

```powershell
& "C:\Program Files\MySQL\MySQL Server 8.0\bin\mysqldump.exe" `
  -h localhost `
  -P 3306 `
  -u root `
  -p `
  --single-transaction `
  --quick `
  --routines `
  --triggers `
  --events `
  --hex-blob `
  --set-gtid-purged=OFF `
  --default-character-set=utf8mb4 `
  threat_intelligence_db > "threat_intel_backup.sql"
```

*(You will be prompted for your local root password. The backup file is automatically ignored by `.gitignore`.)*

---

## 3. Step 2: Verify Local Table Row Counts
Before importing, check your local row counts so you can compare them after migration:

```powershell
& "C:\Program Files\MySQL\MySQL Server 8.0\bin\mysql.exe" -h localhost -P 3306 -u root -p threat_intelligence_db -e "
SELECT 'phishing_urls' AS table_name, COUNT(*) AS total_rows FROM phishing_urls
UNION ALL
SELECT 'scam_messages', COUNT(*) FROM scam_messages
UNION ALL
SELECT 'email_scams', COUNT(*) FROM email_scams
UNION ALL
SELECT 'suspicious_calls', COUNT(*) FROM suspicious_calls
UNION ALL
SELECT 'malicious_ips', COUNT(*) FROM malicious_ips;
"
```

---

## 4. Step 3: Create the Target Database on Cloud MySQL
Connect to your remote cloud database and ensure the target database exists:

```powershell
# For TiDB Cloud Serverless (example with your cluster details)
& "C:\Program Files\MySQL\MySQL Server 8.0\bin\mysql.exe" `
  -h <CLOUD_DB_HOST> `
  -P <CLOUD_DB_PORT> `
  -u <CLOUD_DB_USER> `
  --ssl-mode=REQUIRED `
  -p `
  -e "CREATE DATABASE IF NOT EXISTS threat_intelligence_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
```

---

## 5. Step 4: Import Data into Cloud MySQL
Stream the backup into the remote cloud database:

```powershell
& "C:\Program Files\MySQL\MySQL Server 8.0\bin\mysql.exe" `
  -h <CLOUD_DB_HOST> `
  -P <CLOUD_DB_PORT> `
  -u <CLOUD_DB_USER> `
  --ssl-mode=REQUIRED `
  --default-character-set=utf8mb4 `
  -D threat_intelligence_db `
  -p < "threat_intel_backup.sql"
```

---

## 6. Step 5: Post-Migration Verification
Execute the verification query on the cloud database to confirm row count equality:

```powershell
& "C:\Program Files\MySQL\MySQL Server 8.0\bin\mysql.exe" `
  -h <CLOUD_DB_HOST> `
  -P <CLOUD_DB_PORT> `
  -u <CLOUD_DB_USER> `
  --ssl-mode=REQUIRED `
  -D threat_intelligence_db `
  -p `
  -e "
SELECT 'phishing_urls' AS table_name, COUNT(*) AS total_rows FROM phishing_urls
UNION ALL
SELECT 'scam_messages', COUNT(*) FROM scam_messages
UNION ALL
SELECT 'email_scams', COUNT(*) FROM email_scams
UNION ALL
SELECT 'suspicious_calls', COUNT(*) FROM suspicious_calls
UNION ALL
SELECT 'malicious_ips', COUNT(*) FROM malicious_ips;
"
```

If the row counts match the local database, migration is 100% complete and verified.

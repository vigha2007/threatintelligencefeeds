-- ============================================================
-- mysql_config_patch.sql
-- ============================================================
-- PURPOSE:
--   Apply before running large bulk inserts (≥ 200,000 rows/table).
--   Run this once per session:
--       mysql -u root -p threat_intelligence_db < mysql_config_patch.sql
--
-- These are SESSION-level settings that persist only for the duration
-- of the current connection.  For permanent changes, see the [my.ini]
-- block at the bottom of this file.
-- ============================================================

USE threat_intelligence_db;

-- ── Packet & timeout settings ─────────────────────────────────────────────

-- Allow single INSERT packets up to 128 MB (default = 4 MB)
SET GLOBAL max_allowed_packet    = 134217728;   -- 128 MB
SET SESSION max_allowed_packet   = 134217728;

-- Network timeouts — keep connection alive during long bulk inserts
SET GLOBAL  net_read_timeout     = 600;         -- 10 minutes
SET SESSION net_read_timeout     = 600;
SET GLOBAL  net_write_timeout    = 600;
SET SESSION net_write_timeout    = 600;
SET GLOBAL  wait_timeout         = 600;
SET SESSION wait_timeout         = 600;
SET GLOBAL  interactive_timeout  = 600;
SET SESSION interactive_timeout  = 600;

-- ── InnoDB buffer pool ────────────────────────────────────────────────────
-- Increase to ~70% of available RAM for bulk import performance.
-- Adjust the value below based on your system's total RAM.
-- Example: 4 GB RAM → 2.8 GB buffer pool
SET GLOBAL innodb_buffer_pool_size = 2684354560;  -- 2.5 GB (adjust as needed)

-- Larger log files reduce checkpoint frequency during bulk inserts
SET GLOBAL innodb_log_buffer_size = 67108864;     -- 64 MB

-- Disable double-write buffer for import speed (re-enable after import)
-- WARNING: Do NOT use on production if you cannot afford potential data loss
-- SET GLOBAL innodb_doublewrite = 0;             -- uncomment only if safe

-- ── Bulk-insert optimisation ─────────────────────────────────────────────
-- Disable unique-key checks during import (re-enable immediately after)
SET SESSION unique_checks   = 0;
SET SESSION foreign_key_checks = 0;

-- Disable autocommit — DataGenerator.java handles commits manually
SET SESSION autocommit = 0;

-- ── Verification ─────────────────────────────────────────────────────────
SELECT @@max_allowed_packet      AS max_allowed_packet,
       @@net_read_timeout        AS net_read_timeout,
       @@net_write_timeout       AS net_write_timeout,
       @@wait_timeout            AS wait_timeout,
       @@innodb_buffer_pool_size AS innodb_buffer_pool_size;

-- ============================================================
-- AFTER import is complete, restore safe defaults:
-- ============================================================
--   SET SESSION unique_checks      = 1;
--   SET SESSION foreign_key_checks = 1;
--   SET SESSION autocommit         = 1;
-- ============================================================


-- ============================================================
-- PERMANENT my.ini / my.cnf changes
-- ============================================================
-- Edit C:\ProgramData\MySQL\MySQL Server 8.x\my.ini  (Windows)
-- or  /etc/mysql/mysql.conf.d/mysqld.cnf              (Linux)
-- and add/update the following lines under [mysqld]:
--
-- [mysqld]
-- max_allowed_packet         = 128M
-- net_read_timeout           = 600
-- net_write_timeout          = 600
-- wait_timeout               = 600
-- interactive_timeout        = 600
-- innodb_buffer_pool_size    = 2G      # ~70% of RAM
-- innodb_log_buffer_size     = 64M
-- innodb_flush_log_at_trx_commit = 2   # faster commits; slight durability trade-off
-- innodb_io_capacity         = 2000    # raise for SSDs
-- bulk_insert_buffer_size    = 256M
--
-- Then restart MySQL:
--   Windows: net stop MySQL80 && net start MySQL80
--   Linux:   sudo systemctl restart mysql
-- ============================================================


-- ============================================================
-- ROW COUNT VERIFICATION QUERY
-- Run this after DataGenerator completes to confirm target counts:
-- ============================================================
SELECT 'threats'               AS table_name, COUNT(*) AS row_count FROM threats
UNION ALL
SELECT 'phishing_urls',                        COUNT(*) FROM phishing_urls
UNION ALL
SELECT 'suspicious_calls',                     COUNT(*) FROM suspicious_calls
UNION ALL
SELECT 'email_scams',                          COUNT(*) FROM email_scams
UNION ALL
SELECT 'malicious_ips',                        COUNT(*) FROM malicious_ips
UNION ALL
SELECT 'scam_messages',                        COUNT(*) FROM scam_messages
UNION ALL
SELECT 'scam_detector_results',                COUNT(*) FROM scam_detector_results
UNION ALL
SELECT 'users',                                COUNT(*) FROM users
UNION ALL
SELECT '--- TOTAL (threat tables) ---',
       SUM(t.c)
FROM (
    SELECT COUNT(*) c FROM threats
    UNION ALL SELECT COUNT(*) FROM phishing_urls
    UNION ALL SELECT COUNT(*) FROM suspicious_calls
    UNION ALL SELECT COUNT(*) FROM email_scams
    UNION ALL SELECT COUNT(*) FROM malicious_ips
    UNION ALL SELECT COUNT(*) FROM scam_messages
) t;

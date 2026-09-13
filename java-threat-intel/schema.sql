-- ============================================================
-- threat_intelligence_db — Schema v2 (Large-Dataset Edition)
-- ============================================================
-- Changes from v1:
--   • All primary keys use BIGINT to future-proof for millions of rows.
--   • ROW_FORMAT=DYNAMIC + ENGINE=InnoDB (explicit) on every table.
--   • Composite indexes added for the most common filter patterns:
--       (severity, detected_at) — dashboard severity + time queries
--       (type, severity)        — threats breakdown
--       specific column indexes kept from v1
--   • Table-level COMMENT documents the expected row-count target.
-- ============================================================

CREATE DATABASE IF NOT EXISTS threat_intelligence_db
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE threat_intelligence_db;

-- ============================================================
-- users
-- ============================================================
CREATE TABLE IF NOT EXISTS users (
    user_id  BIGINT       AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    email    VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    role     VARCHAR(50)  DEFAULT 'user',
    created_at TIMESTAMP  DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB ROW_FORMAT=DYNAMIC;

-- ============================================================
-- threats                         (target: ≥ 200,000 rows)
-- ============================================================
CREATE TABLE IF NOT EXISTS threats (
    id          BIGINT       AUTO_INCREMENT PRIMARY KEY,
    title       VARCHAR(255) NOT NULL,
    type        VARCHAR(100) NOT NULL,
    severity    VARCHAR(50)  NOT NULL DEFAULT 'medium',
    description TEXT,
    source      VARCHAR(255),
    detected_at TIMESTAMP    DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB ROW_FORMAT=DYNAMIC
  COMMENT='Unified threat registry. Target: ≥200,000 rows.';

-- Indexes for v1 compatibility
CREATE INDEX IF NOT EXISTS idx_threats_type        ON threats(type);
CREATE INDEX IF NOT EXISTS idx_threats_severity    ON threats(severity);
CREATE INDEX IF NOT EXISTS idx_threats_detected_at ON threats(detected_at);

-- Composite indexes for dashboard filter + sort patterns
CREATE INDEX IF NOT EXISTS idx_threats_sev_det   ON threats(severity, detected_at);
CREATE INDEX IF NOT EXISTS idx_threats_type_sev  ON threats(type, severity);

-- ============================================================
-- phishing_urls                   (target: ≥ 200,000 rows)
-- ============================================================
CREATE TABLE IF NOT EXISTS phishing_urls (
    id          BIGINT        AUTO_INCREMENT PRIMARY KEY,
    url         VARCHAR(2048) NOT NULL,
    domain      VARCHAR(255),
    severity    VARCHAR(50)   NOT NULL DEFAULT 'medium',
    notes       TEXT,
    detected_at TIMESTAMP     DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB ROW_FORMAT=DYNAMIC
  COMMENT='Phishing URL dataset. Target: ≥200,000 rows.';

CREATE INDEX IF NOT EXISTS idx_phishing_severity ON phishing_urls(severity);
CREATE INDEX IF NOT EXISTS idx_phishing_detected ON phishing_urls(detected_at);
CREATE INDEX IF NOT EXISTS idx_phishing_domain   ON phishing_urls(domain(191));
CREATE INDEX IF NOT EXISTS idx_phishing_sev_det  ON phishing_urls(severity, detected_at);

-- ============================================================
-- suspicious_calls                (target: ≥ 200,000 rows)
-- ============================================================
CREATE TABLE IF NOT EXISTS suspicious_calls (
    id                   BIGINT       AUTO_INCREMENT PRIMARY KEY,
    phone_number         VARCHAR(64)  NOT NULL,
    phone_number_10digit VARCHAR(32),
    country_code         VARCHAR(16)  DEFAULT '+91',
    country              VARCHAR(64),
    label                INT          DEFAULT 0,
    category             VARCHAR(64)  DEFAULT 'normal',
    data_type            VARCHAR(32)  DEFAULT 'synthetic',
    source               VARCHAR(64)  DEFAULT 'synthetic_generation',
    severity             VARCHAR(50)  NOT NULL DEFAULT 'medium',
    pattern              VARCHAR(500),
    detected_at          TIMESTAMP    DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB ROW_FORMAT=DYNAMIC
  COMMENT='Suspicious call dataset. Target: ≥ 200,000 rows.';

CREATE INDEX IF NOT EXISTS idx_calls_severity     ON suspicious_calls(severity);
CREATE INDEX IF NOT EXISTS idx_calls_detected     ON suspicious_calls(detected_at);
CREATE INDEX IF NOT EXISTS idx_calls_phone        ON suspicious_calls(phone_number);
CREATE INDEX IF NOT EXISTS idx_calls_phone_10d    ON suspicious_calls(phone_number_10digit);
CREATE INDEX IF NOT EXISTS idx_calls_category     ON suspicious_calls(category);
CREATE INDEX IF NOT EXISTS idx_calls_data_type    ON suspicious_calls(data_type);
CREATE INDEX IF NOT EXISTS idx_calls_sev_det      ON suspicious_calls(severity, detected_at);

-- ============================================================
-- email_scams                     (target: ≥ 200,000 rows)
-- ============================================================
CREATE TABLE IF NOT EXISTS email_scams (
    id               BIGINT      AUTO_INCREMENT PRIMARY KEY,
    sender           VARCHAR(255) NOT NULL,
    subject          VARCHAR(500),
    category         VARCHAR(64),
    severity         VARCHAR(50)  NOT NULL DEFAULT 'medium',
    recipients_count INT          DEFAULT 1,
    detected_at      TIMESTAMP    DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB ROW_FORMAT=DYNAMIC
  COMMENT='Email scam dataset. Target: ≥200,000 rows.';

CREATE INDEX IF NOT EXISTS idx_email_severity  ON email_scams(severity);
CREATE INDEX IF NOT EXISTS idx_email_detected  ON email_scams(detected_at);
CREATE INDEX IF NOT EXISTS idx_email_category  ON email_scams(category);
CREATE INDEX IF NOT EXISTS idx_email_sev_det   ON email_scams(severity, detected_at);

-- ============================================================
-- malicious_ips                   (target: ≥ 200,000 rows)
-- ============================================================
CREATE TABLE IF NOT EXISTS malicious_ips (
    id          BIGINT      AUTO_INCREMENT PRIMARY KEY,
    ip_address  VARCHAR(64) NOT NULL,
    country     VARCHAR(64),
    threat_type VARCHAR(128),
    severity    VARCHAR(50) NOT NULL DEFAULT 'medium',
    detected_at TIMESTAMP   DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB ROW_FORMAT=DYNAMIC
  COMMENT='Malicious IP dataset. Target: ≥200,000 rows.';

CREATE INDEX IF NOT EXISTS idx_ips_severity         ON malicious_ips(severity);
CREATE INDEX IF NOT EXISTS idx_ips_detected         ON malicious_ips(detected_at);
CREATE INDEX IF NOT EXISTS idx_ips_address          ON malicious_ips(ip_address);
CREATE INDEX IF NOT EXISTS idx_ips_threat_type      ON malicious_ips(threat_type);
CREATE INDEX IF NOT EXISTS idx_ips_sev_det          ON malicious_ips(severity, detected_at);
CREATE INDEX IF NOT EXISTS idx_ips_ip_threat        ON malicious_ips(ip_address, threat_type);

-- ============================================================
-- scam_messages                   (target: ≥ 200,000 rows)
-- ============================================================
CREATE TABLE IF NOT EXISTS scam_messages (
    id          BIGINT     AUTO_INCREMENT PRIMARY KEY,
    channel     VARCHAR(32) NOT NULL DEFAULT 'sms',
    sender      VARCHAR(128),
    content     TEXT        NOT NULL,
    severity    VARCHAR(50) NOT NULL DEFAULT 'medium',
    detected_at TIMESTAMP   DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB ROW_FORMAT=DYNAMIC
  COMMENT='Scam message dataset. Target: ≥200,000 rows.';

CREATE INDEX IF NOT EXISTS idx_scam_msg_severity  ON scam_messages(severity);
CREATE INDEX IF NOT EXISTS idx_scam_msg_detected  ON scam_messages(detected_at);
CREATE INDEX IF NOT EXISTS idx_scam_msg_channel   ON scam_messages(channel);
CREATE INDEX IF NOT EXISTS idx_scam_msg_chan_sev  ON scam_messages(channel, severity);
CREATE INDEX IF NOT EXISTS idx_scam_msg_sev_det   ON scam_messages(severity, detected_at);

-- ============================================================
-- scam_detector_results           (grows over time via ML API)
-- ============================================================
CREATE TABLE IF NOT EXISTS scam_detector_results (
    id             BIGINT       AUTO_INCREMENT PRIMARY KEY,
    input_text     TEXT,
    classification VARCHAR(255),
    confidence     FLOAT,
    severity       VARCHAR(50),
    raw_response   JSON,
    created_at     TIMESTAMP    DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB ROW_FORMAT=DYNAMIC
  COMMENT='ML prediction audit log. Grows unbounded via /api/analyze.';

CREATE INDEX IF NOT EXISTS idx_scam_det_severity   ON scam_detector_results(severity);
CREATE INDEX IF NOT EXISTS idx_scam_det_created    ON scam_detector_results(created_at);
CREATE INDEX IF NOT EXISTS idx_scam_det_class      ON scam_detector_results(classification);
CREATE INDEX IF NOT EXISTS idx_scam_det_sev_crt    ON scam_detector_results(severity, created_at);
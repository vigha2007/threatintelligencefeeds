CREATE DATABASE IF NOT EXISTS threat_intelligence_db;
USE threat_intelligence_db;

-- ============================================================
-- users
-- ============================================================
CREATE TABLE IF NOT EXISTS users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(50) DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================
-- threats
-- ============================================================
CREATE TABLE IF NOT EXISTS threats (
    id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    type VARCHAR(100) NOT NULL,
    severity VARCHAR(50) NOT NULL DEFAULT 'medium',
    description TEXT,
    source VARCHAR(255),
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_threats_type        ON threats(type);
CREATE INDEX idx_threats_severity    ON threats(severity);
CREATE INDEX idx_threats_detected_at ON threats(detected_at);

-- ============================================================
-- phishing_urls
-- ============================================================
CREATE TABLE IF NOT EXISTS phishing_urls (
    id INT AUTO_INCREMENT PRIMARY KEY,
    url VARCHAR(2048) NOT NULL,
    domain VARCHAR(255),
    severity VARCHAR(50) NOT NULL DEFAULT 'medium',
    notes TEXT,
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_phishing_severity ON phishing_urls(severity);
CREATE INDEX idx_phishing_detected ON phishing_urls(detected_at);

-- ============================================================
-- suspicious_calls
-- ============================================================
CREATE TABLE IF NOT EXISTS suspicious_calls (
    id INT AUTO_INCREMENT PRIMARY KEY,
    phone_number VARCHAR(64) NOT NULL,
    country VARCHAR(64),
    severity VARCHAR(50) NOT NULL DEFAULT 'medium',
    pattern VARCHAR(500),
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_calls_severity ON suspicious_calls(severity);
CREATE INDEX idx_calls_detected ON suspicious_calls(detected_at);

-- ============================================================
-- email_scams
-- ============================================================
CREATE TABLE IF NOT EXISTS email_scams (
    id INT AUTO_INCREMENT PRIMARY KEY,
    sender VARCHAR(255) NOT NULL,
    subject VARCHAR(500),
    category VARCHAR(64),
    severity VARCHAR(50) NOT NULL DEFAULT 'medium',
    recipients_count INT DEFAULT 1,
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_email_severity ON email_scams(severity);
CREATE INDEX idx_email_detected ON email_scams(detected_at);

-- ============================================================
-- malicious_ips
-- ============================================================
CREATE TABLE IF NOT EXISTS malicious_ips (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(64) NOT NULL,
    country VARCHAR(64),
    threat_type VARCHAR(128),
    severity VARCHAR(50) NOT NULL DEFAULT 'medium',
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_ips_severity ON malicious_ips(severity);
CREATE INDEX idx_ips_detected ON malicious_ips(detected_at);
CREATE INDEX idx_ips_address  ON malicious_ips(ip_address);

-- ============================================================
-- scam_messages
-- ============================================================
CREATE TABLE IF NOT EXISTS scam_messages (
    id INT AUTO_INCREMENT PRIMARY KEY,
    channel VARCHAR(32) NOT NULL DEFAULT 'sms',
    sender VARCHAR(128),
    content TEXT NOT NULL,
    severity VARCHAR(50) NOT NULL DEFAULT 'medium',
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_scam_msg_severity ON scam_messages(severity);
CREATE INDEX idx_scam_msg_detected ON scam_messages(detected_at);

-- ============================================================
-- scam_detector_results
-- ============================================================
CREATE TABLE IF NOT EXISTS scam_detector_results (
    id INT AUTO_INCREMENT PRIMARY KEY,
    input_text TEXT,
    classification VARCHAR(255),
    confidence FLOAT,
    severity VARCHAR(50),
    raw_response JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_scam_det_severity ON scam_detector_results(severity);
CREATE INDEX idx_scam_det_created  ON scam_detector_results(created_at);
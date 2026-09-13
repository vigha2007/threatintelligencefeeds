-- ============================================================
-- scam_detector_results (aligned with schema.sql BIGINT definition)
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

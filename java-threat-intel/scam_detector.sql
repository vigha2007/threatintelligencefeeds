
CREATE TABLE IF NOT EXISTS scam_detector_results (
    id INT AUTO_INCREMENT PRIMARY KEY,
    input_text TEXT,
    classification VARCHAR(255),
    confidence FLOAT,
    severity VARCHAR(50),
    raw_response JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

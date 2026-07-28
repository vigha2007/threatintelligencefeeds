package com.threatintel;
public class ThreatPrediction {
    private String prediction;    // "Safe" or "Malicious"
    private double confidence;    // 0.0 – 1.0
    private String threatLevel;   // "LOW", "MEDIUM", "HIGH"
    private String dataType;      // "url", "email", "sms", "call", "ip"

    // ── Constructors ──────────────────────────────────────────────────────────
    public ThreatPrediction() {}

    public ThreatPrediction(String prediction, double confidence,
                             String threatLevel, String dataType) {
        this.prediction  = prediction;
        this.confidence  = confidence;
        this.threatLevel = threatLevel;
        this.dataType    = dataType;
    }

    // ── Getters & Setters ─────────────────────────────────────────────────────
    public String getPrediction()          { return prediction; }
    public void   setPrediction(String p)  { this.prediction = p; }

    public double getConfidence()          { return confidence; }
    public void   setConfidence(double c)  { this.confidence = c; }

    public String getThreatLevel()         { return threatLevel; }
    public void   setThreatLevel(String t) { this.threatLevel = t; }

    public String getDataType()            { return dataType; }
    public void   setDataType(String d)    { this.dataType = d; }

    public boolean isMalicious() { return "Malicious".equalsIgnoreCase(prediction); }
}
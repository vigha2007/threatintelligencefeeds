"""
ML/fastapi_app.py
=================
VigiLock Production ML Inference REST API powered by FastAPI.

Multi-model routing: Each of the 5 CTI threat types is served by its own
dataset-specific best model + preprocessor bundle, automatically selected
by ML/training/train_all_models.py:

  url     -> phishing_urls      -> XGBoost  (TF-IDF 5000 + 38 dense = 5038 features)
  sms     -> scam_messages      -> XGBoost  (TF-IDF 3000 + 38 dense = 3038 features)
  email   -> email_scams        -> CatBoost (TF-IDF 3000 + 38 dense = 3038 features)
  call    -> suspicious_calls   -> Random Forest (40 phone structural features - Synthetic POC)
  ip      -> malicious_ips      -> XGBoost  (TF-IDF 1000 + 38 dense = 1038 features)

Artifacts loaded (from ML/models/):
  best_{dataset}_model.pkl       -- winning trained classifier
  best_{dataset}_preprocessor.pkl -- scaler + vectorizer + feature_order bundle

Feature extractors sourced from ML/training/train_all_models.py:
  extract_phone_features()       -- 40-feature phone structural extractor
  extract_text_or_url_features() -- 38-feature lexical extractor

Endpoints:
  GET  /         -> Root service status & model inventory
  GET  /health   -> Health check (all 5 models must be loaded)
  POST /predict  -> Real-time per-type threat classification
  GET  /docs     -> OpenAPI interactive Swagger documentation
"""

import os
import re
import sys
import joblib
import numpy as np
import scipy.sparse as sp
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional

# ---------------------------------------------------------------------------
# Path setup & Feature Extractors
# ---------------------------------------------------------------------------
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

TRAINING_DIR = os.path.join(SCRIPT_DIR, "training")
if TRAINING_DIR not in sys.path:
    sys.path.insert(0, TRAINING_DIR)

from train_all_models import extract_phone_features, extract_text_or_url_features, normalize_phone_number

MODELS_DIR = os.path.join(SCRIPT_DIR, "models")

# ---------------------------------------------------------------------------
# Type -> Dataset routing table
# ---------------------------------------------------------------------------
TYPE_TO_DATASET: dict[str, str] = {
    # URL / Phishing
    "url":              "phishing_urls",
    "phishing_url":     "phishing_urls",
    "phishing_urls":    "phishing_urls",
    # SMS / Scam messages
    "sms":              "scam_messages",
    "message":          "scam_messages",
    "text":             "scam_messages",
    "scam_messages":    "scam_messages",
    "scam_message":     "scam_messages",
    # Email
    "email":            "email_scams",
    "email_scams":      "email_scams",
    "email_scam":       "email_scams",
    # Call / Phone
    "call":             "suspicious_calls",
    "phone":            "suspicious_calls",
    "suspicious_calls": "suspicious_calls",
    "suspicious_call":  "suspicious_calls",
    # IP
    "ip":               "malicious_ips",
    "malicious_ip":     "malicious_ips",
    "malicious_ips":    "malicious_ips",
}

ATTACK_TYPE_LABELS: dict[str, str] = {
    "phishing_urls":    "Phishing URL",
    "scam_messages":    "Scam Message",
    "email_scams":      "Email Scam",
    "suspicious_calls": "Suspicious Call",
    "malicious_ips":    "Malicious IP",
}

DATASET_DOMAIN_TYPE: dict[str, str] = {
    "phishing_urls":    "url",
    "scam_messages":    "sms",
    "email_scams":      "email",
    "suspicious_calls": "call",
    "malicious_ips":    "ip",
}

# ---------------------------------------------------------------------------
# Global artifact registry
# ---------------------------------------------------------------------------
artifacts: dict[str, dict] = {}
load_errors: dict[str, str] = {}


def load_all_artifacts() -> None:
    """Load all 5 dataset-specific model + preprocessor bundles at startup."""
    datasets = list(DATASET_DOMAIN_TYPE.keys())
    for ds in datasets:
        # Check both naming styles: best_<ds>_model.pkl and <ds>_best_model.pkl
        model_path = os.path.join(MODELS_DIR, f"best_{ds}_model.pkl")
        if not os.path.exists(model_path):
            model_path = os.path.join(MODELS_DIR, f"{ds}_best_model.pkl")

        prep_path = os.path.join(MODELS_DIR, f"best_{ds}_preprocessor.pkl")
        if not os.path.exists(prep_path):
            prep_path = os.path.join(MODELS_DIR, f"{ds}_preprocessor.pkl")

        try:
            if not os.path.exists(model_path):
                raise FileNotFoundError(f"Model file not found: {model_path}")
            if not os.path.exists(prep_path):
                raise FileNotFoundError(f"Preprocessor file not found: {prep_path}")

            model = joblib.load(model_path)
            bundle = joblib.load(prep_path)

            is_call = bundle.get("is_call", ds == "suspicious_calls")
            vectorizer = bundle.get("vectorizer")
            scaler = bundle.get("scaler")

            vocab_size = len(getattr(vectorizer, "vocabulary_", {})) if vectorizer else 0
            n_features = getattr(scaler, "n_features_in_", "?") if scaler else "?"

            artifacts[ds] = {
                "model": model,
                "vectorizer": vectorizer,
                "scaler": scaler,
                "feature_order": bundle.get("feature_order", []),
                "domain_type": bundle.get("domain_type", DATASET_DOMAIN_TYPE[ds]),
                "is_call": is_call,
                "model_class": type(model).__name__,
                "vocab_size": vocab_size,
                "n_features": n_features,
                "synthetic": bundle.get("synthetic", False),
            }
            print(f"[OK] Loaded {ds}: {type(model).__name__} (is_call={is_call}) + TF-IDF({vocab_size}) + Scaler({n_features}f)")

        except Exception as exc:
            load_errors[ds] = str(exc)
            print(f"[ERROR] Failed to load {ds}: {exc}")


# ---------------------------------------------------------------------------
# FastAPI lifespan
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup: load all 5 per-dataset ML artifact bundles."""
    print("[STARTUP] Loading all 5 dataset-specific ML artifacts...")
    load_all_artifacts()
    loaded = [ds for ds in DATASET_DOMAIN_TYPE if ds in artifacts]
    failed = [ds for ds in DATASET_DOMAIN_TYPE if ds in load_errors]
    print(f"[STARTUP] Loaded: {loaded}")
    if failed:
        print(f"[STARTUP] Failed: {failed}")
    yield


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------
app = FastAPI(
    title="VigiLock Cyber Threat Intelligence ML API",
    description=(
        "Multi-model threat classification API. Each of the 5 CTI threat types "
        "(URL, Message, Email, Call, IP) is served by its own best-performing ML model."
    ),
    version="2.2.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS
cors_origins = os.getenv("CORS_ORIGINS", "*").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------
class ThreatPredictionRequest(BaseModel):
    content: str = Field(
        ...,
        description="Raw threat payload (URL, text message, email body, phone number, or IP address)"
    )
    type: Optional[str] = Field(
        default="generic",
        description=(
            "Threat payload type: 'url' | 'message'/'sms' | 'email' | 'call'/'phone' | 'ip'."
        )
    )
    data_type: Optional[str] = Field(
        default=None,
        description="Alias for 'type' (backward compatibility)"
    )


class ThreatPredictionResponse(BaseModel):
    prediction: str = Field(..., description="'MALICIOUS' or 'LEGITIMATE'")
    classification: str = Field(..., description="'MALICIOUS', 'SUSPICIOUS', or 'LEGITIMATE'")
    attack_type: str = Field(..., description="Threat category e.g. 'Phishing URL', 'Suspicious Call'")
    confidence: float = Field(..., description="Confidence score 0.00–1.00 for the predicted class")
    classes: list = Field(default_factory=list, description="Model classes_ array")
    probabilities: list = Field(default_factory=list, description="Probabilities for all classes")
    malicious_prob: float = Field(0.0, description="Probability of malicious class")
    severity: str = Field(..., description="'HIGH', 'MEDIUM', or 'LOW'")
    threat_level: str = Field(..., description="Alias for severity ('HIGH', 'MEDIUM', 'LOW')")
    data_type: str = Field(..., description="Resolved domain type: 'url', 'sms', 'email', 'call', 'ip'")
    dataset: str = Field(..., description="Dataset-specific model used for prediction")
    model_class: str = Field(..., description="Exact ML model class used")
    recommended_action: str = Field(..., description="Actionable security recommendation")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def resolve_dataset(raw_type: str) -> Optional[str]:
    """Map the user-provided type string to a canonical dataset name."""
    return TYPE_TO_DATASET.get(raw_type.lower().strip())


def calculate_severity_and_action(prediction: str, malicious_prob: float) -> tuple[str, str, str]:
    """
    Returns (classification, severity, recommended_action) strictly following:
    - LOW risk    -> LEGITIMATE / LOW
    - MEDIUM risk -> SUSPICIOUS / MEDIUM
    - HIGH risk   -> MALICIOUS / HIGH
    """
    if prediction == "MALICIOUS":
        if malicious_prob >= 0.65:
            return (
                "MALICIOUS",
                "HIGH",
                "Do not interact with this content. Block/report it and follow the recommended incident-response steps."
            )
        else:
            return (
                "SUSPICIOUS",
                "MEDIUM",
                "Exercise caution. Do not click links, provide credentials, send money, or share OTPs until the source is verified."
            )
    else:
        return (
            "LEGITIMATE",
            "LOW",
            "Low-risk content detected. Continue with normal security awareness."
        )


def run_inference(dataset: str, content: str) -> dict:
    """
    Run inference using the dataset-specific model and preprocessor.
    Matches exact feature extraction used during training.
    """
    entry = artifacts[dataset]
    model = entry["model"]
    scaler = entry["scaler"]
    vectorizer = entry["vectorizer"]
    domain_type = entry["domain_type"]
    is_call = entry["is_call"]

    if is_call:
        # Dedicated Phone Feature Extraction (40 structural features)
        raw_phone_feat = extract_phone_features(content)
        if len(raw_phone_feat) != scaler.n_features_in_:
            raise ValueError(
                "Feature dimension mismatch: extract_phone_features returned " + str(len(raw_phone_feat)) +
                " features but scaler expects " + str(scaler.n_features_in_) + "."
            )
        X_input = scaler.transform([raw_phone_feat])
    else:
        # Dense Lexical Features + TF-IDF
        raw_lex = extract_text_or_url_features(domain_type, content)
        if len(raw_lex) != scaler.n_features_in_:
            raise ValueError(
                f"Feature dimension mismatch: extract_text_or_url_features returned {len(raw_lex)} "
                f"features but scaler expects {scaler.n_features_in_}."
            )
        lex_scaled = scaler.transform([raw_lex])
        tfidf_vec = vectorizer.transform([content])
        X_input = sp.hstack([tfidf_vec, lex_scaled]).tocsr()

    # Predict & dynamic class probability extraction
    raw_pred = int(model.predict(X_input)[0])
    classes_list = list(getattr(model, "classes_", [0, 1]))

    if hasattr(model, "predict_proba"):
        probas = model.predict_proba(X_input)[0]
        try:
            predicted_index = classes_list.index(raw_pred)
            confidence_score = float(probas[predicted_index])
        except (ValueError, IndexError):
            predicted_index = 0
            confidence_score = float(probas[0])
            
        try:
            malicious_index = classes_list.index(1) if 1 in classes_list else -1
            malicious_prob = float(probas[malicious_index])
        except (ValueError, IndexError):
            malicious_prob = float(probas[1]) if len(probas) > 1 else float(probas[0])
    else:
        probas = [1.0 if c == raw_pred else 0.0 for c in classes_list]
        confidence_score = 1.0
        malicious_prob = 1.0 if raw_pred == 1 else 0.0

    prediction_label = "MALICIOUS" if raw_pred == 1 else "LEGITIMATE"

    return {
        "raw_pred": raw_pred,
        "classes": [int(c) if isinstance(c, (np.integer, int)) else str(c) for c in classes_list],
        "probabilities": [round(float(p), 4) for p in probas],
        "prediction": prediction_label,
        "malicious_prob": round(malicious_prob, 4),
        "confidence": round(confidence_score, 4),
        "model_class": entry["model_class"],
        "domain_type": domain_type,
    }


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@app.get("/", tags=["System Status"])
def root():
    """Return service status and loaded model inventory."""
    inventory = {}
    for ds, entry in artifacts.items():
        inventory[ds] = {
            "model_class": entry["model_class"],
            "vocab_size": entry["vocab_size"],
            "n_features": entry["n_features"],
            "domain_type": entry["domain_type"],
            "synthetic_poc": entry.get("synthetic", False),
            "status": "loaded",
        }
    for ds, err in load_errors.items():
        inventory[ds] = {"status": "error", "error": err}

    all_loaded = len(artifacts) == len(DATASET_DOMAIN_TYPE) and not load_errors
    return {
        "service": "VigiLock Cyber Threat Intelligence ML API",
        "version": "2.1.0",
        "status": "online" if all_loaded else "degraded",
        "models_loaded": len(artifacts),
        "models_failed": len(load_errors),
        "inventory": inventory,
        "docs_url": "/docs",
    }


@app.get("/health", tags=["System Status"])
def health_check():
    """Health check — all 5 models must be loaded."""
    if len(load_errors) > 0 or len(artifacts) < len(DATASET_DOMAIN_TYPE):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "status": "unhealthy",
                "loaded": list(artifacts.keys()),
                "failed": load_errors,
                "missing": [ds for ds in DATASET_DOMAIN_TYPE if ds not in artifacts and ds not in load_errors],
            }
        )
    return {
        "status": "healthy",
        "models": {ds: entry["model_class"] for ds, entry in artifacts.items()},
        "total_loaded": len(artifacts),
    }


@app.post("/predict", response_model=ThreatPredictionResponse, tags=["Threat Inference"])
def predict_threat(payload: ThreatPredictionRequest):
    """
    Route the request to the correct dataset-specific ML model and return a prediction.
    """
    content = (payload.content or "").strip()
    if not content:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="'content' field cannot be empty."
        )

    raw_type = (payload.data_type or payload.type or "generic").strip()
    dataset = resolve_dataset(raw_type)
    if dataset is None:
        accepted = sorted(set(TYPE_TO_DATASET.keys()))
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unknown threat type '{raw_type}'. Accepted values: {accepted}"
        )

    if dataset not in artifacts:
        err = load_errors.get(dataset, "Unknown load error")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Model for '{dataset}' is not available: {err}"
        )

    try:
        result = run_inference(dataset, content)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Inference error for dataset '{dataset}': {str(exc)}"
        )

    classification, severity, recommended_action = calculate_severity_and_action(
        result["prediction"], result["malicious_prob"]
    )

    if classification == "LEGITIMATE":
        attack_type = "None Detected"
    elif classification == "SUSPICIOUS":
        dataset_name = dataset.replace("_", " ").title()
        attack_type = f"Suspicious {dataset_name}" if "Suspicious" not in dataset_name else dataset_name
    else:
        attack_type = ATTACK_TYPE_LABELS.get(dataset, "Threat Detected")

    return ThreatPredictionResponse(
        prediction=result["prediction"],
        classification=classification,
        attack_type=attack_type,
        confidence=result["confidence"],
        classes=result["classes"],
        probabilities=result["probabilities"],
        malicious_prob=result["malicious_prob"],
        severity=severity,
        threat_level=severity,
        data_type=result["domain_type"],
        dataset=dataset,
        model_class=result["model_class"],
        recommended_action=recommended_action,
    )


# Alias endpoint for calls (/predict/call)
@app.post("/predict/call", response_model=ThreatPredictionResponse, tags=["Threat Inference"])
def predict_call_alias(payload: ThreatPredictionRequest):
    payload.type = "call"
    return predict_threat(payload)


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("fastapi_app:app", host="0.0.0.0", port=port, reload=True)

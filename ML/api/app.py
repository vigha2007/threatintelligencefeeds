"""
Cyber Threat Intelligence — Flask Prediction API
=================================================
Notebook-aligned prediction pipeline (ML_Training_CatBoost_70_30 (1).ipynb)

Preprocessing (identical to notebook):
  - TF-IDF only: max_features=5000, stop_words='english', lowercase=True
  - NO lexical features, NO scaler

Model: CatBoostClassifier trained on 1,292,417 rows (70/30 split)
  Artifacts:
    ML/models/catboost_notebook.cbm   (CatBoost native binary — primary)
    ML/models/tfidf_vectorizer.pkl    (notebook-trained vectorizer — primary)

  Fallback (if notebook artifacts not yet trained):
    ML/models/trained_catboost.pkl    (old catboost pkl)
    ML/models/vectorizer.pkl          (old vectorizer pkl)

Endpoints:
  POST /predict/message   -> SMS scam detection
  POST /predict/email     -> Email scam detection
  POST /predict/url       -> Phishing URL detection
  POST /predict/ip        -> Malicious IP detection
  POST /predict/call      -> Suspicious call detection
  POST /predict           -> Generic {type, content}
  GET  /health            -> Health check
  GET  /import-summary    -> Last Indian phone import summary (from integrate_indian_phones.py)

Each response:
  { prediction, confidence, threat_level, data_type, safe_prob, malicious_prob }

Run with:
    .venv\\Scripts\\python.exe ML/api/app.py
"""

import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

import os
import json
import joblib
import numpy as np
from flask import Flask, request, jsonify
from flask_cors import CORS
from catboost import CatBoostClassifier

# ── Paths ──────────────────────────────────────────────────────────────────────
_HERE = os.path.abspath(os.path.dirname(__file__))
MODELS_DIR = os.path.abspath(os.path.join(_HERE, "..", "models"))

app = Flask(__name__)
CORS(app)

# ── Lazy-loaded artifacts ──────────────────────────────────────────────────────
_model = None
_vectorizer = None
_model_info = {}


def _load_artifacts():
    """Load CatBoost model + TF-IDF vectorizer once at startup.

    Priority:
      1. catboost_notebook.cbm  + tfidf_vectorizer.pkl  (notebook-exact)
      2. trained_catboost.pkl   + vectorizer.pkl         (legacy fallback)
    """
    global _model, _vectorizer, _model_info
    if _model is not None and _vectorizer is not None:
        return  # already loaded

    # ── 1. Try notebook artifacts ─────────────────────────────────────────────
    cbm_path = os.path.join(MODELS_DIR, "catboost_notebook.cbm")
    vec_path  = os.path.join(MODELS_DIR, "tfidf_vectorizer.pkl")

    if os.path.exists(cbm_path) and os.path.exists(vec_path):
        print("[INFO] Loading notebook-trained CatBoost model (catboost_notebook.cbm)...")
        m = CatBoostClassifier()
        m.load_model(cbm_path)
        v = joblib.load(vec_path)
        _model = m
        _vectorizer = v
        _model_info = {
            "source": "notebook",
            "model_file": "catboost_notebook.cbm",
            "vectorizer_file": "tfidf_vectorizer.pkl",
            "features": getattr(v, "max_features", "?"),
        }
        print(f"[OK] Notebook model loaded. Features={_model_info['features']}")
        return

    # ── 2. Fallback: legacy pkl model ─────────────────────────────────────────
    legacy_model_path = os.path.join(MODELS_DIR, "trained_catboost.pkl")
    legacy_vec_path   = os.path.join(MODELS_DIR, "vectorizer.pkl")

    if os.path.exists(legacy_model_path) and os.path.exists(legacy_vec_path):
        print("[WARN] Notebook model not found. Loading legacy trained_catboost.pkl ...")
        _model      = joblib.load(legacy_model_path)
        _vectorizer = joblib.load(legacy_vec_path)
        _model_info = {
            "source": "legacy",
            "model_file": "trained_catboost.pkl",
            "vectorizer_file": "vectorizer.pkl",
            "features": getattr(_vectorizer, "max_features", "?"),
        }
        print(f"[OK] Legacy model loaded. Features={_model_info['features']}")
        return

    print("[ERROR] No model artifacts found. Run ML/train_catboost_notebook.py first.")


# ── Prediction helpers ─────────────────────────────────────────────────────────

def _threat_level(prob: float) -> str:
    if prob >= 0.80:
        return "HIGH"
    if prob >= 0.50:
        return "MEDIUM"
    return "LOW"


def _predict(content: str):
    """Run prediction using TF-IDF only (notebook pipeline). Returns (y_pred, mal_prob, safe_prob)."""
    _load_artifacts()

    if _model is None or _vectorizer is None:
        raise RuntimeError("Model or vectorizer not loaded.")

    # TF-IDF transform (no lexical features, no scaler — matches notebook)
    X = _vectorizer.transform([content])

    y_pred = int(_model.predict(X)[0])

    if hasattr(_model, "predict_proba"):
        probs = _model.predict_proba(X)[0]
        mal_prob = float(probs[1])
    else:
        mal_prob = float(y_pred)

    safe_prob = 1.0 - mal_prob
    return y_pred, mal_prob, safe_prob


def _build_response(data_type: str, y_pred: int, mal_prob: float, safe_prob: float):
    label = "Malicious" if y_pred == 1 else "Safe"
    confidence = round((mal_prob if y_pred == 1 else safe_prob) * 100, 2)
    return jsonify({
        "prediction":     label,
        "confidence":     confidence,
        "threat_level":   _threat_level(mal_prob),
        "data_type":      data_type,
        "safe_prob":      round(safe_prob, 4),
        "malicious_prob": round(mal_prob, 4),
    })


def _handle_predict(data_type: str):
    """Common handler for all typed endpoints."""
    if _model is None or _vectorizer is None:
        _load_artifacts()
    if _model is None or _vectorizer is None:
        return jsonify({"error": "Model not loaded. Run ML/train_catboost_notebook.py first."}), 503

    body = request.get_json(force=True, silent=True) or {}
    content = str(body.get("content", "")).strip()
    if not content:
        return jsonify({"error": "'content' field is required."}), 400

    try:
        y, mal, safe = _predict(content)
        return _build_response(data_type, y, mal, safe)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ── Endpoints ──────────────────────────────────────────────────────────────────

@app.route("/predict/message", methods=["POST"])
def predict_message():
    return _handle_predict("message")


@app.route("/predict/email", methods=["POST"])
def predict_email():
    return _handle_predict("email")


@app.route("/predict/url", methods=["POST"])
def predict_url():
    return _handle_predict("url")


@app.route("/predict/ip", methods=["POST"])
def predict_ip():
    return _handle_predict("ip")


@app.route("/predict/call", methods=["POST"])
def predict_call():
    return _handle_predict("call")


@app.route("/predict", methods=["POST"])
def predict_generic():
    """Generic endpoint: { type: 'message|email|url|ip|call', content: '...' }"""
    body = request.get_json(force=True, silent=True) or {}
    d_type = str(body.get("type", "")).strip().lower()
    content = str(body.get("content", "")).strip()

    if not d_type or not content:
        return jsonify({"error": "Fields 'type' and 'content' are required."}), 400

    type_map = {
        "message": "message",
        "sms":     "message",
        "email":   "email",
        "url":     "url",
        "ip":      "ip",
        "call":    "call",
        "suspicious_call": "call",
    }
    mapped = type_map.get(d_type)
    if not mapped:
        return jsonify({"error": f"Unknown type '{d_type}'. Valid: message, email, url, ip, call."}), 400

    # Reuse handle logic directly
    if _model is None or _vectorizer is None:
        _load_artifacts()
    if _model is None or _vectorizer is None:
        return jsonify({"error": "Model not loaded. Run ML/train_catboost_notebook.py first."}), 503

    try:
        y, mal, safe = _predict(content)
        return _build_response(mapped, y, mal, safe)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/health", methods=["GET"])
def health():
    _load_artifacts()
    model_ok = _model is not None
    vec_ok   = _vectorizer is not None
    all_ok   = model_ok and vec_ok
    return jsonify({
        "status":        "ok" if all_ok else "degraded",
        "model_loaded":  model_ok,
        "vector_loaded": vec_ok,
        "model_info":    _model_info,
    }), 200 if all_ok else 503


@app.route("/import-summary", methods=["GET"])
def import_summary():
    """Return the last Indian phone numbers import summary produced by integrate_indian_phones.py."""
    summary_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "logs", "indian_phones_import_summary.json")
    )
    if not os.path.exists(summary_path):
        return jsonify({
            "error": "No import summary found. Run ML/integrate_indian_phones.py first.",
            "path":  summary_path,
        }), 404
    try:
        with open(summary_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return jsonify(data), 200
    except Exception as exc:
        return jsonify({"error": f"Failed to read summary: {exc}"}), 500


if __name__ == "__main__":
    _load_artifacts()
    app.run(host="0.0.0.0", port=5000, debug=False)

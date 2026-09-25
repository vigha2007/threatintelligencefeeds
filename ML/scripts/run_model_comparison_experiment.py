"""
ML/scripts/run_model_comparison_experiment.py
=============================================
Reproducible Machine Learning Model Comparison Experiment for IEEE Research Paper.

Evaluates 7 Classical ML / Ensemble Algorithms on the EXACT SAME Dataset,
Train/Test Split, and Feature Representation:
  1. Logistic Regression
  2. Naive Bayes (MultinomialNB)
  3. Decision Tree
  4. Random Forest
  5. Support Vector Machine (Linear SVM with probability calibration)
  6. XGBoost (Extreme Gradient Boosting)
  7. CatBoost (Categorical Boosting)

Outputs:
  - ML/evaluation/model_comparison_results.json
  - ML/reports/model_comparison_results.csv
"""

import os
import sys
import time
import json
import warnings
import numpy as np
import pandas as pd
import mysql.connector

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
)

# Algorithms
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import MultinomialNB
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV
from xgboost import XGBClassifier
from catboost import CatBoostClassifier

warnings.filterwarnings("ignore")

# ── Paths ───────────────────────────────────────────────────────────────────
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ML_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
EVAL_DIR = os.path.join(ML_DIR, "evaluation")
REPORTS_DIR = os.path.join(ML_DIR, "reports")

os.makedirs(EVAL_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

JSON_OUT = os.path.join(EVAL_DIR, "model_comparison_results.json")
CSV_OUT = os.path.join(REPORTS_DIR, "model_comparison_results.csv")

RANDOM_STATE = 42
TEST_SIZE = 0.20
MAX_FEATURES = 5000

print("=" * 80)
print("  IEEE RESEARCH MODEL COMPARISON EXPERIMENT: CYBER THREAT DETECTION")
print("=" * 80)

# ── 1. Load Dataset from MySQL ──────────────────────────────────────────────
print("\n[Step 1/5] Loading Scam Messages Dataset from MySQL database...")
conn = mysql.connector.connect(
    host="localhost",
    user="root",
    password="vigha@2007",
    database="threat_intelligence_db",
)
query = "SELECT content, severity FROM scam_messages WHERE content IS NOT NULL"
df = pd.read_sql(query, conn)
conn.close()

df["content"] = df["content"].astype(str).str.strip()
df = df[df["content"].str.len() > 2].reset_index(drop=True)
df["label"] = df["severity"].apply(lambda s: 1 if str(s).lower() in ("high", "critical", "medium") else 0)

total_samples = len(df)
benign_count = int((df["label"] == 0).sum())
malicious_count = int((df["label"] == 1).sum())

print(f"  Total verified samples: {total_samples:,}")
print(f"  - Benign samples (label=0):    {benign_count:,} ({benign_count/total_samples*100:.2f}%)")
print(f"  - Malicious samples (label=1): {malicious_count:,} ({malicious_count/total_samples*100:.2f}%)")

# ── 2. Train/Test Split ─────────────────────────────────────────────────────
print(f"\n[Step 2/5] Performing Stratified Train/Test Split (80:20, random_state={RANDOM_STATE})...")
X_raw = df["content"]
y = df["label"].values

X_train_raw, X_test_raw, y_train, y_test = train_test_split(
    X_raw, y, test_size=TEST_SIZE, stratify=y, random_state=RANDOM_STATE
)
print(f"  Training set size: {len(X_train_raw):,} samples")
print(f"  Testing set size:  {len(X_test_raw):,} samples")

# ── 3. Feature Representation ───────────────────────────────────────────────
print(f"\n[Step 3/5] Extracting TF-IDF Text Feature Representation (max_features={MAX_FEATURES})...")
tfidf = TfidfVectorizer(
    max_features=MAX_FEATURES,
    ngram_range=(1, 2),
    sublinear_tf=True,
    stop_words="english",
    strip_accents="unicode",
)
X_train = tfidf.fit_transform(X_train_raw)
X_test = tfidf.transform(X_test_raw)
print(f"  Vocabulary size: {len(tfidf.vocabulary_)} features")
print(f"  X_train sparse matrix shape: {X_train.shape}")
print(f"  X_test sparse matrix shape:  {X_test.shape}")

# ── 4. Candidate Model Definitions ──────────────────────────────────────────
models = {
    "Logistic Regression": LogisticRegression(
        C=1.0, max_iter=1000, random_state=RANDOM_STATE, solver="lbfgs"
    ),
    "Naive Bayes": MultinomialNB(
        alpha=1.0
    ),
    "Decision Tree": DecisionTreeClassifier(
        max_depth=20, random_state=RANDOM_STATE
    ),
    "Random Forest": RandomForestClassifier(
        n_estimators=150, max_depth=20, random_state=RANDOM_STATE, n_jobs=-1
    ),
    "SVM": CalibratedClassifierCV(
        LinearSVC(C=1.0, random_state=RANDOM_STATE),
        method="sigmoid",
        cv=3,
    ),
    "XGBoost": XGBClassifier(
        n_estimators=150,
        max_depth=6,
        learning_rate=0.1,
        random_state=RANDOM_STATE,
        n_jobs=-1,
        eval_metric="logloss",
    ),
    "CatBoost": CatBoostClassifier(
        iterations=150,
        depth=6,
        learning_rate=0.1,
        random_seed=RANDOM_STATE,
        verbose=0,
    ),
}

# ── 5. Train, Evaluate & Measure ───────────────────────────────────────────
print("\n[Step 4/5] Training and evaluating all 7 models on the identical test set...")
results = []
detailed_dict = {
    "metadata": {
        "dataset": "scam_messages (SMS Threat Intelligence Corpus)",
        "source": "MySQL threat_intelligence_db.scam_messages",
        "total_samples": total_samples,
        "train_samples": len(X_train_raw),
        "test_samples": len(X_test_raw),
        "train_test_split": "80:20 (Stratified)",
        "random_state": RANDOM_STATE,
        "feature_representation": f"TF-IDF (1-2 ngrams, sublinear_tf, max_features={MAX_FEATURES})",
        "feature_count": MAX_FEATURES,
        "evaluated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    },
    "models": {},
}

for name, model in models.items():
    print(f"\n  --> Training {name}...")
    t_start_train = time.time()
    model.fit(X_train, y_train)
    t_train = round(time.time() - t_start_train, 4)

    t_start_pred = time.time()
    y_pred = model.predict(X_test)
    t_pred = round(time.time() - t_start_pred, 4)

    if hasattr(model, "predict_proba"):
        y_proba = model.predict_proba(X_test)[:, 1]
    elif hasattr(model, "decision_function"):
        y_proba = model.decision_function(X_test)
    else:
        y_proba = y_pred

    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred, zero_division=0))
    rec = float(recall_score(y_test, y_pred, zero_division=0))
    f1 = float(f1_score(y_test, y_pred, zero_division=0))
    roc = float(roc_auc_score(y_test, y_proba))

    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = int(cm[0, 0]), int(cm[0, 1]), int(cm[1, 0]), int(cm[1, 1])

    row = {
        "Model": name,
        "Accuracy (%)": round(acc * 100, 2),
        "Precision (%)": round(prec * 100, 2),
        "Recall (%)": round(rec * 100, 2),
        "F1-Score (%)": round(f1 * 100, 2),
        "ROC-AUC (%)": round(roc * 100, 2),
        "Training Time (s)": t_train,
        "Inference Time (s)": t_pred,
        "TP": tp,
        "TN": tn,
        "FP": fp,
        "FN": fn,
    }
    results.append(row)

    detailed_dict["models"][name] = {
        "accuracy": round(acc, 6),
        "accuracy_pct": round(acc * 100, 2),
        "precision": round(prec, 6),
        "precision_pct": round(prec * 100, 2),
        "recall": round(rec, 6),
        "recall_pct": round(rec * 100, 2),
        "f1_score": round(f1, 6),
        "f1_pct": round(f1 * 100, 2),
        "roc_auc": round(roc, 6),
        "roc_auc_pct": round(roc * 100, 2),
        "training_time_seconds": t_train,
        "inference_time_seconds": t_pred,
        "confusion_matrix": {
            "true_positive": tp,
            "true_negative": tn,
            "false_positive": fp,
            "false_negative": fn,
        },
    }
    print(f"      Acc: {acc*100:.2f}% | Prec: {prec*100:.2f}% | Rec: {rec*100:.2f}% | F1: {f1*100:.2f}% | AUC: {roc*100:.2f}% | Train: {t_train}s | Pred: {t_pred}s")

# ── 6. Save Results to Disk ─────────────────────────────────────────────────
print("\n[Step 5/5] Saving results to JSON and CSV...")
with open(JSON_OUT, "w", encoding="utf-8") as f:
    json.dump(detailed_dict, f, indent=4)
print(f"  [OK] Saved: {JSON_OUT}")

results_df = pd.DataFrame(results)
results_df.to_csv(CSV_OUT, index=False)
print(f"  [OK] Saved: {CSV_OUT}")

print("\n" + "=" * 80)
print("  EXPERIMENT COMPLETE — SUMMARY TABLE")
print("=" * 80)
print(results_df[["Model", "Accuracy (%)", "Precision (%)", "Recall (%)", "F1-Score (%)", "ROC-AUC (%)", "Training Time (s)", "Inference Time (s)"]].to_string(index=False))

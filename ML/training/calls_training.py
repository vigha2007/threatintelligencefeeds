"""
ML/training/calls_training.py
=============================
VigiLock Calls Dedicated Model Training and Evaluation Script.

Trains Random Forest, XGBoost, and CatBoost on:
  suspicious_calls_india_50000_synthetic.csv

Enforces:
- 80:20 Stratified Train/Test Split (random_state=42, shuffle=True, stratify=y)
- Zero Data Leakage (Scaler fit strictly on X_train)
- Phone Structural Feature Engineering (no category/label leakage)
- Automatic selection of the best model (F1 -> Recall -> Precision -> AUC -> Acc -> Speed)
- Artifact saving (best_calls_model.pkl, calls_model_comparison.csv)
"""

import os
import sys
import time
import json
import joblib
import warnings
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix
)
from xgboost import XGBClassifier
from catboost import CatBoostClassifier

warnings.filterwarnings("ignore")

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ML_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

from train_all_models import extract_phone_features, select_best_model

DATA_DIR = os.path.join(ML_DIR, "data")
MODELS_DIR = os.path.join(ML_DIR, "models")
REPORTS_DIR = os.path.join(ML_DIR, "reports")


def train_calls_model():
    file_name = "suspicious_calls_india_50000_synthetic.csv"
    file_path = os.path.join(DATA_DIR, file_name)
    print("=" * 70)
    print(f"   TRAINING CALLS DATASET: {file_name}")
    print("=" * 70)

    df = pd.read_csv(file_path)
    total_records = len(df)
    missing_counts = df.isnull().sum().to_dict()
    total_dupes = df.duplicated().sum()
    phone_dupes = df.duplicated(subset=["phone_number"]).sum()
    
    print(f"Total records: {total_records}")
    print(f"Missing values: {missing_counts}")
    print(f"Total duplicate rows: {total_dupes}")
    print(f"Duplicate phone numbers: {phone_dupes}")
    
    y = df["label"].astype(int).values
    class_0 = int(sum(y == 0))
    class_1 = int(sum(y == 1))
    print(f"Label distribution: 0 (Normal)={class_0} ({class_0/total_records*100:.2f}%), 1 (Scam)={class_1} ({class_1/total_records*100:.2f}%)")
    
    df_train, df_test, y_train, y_test = train_test_split(
        df, y, test_size=0.20, random_state=42, shuffle=True, stratify=y
    )
    print(f"Training size: {len(df_train)} | Testing size: {len(df_test)}")
    
    print("Extracting 38-dimensional phone structural features...")
    X_raw_train = np.array([extract_phone_features(p) for p in df_train["phone_number"]])
    X_raw_test = np.array([extract_phone_features(p) for p in df_test["phone_number"]])
    
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_raw_train)
    X_test = scaler.transform(X_raw_test)
    print(f"Feature matrix shape: Train={X_train.shape}, Test={X_test.shape}")
    
    models = {
        "Random Forest": RandomForestClassifier(
            n_estimators=150, max_depth=15, random_state=42, n_jobs=-1, class_weight="balanced"
        ),
        "XGBoost": XGBClassifier(
            n_estimators=150, max_depth=6, learning_rate=0.1, random_state=42, n_jobs=-1, eval_metric="logloss"
        ),
        "CatBoost": CatBoostClassifier(
            iterations=150, depth=6, learning_rate=0.1, random_seed=42, verbose=0
        )
    }
    
    results = []
    metrics_dict = {}
    fitted_models = {}
    
    for name, model in models.items():
        print(f"\n--- Training {name} ---")
        t0 = time.time()
        model.fit(X_train, y_train)
        train_time = round(time.time() - t0, 3)
        
        t1 = time.time()
        y_pred = model.predict(X_test)
        pred_time = round(time.time() - t1, 4)
        
        y_proba = model.predict_proba(X_test)[:, 1] if hasattr(model, "predict_proba") else y_pred
        
        acc = round(float(accuracy_score(y_test, y_pred)), 4)
        prec = round(float(precision_score(y_test, y_pred, zero_division=0)), 4)
        rec = round(float(recall_score(y_test, y_pred, zero_division=0)), 4)
        f1 = round(float(f1_score(y_test, y_pred, zero_division=0)), 4)
        roc = round(float(roc_auc_score(y_test, y_proba)), 4)
        
        cm = confusion_matrix(y_test, y_pred)
        tn, fp, fn, tp = int(cm[0, 0]), int(cm[0, 1]), int(cm[1, 0]), int(cm[1, 1])
        
        print(f"[{name}] Acc={acc*100:.2f}% | Prec={prec*100:.2f}% | Rec={rec*100:.2f}% | F1={f1*100:.2f}% | AUC={roc*100:.2f}% | TP={tp} TN={tn} FP={fp} FN={fn}")
        
        res_row = {
            "model": name,
            "accuracy": acc,
            "precision": prec,
            "recall": rec,
            "f1_score": f1,
            "roc_auc": roc,
            "train_time": train_time,
            "test_time": pred_time,
            "TP": tp,
            "TN": tn,
            "FP": fp,
            "FN": fn
        }
        results.append(res_row)
        metrics_dict[name] = {
            "Accuracy": acc,
            "Precision": prec,
            "Recall": rec,
            "F1": f1,
            "ROC-AUC": roc,
            "Training Time (s)": train_time,
            "Prediction Time (s)": pred_time,
            "TP": tp, "TN": tn, "FP": fp, "FN": fn
        }
        fitted_models[name] = model
        
    winner_name, winner_metrics = select_best_model(metrics_dict)
    winner_model = fitted_models[winner_name]
    print("\n" + "=" * 70)
    print(f"🏆 BEST CALLS MODEL: {winner_name} (F1 = {winner_metrics['F1']*100:.2f}%)")
    print("=" * 70)
    
    # Save winner model
    best_model_path1 = os.path.join(MODELS_DIR, "best_calls_model.pkl")
    best_model_path2 = os.path.join(MODELS_DIR, "suspicious_calls_best_model.pkl")
    joblib.dump(winner_model, best_model_path1)
    joblib.dump(winner_model, best_model_path2)
    print(f"Saved: {best_model_path1} and {best_model_path2}")
    
    # Save preprocessor
    prep_bundle = {
        "dataset_name": "suspicious_calls",
        "domain_type": "call",
        "scaler": scaler,
        "vectorizer": None,
        "max_tfidf": 0,
        "is_call": True,
        "feature_order": sorted([
            "raw_length", "digit_count", "has_plus", "has_91_prefix", "is_valid_10digit",
            "starts_with_6", "starts_with_7", "starts_with_8", "starts_with_9", "is_valid_indian_mobile",
            "first_digit", "first_2_digits", "first_3_digits", "first_4_digits",
            "last_digit", "last_2_digits", "last_3_digits",
            "freq_digit_0", "freq_digit_1", "freq_digit_2", "freq_digit_3", "freq_digit_4",
            "freq_digit_5", "freq_digit_6", "freq_digit_7", "freq_digit_8", "freq_digit_9",
            "unique_digit_count", "digit_diversity_ratio", "even_digit_ratio", "odd_digit_ratio",
            "zero_count", "digit_mean", "digit_std",
            "max_consecutive_rep", "repeated_pairs_count", "max_asc_run", "max_desc_run",
            "consecutive_diff_mean", "consecutive_diff_std"
        ]),
        "winner_model_name": winner_name,
        "metrics": winner_metrics,
        "synthetic": True,
        "dataset_file": file_name
    }
    joblib.dump(prep_bundle, os.path.join(MODELS_DIR, "best_calls_preprocessor.pkl"))
    joblib.dump(prep_bundle, os.path.join(MODELS_DIR, "suspicious_calls_preprocessor.pkl"))
    
    # Save comparison CSV
    comp_df = pd.DataFrame(results)
    comp_csv = os.path.join(REPORTS_DIR, "calls_model_comparison.csv")
    comp_df.to_csv(comp_csv, index=False)
    print(f"Exported calls comparison to: {comp_csv}")
    
    return comp_df, winner_name, winner_metrics


if __name__ == "__main__":
    train_calls_model()

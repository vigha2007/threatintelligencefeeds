"""
train.py  (CLEANED — XGBoost + CatBoost ONLY)
=============================================
Previous version contained: SVM, LightGBM, Logistic Regression, Random Forest,
Naive Bayes, CNN, LSTM, Bi-LSTM, Transformer.

All of those have been REMOVED. Only XGBoost and CatBoost remain.

Entry point: python ML/train.py
"""

import os
import sys
import json
import time
import joblib
import numpy as np
import pandas as pd
from xgboost import XGBClassifier
from catboost import CatBoostClassifier
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                              f1_score, roc_auc_score)

# Add parent and local dir to system path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ML.utils.helpers import setup_logger, save_versioned_model, MODELS_DIR, EVALUATION_DIR
from ML.datasets.downloader import download_all_datasets
from ML.preprocess import preprocess_dataset

logger = setup_logger("train_pipeline")

DATA_FILE = os.path.join(os.path.dirname(__file__), "data", "combined_dataset.csv")


# ─── Classical Model Training (XGBoost + CatBoost only) ────────────────────

def train_models(X_train, y_train, X_val, y_val, X_test, y_test):
    """Train and evaluate XGBoost and CatBoost with memory-saving optimizations."""
    logger.info("=" * 60)
    logger.info("  MODEL TRAINING — XGBoost + CatBoost")
    logger.info("=" * 60)

    models = {
        "XGBoost": XGBClassifier(
            n_estimators=300, max_depth=6, learning_rate=0.1,
            eval_metric="logloss", random_state=42, n_jobs=-1,
            tree_method="hist", verbosity=0,
        ),
        "CatBoost": CatBoostClassifier(
            iterations=300, depth=6, learning_rate=0.1,
            random_state=42, verbose=0, thread_count=-1,
        ),
    }

    results = {}
    for name, model in models.items():
        try:
            logger.info(f"Training: {name}...")
            t0 = time.time()
            
            if name == "CatBoost":
                from sklearn.model_selection import train_test_split
                from catboost import Pool
                import gc
                
                # Downsample training set for CatBoost to avoid OOM
                max_cb_train = 50000
                if X_train.shape[0] > max_cb_train:
                    indices = np.arange(X_train.shape[0])
                    _, cb_train_idx = train_test_split(
                        indices,
                        test_size=max_cb_train / X_train.shape[0],
                        random_state=42,
                        stratify=y_train
                    )
                    X_train_cb = X_train[cb_train_idx].toarray()
                    y_train_cb = y_train[cb_train_idx]
                    logger.info(f"    Downsampled CatBoost training data to {X_train_cb.shape[0]:,} rows for memory efficiency.")
                else:
                    X_train_cb = X_train.toarray()
                    y_train_cb = y_train
                
                train_pool_cb = Pool(X_train_cb, label=y_train_cb)
                model.fit(train_pool_cb, verbose=False)
                train_time = time.time() - t0
                
                del X_train_cb, y_train_cb, train_pool_cb
                gc.collect()
                
                # Chunked predictions for evaluation to avoid OOM
                logger.info(f"    Running CatBoost predictions in chunks on {X_test.shape[0]:,} test records ...")
                y_pred_list = []
                y_prob_list = []
                batch_size = 10000
                for i in range(0, X_test.shape[0], batch_size):
                    chunk = X_test[i : i + batch_size].toarray()
                    y_pred_list.append(model.predict(chunk))
                    y_prob_list.append(model.predict_proba(chunk)[:, 1])
                y_pred = np.concatenate(y_pred_list).astype(int).flatten()
                y_prob = np.concatenate(y_prob_list)
            else:
                model.fit(X_train, y_train)
                train_time = time.time() - t0
                y_pred = model.predict(X_test)
                y_prob = model.predict_proba(X_test)[:, 1]

            metrics = {
                "accuracy":    float(accuracy_score(y_test, y_pred)),
                "precision":   float(precision_score(y_test, y_pred, zero_division=0)),
                "recall":      float(recall_score(y_test, y_pred, zero_division=0)),
                "f1":          float(f1_score(y_test, y_pred, zero_division=0)),
                "roc_auc":     float(roc_auc_score(y_test, y_prob)),
                "train_time_s": round(train_time, 3),
            }
            logger.info(f"  {name}: F1={metrics['f1']:.4f}  Acc={metrics['accuracy']:.4f}  AUC={metrics['roc_auc']:.4f}")
            results[name] = {"model": model, "metrics": metrics}

        except Exception as e:
            logger.error(f"  [FAIL] {name}: {e}")

    return results


# ─── Main Pipeline ───────────────────────────────────────────────────────────

def run_pipeline():
    # 1. Download datasets
    download_all_datasets()

    # 2. Preprocess
    data_path = DATA_FILE
    if not os.path.exists(data_path):
        logger.error(f"Combined dataset not found at {data_path}.")
        logger.error("Run ML/retrain_xgboost_catboost.py to build datasets first.")
        sys.exit(1)

    X_train, X_test, y_train, y_test, scaler, vectorizer, feat_cols = preprocess_dataset(data_path)

    # Use 10% of train as validation
    n_val = max(1, int(len(y_train) * 0.1))
    X_val    = X_train[-n_val:]
    y_val    = y_train[-n_val:]
    X_train  = X_train[:-n_val]
    y_train  = y_train[:-n_val]

    # 3. Train XGBoost + CatBoost
    all_results = train_models(X_train, y_train, X_val, y_val, X_test, y_test)

    if not all_results:
        logger.error("No models trained successfully.")
        sys.exit(1)

    # 4. Select best by F1
    best_name, best_score, best_model = None, -1.0, None
    for name, res in all_results.items():
        if res["metrics"]["f1"] > best_score:
            best_score = res["metrics"]["f1"]
            best_name  = name
            best_model = res["model"]

    logger.info("=" * 60)
    logger.info(f"  WINNING MODEL: {best_name}  (F1={best_score:.4f})")
    logger.info("=" * 60)

    # 5. Save artifacts
    os.makedirs(MODELS_DIR, exist_ok=True)
    os.makedirs(EVALUATION_DIR, exist_ok=True)

    joblib.dump(best_model, os.path.join(MODELS_DIR, "best_model.pkl"))
    joblib.dump(scaler,     os.path.join(MODELS_DIR, "scaler.pkl"))
    joblib.dump(vectorizer, os.path.join(MODELS_DIR, "vectorizer.pkl"))

    # Save both models explicitly
    joblib.dump(all_results["XGBoost"]["model"],  os.path.join(MODELS_DIR, "trained_xgboost.pkl"))
    joblib.dump(all_results["CatBoost"]["model"], os.path.join(MODELS_DIR, "trained_catboost.pkl"))

    # 6. Save comparison report
    report = {name: res["metrics"] for name, res in all_results.items()}
    with open(os.path.join(EVALUATION_DIR, "comparison_report.json"), "w") as f:
        json.dump(report, f, indent=4)
    logger.info("Comparison report saved.")

    # 7. Print summary table
    logger.info("\n" + "=" * 65)
    logger.info(f"  {'Model':<22} {'F1':>7}  {'Acc':>7}  {'ROC-AUC':>8}  {'Train(s)':>9}")
    logger.info("=" * 65)
    for name, res in sorted(all_results.items(), key=lambda x: -x[1]["metrics"]["f1"]):
        m = res["metrics"]
        logger.info(f"  {name:<22} {m['f1']:>7.4f}  {m['accuracy']:>7.4f}  "
                    f"{m['roc_auc']:>8.4f}  {m['train_time_s']:>9.1f}")
    logger.info("=" * 65)

    # 8. Version the winner
    save_versioned_model(best_name, {
        "best_model.pkl": os.path.join(MODELS_DIR, "best_model.pkl"),
        "scaler.pkl":     os.path.join(MODELS_DIR, "scaler.pkl"),
        "vectorizer.pkl": os.path.join(MODELS_DIR, "vectorizer.pkl"),
    })

    logger.info("Pipeline finished successfully.")


if __name__ == "__main__":
    run_pipeline()
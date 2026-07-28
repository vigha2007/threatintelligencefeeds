"""
ML/train_catboost_notebook.py
==============================
Exact replica of the Google Colab training pipeline:
  ML_Training_CatBoost_70_30 (1).ipynb

Pipeline:
  1. Load 5 CSV files (content, label, source columns only)
  2. Normalize labels using normalize_label()
  3. Drop NaN in content / label / source
  4. Drop exact duplicates on (content, label)
  5. Shuffle with random_state=42
  6. TF-IDF vectorization: max_features=5000, stop_words='english', lowercase=True
  7. Train CatBoostClassifier: iterations=300, depth=8, lr=0.1, 70/30 split
  8. Evaluate and print classification report
  9. Save model → ML/models/catboost_notebook.cbm  (CatBoost native binary)
  10. Save vectorizer → ML/models/tfidf_vectorizer.pkl  (joblib)

Run with:
    .venv\\Scripts\\python.exe ML/train_catboost_notebook.py

Optional flags:
    --fast          Use 50 iterations (quick smoke-test)
    --iterations N  Override iterations
"""

import os
import sys
import gc
import time
import argparse
import numpy as np
import pandas as pd
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, roc_auc_score
from catboost import CatBoostClassifier

# ── Constants (matching notebook exactly) ──────────────────────────────────────
RANDOM_STATE = 42
DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "data"))
MODELS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "models"))

DATASET_FILES = [
    "email_scams.csv",
    "phishing_urls.csv",
    "malicious_ips.csv",
    "suspicious_calls.csv",
    "scam_messages.csv",
]

USECOLS = ["content", "label", "source"]
DTYPES = {"content": "string", "label": "Int64", "source": "string"}


# ── Label normaliser (exact copy from notebook cell 6) ────────────────────────
def normalize_label(val):
    if pd.isna(val):
        return np.nan
    if isinstance(val, (int, np.integer)):
        return 1 if val == 1 else 0
    s = str(val).strip().lower()
    if s in {"1", "malicious", "phishing", "spam", "scam", "bad", "true"}:
        return 1
    if s in {"0", "benign", "ham", "legit", "legitimate", "good", "false"}:
        return 0
    try:
        return 1 if float(s) == 1 else 0
    except ValueError:
        return np.nan


def main(iterations: int = 300):
    os.makedirs(MODELS_DIR, exist_ok=True)

    # ── Step 1: Load CSVs ─────────────────────────────────────────────────────
    print("=" * 70)
    print("STEP 1: Loading datasets")
    print("=" * 70)
    frames = []
    total_rows_loaded = 0
    for fname in DATASET_FILES:
        fpath = os.path.join(DATA_DIR, fname)
        if not os.path.exists(fpath):
            print(f"  [WARN] Missing: {fpath} — skipping")
            continue
        print(f"  Loading {fname} ...")
        df_part = pd.read_csv(
            fpath,
            usecols=USECOLS,
            dtype=DTYPES,
            engine="c",
            low_memory=True,
        )
        frames.append(df_part)
        total_rows_loaded += len(df_part)
        print(f"    -> {len(df_part):,} rows")

    combined_df = pd.concat(frames, axis=0, ignore_index=True)
    del frames
    gc.collect()
    print(f"\nTotal rows loaded: {total_rows_loaded:,}")
    print(f"Combined shape:    {combined_df.shape}")

    # ── Step 2: Preprocessing (exact notebook cell 7) ─────────────────────────
    print("\n" + "=" * 70)
    print("STEP 2: Preprocessing")
    print("=" * 70)
    size_before = len(combined_df)
    print(f"Dataset size BEFORE preprocessing: {size_before:,} rows")

    combined_df["label"] = combined_df["label"].apply(normalize_label)
    combined_df = combined_df.dropna(subset=["content", "label", "source"])
    combined_df = combined_df.drop_duplicates(subset=["content", "label"], keep="first")
    combined_df["label"] = combined_df["label"].astype(np.int8)
    combined_df = combined_df[["content", "label", "source"]].reset_index(drop=True)
    combined_df = combined_df.sample(frac=1.0, random_state=RANDOM_STATE).reset_index(drop=True)

    size_after = len(combined_df)
    print(f"Dataset size AFTER preprocessing:  {size_after:,} rows")
    print(f"Rows removed (duplicates/missing): {size_before - size_after:,}")
    print(f"\nLabel distribution:\n{combined_df['label'].value_counts()}")

    # ── Step 3: TF-IDF (exact notebook cell 8) ────────────────────────────────
    print("\n" + "=" * 70)
    print("STEP 3: TF-IDF vectorization")
    print("=" * 70)
    tfidf_vectorizer = TfidfVectorizer(
        max_features=5000,
        stop_words="english",
        lowercase=True,
        dtype=np.float32,
    )
    print("Fitting TF-IDF vectorizer on full corpus...")
    t0 = time.time()
    X = tfidf_vectorizer.fit_transform(combined_df["content"])
    t1 = time.time()
    y = combined_df["label"].to_numpy(dtype=np.int8)
    print(f"TF-IDF fit+transform time: {t1 - t0:.2f}s")
    print(f"Feature matrix shape: {X.shape}")
    gc.collect()

    # ── Step 4: Train/test split (70:30, exact notebook cell 9) ───────────────
    print("\n" + "=" * 70)
    print(f"SPLIT: 70:30  (test_size=0.30)")
    print("=" * 70)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.30,
        shuffle=True,
        stratify=y,
        random_state=RANDOM_STATE,
    )
    print(f"Train: {X_train.shape[0]:,} rows | Test: {X_test.shape[0]:,} rows")

    # ── Step 5: CatBoost training (exact notebook cell 9) ─────────────────────
    print("\n" + "=" * 70)
    print("STEP 5: Training CatBoostClassifier")
    print("=" * 70)
    cat_model = CatBoostClassifier(
        iterations=iterations,
        depth=8,
        learning_rate=0.1,
        loss_function="Logloss",
        eval_metric="AUC",
        verbose=100,
        random_state=RANDOM_STATE,
    )

    t0 = time.time()
    cat_model.fit(X_train, y_train)
    train_time = time.time() - t0

    # ── Step 6: Evaluate ──────────────────────────────────────────────────────
    t0 = time.time()
    y_pred = cat_model.predict(X_test).astype(int).ravel()
    y_proba = cat_model.predict_proba(X_test)[:, 1]
    test_time = time.time() - t0

    print(f"\n[CatBoost] train={train_time:.2f}s | test={test_time:.2f}s")
    print(classification_report(y_test, y_pred, target_names=["Benign", "Malicious"]))
    acc = accuracy_score(y_test, y_pred)
    auc = roc_auc_score(y_test, y_proba)
    print(f"Accuracy: {acc:.4f} | ROC-AUC: {auc:.4f}")

    # ── Step 7: Save model (native CatBoost binary — no ONNX needed) ──────────
    print("\n" + "=" * 70)
    print("STEP 7: Saving artifacts")
    print("=" * 70)
    model_path = os.path.join(MODELS_DIR, "catboost_notebook.cbm")
    cat_model.save_model(model_path)
    print(f"Saved model:      {model_path}  ({os.path.getsize(model_path)/1024:.1f} KB)")

    vec_path = os.path.join(MODELS_DIR, "tfidf_vectorizer.pkl")
    joblib.dump(tfidf_vectorizer, vec_path)
    print(f"Saved vectorizer: {vec_path}  ({os.path.getsize(vec_path)/1024:.1f} KB)")

    print("\nTraining complete.")
    print("=" * 70)
    print("Update Flask API to load:")
    print(f"  model:      ML/models/catboost_notebook.cbm")
    print(f"  vectorizer: ML/models/tfidf_vectorizer.pkl")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train CatBoost model (notebook pipeline)")
    parser.add_argument("--fast", action="store_true", help="Use 50 iterations for quick testing")
    parser.add_argument("--iterations", type=int, default=300, help="Number of CatBoost iterations")
    args = parser.parse_args()

    n_iter = 50 if args.fast else args.iterations
    if args.fast:
        print(f"[INFO] FAST MODE: using {n_iter} iterations instead of 300")
    main(iterations=n_iter)

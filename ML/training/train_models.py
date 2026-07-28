import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

import os
import time
import math
import joblib
import socket
import numpy as np
import pandas as pd
from urllib.parse import urlparse

from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix

# Algorithms
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import MultinomialNB, GaussianNB
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import SVC, LinearSVC
from sklearn.tree import DecisionTreeClassifier
from xgboost import XGBClassifier

# Handle LightGBM if supported
try:
    from lightgbm import LGBMClassifier
    LIGHTGBM_SUPPORTED = True
except ImportError:
    LIGHTGBM_SUPPORTED = False

DATA_DIR = "ML/data"
MODELS_DIR = "ML/models"
REPORTS_DIR = "ML/reports"
os.makedirs(MODELS_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

MAX_SAMPLES = 5000

def sample_df(df, max_samples=MAX_SAMPLES):
    if len(df) <= max_samples:
        return df
    try:
        from sklearn.model_selection import train_test_split
        _, sampled = train_test_split(df, test_size=max_samples, stratify=df["label"], random_state=42)
        return sampled.reset_index(drop=True)
    except Exception:
        return df.sample(n=max_samples, random_state=42).reset_index(drop=True)

# --- Feature Extraction Helpers ---

def get_entropy(text):
    if not text:
        return 0.0
    text_len = len(text)
    counts = {}
    for c in text:
        counts[c] = counts.get(c, 0) + 1
    entropy = 0.0
    for count in counts.values():
        p = count / text_len
        entropy -= p * math.log2(p)
    return entropy

def extract_url_features(url):
    url = str(url).strip()
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    
    url_len = len(url)
    dots_count = url.count('.')
    digits_count = sum(c.isdigit() for c in url)
    special_count = sum(c in ";/?:@=&+$,-_.!~*'()#" for c in url)
    is_https = 1 if scheme == "https" else 0
    subdomains_count = max(0, netloc.count('.') - 1)
    entropy = get_entropy(url)
    
    return [url_len, dots_count, digits_count, special_count, is_https, subdomains_count, entropy]

def extract_ip_features(ip):
    ip = str(ip).strip()
    is_ipv6 = 0
    is_ipv4 = 0
    ip_int = 0
    
    try:
        socket.inet_pton(socket.AF_INET, ip)
        is_ipv4 = 1
        parts = ip.split('.')
        ip_int = (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])
    except socket.error:
        try:
            socket.inet_pton(socket.AF_INET6, ip)
            is_ipv6 = 1
            ip_int = hash(ip) & 0xffffffff
        except socket.error:
            pass
            
    is_private = 0
    if is_ipv4:
        parts = [int(p) for p in ip.split('.')]
        if parts[0] == 10:
            is_private = 1
        elif parts[0] == 172 and 16 <= parts[1] <= 31:
            is_private = 1
        elif parts[0] == 192 and parts[1] == 168:
            is_private = 1
            
    blacklist_indicator = 0
    return [is_private, is_ipv4, is_ipv6, ip_int, blacklist_indicator]

# --- Training Pipeline ---

def evaluate_splits(X, y, clf, name):
    splits = [(0.2, "80:20"), (0.3, "70:30"), (0.4, "60:40")]
    split_results = {}
    
    for test_size, ratio_name in splits:
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=test_size, random_state=42, stratify=y)
        
        t0 = time.time()
        clf.fit(X_train, y_train)
        train_time = time.time() - t0
        
        t1 = time.time()
        y_pred = clf.predict(X_test)
        test_time = time.time() - t1
        
        # Check predict_proba support for ROC AUC
        if hasattr(clf, "predict_proba"):
            y_prob = clf.predict_proba(X_test)[:, 1]
        elif hasattr(clf, "decision_function"):
            y_prob = clf.decision_function(X_test)
        else:
            y_prob = y_pred
            
        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, zero_division=0)
        rec = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)
        try:
            auc = roc_auc_score(y_test, y_prob)
        except Exception:
            auc = 0.5
            
        cm = confusion_matrix(y_test, y_pred)
        tn, fp, fn, tp = cm.ravel()
        
        split_results[ratio_name] = {
            "accuracy": acc,
            "precision": prec,
            "recall": rec,
            "f1_score": f1,
            "roc_auc": auc,
            "train_time": train_time,
            "test_time": test_time,
            "fp": fp,
            "fn": fn,
            "tp": tp,
            "tn": tn
        }
    return split_results

def tune_hyperparameters(X, y, clf, param_grid):
    # Perform GridSearch on 80:20 train set
    X_train, _, y_train, _ = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    grid = GridSearchCV(clf, param_grid, cv=3, scoring="accuracy", n_jobs=-1)
    grid.fit(X_train, y_train)
    return grid.best_estimator_, grid.best_params_

def select_best_model(results):
    # Selection priority:
    # 1. Highest Accuracy
    # 2. Highest F1 Score
    # 3. Lowest False Positives
    # 4. Lowest False Negatives
    best_name = None
    best_metrics = None
    best_clf = None
    
    for name, data in results.items():
        metrics = data["split_results"]["80:20"] # Evaluate based on 80:20 split
        clf = data["model"]
        
        if best_metrics is None:
            best_name = name
            best_metrics = metrics
            best_clf = clf
            continue
            
        # Comparison logic
        if metrics["accuracy"] > best_metrics["accuracy"]:
            better = True
        elif metrics["accuracy"] == best_metrics["accuracy"]:
            if metrics["f1_score"] > best_metrics["f1_score"]:
                better = True
            elif metrics["f1_score"] == best_metrics["f1_score"]:
                if metrics["fp"] < best_metrics["fp"]:
                    better = True
                elif metrics["fp"] == best_metrics["fp"]:
                    if metrics["fn"] < best_metrics["fn"]:
                        better = True
                    else:
                        better = False
                else:
                    better = False
            else:
                better = False
        else:
            better = False
            
        if better:
            best_name = name
            best_metrics = metrics
            best_clf = clf
            
    return best_name, best_clf, best_metrics

# --- Train Categories ---

def run_sms_pipeline():
    print("\n--- Training SMS Models ---")
    df = pd.read_csv(os.path.join(DATA_DIR, "scam_messages.csv"))
    df = sample_df(df)
    X_text = df["content"].values
    y = df["label"].values
    
    print("Fitting TF-IDF Vectorizer (Unigrams & Bigrams)...")
    vectorizer = TfidfVectorizer(ngram_range=(1, 2), max_features=5000)
    X = vectorizer.fit_transform(X_text)
    
    models = {
        "Logistic Regression": LogisticRegression(max_iter=1000),
        "Multinomial Naive Bayes": MultinomialNB(),
        "Random Forest": RandomForestClassifier(random_state=42),
        "Linear SVM": LinearSVC(max_iter=2000, random_state=42)
    }
    
    param_grids = {
        "Logistic Regression": {"C": [0.1, 1.0, 10.0]},
        "Multinomial Naive Bayes": {"alpha": [0.1, 0.5, 1.0]},
        "Random Forest": {"n_estimators": [50, 100], "max_depth": [10, 20, None]},
        "Linear SVM": {"C": [0.1, 1.0, 5.0]}
    }
    
    results = {}
    for name, clf in models.items():
        print(f"Evaluating {name}...")
        split_results = evaluate_splits(X, y, clf, name)
        
        # CV scores
        cv_5 = cross_val_score(clf, X, y, cv=5, scoring="accuracy", n_jobs=-1)
        cv_10 = cross_val_score(clf, X, y, cv=10, scoring="accuracy", n_jobs=-1)
        
        # Hyperparameter tuning (comparison)
        print(f"Tuning {name}...")
        best_clf, best_params = tune_hyperparameters(X, y, clf, param_grids[name])
        tuned_split_results = evaluate_splits(X, y, best_clf, name)
        
        results[name] = {
            "model": best_clf,
            "best_params": best_params,
            "split_results": split_results,
            "tuned_split_results": tuned_split_results,
            "cv_5_mean": cv_5.mean(),
            "cv_5_std": cv_5.std(),
            "cv_10_mean": cv_10.mean(),
            "cv_10_std": cv_10.std()
        }
        
    best_name, best_clf, best_metrics = select_best_model(results)
    print(f"Best SMS model selected: {best_name} (Acc: {best_metrics['accuracy']:.4f})")
    
    # Save best model and vectorizer
    joblib.dump(best_clf, os.path.join(MODELS_DIR, "message_model.pkl"))
    joblib.dump(vectorizer, os.path.join(MODELS_DIR, "tfidf_sms.pkl"))
    print("Saved message_model.pkl and tfidf_sms.pkl")
    return "SMS", results, best_name

def run_email_pipeline():
    print("\n--- Training Email Models ---")
    df = pd.read_csv(os.path.join(DATA_DIR, "email_scams.csv"))
    df = sample_df(df)
    X_text = df["content"].values
    y = df["label"].values
    
    print("Fitting TF-IDF Vectorizer (Unigrams & Bigrams)...")
    vectorizer = TfidfVectorizer(ngram_range=(1, 2), max_features=5000)
    X = vectorizer.fit_transform(X_text)
    
    models = {
        "Logistic Regression": LogisticRegression(max_iter=1000),
        "Linear SVM": LinearSVC(random_state=42),
        "Random Forest": RandomForestClassifier(random_state=42),
        "Gradient Boosting": GradientBoostingClassifier(random_state=42)
    }
    
    param_grids = {
        "Logistic Regression": {"C": [0.1, 1.0, 10.0]},
        "Linear SVM": {"C": [0.1, 1.0, 5.0]},
        "Random Forest": {"n_estimators": [50, 100], "max_depth": [10, 20, None]},
        "Gradient Boosting": {"n_estimators": [50, 100], "learning_rate": [0.05, 0.1]}
    }
    
    results = {}
    for name, clf in models.items():
        print(f"Evaluating {name}...")
        split_results = evaluate_splits(X, y, clf, name)
        
        cv_5 = cross_val_score(clf, X, y, cv=5, scoring="accuracy", n_jobs=-1)
        cv_10 = cross_val_score(clf, X, y, cv=10, scoring="accuracy", n_jobs=-1)
        
        print(f"Tuning {name}...")
        best_clf, best_params = tune_hyperparameters(X, y, clf, param_grids[name])
        tuned_split_results = evaluate_splits(X, y, best_clf, name)
        
        results[name] = {
            "model": best_clf,
            "best_params": best_params,
            "split_results": split_results,
            "tuned_split_results": tuned_split_results,
            "cv_5_mean": cv_5.mean(),
            "cv_5_std": cv_5.std(),
            "cv_10_mean": cv_10.mean(),
            "cv_10_std": cv_10.std()
        }
        
    best_name, best_clf, best_metrics = select_best_model(results)
    print(f"Best Email model selected: {best_name} (Acc: {best_metrics['accuracy']:.4f})")
    
    joblib.dump(best_clf, os.path.join(MODELS_DIR, "email_model.pkl"))
    joblib.dump(vectorizer, os.path.join(MODELS_DIR, "tfidf_email.pkl"))
    print("Saved email_model.pkl and tfidf_email.pkl")
    return "EMAIL", results, best_name

def run_url_pipeline():
    print("\n--- Training URL Models ---")
    df = pd.read_csv(os.path.join(DATA_DIR, "phishing_urls.csv"))
    df = sample_df(df)
    
    print("Extracting lexical features...")
    X_features = np.array([extract_url_features(url) for url in df["content"].values])
    y = df["label"].values
    
    # Scale URL features
    scaler = StandardScaler()
    X = scaler.fit_transform(X_features)
    
    models = {
        "Random Forest": RandomForestClassifier(random_state=42),
        "XGBoost": XGBClassifier(eval_metric="logloss", random_state=42),
        "Gradient Boosting": GradientBoostingClassifier(random_state=42),
        "Decision Tree": DecisionTreeClassifier(random_state=42)
    }
    
    param_grids = {
        "Random Forest": {"n_estimators": [50, 100], "max_depth": [5, 10, None]},
        "XGBoost": {"n_estimators": [50, 100], "max_depth": [3, 6], "learning_rate": [0.05, 0.1]},
        "Gradient Boosting": {"n_estimators": [50, 100], "learning_rate": [0.05, 0.1]},
        "Decision Tree": {"max_depth": [5, 10, None], "min_samples_split": [2, 5]}
    }
    
    results = {}
    for name, clf in models.items():
        print(f"Evaluating {name}...")
        split_results = evaluate_splits(X, y, clf, name)
        
        cv_5 = cross_val_score(clf, X, y, cv=5, scoring="accuracy", n_jobs=-1)
        cv_10 = cross_val_score(clf, X, y, cv=10, scoring="accuracy", n_jobs=-1)
        
        print(f"Tuning {name}...")
        best_clf, best_params = tune_hyperparameters(X, y, clf, param_grids[name])
        tuned_split_results = evaluate_splits(X, y, best_clf, name)
        
        results[name] = {
            "model": best_clf,
            "best_params": best_params,
            "split_results": split_results,
            "tuned_split_results": tuned_split_results,
            "cv_5_mean": cv_5.mean(),
            "cv_5_std": cv_5.std(),
            "cv_10_mean": cv_10.mean(),
            "cv_10_std": cv_10.std()
        }
        
    best_name, best_clf, best_metrics = select_best_model(results)
    print(f"Best URL model selected: {best_name} (Acc: {best_metrics['accuracy']:.4f})")
    
    # Save URL model and scaler (packaged together or separate)
    joblib.dump(best_clf, os.path.join(MODELS_DIR, "url_model.pkl"))
    joblib.dump(scaler, os.path.join(MODELS_DIR, "scaler_url.pkl"))
    print("Saved url_model.pkl and scaler_url.pkl")
    return "URL", results, best_name

def run_ip_pipeline():
    print("\n--- Training IP Models ---")
    df = pd.read_csv(os.path.join(DATA_DIR, "malicious_ips.csv"))
    df = sample_df(df)
    
    print("Extracting IP network features...")
    X_features = np.array([extract_ip_features(ip) for ip in df["content"].values])
    y = df["label"].values
    
    # Scale IP features
    scaler = StandardScaler()
    X = scaler.fit_transform(X_features)
    
    models = {
        "Random Forest": RandomForestClassifier(random_state=42),
        "Decision Tree": DecisionTreeClassifier(random_state=42),
        "XGBoost": XGBClassifier(eval_metric="logloss", random_state=42)
    }
    
    param_grids = {
        "Random Forest": {"n_estimators": [50, 100], "max_depth": [5, 10, None]},
        "Decision Tree": {"max_depth": [5, 10, None], "min_samples_split": [2, 5]},
        "XGBoost": {"n_estimators": [50, 100], "max_depth": [3, 6]}
    }
    
    if LIGHTGBM_SUPPORTED:
        models["LightGBM"] = LGBMClassifier(random_state=42)
        param_grids["LightGBM"] = {"n_estimators": [50, 100], "learning_rate": [0.05, 0.1]}
        
    results = {}
    for name, clf in models.items():
        print(f"Evaluating {name}...")
        split_results = evaluate_splits(X, y, clf, name)
        
        cv_5 = cross_val_score(clf, X, y, cv=5, scoring="accuracy", n_jobs=-1)
        cv_10 = cross_val_score(clf, X, y, cv=10, scoring="accuracy", n_jobs=-1)
        
        print(f"Tuning {name}...")
        best_clf, best_params = tune_hyperparameters(X, y, clf, param_grids[name])
        tuned_split_results = evaluate_splits(X, y, best_clf, name)
        
        results[name] = {
            "model": best_clf,
            "best_params": best_params,
            "split_results": split_results,
            "tuned_split_results": tuned_split_results,
            "cv_5_mean": cv_5.mean(),
            "cv_5_std": cv_5.std(),
            "cv_10_mean": cv_10.mean(),
            "cv_10_std": cv_10.std()
        }
        
    best_name, best_clf, best_metrics = select_best_model(results)
    print(f"Best IP model selected: {best_name} (Acc: {best_metrics['accuracy']:.4f})")
    
    # Save IP model and scaler
    joblib.dump(best_clf, os.path.join(MODELS_DIR, "ip_model.pkl"))
    joblib.dump(scaler, os.path.join(MODELS_DIR, "scaler_ip.pkl"))
    print("Saved ip_model.pkl and scaler_ip.pkl")
    return "IP", results, best_name

def run_call_pipeline():
    print("\n--- Training Call Models ---")
    df = pd.read_csv(os.path.join(DATA_DIR, "suspicious_calls.csv"))
    df = sample_df(df)
    X_text = df["content"].values
    y = df["label"].values
    
    print("Fitting TF-IDF Vectorizer (Unigrams & Bigrams)...")
    vectorizer = TfidfVectorizer(ngram_range=(1, 2), max_features=5000)
    X = vectorizer.fit_transform(X_text)
    
    models = {
        "Logistic Regression": LogisticRegression(max_iter=1000),
        "Naive Bayes": MultinomialNB(),
        "Random Forest": RandomForestClassifier(random_state=42),
        "Linear SVM": LinearSVC(max_iter=2000, random_state=42)
    }
    
    param_grids = {
        "Logistic Regression": {"C": [0.1, 1.0, 10.0]},
        "Naive Bayes": {"alpha": [0.1, 0.5, 1.0]},
        "Random Forest": {"n_estimators": [50, 100], "max_depth": [10, 20, None]},
        "Linear SVM": {"C": [0.1, 1.0, 5.0]}
    }
    
    results = {}
    for name, clf in models.items():
        print(f"Evaluating {name}...")
        split_results = evaluate_splits(X, y, clf, name)
        
        cv_5 = cross_val_score(clf, X, y, cv=5, scoring="accuracy", n_jobs=-1)
        cv_10 = cross_val_score(clf, X, y, cv=10, scoring="accuracy", n_jobs=-1)
        
        print(f"Tuning {name}...")
        best_clf, best_params = tune_hyperparameters(X, y, clf, param_grids[name])
        tuned_split_results = evaluate_splits(X, y, best_clf, name)
        
        results[name] = {
            "model": best_clf,
            "best_params": best_params,
            "split_results": split_results,
            "tuned_split_results": tuned_split_results,
            "cv_5_mean": cv_5.mean(),
            "cv_5_std": cv_5.std(),
            "cv_10_mean": cv_10.mean(),
            "cv_10_std": cv_10.std()
        }
        
    best_name, best_clf, best_metrics = select_best_model(results)
    print(f"Best Call model selected: {best_name} (Acc: {best_metrics['accuracy']:.4f})")
    
    joblib.dump(best_clf, os.path.join(MODELS_DIR, "call_model.pkl"))
    joblib.dump(vectorizer, os.path.join(MODELS_DIR, "tfidf_call.pkl"))
    print("Saved call_model.pkl and tfidf_call.pkl")
    return "CALL", results, best_name

# --- Report Generation ---

def generate_reports(all_results):
    print("\nGenerating Model Comparison Reports...")
    
    report_content = "# Model Redesign Comparison Report\n\n"
    report_content += "This report summarizes the performance evaluation and cross-validation metrics across all redesigned modules and algorithms.\n\n"
    
    for category, data in all_results.items():
        results = data["results"]
        winner = data["winner"]
        
        report_content += f"## {category} Threat Model Selection\n"
        report_content += f"**Winning Model:** {winner}\n\n"
        report_content += "| Algorithm | Split Ratio | Accuracy | Precision | Recall | F1 Score | ROC AUC | 5-Fold Mean CV | 10-Fold Mean CV | Train Time (s) | Test Time (s) | False Positives | False Negatives |\n"
        report_content += "|---|---|---|---|---|---|---|---|---|---|---|---|---|\n"
        
        for name, metrics_data in results.items():
            best_params = metrics_data["best_params"]
            
            # Print splits
            for split_name in ["80:20", "70:30", "60:40"]:
                res = metrics_data["split_results"][split_name]
                cv_5_mean = metrics_data["cv_5_mean"]
                cv_10_mean = metrics_data["cv_10_mean"]
                
                report_content += f"| {name} | {split_name} | {res['accuracy']:.4f} | {res['precision']:.4f} | {res['recall']:.4f} | {res['f1_score']:.4f} | {res['roc_auc']:.4f} | {cv_5_mean:.4f} | {cv_10_mean:.4f} | {res['train_time']:.4f} | {res['test_time']:.4f} | {res['fp']} | {res['fn']} |\n"
            
        report_content += "\n"
        
    with open(os.path.join(REPORTS_DIR, "model_comparison.md"), "w") as f:
        f.write(report_content)
        
    print("Successfully wrote reports/model_comparison.md")

if __name__ == "__main__":
    pipelines = [
        run_sms_pipeline,
        run_email_pipeline,
        run_url_pipeline,
        run_ip_pipeline,
        run_call_pipeline
    ]
    
    all_results = {}
    for pipe in pipelines:
        cat, res, winner = pipe()
        all_results[cat] = {"results": res, "winner": winner}
        
    generate_reports(all_results)

"""
ML/scripts/run_5domain_ieee_experiments.py
===========================================
Executes a multi-model comparison experiment across ALL 5 Threat Domains:
  1. Scam Messages (SMS)
  2. Email Scams
  3. Phishing URLs
  4. Malicious IPs
  5. Suspicious Calls

Models Evaluated per Domain (SVM excluded):
  1. Logistic Regression
  2. Naive Bayes
  3. Decision Tree
  4. Random Forest
  5. Gradient Boosting
  6. LightGBM
  7. XGBoost
  8. CatBoost
"""

import os
import re
import sys
import time
import json
import warnings
import numpy as np
import pandas as pd
import mysql.connector
import scipy.sparse as sp

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import MinMaxScaler
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
)

# Models
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import MultinomialNB, GaussianNB
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
import lightgbm as lgb
from xgboost import XGBClassifier
from catboost import CatBoostClassifier

warnings.filterwarnings("ignore")

RANDOM_STATE = 42
TEST_SIZE = 0.20

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ML_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
REPORTS_DIR = os.path.join(ML_DIR, "reports")
EVAL_DIR = os.path.join(ML_DIR, "evaluation")
os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(EVAL_DIR, exist_ok=True)

REPORT_MD_PATH = os.path.join(REPORTS_DIR, "ieee_model_comparison_tables.md")
JSON_RESULTS_PATH = os.path.join(EVAL_DIR, "five_domain_comparison_results.json")


def get_db_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="vigha@2007",
        database="threat_intelligence_db",
    )


# ── Feature Extractors ──────────────────────────────────────────────────────

SUSPICIOUS_TLDS = {'ru', 'xyz', 'fit', 'tk', 'info', 'top', 'ga', 'cf', 'gq', 'ml', 'cc', 'click', 'vip', 'work', 'tokyo', 'agency', 'best', 'support', 'secure', 'loan'}
SUSPICIOUS_URL_KEYWORDS = {'login', 'verify', 'update', 'secure', 'bank', 'account', 'signin', 'webscr', 'cmd', 'admin', 'portal', 'free', 'bonus', 'prize', 'claim', 'paypal', 'wallet', 'crypto', 'reset', 'password', 'confirm'}

def extract_url_lexical(urls):
    feats = []
    for u in urls:
        u_str = str(u).lower().strip()
        l = len(u_str)
        num_dots = u_str.count('.')
        num_slashes = u_str.count('/')
        num_hyphens = u_str.count('-')
        num_digits = sum(c.isdigit() for c in u_str)
        digit_ratio = num_digits / max(l, 1)
        has_at = 1.0 if '@' in u_str else 0.0
        has_ip = 1.0 if bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', u_str)) else 0.0
        is_https = 1.0 if u_str.startswith('https') else 0.0
        has_suspicious_tld = 1.0 if any(tld in u_str for tld in SUSPICIOUS_TLDS) else 0.0
        has_suspicious_kw = 1.0 if any(kw in u_str for kw in SUSPICIOUS_URL_KEYWORDS) else 0.0
        feats.append([l, num_dots, num_slashes, num_hyphens, num_digits, digit_ratio, has_at, has_ip, is_https, has_suspicious_tld, has_suspicious_kw])
    return np.array(feats, dtype=np.float32)

def extract_ip_features(ips):
    feats = []
    for ip in ips:
        ip_str = str(ip).strip()
        parts = ip_str.split('.')
        if len(parts) == 4 and all(p.isdigit() for p in parts):
            o1, o2, o3, o4 = [int(p) for p in parts]
        else:
            o1, o2, o3, o4 = 0, 0, 0, 0
        ip_int = (o1 << 24) | (o2 << 16) | (o3 << 8) | o4
        is_priv = 1.0 if (o1 == 10) or (o1 == 172 and 16 <= o2 <= 31) or (o1 == 192 and o2 == 168) or (o1 == 127) else 0.0
        oct_std = float(np.std([o1, o2, o3, o4]))
        oct_range = float(max(o1, o2, o3, o4) - min(o1, o2, o3, o4))
        oct_sum = float(o1 + o2 + o3 + o4)
        feats.append([o1/255.0, o2/255.0, o3/255.0, o4/255.0, ip_int / 4294967295.0, is_priv, oct_std, oct_range, oct_sum])
    return np.array(feats, dtype=np.float32)

def extract_call_features(rows):
    feats = []
    for num, pat in rows:
        num_str = re.sub(r'[^0-9]', '', str(num or ''))
        pat_str = str(pat or '').lower()
        l = len(num_str)
        is_10digit = 1.0 if l == 10 else 0.0
        is_india_mobile = 1.0 if (l == 10 and num_str and num_str[0] in '6789') or (l == 12 and num_str.startswith('91') and num_str[2] in '6789') else 0.0
        repeats = max([num_str.count(c) for c in set(num_str)]) / max(l, 1) if num_str else 0.0
        has_robocall = 1.0 if 'robocall' in pat_str or 'unwanted' in pat_str else 0.0
        has_telemarketer = 1.0 if 'telemarketer' in pat_str or 'prerecorded' in pat_str else 0.0
        has_scam_keyword = 1.0 if any(w in pat_str for w in ['irs', 'arrest', 'card', 'bank', 'lottery', 'winner', 'loan', 'refund', 'urgent', 'police']) else 0.0
        feats.append([l, is_10digit, is_india_mobile, repeats, has_robocall, has_telemarketer, has_scam_keyword])
    return np.array(feats, dtype=np.float32)


def get_candidate_models(domain_type: str, is_dense: bool = False):
    nb = GaussianNB() if is_dense else MultinomialNB(alpha=1.0)
    return {
        "Logistic Regression": LogisticRegression(C=1.0, max_iter=1000, random_state=RANDOM_STATE),
        "Naive Bayes": nb,
        "Decision Tree": DecisionTreeClassifier(max_depth=15, random_state=RANDOM_STATE),
        "Random Forest": RandomForestClassifier(n_estimators=100, max_depth=15, random_state=RANDOM_STATE, n_jobs=-1),
        "Gradient Boosting": GradientBoostingClassifier(n_estimators=60, max_depth=4, learning_rate=0.1, random_state=RANDOM_STATE),
        "LightGBM": lgb.LGBMClassifier(n_estimators=100, max_depth=6, learning_rate=0.1, random_state=RANDOM_STATE, n_jobs=-1, verbose=-1),
        "XGBoost": XGBClassifier(n_estimators=100, max_depth=6, learning_rate=0.1, random_state=RANDOM_STATE, n_jobs=-1, eval_metric="logloss"),
        "CatBoost": CatBoostClassifier(iterations=100, depth=6, learning_rate=0.1, random_seed=RANDOM_STATE, verbose=0),
    }


def evaluate_domain(domain_name, X, y, is_dense=False):
    print(f"\n================================================================================")
    print(f"  EVALUATING DOMAIN: {domain_name} (Total: {len(y):,}, Malicious: {(y==1).sum():,}, Benign: {(y==0).sum():,})")
    print(f"================================================================================")
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, stratify=y, random_state=RANDOM_STATE
    )
    
    models = get_candidate_models(domain_name, is_dense=is_dense)
    domain_results = []
    
    for name, model in models.items():
        t0 = time.time()
        # Ensure correct matrix format
        if is_dense and sp.issparse(X_train):
            X_tr = X_train.toarray()
            X_te = X_test.toarray()
        else:
            X_tr = X_train
            X_te = X_test
            
        model.fit(X_tr, y_train)
        t_train = round(time.time() - t0, 4)
        
        t0_pred = time.time()
        y_pred = model.predict(X_te)
        t_pred = round(time.time() - t0_pred, 4)
        
        if hasattr(model, "predict_proba"):
            y_proba = model.predict_proba(X_te)[:, 1]
        elif hasattr(model, "decision_function"):
            y_proba = model.decision_function(X_te)
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
            "Domain": domain_name,
            "Model": name,
            "Accuracy": round(acc * 100, 2),
            "Precision": round(prec * 100, 2),
            "Recall": round(rec * 100, 2),
            "F1-Score": round(f1 * 100, 2),
            "ROC-AUC": round(roc * 100, 2),
            "Training Time (s)": t_train,
            "Inference Time (s)": t_pred,
            "TP": tp,
            "TN": tn,
            "FP": fp,
            "FN": fn,
        }
        domain_results.append(row)
        print(f"  [{name:19s}] Acc: {acc*100:6.2f}% | Prec: {prec*100:6.2f}% | Rec: {rec*100:6.2f}% | F1: {f1*100:6.2f}% | AUC: {roc*100:6.2f}% | Train: {t_train:6.2f}s")
        
    return domain_results, len(y_train), len(y_test)


def main():
    conn = get_db_connection()
    all_experiments = {}
    
    # ── 1. Scam Messages (SMS) ────────────────────────────────────────────────
    df_sms = pd.read_sql("SELECT content, severity FROM scam_messages WHERE content IS NOT NULL", conn)
    df_sms["content"] = df_sms["content"].astype(str).str.strip()
    df_sms = df_sms[df_sms["content"].str.len() > 2].reset_index(drop=True)
    df_sms["label"] = df_sms["severity"].apply(lambda s: 1 if str(s).lower() in ("high", "critical", "medium") else 0)
    
    tfidf_sms = TfidfVectorizer(max_features=4000, ngram_range=(1, 2), sublinear_tf=True, stop_words="english")
    X_sms = tfidf_sms.fit_transform(df_sms["content"])
    y_sms = df_sms["label"].values
    res_sms, tr_sms, te_sms = evaluate_domain("Scam Messages (SMS)", X_sms, y_sms, is_dense=False)
    all_experiments["sms"] = {"results": res_sms, "train_count": tr_sms, "test_count": te_sms, "features": "TF-IDF (4,000 Unigrams+Bigrams)"}
    
    # ── 2. Email Scams ────────────────────────────────────────────────────────
    df_email = pd.read_sql("SELECT subject, severity FROM email_scams WHERE subject IS NOT NULL", conn)
    df_email["subject"] = df_email["subject"].astype(str).str.strip()
    df_email = df_email[df_email["subject"].str.len() > 2].reset_index(drop=True)
    df_email["label"] = df_email["severity"].apply(lambda s: 1 if str(s).lower() in ("high", "critical", "medium") else 0)
    
    tfidf_email = TfidfVectorizer(max_features=4000, ngram_range=(1, 2), sublinear_tf=True, stop_words="english")
    X_email = tfidf_email.fit_transform(df_email["subject"])
    y_email = df_email["label"].values
    res_email, tr_email, te_email = evaluate_domain("Email Scams", X_email, y_email, is_dense=False)
    all_experiments["email"] = {"results": res_email, "train_count": tr_email, "test_count": te_email, "features": "TF-IDF (4,000 Unigrams+Bigrams)"}
    
    # ── 3. Phishing URLs ──────────────────────────────────────────────────────
    df_url = pd.read_sql("SELECT url, severity FROM phishing_urls WHERE url IS NOT NULL", conn)
    df_url["url"] = df_url["url"].astype(str).str.strip()
    df_url = df_url[df_url["url"].str.len() > 2].reset_index(drop=True)
    df_url["label"] = df_url["severity"].apply(lambda s: 1 if str(s).lower() in ("high", "critical", "medium") else 0)
    if len(df_url) > 50000:
        df_url, _ = train_test_split(df_url, train_size=50000, stratify=df_url["label"], random_state=RANDOM_STATE)
        df_url = df_url.reset_index(drop=True)
        
    tfidf_url = TfidfVectorizer(max_features=2500, analyzer="char", ngram_range=(3, 5))
    X_url_char = tfidf_url.fit_transform(df_url["url"])
    X_url_lex = extract_url_lexical(df_url["url"])
    scaler_url = MinMaxScaler() # Strictly non-negative [0, 1]
    X_url_lex_scaled = sp.csr_matrix(scaler_url.fit_transform(X_url_lex))
    X_url = sp.hstack([X_url_char, X_url_lex_scaled]).tocsr()
    y_url = df_url["label"].values
    res_url, tr_url, te_url = evaluate_domain("Phishing URLs", X_url, y_url, is_dense=False)
    all_experiments["url"] = {"results": res_url, "train_count": tr_url, "test_count": te_url, "features": "Char n-grams (3-5) + 11 Scaled Lexical Features"}
    
    # ── 4. Malicious IPs ──────────────────────────────────────────────────────
    df_ip = pd.read_sql("SELECT ip_address, severity FROM malicious_ips WHERE ip_address IS NOT NULL", conn)
    df_ip["ip_address"] = df_ip["ip_address"].astype(str).str.strip()
    df_ip["label"] = df_ip["severity"].apply(lambda s: 1 if str(s).lower() in ("high", "critical", "medium") else 0)
    if len(df_ip) > 50000:
        df_ip, _ = train_test_split(df_ip, train_size=50000, stratify=df_ip["label"], random_state=RANDOM_STATE)
        df_ip = df_ip.reset_index(drop=True)
        
    X_ip = extract_ip_features(df_ip["ip_address"])
    y_ip = df_ip["label"].values
    res_ip, tr_ip, te_ip = evaluate_domain("Malicious IPs", X_ip, y_ip, is_dense=True)
    all_experiments["ip"] = {"results": res_ip, "train_count": tr_ip, "test_count": te_ip, "features": "9 Statistical & Numerical Octet Features"}
    
    # ── 5. Suspicious Calls ───────────────────────────────────────────────────
    df_call = pd.read_sql("SELECT phone_number, pattern, severity FROM suspicious_calls WHERE phone_number IS NOT NULL", conn)
    df_call["label"] = df_call["severity"].apply(lambda s: 1 if str(s).lower() in ("high", "critical", "medium") else 0)
    if len(df_call) > 50000:
        df_call, _ = train_test_split(df_call, train_size=50000, stratify=df_call["label"], random_state=RANDOM_STATE)
        df_call = df_call.reset_index(drop=True)
        
    call_pairs = list(zip(df_call["phone_number"], df_call["pattern"]))
    X_call = extract_call_features(call_pairs)
    y_call = df_call["label"].values
    res_call, tr_call, te_call = evaluate_domain("Suspicious Calls", X_call, y_call, is_dense=True)
    all_experiments["call"] = {"results": res_call, "train_count": tr_call, "test_count": te_call, "features": "7 Telecom Pattern & Keyword Features"}
    
    conn.close()
    
    # ── Save JSON ─────────────────────────────────────────────────────────────
    with open(JSON_RESULTS_PATH, "w", encoding="utf-8") as f:
        json.dump(all_experiments, f, indent=4)
    print(f"\nSaved raw JSON to {JSON_RESULTS_PATH}")
    
    # ── Generate IEEE Markdown Tables Document ────────────────────────────────
    md = []
    md.append("# IEEE Performance Comparison: 5-Domain Threat Intelligence Models\n")
    md.append("> **Experimental Environment:** Python 3.11, Scikit-Learn, LightGBM, XGBoost, CatBoost. Stratified 80:20 Train-Test Splits. SVM & DistilBERT strictly excluded.\n\n---\n")
    
    # Table 1: SMS
    md.append("## TABLE I. MODEL PERFORMANCE COMPARISON FOR SCAM MESSAGES (SMS) THREAT DETECTION\n")
    md.append(f"* **Dataset Size:** {len(df_sms):,} samples (Train: {tr_sms:,}, Test: {te_sms:,})\n")
    md.append(f"* **Feature Representation:** {all_experiments['sms']['features']}\n\n")
    md.append("| Model | Accuracy (%) | Precision (%) | Recall (%) | F1-Score (%) | ROC-AUC (%) | Training Time (s) |\n")
    md.append("|:---|:---:|:---:|:---:|:---:|:---:|:---:|\n")
    for r in res_sms:
        md.append(f"| **{r['Model']}** | {r['Accuracy']:.2f} | {r['Precision']:.2f} | {r['Recall']:.2f} | {r['F1-Score']:.2f} | {r['ROC-AUC']:.2f} | {r['Training Time (s)']:.3f} |\n")
    md.append("\n---\n")
    
    # Table 2: Email
    md.append("## TABLE II. MODEL PERFORMANCE COMPARISON FOR EMAIL SCAM THREAT DETECTION\n")
    md.append(f"* **Dataset Size:** {len(df_email):,} samples (Train: {tr_email:,}, Test: {te_email:,})\n")
    md.append(f"* **Feature Representation:** {all_experiments['email']['features']}\n\n")
    md.append("| Model | Accuracy (%) | Precision (%) | Recall (%) | F1-Score (%) | ROC-AUC (%) | Training Time (s) |\n")
    md.append("|:---|:---:|:---:|:---:|:---:|:---:|:---:|\n")
    for r in res_email:
        md.append(f"| **{r['Model']}** | {r['Accuracy']:.2f} | {r['Precision']:.2f} | {r['Recall']:.2f} | {r['F1-Score']:.2f} | {r['ROC-AUC']:.2f} | {r['Training Time (s)']:.3f} |\n")
    md.append("\n---\n")

    # Table 3: URL
    md.append("## TABLE III. MODEL PERFORMANCE COMPARISON FOR PHISHING URL THREAT DETECTION\n")
    md.append(f"* **Dataset Size:** {len(df_url):,} benchmark samples (Train: {tr_url:,}, Test: {te_url:,})\n")
    md.append(f"* **Feature Representation:** {all_experiments['url']['features']}\n\n")
    md.append("| Model | Accuracy (%) | Precision (%) | Recall (%) | F1-Score (%) | ROC-AUC (%) | Training Time (s) |\n")
    md.append("|:---|:---:|:---:|:---:|:---:|:---:|:---:|\n")
    for r in res_url:
        md.append(f"| **{r['Model']}** | {r['Accuracy']:.2f} | {r['Precision']:.2f} | {r['Recall']:.2f} | {r['F1-Score']:.2f} | {r['ROC-AUC']:.2f} | {r['Training Time (s)']:.3f} |\n")
    md.append("\n---\n")

    # Table 4: IP
    md.append("## TABLE IV. MODEL PERFORMANCE COMPARISON FOR MALICIOUS IP THREAT DETECTION\n")
    md.append(f"* **Dataset Size:** {len(df_ip):,} benchmark samples (Train: {tr_ip:,}, Test: {te_ip:,})\n")
    md.append(f"* **Feature Representation:** {all_experiments['ip']['features']}\n\n")
    md.append("| Model | Accuracy (%) | Precision (%) | Recall (%) | F1-Score (%) | ROC-AUC (%) | Training Time (s) |\n")
    md.append("|:---|:---:|:---:|:---:|:---:|:---:|:---:|\n")
    for r in res_ip:
        md.append(f"| **{r['Model']}** | {r['Accuracy']:.2f} | {r['Precision']:.2f} | {r['Recall']:.2f} | {r['F1-Score']:.2f} | {r['ROC-AUC']:.2f} | {r['Training Time (s)']:.3f} |\n")
    md.append("\n---\n")

    # Table 5: Calls
    md.append("## TABLE V. MODEL PERFORMANCE COMPARISON FOR SUSPICIOUS CALLS THREAT DETECTION\n")
    md.append(f"* **Dataset Size:** {len(df_call):,} benchmark samples (Train: {tr_call:,}, Test: {te_call:,})\n")
    md.append(f"* **Feature Representation:** {all_experiments['call']['features']}\n\n")
    md.append("| Model | Accuracy (%) | Precision (%) | Recall (%) | F1-Score (%) | ROC-AUC (%) | Training Time (s) |\n")
    md.append("|:---|:---:|:---:|:---:|:---:|:---:|:---:|\n")
    for r in res_call:
        md.append(f"| **{r['Model']}** | {r['Accuracy']:.2f} | {r['Precision']:.2f} | {r['Recall']:.2f} | {r['F1-Score']:.2f} | {r['ROC-AUC']:.2f} | {r['Training Time (s)']:.3f} |\n")
    md.append("\n---\n")

    # Final Proposed System Table
    # Identify best models from the experiment
    best_sms = max(res_sms, key=lambda x: x["F1-Score"])
    best_email = max(res_email, key=lambda x: x["F1-Score"])
    best_url = max(res_url, key=lambda x: x["F1-Score"])
    best_ip = max(res_ip, key=lambda x: x["F1-Score"])
    best_call = max(res_call, key=lambda x: x["F1-Score"])

    md.append("## TABLE VI. SUMMARY OF PROPOSED MULTI-DOMAIN THREAT INTELLIGENCE SYSTEM\n")
    md.append("| Threat Domain | Model Selected for Proposed System | Accuracy (%) | Precision (%) | Recall (%) | F1-Score (%) | ROC-AUC (%) |\n")
    md.append("|:---|:---|:---:|:---:|:---:|:---:|:---:|\n")
    md.append(f"| **Scam Messages (SMS)** | **{best_sms['Model']}** | {best_sms['Accuracy']:.2f} | {best_sms['Precision']:.2f} | {best_sms['Recall']:.2f} | {best_sms['F1-Score']:.2f} | {best_sms['ROC-AUC']:.2f} |\n")
    md.append(f"| **Email Scams** | **{best_email['Model']}** | {best_email['Accuracy']:.2f} | {best_email['Precision']:.2f} | {best_email['Recall']:.2f} | {best_email['F1-Score']:.2f} | {best_email['ROC-AUC']:.2f} |\n")
    md.append(f"| **Phishing URLs** | **{best_url['Model']}** | {best_url['Accuracy']:.2f} | {best_url['Precision']:.2f} | {best_url['Recall']:.2f} | {best_url['F1-Score']:.2f} | {best_url['ROC-AUC']:.2f} |\n")
    md.append(f"| **Malicious IPs** | **{best_ip['Model']}** | {best_ip['Accuracy']:.2f} | {best_ip['Precision']:.2f} | {best_ip['Recall']:.2f} | {best_ip['F1-Score']:.2f} | {best_ip['ROC-AUC']:.2f} |\n")
    md.append(f"| **Suspicious Calls** | **{best_call['Model']}** | {best_call['Accuracy']:.2f} | {best_call['Precision']:.2f} | {best_call['Recall']:.2f} | {best_call['F1-Score']:.2f} | {best_call['ROC-AUC']:.2f} |\n")
    
    with open(REPORT_MD_PATH, "w", encoding="utf-8") as f:
        f.write("".join(md))
        
    print(f"\nSuccessfully generated IEEE comparison document at: {REPORT_MD_PATH}")

if __name__ == "__main__":
    main()

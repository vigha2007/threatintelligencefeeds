import os
import re
import time
import json
import random
import numpy as np
import pandas as pd
import tldextract
import scipy.sparse as sp
from sklearn.preprocessing import StandardScaler
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score

from xgboost import XGBClassifier
from catboost import CatBoostClassifier

# --- Suspicious indicators for URL and text features ---
SUSPICIOUS_TLDS = {
    'ru', 'xyz', 'fit', 'tk', 'info', 'top', 'ga', 'cf', 'gq', 'ml', 'cc',
    'click', 'vip', 'work', 'tokyo', 'agency', 'best', 'support', 'secure',
    'country', 'science', 'gdn', 'stream', 'club', 'date', 'faith', 'loan'
}

SUSPICIOUS_URL_KEYWORDS = {
    'login', 'verify', 'update', 'secure', 'bank', 'account', 'signin',
    'webscr', 'cmd', 'admin', 'portal', 'free', 'bonus', 'prize', 'claim',
    'ebayisapi', 'paypal', 'wallet', 'crypto', 'reset', 'password', 'confirm'
}

SUSPICIOUS_TEXT_KEYWORDS = {
    'urgent', 'winner', 'free', 'click', 'verify', 'account', 'suspended',
    'prize', 'claim', 'limited', 'congratulations', 'offer', 'selected',
    'reward', 'otp', 'password', 'bank', 'transfer', 'kyc', 'gift', 'coupon',
    'bonus', 'cash', 'security', 'warning', 'locked', 'alert', 'support',
    'update', 'billing', 'card', 'behalf', 'tax', 'refund', 'debt'
}

def extract_lexical_features(data_type: str, content: str) -> list:
    """
    Extract a fixed set of dense numerical features based on data type.
    Returns a list of floats in a guaranteed alphabetical order of feature keys.
    """
    t = str(data_type).lower().strip()
    content = str(content)
    
    # Initialize all possible features to 0.0
    features = {
        "length": 0.0,
        "digit_count": 0.0,
        "digit_ratio": 0.0,
        "uppercase_ratio": 0.0,
        "special_chars_count": 0.0,
        "special_chars_ratio": 0.0,
        
        "url_num_dots": 0.0,
        "url_num_hyphens": 0.0,
        "url_num_slashes": 0.0,
        "url_has_ip": 0.0,
        "url_has_at": 0.0,
        "url_subdomain_len": 0.0,
        "url_domain_len": 0.0,
        "url_is_https": 0.0,
        "url_has_suspicious_tld": 0.0,
        "url_has_suspicious_keyword": 0.0,
        "url_num_params": 0.0,
        "url_has_port": 0.0,
        
        "text_word_count": 0.0,
        "text_avg_word_len": 0.0,
        "text_exclamation_count": 0.0,
        "text_question_count": 0.0,
        "text_has_phone": 0.0,
        "text_has_money": 0.0,
        "text_link_count": 0.0,
        "text_has_email_pattern": 0.0,
        "text_suspicious_keyword_count": 0.0,
        
        "ip_is_valid": 0.0,
        "ip_is_private": 0.0,
        
        "is_type_url": 1.0 if t == "url" else 0.0,
        "is_type_email": 1.0 if t == "email" else 0.0,
        "is_type_sms": 1.0 if t == "sms" else 0.0,
        "is_type_call": 1.0 if t == "call" else 0.0,
        "is_type_ip": 1.0 if t == "ip" else 0.0,
    }
    
    content_len = len(content)
    if content_len > 0:
        features["length"] = float(content_len)
        features["digit_count"] = float(sum(c.isdigit() for c in content))
        features["digit_ratio"] = features["digit_count"] / content_len
        features["uppercase_ratio"] = float(sum(c.isupper() for c in content)) / content_len
        features["special_chars_count"] = float(sum(c in "!#$%^&*()+=[]{}|;<>?,\\" for c in content))
        features["special_chars_ratio"] = features["special_chars_count"] / content_len
        
    if t == "url":
        ext = tldextract.extract(content)
        features["url_num_dots"] = float(content.count("."))
        features["url_num_hyphens"] = float(content.count("-"))
        features["url_num_slashes"] = float(content.count("/"))
        features["url_has_ip"] = 1.0 if re.search(r'\d{1,3}(\.\d{1,3}){3}', content) else 0.0
        features["url_has_at"] = 1.0 if "@" in content else 0.0
        features["url_subdomain_len"] = float(len(ext.subdomain))
        features["url_domain_len"] = float(len(ext.domain))
        features["url_is_https"] = 1.0 if content.startswith("https") else 0.0
        
        tld = ext.suffix.lower()
        features["url_has_suspicious_tld"] = 1.0 if tld in SUSPICIOUS_TLDS else 0.0
        
        content_lower = content.lower()
        features["url_has_suspicious_keyword"] = 1.0 if any(kw in content_lower for kw in SUSPICIOUS_URL_KEYWORDS) else 0.0
        features["url_num_params"] = float(content.count("?") + content.count("&"))
        features["url_has_port"] = 1.0 if re.search(r':\d+', content) else 0.0
        
    elif t in ("email", "sms", "call"):
        words = content.lower().split()
        features["text_word_count"] = float(len(words))
        features["text_avg_word_len"] = np.mean([len(w) for w in words]) if words else 0.0
        features["text_exclamation_count"] = float(content.count("!"))
        features["text_question_count"] = float(content.count("?"))
        features["text_has_phone"] = 1.0 if re.search(r'\+?\d[\d\s\-]{8,}', content) else 0.0
        features["text_has_money"] = 1.0 if re.search(r'[\$£€]\d+', content) else 0.0
        features["text_link_count"] = float(len(re.findall(r'http[s]?://', content)))
        features["text_has_email_pattern"] = 1.0 if re.search(r'[\w\.-]+@[\w\.-]+', content) else 0.0
        features["text_suspicious_keyword_count"] = float(sum(w in SUSPICIOUS_TEXT_KEYWORDS for w in words))
        
    elif t == "ip":
        is_ip = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', content.strip()))
        features["ip_is_valid"] = 1.0 if is_ip else 0.0
        
        if is_ip:
            features["url_has_ip"] = 1.0
            is_private = content.startswith("192.168.") or content.startswith("10.") or content.startswith("172.")
            features["ip_is_private"] = 1.0 if is_private else 0.0

    ordered_keys = sorted(features.keys())
    return [features[k] for k in ordered_keys]

def load_data():
    print("Loading local CSV files from ML/data/...")
    files = {
        "email_scams.csv": "email",
        "malicious_ips.csv": "ip",
        "phishing_urls.csv": "url",
        "scam_messages.csv": "sms",
        "suspicious_calls.csv": "call"
    }
    
    dfs = []
    for filename, t in files.items():
        path = os.path.join("ML/data", filename)
        if not os.path.exists(path):
            print(f"  [WARNING] File {path} not found. Skipping.")
            continue
        df = pd.read_csv(path)
        print(f"  Loaded {path}: {len(df)} rows.")
        df.dropna(subset=["content", "label"], inplace=True)
        df["content"] = df["content"].astype(str).str.strip()
        df = df[df["content"] != ""]
        df["mapped_type"] = t
        df["label"] = df["label"].astype(int)
        # Ensure binary labels
        df["label"] = df["label"].apply(lambda l: 1 if l == 1 else 0)
        dfs.append(df[["content", "mapped_type", "label"]])
        
    comb = pd.concat(dfs, ignore_index=True)
    print(f"Combined raw rows: {len(comb)}")
    comb.drop_duplicates(subset=["content"], inplace=True)
    print(f"Combined deduplicated rows: {len(comb)}")
    print("Class distribution:\n", comb["label"].value_counts(normalize=True))
    
    # Stratified sample to exactly 500,000 rows
    target_samples = min(500000, len(comb))
    print(f"Sampling down to {target_samples} records...")
    df_sample, _ = train_test_split(
        comb, train_size=target_samples, stratify=comb["label"], random_state=42
    )
    df_sample.reset_index(drop=True, inplace=True)
    return df_sample

def main():
    df = load_data()
    
    # Extract lexical features once for all rows to save computational time
    print("Extracting lexical features for all rows (pre-computation)...")
    t0 = time.time()
    X_lex = np.array([extract_lexical_features(t, c) for t, c in zip(df["mapped_type"], df["content"])])
    print(f"Lexical feature extraction completed in {time.time() - t0:.2f} seconds.")
    
    split_ratios = [
        (0.2, "80:20"),
        (0.3, "70:30"),
        (0.4, "60:40")
    ]
    
    results = {}
    
    for test_ratio, label in split_ratios:
        print(f"\n==================================================")
        print(f" Evaluating split ratio {label} ({100-int(test_ratio*100)}:{int(test_ratio*100)})")
        print(f"==================================================")
        
        # 1. Split (using the same random state and stratify on both arrays)
        df_train, df_test, X_lex_train, X_lex_test = train_test_split(
            df, X_lex, test_size=test_ratio, stratify=df["label"], random_state=42
        )
        print(f"Train size: {len(df_train)} | Test size: {len(df_test)}")
        
        # 2. Extract TF-IDF features
        print("Extracting TF-IDF features...")
        vectorizer = TfidfVectorizer(max_features=5000, ngram_range=(1, 2))
        X_tfidf_train = vectorizer.fit_transform(df_train["content"])
        X_tfidf_test = vectorizer.transform(df_test["content"])
        
        # 3. Scale Lexical features
        print("Scaling lexical features...")
        scaler = StandardScaler()
        X_lex_train_scaled = scaler.fit_transform(X_lex_train)
        X_lex_test_scaled = scaler.transform(X_lex_test)
        
        # 4. Combine TF-IDF and Lexical features
        X_train = sp.hstack([X_tfidf_train, X_lex_train_scaled]).tocsr()
        X_test = sp.hstack([X_tfidf_test, X_lex_test_scaled]).tocsr()
        
        y_train = df_train["label"].values
        y_test = df_test["label"].values
        
        results[label] = {}
        
        # 5. Train CatBoost
        print("Training CatBoostClassifier...")
        t0 = time.time()
        cb = CatBoostClassifier(
            iterations=100,
            depth=6,
            learning_rate=0.1,
            thread_count=-1,
            verbose=0,
            random_state=42
        )
        cb.fit(X_train, y_train)
        cb_time = time.time() - t0
        print(f"CatBoost trained in {cb_time:.2f} seconds.")
        
        # 6. Train XGBoost
        print("Training XGBClassifier...")
        t0 = time.time()
        xgb = XGBClassifier(
            n_estimators=100,
            max_depth=6,
            learning_rate=0.1,
            n_jobs=-1,
            eval_metric="logloss",
            random_state=42
        )
        xgb.fit(X_train, y_train)
        xgb_time = time.time() - t0
        print(f"XGBoost trained in {xgb_time:.2f} seconds.")
        
        # 7. Evaluate
        for name, clf in [("CatBoost", cb), ("XGBoost", xgb)]:
            y_pred = clf.predict(X_test)
            y_prob = clf.predict_proba(X_test)[:, 1]
            
            acc = accuracy_score(y_test, y_pred)
            prec = precision_score(y_test, y_pred, zero_division=0)
            rec = recall_score(y_test, y_pred, zero_division=0)
            f1 = f1_score(y_test, y_pred, zero_division=0)
            roc_auc = roc_auc_score(y_test, y_prob)
            
            results[label][name] = {
                "accuracy": acc,
                "precision": prec,
                "recall": rec,
                "f1_score": f1,
                "roc_auc": roc_auc
            }
            
            print(f"[{name}] Acc: {acc:.4%}, Prec: {prec:.4%}, Rec: {rec:.4%}, F1: {f1:.4%}, AUC: {roc_auc:.4%}")
            
    # Save results to file
    out_dir = "ML/evaluation"
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "split_comparison_results.json"), "w") as f:
        json.dump(results, f, indent=4)
        
    print("\nTraining and evaluation finished! Results saved to ML/evaluation/split_comparison_results.json.")

if __name__ == "__main__":
    main()

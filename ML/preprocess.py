import pandas as pd
import numpy as np
import re
import tldextract
import scipy.sparse as sp
from sklearn.preprocessing import StandardScaler
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split

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
    t = data_type.lower().strip()
    
    # Initialize all possible features to 0.0
    features = {
        # Common structural features
        "length": 0.0,
        "digit_count": 0.0,
        "digit_ratio": 0.0,
        "uppercase_ratio": 0.0,
        "special_chars_count": 0.0,
        "special_chars_ratio": 0.0,
        
        # URL-specific lexical features
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
        
        # Text-specific (Email/SMS/Call) features
        "text_word_count": 0.0,
        "text_avg_word_len": 0.0,
        "text_exclamation_count": 0.0,
        "text_question_count": 0.0,
        "text_has_phone": 0.0,
        "text_has_money": 0.0,
        "text_link_count": 0.0,
        "text_has_email_pattern": 0.0,
        "text_suspicious_keyword_count": 0.0,
        
        # IP-specific features
        "ip_is_valid": 0.0,
        "ip_is_private": 0.0,
        
        # Type indicator features (One-hot encoded manually for stability)
        "is_type_url": 1.0 if t == "url" else 0.0,
        "is_type_email": 1.0 if t == "email" else 0.0,
        "is_type_sms": 1.0 if t == "sms" else 0.0,
        "is_type_call": 1.0 if t == "call" else 0.0,
        "is_type_ip": 1.0 if t == "ip" else 0.0,
    }
    
    # Common features calculated for all strings
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

    # Ensure stable ordering of the feature vector
    ordered_keys = sorted(features.keys())
    return [features[k] for k in ordered_keys]

def preprocess_dataset(filepath: str):
    """
    Load and preprocess the threat intelligence dataset.
    Splits data, extracts lexical features, fits scaler/vectorizer on train,
    and returns matrices for model training.
    """
    df = pd.read_csv(filepath)
    df.dropna(subset=["type", "content", "label"], inplace=True)
    df["content"] = df["content"].astype(str).str.strip()
    df["type"] = df["type"].astype(str).str.strip().str.lower()
    df["label"] = df["label"].astype(int)

    print(f"Raw label distribution:\n{df['label'].value_counts()}\n")

    # Split into train and test sets first to avoid leakage
    df_train, df_test = train_test_split(
        df, test_size=0.2, random_state=42, stratify=df["label"]
    )

    print("Extracting lexical features...")
    X_lex_train = np.array([extract_lexical_features(t, c) for t, c in zip(df_train["type"], df_train["content"])])
    X_lex_test = np.array([extract_lexical_features(t, c) for t, c in zip(df_test["type"], df_test["content"])])

    # Scale lexical features
    scaler = StandardScaler()
    X_lex_train_scaled = scaler.fit_transform(X_lex_train)
    X_lex_test_scaled = scaler.transform(X_lex_test)

    # Extract TF-IDF features
    print("Fitting TF-IDF vectorizer...")
    vectorizer = TfidfVectorizer(max_features=5000, ngram_range=(1, 2))
    X_tfidf_train = vectorizer.fit_transform(df_train["content"])
    X_tfidf_test = vectorizer.transform(df_test["content"])

    # Combine sparse TF-IDF and dense scaled lexical features
    X_train = sp.hstack([X_tfidf_train, X_lex_train_scaled]).tocsr()
    X_test = sp.hstack([X_tfidf_test, X_lex_test_scaled]).tocsr()

    y_train = df_train["label"].values
    y_test = df_test["label"].values

    print(f"[OK] Preprocessing completed.")
    print(f"Train matrix shape: {X_train.shape} | Test matrix shape: {X_test.shape}")

    # Return dummy placeholder for FEATURE_COLS/le_type to maintain partial compatibility
    dummy_feature_cols = sorted([
        "length", "digit_count", "digit_ratio", "uppercase_ratio", "special_chars_count", "special_chars_ratio",
        "url_num_dots", "url_num_hyphens", "url_num_slashes", "url_has_ip", "url_has_at", "url_subdomain_len",
        "url_domain_len", "url_is_https", "url_has_suspicious_tld", "url_has_suspicious_keyword", "url_num_params",
        "url_has_port", "text_word_count", "text_avg_word_len", "text_exclamation_count", "text_question_count",
        "text_has_phone", "text_has_money", "text_link_count", "text_has_email_pattern", "text_suspicious_keyword_count",
        "ip_is_valid", "ip_is_private", "is_type_url", "is_type_email", "is_type_sms", "is_type_call", "is_type_ip"
    ])
    
    return X_train, X_test, y_train, y_test, scaler, vectorizer, dummy_feature_cols
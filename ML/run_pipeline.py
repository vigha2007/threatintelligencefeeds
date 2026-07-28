"""
Cyber Threat Intelligence -- Full Data Pipeline
=====================================================
Downloads real Hugging Face datasets, preprocesses them,
and saves 5 final CSV files inside ML/data/.

Run with:
    python ML/run_pipeline.py
"""

import sys
import io

# Force UTF-8 output on Windows to avoid cp1252 encoding errors
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

import os
import re
import datetime
import pandas as pd

# ------------------------------------------------------------------
# Paths
# ------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)

TIMESTAMP = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

print("=" * 65)
print("  CYBER THREAT INTELLIGENCE - DATASET PIPELINE")
print("=" * 65)
print(f"Data directory : {DATA_DIR}")
print(f"Timestamp      : {TIMESTAMP}")
print()


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def load_hf(repo_id, split="train", trust_remote_code=False):
    """Load a Hugging Face dataset and return a pandas DataFrame."""
    from datasets import load_dataset
    ds = load_dataset(repo_id, split=split, trust_remote_code=trust_remote_code)
    return ds.to_pandas()


def standardize(df, content_col, label_col, threat_type, source,
                positive_values=None, positive_label=1):
    """
    Standardize any raw dataframe into the common schema:
      id | content | threat_type | label | source | timestamp

    positive_values : list of raw label values that map to 1 (Threat).
                      If None, the raw column is assumed already 0/1.
    """
    df = df[[content_col, label_col]].copy()
    df = df.rename(columns={content_col: "content", label_col: "label"})
    df = df.dropna(subset=["content", "label"])
    df = df.drop_duplicates(subset=["content"])
    df["content"] = df["content"].astype(str).str.strip()
    df = df[df["content"] != ""]

    if positive_values is not None:
        pv_lower = [str(p).lower() for p in positive_values]
        df["label"] = df["label"].apply(
            lambda v: 1 if str(v).strip().lower() in pv_lower else 0
        )
    else:
        df["label"] = pd.to_numeric(df["label"], errors="coerce").fillna(0).astype(int)
        df["label"] = df["label"].apply(lambda v: 1 if v == positive_label else 0)

    df["threat_type"] = threat_type
    df["source"]      = source
    df["timestamp"]   = TIMESTAMP
    df = df.reset_index(drop=True)
    df.insert(0, "id", range(1, len(df) + 1))
    return df[["id", "content", "threat_type", "label", "source", "timestamp"]]


def save_and_report(df, filename, category_name):
    path = os.path.join(DATA_DIR, filename)
    df.to_csv(path, index=False, encoding="utf-8")
    threat_count = int(df["label"].sum())
    safe_count   = len(df) - threat_count
    size_kb      = os.path.getsize(path) / 1024

    print()
    print(f"[SAVED]  {path}")
    print(f"  Category : {category_name}")
    print(f"  Rows     : {len(df)}")
    print(f"  Columns  : {len(df.columns)}  ->  {list(df.columns)}")
    print(f"  Threat=1 : {threat_count}   |   Safe=0 : {safe_count}")
    print(f"  Size     : {size_kb:.1f} KB")
    print()
    print("  First 10 rows:")
    print(df.head(10).to_string(index=False))
    print()
    return path


# ==================================================================
# 1.  SCAM MESSAGES  (SMS)
# ==================================================================
print("-" * 65)
print("[1/5] SCAM MESSAGES  (SMS)")
print("-" * 65)

sms_path = None
for repo, content_col, label_col, positive_values in [
    ("ucirvine/sms_spam",  "sms",     "label",  [1, "spam"]),
    ("oderinlo/sms-spam",  "message", "label",  [1, "spam"]),
]:
    try:
        print(f"  Trying: {repo}")
        raw = load_hf(repo)
        print(f"  Columns found: {list(raw.columns)}")
        df_sms = standardize(raw, content_col, label_col,
                             "SMS_SCAM", repo, positive_values=positive_values)
        sms_path = save_and_report(df_sms, "scam_messages.csv", "Scam Messages")
        break
    except Exception as e:
        print(f"  FAILED ({repo}): {e}")

if not sms_path:
    print("  All SMS sources failed -- using synthetic fallback.")
    rows = [
        {"content": "WINNER!! Claim your prize now call 09061703589",      "label": 1},
        {"content": "Free entry 2 win FA Cup final tkts txt CUP 87121",    "label": 1},
        {"content": "You have won a 1000 cash prize Text WIN to 80085",    "label": 1},
        {"content": "Urgent! Mobile awarded $2000 prize. Call now.",       "label": 1},
        {"content": "Congratulations! You have been selected for free iPhone.", "label": 1},
        {"content": "Hey, are you coming to the meeting today?",           "label": 0},
        {"content": "Can you pick up milk on your way home?",              "label": 0},
        {"content": "The project deadline has been extended to Friday.",   "label": 0},
        {"content": "See you at the gym tomorrow morning.",                "label": 0},
        {"content": "Happy birthday! Hope you have a great day.",          "label": 0},
    ]
    df_sms = pd.DataFrame(rows)
    df_sms["threat_type"] = "SMS_SCAM"
    df_sms["source"]      = "synthetic"
    df_sms["timestamp"]   = TIMESTAMP
    df_sms.insert(0, "id", range(1, len(df_sms) + 1))
    sms_path = save_and_report(df_sms, "scam_messages.csv", "Scam Messages")


# ==================================================================
# 2.  EMAIL SCAMS
# ==================================================================
print("-" * 65)
print("[2/5] EMAIL SCAMS")
print("-" * 65)

email_path = None
for repo, content_col, label_col, positive_values in [
    ("mshenoda/spam-email",  "Message", "Category", ["spam"]),
    ("dmnkfr/email-spam",    "text",    "label",    [1, "spam"]),
    ("wangrongsheng/emailspam", "text", "label",    [1, "spam"]),
]:
    try:
        print(f"  Trying: {repo}")
        raw = load_hf(repo)
        print(f"  Columns found: {list(raw.columns)}")
        df_email = standardize(raw, content_col, label_col,
                               "EMAIL_SCAM", repo, positive_values=positive_values)
        email_path = save_and_report(df_email, "email_scams.csv", "Email Scams")
        break
    except Exception as e:
        print(f"  FAILED ({repo}): {e}")

if not email_path:
    print("  All email sources failed -- deriving from SMS dataset.")
    df_email = df_sms.copy()
    df_email["threat_type"] = "EMAIL_SCAM"
    df_email["id"] = range(1, len(df_email) + 1)
    email_path = save_and_report(df_email, "email_scams.csv", "Email Scams")


# ==================================================================
# 3.  PHISHING URLs
# ==================================================================
print("-" * 65)
print("[3/5] PHISHING URLs")
print("-" * 65)

url_path = None
for repo, content_col, label_col, positive_values in [
    ("shawonashraf/phishing-urls",  "url",    "label",  [1, "bad", "phishing"]),
    ("pirocheto/phishing-url",      "url",    "status", [1, "phishing", "bad"]),
    ("Kei93/phishing-url-dataset",  "url",    "label",  [1, "phishing"]),
]:
    try:
        print(f"  Trying: {repo}")
        raw = load_hf(repo)
        print(f"  Columns found: {list(raw.columns)}")
        df_url = standardize(raw, content_col, label_col,
                             "PHISHING_URL", repo, positive_values=positive_values)
        url_path = save_and_report(df_url, "phishing_urls.csv", "Phishing URLs")
        break
    except Exception as e:
        print(f"  FAILED ({repo}): {e}")

if not url_path:
    print("  All URL sources failed -- using synthetic fallback.")
    rows = [
        {"content": "http://paypal-security-update.com/login",       "label": 1},
        {"content": "http://amazon-prize-winner.net/claim",           "label": 1},
        {"content": "http://bankofamerica-alert.cc/verify",           "label": 1},
        {"content": "http://apple-id-disabled.ru/restore",           "label": 1},
        {"content": "http://microsoft-support-help.xyz/fix",         "label": 1},
        {"content": "https://www.google.com",                        "label": 0},
        {"content": "https://www.github.com",                        "label": 0},
        {"content": "https://www.stackoverflow.com",                 "label": 0},
        {"content": "https://www.wikipedia.org",                     "label": 0},
        {"content": "https://www.python.org",                        "label": 0},
    ]
    df_url = pd.DataFrame(rows)
    df_url["threat_type"] = "PHISHING_URL"
    df_url["source"]      = "synthetic"
    df_url["timestamp"]   = TIMESTAMP
    df_url.insert(0, "id", range(1, len(df_url) + 1))
    url_path = save_and_report(df_url, "phishing_urls.csv", "Phishing URLs")


# ==================================================================
# 4.  MALICIOUS IPs
# ==================================================================
print("-" * 65)
print("[4/5] MALICIOUS IPs")
print("-" * 65)

ip_path = None

def looks_like_ip(val):
    return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", str(val).strip()))

for repo, content_col, label_col, positive_values in [
    ("swaption2009/cyber-threat-intelligence-custom-data", "content", "label", [1, "malicious"]),
    ("AYI-NEDJIMI/threat-intelligence",                    "ip",      "label", [1, "malicious"]),
]:
    try:
        print(f"  Trying: {repo}")
        raw = load_hf(repo, trust_remote_code=True)
        print(f"  Columns found: {list(raw.columns)}")

        # Auto-detect IP address column
        ip_col = content_col
        for col in raw.columns:
            if col.lower() in ["ip", "ip_address", "address", "src_ip", "source_ip", "content", "value"]:
                sample = raw[col].dropna().head(20).astype(str).tolist()
                if any(looks_like_ip(v) for v in sample):
                    ip_col = col
                    break

        lbl_col = label_col
        for col in raw.columns:
            if col.lower() in ["label", "type", "class", "category", "malicious", "is_malicious", "threat"]:
                lbl_col = col
                break

        df_ip = standardize(raw, ip_col, lbl_col, "MALICIOUS_IP", repo,
                            positive_values=positive_values)
        ip_path = save_and_report(df_ip, "malicious_ips.csv", "Malicious IPs")
        break
    except Exception as e:
        print(f"  FAILED ({repo}): {e}")

if not ip_path:
    print("  All IP sources failed -- using synthetic fallback.")
    rows = [
        {"content": "185.220.101.34",   "label": 1},
        {"content": "45.142.212.100",   "label": 1},
        {"content": "194.165.16.77",    "label": 1},
        {"content": "91.108.4.0",       "label": 1},
        {"content": "185.100.87.202",   "label": 1},
        {"content": "198.144.120.18",   "label": 1},
        {"content": "103.224.182.248",  "label": 1},
        {"content": "89.248.167.131",   "label": 1},
        {"content": "8.8.8.8",          "label": 0},
        {"content": "1.1.1.1",          "label": 0},
        {"content": "9.9.9.9",          "label": 0},
        {"content": "208.67.222.222",   "label": 0},
        {"content": "64.6.64.6",        "label": 0},
        {"content": "149.112.112.112",  "label": 0},
    ]
    df_ip = pd.DataFrame(rows)
    df_ip["threat_type"] = "MALICIOUS_IP"
    df_ip["source"]      = "synthetic"
    df_ip["timestamp"]   = TIMESTAMP
    df_ip.insert(0, "id", range(1, len(df_ip) + 1))
    ip_path = save_and_report(df_ip, "malicious_ips.csv", "Malicious IPs")


# ==================================================================
# 5.  SUSPICIOUS CALLS
# ==================================================================
print("-" * 65)
print("[5/5] SUSPICIOUS CALLS")
print("-" * 65)

call_path = None
for repo, content_col, label_col, positive_values in [
    ("BothBosu/scam-dialogue", "dialogue", "label", [1, "scam"]),
]:
    try:
        print(f"  Trying: {repo}")
        raw = load_hf(repo)
        print(f"  Columns found: {list(raw.columns)}")
        df_call = standardize(raw, content_col, label_col,
                              "SUSPICIOUS_CALL", repo, positive_values=positive_values)
        call_path = save_and_report(df_call, "suspicious_calls.csv", "Suspicious Calls")
        break
    except Exception as e:
        print(f"  FAILED ({repo}): {e}")

if not call_path:
    print("  All Call sources failed -- using synthetic fallback.")
    rows = [
        {"content": "This is the IRS. You owe back taxes and will be arrested unless you pay now.", "label": 1},
        {"content": "Your computer has a virus. Press 1 to speak to Microsoft support immediately.", "label": 1},
        {"content": "Congratulations! You have won a free cruise. Press 1 to claim your prize.",    "label": 1},
        {"content": "This is a final warning. Your Social Security number has been suspended.",     "label": 1},
        {"content": "We are calling from your bank. Give us your card number to secure your account.", "label": 1},
        {"content": "You have been selected for a government grant. No repayment required. Call now.", "label": 1},
        {"content": "Your car warranty is about to expire. Press 1 to renew immediately.",          "label": 1},
        {"content": "This is Amazon customer service. Suspicious activity on your account.",        "label": 1},
        {"content": "Your Medicare benefits are expiring. Verify your information today.",          "label": 1},
        {"content": "Unusual login detected on your PayPal account. Call us immediately.",          "label": 1},
        {"content": "Hi, calling to confirm your appointment scheduled for tomorrow at 3 PM.",      "label": 0},
        {"content": "Your prescription is ready for pickup at the pharmacy.",                       "label": 0},
        {"content": "Calling about your recent job application. We want to schedule an interview.", "label": 0},
        {"content": "Your package has been delivered to your front door.",                          "label": 0},
        {"content": "Reminder of your dental cleaning appointment next Monday.",                    "label": 0},
        {"content": "Calling to let you know the plumber will arrive between 2 and 4 PM.",          "label": 0},
        {"content": "Your library book is due for return by this Friday.",                          "label": 0},
        {"content": "School is closed tomorrow due to weather.",                                    "label": 0},
        {"content": "Your order is confirmed and will ship in 1-2 business days.",                  "label": 0},
        {"content": "Calling to confirm your reservation for this Saturday.",                       "label": 0},
    ]
    df_call = pd.DataFrame(rows)
    df_call["threat_type"] = "SUSPICIOUS_CALL"
    df_call["source"]      = "synthetic"
    df_call["timestamp"]   = TIMESTAMP
    df_call.insert(0, "id", range(1, len(df_call) + 1))
    call_path = save_and_report(df_call, "suspicious_calls.csv", "Suspicious Calls")


# ==================================================================
# FINAL VERIFICATION
# ==================================================================
print("=" * 65)
print("  FINAL VERIFICATION")
print("=" * 65)

required_files = {
    "scam_messages.csv":    "Scam Messages",
    "email_scams.csv":      "Email Scams",
    "phishing_urls.csv":    "Phishing URLs",
    "malicious_ips.csv":    "Malicious IPs",
    "suspicious_calls.csv": "Suspicious Calls",
}

all_ok = True
for fname, label in required_files.items():
    fpath = os.path.join(DATA_DIR, fname)
    if os.path.exists(fpath):
        size_kb = os.path.getsize(fpath) / 1024
        with open(fpath, encoding="utf-8") as f:
            rows = sum(1 for _ in f) - 1
        status = "[OK]"
        print(f"  {status}  {fname:<26}  {rows:>6} rows  {size_kb:>7.1f} KB")
        print(f"         {fpath}")
    else:
        print(f"  [MISSING]  {fpath}")
        all_ok = False

print()
if all_ok:
    print("  ALL 5 dataset CSV files created successfully!")
else:
    print("  WARNING: Some files are still missing. Review errors above.")
print("=" * 65)

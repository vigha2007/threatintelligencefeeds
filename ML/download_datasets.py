import os
import urllib.request
import pandas as pd
import numpy as np
import random

EMAIL_DATASET_URL = "https://raw.githubusercontent.com/amankharwal/Email-spam-detection/master/emails.csv"
EMAIL_CSV_PATH = "data/emails.csv"
SMS_CSV_PATH = "data/spam.csv"
URL_CSV_PATH = "data/phishing_site_urls.csv"
FINAL_DATASET_PATH = "data/dataset.csv"

def download_email_dataset():
    """Download the spam email classification dataset and overwrite any existing file."""
    # Force download to replace LFS pointer files
    if os.path.exists(EMAIL_CSV_PATH):
        try:
            os.remove(EMAIL_CSV_PATH)
        except Exception:
            pass

    print("Downloading email spam dataset...")
    try:
        os.makedirs(os.path.dirname(EMAIL_CSV_PATH), exist_ok=True)
        # Use simple urllib to avoid dependencies
        urllib.request.urlretrieve(EMAIL_DATASET_URL, EMAIL_CSV_PATH)
        print("[OK] Email dataset downloaded successfully.")
    except Exception as e:
        print(f"[ERROR] Failed to download email dataset: {e}")
        raise

def generate_synthetic_ips(num_samples=10000):
    """Generate safe and malicious synthetic IP data."""
    print("Generating synthetic IP addresses...")
    random.seed(42)
    np.random.seed(42)
    rows = []
    
    half_samples = num_samples // 2
    
    # 1. Legitimate/Safe IPs (common public DNS, local ranges, well-known subnets)
    safe_templates = [
        "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112",
        "208.67.222.222", "208.67.220.220", "192.168.1.1", "192.168.0.1", "10.0.0.1"
    ]
    for ip in safe_templates:
        rows.append({"type": "ip", "content": ip, "label": 0})
        
    while len(rows) < half_samples:
        # Generate private IP ranges
        if random.random() < 0.5:
            ip = f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}"
        else:
            ip = f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        rows.append({"type": "ip", "content": ip, "label": 0})
        
    # 2. Malicious IPs (random public IPs representing flagged malicious addresses)
    while len(rows) < num_samples:
        first_octet = random.choice([x for x in range(1, 224) if x not in [10, 127, 192, 172]])
        ip = f"{first_octet}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        rows.append({"type": "ip", "content": ip, "label": 1})
        
    return pd.DataFrame(rows)

def prepare_balanced_dataset():
    """Merge, clean, balance, and compile the final threat intelligence dataset."""
    print("Compiling dataset...")
    
    # --- 1. URLs ---
    print("Loading URLs...")
    url_df = pd.read_csv(URL_CSV_PATH, encoding="latin-1")
    url_df = url_df.rename(columns={"URL": "content", "Label": "label"})
    url_df["label"] = url_df["label"].map({"good": 0, "bad": 1, "phishing": 1, "legitimate": 0})
    url_df["type"] = "url"
    url_df = url_df.dropna(subset=["content", "label"])
    
    # Sample balanced URLs
    urls_safe = url_df[url_df["label"] == 0]
    urls_malicious = url_df[url_df["label"] == 1]
    url_sample_size = 25000
    urls_safe_sampled = urls_safe.sample(n=min(len(urls_safe), url_sample_size), random_state=42)
    urls_malicious_sampled = urls_malicious.sample(n=min(len(urls_malicious), url_sample_size), random_state=42)
    url_balanced = pd.concat([urls_safe_sampled, urls_malicious_sampled])
    print(f"   URL samples: {len(url_balanced)} (Safe: {len(urls_safe_sampled)}, Malicious: {len(urls_malicious_sampled)})")
    
    # --- 2. Emails ---
    print("Loading Emails...")
    email_df = pd.read_csv(EMAIL_CSV_PATH)
    # amankharwal emails.csv has columns: 'text' and 'spam'
    email_df = email_df.rename(columns={"text": "content", "spam": "label"})
    email_df["type"] = "email"
    email_df = email_df.dropna(subset=["content", "label"])
    
    # Balance Emails using upsampling if needed
    emails_safe = email_df[email_df["label"] == 0]
    emails_malicious = email_df[email_df["label"] == 1]
    
    # Let's target 10000 total email samples (5000 safe, 5000 malicious)
    email_target_size = 5000
    emails_safe_sampled = emails_safe.sample(n=email_target_size, replace=True if len(emails_safe) < email_target_size else False, random_state=42)
    emails_malicious_sampled = emails_malicious.sample(n=email_target_size, replace=True if len(emails_malicious) < email_target_size else False, random_state=42)
    email_balanced = pd.concat([emails_safe_sampled, emails_malicious_sampled])
    print(f"   Email samples: {len(email_balanced)} (Safe: {len(emails_safe_sampled)}, Malicious: {len(emails_malicious_sampled)})")
    
    # --- 3. SMS ---
    print("Loading SMS...")
    sms_df = pd.read_csv(SMS_CSV_PATH, encoding="latin-1", usecols=["v1", "v2"])
    sms_df = sms_df.rename(columns={"v1": "label", "v2": "content"})
    sms_df["label"] = sms_df["label"].map({"ham": 0, "spam": 1})
    sms_df["type"] = "sms"
    sms_df = sms_df.dropna(subset=["content", "label"])
    
    # Balance SMS using upsampling for malicious
    sms_safe = sms_df[sms_df["label"] == 0]
    sms_malicious = sms_df[sms_df["label"] == 1]
    sms_mal_upsampled = sms_malicious.sample(n=len(sms_safe), replace=True, random_state=42)
    sms_balanced = pd.concat([sms_safe, sms_mal_upsampled])
    print(f"   SMS samples: {len(sms_balanced)} (Safe: {len(sms_safe)}, Malicious: {len(sms_mal_upsampled)})")
    
    # --- 4. Calls ---
    print("Loading Calls (SMS based transcripts)...")
    # Copy SMS dataset but mark as 'call'
    call_balanced = sms_balanced.copy()
    call_balanced["type"] = "call"
    print(f"   Call samples: {len(call_balanced)}")
    
    # --- 5. IPs ---
    ip_balanced = generate_synthetic_ips(num_samples=10000)
    print(f"   IP samples: {len(ip_balanced)} (Safe: 5000, Malicious: 5000)")
    
    # --- Merge and Shuffle ---
    combined = pd.concat([url_balanced, email_balanced, sms_balanced, call_balanced, ip_balanced], ignore_index=True)
    combined["content"] = combined["content"].astype(str).str.strip()
    combined = combined.dropna()
    
    # Shuffle final dataset
    combined = combined.sample(frac=1, random_state=42).reset_index(drop=True)
    
    print(f"\nTotal Compiled Rows: {len(combined)}")
    print(combined.groupby(["type", "label"]).size())
    
    combined.to_csv(FINAL_DATASET_PATH, index=False)
    print(f"\nUnified dataset successfully saved to {FINAL_DATASET_PATH}")

if __name__ == "__main__":
    download_email_dataset()
    prepare_balanced_dataset()

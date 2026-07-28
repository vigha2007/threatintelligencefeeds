"""
build_datasets_and_retrain.py
Builds new malicious_ips.csv and email_scams.csv from real-world public feeds,
then retrains CatBoost and XGBoost with 80:20, 70:30, 60:40 splits.
"""

import os
import re
import json
import time
import socket
import struct
import random
import hashlib
import warnings
import urllib.request
import numpy as np
import pandas as pd
from datetime import datetime, timezone
from collections import defaultdict

warnings.filterwarnings("ignore")

DATA_DIR = "ML/data"
MODELS_DIR = "ML/models"
EVAL_DIR = "ML/evaluation"
NOW_TS = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

# =========================================================
# PHASE 1A: Build malicious_ips.csv
# =========================================================

def fetch_text(url, timeout=30, encoding="utf-8"):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 ThreatIntel/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode(encoding, errors="replace")

IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")

def is_valid_public_ip(ip):
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        nums = [int(p) for p in parts]
    except ValueError:
        return False
    if any(n < 0 or n > 255 for n in nums):
        return False
    # Exclude private, loopback, link-local, multicast
    if nums[0] in (10, 127) or nums[0] >= 224:
        return False
    if nums[0] == 172 and 16 <= nums[1] <= 31:
        return False
    if nums[0] == 192 and nums[1] == 168:
        return False
    if nums[0] == 169 and nums[1] == 254:
        return False
    if nums[0] == 0:
        return False
    return True

def expand_cidr_sample(cidr, max_ips=50):
    """Expand a CIDR block to a sample of IPs."""
    try:
        network, prefix = cidr.split("/")
        prefix = int(prefix)
        packed = struct.unpack("!I", socket.inet_aton(network))[0]
        host_bits = 32 - prefix
        num_hosts = min(2 ** host_bits, max_ips)
        ips = []
        for i in range(1, num_hosts):
            ip_int = (packed & (0xFFFFFFFF << host_bits)) | i
            ip = socket.inet_ntoa(struct.pack("!I", ip_int))
            if is_valid_public_ip(ip):
                ips.append(ip)
            if len(ips) >= max_ips:
                break
        return ips
    except Exception:
        return []

def build_malicious_ips():
    print("\n" + "="*60)
    print("PHASE 1A: Building malicious_ips.csv")
    print("="*60)

    malicious_ips = {}  # ip -> source label
    benign_ips = {}

    # --- Source 1: IPsum (aggregates 30+ blacklists) ---
    print("Downloading IPsum threat feed...")
    try:
        content = fetch_text("https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt")
        for line in content.split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            ip = parts[0].strip()
            if IPV4_RE.match(ip) and is_valid_public_ip(ip):
                malicious_ips[ip] = "stamparm/ipsum"
        print(f"  IPsum: {len(malicious_ips)} malicious IPs loaded")
    except Exception as e:
        print(f"  IPsum WARN: {e}")

    # --- Source 2: EmergingThreats Block List ---
    print("Downloading EmergingThreats block list...")
    try:
        content = fetch_text("https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt")
        count_before = len(malicious_ips)
        for line in content.split("\n"):
            ip = line.strip()
            if IPV4_RE.match(ip) and is_valid_public_ip(ip):
                malicious_ips[ip] = "EmergingThreats"
        print(f"  EmergingThreats: +{len(malicious_ips)-count_before} new IPs")
    except Exception as e:
        print(f"  EmergingThreats WARN: {e}")

    # --- Source 3: FeodoTracker (C2 botnets: Emotet, Dridex, TrickBot) ---
    print("Downloading FeodoTracker C2 IPs...")
    try:
        content = fetch_text("https://feodotracker.abuse.ch/downloads/ipblocklist.txt")
        count_before = len(malicious_ips)
        for line in content.split("\n"):
            ip = line.strip()
            if IPV4_RE.match(ip) and is_valid_public_ip(ip):
                malicious_ips[ip] = "abuse.ch/FeodoTracker"
        print(f"  FeodoTracker: +{len(malicious_ips)-count_before} new IPs")
    except Exception as e:
        print(f"  FeodoTracker WARN: {e}")

    # --- Source 4: Spamhaus DROP (hijacked/rogue blocks) - expand CIDRs ---
    print("Downloading Spamhaus DROP list (CIDR expansion)...")
    try:
        content = fetch_text("https://www.spamhaus.org/drop/drop.txt")
        count_before = len(malicious_ips)
        for line in content.split("\n"):
            line = line.strip()
            if not line or line.startswith(";"):
                continue
            cidr = line.split(";")[0].strip()
            if "/" in cidr:
                sample_ips = expand_cidr_sample(cidr, max_ips=20)
                for ip in sample_ips:
                    malicious_ips[ip] = "Spamhaus/DROP"
        print(f"  Spamhaus DROP: +{len(malicious_ips)-count_before} new IPs")
    except Exception as e:
        print(f"  Spamhaus DROP WARN: {e}")

    # --- Source 5: URLhaus (active malware hosting IPs) ---
    print("Downloading URLhaus active IPs...")
    try:
        content = fetch_text("https://urlhaus.abuse.ch/downloads/text_recent/")
        count_before = len(malicious_ips)
        for line in content.split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Extract IP from URL
            match = re.search(r"https?://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
            if match:
                ip = match.group(1)
                if is_valid_public_ip(ip):
                    malicious_ips[ip] = "abuse.ch/URLhaus"
        print(f"  URLhaus: +{len(malicious_ips)-count_before} new IPs")
    except Exception as e:
        print(f"  URLhaus WARN: {e}")

    total_malicious = len(malicious_ips)
    print(f"\n  Total unique malicious IPs collected: {total_malicious}")

    # --- Build BENIGN IP pool ---
    print("\nBuilding benign IP pool...")
    # Well-known benign IPs
    known_benign = [
        "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
        "9.9.9.9", "149.112.112.112",
        "208.67.222.222", "208.67.220.220",
        "4.2.2.1", "4.2.2.2",
        "64.6.64.6", "64.6.65.6",
        "77.88.8.8", "77.88.8.1",
        "176.103.130.130", "176.103.130.131",
        "185.228.168.168", "185.228.169.168",
        "156.154.70.1", "156.154.71.1",
        "198.101.242.72", "23.253.163.53",
    ]
    for ip in known_benign:
        benign_ips[ip] = "known_benign_dns"

    # CDN and Cloud Provider IPs (well-known public)
    cdn_ranges = [
        ("151.101.0.0", 16, "Fastly CDN"),
        ("104.16.0.0", 12, "Cloudflare"),
        ("13.32.0.0", 15, "AWS CloudFront"),
        ("23.0.0.0", 12, "Akamai CDN"),
        ("66.220.144.0", 20, "Meta/Facebook"),
        ("31.13.0.0", 16, "Meta/Instagram"),
        ("17.0.0.0", 8, "Apple"),
        ("72.21.0.0", 16, "Amazon"),
        ("216.58.192.0", 19, "Google"),
        ("142.250.0.0", 15, "Google"),
        ("52.0.0.0", 8, "AWS"),
        ("35.0.0.0", 8, "Google Cloud"),
    ]
    random.seed(42)
    np.random.seed(42)
    for base_ip, prefix, name in cdn_ranges:
        try:
            packed = struct.unpack("!I", socket.inet_aton(base_ip))[0]
            host_bits = 32 - prefix
            num_hosts = min(2 ** host_bits, 5000)
            sampled = random.sample(range(1, num_hosts), min(300, num_hosts - 1))
            for i in sampled:
                ip_int = (packed & (0xFFFFFFFF << host_bits)) | i
                ip = socket.inet_ntoa(struct.pack("!I", ip_int))
                if ip not in malicious_ips and is_valid_public_ip(ip):
                    benign_ips[ip] = f"CDN/{name}"
                if len(benign_ips) >= 65000:
                    break
        except Exception:
            pass

    # Fill benign pool with random routable IPs
    benign_first_octets = [23, 24, 32, 34, 36, 37, 38, 40, 43, 45, 47,
                           50, 51, 52, 54, 59, 60, 62, 63, 65, 66, 67, 68,
                           69, 70, 71, 72, 74, 75, 76, 79, 80, 81, 82, 83,
                           84, 85, 86, 87, 88, 89, 93, 95, 96, 97, 98, 99]
    attempts = 0
    while len(benign_ips) < 65000 and attempts < 200000:
        attempts += 1
        first = random.choice(benign_first_octets)
        ip = f"{first}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        if ip not in malicious_ips and ip not in benign_ips and is_valid_public_ip(ip):
            benign_ips[ip] = "routable_public"

    print(f"  Total benign IPs: {len(benign_ips)}")

    # --- Build DataFrame ---
    rows = []
    row_id = 1

    for ip, source in malicious_ips.items():
        rows.append({
            "id": row_id,
            "content": ip,
            "label": 1,
            "threat_type": "MALICIOUS_IP",
            "source": source,
            "timestamp": NOW_TS,
        })
        row_id += 1

    for ip, source in benign_ips.items():
        rows.append({
            "id": row_id,
            "content": ip,
            "label": 0,
            "threat_type": "BENIGN_IP",
            "source": source,
            "timestamp": NOW_TS,
        })
        row_id += 1

    df = pd.DataFrame(rows, columns=["id", "content", "label", "threat_type", "source", "timestamp"])
    df = df.drop_duplicates(subset="content").reset_index(drop=True)
    df["id"] = range(1, len(df) + 1)

    out_path = os.path.join(DATA_DIR, "malicious_ips.csv")
    df.to_csv(out_path, index=False)

    print(f"\n  [OK] Saved: {out_path}")
    print(f"  Total records: {len(df)}")
    print(f"  Malicious (label=1): {(df['label']==1).sum()}")
    print(f"  Benign (label=0): {(df['label']==0).sum()}")
    print(f"  Sources:\n{df['source'].value_counts().to_string()}")

    return df


# =========================================================
# PHASE 1B: Build email_scams.csv
# =========================================================

def build_email_scams():
    print("\n" + "="*60)
    print("PHASE 1B: Building email_scams.csv (email-only, no SMS)")
    print("="*60)

    from datasets import load_dataset

    all_rows = []

    # --- Source 1: SetFit/enron_spam (Enron email corpus - REAL emails) ---
    print("Loading SetFit/enron_spam (Enron Emails)...")
    try:
        ds = load_dataset("SetFit/enron_spam", split="train")
        df_enron = ds.to_pandas()
        # Use 'message' (full email body with headers) or 'text' (cleaned)
        text_col = "message" if "message" in df_enron.columns else "text"
        df_enron = df_enron[[text_col, "label"]].copy()
        df_enron.columns = ["content", "label"]
        df_enron["source"] = "SetFit/enron_spam"
        df_enron["label"] = df_enron["label"].astype(int)
        df_enron = df_enron.dropna(subset=["content"]).copy()
        df_enron = df_enron[df_enron["content"].str.strip().str.len() > 10]
        print(f"  Enron: {len(df_enron)} records | spam: {(df_enron['label']==1).sum()} | ham: {(df_enron['label']==0).sum()}")
        all_rows.append(df_enron)
    except Exception as e:
        print(f"  Enron WARN: {e}")

    # Also load test split
    try:
        ds_test = load_dataset("SetFit/enron_spam", split="test")
        df_enron_test = ds_test.to_pandas()
        text_col = "message" if "message" in df_enron_test.columns else "text"
        df_enron_test = df_enron_test[[text_col, "label"]].copy()
        df_enron_test.columns = ["content", "label"]
        df_enron_test["source"] = "SetFit/enron_spam"
        df_enron_test["label"] = df_enron_test["label"].astype(int)
        df_enron_test = df_enron_test.dropna(subset=["content"]).copy()
        df_enron_test = df_enron_test[df_enron_test["content"].str.strip().str.len() > 10]
        print(f"  Enron test: +{len(df_enron_test)} records")
        all_rows.append(df_enron_test)
    except Exception as e:
        print(f"  Enron test WARN: {e}")

    # --- Source 2: Deysi/spam-detection-dataset (email spam) ---
    print("Loading Deysi/spam-detection-dataset...")
    try:
        ds2 = load_dataset("Deysi/spam-detection-dataset", split="train")
        df_deysi = ds2.to_pandas()
        print(f"  Deysi columns: {list(df_deysi.columns)}")
        text_col = "text" if "text" in df_deysi.columns else df_deysi.columns[0]
        label_col = "label" if "label" in df_deysi.columns else df_deysi.columns[1]
        df_deysi = df_deysi[[text_col, label_col]].copy()
        df_deysi.columns = ["content", "label"]
        df_deysi["source"] = "Deysi/spam-detection-dataset"
        df_deysi["label"] = df_deysi["label"].astype(int)
        df_deysi = df_deysi.dropna(subset=["content"])
        # Filter to likely email (longer texts, not SMS)
        df_deysi = df_deysi[df_deysi["content"].str.len() > 50]
        print(f"  Deysi: {len(df_deysi)} records | spam: {(df_deysi['label']==1).sum()} | ham: {(df_deysi['label']==0).sum()}")
        all_rows.append(df_deysi)
    except Exception as e:
        print(f"  Deysi WARN: {e}")

    # --- Source 3: jackhhao/jailbreak-classification (adversarial email-like) ---
    print("Loading jackhhao/jailbreak-classification...")
    try:
        ds3 = load_dataset("jackhhao/jailbreak-classification", split="train")
        df_jb = ds3.to_pandas()
        print(f"  Jailbreak columns: {list(df_jb.columns)}")
        text_col = "prompt" if "prompt" in df_jb.columns else df_jb.columns[0]
        label_col = "type" if "type" in df_jb.columns else df_jb.columns[1]
        df_jb = df_jb[[text_col, label_col]].copy()
        df_jb.columns = ["content", "label_text"]
        # jailbreak=1 (adversarial/malicious), normal=0
        df_jb["label"] = df_jb["label_text"].apply(lambda x: 1 if str(x).lower() in ("jailbreak", "1", "malicious") else 0)
        df_jb["source"] = "jackhhao/jailbreak-classification"
        df_jb = df_jb[["content", "label", "source"]]
        df_jb = df_jb[df_jb["content"].str.len() > 30]
        print(f"  Jailbreak: {len(df_jb)} records")
        all_rows.append(df_jb)
    except Exception as e:
        print(f"  Jailbreak WARN: {e}")

    # --- Source 4: Download SpamAssassin public corpus (tar.bz2) ---
    print("Downloading SpamAssassin public corpus emails...")
    sa_emails = []
    sa_archives = [
        ("https://spamassassin.apache.org/old/publiccorpus/20050311_spam_2.tar.bz2", 1),
        ("https://spamassassin.apache.org/old/publiccorpus/20030228_spam.tar.bz2", 1),
        ("https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2", 0),
        ("https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham_2.tar.bz2", 0),
        ("https://spamassassin.apache.org/old/publiccorpus/20030228_hard_ham.tar.bz2", 0),
    ]
    try:
        import tarfile, io
        for url, lbl in sa_archives:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=60) as r:
                    data = r.read()
                with tarfile.open(fileobj=io.BytesIO(data), mode="r:bz2") as tar:
                    for member in tar.getmembers():
                        if member.isfile() and not member.name.endswith("cmds"):
                            try:
                                f = tar.extractfile(member)
                                if f:
                                    text = f.read().decode("utf-8", errors="replace")
                                    # Take first 2000 chars as content
                                    text = text[:2000].strip()
                                    if len(text) > 50:
                                        sa_emails.append({"content": text, "label": lbl, "source": "SpamAssassin/publiccorpus"})
                            except Exception:
                                pass
                print(f"  SpamAssassin {url.split('/')[-1]}: loaded {sum(1 for e in sa_emails if e['label']==lbl)} emails (label={lbl})")
            except Exception as e:
                print(f"  SpamAssassin archive WARN: {url.split('/')[-1]}: {str(e)[:60]}")

        if sa_emails:
            df_sa = pd.DataFrame(sa_emails)
            print(f"  SpamAssassin total: {len(df_sa)} emails | spam: {(df_sa['label']==1).sum()} | ham: {(df_sa['label']==0).sum()}")
            all_rows.append(df_sa)
    except Exception as e:
        print(f"  SpamAssassin WARN: {e}")

    # --- Combine all sources ---
    print("\nCombining all email sources...")
    df_all = pd.concat(all_rows, ignore_index=True)
    df_all = df_all[["content", "label", "source"]].copy()

    # Deduplicate by content hash
    df_all["_hash"] = df_all["content"].apply(lambda x: hashlib.md5(str(x).encode()).hexdigest())
    df_all = df_all.drop_duplicates(subset="_hash").drop(columns=["_hash"])

    # Add project schema columns
    df_all["threat_type"] = "EMAIL_SCAM"
    df_all["timestamp"] = NOW_TS
    df_all = df_all.reset_index(drop=True)
    df_all.insert(0, "id", range(1, len(df_all) + 1))

    # Final column order
    df_all = df_all[["id", "content", "threat_type", "label", "source", "timestamp"]]

    out_path = os.path.join(DATA_DIR, "email_scams.csv")
    df_all.to_csv(out_path, index=False)

    print(f"\n  [OK] Saved: {out_path}")
    print(f"  Total records: {len(df_all)}")
    print(f"  Spam (label=1): {(df_all['label']==1).sum()}")
    print(f"  Ham (label=0): {(df_all['label']==0).sum()}")
    print(f"  Sources:\n{df_all['source'].value_counts().to_string()}")

    return df_all


# =========================================================
# PHASE 2: Retrain CatBoost + XGBoost
# =========================================================

def extract_ip_features(ip_series):
    """Extract numerical features from IP addresses."""
    records = []
    for ip in ip_series:
        try:
            parts = ip.split(".")
            if len(parts) == 4:
                nums = [int(p) for p in parts]
                o1, o2, o3, o4 = nums
            else:
                o1, o2, o3, o4 = 0, 0, 0, 0
        except Exception:
            o1, o2, o3, o4 = 0, 0, 0, 0

        records.append({
            "octet1": o1,
            "octet2": o2,
            "octet3": o3,
            "octet4": o4,
            "ip_int": (o1 << 24) | (o2 << 16) | (o3 << 8) | o4,
            # Simple entropy proxy
            "octet_range": max(o1, o2, o3, o4) - min(o1, o2, o3, o4),
            "octet_sum": o1 + o2 + o3 + o4,
            "octet_std": float(np.std([o1, o2, o3, o4])),
            "is_private": int((o1 == 10) or (o1 == 172 and 16 <= o2 <= 31) or (o1 == 192 and o2 == 168)),
            "is_loopback": int(o1 == 127),
        })
    return pd.DataFrame(records)

def load_all_datasets():
    """Load and combine all 5 datasets for unified training."""
    print("\nLoading all datasets for unified training...")
    from sklearn.feature_extraction.text import TfidfVectorizer
    import scipy.sparse as sp

    dfs = {}
    for fname in ["email_scams.csv", "malicious_ips.csv", "phishing_urls.csv", "scam_messages.csv", "suspicious_calls.csv"]:
        path = os.path.join(DATA_DIR, fname)
        if os.path.exists(path):
            df = pd.read_csv(path)
            df = df.dropna(subset=["content", "label"])
            df["label"] = df["label"].astype(int)
            # Sample large datasets to keep training tractable
            if len(df) > 150000:
                df = df.sample(n=150000, random_state=42)
            dfs[fname] = df
            print(f"  {fname}: {len(df)} records")

    return dfs

def build_combined_features(dfs):
    """Build a combined feature matrix for all datasets."""
    from sklearn.feature_extraction.text import TfidfVectorizer
    import scipy.sparse as sp
    import joblib

    print("\nBuilding combined feature matrix...")

    # Separate IP data from text data
    ip_df = dfs.get("malicious_ips.csv", pd.DataFrame())
    text_dfs = {k: v for k, v in dfs.items() if k != "malicious_ips.csv"}

    # --- Text features ---
    text_combined = pd.concat(list(text_dfs.values()), ignore_index=True) if text_dfs else pd.DataFrame()
    
    X_list = []
    y_list = []

    if len(text_combined) > 0:
        print(f"  Text records: {len(text_combined)}")
        # TF-IDF on text content
        tfidf = TfidfVectorizer(
            ngram_range=(1, 2),
            max_features=10000,
            strip_accents="unicode",
            analyzer="word",
            token_pattern=r"\b\w+\b",
            max_df=0.95,
            min_df=2,
            sublinear_tf=True,
        )
        X_text = tfidf.fit_transform(text_combined["content"].fillna("").astype(str))
        y_text = text_combined["label"].values
        X_list.append(X_text)
        y_list.append(y_text)

        # Save vectorizer
        joblib.dump(tfidf, os.path.join(MODELS_DIR, "vectorizer.pkl"))
        print(f"  TF-IDF matrix: {X_text.shape}")
    else:
        tfidf = None

    if len(ip_df) > 0:
        print(f"  IP records: {len(ip_df)}")
        ip_features = extract_ip_features(ip_df["content"].fillna("0.0.0.0"))
        y_ip = ip_df["label"].values
        # Pad IP features to match TF-IDF feature width
        if tfidf is not None:
            n_text_features = 10000
            # Pad with zeros
            from scipy.sparse import csr_matrix, hstack
            ip_sparse_base = csr_matrix(ip_features.values.astype(np.float32))
            # Pad to align with text features (TF-IDF has 10000 cols, IP has 10 cols)
            # We'll combine differently: stack IP features in separate array
            X_ip_padded = sp.hstack([
                ip_sparse_base,
                sp.csr_matrix((len(ip_df), n_text_features - ip_features.shape[1]))
            ])
            X_list.append(X_ip_padded)
        else:
            from scipy.sparse import csr_matrix
            X_list.append(csr_matrix(ip_features.values.astype(np.float32)))
        y_list.append(y_ip)

    X_all = sp.vstack(X_list) if len(X_list) > 1 else X_list[0]
    y_all = np.concatenate(y_list)

    # Shuffle
    idx = np.random.permutation(len(y_all))
    X_all = X_all[idx]
    y_all = y_all[idx]

    print(f"  Combined dataset: {X_all.shape[0]} samples, {X_all.shape[1]} features")
    print(f"  Label distribution: 0={np.sum(y_all==0)}, 1={np.sum(y_all==1)}")

    return X_all, y_all


def train_and_evaluate():
    import scipy.sparse as sp
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import (accuracy_score, precision_score,
                                  recall_score, f1_score, roc_auc_score,
                                  confusion_matrix, classification_report)
    import xgboost as xgb
    import catboost as cb
    import joblib
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.colors import LinearSegmentedColormap

    print("\n" + "="*60)
    print("PHASE 2: Training CatBoost + XGBoost")
    print("="*60)

    dfs = load_all_datasets()
    X_all, y_all = build_combined_features(dfs)

    splits = [
        ("80:20", 0.20),
        ("70:30", 0.30),
        ("60:40", 0.40),
    ]

    all_results = {}
    best_models = {}

    for split_name, test_size in splits:
        print(f"\n{'='*50}")
        print(f"  Split: {split_name} (test_size={test_size})")
        print(f"{'='*50}")

        X_train, X_test, y_train, y_test = train_test_split(
            X_all, y_all, test_size=test_size, random_state=42, stratify=y_all
        )
        print(f"  Train: {X_train.shape[0]} | Test: {X_test.shape[0]}")

        split_results = {}

        # --- XGBoost ---
        print(f"\n  Training XGBoost ({split_name})...")
        xgb_model = xgb.XGBClassifier(
            n_estimators=300,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            use_label_encoder=False,
            eval_metric="logloss",
            tree_method="hist",
            random_state=42,
            n_jobs=-1,
        )
        xgb_model.fit(X_train, y_train, verbose=False)
        y_pred_xgb = xgb_model.predict(X_test)
        y_prob_xgb = xgb_model.predict_proba(X_test)[:, 1]

        xgb_metrics = {
            "accuracy": round(accuracy_score(y_test, y_pred_xgb), 6),
            "precision": round(precision_score(y_test, y_pred_xgb, zero_division=0), 6),
            "recall": round(recall_score(y_test, y_pred_xgb, zero_division=0), 6),
            "f1": round(f1_score(y_test, y_pred_xgb, zero_division=0), 6),
            "roc_auc": round(roc_auc_score(y_test, y_prob_xgb), 6),
        }
        split_results["XGBoost"] = xgb_metrics
        print(f"    Accuracy: {xgb_metrics['accuracy']*100:.2f}%  ROC-AUC: {xgb_metrics['roc_auc']*100:.2f}%")

        # --- CatBoost ---
        print(f"\n  Training CatBoost ({split_name})...")
        # Convert sparse to dense for CatBoost if small enough, else use Pool
        cb_model = cb.CatBoostClassifier(
            iterations=300,
            depth=6,
            learning_rate=0.1,
            loss_function="Logloss",
            eval_metric="AUC",
            random_seed=42,
            verbose=0,
            thread_count=-1,
        )
        from catboost import Pool
        train_pool = Pool(X_train, label=y_train)
        test_pool = Pool(X_test, label=y_test)
        cb_model.fit(train_pool, eval_set=test_pool, verbose=False)
        y_pred_cb = cb_model.predict(test_pool)
        y_prob_cb = cb_model.predict_proba(test_pool)[:, 1]

        cb_metrics = {
            "accuracy": round(accuracy_score(y_test, y_pred_cb), 6),
            "precision": round(precision_score(y_test, y_pred_cb, zero_division=0), 6),
            "recall": round(recall_score(y_test, y_pred_cb, zero_division=0), 6),
            "f1": round(f1_score(y_test, y_pred_cb, zero_division=0), 6),
            "roc_auc": round(roc_auc_score(y_test, y_prob_cb), 6),
        }
        split_results["CatBoost"] = cb_metrics
        print(f"    Accuracy: {cb_metrics['accuracy']*100:.2f}%  ROC-AUC: {cb_metrics['roc_auc']*100:.2f}%")

        all_results[split_name] = split_results

        # Save models for the 80:20 split
        if split_name == "80:20":
            joblib.dump(xgb_model, os.path.join(MODELS_DIR, "best_model.pkl"))
            best_models["xgb"] = (xgb_model, X_test, y_test, y_pred_xgb, y_prob_xgb)
            best_models["cb"] = (cb_model, X_test, y_test, y_pred_cb, y_prob_cb)
            best_models["y_test"] = y_test
            print(f"\n  Saved best_model.pkl (XGBoost 80:20)")

    # =========================================================
    # PHASE 3: Regenerate Evaluation Artifacts
    # =========================================================
    print("\n" + "="*60)
    print("PHASE 3: Regenerating Evaluation Artifacts")
    print("="*60)

    os.makedirs(EVAL_DIR, exist_ok=True)

    # --- Clear old artifacts ---
    for f in os.listdir(EVAL_DIR):
        if f.endswith(".png") or (f.endswith(".json") and f != "split_comparison_results.json"):
            try:
                os.remove(os.path.join(EVAL_DIR, f))
            except Exception:
                pass

    # Custom colormap for confusion matrices
    cmap = LinearSegmentedColormap.from_list("threat_cm", ["#0d1117", "#1a2744", "#2563eb", "#60a5fa"])

    for model_key, model_name in [("xgb", "XGBoost"), ("cb", "CatBoost")]:
        model, X_test, y_test, y_pred, y_prob = best_models[model_key]

        # --- Confusion Matrix ---
        cm = confusion_matrix(y_test, y_pred)
        fig, ax = plt.subplots(figsize=(8, 6))
        fig.patch.set_facecolor("#0d1117")
        ax.set_facecolor("#0d1117")
        im = ax.imshow(cm, cmap=cmap)
        ax.set_title(f"{model_name} — Confusion Matrix (80:20 Split)",
                     color="white", fontsize=14, fontweight="bold", pad=15)
        ax.set_xlabel("Predicted Label", color="#94a3b8", fontsize=12)
        ax.set_ylabel("True Label", color="#94a3b8", fontsize=12)
        ax.set_xticks([0, 1])
        ax.set_yticks([0, 1])
        ax.set_xticklabels(["Benign (0)", "Malicious (1)"], color="white")
        ax.set_yticklabels(["Benign (0)", "Malicious (1)"], color="white")
        for i in range(2):
            for j in range(2):
                ax.text(j, i, str(cm[i, j]),
                        ha="center", va="center",
                        color="white", fontsize=18, fontweight="bold")
        plt.colorbar(im, ax=ax)
        plt.tight_layout()
        save_path = os.path.join(EVAL_DIR, f"cm_{model_name.lower()}.png")
        plt.savefig(save_path, dpi=150, bbox_inches="tight", facecolor=fig.get_facecolor())
        plt.close()
        print(f"  Saved: {save_path}")

        # Also save in models dir
        models_cm_path = os.path.join(MODELS_DIR, f"cm_{model_name}.png")
        fig2, ax2 = plt.subplots(figsize=(8, 6))
        fig2.patch.set_facecolor("#0d1117")
        ax2.set_facecolor("#0d1117")
        im2 = ax2.imshow(cm, cmap=cmap)
        ax2.set_title(f"{model_name} — Confusion Matrix", color="white", fontsize=14, fontweight="bold")
        ax2.set_xlabel("Predicted Label", color="#94a3b8")
        ax2.set_ylabel("True Label", color="#94a3b8")
        ax2.set_xticks([0, 1])
        ax2.set_yticks([0, 1])
        ax2.set_xticklabels(["Benign", "Malicious"], color="white")
        ax2.set_yticklabels(["Benign", "Malicious"], color="white")
        for i in range(2):
            for j in range(2):
                ax2.text(j, i, str(cm[i, j]), ha="center", va="center", color="white", fontsize=18, fontweight="bold")
        plt.colorbar(im2, ax=ax2)
        plt.tight_layout()
        plt.savefig(models_cm_path, dpi=150, bbox_inches="tight", facecolor=fig2.get_facecolor())
        plt.close()
        print(f"  Saved: {models_cm_path}")

        # --- ROC Curve ---
        from sklearn.metrics import roc_curve, auc as auc_score
        fpr, tpr, _ = roc_curve(y_test, y_prob)
        roc_auc_val = auc_score(fpr, tpr)
        fig, ax = plt.subplots(figsize=(8, 6))
        fig.patch.set_facecolor("#0d1117")
        ax.set_facecolor("#111827")
        ax.plot(fpr, tpr, color="#3b82f6", lw=2,
                label=f"ROC Curve (AUC = {roc_auc_val:.4f})")
        ax.plot([0, 1], [0, 1], color="#475569", lw=1, linestyle="--", label="Random Classifier")
        ax.fill_between(fpr, tpr, alpha=0.15, color="#3b82f6")
        ax.set_xlim([0.0, 1.0])
        ax.set_ylim([0.0, 1.05])
        ax.set_xlabel("False Positive Rate", color="#94a3b8", fontsize=12)
        ax.set_ylabel("True Positive Rate", color="#94a3b8", fontsize=12)
        ax.set_title(f"{model_name} — ROC Curve (80:20 Split)",
                     color="white", fontsize=14, fontweight="bold")
        ax.tick_params(colors="white")
        ax.spines["bottom"].set_color("#374151")
        ax.spines["left"].set_color("#374151")
        ax.spines["top"].set_color("#374151")
        ax.spines["right"].set_color("#374151")
        legend = ax.legend(fancybox=True, framealpha=0.3, fontsize=11)
        legend.get_frame().set_facecolor("#1e293b")
        for text in legend.get_texts():
            text.set_color("white")
        plt.tight_layout()
        roc_path = os.path.join(EVAL_DIR, f"roc_{model_name.lower()}.png")
        plt.savefig(roc_path, dpi=150, bbox_inches="tight", facecolor=fig.get_facecolor())
        plt.close()
        print(f"  Saved: {roc_path}")

        # --- Precision-Recall Curve ---
        from sklearn.metrics import precision_recall_curve, average_precision_score
        precision_vals, recall_vals, _ = precision_recall_curve(y_test, y_prob)
        avg_prec = average_precision_score(y_test, y_prob)
        fig, ax = plt.subplots(figsize=(8, 6))
        fig.patch.set_facecolor("#0d1117")
        ax.set_facecolor("#111827")
        ax.plot(recall_vals, precision_vals, color="#10b981", lw=2,
                label=f"PR Curve (AP = {avg_prec:.4f})")
        ax.fill_between(recall_vals, precision_vals, alpha=0.15, color="#10b981")
        ax.set_xlabel("Recall", color="#94a3b8", fontsize=12)
        ax.set_ylabel("Precision", color="#94a3b8", fontsize=12)
        ax.set_title(f"{model_name} — Precision-Recall Curve (80:20 Split)",
                     color="white", fontsize=14, fontweight="bold")
        ax.tick_params(colors="white")
        ax.spines["bottom"].set_color("#374151")
        ax.spines["left"].set_color("#374151")
        ax.spines["top"].set_color("#374151")
        ax.spines["right"].set_color("#374151")
        ax.set_xlim([0.0, 1.0])
        ax.set_ylim([0.0, 1.05])
        legend = ax.legend(fancybox=True, framealpha=0.3, fontsize=11)
        legend.get_frame().set_facecolor("#1e293b")
        for text in legend.get_texts():
            text.set_color("white")
        plt.tight_layout()
        pr_path = os.path.join(EVAL_DIR, f"pr_{model_name.lower()}.png")
        plt.savefig(pr_path, dpi=150, bbox_inches="tight", facecolor=fig.get_facecolor())
        plt.close()
        print(f"  Saved: {pr_path}")

        # --- Feature Importance (XGBoost) ---
        if model_key == "xgb":
            try:
                fi = xgb_model.feature_importances_
                top_n = 20
                top_idx = np.argsort(fi)[-top_n:]
                top_vals = fi[top_idx]
                top_labels = [f"Feature {i}" for i in top_idx]

                fig, ax = plt.subplots(figsize=(10, 8))
                fig.patch.set_facecolor("#0d1117")
                ax.set_facecolor("#111827")
                colors = plt.cm.Blues(np.linspace(0.4, 1.0, top_n))
                ax.barh(range(top_n), top_vals, color=colors)
                ax.set_yticks(range(top_n))
                ax.set_yticklabels(top_labels, color="white", fontsize=9)
                ax.set_xlabel("Feature Importance Score", color="#94a3b8")
                ax.set_title("XGBoost — Top 20 Feature Importances",
                             color="white", fontsize=14, fontweight="bold")
                ax.tick_params(colors="white")
                for spine in ax.spines.values():
                    spine.set_color("#374151")
                plt.tight_layout()
                fi_path = os.path.join(EVAL_DIR, "feature_importance_xgboost.png")
                plt.savefig(fi_path, dpi=150, bbox_inches="tight", facecolor=fig.get_facecolor())
                plt.close()
                print(f"  Saved: {fi_path}")
            except Exception as e:
                print(f"  XGBoost FI WARN: {e}")

        # --- Classification Report ---
        report = classification_report(y_test, y_pred, target_names=["Benign", "Malicious"])
        report_path = os.path.join(EVAL_DIR, f"classification_report_{model_name.lower()}.txt")
        with open(report_path, "w") as f:
            f.write(f"{model_name} Classification Report (80:20 Split)\n")
            f.write("="*50 + "\n")
            f.write(report)
        print(f"  Saved: {report_path}")

        # --- Metrics JSON ---
        metrics_80 = all_results["80:20"][model_name]
        metrics_path = os.path.join(EVAL_DIR, f"metrics_{model_name.lower()}.json")
        with open(metrics_path, "w") as f:
            json.dump(metrics_80, f, indent=4)
        print(f"  Saved: {metrics_path}")

    # Feature importance for CatBoost
    try:
        cb_model_obj, _, _, _, _ = best_models["cb"]
        fi_cb = cb_model_obj.get_feature_importance()
        top_n = 20
        top_idx = np.argsort(fi_cb)[-top_n:]
        top_vals = fi_cb[top_idx]
        top_labels = [f"Feature {i}" for i in top_idx]

        fig, ax = plt.subplots(figsize=(10, 8))
        fig.patch.set_facecolor("#0d1117")
        ax.set_facecolor("#111827")
        colors = plt.cm.Greens(np.linspace(0.4, 1.0, top_n))
        ax.barh(range(top_n), top_vals, color=colors)
        ax.set_yticks(range(top_n))
        ax.set_yticklabels(top_labels, color="white", fontsize=9)
        ax.set_xlabel("Feature Importance Score", color="#94a3b8")
        ax.set_title("CatBoost — Top 20 Feature Importances",
                     color="white", fontsize=14, fontweight="bold")
        ax.tick_params(colors="white")
        for spine in ax.spines.values():
            spine.set_color("#374151")
        plt.tight_layout()
        fi_path = os.path.join(EVAL_DIR, "feature_importance_catboost.png")
        plt.savefig(fi_path, dpi=150, bbox_inches="tight", facecolor=fig.get_facecolor())
        plt.close()
        print(f"  Saved: {fi_path}")
    except Exception as e:
        print(f"  CatBoost FI WARN: {e}")

    # --- Save split_comparison_results.json ---
    split_path = os.path.join(EVAL_DIR, "split_comparison_results.json")
    with open(split_path, "w") as f:
        json.dump(all_results, f, indent=4)
    print(f"\n  Saved: {split_path}")

    # --- Save comparison_report.json ---
    comp_report = {
        "CatBoost": all_results["80:20"]["CatBoost"],
        "XGBoost": all_results["80:20"]["XGBoost"],
    }
    comp_path = os.path.join(EVAL_DIR, "comparison_report.json")
    with open(comp_path, "w") as f:
        json.dump(comp_report, f, indent=4)
    print(f"  Saved: {comp_path}")

    # =========================================================
    # PHASE 4: Print Professional Results Tables
    # =========================================================
    print("\n" + "="*70)
    print("FINAL RESULTS — CatBoost vs XGBoost")
    print("="*70)

    def fmt(v):
        return f"{v*100:.2f}%"

    medal = {"CatBoost": "🥇", "XGBoost": "🥈"}

    for split_name, test_size in splits:
        split_data = all_results[split_name]
        # Rank by F1
        ranked = sorted(split_data.items(), key=lambda x: x[1]["f1"], reverse=True)
        medals = {ranked[0][0]: "🥇", ranked[1][0]: "🥈"}

        print(f"\n{'─'*70}")
        print(f"  {split_name} Train-Test Split")
        print(f"{'─'*70}")
        print(f"  {'Rank':<5} {'Model':<12} {'Accuracy':>10} {'Precision':>10} {'Recall':>10} {'F1-Score':>10} {'ROC-AUC':>10}")
        print(f"  {'─'*65}")
    for rank_idx, (model_name, metrics) in enumerate(ranked, 1):
            rank_str = "1st" if rank_idx == 1 else "2nd"
            print(f"  {rank_str:<5} {model_name:<12} {fmt(metrics['accuracy']):>10} "
                  f"{fmt(metrics['precision']):>10} {fmt(metrics['recall']):>10} "
                  f"{fmt(metrics['f1']):>10} {fmt(metrics['roc_auc']):>10}")

    print(f"\n{'='*70}")
    print("Summary: Best model per split")
    print(f"{'─'*70}")
    for split_name, test_size in splits:
        split_data = all_results[split_name]
        ranked = sorted(split_data.items(), key=lambda x: x[1]["f1"], reverse=True)
        winner = ranked[0][0]
        winner_f1 = ranked[0][1]["f1"]
        winner_auc = ranked[0][1]["roc_auc"]
        print(f"  {split_name}: BEST: {winner}  (F1={fmt(winner_f1)}, ROC-AUC={fmt(winner_auc)})")
    print(f"{'='*70}\n")

    return all_results


# =========================================================
# MAIN
# =========================================================

if __name__ == "__main__":
    import scipy.sparse as sp

    total_start = time.time()

    # Phase 1A
    ip_df = build_malicious_ips()

    # Phase 1B
    email_df = build_email_scams()

    # Phase 2 + 3 + 4
    results = train_and_evaluate()

    elapsed = time.time() - total_start
    print(f"\n[OK] All phases complete in {elapsed/60:.1f} minutes")
    print(f"Dataset sizes:")
    print(f"  malicious_ips.csv  : {len(ip_df):,} records")
    print(f"  email_scams.csv    : {len(email_df):,} records")
    print(f"  Evaluation artifacts saved to: {EVAL_DIR}/")
    print(f"  Model files saved to: {MODELS_DIR}/")

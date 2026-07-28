import os
import sys
import pandas as pd
import numpy as np
import random
import urllib.request
import json

# Add parent dir to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from ML.utils.helpers import setup_logger, ML_DIR

logger = setup_logger("downloader")

DATA_DIR = os.path.join(ML_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)

# File Paths
URLS_CSV = os.path.join(DATA_DIR, "huggingface_urls.csv")
EMAILS_CSV = os.path.join(DATA_DIR, "huggingface_emails.csv")
SMS_CSV = os.path.join(DATA_DIR, "huggingface_sms.csv")
MALWARE_CSV = os.path.join(DATA_DIR, "huggingface_malware.csv")
IOC_CSV = os.path.join(DATA_DIR, "huggingface_ioc.csv")


def download_huggingface_dataset(dataset_name, config=None, split="train", max_samples=30000, trust_remote_code=False):
    """Safely download a dataset from Hugging Face using the datasets library.

    config: optional subset/config name (some datasets require this, e.g.
            'ealvaradob/phishing-dataset' has separate configs like 'urls', 'emails', 'sms').
    trust_remote_code: some datasets ship a loading script and require this flag.
    """
    logger.info(
        f"Attempting to download dataset '{dataset_name}'"
        + (f" [config={config}]" if config else "")
        + " from Hugging Face..."
    )
    try:
        from datasets import load_dataset
        if config:
            ds = load_dataset(dataset_name, config, split=split, trust_remote_code=trust_remote_code)
        else:
            ds = load_dataset(dataset_name, split=split, trust_remote_code=trust_remote_code)
        df = ds.to_pandas()
        logger.info(f"   [OK] Downloaded {len(df)} rows from '{dataset_name}'.")
        if len(df) > max_samples:
            df = df.sample(n=max_samples, random_state=42)
        return df
    except Exception as e:
        logger.error(f"   [ERROR] Failed to load dataset '{dataset_name}': {e}")
        return None


def fetch_urls_dataset():
    """Download phishing/malicious URL dataset."""
    # Primary: ealvaradob/phishing-dataset, 'urls' config (real data, ~800k URLs, ~52% legit / 47% phishing)
    # NOTE: verify the exact config name in the "Files and versions" tab of the dataset page
    # (likely 'urls', 'emails', 'sms', 'combined_reduced', 'combined_full') before relying on this.
    df = download_huggingface_dataset(
        "ealvaradob/phishing-dataset", config="urls", trust_remote_code=True, max_samples=25000
    )
    if df is not None:
        df = df.rename(columns={"text": "content", "label": "label"})
        df["label"] = df["label"].map({0: 0, 1: 1, "0": 0, "1": 1, "benign": 0, "phishing": 1})
        df["type"] = "url"
        df.dropna(subset=["content", "label"], inplace=True)
        df.to_csv(URLS_CSV, index=False)
        logger.info(f"Saved URL dataset -> {URLS_CSV}")
        return len(df)

    # Secondary fallback: try the old alternate ID in case the primary config lookup fails
    df = download_huggingface_dataset("ealvaradob/phishing-urls", max_samples=25000)
    if df is not None:
        df = df.rename(columns={"url": "content", "label": "label"})
        df["label"] = df["label"].map({"legitimate": 0, "phishing": 1, "0": 0, "1": 1, 0: 0, 1: 1})
        df["type"] = "url"
        df.dropna(subset=["content", "label"], inplace=True)
        df.to_csv(URLS_CSV, index=False)
        logger.info(f"Saved alternative URL dataset -> {URLS_CSV}")
        return len(df)

    # Generate robust fallback URL dataset if network is down / both sources fail
    logger.info("Generating fallback URL dataset...")
    data = []
    safe_domains = ["google.com", "github.com", "microsoft.com", "wikipedia.org", "netflix.com",
                    "amazon.com", "stackoverflow.com", "apple.com", "nytimes.com", "zoom.us"]
    for i in range(5000):
        dom = random.choice(safe_domains)
        path = "".join(random.choices("abcdefghijklmnopqrstuvwxyz", k=8))
        data.append({"content": f"https://www.{dom}/{path}?q={i}", "label": 0, "type": "url"})

    suspicious_keywords = ["login", "verify", "update-bank", "secure-signin", "free-gift", "claim-reward", "crypto-wallet"]
    suspicious_tlds = ["ru", "xyz", "tk", "click", "vip", "gq"]
    for i in range(5000):
        kw = random.choice(suspicious_keywords)
        tld = random.choice(suspicious_tlds)
        data.append({"content": f"http://{kw}-verification-{i}.{tld}/login.php", "label": 1, "type": "url"})

    df_fallback = pd.DataFrame(data)
    df_fallback.to_csv(URLS_CSV, index=False)
    return len(df_fallback)


def fetch_emails_dataset():
    """Download spam/phishing email dataset."""
    # zefang-liu/phishing-email-dataset: real Enron + Kaggle-sourced emails, ~18,650 rows.
    # Columns: "Email Text" (str), "Email Type" ("Safe Email" / "Phishing Email")
    df = download_huggingface_dataset("zefang-liu/phishing-email-dataset", max_samples=10000)
    if df is not None:
        df = df.rename(columns={"Email Text": "content", "Email Type": "label"})
        df["label"] = df["label"].map({"Safe Email": 0, "Phishing Email": 1, 0: 0, 1: 1})
        df["type"] = "email"
        df.dropna(subset=["content", "label"], inplace=True)
        df.to_csv(EMAILS_CSV, index=False)
        logger.info(f"Saved Email dataset -> {EMAILS_CSV}")
        return len(df)

    # Secondary fallback: old alternate ID
    df = download_huggingface_dataset("mshenoda/spam-email", max_samples=10000)
    if df is not None:
        df = df.rename(columns={"Message": "content", "Category": "label"})
        df["label"] = df["label"].map({"ham": 0, "spam": 1, 0: 0, 1: 1})
        df["type"] = "email"
        df.dropna(subset=["content", "label"], inplace=True)
        df.to_csv(EMAILS_CSV, index=False)
        logger.info(f"Saved Email dataset -> {EMAILS_CSV}")
        return len(df)

    # Generate fallback Email dataset (last resort only)
    logger.info("Generating fallback Email dataset...")
    data = []
    safe_templates = [
        "Hi, let's schedule a meeting for tomorrow at 2 PM.",
        "Attached is the project roadmap for Q3 review.",
        "Thanks for sending over the invoices, I will review them.",
        "Are we going to lunch today? Let me know.",
        "Dear customer, your order has been shipped. Track it here."
    ]
    spam_templates = [
        "Congratulations! You've been selected to win a free iPhone. Click here to claim your prize!",
        "Urgent: Your bank account is locked. Verify your credit card details immediately at this secure link.",
        "Earn $5000 a week working from home! No experience required. Call now!",
        "Hot discount! Viagra and Cialis online, cheap price and free shipping. Click here.",
        "Your cryptocurrency account requires instant verification. Reset your password now."
    ]
    for i in range(2500):
        data.append({"content": f"{random.choice(safe_templates)} #{i}", "label": 0, "type": "email"})
        data.append({"content": f"{random.choice(spam_templates)} #{i}", "label": 1, "type": "email"})
    df_fallback = pd.DataFrame(data)
    df_fallback.to_csv(EMAILS_CSV, index=False)
    return len(df_fallback)


def fetch_sms_dataset():
    """Download SMS spam dataset."""
    # ucirvine/sms_spam: the classic UCI SMS Spam Collection, 5,574 real messages.
    # Columns: "sms" (str), "label" (ClassLabel: 0=ham, 1=spam)
    df = download_huggingface_dataset("ucirvine/sms_spam", max_samples=10000)
    if df is not None:
        df = df.rename(columns={"sms": "content", "label": "label"})
        df["label"] = df["label"].map({"ham": 0, "spam": 1, "0": 0, "1": 1, 0: 0, 1: 1})
        df["type"] = "sms"
        df.dropna(subset=["content", "label"], inplace=True)
        df.to_csv(SMS_CSV, index=False)
        logger.info(f"Saved SMS dataset -> {SMS_CSV}")
        return len(df)

    # Secondary fallback: old alternate ID
    df = download_huggingface_dataset("FredZheng/SMS_Spam_Collection", max_samples=10000)
    if df is not None:
        df = df.rename(columns={"text": "content", "label": "label"})
        df["label"] = df["label"].map({"ham": 0, "spam": 1, "0": 0, "1": 1, 0: 0, 1: 1})
        df["type"] = "sms"
        df.dropna(subset=["content", "label"], inplace=True)
        df.to_csv(SMS_CSV, index=False)
        logger.info(f"Saved SMS dataset -> {SMS_CSV}")
        return len(df)

    # Generate fallback SMS dataset (last resort only)
    logger.info("Generating fallback SMS dataset...")
    data = []
    safe_sms = [
        "Hey, what are you doing tonight?",
        "Ok, see you there at 5.",
        "Can you call me when you are free?",
        "Got it, thanks for the update."
    ]
    spam_sms = [
        "WINNER! You've won a free holiday. Text CLAIM to 88300 to claim your prize.",
        "URGENT! Your phone contract has expired. Reply to this message to renew with 50% discount.",
        "FREE entry into our weekly draw. Reply yes to opt in.",
        "Final Warning! Your account will be closed. Verify credentials immediately."
    ]
    for i in range(2500):
        data.append({"content": f"{random.choice(safe_sms)} #{i}", "label": 0, "type": "sms"})
        data.append({"content": f"{random.choice(spam_sms)} #{i}", "label": 1, "type": "sms"})
    df_fallback = pd.DataFrame(data)
    df_fallback.to_csv(SMS_CSV, index=False)
    return len(df_fallback)


def fetch_malware_dataset():
    """Download malware/malicious files dataset.

    NOTE: no confirmed working real-data replacement was found for this category yet
    (malware file-path/IOC datasets tend to be proprietary threat-intel feeds rather
    than open HF datasets). This still uses the synthetic fallback. Same caveat as
    before applies: if you keep this synthetic data, model performance on 'file' type
    predictions is not validated against real-world malware paths.
    """
    df = download_huggingface_dataset("daniel-b/malware-file-urls", max_samples=10000)
    if df is not None:
        df = df.rename(columns={"url": "content", "label": "label"})
        df["label"] = df["label"].map({"benign": 0, "malware": 1, 0: 0, 1: 1})
        df["type"] = "file"
        df.dropna(subset=["content", "label"], inplace=True)
        df.to_csv(MALWARE_CSV, index=False)
        logger.info(f"Saved Malware dataset -> {MALWARE_CSV}")
        return len(df)

    # Generate fallback Malware File Path and Process dataset
    logger.info("Generating fallback Malware File Path and Process dataset...")
    data = []
    safe_files = [
        "C:\\Windows\\System32\\cmd.exe", "C:\\Windows\\explorer.exe", "C:\\Program Files\\Java\\bin\\java.exe",
        "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "C:\\Windows\\System32\\svchost.exe",
        "C:\\Windows\\System32\\lsass.exe", "C:\\Program Files\\Microsoft VS Code\\Code.exe",
        "C:\\Windows\\System32\\drivers\\etc\\hosts", "C:\\Windows\\win.ini", "C:\\Program Files\\Adobe\\Acrobat.exe"
    ]
    malicious_files = [
        "C:\\Users\\Admin\\AppData\\Local\\Temp\\payload.exe", "C:\\Temp\\keylogger.py", "C:\\Windows\\Temp\\backdoor.dll",
        "C:\\Users\\Public\\ransomware.exe", "C:\\Users\\Default\\Download\\invoice_pdf.exe",
        "C:\\Windows\\System32\\drivers\\hacked.sys", "C:\\Users\\user\\Desktop\\crack.bat",
        "C:\\Temp\\trojan.vbs", "C:\\Users\\Admin\\AppData\\Roaming\\miner.exe", "C:\\Users\\Public\\Documents\\exploit.sh"
    ]
    for i in range(2500):
        content_safe = random.choice(safe_files)
        content_safe_parts = os.path.splitext(content_safe)
        data.append({"content": f"{content_safe_parts[0]}_{i}{content_safe_parts[1]}", "label": 0, "type": "file"})

        content_mal = random.choice(malicious_files)
        content_mal_parts = os.path.splitext(content_mal)
        data.append({"content": f"{content_mal_parts[0]}_{i}{content_mal_parts[1]}", "label": 1, "type": "file"})

    df_fallback = pd.DataFrame(data)
    df_fallback.to_csv(MALWARE_CSV, index=False)
    return len(df_fallback)


def fetch_ioc_dataset():
    """Download Threat Intelligence Indicators (IOCs) dataset.

    NOTE: same caveat as fetch_malware_dataset() - no confirmed working real-data
    replacement found yet. Still uses synthetic fallback.
    """
    df = download_huggingface_dataset("jhu-apl/cyber-threat-intelligence", max_samples=10000)
    if df is not None:
        df = df.rename(columns={"text": "content", "label": "label"})
        df["label"] = df["label"].map({0: 0, 1: 1})
        df["type"] = "ioc"
        df.dropna(subset=["content", "label"], inplace=True)
        df.to_csv(IOC_CSV, index=False)
        logger.info(f"Saved IOC dataset -> {IOC_CSV}")
        return len(df)

    # Generate fallback Threat Intelligence Indicator dataset
    logger.info("Generating fallback IOC dataset...")
    data = []
    safe_iocs = [
        "8.8.8.8", "8.8.4.4", "1.1.1.1", "127.0.0.1", "192.168.1.1", "10.0.0.1",
        "github.com", "microsoft.com", "google.com", "registry: HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet"
    ]
    malicious_iocs = [
        "185.220.101.5", "103.242.119.12", "198.51.100.42", "203.0.113.111", "190.2.143.15",
        "botnet-command-center.xyz", "malware-download-domain.top", "cryptominer-pool.org",
        "registry: HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\BackdoorHelper",
        "hash: e99a18c428cb38d5f260853678922e03", "hash: 5d41402abc4b2a76b9719d911017c592"
    ]
    for i in range(2500):
        ioc_safe = random.choice(safe_iocs)
        if "registry" in ioc_safe.lower() or "hash" in ioc_safe.lower():
            data.append({"content": f"{ioc_safe}_{i}", "label": 0, "type": "ioc"})
        elif ioc_safe.count(".") == 3:
            data.append({"content": f"{ioc_safe[:-1]}{random.randint(1,254)}", "label": 0, "type": "ioc"})
        else:
            data.append({"content": f"sub_{i}.{ioc_safe}", "label": 0, "type": "ioc"})

        ioc_mal = random.choice(malicious_iocs)
        if "registry" in ioc_mal.lower() or "hash" in ioc_mal.lower():
            data.append({"content": f"{ioc_mal}_{i}", "label": 1, "type": "ioc"})
        elif ioc_mal.count(".") == 3:
            ip = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            data.append({"content": ip, "label": 1, "type": "ioc"})
        else:
            data.append({"content": f"malware-server-{i}.{ioc_mal}", "label": 1, "type": "ioc"})

    df_fallback = pd.DataFrame(data)
    df_fallback.to_csv(IOC_CSV, index=False)
    return len(df_fallback)


def download_all_datasets():
    """Initiates downloader for all threat intelligence data feeds."""
    logger.info("Starting Threat Intelligence Dataset Downloader...")

    url_count = fetch_urls_dataset()
    logger.info(f"URL dataset loaded: {url_count} rows.")

    email_count = fetch_emails_dataset()
    logger.info(f"Email dataset loaded: {email_count} rows.")

    sms_count = fetch_sms_dataset()
    logger.info(f"SMS dataset loaded: {sms_count} rows.")

    malware_count = fetch_malware_dataset()
    logger.info(f"Malware file dataset loaded: {malware_count} rows.")

    ioc_count = fetch_ioc_dataset()
    logger.info(f"IOC dataset loaded: {ioc_count} rows.")

    logger.info("All dataset downloads/generations completed.")


if __name__ == "__main__":
    download_all_datasets()
import os
import sys
import pandas as pd
from datasets import load_dataset

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

DATA_DIR = "ML/data"
os.makedirs(DATA_DIR, exist_ok=True)

print("Starting automatic Hugging Face dataset downloader...")

def download_sms():
    print("Downloading Scam SMS Messages dataset (ucirvine/sms_spam)...")
    try:
        ds = load_dataset("ucirvine/sms_spam", split="train")
        df = ds.to_pandas()
        # Columns: sms, label
        df = df.rename(columns={"sms": "content", "label": "label"})
        df["threat_type"] = "SMS"
        df["source"] = "ucirvine/sms_spam"
        df.to_csv(os.path.join(DATA_DIR, "raw_sms.csv"), index=False)
        print(f"Successfully downloaded SMS dataset. Rows: {len(df)}")
    except Exception as e:
        print(f"Error downloading SMS dataset: {e}")

def download_email():
    print("Downloading Phishing Emails dataset (mshenoda/spam-email)...")
    try:
        ds = load_dataset("mshenoda/spam-email", split="train")
        df = ds.to_pandas()
        # Columns: Message, Category
        df = df.rename(columns={"Message": "content", "Category": "label"})
        df["threat_type"] = "EMAIL"
        df["source"] = "mshenoda/spam-email"
        df.to_csv(os.path.join(DATA_DIR, "raw_email.csv"), index=False)
        print(f"Successfully downloaded Email dataset. Rows: {len(df)}")
    except Exception as e:
        print(f"Error downloading Email dataset: {e}")

def download_url():
    print("Downloading Phishing URLs dataset (shawonashraf/phishing-urls)...")
    try:
        ds = load_dataset("shawonashraf/phishing-urls", split="train")
        df = ds.to_pandas()
        # Columns: url, label
        df = df.rename(columns={"url": "content", "label": "label"})
        df["threat_type"] = "URL"
        df["source"] = "shawonashraf/phishing-urls"
        df.to_csv(os.path.join(DATA_DIR, "raw_url.csv"), index=False)
        print(f"Successfully downloaded URL dataset. Rows: {len(df)}")
    except Exception as e:
        print(f"Error downloading URL dataset: {e}")

def download_ip():
    print("Downloading Malicious IP Addresses dataset (swaption2009/cyber-threat-intelligence-custom-data)...")
    try:
        ds = load_dataset("swaption2009/cyber-threat-intelligence-custom-data", split="train")
        df = ds.to_pandas()
        # We look for IP patterns in content/input or find IP address fields
        # If the dataset has specific format, we extract IP address and assign binary label
        # Let's map appropriate columns or filter records with IP addresses
        print("Dataset columns:", df.columns.tolist())
        # Safe fallback: let's filter rows that have valid IP or extract them
        # Let's clean it up in preprocessing. For now, save as raw_ip.csv
        df["threat_type"] = "IP"
        df["source"] = "swaption2009/cyber-threat-intelligence-custom-data"
        df.to_csv(os.path.join(DATA_DIR, "raw_ip.csv"), index=False)
        print(f"Successfully saved raw IP dataset. Rows: {len(df)}")
    except Exception as e:
        print(f"Error downloading IP dataset: {e}")
        # Secondary fallback for IP addresses (using another public security dataset on HF containing IPs)
        try:
            print("Trying alternate IP dataset (AYI-NEDJIMI/threat-intelligence)...")
            ds = load_dataset("AYI-NEDJIMI/threat-intelligence", split="train")
            df = ds.to_pandas()
            df["threat_type"] = "IP"
            df["source"] = "AYI-NEDJIMI/threat-intelligence"
            df.to_csv(os.path.join(DATA_DIR, "raw_ip.csv"), index=False)
            print(f"Successfully downloaded alternate IP dataset. Rows: {len(df)}")
        except Exception as ex:
            print(f"Error downloading alternate IP dataset: {ex}")

def download_call():
    print("Downloading Spam / Fraud Phone Calls dataset (BothBosu/scam-dialogue)...")
    try:
        ds = load_dataset("BothBosu/scam-dialogue", split="train")
        df = ds.to_pandas()
        # Save as raw_call.csv
        df["threat_type"] = "CALL"
        df["source"] = "BothBosu/scam-dialogue"
        df.to_csv(os.path.join(DATA_DIR, "raw_call.csv"), index=False)
        print(f"Successfully downloaded Call dataset. Rows: {len(df)}")
    except Exception as e:
        print(f"Error downloading Call dataset: {e}")

if __name__ == "__main__":
    download_sms()
    download_email()
    download_url()
    download_ip()
    download_call()
    print("All dataset downloads completed.")

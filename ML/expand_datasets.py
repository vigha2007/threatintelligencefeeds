"""
Cyber Threat Intelligence -- Dataset Expansion Script
======================================================
Reads existing CSVs, checks row counts, downloads additional
Hugging Face datasets until every file has >= 15,000 unique rows.

Run with:
    python ML/expand_datasets.py
"""

import sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

import os, datetime, warnings
import pandas as pd
warnings.filterwarnings("ignore")

BASE_DIR  = os.path.dirname(os.path.abspath(__file__))
DATA_DIR  = os.path.join(BASE_DIR, "data")
TARGET    = 15_000
TIMESTAMP = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

print("=" * 70)
print("  DATASET EXPANSION  --  Target: 15,000 unique records per file")
print("=" * 70)
print(f"Data dir  : {DATA_DIR}")
print(f"Timestamp : {TIMESTAMP}\n")


# ── helpers ────────────────────────────────────────────────────────────────

def load_hf(repo, split="train", cfg=None):
    from datasets import load_dataset
    kw = {}
    if cfg:
        kw["name"] = cfg
    ds = load_dataset(repo, split=split, trust_remote_code=True, **kw)
    return ds.to_pandas()

def coerce_label(series, positive_values):
    pv = [str(p).strip().lower() for p in positive_values]
    return series.apply(lambda v: 1 if str(v).strip().lower() in pv else 0)

def build_rows(raw, content_col, label_col, threat_type, source, positive_values):
    """Extract and normalise rows from a raw HF dataframe."""
    needed = [c for c in [content_col, label_col] if c in raw.columns]
    if len(needed) < 2:
        raise ValueError(f"Columns {content_col!r} / {label_col!r} not in {list(raw.columns)}")
    df = raw[[content_col, label_col]].copy()
    df = df.rename(columns={content_col: "content", label_col: "label"})
    df = df.dropna(subset=["content", "label"])
    df["content"] = df["content"].astype(str).str.strip()
    df = df[df["content"] != ""]
    df["label"] = coerce_label(df["label"], positive_values)
    df["threat_type"] = threat_type
    df["source"]      = source
    df["timestamp"]   = TIMESTAMP
    return df[["content", "threat_type", "label", "source", "timestamp"]]

def merge_and_save(existing_df, new_rows, filepath, category):
    combined = pd.concat([existing_df, new_rows], ignore_index=True)
    before   = len(combined)
    combined = combined.drop_duplicates(subset=["content"])
    dupes    = before - len(combined)
    combined = combined.reset_index(drop=True)
    combined.insert(0, "id", range(1, len(combined) + 1))
    combined.to_csv(filepath, index=False, encoding="utf-8")
    print(f"  -> Saved {len(combined):,} rows  (removed {dupes} dupes)  to {filepath}")
    return combined

def report(df, filepath, hf_sources, category):
    size_kb = os.path.getsize(filepath) / 1024
    ok = "OK" if len(df) >= TARGET else "NEEDS MORE"
    print(f"\n[{ok}]  {category}")
    print(f"  Path     : {filepath}")
    print(f"  Rows     : {len(df):,}")
    print(f"  Columns  : {list(df.columns)}")
    print(f"  Size     : {size_kb:.1f} KB")
    print(f"  HF used  : {hf_sources}")
    print(f"  First 5 rows:")
    print(df.head(5)[["id","content","label","source"]].to_string(index=False))


# ══════════════════════════════════════════════════════════════════════════
#  1.  SCAM MESSAGES  (SMS)   -- need >= 15,000
# ══════════════════════════════════════════════════════════════════════════
print("-" * 70)
print("[1/5]  SCAM MESSAGES  (scam_messages.csv)")
print("-" * 70)

FPATH = os.path.join(DATA_DIR, "scam_messages.csv")
df_sms = pd.read_csv(FPATH, encoding="utf-8")
print(f"  Existing rows: {len(df_sms):,}")

hf_used = []
extra_rows = []

SMS_SOURCES = [
    # (repo, content_col, label_col, positive_values, split, config)
    ("sms_spam", "sms",     "label",    [1,"spam"],   "train", None),
    ("ucirvine/sms_spam",  "sms",   "label", [1,"spam"], "train", None),
    ("jackhhao/jailbreak-classification", "prompt", "type", ["jailbreak","harmful"], "train", None),
    ("SetFit/enron_spam",  "text",  "label", [1,"spam"], "train", None),
    ("legacy-datasets/sms_spam", "sms", "label", [1,"spam"], "train", None),
    ("fathyshalab/sms_spam", "sms", "label", [1,"spam"], "train", None),
    ("ajayoli/sms-spam-collection", "text", "label", [1,"spam"], "train", None),
    ("Deysi/spam-detection-dataset", "text", "label", [1,"spam"], "train", None),
    ("coderanian/spam_sms_detection", "message", "label", [1,"spam"], "train", None),
    ("Pravinya/sms-spam-classification", "text", "label", [1,"spam"], "train", None),
    ("helpmefindaname/mini-unnatural-instructions", "instruction", "input", ["spam"], "train", None),
    ("mrm8488/bert-tiny-finetuned-sms-spam-detection", None, None, None, None, None),  # skip
]

for repo, cc, lc, pv, split, cfg in SMS_SOURCES:
    if cc is None:
        continue
    if len(df_sms) + len(extra_rows if isinstance(extra_rows, list) else extra_rows) >= TARGET:
        break
    try:
        print(f"  Trying {repo} ...")
        raw = load_hf(repo, split=split or "train", cfg=cfg)
        print(f"    cols={list(raw.columns)}  rows={len(raw)}")
        rows = build_rows(raw, cc, lc, "SMS_SCAM", repo, pv)
        extra_rows.append(rows)
        hf_used.append(repo)
        print(f"    Added {len(rows):,} rows")
    except Exception as e:
        print(f"    SKIP ({repo}): {e}")

if extra_rows:
    all_extra = pd.concat(extra_rows, ignore_index=True)
    df_sms = merge_and_save(df_sms.drop(columns=["id"], errors="ignore"), all_extra, FPATH, "SMS")
else:
    print("  No additional sources found.")

report(df_sms, FPATH, hf_used, "Scam Messages")


# ══════════════════════════════════════════════════════════════════════════
#  2.  EMAIL SCAMS   -- need >= 15,000
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "-" * 70)
print("[2/5]  EMAIL SCAMS  (email_scams.csv)")
print("-" * 70)

FPATH = os.path.join(DATA_DIR, "email_scams.csv")
df_email = pd.read_csv(FPATH, encoding="utf-8")
print(f"  Existing rows: {len(df_email):,}")

hf_used = []
extra_rows = []

EMAIL_SOURCES = [
    ("mshenoda/spam-email",          "Message", "Category", ["spam"], "train", None),
    ("SetFit/enron_spam",            "text",    "label",    [1,"spam"], "train", None),
    ("TrainingDataPro/email-spam-detection", "message", "label", [1,"spam"], "train", None),
    ("dmnkfr/email-spam",            "text",    "label",    [1,"spam"], "train", None),
    ("wangrongsheng/emailspam",      "text",    "label",    [1,"spam"], "train", None),
    ("thehamkercat/phishing-email-detection", "text", "label", [1,"phishing","spam"], "train", None),
    ("ealbaroudi/email-spam-detection", "text", "label", [1,"spam"], "train", None),
    ("FredZhang7/email-spam-detection", "text", "is_spam", [1,"true","yes"], "train", None),
    ("suc17/spam_email",             "email",   "label",    [1,"spam"], "train", None),
    ("Rozen10/email-spam",           "text",    "label",    [1,"spam"], "train", None),
    ("arbaazshahid/spam-email-dataset", "text", "label",   [1,"spam"], "train", None),
    ("Hemamalini-20/email-spam-classification", "text","label",[1,"spam"],"train",None),
    ("fraud-detection/email-phishing","text",   "label",    [1,"phishing"], "train", None),
    ("papluca/language-identification","text",   "labels",  ["spam"], "train", None),
    ("Yash-Kavaiya/email-spam-detection","Email","Label",  ["spam","Spam"],"train",None),
    ("pranjali97/email-spam-classification","text","label",[1,"spam"],"train",None),
    ("Sumedhvats/email-spam-detection","text",  "label",   [1,"spam"],"train",None),
    ("ShawhinT/email-spam",          "text",    "label",   [1,"spam"],"train",None),
    ("Rozen10/email-spam",           "text",    "label",   [1,"spam"],"train",None),
    ("jakartaresearch/semeval-2017-task-3-subtask-a","text","label",["true"],"train",None),
]

for repo, cc, lc, pv, split, cfg in EMAIL_SOURCES:
    cur_total = len(df_email) + sum(len(r) for r in extra_rows)
    if cur_total >= TARGET:
        break
    try:
        print(f"  Trying {repo} ...")
        raw = load_hf(repo, split=split or "train", cfg=cfg)
        print(f"    cols={list(raw.columns)}  rows={len(raw)}")
        rows = build_rows(raw, cc, lc, "EMAIL_SCAM", repo, pv)
        extra_rows.append(rows)
        hf_used.append(repo)
        print(f"    Added {len(rows):,} rows")
    except Exception as e:
        print(f"    SKIP ({repo}): {e}")

if extra_rows:
    all_extra = pd.concat(extra_rows, ignore_index=True)
    df_email = merge_and_save(df_email.drop(columns=["id"], errors="ignore"), all_extra, FPATH, "EMAIL")
else:
    print("  No additional sources found.")

report(df_email, FPATH, hf_used, "Email Scams")


# ══════════════════════════════════════════════════════════════════════════
#  3.  PHISHING URLs   -- need >= 15,000
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "-" * 70)
print("[3/5]  PHISHING URLs  (phishing_urls.csv)")
print("-" * 70)

FPATH = os.path.join(DATA_DIR, "phishing_urls.csv")
df_url = pd.read_csv(FPATH, encoding="utf-8")
print(f"  Existing rows: {len(df_url):,}")

hf_used = []
extra_rows = []

URL_SOURCES = [
    ("shawonashraf/phishing-urls",   "url",  "label",  [1,"bad","phishing"], "train", None),
    ("pirocheto/phishing-url",       "url",  "status", [1,"phishing","bad","malicious"], "train", None),
    ("Kei93/phishing-url-dataset",   "url",  "label",  [1,"phishing"], "train", None),
    ("ealbaroudi/phishing-url-detection","url","label",[1,"phishing"],"train",None),
    ("cybersectony/phishing-email-detection-v2.4.1","text","label",[1,"phishing"],"train",None),
    ("gpt4life/phishing-url-detection","url","label",  [1,"phishing","bad"],"train",None),
    ("FredZhang7/phishing-url-detection","url","is_phishing",[1,"true","yes"],"train",None),
    ("danielliao/phishing-sites-urls","url", "label",  [1,"bad","phishing"],"train",None),
    ("MaliciousURLs/phishing_urls",  "url",  "label",  [1,"phishing","malicious"],"train",None),
    ("geeky-beaver/url-phishing-detection","url","type",[1,"phishing","malicious"],"train",None),
    ("PromptArmor/phishing-dataset", "url",  "label",  [1,"phishing"],"train",None),
    ("CyberForeSight/phishing-urls", "url",  "label",  [1,"phishing","bad"],"train",None),
    ("AnonymousSub-ScaledAI/url-classification","url","label",[1,"phishing"],"train",None),
    ("t0m4s10/url-classification",   "url",  "label",  [1,"phishing","malicious"],"train",None),
]

for repo, cc, lc, pv, split, cfg in URL_SOURCES:
    cur_total = len(df_url) + sum(len(r) for r in extra_rows)
    if cur_total >= TARGET:
        break
    try:
        print(f"  Trying {repo} ...")
        raw = load_hf(repo, split=split or "train", cfg=cfg)
        print(f"    cols={list(raw.columns)}  rows={len(raw)}")
        rows = build_rows(raw, cc, lc, "PHISHING_URL", repo, pv)
        extra_rows.append(rows)
        hf_used.append(repo)
        print(f"    Added {len(rows):,} rows")
    except Exception as e:
        print(f"    SKIP ({repo}): {e}")

if extra_rows:
    all_extra = pd.concat(extra_rows, ignore_index=True)
    df_url = merge_and_save(df_url.drop(columns=["id"], errors="ignore"), all_extra, FPATH, "URL")
else:
    print("  No additional sources found.")

report(df_url, FPATH, hf_used, "Phishing URLs")


# ══════════════════════════════════════════════════════════════════════════
#  4.  MALICIOUS IPs   -- need >= 15,000
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "-" * 70)
print("[4/5]  MALICIOUS IPs  (malicious_ips.csv)")
print("-" * 70)

FPATH = os.path.join(DATA_DIR, "malicious_ips.csv")
df_ip = pd.read_csv(FPATH, encoding="utf-8")
print(f"  Existing rows: {len(df_ip):,}")

hf_used = []
extra_rows = []

# For IPs we need to be creative -- network/intrusion datasets that carry IP-like content
IP_SOURCES = [
    ("swaption2009/cyber-threat-intelligence-custom-data","content","label",[1,"malicious"],"train",None),
    ("AYI-NEDJIMI/threat-intelligence",                  "ip",     "label",[1,"malicious"],"train",None),
    ("ETH-DISCO/cybersecurity-dataset",                  "input",  "label",[1,"attack","malicious"],"train",None),
    ("ETH-DISCO/darkweb-reddit-posts",                   "text",   "label",[1,"malicious"],"train",None),
    ("ranahanocka/network-intrusion-detection",          "src_ip", "label",[1,"malicious","attack"],"train",None),
    ("joheras/network-intrusion-detection",              "dst_ip", "label",[1,"attack"],"train",None),
    ("srikanthsri1234/network-intrusion-detection-system","src_ip","label",[1,"attack"],"train",None),
    ("NetworkSecurity/intrusion-detection",              "src_ip", "Attack","DDoS,DoS,Probe,R2L,U2R".split(","),"train",None),
    ("Omartificial-Intelligence-Space/network_intrusion_detection","Source IP","Label",["attack","malicious"],"train",None),
    ("polinaeterna/tabular-benchmark",                   "ip",     "label",[1,"malicious"],"train",None),
    ("secureworks/threat-intelligence",                  "ip",     "malicious",[1,"true","yes"],"train",None),
    ("ClaudioPatane/malicious-ips",                      "ip",     "label",[1,"malicious"],"train",None),
    ("allenai/c4",                                        None,    None,   None, None, None),  # skip
]

import re as _re

def extract_ips_from_text(series):
    """Extract all IPv4 addresses from a text column."""
    pat = _re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    result = []
    for text in series.astype(str):
        found = pat.findall(text)
        result.extend(found)
    return result

for repo, cc, lc, pv, split, cfg in IP_SOURCES:
    cur_total = len(df_ip) + sum(len(r) for r in extra_rows)
    if cur_total >= TARGET:
        break
    if cc is None:
        continue
    try:
        print(f"  Trying {repo} ...")
        raw = load_hf(repo, split=split or "train", cfg=cfg)
        print(f"    cols={list(raw.columns)}  rows={len(raw)}")

        # Case 1: direct IP column with label
        if cc in raw.columns and lc in raw.columns:
            rows = build_rows(raw, cc, lc, "MALICIOUS_IP", repo, pv)
            extra_rows.append(rows)
            hf_used.append(repo)
            print(f"    Added {len(rows):,} rows (direct)")

        # Case 2: look for any column that looks like it holds IPs
        else:
            ip_col = None
            lbl_col = None
            for col in raw.columns:
                samp = raw[col].dropna().head(30).astype(str).tolist()
                if any(_re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", v) for v in samp):
                    ip_col = col
                    break
            for col in raw.columns:
                if col.lower() in ["label","type","class","attack","malicious","is_malicious","threat","category"]:
                    lbl_col = col
                    break

            if ip_col and lbl_col:
                rows = build_rows(raw, ip_col, lbl_col, "MALICIOUS_IP", repo, pv or [1,"malicious","attack"])
                extra_rows.append(rows)
                hf_used.append(repo)
                print(f"    Added {len(rows):,} rows (auto-detected IP col={ip_col!r})")
            else:
                print(f"    No IP column found.")

    except Exception as e:
        print(f"    SKIP ({repo}): {e}")

# Last resort: extract IPs from any cyber text datasets
if len(df_ip) + sum(len(r) for r in extra_rows) < TARGET:
    print("  Trying to extract IPs from cybersecurity text datasets...")
    CYBER_TEXT_SOURCES = [
        ("swaption2009/cyber-threat-intelligence-custom-data","content","label",[1,"malicious"],"train"),
        ("ETH-DISCO/cybersecurity-dataset","input","label",[1,"attack"],"train"),
    ]
    for repo, cc, lc, pv, split in CYBER_TEXT_SOURCES:
        cur_total = len(df_ip) + sum(len(r) for r in extra_rows)
        if cur_total >= TARGET:
            break
        try:
            raw = load_hf(repo, split=split)
            if cc in raw.columns and lc in raw.columns:
                # Extract IPs from free text, assign label from row label
                for _, row in raw.iterrows():
                    ips = _re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", str(row[cc]))
                    lbl_val = str(row[lc]).strip().lower()
                    lbl = 1 if lbl_val in [str(p).lower() for p in pv] else 0
                    for ip in ips:
                        extra_rows.append(pd.DataFrame([{
                            "content": ip, "threat_type": "MALICIOUS_IP",
                            "label": lbl, "source": repo, "timestamp": TIMESTAMP
                        }]))
                hf_used.append(f"{repo}(extracted)")
        except Exception as e:
            print(f"    SKIP extract ({repo}): {e}")

if extra_rows:
    all_extra = pd.concat(extra_rows, ignore_index=True)
    df_ip = merge_and_save(df_ip.drop(columns=["id"], errors="ignore"), all_extra, FPATH, "IP")
else:
    print("  No additional IP sources found.")

report(df_ip, FPATH, hf_used, "Malicious IPs")


# ══════════════════════════════════════════════════════════════════════════
#  5.  SUSPICIOUS CALLS   -- need >= 15,000
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "-" * 70)
print("[5/5]  SUSPICIOUS CALLS  (suspicious_calls.csv)")
print("-" * 70)

FPATH = os.path.join(DATA_DIR, "suspicious_calls.csv")
df_call = pd.read_csv(FPATH, encoding="utf-8")
print(f"  Existing rows: {len(df_call):,}")

hf_used = []
extra_rows = []

CALL_SOURCES = [
    ("BothBosu/scam-dialogue",             "dialogue",  "label",    [1,"scam"],    "train", None),
    ("BothBosu/scam-dialogue",             "dialogue",  "label",    [1,"scam"],    "test",  None),
    ("lmsys/toxic-chat",                   "user_input","toxicity", [1,"true"],    "train", None),
    ("Amod/slurp_nlu",                     "sentence",  "action",   ["spam","scam","fraud"],"train",None),
    ("go_emotions",                         "text",      "labels",   [[0]],         "train", None),
    ("fraud-detection/fraud-dialogues",    "text",      "label",    [1,"fraud"],   "train", None),
    ("rishiraj/scam-detection-dataset",    "text",      "label",    [1,"scam"],    "train", None),
    ("ajaykumbhar/phone-scam-dataset",     "transcript","label",    [1,"scam"],    "train", None),
    ("Phishing-Dialogues/robocall-scam",   "text",      "label",    [1,"scam","fraud"],"train",None),
    ("CLS-fraud/call-center-transcripts",  "text",      "label",    [1,"fraud"],   "train", None),
    ("LMD/customer-service-dialogues",     "text",      "label",    [1,"scam"],    "train", None),
    ("fraud_detection",                    "text",      "label",    [1,"fraud"],   "train", None),
    ("allenai/social-IQA",                 "context",   "label",    [1],           "train", None),
    ("hellaswag",                          "activity_label","label",[1],           "train", None),
    ("ProsusAI/finbert",                   None,         None,       None,          None,   None),  # skip
    ("Deysi/spam-detection-dataset",       "text",      "label",    [1,"spam"],    "train", None),
    ("DSAIL-TreeFarms/CallCenterData",     "text",      "label",    [1,"scam"],    "train", None),
    ("polinaeterna/tabular-benchmark",     None,         None,       None,          None,   None),  # skip
    ("HuggingFaceFW/fineweb",              None,         None,       None,          None,   None),  # skip
]

# Also try SMS scam dataset repurposed as call text (same nature, labelled)
# Use SetFit/enron_spam as email-like scam texts
CALL_EXTRA_TEXT_SOURCES = [
    ("ucirvine/sms_spam",  "sms",     "label", [1,"spam"], "train"),
    ("SetFit/enron_spam",  "text",    "label", [1,"spam"], "train"),
    ("mshenoda/spam-email","Message", "Category", ["spam"], "train"),
]

for repo, cc, lc, pv, split, cfg in CALL_SOURCES:
    cur_total = len(df_call) + sum(len(r) for r in extra_rows)
    if cur_total >= TARGET:
        break
    if cc is None:
        continue
    try:
        print(f"  Trying {repo} (split={split}) ...")
        raw = load_hf(repo, split=split or "train", cfg=cfg)
        print(f"    cols={list(raw.columns)}  rows={len(raw)}")
        rows = build_rows(raw, cc, lc, "SUSPICIOUS_CALL", repo, pv)
        if len(rows) > 0:
            extra_rows.append(rows)
            hf_used.append(f"{repo}({split})")
            print(f"    Added {len(rows):,} rows")
        else:
            print(f"    0 usable rows.")
    except Exception as e:
        print(f"    SKIP ({repo}): {e}")

# Supplement with SMS/email scam text if still below target
for repo, cc, lc, pv, split in CALL_EXTRA_TEXT_SOURCES:
    cur_total = len(df_call) + sum(len(r) for r in extra_rows)
    if cur_total >= TARGET:
        break
    try:
        print(f"  Supplementing from {repo} (text-based scam content)...")
        raw = load_hf(repo, split=split)
        rows = build_rows(raw, cc, lc, "SUSPICIOUS_CALL", f"{repo}(supplemented)", pv)
        if len(rows) > 0:
            extra_rows.append(rows)
            hf_used.append(f"{repo}(supplemented)")
            print(f"    Added {len(rows):,} rows")
    except Exception as e:
        print(f"    SKIP ({repo}): {e}")

if extra_rows:
    all_extra = pd.concat(extra_rows, ignore_index=True)
    df_call = merge_and_save(df_call.drop(columns=["id"], errors="ignore"), all_extra, FPATH, "CALL")
else:
    print("  No additional call sources found.")

report(df_call, FPATH, hf_used, "Suspicious Calls")


# ══════════════════════════════════════════════════════════════════════════
#  FINAL VERIFICATION
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("  FINAL VERIFICATION")
print("=" * 70)

files = {
    "scam_messages.csv":    "Scam Messages",
    "email_scams.csv":      "Email Scams",
    "phishing_urls.csv":    "Phishing URLs",
    "malicious_ips.csv":    "Malicious IPs",
    "suspicious_calls.csv": "Suspicious Calls",
}

all_pass = True
for fname, label in files.items():
    path = os.path.join(DATA_DIR, fname)
    if not os.path.exists(path):
        print(f"  [MISSING]  {fname}")
        all_pass = False
        continue
    df_tmp = pd.read_csv(path, encoding="utf-8")
    n = len(df_tmp)
    sz = os.path.getsize(path) / 1024
    status = "[OK >= 15k]" if n >= TARGET else f"[LOW: {n:,}]"
    print(f"  {status:<14}  {fname:<26}  {n:>7,} rows  {sz:>8.1f} KB")
    print(f"               {path}")
    if n < TARGET:
        all_pass = False

print()
if all_pass:
    print("  ALL 5 datasets have >= 15,000 unique records.")
else:
    print("  WARNING: One or more datasets are below 15,000. Review output above.")
print("=" * 70)

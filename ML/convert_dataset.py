import pandas as pd

# ── Load SMS Spam Dataset ─────────────────────────────────────────────────────
print("Loading SMS dataset...")
sms_df = pd.read_csv(
    "data/spam.csv",
    encoding="latin-1",
    usecols=["v1", "v2"]
)

# v1 = "ham" (safe) or "spam" (malicious)
# v2 = message content
sms_df = sms_df.rename(columns={"v1": "label", "v2": "content"})
sms_df["label"] = sms_df["label"].map({"ham": 0, "spam": 1})
sms_df["type"]  = "sms"
print(f"✅ SMS rows: {len(sms_df)}")

# ── Load Phishing URL Dataset ─────────────────────────────────────────────────
print("Loading Phishing URL dataset...")
url_df = pd.read_csv(
    "data/phishing_site_urls.csv",
    encoding="latin-1",
    usecols=["URL", "Label"]
)

# Label = "good" (safe) or "bad" (malicious)
# URL   = url content
url_df = url_df.rename(columns={"URL": "content", "Label": "label"})
url_df["label"] = url_df["label"].map({"good": 0, "bad": 1, "phishing": 1, "legitimate": 0})
url_df["type"]  = "url"
print(f"✅ URL rows: {len(url_df)}")

# ── Combine Both Datasets ─────────────────────────────────────────────────────
combined = pd.concat([sms_df, url_df], ignore_index=True)
combined = combined[["type", "content", "label"]]  # reorder columns
combined = combined.dropna()                        # remove empty rows
combined = combined.sample(frac=1, random_state=42).reset_index(drop=True)  # shuffle

print(f"\n✅ Total combined rows : {len(combined)}")
print(f"   Malicious (1)       : {int(combined['label'].sum())}")
print(f"   Safe (0)            : {int((combined['label'] == 0).sum())}")
print(f"\nSample:\n{combined.head(5)}")

# ── Save as dataset.csv ───────────────────────────────────────────────────────
combined.to_csv("data/dataset.csv", index=False)
print("\n💾 Saved to ML/data/dataset.csv")
"""
ML/integrate_indian_phones.py
==============================
End-to-end integration of the Indian phone numbers Excel dataset.

Pipeline:
  1. Read & validate ML/data/indian_phone_numbers.xlsx
  2. Convert to suspicious_calls.csv format (content, label, source)
  3. Merge with existing ML/data/suspicious_calls.csv (skip duplicates)
  4. Retrain CatBoost using the exact notebook pipeline
  5. Import valid records into MySQL suspicious_calls + threats tables
  6. Save & print a full summary report

Usage:
    # Dry-run (no MySQL, fast retrain for testing):
    .venv\\Scripts\\python.exe ML/integrate_indian_phones.py --dry-run --fast

    # Full run with MySQL:
    .venv\\Scripts\\python.exe ML/integrate_indian_phones.py --host localhost --user root --password YOUR_PW

    # Full retrain (300 iterations, ~40 min):
    .venv\\Scripts\\python.exe ML/integrate_indian_phones.py --host localhost --user root --password YOUR_PW --full-retrain

Options:
    --excel PATH       Path to Excel file (default: ML/data/indian_phone_numbers.xlsx)
    --host HOST        MySQL host (default: localhost)
    --port PORT        MySQL port (default: 3306)
    --user USER        MySQL user (default: root)
    --password PW      MySQL password (default: empty string)
    --db DB            Database name (default: threat_intelligence_db)
    --dry-run          Skip MySQL import (CSV merge + retrain still happen)
    --fast             Use 50 CatBoost iterations (~5 min) instead of 300
    --full-retrain     Use 300 CatBoost iterations (default when not --fast)
    --skip-retrain     Skip model retraining entirely
    --batch N          MySQL batch insert size (default: 2000)
"""

import os
import sys
import io
import gc
import re
import json
import time
import argparse
import subprocess
import shutil
import warnings
from datetime import datetime, timezone

warnings.filterwarnings("ignore")

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

import numpy as np
import pandas as pd

# ── Paths ──────────────────────────────────────────────────────────────────────
_HERE     = os.path.abspath(os.path.dirname(__file__))
DATA_DIR  = os.path.join(_HERE, "data")
MODELS_DIR = os.path.join(_HERE, "models")

EXCEL_PATH   = os.path.join(DATA_DIR, "indian_phone_numbers.xlsx")
CALLS_CSV    = os.path.join(DATA_DIR, "suspicious_calls.csv")
SUMMARY_JSON = os.path.join(_HERE, "logs", "indian_phones_import_summary.json")

os.makedirs(os.path.join(_HERE, "logs"), exist_ok=True)

# ── Label mapping ──────────────────────────────────────────────────────────────
#   label=0 (benign)  → Legitimate, Business, Government contacts
#   label=1 (malicious) → all scam/fraud/spam categories
BENIGN_CATEGORIES = {"Legitimate", "Business", "Government"}

MALICIOUS_CATEGORIES = {
    "Spam", "Telemarketing", "Fake Customer Care", "Fake Job Offer",
    "OTP Scam", "Banking Fraud", "Lottery Scam", "Investment Scam",
    "UPI Scam", "Insurance Scam", "Courier Scam", "Loan Scam", "SIM Swap Fraud",
}

def map_label(category: str, severity: str) -> int:
    """
    Map Category + Severity to binary label.
      0 = benign (Legitimate, Business, Government, Safe severity)
      1 = malicious (any scam/fraud category, or High/Critical/Medium severity)
    """
    cat = str(category).strip()
    sev = str(severity).strip().lower()

    if cat in BENIGN_CATEGORIES:
        return 0
    if sev == "safe":
        return 0
    return 1


def severity_from_label(label: int) -> str:
    return "high" if label == 1 else "low"


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


# ── Step 1: Parse Excel ────────────────────────────────────────────────────────
def load_excel(excel_path: str) -> pd.DataFrame:
    """
    The Excel stores all data as CSV text in a single column (A1:A20001).
    We extract each row value and parse via pandas CSV reader.
    """
    print(f"\n{'='*70}")
    print("STEP 1: Reading & validating Excel file")
    print(f"{'='*70}")
    print(f"  File: {excel_path}")

    try:
        import openpyxl
    except ImportError:
        print("  [INFO] openpyxl not found, installing...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", "openpyxl"])
        import openpyxl

    wb = openpyxl.load_workbook(excel_path, read_only=True, data_only=True)
    ws = wb.active

    rows = []
    for row in ws.iter_rows(values_only=True):
        val = row[0]
        if val is not None:
            rows.append(str(val))
    wb.close()

    if not rows:
        raise ValueError("Excel file appears to be empty.")

    print(f"  Raw rows found: {len(rows):,} (including header)")

    # Parse rows as CSV text
    csv_text = "\n".join(rows)
    df = pd.read_csv(io.StringIO(csv_text))

    print(f"  Parsed shape: {df.shape}")
    print(f"  Columns: {df.columns.tolist()}")

    # Validate required columns
    required = ["Phone Number", "Country", "Category", "Severity", "Pattern / Notes", "Source"]
    missing_cols = [c for c in required if c not in df.columns]
    if missing_cols:
        raise ValueError(f"Missing required columns: {missing_cols}")

    # Basic stats
    print(f"\n  Category distribution:")
    for cat, cnt in df["Category"].value_counts().items():
        print(f"    {cat:<22} {cnt:>5}")
    print(f"\n  Severity distribution:")
    for sev, cnt in df["Severity"].value_counts().items():
        print(f"    {sev:<12} {cnt:>5}")
    print(f"\n  Null values: {df.isnull().sum().sum()} total")

    return df


# ── Step 2: Validate & convert to suspicious_calls.csv format ──────────────────
def convert_to_calls_format(df: pd.DataFrame) -> pd.DataFrame:
    """
    Convert the Indian phone numbers DataFrame into the 3-column format
    used by the notebook pipeline: content, label, source.

    content format mirrors FCC data so that extract_phone() still works:
    "Unwanted call received. Caller phone: +91XXXXXXXXXX. Category: Lottery Scam.
     Pattern: <Pattern/Notes text>"
    """
    print(f"\n{'='*70}")
    print("STEP 2: Converting to suspicious_calls.csv format")
    print(f"{'='*70}")

    total_rows  = len(df)
    invalid_rows = 0
    records = []

    for _, row in df.iterrows():
        phone_raw = str(row["Phone Number"]).strip()
        country   = str(row["Country"]).strip()
        category  = str(row["Category"]).strip()
        severity  = str(row["Severity"]).strip()
        pattern   = str(row["Pattern / Notes"]).strip()
        source    = str(row["Source"]).strip()

        # Validate phone number (must be numeric / start with + or digits)
        phone_clean = re.sub(r"[^\d+]", "", phone_raw)
        if len(phone_clean) < 7:
            invalid_rows += 1
            continue

        # Ensure +91 prefix for Indian numbers
        if not phone_clean.startswith("+"):
            phone_clean = "+" + phone_clean

        label = map_label(category, severity)

        # Build content string in the same style as FCC call reports
        content = (
            f"Unwanted call received. Caller phone: {phone_clean}. "
            f"Country: {country}. Category: {category}. "
            f"Pattern: {pattern}"
        )

        records.append({
            "content": content,
            "label":   label,
            "source":  f"Indian-PhoneNumbers/{source}",
        })

    converted = pd.DataFrame(records)

    valid = len(converted)
    malicious = int(converted["label"].sum())
    benign    = valid - malicious

    print(f"  Total rows in Excel:    {total_rows:,}")
    print(f"  Invalid/skipped rows:   {invalid_rows:,}")
    print(f"  Valid converted rows:   {valid:,}")
    print(f"    → Malicious (label=1): {malicious:,}")
    print(f"    → Benign   (label=0): {benign:,}")

    return converted


# ── Step 3: Merge with existing suspicious_calls.csv ──────────────────────────
def merge_with_existing(new_df: pd.DataFrame, calls_csv: str) -> dict:
    """
    Load existing suspicious_calls.csv, append new records, deduplicate on
    (content, label) exactly as the notebook does, then save back.
    Returns merge statistics.
    """
    print(f"\n{'='*70}")
    print("STEP 3: Merging with existing suspicious_calls.csv")
    print(f"{'='*70}")

    stats = {}

    if os.path.exists(calls_csv):
        print(f"  Loading existing: {calls_csv}")
        existing = pd.read_csv(
            calls_csv,
            usecols=["content", "label", "source"],
            dtype={"content": "string", "label": "Int64", "source": "string"},
            engine="c",
            low_memory=True,
        )
        existing["label"] = existing["label"].fillna(-1).astype(int)
        existing_count = len(existing)
        print(f"  Existing rows: {existing_count:,}")
    else:
        print(f"  [WARN] {calls_csv} not found — creating new file.")
        existing = pd.DataFrame(columns=["content", "label", "source"])
        existing_count = 0

    stats["existing_rows"] = existing_count

    # Back up original
    if os.path.exists(calls_csv):
        backup = calls_csv.replace(".csv", "_backup_before_indian.csv")
        shutil.copy2(calls_csv, backup)
        print(f"  Backup saved: {backup}")

    # Merge
    merged = pd.concat([existing, new_df], axis=0, ignore_index=True)
    before_dedup = len(merged)

    # Deduplicate on (content, label) — same as notebook
    merged = merged.drop_duplicates(subset=["content", "label"], keep="first")
    after_dedup = len(merged)

    duplicates_skipped = before_dedup - after_dedup
    new_rows_added = after_dedup - existing_count

    print(f"  New rows from Excel:         {len(new_df):,}")
    print(f"  Duplicate rows skipped:      {duplicates_skipped:,}")
    print(f"  Net new rows added:          {new_rows_added:,}")
    print(f"  Total rows after merge:      {after_dedup:,}")

    # Save merged CSV
    print(f"  Saving merged CSV ...")
    merged.to_csv(calls_csv, index=False)
    print(f"  Saved: {calls_csv}")

    stats["new_rows_from_excel"]  = len(new_df)
    stats["duplicates_skipped"]   = duplicates_skipped
    stats["net_new_rows_added"]   = new_rows_added
    stats["total_rows_after_merge"] = after_dedup

    del existing, merged
    gc.collect()
    return stats


# ── Step 4: Retrain CatBoost model ────────────────────────────────────────────
def retrain_model(iterations: int = 300) -> dict:
    """
    Invoke train_catboost_notebook.py as a subprocess to retrain with the
    updated suspicious_calls.csv. Streams output live.
    """
    print(f"\n{'='*70}")
    print(f"STEP 4: Retraining CatBoost model ({iterations} iterations)")
    print(f"{'='*70}")
    print("  This may take several minutes. Output streamed live...")

    train_script = os.path.join(_HERE, "train_catboost_notebook.py")
    if not os.path.exists(train_script):
        return {"success": False, "error": f"Training script not found: {train_script}"}

    t0 = time.time()
    try:
        result = subprocess.run(
            [sys.executable, train_script, "--iterations", str(iterations)],
            cwd=os.path.dirname(_HERE),   # project root
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        elapsed = time.time() - t0

        if result.returncode == 0:
            print(f"\n  [OK] Model retrained in {elapsed:.1f}s")
            # Verify output files
            cbm_path = os.path.join(MODELS_DIR, "catboost_notebook.cbm")
            vec_path = os.path.join(MODELS_DIR, "tfidf_vectorizer.pkl")
            model_ok = os.path.exists(cbm_path)
            vec_ok   = os.path.exists(vec_path)
            print(f"  catboost_notebook.cbm: {'✓' if model_ok else '✗'} "
                  f"({os.path.getsize(cbm_path)/1024:.1f} KB)" if model_ok else "  catboost_notebook.cbm: ✗ NOT FOUND")
            print(f"  tfidf_vectorizer.pkl:  {'✓' if vec_ok else '✗'} "
                  f"({os.path.getsize(vec_path)/1024:.1f} KB)" if vec_ok else "  tfidf_vectorizer.pkl: ✗ NOT FOUND")
            return {
                "success":         True,
                "iterations":      iterations,
                "train_time_sec":  round(elapsed, 1),
                "model_path":      cbm_path if model_ok else None,
                "vectorizer_path": vec_path if vec_ok else None,
            }
        else:
            return {
                "success":  False,
                "error":    f"Training script exited with code {result.returncode}",
                "train_time_sec": round(elapsed, 1),
            }
    except Exception as exc:
        return {"success": False, "error": str(exc)}


# ── Step 5: MySQL import ───────────────────────────────────────────────────────
def import_to_mysql(
    new_df_raw: pd.DataFrame,
    excel_df: pd.DataFrame,
    host: str, port: int, user: str, password: str, db: str,
    batch_size: int,
    dry_run: bool,
) -> dict:
    """
    Import the new Indian phone records into MySQL suspicious_calls + threats.
    Uses INSERT IGNORE to skip duplicates based on phone_number.
    """
    print(f"\n{'='*70}")
    print("STEP 5: Importing to MySQL")
    print(f"{'='*70}")

    if dry_run:
        print("  [DRY-RUN] Skipping MySQL import.")
        print(f"  Would insert {len(new_df_raw):,} rows into suspicious_calls")
        print(f"  Would insert {len(new_df_raw):,} rows into threats")
        return {
            "dry_run":             True,
            "would_insert_calls":  len(new_df_raw),
            "would_insert_threats": len(new_df_raw),
        }

    try:
        import mysql.connector
        from mysql.connector import errorcode
    except ImportError:
        print("  [INFO] mysql-connector-python not found, installing...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", "mysql-connector-python"])
        import mysql.connector
        from mysql.connector import errorcode

    try:
        conn = mysql.connector.connect(
            host=host, port=port, user=user, password=password,
            database=db, charset="utf8mb4", connection_timeout=600,
        )
        print(f"  [OK] Connected to MySQL: {user}@{host}:{port}/{db}")
    except mysql.connector.Error as err:
        msg = f"MySQL connection failed: {err}"
        print(f"  [ERROR] {msg}")
        return {"success": False, "error": msg}

    now = utcnow()

    # --- Build rows for suspicious_calls table ---
    sql_calls = """
        INSERT IGNORE INTO suspicious_calls
            (phone_number, country, severity, pattern, detected_at)
        VALUES (%s, %s, %s, %s, %s)
    """
    sql_threats = """
        INSERT IGNORE INTO threats
            (title, type, severity, description, source, detected_at)
        VALUES (%s, %s, %s, %s, %s, %s)
    """

    call_rows   = []
    threat_rows = []

    phone_re = re.compile(r"Caller phone:\s*([\d+\-\s]+)")

    for _, row in new_df_raw.iterrows():
        content  = str(row["content"])
        label    = int(row["label"])
        source   = str(row["source"])
        sev_str  = "high" if label == 1 else "low"

        m = phone_re.search(content)
        phone = m.group(1).strip()[:64] if m else content[:64]

        # Extract country from content ("Country: India")
        m2 = re.search(r"Country:\s*([^.]+)\.", content)
        country = m2.group(1).strip()[:64] if m2 else "India"

        call_rows.append((phone, country, sev_str, content[:500], now))
        threat_rows.append((phone[:255], "suspicious_call", sev_str, content[:500], source[:255], now))

    cursor = conn.cursor()

    # Disable checks for speed
    for cmd in ["SET SESSION foreign_key_checks=0", "SET SESSION unique_checks=0"]:
        try:
            cursor.execute(cmd)
        except Exception:
            pass
    conn.commit()

    inserted_calls   = 0
    inserted_threats = 0

    for i in range(0, len(call_rows), batch_size):
        chunk = call_rows[i: i + batch_size]
        cursor.executemany(sql_calls, chunk)
        inserted_calls += cursor.rowcount
    conn.commit()

    for i in range(0, len(threat_rows), batch_size):
        chunk = threat_rows[i: i + batch_size]
        cursor.executemany(sql_threats, chunk)
        inserted_threats += cursor.rowcount
    conn.commit()

    # Re-enable
    for cmd in ["SET SESSION foreign_key_checks=1", "SET SESSION unique_checks=1"]:
        try:
            cursor.execute(cmd)
        except Exception:
            pass
    conn.commit()

    # Get total count in table
    cursor.execute("SELECT COUNT(*) FROM suspicious_calls")
    total_in_table = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM suspicious_calls WHERE country='India'")
    india_count = cursor.fetchone()[0]

    cursor.close()
    conn.close()

    print(f"  Inserted into suspicious_calls: {inserted_calls:,}")
    print(f"  Inserted into threats:          {inserted_threats:,}")
    print(f"  Total rows in suspicious_calls: {total_in_table:,}")
    print(f"  Indian records in table:        {india_count:,}")

    return {
        "success":                True,
        "inserted_calls":         inserted_calls,
        "inserted_threats":       inserted_threats,
        "total_in_table":         total_in_table,
        "india_records_in_table": india_count,
    }


# ── Step 6: Verify model predictions on Indian numbers ────────────────────────
def verify_predictions(sample_phones: list) -> list:
    """Quick sanity check — run 5 sample Indian phone numbers through the model."""
    print(f"\n{'='*70}")
    print("STEP 6: Verifying model predictions on sample Indian numbers")
    print(f"{'='*70}")

    results = []
    try:
        import joblib
        from catboost import CatBoostClassifier

        cbm_path = os.path.join(MODELS_DIR, "catboost_notebook.cbm")
        vec_path  = os.path.join(MODELS_DIR, "tfidf_vectorizer.pkl")

        if not (os.path.exists(cbm_path) and os.path.exists(vec_path)):
            print("  [WARN] Model files not found — skipping prediction verification.")
            return []

        model = CatBoostClassifier()
        model.load_model(cbm_path)
        vectorizer = joblib.load(vec_path)

        for phone_content in sample_phones:
            X = vectorizer.transform([phone_content])
            pred  = int(model.predict(X)[0])
            proba = float(model.predict_proba(X)[0][1])
            label = "Malicious" if pred == 1 else "Benign"
            print(f"  {phone_content[:80]:<80} → {label} ({proba:.2%})")
            results.append({"content": phone_content[:80], "prediction": label, "confidence": round(proba, 4)})
    except Exception as exc:
        print(f"  [WARN] Prediction check failed: {exc}")

    return results


# ── Main ───────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Indian Phone Numbers Dataset Integrator")
    parser.add_argument("--excel",        default=EXCEL_PATH,          help="Path to Excel file")
    parser.add_argument("--host",         default="localhost",          help="MySQL host")
    parser.add_argument("--port",         type=int, default=3306,       help="MySQL port")
    parser.add_argument("--user",         default="root",               help="MySQL user")
    parser.add_argument("--password",     default="",                   help="MySQL password")
    parser.add_argument("--db",           default="threat_intelligence_db", help="Database name")
    parser.add_argument("--batch",        type=int, default=2000,       help="MySQL batch size")
    parser.add_argument("--dry-run",      action="store_true",          help="Skip MySQL import")
    parser.add_argument("--fast",         action="store_true",          help="50 CatBoost iterations (~5 min)")
    parser.add_argument("--full-retrain", action="store_true",          help="300 iterations (default)")
    parser.add_argument("--skip-retrain", action="store_true",          help="Skip model retraining")
    args = parser.parse_args()

    iterations = 50 if args.fast else 300
    if args.fast:
        print(f"[INFO] FAST MODE: {iterations} iterations")

    start_ts = time.time()
    summary = {
        "timestamp":    utcnow(),
        "excel_file":   args.excel,
        "dry_run":      args.dry_run,
        "iterations":   iterations,
    }

    print("\n" + "="*70)
    print("  INDIAN PHONE NUMBERS — THREAT INTELLIGENCE INTEGRATOR")
    print("="*70)

    # ── Step 1: Load Excel ────────────────────────────────────────────────────
    excel_df = load_excel(args.excel)

    # ── Step 2: Convert to calls format ──────────────────────────────────────
    converted_df = convert_to_calls_format(excel_df)

    summary["excel_total_rows"]     = len(excel_df)
    summary["converted_valid_rows"] = len(converted_df)
    summary["malicious_count"]      = int(converted_df["label"].sum())
    summary["benign_count"]         = len(converted_df) - int(converted_df["label"].sum())

    # ── Step 3: Merge with existing suspicious_calls.csv ─────────────────────
    merge_stats = merge_with_existing(converted_df, CALLS_CSV)
    summary.update(merge_stats)

    # ── Step 4: Retrain model ─────────────────────────────────────────────────
    if args.skip_retrain:
        print(f"\n{'='*70}")
        print("STEP 4: Skipping model retraining (--skip-retrain)")
        print(f"{'='*70}")
        retrain_stats = {"success": False, "skipped": True}
    else:
        retrain_stats = retrain_model(iterations=iterations)

    summary["retrain"] = retrain_stats

    # ── Step 5: MySQL import ──────────────────────────────────────────────────
    mysql_stats = import_to_mysql(
        new_df_raw=converted_df,
        excel_df=excel_df,
        host=args.host, port=args.port,
        user=args.user, password=args.password, db=args.db,
        batch_size=args.batch,
        dry_run=args.dry_run,
    )
    summary["mysql"] = mysql_stats

    # ── Step 6: Verify predictions ────────────────────────────────────────────
    sample_contents = converted_df.head(5)["content"].tolist() if len(converted_df) >= 5 else []
    if not args.skip_retrain and retrain_stats.get("success"):
        verify_results = verify_predictions(sample_contents)
        summary["sample_predictions"] = verify_results

    # ── Final summary ─────────────────────────────────────────────────────────
    elapsed = time.time() - start_ts
    summary["total_elapsed_sec"] = round(elapsed, 1)

    # Save summary JSON
    os.makedirs(os.path.dirname(SUMMARY_JSON), exist_ok=True)
    with open(SUMMARY_JSON, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, default=str)

    print(f"\n{'='*70}")
    print("  INTEGRATION COMPLETE — SUMMARY")
    print(f"{'='*70}")
    print(f"  ┌─ Excel file                  {args.excel}")
    print(f"  │  Records in Excel:            {summary.get('excel_total_rows', '?'):,}")
    print(f"  │  Valid converted records:     {summary.get('converted_valid_rows', '?'):,}")
    print(f"  │    Malicious (label=1):       {summary.get('malicious_count', '?'):,}")
    print(f"  │    Benign    (label=0):       {summary.get('benign_count', '?'):,}")
    print(f"  │")
    print(f"  ├─ Dataset Merge (suspicious_calls.csv)")
    print(f"  │  Existing rows:               {summary.get('existing_rows', '?'):,}")
    print(f"  │  New rows from Excel:         {summary.get('new_rows_from_excel', '?'):,}")
    print(f"  │  Duplicate rows skipped:      {summary.get('duplicates_skipped', '?'):,}")
    print(f"  │  Net new rows added:          {summary.get('net_new_rows_added', '?'):,}")
    print(f"  │  Total rows after merge:      {summary.get('total_rows_after_merge', '?'):,}")
    print(f"  │")

    rt = summary.get("retrain", {})
    if rt.get("skipped"):
        print(f"  ├─ ML Model Retraining:        SKIPPED")
    elif rt.get("success"):
        print(f"  ├─ ML Model Retraining:        ✓ SUCCESS")
        print(f"  │  Iterations:                  {rt.get('iterations', '?')}")
        print(f"  │  Training time:               {rt.get('train_time_sec', '?')}s")
        print(f"  │  Model:                       {rt.get('model_path', '?')}")
        print(f"  │  Vectorizer:                  {rt.get('vectorizer_path', '?')}")
    else:
        print(f"  ├─ ML Model Retraining:        ✗ FAILED — {rt.get('error', 'unknown error')}")

    mysql = summary.get("mysql", {})
    if mysql.get("dry_run"):
        print(f"  ├─ MySQL Import:               DRY-RUN (not inserted)")
        print(f"  │  Would insert:                {mysql.get('would_insert_calls', '?'):,} rows")
    elif mysql.get("success"):
        print(f"  ├─ MySQL Import:               ✓ SUCCESS")
        print(f"  │  Inserted (suspicious_calls): {mysql.get('inserted_calls', '?'):,}")
        print(f"  │  Inserted (threats):          {mysql.get('inserted_threats', '?'):,}")
        print(f"  │  Total in suspicious_calls:   {mysql.get('total_in_table', '?'):,}")
        print(f"  │  Indian records in table:     {mysql.get('india_records_in_table', '?'):,}")
    else:
        print(f"  ├─ MySQL Import:               ✗ FAILED — {mysql.get('error', 'unknown')}")

    print(f"  │")
    print(f"  └─ Total elapsed:               {elapsed:.1f}s")
    print(f"\n  Summary saved: {SUMMARY_JSON}")
    print(f"{'='*70}")

    if retrain_stats.get("success"):
        print("\n  ✓ ML model retrained with Indian phone numbers.")
        print("  ✓ API will use updated catboost_notebook.cbm + tfidf_vectorizer.pkl on next restart.")
        print("  ✓ Restart the Flask API: .venv\\Scripts\\python.exe ML/api/app.py")


if __name__ == "__main__":
    main()

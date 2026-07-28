"""
ML/import_to_mysql.py
======================
Imports all 5 CSV datasets into MySQL using the EXACT same preprocessing
pipeline as the Google Colab notebook (ML_Training_CatBoost_70_30 (1).ipynb):

  1. Load each CSV (content, label, source columns)
  2. Normalize labels with normalize_label()
  3. Drop NaN in content / label / source
  4. Drop exact duplicates on (content, label)

Then maps each dataset to its corresponding MySQL table and inserts in batches.

TABLE MAPPING:
  email_scams.csv      -> email_scams       (sender=content, subject=content[:500])
  phishing_urls.csv    -> phishing_urls     (url=content, domain=extracted from url)
  malicious_ips.csv    -> malicious_ips     (ip_address=content)
  suspicious_calls.csv -> suspicious_calls  (phone_number=extracted, pattern=content)
  scam_messages.csv    -> scam_messages     (content=content)

ALSO inserts into the unified threats table for dashboard views.

Usage:
    .venv\\Scripts\\python.exe ML/import_to_mysql.py

Options:
    --host HOST          MySQL host (default: localhost)
    --port PORT          MySQL port (default: 3306)
    --user USER          MySQL user (default: root)
    --password PASSWORD  MySQL password (default: empty)
    --db DB              Database name (default: threat_intelligence_db)
    --batch N            Batch insert size (default: 2000)
    --dry-run            Print counts without inserting
"""

import os
import sys
import io
import gc
import re
import argparse
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")
import numpy as np
import pandas as pd
import mysql.connector
from mysql.connector import errorcode
from datetime import datetime, timezone

def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

# ── Constants ─────────────────────────────────────────────────────────────────
DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "data"))
RANDOM_STATE = 42

DATASET_FILES = [
    "email_scams.csv",
    "phishing_urls.csv",
    "malicious_ips.csv",
    "suspicious_calls.csv",
    "scam_messages.csv",
]

# ── Label normaliser (exact copy from notebook) ────────────────────────────────
def normalize_label(val):
    if pd.isna(val):
        return np.nan
    if isinstance(val, (int, np.integer)):
        return 1 if val == 1 else 0
    s = str(val).strip().lower()
    if s in {"1", "malicious", "phishing", "spam", "scam", "bad", "true"}:
        return 1
    if s in {"0", "benign", "ham", "legit", "legitimate", "good", "false"}:
        return 0
    try:
        return 1 if float(s) == 1 else 0
    except ValueError:
        return np.nan


def severity_from_label(label: int) -> str:
    return "high" if label == 1 else "low"


def extract_domain(url: str) -> str:
    """Extract domain from a URL string."""
    try:
        m = re.match(r"https?://([^/]+)", str(url).strip())
        if m:
            return m.group(1)[:255]
    except Exception:
        pass
    return ""


def extract_phone(text: str) -> str:
    """Extract phone number from FCC call report text."""
    m = re.search(r"Caller phone:\s*([\d\-\(\)\s\.]+)", str(text))
    if m:
        return m.group(1).strip()[:64]
    # Fallback: first 64 chars
    return str(text).strip()[:64]


def preprocess_csv(fpath: str) -> pd.DataFrame:
    """Load and preprocess a CSV exactly as in the notebook."""
    print(f"  Loading {os.path.basename(fpath)} ...")
    df = pd.read_csv(
        fpath,
        usecols=["content", "label", "source"],
        dtype={"content": "string", "label": "Int64", "source": "string"},
        engine="c",
        low_memory=True,
    )
    size_before = len(df)

    df["label"] = df["label"].apply(normalize_label)
    df = df.dropna(subset=["content", "label", "source"])
    df = df.drop_duplicates(subset=["content", "label"], keep="first")
    df["label"] = df["label"].astype(int)

    size_after = len(df)
    print(f"    {size_before:,} rows loaded → {size_after:,} after dedup/dropna "
          f"({size_before - size_after:,} removed)")
    return df.reset_index(drop=True)


def batch_insert(cursor, sql: str, rows: list, batch_size: int = 2000):
    """Insert rows in batches and return the count inserted."""
    total = 0
    for i in range(0, len(rows), batch_size):
        chunk = rows[i: i + batch_size]
        cursor.executemany(sql, chunk)
        total += len(chunk)
    return total


def import_email_scams(df: pd.DataFrame, cursor, conn, batch_size: int, dry_run: bool):
    """Import email_scams.csv → email_scams table + threats table."""
    sql_email = """
        INSERT INTO email_scams (sender, subject, category, severity, recipients_count, detected_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """
    sql_threat = """
        INSERT INTO threats (title, type, severity, description, source, detected_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """
    now = utcnow()
    email_rows = []
    threat_rows = []

    for _, row in df.iterrows():
        raw_content = str(row["content"])
        content_sliced = raw_content[:60000]
        sev = severity_from_label(int(row["label"]))
        email_rows.append((
            raw_content[:255],   # sender (use content as sender for raw data)
            raw_content[:500],   # subject
            "EMAIL_SCAM",        # category
            sev,
            1,                   # recipients_count
            now,
        ))
        threat_rows.append((
            raw_content[:255],   # title
            "email_scam",        # type
            sev,
            content_sliced,      # description
            str(row["source"])[:255],
            now,
        ))

    if dry_run:
        print(f"    [DRY-RUN] Would insert {len(email_rows):,} email_scams rows")
        return len(email_rows)

    count = batch_insert(cursor, sql_email, email_rows, batch_size)
    conn.commit()
    batch_insert(cursor, sql_threat, threat_rows, batch_size)
    conn.commit()
    print(f"    Inserted {count:,} rows into email_scams")
    return count


def import_phishing_urls(df: pd.DataFrame, cursor, conn, batch_size: int, dry_run: bool):
    sql = """
        INSERT INTO phishing_urls (url, domain, severity, notes, detected_at)
        VALUES (?, ?, ?, ?, ?)
    """
    sql_threat = """
        INSERT INTO threats (title, type, severity, description, source, detected_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """
    now = utcnow()
    url_rows = []
    threat_rows = []

    for _, row in df.iterrows():
        url = str(row["content"])[:2048]
        domain = extract_domain(url)
        sev = severity_from_label(int(row["label"]))
        url_rows.append((url, domain or None, sev, None, now))
        threat_rows.append((url[:255], "phishing_url", sev, url, str(row["source"])[:255], now))

    if dry_run:
        print(f"    [DRY-RUN] Would insert {len(url_rows):,} phishing_urls rows")
        return len(url_rows)

    count = batch_insert(cursor, sql, url_rows, batch_size)
    conn.commit()
    batch_insert(cursor, sql_threat, threat_rows, batch_size)
    conn.commit()
    print(f"    Inserted {count:,} rows into phishing_urls")
    return count


def import_malicious_ips(df: pd.DataFrame, cursor, conn, batch_size: int, dry_run: bool):
    sql = """
        INSERT INTO malicious_ips (ip_address, country, threat_type, severity, detected_at)
        VALUES (?, ?, ?, ?, ?)
    """
    sql_threat = """
        INSERT INTO threats (title, type, severity, description, source, detected_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """
    now = utcnow()
    ip_rows = []
    threat_rows = []

    for _, row in df.iterrows():
        ip = str(row["content"])[:64]
        sev = severity_from_label(int(row["label"]))
        ip_rows.append((ip, None, "MALICIOUS_IP", sev, now))
        threat_rows.append((ip, "malicious_ip", sev, ip, str(row["source"])[:255], now))

    if dry_run:
        print(f"    [DRY-RUN] Would insert {len(ip_rows):,} malicious_ips rows")
        return len(ip_rows)

    count = batch_insert(cursor, sql, ip_rows, batch_size)
    conn.commit()
    batch_insert(cursor, sql_threat, threat_rows, batch_size)
    conn.commit()
    print(f"    Inserted {count:,} rows into malicious_ips")
    return count


def import_suspicious_calls(df: pd.DataFrame, cursor, conn, batch_size: int, dry_run: bool):
    sql = """
        INSERT INTO suspicious_calls (phone_number, country, severity, pattern, detected_at)
        VALUES (?, ?, ?, ?, ?)
    """
    sql_threat = """
        INSERT INTO threats (title, type, severity, description, source, detected_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """
    now = utcnow()
    call_rows = []
    threat_rows = []

    for _, row in df.iterrows():
        content = str(row["content"])
        phone = extract_phone(content)
        sev = severity_from_label(int(row["label"]))
        call_rows.append((phone, None, sev, content[:500], now))
        threat_rows.append((phone, "suspicious_call", sev, content[:500], str(row["source"])[:255], now))

    if dry_run:
        print(f"    [DRY-RUN] Would insert {len(call_rows):,} suspicious_calls rows")
        return len(call_rows)

    count = batch_insert(cursor, sql, call_rows, batch_size)
    conn.commit()
    batch_insert(cursor, sql_threat, threat_rows, batch_size)
    conn.commit()
    print(f"    Inserted {count:,} rows into suspicious_calls")
    return count


def import_scam_messages(df: pd.DataFrame, cursor, conn, batch_size: int, dry_run: bool):
    sql = """
        INSERT INTO scam_messages (channel, sender, content, severity, detected_at)
        VALUES (?, ?, ?, ?, ?)
    """
    sql_threat = """
        INSERT INTO threats (title, type, severity, description, source, detected_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """
    now = utcnow()
    msg_rows = []
    threat_rows = []

    for _, row in df.iterrows():
        raw_content = str(row["content"])
        content_sliced = raw_content[:60000]
        sev = severity_from_label(int(row["label"]))
        msg_rows.append(("sms", None, content_sliced, sev, now))
        threat_rows.append((raw_content[:255], "scam_message", sev, content_sliced, str(row["source"])[:255], now))

    if dry_run:
        print(f"    [DRY-RUN] Would insert {len(msg_rows):,} scam_messages rows")
        return len(msg_rows)

    count = batch_insert(cursor, sql, msg_rows, batch_size)
    conn.commit()
    batch_insert(cursor, sql_threat, threat_rows, batch_size)
    conn.commit()
    print(f"    Inserted {count:,} rows into scam_messages")
    return count


IMPORTERS = {
    "email_scams.csv":      import_email_scams,
    "phishing_urls.csv":    import_phishing_urls,
    "malicious_ips.csv":    import_malicious_ips,
    "suspicious_calls.csv": import_suspicious_calls,
    "scam_messages.csv":    import_scam_messages,
}


def main():
    parser = argparse.ArgumentParser(description="Import CSV datasets into MySQL")
    parser.add_argument("--host",     default="localhost")
    parser.add_argument("--port",     type=int, default=3306)
    parser.add_argument("--user",     default="root")
    parser.add_argument("--password", default="")
    parser.add_argument("--db",       default="threat_intelligence_db")
    parser.add_argument("--batch",    type=int, default=2000, help="Batch insert size")
    parser.add_argument("--dry-run",  action="store_true", help="Count rows without inserting")
    args = parser.parse_args()

    print("=" * 70)
    print("Threat Intelligence DB — Full Dataset Importer")
    print(f"Target DB: {args.user}@{args.host}:{args.port}/{args.db}")
    print("=" * 70)

    conn = None
    cursor = None

    if not args.dry_run:
        try:
            conn = mysql.connector.connect(
                host=args.host,
                port=args.port,
                user=args.user,
                password=args.password,
                database=args.db,
                charset="utf8mb4",
                connection_timeout=600,
                allow_local_infile=True,
            )
            # Use a regular cursor for SET commands (prepared cursor can't run them)
            regular_cursor = conn.cursor()
            for cmd in [
                "SET SESSION foreign_key_checks=0",
                "SET SESSION unique_checks=0",
            ]:
                try:
                    regular_cursor.execute(cmd)
                except Exception as e:
                    print(f"  [INFO] Skipping optimization '{cmd}': {e}")
            conn.commit()
            regular_cursor.close()

            # Use a prepared cursor for all data inserts (handles special chars safely)
            cursor = conn.cursor(prepared=True)
            print("[OK] Connected to MySQL.")
        except mysql.connector.Error as err:
            if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
                print("[ERROR] MySQL access denied. Check user/password.")
            elif err.errno == errorcode.ER_BAD_DB_ERROR:
                print(f"[ERROR] Database '{args.db}' does not exist. Run schema.sql first.")
            else:
                print(f"[ERROR] MySQL connection failed: {err}")
            sys.exit(1)

    grand_total = 0
    start_ts = __import__("time").time()

    for fname in DATASET_FILES:
        fpath = os.path.join(DATA_DIR, fname)
        if not os.path.exists(fpath):
            print(f"\n[WARN] Missing file: {fpath} - skipping")
            continue

        print(f"\n{'-' * 70}")
        print(f"Processing: {fname}")
        print(f"{'-' * 70}")

        df = preprocess_csv(fpath)
        gc.collect()

        importer = IMPORTERS[fname]
        count = importer(df, cursor, conn, args.batch, args.dry_run)
        grand_total += count
        del df
        gc.collect()

    elapsed = __import__("time").time() - start_ts
    print(f"\n{'=' * 70}")
    print(f"DONE. Total rows inserted: {grand_total:,}  ({elapsed:.1f}s)")
    print("=" * 70)

    if not args.dry_run and conn:
        # Re-enable constraints
        cursor.execute("SET SESSION foreign_key_checks=1")
        cursor.execute("SET SESSION unique_checks=1")
        conn.commit()
        cursor.close()
        conn.close()

    # Verification instructions
    print("\nVerify in MySQL with:")
    print("  SELECT 'email_scams'      AS tbl, COUNT(*) AS cnt FROM email_scams")
    print("  UNION SELECT 'phishing_urls', COUNT(*) FROM phishing_urls")
    print("  UNION SELECT 'malicious_ips', COUNT(*) FROM malicious_ips")
    print("  UNION SELECT 'suspicious_calls', COUNT(*) FROM suspicious_calls")
    print("  UNION SELECT 'scam_messages', COUNT(*) FROM scam_messages;")


if __name__ == "__main__":
    main()

"""
fast_retrain.py - Optimized retraining of IP and Email models (CatBoost + XGBoost)
Uses pre-downloaded CSVs. No HuggingFace downloads. Real-time stdout progress.
"""
import os, sys, time, json, warnings, socket, struct
import numpy as np
import pandas as pd
import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.colors import LinearSegmentedColormap

warnings.filterwarnings("ignore")

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, classification_report,
    roc_curve, auc as sk_auc, precision_recall_curve, average_precision_score
)
import xgboost as xgb
from catboost import CatBoostClassifier, Pool

# ── Paths ────────────────────────────────────────────────────────────────────
DATA_DIR  = "ML/data"
MODELS_DIR = "ML/models"
EVAL_DIR   = "ML/evaluation"
os.makedirs(EVAL_DIR, exist_ok=True)
os.makedirs(MODELS_DIR, exist_ok=True)

SPLITS = [("80:20", 0.20), ("70:30", 0.30), ("60:40", 0.40)]
ALL_RESULTS = {}

def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)

# ── Dark-theme plot helper ────────────────────────────────────────────────────
DARK_FG  = "white"
DARK_BG  = "#0d1117"
DARK_AX  = "#111827"
DARK_GRID= "#374151"
CMAP_CM  = LinearSegmentedColormap.from_list("tc", ["#0d1117", "#1a2744", "#2563eb", "#60a5fa"])

def dark_fig(w=8, h=6):
    fig, ax = plt.subplots(figsize=(w, h))
    fig.patch.set_facecolor(DARK_BG)
    ax.set_facecolor(DARK_AX)
    for spine in ax.spines.values():
        spine.set_color(DARK_GRID)
    ax.tick_params(colors=DARK_FG)
    return fig, ax

def save_confusion_matrix(y_true, y_pred, model_name, split_label, dest_dir):
    cm = confusion_matrix(y_true, y_pred)
    fig, ax = dark_fig()
    im = ax.imshow(cm, cmap=CMAP_CM)
    ax.set_title(f"{model_name} — Confusion Matrix ({split_label})", color=DARK_FG, fontsize=13, fontweight="bold")
    ax.set_xlabel("Predicted", color="#94a3b8"); ax.set_ylabel("Actual", color="#94a3b8")
    ax.set_xticks([0,1]); ax.set_yticks([0,1])
    ax.set_xticklabels(["Benign","Malicious"], color=DARK_FG)
    ax.set_yticklabels(["Benign","Malicious"], color=DARK_FG)
    for i in range(2):
        for j in range(2):
            ax.text(j, i, str(cm[i,j]), ha="center", va="center", color=DARK_FG, fontsize=16, fontweight="bold")
    plt.colorbar(im, ax=ax)
    plt.tight_layout()
    fname = os.path.join(dest_dir, f"cm_{model_name.lower()}.png")
    plt.savefig(fname, dpi=130, bbox_inches="tight", facecolor=DARK_BG)
    plt.close()
    log(f"  Saved {fname}")

def save_roc(y_true, y_prob, model_name, split_label, dest_dir):
    fpr, tpr, _ = roc_curve(y_true, y_prob)
    val = sk_auc(fpr, tpr)
    fig, ax = dark_fig()
    ax.plot(fpr, tpr, color="#3b82f6", lw=2, label=f"AUC = {val:.4f}")
    ax.plot([0,1],[0,1], color="#475569", lw=1, linestyle="--")
    ax.fill_between(fpr, tpr, alpha=0.12, color="#3b82f6")
    ax.set_xlim([0,1]); ax.set_ylim([0,1.05])
    ax.set_xlabel("False Positive Rate", color="#94a3b8"); ax.set_ylabel("True Positive Rate", color="#94a3b8")
    ax.set_title(f"{model_name} — ROC Curve ({split_label})", color=DARK_FG, fontsize=13, fontweight="bold")
    leg = ax.legend(fontsize=10, fancybox=True, framealpha=0.3)
    leg.get_frame().set_facecolor("#1e293b")
    for t in leg.get_texts(): t.set_color(DARK_FG)
    plt.tight_layout()
    fname = os.path.join(dest_dir, f"roc_{model_name.lower()}.png")
    plt.savefig(fname, dpi=130, bbox_inches="tight", facecolor=DARK_BG)
    plt.close()
    log(f"  Saved {fname}")

def save_pr_curve(y_true, y_prob, model_name, split_label, dest_dir):
    p, r, _ = precision_recall_curve(y_true, y_prob)
    ap = average_precision_score(y_true, y_prob)
    fig, ax = dark_fig()
    ax.plot(r, p, color="#10b981", lw=2, label=f"AP = {ap:.4f}")
    ax.fill_between(r, p, alpha=0.12, color="#10b981")
    ax.set_xlim([0,1]); ax.set_ylim([0,1.05])
    ax.set_xlabel("Recall", color="#94a3b8"); ax.set_ylabel("Precision", color="#94a3b8")
    ax.set_title(f"{model_name} — Precision-Recall Curve ({split_label})", color=DARK_FG, fontsize=13, fontweight="bold")
    leg = ax.legend(fontsize=10, fancybox=True, framealpha=0.3)
    leg.get_frame().set_facecolor("#1e293b")
    for t in leg.get_texts(): t.set_color(DARK_FG)
    plt.tight_layout()
    fname = os.path.join(dest_dir, f"pr_{model_name.lower()}.png")
    plt.savefig(fname, dpi=130, bbox_inches="tight", facecolor=DARK_BG)
    plt.close()
    log(f"  Saved {fname}")

def save_feature_importance(importances, model_name, dest_dir, color="#3b82f6"):
    top_n = min(20, len(importances))
    idx = np.argsort(importances)[-top_n:]
    vals = importances[idx]
    labels = [f"Feature {i}" for i in idx]
    fig, ax = dark_fig(10, 7)
    colors = plt.cm.Blues(np.linspace(0.4, 1.0, top_n))
    ax.barh(range(top_n), vals, color=colors)
    ax.set_yticks(range(top_n)); ax.set_yticklabels(labels, color=DARK_FG, fontsize=8)
    ax.set_xlabel("Importance Score", color="#94a3b8")
    ax.set_title(f"{model_name} — Feature Importances", color=DARK_FG, fontsize=13, fontweight="bold")
    plt.tight_layout()
    fname = os.path.join(dest_dir, f"feature_importance_{model_name.lower()}.png")
    plt.savefig(fname, dpi=130, bbox_inches="tight", facecolor=DARK_BG)
    plt.close()
    log(f"  Saved {fname}")

# ── IP Feature Extraction (fast vectorized) ───────────────────────────────────
def ip_to_features(ip_series):
    records = []
    for ip in ip_series:
        try:
            parts = [int(x) for x in str(ip).strip().split(".")]
            if len(parts) != 4:
                raise ValueError
            o1, o2, o3, o4 = parts
        except Exception:
            o1, o2, o3, o4 = 0, 0, 0, 0
        ip_int = (o1 << 24) | (o2 << 16) | (o3 << 8) | o4
        records.append([
            o1, o2, o3, o4,
            ip_int,
            o1 + o2 + o3 + o4,
            max(o1, o2, o3, o4) - min(o1, o2, o3, o4),
            float(np.std([o1, o2, o3, o4])),
            int(o1 == 10),
            int(o1 == 192 and o2 == 168),
            int(o1 == 172 and 16 <= o2 <= 31),
            int(o1 == 127),
            int(o1 >= 224),
            int(o1 in (1, 8, 9, 66, 67, 68, 69, 70, 71, 72, 74, 75, 76)),
            int(o4 == 1 or o4 == 254),
        ])
    return np.array(records, dtype=np.float32)

# ── Shared train/evaluate logic ───────────────────────────────────────────────
def train_and_eval(X, y, model_name_xgb, model_name_cb, xgb_params, cb_params,
                   xgb_save_path, cb_save_path, label, scaler=None):
    """Train both XGBoost and CatBoost on all 3 splits, save best (80:20) model."""
    results = {model_name_xgb: {}, model_name_cb: {}}
    best_xgb = None
    best_cb  = None

    for split_label, test_size in SPLITS:
        log(f"\n  [{split_label}] Splitting data ...")
        X_tr, X_te, y_tr, y_te = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y
        )
        log(f"    Train: {len(y_tr):,}  Test: {len(y_te):,}")

        # ── XGBoost ────────────────────────────────────────────────────────
        log(f"  [{split_label}] Training XGBoost ...")
        t0 = time.time()
        xgb_mdl = xgb.XGBClassifier(**xgb_params)
        xgb_mdl.fit(X_tr, y_tr, verbose=False)
        elapsed = time.time() - t0
        y_pred_x = xgb_mdl.predict(X_te)
        y_prob_x = xgb_mdl.predict_proba(X_te)[:, 1]
        m_x = {
            "accuracy":  round(accuracy_score(y_te, y_pred_x), 6),
            "precision": round(precision_score(y_te, y_pred_x, zero_division=0), 6),
            "recall":    round(recall_score(y_te, y_pred_x, zero_division=0), 6),
            "f1":        round(f1_score(y_te, y_pred_x, zero_division=0), 6),
            "roc_auc":   round(roc_auc_score(y_te, y_prob_x), 6),
        }
        results[model_name_xgb][split_label] = m_x
        log(f"    XGBoost done in {elapsed:.1f}s — Acc: {m_x['accuracy']*100:.2f}%  AUC: {m_x['roc_auc']*100:.2f}%")

        if split_label == "80:20":
            best_xgb = (xgb_mdl, X_te, y_te, y_pred_x, y_prob_x)

        # ── CatBoost ───────────────────────────────────────────────────────
        log(f"  [{split_label}] Training CatBoost ...")
        t0 = time.time()
        cb_mdl = CatBoostClassifier(**cb_params)
        cb_mdl.fit(Pool(X_tr, y_tr), eval_set=Pool(X_te, y_te), verbose=False)
        elapsed = time.time() - t0
        y_pred_c = cb_mdl.predict(Pool(X_te))
        y_prob_c = cb_mdl.predict_proba(Pool(X_te))[:, 1]
        m_c = {
            "accuracy":  round(accuracy_score(y_te, y_pred_c), 6),
            "precision": round(precision_score(y_te, y_pred_c, zero_division=0), 6),
            "recall":    round(recall_score(y_te, y_pred_c, zero_division=0), 6),
            "f1":        round(f1_score(y_te, y_pred_c, zero_division=0), 6),
            "roc_auc":   round(roc_auc_score(y_te, y_prob_c), 6),
        }
        results[model_name_cb][split_label] = m_c
        log(f"    CatBoost done in {elapsed:.1f}s — Acc: {m_c['accuracy']*100:.2f}%  AUC: {m_c['roc_auc']*100:.2f}%")

        if split_label == "80:20":
            best_cb = (cb_mdl, X_te, y_te, y_pred_c, y_prob_c)

    # Save best models (80:20)
    log(f"\n  Saving {model_name_xgb} -> {xgb_save_path}")
    joblib.dump(best_xgb[0], xgb_save_path)
    log(f"  Saving {model_name_cb} -> {cb_save_path}")
    joblib.dump(best_cb[0], cb_save_path)

    # Save artifacts for 80:20 split only
    for (model_name, best) in [(model_name_xgb, best_xgb), (model_name_cb, best_cb)]:
        mdl, X_te, y_te, y_pred, y_prob = best
        save_confusion_matrix(y_te, y_pred, model_name, "80:20", EVAL_DIR)
        # Also overwrite the models-dir CM
        save_confusion_matrix(y_te, y_pred, model_name, "80:20", MODELS_DIR)
        save_roc(y_te, y_prob, model_name, "80:20", EVAL_DIR)
        save_pr_curve(y_te, y_prob, model_name, "80:20", EVAL_DIR)
        try:
            fi = mdl.feature_importances_
        except Exception:
            try:
                fi = mdl.get_feature_importance()
            except Exception:
                fi = None
        if fi is not None:
            save_feature_importance(fi, model_name, EVAL_DIR)
        # Classification report
        rpt = classification_report(y_te, y_pred, target_names=["Benign", "Malicious"])
        rpt_path = os.path.join(EVAL_DIR, f"classification_report_{model_name.lower()}.txt")
        with open(rpt_path, "w") as f:
            f.write(f"{model_name} Classification Report (80:20)\n{'='*50}\n{rpt}")
        log(f"  Saved {rpt_path}")
        # Metrics JSON (80:20)
        m80 = results[model_name]["80:20"]
        j_path = os.path.join(EVAL_DIR, f"metrics_{model_name.lower()}.json")
        with open(j_path, "w") as f:
            json.dump(m80, f, indent=4)
        log(f"  Saved {j_path}")

    return results

# ══════════════════════════════════════════════════════════════════════════════
# MODEL 1: MALICIOUS IP DETECTION
# ══════════════════════════════════════════════════════════════════════════════
def train_ip_model():
    log("\n" + "="*65)
    log("MODEL 1: Malicious IP Detection (XGBoost + CatBoost)")
    log("="*65)

    log("Loading ML/data/malicious_ips.csv ...")
    df = pd.read_csv(os.path.join(DATA_DIR, "malicious_ips.csv"))
    df = df.dropna(subset=["content", "label"])
    df["label"] = df["label"].astype(int)
    log(f"  Total records: {len(df):,}  |  Malicious: {(df.label==1).sum():,}  |  Benign: {(df.label==0).sum():,}")

    log("Extracting IP numerical features ...")
    t0 = time.time()
    X = ip_to_features(df["content"])
    y = df["label"].values
    log(f"  Feature matrix: {X.shape} in {time.time()-t0:.2f}s")

    # Scale features
    scaler = StandardScaler()
    X = scaler.fit_transform(X)
    joblib.dump(scaler, os.path.join(MODELS_DIR, "scaler_ip.pkl"))
    log("  Saved scaler_ip.pkl")

    xgb_params = dict(
        n_estimators=200, max_depth=6, learning_rate=0.1,
        subsample=0.8, colsample_bytree=0.8,
        tree_method="hist", random_state=42, n_jobs=-1,
        eval_metric="logloss"
    )
    cb_params = dict(
        iterations=200, depth=6, learning_rate=0.1,
        loss_function="Logloss", random_seed=42, verbose=0, thread_count=-1
    )

    results = train_and_eval(
        X, y,
        model_name_xgb="ip_xgboost",
        model_name_cb="ip_catboost",
        xgb_params=xgb_params,
        cb_params=cb_params,
        xgb_save_path=os.path.join(MODELS_DIR, "ip_model.pkl"),
        cb_save_path=os.path.join(MODELS_DIR, "ip_model_catboost.pkl"),
        label="IP Detection",
    )
    return results

# ══════════════════════════════════════════════════════════════════════════════
# MODEL 2: EMAIL SCAM DETECTION
# ══════════════════════════════════════════════════════════════════════════════
def train_email_model():
    log("\n" + "="*65)
    log("MODEL 2: Email Scam Detection (XGBoost + CatBoost)")
    log("="*65)

    log("Loading ML/data/email_scams.csv ...")
    df = pd.read_csv(os.path.join(DATA_DIR, "email_scams.csv"))
    df = df.dropna(subset=["content", "label"])
    df["label"] = df["label"].astype(int)
    log(f"  Total records: {len(df):,}  |  Spam: {(df.label==1).sum():,}  |  Ham: {(df.label==0).sum():,}")

    log("Building TF-IDF features (max_features=8000) ...")
    t0 = time.time()
    tfidf = TfidfVectorizer(
        ngram_range=(1, 2), max_features=8000,
        strip_accents="unicode", sublinear_tf=True,
        max_df=0.95, min_df=2
    )
    X = tfidf.fit_transform(df["content"].fillna("").astype(str))
    y = df["label"].values
    log(f"  TF-IDF matrix: {X.shape} in {time.time()-t0:.2f}s")
    joblib.dump(tfidf, os.path.join(MODELS_DIR, "tfidf_email.pkl"))
    log("  Saved tfidf_email.pkl")

    xgb_params = dict(
        n_estimators=200, max_depth=6, learning_rate=0.1,
        subsample=0.8, colsample_bytree=0.5,
        tree_method="hist", random_state=42, n_jobs=-1,
        eval_metric="logloss"
    )
    cb_params = dict(
        iterations=200, depth=6, learning_rate=0.1,
        loss_function="Logloss", random_seed=42, verbose=0, thread_count=-1
    )

    results = train_and_eval(
        X, y,
        model_name_xgb="email_xgboost",
        model_name_cb="email_catboost",
        xgb_params=xgb_params,
        cb_params=cb_params,
        xgb_save_path=os.path.join(MODELS_DIR, "email_model.pkl"),
        cb_save_path=os.path.join(MODELS_DIR, "email_model_catboost.pkl"),
        label="Email Scam Detection",
    )
    return results

# ══════════════════════════════════════════════════════════════════════════════
# COMBINED RESULTS TABLE & ARTIFACT SAVE
# ══════════════════════════════════════════════════════════════════════════════
def print_results_table(all_results):
    def fmt(v): return f"{v*100:.2f}%"

    log("\n" + "="*80)
    log("FINAL RESULTS: CatBoost vs XGBoost — IP + Email Models")
    log("="*80)

    # Aggregate over all model keys for a combined table per split
    combined = {}  # split -> model_key -> metrics
    for model_key, split_dict in all_results.items():
        for split, metrics in split_dict.items():
            if split not in combined:
                combined[split] = {}
            combined[split][model_key] = metrics

    for split_label, _ in SPLITS:
        models_data = combined.get(split_label, {})
        ranked = sorted(models_data.items(), key=lambda x: x[1]["f1"], reverse=True)

        log(f"\n--- {split_label} Train-Test Split ---")
        log(f"  {'Rank':<5} {'Model':<20} {'Accuracy':>10} {'Precision':>10} {'Recall':>10} {'F1-Score':>10} {'ROC-AUC':>10}")
        log(f"  {'-'*65}")
        for rank_idx, (mname, m) in enumerate(ranked, 1):
            rank_str = "#1" if rank_idx == 1 else f"#{rank_idx}"
            log(f"  {rank_str:<5} {mname:<20} {fmt(m['accuracy']):>10} {fmt(m['precision']):>10} {fmt(m['recall']):>10} {fmt(m['f1']):>10} {fmt(m['roc_auc']):>10}")

    log("\n" + "="*80)
    log("SUMMARY — Best model per split (by F1):")
    for split_label, _ in SPLITS:
        models_data = combined.get(split_label, {})
        if not models_data:
            continue
        ranked = sorted(models_data.items(), key=lambda x: x[1]["f1"], reverse=True)
        w, wm = ranked[0]
        log(f"  {split_label}: BEST = {w}  (F1={fmt(wm['f1'])}, AUC={fmt(wm['roc_auc'])})")
    log("="*80)

def save_global_artifacts(all_results):
    """Save comparison_report.json and split_comparison_results.json."""
    # Comparison report (80:20 only)
    comp = {}
    for mname, split_dict in all_results.items():
        if "80:20" in split_dict:
            comp[mname] = split_dict["80:20"]
    with open(os.path.join(EVAL_DIR, "comparison_report.json"), "w") as f:
        json.dump(comp, f, indent=4)
    log(f"Saved comparison_report.json")

    # Split comparison all splits
    with open(os.path.join(EVAL_DIR, "split_comparison_results.json"), "w") as f:
        json.dump(all_results, f, indent=4)
    log(f"Saved split_comparison_results.json")

# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    import sys
    # Force UTF-8 stdout on Windows
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    total_start = time.time()
    all_results = {}

    # MODEL 1: IP
    ip_results = train_ip_model()
    all_results.update(ip_results)

    # MODEL 2: EMAIL
    email_results = train_email_model()
    all_results.update(email_results)

    # Save global artifacts
    save_global_artifacts(all_results)

    # Print final tables
    print_results_table(all_results)

    total_elapsed = time.time() - total_start
    log(f"\n[DONE] All models trained and artifacts saved in {total_elapsed/60:.1f} minutes.")
    log(f"  Model files   -> {MODELS_DIR}/")
    log(f"  Eval artifacts -> {EVAL_DIR}/")

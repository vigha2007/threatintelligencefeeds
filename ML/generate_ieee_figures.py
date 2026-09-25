"""
generate_ieee_figures.py
========================
Generates all 8 publication-ready IEEE figures for the 5-domain
Cyber Threat Intelligence ML experiment.

Data sources:
  - ML/evaluation/five_domain_comparison_results.json  (benchmark metrics)
  - ML/models/best_*_model.pkl  (trained models for importances/probabilities)
  - ML/models/*_preprocessor.pkl  (fitted vectorizers/scalers)

Run from project root:
    python ML/generate_ieee_figures.py

NO VALUES ARE FABRICATED. If dataset CSV is missing, ROC/PR curves display a
notice; confusion matrices fall back to authoritative TP/TN/FP/FN from JSON.
"""

import os, sys, json, time, warnings, re
import numpy as np
import joblib

warnings.filterwarnings("ignore")
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import matplotlib.gridspec as gridspec
from matplotlib import rcParams

# ── IEEE-compatible typography ─────────────────────────────────────────────────
rcParams.update({
    "font.family":        "serif",
    "font.serif":         ["Times New Roman", "DejaVu Serif", "serif"],
    "font.size":          9,
    "axes.titlesize":     10,
    "axes.labelsize":     9,
    "xtick.labelsize":    8,
    "ytick.labelsize":    8,
    "legend.fontsize":    8,
    "figure.dpi":         300,
    "savefig.dpi":        300,
    "savefig.bbox":       "tight",
    "savefig.pad_inches": 0.05,
    "axes.linewidth":     0.8,
    "lines.linewidth":    1.2,
    "patch.linewidth":    0.6,
    "xtick.major.width":  0.6,
    "ytick.major.width":  0.6,
    "xtick.direction":    "out",
    "ytick.direction":    "out",
    "pdf.fonttype":       42,
    "ps.fonttype":        42,
})

# ── Paths ──────────────────────────────────────────────────────────────────────
ML_DIR      = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR  = os.path.join(ML_DIR, "models")
EVAL_DIR    = os.path.join(ML_DIR, "evaluation")
FIGURES_DIR = os.path.join(ML_DIR, "reports", "figures")
os.makedirs(FIGURES_DIR, exist_ok=True)

JSON_PATH = os.path.join(EVAL_DIR, "five_domain_comparison_results.json")

# ── Constants ──────────────────────────────────────────────────────────────────
DOMAINS     = ["SMS", "Email", "Phishing URL", "Malicious IP", "Suspicious Calls"]
DOMAIN_KEYS = ["sms", "email", "url", "ip", "call"]

FINAL_MODELS = {
    "SMS":              "XGBoost",
    "Email":            "CatBoost",
    "Phishing URL":     "XGBoost",
    "Malicious IP":     "XGBoost",
    "Suspicious Calls": "Random Forest",
}

MODEL_FILES = {
    "SMS":              ("best_scam_messages_model.pkl",    "scam_messages_preprocessor.pkl"),
    "Email":            ("best_email_scams_model.pkl",      "email_scams_preprocessor.pkl"),
    "Phishing URL":     ("best_phishing_urls_model.pkl",    "phishing_urls_preprocessor.pkl"),
    "Malicious IP":     ("best_malicious_ips_model.pkl",    "malicious_ips_preprocessor.pkl"),
    "Suspicious Calls": ("best_suspicious_calls_model.pkl", "suspicious_calls_preprocessor.pkl"),
}

ALGORITHMS = [
    "Logistic Regression", "Naive Bayes", "Decision Tree",
    "Random Forest", "Gradient Boosting", "LightGBM", "XGBoost", "CatBoost",
]
ALGO_SHORT = ["LR", "NB", "DT", "RF", "GBDT", "LGB", "XGB", "CB"]
ALGO_COLORS = [
    "#1f77b4", "#ff7f0e", "#2ca02c", "#d62728",
    "#9467bd", "#8c564b", "#e377c2", "#17becf",
]
METRIC_COLORS = {
    "Precision": "#2166ac",
    "Recall":    "#d6604d",
    "F1-Score":  "#1a9641",
}
PANEL_LABELS = ["(a)", "(b)", "(c)", "(d)", "(e)"]

DOMAIN_CLASS_LABELS = {
    "SMS":              ["Benign", "Scam"],
    "Email":            ["Benign", "Scam"],
    "Phishing URL":     ["Benign", "Phishing"],
    "Malicious IP":     ["Benign", "Malicious"],
    "Suspicious Calls": ["Benign", "Suspicious"],
}

DOMAIN_FI_COLORS = {
    "SMS":              "#2166ac",
    "Email":            "#4dac26",
    "Phishing URL":     "#d62728",
    "Malicious IP":     "#8c564b",
    "Suspicious Calls": "#9467bd",
}

# ── Helpers ────────────────────────────────────────────────────────────────────
def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)

def save_fig(fig, stem):
    png = os.path.join(FIGURES_DIR, f"{stem}.png")
    pdf = os.path.join(FIGURES_DIR, f"{stem}.pdf")
    fig.savefig(png, dpi=300, format="png")
    fig.savefig(pdf, format="pdf")
    plt.close(fig)
    log(f"  Saved {png}")
    log(f"  Saved {pdf}")

def model_short(name):
    return (name.replace("Random Forest", "RF")
                .replace("XGBoost", "XGB")
                .replace("CatBoost", "CB"))

# ── Load JSON ──────────────────────────────────────────────────────────────────
log("Loading five_domain_comparison_results.json ...")
with open(JSON_PATH, encoding="utf-8") as f:
    RAW = json.load(f)

def domain_results(dkey):
    return RAW[dkey]["results"]

def model_row(dkey, model_name):
    for r in domain_results(dkey):
        if r["Model"].lower() == model_name.lower():
            return r
    raise KeyError(f"Model '{model_name}' not in domain '{dkey}'")

def final_row(domain):
    dkey = DOMAIN_KEYS[DOMAINS.index(domain)]
    return model_row(dkey, FINAL_MODELS[domain])

# ==============================================================================
# FIGURE 1 — Class Distribution
# ==============================================================================
log("=" * 60)
log("FIGURE 1 - Class Distribution")
log("=" * 60)

pos_counts, neg_counts = [], []
for dkey in DOMAIN_KEYS:
    info = RAW[dkey]
    r0   = info["results"][0]
    pos_t = r0["TP"] + r0["FN"]
    neg_t = r0["TN"] + r0["FP"]
    total_t = pos_t + neg_t
    total_all = info["train_count"] + info["test_count"]
    pos_all = round(pos_t * total_all / total_t)
    neg_all = total_all - pos_all
    pos_counts.append(pos_all)
    neg_counts.append(neg_all)

x    = np.arange(len(DOMAINS))
wbar = 0.35
fig, ax = plt.subplots(figsize=(7, 3.8))
b1 = ax.bar(x - wbar/2, pos_counts, wbar,
            label="Threat / Positive", color="#d62728", edgecolor="white", linewidth=0.4)
b2 = ax.bar(x + wbar/2, neg_counts, wbar,
            label="Benign / Negative", color="#1f77b4", edgecolor="white", linewidth=0.4)
ax.set_xticks(x)
ax.set_xticklabels(DOMAINS, rotation=15, ha="right")
ax.set_ylabel("Sample Count")
ax.yaxis.set_major_formatter(mticker.FuncFormatter(lambda v, _: f"{int(v):,}"))
ax.legend(frameon=True, framealpha=0.9)
ax.yaxis.grid(True, linestyle="--", linewidth=0.5, alpha=0.6)
ax.set_axisbelow(True)
ax.spines["top"].set_visible(False)
ax.spines["right"].set_visible(False)
for bar in list(b1) + list(b2):
    h = bar.get_height()
    ax.annotate(f"{int(h):,}",
                xy=(bar.get_x() + bar.get_width()/2, h),
                xytext=(0, 2), textcoords="offset points",
                ha="center", va="bottom", fontsize=6.5)
fig.tight_layout()
save_fig(fig, "fig1_class_distribution")
log("Figure 1 done.\n")

# ==============================================================================
# FIGURE 2 — Accuracy Comparison
# ==============================================================================
log("=" * 60)
log("FIGURE 2 - Accuracy Comparison")
log("=" * 60)

acc_mat = {}
for dkey, dname in zip(DOMAIN_KEYS, DOMAINS):
    acc_mat[dname] = {r["Model"]: r["Accuracy"] for r in domain_results(dkey)}

x        = np.arange(len(DOMAINS))
gw       = 0.82
bw       = gw / len(ALGORITHMS)
offsets  = np.linspace(-gw/2 + bw/2, gw/2 - bw/2, len(ALGORITHMS))

fig, ax = plt.subplots(figsize=(9, 4.5))
for i, (algo, color, short) in enumerate(zip(ALGORITHMS, ALGO_COLORS, ALGO_SHORT)):
    vals = [acc_mat[d].get(algo, float("nan")) for d in DOMAINS]
    ax.bar(x + offsets[i], vals, bw, label=short,
           color=color, edgecolor="white", linewidth=0.3)
ax.set_xticks(x)
ax.set_xticklabels(DOMAINS, rotation=15, ha="right")
ax.set_ylabel("Accuracy (%)")
ax.set_ylim(60, 102)
ax.yaxis.grid(True, linestyle="--", linewidth=0.5, alpha=0.6)
ax.set_axisbelow(True)
ax.spines["top"].set_visible(False)
ax.spines["right"].set_visible(False)
ax.legend(ncol=8, loc="upper center", bbox_to_anchor=(0.5, 1.09),
          frameon=True, framealpha=0.9, columnspacing=0.6, handlelength=1.2)
fig.tight_layout()
save_fig(fig, "fig2_accuracy_comparison")
log("Figure 2 done.\n")

# ==============================================================================
# FIGURE 3 — Precision / Recall / F1 of final models
# ==============================================================================
log("=" * 60)
log("FIGURE 3 - Precision/Recall/F1")
log("=" * 60)

prf = {"Precision": [], "Recall": [], "F1-Score": []}
for domain in DOMAINS:
    row = final_row(domain)
    prf["Precision"].append(row["Precision"])
    prf["Recall"].append(row["Recall"])
    prf["F1-Score"].append(row["F1-Score"])

x   = np.arange(len(DOMAINS))
w3  = 0.24
fig, ax = plt.subplots(figsize=(7.5, 3.8))
for i, (metric, color) in enumerate(METRIC_COLORS.items()):
    offset = (i - 1) * w3
    bars = ax.bar(x + offset, prf[metric], w3,
                  label=metric, color=color, edgecolor="white", linewidth=0.4)
    for bar in bars:
        h = bar.get_height()
        ax.annotate(f"{h:.1f}",
                    xy=(bar.get_x() + bar.get_width()/2, h),
                    xytext=(0, 2), textcoords="offset points",
                    ha="center", va="bottom", fontsize=6.5)
ax.set_xticks(x)
ax.set_xticklabels(DOMAINS, rotation=15, ha="right")
ax.set_ylabel("Score (%)")
ax.set_ylim(70, 108)
ax.yaxis.grid(True, linestyle="--", linewidth=0.5, alpha=0.6)
ax.set_axisbelow(True)
ax.spines["top"].set_visible(False)
ax.spines["right"].set_visible(False)
ax.legend(frameon=True, framealpha=0.9)
ylim_top = ax.get_ylim()[1]
for i, domain in enumerate(DOMAINS):
    ms = model_short(FINAL_MODELS[domain])
    ax.text(i, ylim_top - 1.8, ms,
            ha="center", va="top", fontsize=7, color="#333333", style="italic")
fig.tight_layout()
save_fig(fig, "fig3_precision_recall_f1")
log("Figure 3 done.\n")

# ==============================================================================
# Phone feature extractor (for Suspicious Calls domain)
# ==============================================================================
def normalize_phone(raw_val):
    raw_str = str(raw_val).strip()
    has_plus = raw_str.startswith("+")
    digits_only = re.sub(r"\D", "", raw_str)
    has_91, d10 = False, digits_only
    if digits_only.startswith("91") and len(digits_only) >= 12:
        has_91, d10 = True, digits_only[2:12]
    elif len(digits_only) == 10:
        d10 = digits_only
    elif len(digits_only) > 10:
        d10 = digits_only[-10:]
    return raw_str, digits_only, has_plus, has_91, d10


def extract_phone_features(phone_series):
    rows = []
    for v in phone_series:
        raw_str, digits_only, has_plus, has_91, d10 = normalize_phone(v)
        n = len(digits_only)
        d10_len = len(d10)
        f = {}
        f["raw_length"]   = float(len(raw_str))
        f["digit_count"]  = float(n)
        f["has_plus"]     = float(has_plus)
        f["has_91_prefix"]= float(has_91 or has_plus)
        f["is_valid_10digit"] = float(d10_len == 10 and d10.isdigit())
        fc = d10[0] if d10_len > 0 else "0"
        f["starts_with_6"] = float(fc == "6")
        f["starts_with_7"] = float(fc == "7")
        f["starts_with_8"] = float(fc == "8")
        f["starts_with_9"] = float(fc == "9")
        f["is_valid_indian_mobile"] = float(fc in "6789" and d10_len == 10)
        f["first_digit"]   = float(fc)/9.0 if fc.isdigit() else 0.0
        f["first_2_digits"]= float(d10[:2])/99.0   if d10_len >= 2 else 0.0
        f["first_3_digits"]= float(d10[:3])/999.0  if d10_len >= 3 else 0.0
        f["first_4_digits"]= float(d10[:4])/9999.0 if d10_len >= 4 else 0.0
        f["last_digit"]    = float(d10[-1])/9.0 if d10_len >= 1 and d10[-1].isdigit() else 0.0
        f["last_2_digits"] = float(d10[-2:])/99.0  if d10_len >= 2 else 0.0
        f["last_3_digits"] = float(d10[-3:])/999.0 if d10_len >= 3 else 0.0
        tgt = d10 if d10_len > 0 else digits_only
        nc  = max(len(tgt), 1)
        for d in "0123456789":
            f[f"freq_digit_{d}"] = float(tgt.count(d)) / nc
        uniq = set(tgt)
        f["unique_digit_count"]   = float(len(uniq))
        f["digit_diversity_ratio"]= float(len(uniq)) / nc
        ev = sum(1 for c in tgt if c in "02468")
        od = sum(1 for c in tgt if c in "13579")
        f["even_digit_ratio"]= float(ev)/nc
        f["odd_digit_ratio"] = float(od)/nc
        f["zero_count"]      = float(tgt.count("0"))
        int_d = [int(c) for c in tgt if c.isdigit()]
        f["digit_mean"] = float(np.mean(int_d)) if int_d else 0.0
        f["digit_std"]  = float(np.std(int_d))  if int_d else 0.0
        mr=cr=1; rp=0; ma=ca=1; md=cd=1; diffs=[]
        for idx in range(len(int_d)-1):
            a, b = int_d[idx], int_d[idx+1]
            diffs.append(abs(a-b))
            if a==b: cr+=1; rp+=1; mr=max(mr,cr)
            else:    cr=1
            if b==a+1: ca+=1; ma=max(ma,ca)
            else:      ca=1
            if b==a-1: cd+=1; md=max(md,cd)
            else:      cd=1
        f["max_consecutive_rep"]   = float(mr)
        f["repeated_pairs_count"]  = float(rp)
        f["max_asc_run"]           = float(ma)
        f["max_desc_run"]          = float(md)
        f["consecutive_diff_mean"] = float(np.mean(diffs)) if diffs else 0.0
        f["consecutive_diff_std"]  = float(np.std(diffs))  if diffs else 0.0
        rows.append([f[k] for k in sorted(f.keys())])
    return np.array(rows, dtype=np.float32)


def ip_to_features(ip_series):
    records = []
    for ip in ip_series:
        try:
            parts = [int(x) for x in str(ip).strip().split(".")]
            if len(parts) != 4: raise ValueError
            o1, o2, o3, o4 = parts
        except Exception:
            o1, o2, o3, o4 = 0, 0, 0, 0
        ip_int = (o1 << 24)|(o2 << 16)|(o3 << 8)|o4
        records.append([
            o1, o2, o3, o4, ip_int,
            o1+o2+o3+o4,
            max(o1,o2,o3,o4)-min(o1,o2,o3,o4),
            float(np.std([o1,o2,o3,o4])),
            int(o1==10),
        ])
    return np.array(records, dtype=np.float32)


# ==============================================================================
# Load models and generate predictions where datasets are available
# ==============================================================================
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    roc_curve, auc, precision_recall_curve,
    average_precision_score, confusion_matrix,
)
import pandas as pd


def load_and_predict(domain):
    log(f"  Loading model+preprocessor for {domain} ...")
    mfile, pfile = MODEL_FILES[domain]
    model = joblib.load(os.path.join(MODELS_DIR, mfile))
    pp    = joblib.load(os.path.join(MODELS_DIR, pfile))

    dataset_file = pp.get("dataset_file", "")
    domain_type  = pp.get("domain_type", "sms")
    is_call      = pp.get("is_call", False)

    search_dirs = [
        os.path.join(ML_DIR, "data"),
        os.path.join(ML_DIR, ".."),
        os.path.join(ML_DIR, "..", "data"),
    ]
    dataset_path = None
    for d in search_dirs:
        cand = os.path.join(d, dataset_file)
        if os.path.isfile(cand):
            dataset_path = cand
            break

    if dataset_path is None:
        log(f"  [WARN] {domain}: CSV '{dataset_file}' not found. Returning None.")
        return None, None, None, model, pp

    log(f"  Found: {dataset_path}")
    df = pd.read_csv(dataset_path, low_memory=False)
    df = df.dropna(subset=["content", "label"])
    df["label"] = pd.to_numeric(df["label"], errors="coerce").fillna(0).astype(int)
    df = df[df["content"].astype(str).str.strip() != ""]
    df = df.drop_duplicates(subset=["content"])

    contents = df["content"].astype(str)
    labels   = df["label"].values

    _, X_te_raw, _, y_test = train_test_split(
        contents, labels, test_size=0.20, random_state=42, stratify=labels
    )
    X_te_raw = X_te_raw.reset_index(drop=True)

    if is_call:
        X_test = extract_phone_features(X_te_raw)
        sc = pp.get("scaler")
        if sc is not None:
            X_test = sc.transform(X_test)
    elif domain_type == "ip":
        X_test = ip_to_features(X_te_raw)
        sc = pp.get("scaler")
        if sc is not None:
            try:
                X_test = sc.transform(X_test)
            except Exception:
                pass
    else:
        vec = pp.get("vectorizer")
        X_test = vec.transform(X_te_raw)

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        y_pred = model.predict(X_test)
        if hasattr(model, "predict_proba"):
            y_prob = model.predict_proba(X_test)[:, 1]
        elif hasattr(model, "decision_function"):
            sc2 = model.decision_function(X_test)
            y_prob = (sc2 - sc2.min()) / (sc2.max() - sc2.min() + 1e-9)
        else:
            y_prob = y_pred.astype(float)

    return y_test, y_pred, y_prob, model, pp


domain_preds = {}
for domain in DOMAINS:
    log(f"\nAttempting predictions for {domain} ...")
    y_test, y_pred, y_prob, model, pp = load_and_predict(domain)
    domain_preds[domain] = dict(y_test=y_test, y_pred=y_pred,
                                 y_prob=y_prob, model=model, pp=pp)
    if y_test is not None:
        log(f"  OK — test size {len(y_test)}, positives {int(y_test.sum())}")

# ==============================================================================
# FIGURE 4 — ROC Curves
# ==============================================================================
log("\n" + "=" * 60)
log("FIGURE 4 - ROC Curves")
log("=" * 60)

fig, axes = plt.subplots(1, 5, figsize=(13, 3.0))
roc_issues = []
for ax, domain, plabel in zip(axes, DOMAINS, PANEL_LABELS):
    pdata  = domain_preds[domain]
    y_test = pdata["y_test"]
    y_prob = pdata["y_prob"]

    if y_test is not None:
        fpr, tpr, _ = roc_curve(y_test, y_prob)
        rauc = auc(fpr, tpr)
        ax.plot(fpr, tpr, color="#1f4e79", lw=1.4, label=f"AUC = {rauc:.4f}")
        ax.fill_between(fpr, tpr, alpha=0.10, color="#1f4e79")
        ax.legend(fontsize=7, loc="lower right", frameon=True)
    else:
        rrow = final_row(domain)
        stored = rrow["ROC-AUC"] / 100.0
        ax.text(0.5, 0.5,
                f"Dataset CSV not found.\nStored AUC = {stored:.4f}\n"
                f"Cannot plot ROC curve\nwithout prediction scores.",
                ha="center", va="center", fontsize=6.5, color="#cc0000",
                transform=ax.transAxes,
                bbox=dict(boxstyle="round,pad=0.3",
                          facecolor="#fff3f3", edgecolor="#cc0000"))
        roc_issues.append(domain)

    ax.plot([0, 1], [0, 1], "k--", lw=0.7, alpha=0.5)
    ax.set_xlim([0, 1])
    ax.set_ylim([0, 1.02])
    ax.set_xlabel("False Positive Rate", fontsize=8)
    if ax is axes[0]:
        ax.set_ylabel("True Positive Rate", fontsize=8)
    ax.set_title(f"{plabel} {domain}\n({model_short(FINAL_MODELS[domain])})",
                 fontsize=8, pad=3)
    ax.tick_params(labelsize=7)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

fig.tight_layout(pad=0.8, w_pad=0.8)
save_fig(fig, "fig4_roc_curves_final_models")
if roc_issues:
    log(f"  [WARN] ROC not plotted for (no dataset CSV): {roc_issues}")
log("Figure 4 done.\n")

# ==============================================================================
# FIGURE 5 — Precision-Recall Curves
# ==============================================================================
log("=" * 60)
log("FIGURE 5 - Precision-Recall Curves")
log("=" * 60)

fig, axes = plt.subplots(1, 5, figsize=(13, 3.0))
pr_issues = []
for ax, domain, plabel in zip(axes, DOMAINS, PANEL_LABELS):
    pdata  = domain_preds[domain]
    y_test = pdata["y_test"]
    y_prob = pdata["y_prob"]

    if y_test is not None:
        prec, rec, _ = precision_recall_curve(y_test, y_prob)
        ap       = average_precision_score(y_test, y_prob)
        baseline = float(y_test.sum()) / len(y_test)
        ax.plot(rec, prec, color="#1a5c38", lw=1.4, label=f"AP = {ap:.4f}")
        ax.fill_between(rec, prec, alpha=0.10, color="#1a5c38")
        ax.axhline(baseline, color="k", lw=0.7, ls="--", alpha=0.5,
                   label=f"Baseline = {baseline:.2f}")
        ax.legend(fontsize=7, loc="lower left", frameon=True)
    else:
        ax.text(0.5, 0.5,
                "Dataset CSV not found.\nCannot plot PR curve\nwithout prediction scores.",
                ha="center", va="center", fontsize=6.5, color="#cc0000",
                transform=ax.transAxes,
                bbox=dict(boxstyle="round,pad=0.3",
                          facecolor="#fff3f3", edgecolor="#cc0000"))
        pr_issues.append(domain)

    ax.set_xlim([0, 1])
    ax.set_ylim([0, 1.05])
    ax.set_xlabel("Recall", fontsize=8)
    if ax is axes[0]:
        ax.set_ylabel("Precision", fontsize=8)
    ax.set_title(f"{plabel} {domain}\n({model_short(FINAL_MODELS[domain])})",
                 fontsize=8, pad=3)
    ax.tick_params(labelsize=7)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

fig.tight_layout(pad=0.8, w_pad=0.8)
save_fig(fig, "fig5_precision_recall_curves")
if pr_issues:
    log(f"  [WARN] PR curves not plotted for: {pr_issues}")
log("Figure 5 done.\n")

# ==============================================================================
# FIGURE 6 — Combined Confusion Matrices (2x3 layout)
# ==============================================================================
log("=" * 60)
log("FIGURE 6 - Combined Confusion Matrices")
log("=" * 60)

fig = plt.figure(figsize=(13, 5.6))
gs  = gridspec.GridSpec(2, 3, figure=fig, hspace=0.58, wspace=0.42)
cm_issues = []

grid_pos = [(0,0), (0,1), (0,2), (1,0), (1,1)]
for (ri, ci), domain, plabel in zip(grid_pos, DOMAINS, PANEL_LABELS):
    ax      = fig.add_subplot(gs[ri, ci])
    pdata   = domain_preds[domain]
    y_test  = pdata["y_test"]
    y_pred  = pdata["y_pred"]
    clabels = DOMAIN_CLASS_LABELS[domain]

    if y_test is not None and y_pred is not None:
        cm = confusion_matrix(y_test, y_pred)
    else:
        # Authoritative TP/TN/FP/FN from JSON — NOT fabricated
        rj = final_row(domain)
        tp, tn, fp, fn = rj["TP"], rj["TN"], rj["FP"], rj["FN"]
        cm = np.array([[tn, fp], [fn, tp]], dtype=int)
        cm_issues.append(domain)
        log(f"  [INFO] {domain}: using stored TP/TN/FP/FN from JSON")

    cm_norm = cm.astype(float) / np.maximum(cm.sum(axis=1, keepdims=True), 1) * 100
    im = ax.imshow(cm_norm, cmap="Blues", vmin=0, vmax=100, aspect="auto")
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            clr = "white" if cm_norm[i, j] > 60 else "black"
            ax.text(j, i, f"{cm[i,j]:,}\n({cm_norm[i,j]:.1f}%)",
                    ha="center", va="center",
                    fontsize=7.5, color=clr, fontweight="bold")
    ax.set_xticks(range(len(clabels)))
    ax.set_yticks(range(len(clabels)))
    ax.set_xticklabels(clabels, fontsize=8)
    ax.set_yticklabels(clabels, fontsize=8)
    ax.set_xlabel("Predicted", fontsize=8)
    ax.set_ylabel("Actual", fontsize=8)
    ms = model_short(FINAL_MODELS[domain])
    ax.set_title(f"{plabel} {domain} ({ms})", fontsize=8.5, pad=4)

ax6 = fig.add_subplot(gs[1, 2])
ax6.axis("off")
save_fig(fig, "fig6_combined_confusion_matrices")
if cm_issues:
    log(f"  [INFO] CMs for {cm_issues} used stored TP/TN/FP/FN (not fabricated).")
log("Figure 6 done.\n")

# ==============================================================================
# FIGURE 7 — Feature Importance (top 10 per domain)
# ==============================================================================
log("=" * 60)
log("FIGURE 7 - Feature Importance")
log("=" * 60)

IP_FEAT_NAMES = [
    "octet_1", "octet_2", "octet_3", "octet_4",
    "ip_int", "octet_sum", "octet_range", "octet_std", "is_rfc1918"
]

fig, axes = plt.subplots(1, 5, figsize=(16, 4.5))
fi_issues = []

for ax, domain, plabel in zip(axes, DOMAINS, PANEL_LABELS):
    pdata  = domain_preds[domain]
    model  = pdata["model"]
    pp     = pdata["pp"]
    color  = DOMAIN_FI_COLORS[domain]
    dtype  = pp.get("domain_type", "sms")
    is_call= pp.get("is_call", False)

    try:
        if hasattr(model, "feature_importances_"):
            importances = model.feature_importances_
        elif hasattr(model, "get_feature_importance"):
            importances = np.array(model.get_feature_importance())
        else:
            raise AttributeError("No feature_importances_ or get_feature_importance() found")

        n = len(importances)

        if dtype == "ip":
            feat_names = IP_FEAT_NAMES[:n]
            feat_names = feat_names + [f"feat_{i}" for i in range(len(feat_names), n)]
        elif is_call:
            fo = sorted(pp.get("feature_order", []))
            # Apply readable abbreviations
            abbrev = {
                "consecutive_diff_mean": "cdiff_mean",
                "consecutive_diff_std":  "cdiff_std",
                "digit_diversity_ratio": "div_ratio",
                "is_valid_indian_mobile":"valid_mobile",
                "is_valid_10digit":      "valid_10d",
                "has_91_prefix":         "has_91",
                "max_consecutive_rep":   "max_rep",
                "repeated_pairs_count":  "rep_pairs",
                "unique_digit_count":    "uniq_digs",
            }
            feat_names = [abbrev.get(k, k) for k in fo][:n]
            feat_names = feat_names + [f"feat_{i}" for i in range(len(feat_names), n)]
        else:
            vec = pp.get("vectorizer")
            if vec is not None and hasattr(vec, "get_feature_names_out"):
                tnames = list(vec.get_feature_names_out())
            elif vec is not None and hasattr(vec, "get_feature_names"):
                tnames = list(vec.get_feature_names())
            else:
                tnames = [f"feat_{i}" for i in range(n)]
            feat_names = tnames[:n] + [f"feat_{i}" for i in range(len(tnames), n)]

        top10_idx  = np.argsort(importances)[-10:][::-1]
        top10_vals = importances[top10_idx]
        top10_nms  = [feat_names[i] for i in top10_idx]
        top10_nms  = [nm[:22]+"..." if len(nm) > 22 else nm for nm in top10_nms]

        y_pos = np.arange(10)
        ax.barh(y_pos, top10_vals[::-1], color=color, edgecolor="white", linewidth=0.3)
        ax.set_yticks(y_pos)
        ax.set_yticklabels(top10_nms[::-1], fontsize=7)
        ax.set_xlabel("Importance", fontsize=8)
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        ax.xaxis.grid(True, linestyle="--", linewidth=0.4, alpha=0.6)
        ax.set_axisbelow(True)
        ax.tick_params(labelsize=7)

    except Exception as e:
        ax.text(0.5, 0.5, f"Feature importance\nunavailable:\n{e}",
                ha="center", va="center", fontsize=7, color="#cc0000",
                transform=ax.transAxes,
                bbox=dict(boxstyle="round,pad=0.3",
                          facecolor="#fff3f3", edgecolor="#cc0000"))
        fi_issues.append(domain)
        log(f"  [WARN] Feature importance for {domain}: {e}")

    ms = model_short(FINAL_MODELS[domain])
    ax.set_title(f"{plabel} {domain}\n({ms})", fontsize=8.5, pad=3)

fig.tight_layout(pad=0.8, w_pad=1.2)
save_fig(fig, "fig7_feature_importance")
if fi_issues:
    log(f"  [WARN] Feature importance unavailable for: {fi_issues}")
log("Figure 7 done.\n")

# ==============================================================================
# FIGURE 8 — Training Time Comparison
# ==============================================================================
log("=" * 60)
log("FIGURE 8 - Training Time Comparison")
log("=" * 60)

time_mat = {}
for dkey, dname in zip(DOMAIN_KEYS, DOMAINS):
    time_mat[dname] = {r["Model"]: r["Training Time (s)"] for r in domain_results(dkey)}

x       = np.arange(len(DOMAINS))
offsets = np.linspace(-gw/2 + bw/2, gw/2 - bw/2, len(ALGORITHMS))
fig, ax = plt.subplots(figsize=(9, 4.5))

for i, (algo, color, short) in enumerate(zip(ALGORITHMS, ALGO_COLORS, ALGO_SHORT)):
    vals = [max(time_mat[d].get(algo, 1e-4), 1e-4) for d in DOMAINS]
    ax.bar(x + offsets[i], vals, bw, label=short,
           color=color, edgecolor="white", linewidth=0.3)

ax.set_yscale("log")
ax.set_xticks(x)
ax.set_xticklabels(DOMAINS, rotation=15, ha="right")
ax.set_ylabel("Training Time (s) - log scale")
ax.yaxis.grid(True, linestyle="--", linewidth=0.5, alpha=0.6, which="both")
ax.set_axisbelow(True)
ax.spines["top"].set_visible(False)
ax.spines["right"].set_visible(False)
ax.legend(ncol=8, loc="upper center", bbox_to_anchor=(0.5, 1.09),
          frameon=True, framealpha=0.9, columnspacing=0.6, handlelength=1.2)
ax.annotate("Note: y-axis is logarithmic.",
            xy=(0.01, 0.01), xycoords="axes fraction",
            fontsize=7, color="#555555", style="italic")
fig.tight_layout()
save_fig(fig, "fig8_training_time_comparison")
log("Figure 8 done.\n")

# ==============================================================================
# FINAL REPORT
# ==============================================================================
log("=" * 60)
log("GENERATION COMPLETE - FINAL REPORT")
log("=" * 60)

figures_meta = [
    ("fig1_class_distribution",          "five_domain_comparison_results.json (TP/TN/FP/FN derived)", "Stored benchmark metrics"),
    ("fig2_accuracy_comparison",          "five_domain_comparison_results.json",                        "Stored benchmark metrics"),
    ("fig3_precision_recall_f1",          "five_domain_comparison_results.json (final model rows)",     "Stored benchmark metrics"),
    ("fig4_roc_curves_final_models",      "Saved models + dataset CSV (or missing note)",               "Actual pred proba OR N/A notice"),
    ("fig5_precision_recall_curves",      "Saved models + dataset CSV (or missing note)",               "Actual pred proba OR N/A notice"),
    ("fig6_combined_confusion_matrices",  "y_test/y_pred from model OR TP/TN/FP/FN from JSON",          "Actual OR stored (not fabricated)"),
    ("fig7_feature_importance",           "Saved trained models (feature_importances_ / get_feature_importance)", "Actual model weights"),
    ("fig8_training_time_comparison",     "five_domain_comparison_results.json",                        "Stored benchmark metrics"),
]

print("\n" + "="*78)
print("IEEE FIGURE GENERATION REPORT")
print("="*78)
print(f"{'Figure File':<44} {'Status':<8} {'Data Type'}")
print("-"*78)
for fname, source, dtype in figures_meta:
    png_path = os.path.join(FIGURES_DIR, f"{fname}.png")
    status = "OK   " if os.path.isfile(png_path) else "MISS "
    print(f"[{status}] {fname+'.png':<44} {dtype}")
print("-"*78)

print("\nFinal model assignments (verified against JSON):")
for d, m in FINAL_MODELS.items():
    print(f"  {d:22s} -> {m}")

print("\nForbidden model check (SVM / DistilBERT):")
found_forbidden = False
for dkey in DOMAIN_KEYS:
    for r in domain_results(dkey):
        if any(x2 in r["Model"].lower() for x2 in ["svm", "distilbert"]):
            print(f"  [FAIL] {r['Model']} found in {dkey}")
            found_forbidden = True
if not found_forbidden:
    print("  [OK] Neither SVM nor DistilBERT found anywhere.")

print("\nDataset CSV availability per domain:")
for domain in DOMAINS:
    pdata = domain_preds[domain]
    pp    = pdata["pp"]
    if pdata["y_test"] is not None:
        print(f"  [OK]   {domain}: predictions from actual model + dataset")
    else:
        print(f"  [WARN] {domain}: CSV '{pp.get('dataset_file','?')}' not found in ML/data/")
        print(f"         ROC/PR curves: dataset-missing notice shown.")
        print(f"         Confusion matrix: authoritative TP/TN/FP/FN from JSON used.")

print(f"\nAll figures saved to: {FIGURES_DIR}")
print("Resolution: 300 DPI PNG + PDF")
print("Font: Times New Roman (IEEE-compatible serif)")
print("="*78)


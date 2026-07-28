# Walkthrough: Model Re-Training and Evaluation
> **Report Generated:** 2026-07-10 | **Pipeline Version:** XGBoost+CatBoost Only

---
## Dataset Used

| Dataset File | Type | Records (Cleaned) | Source |
|---|---|---|---|
| phishing_urls.csv | Phishing URLs | 879,465 | Kaggle / HuggingFace |
| malicious_ips.csv | Malicious IPs | 216,665 | IPsum / EmergingThreats / FeodoTracker |
| email_scams.csv | Email Scams | 36,741 | mshenoda/spam-email (HuggingFace) |
| scam_messages.csv | SMS Scam Messages | 43,044 | ucirvine/sms_spam (HuggingFace) |
| suspicious_calls.csv | Suspicious Calls | 117,360 | FCC opendata (malicious) + PolyAI/minds14 (benign) |
| **Total** | — | **1,292,058** | — |

## Data Preprocessing

The following cleaning steps were applied:

1. **Null removal** — Rows with null `content` or `label` dropped.
2. **Exact duplicate removal** — Within each file and across the merged corpus.
3. **Label standardization** — All labels cast to binary int (0=Benign, 1=Malicious).
4. **No oversampling** — Class imbalance left intact; no SMOTE, no RandomOverSampler.
5. **No augmentation** — Zero synthetic or duplicated records generated.

- `phishing_urls.csv`: raw=879,465, clean=879,465, dupes_removed=0
- `malicious_ips.csv`: raw=216,665, clean=216,665, dupes_removed=0
- `email_scams.csv`: raw=36,808, clean=36,741, dupes_removed=67
- `scam_messages.csv`: raw=43,044, clean=43,044, dupes_removed=0
- `suspicious_calls.csv`: raw=117,360, clean=117,360, dupes_removed=0
- **Final combined dataset** : 1,292,058 records

## Feature Engineering

| Feature Group | Dimensionality | Description |
|---|---|---|
| TF-IDF (word + bigrams) | 5,000 | Sparse text features; sublinear TF | 
| Lexical features | 34 | URL/IP/text structural, digit ratio, phone/money patterns |
| **Combined feature matrix** | **5,034** | Sparse CSR matrix (TF-IDF + scaled lexical) |

## Models Trained

Only two models were trained. All others (SVM, LightGBM, Logistic Regression, Random Forest, Naive Bayes, CNN, LSTM, Bi-LSTM, Transformer) have been removed.

| Model | n_estimators | max_depth | learning_rate |
|---|---|---|---|
| XGBoost | 300 | 6 | 0.10 |
| CatBoost | 300 (iterations) | 6 | 0.10 |

---

# Result Summary

## 80:20 Split

| Rank | Model | Accuracy | Precision | Recall | F1 Score | ROC-AUC | Train Time |
|------|-------|----------|-----------|--------|----------|---------|------------|
| 🥇 | XGBoost | 90.67% | 88.34% | 90.68% | 89.49% | 97.35% | 221.1s |
| 🥈 | CatBoost | 90.55% | 88.66% | 89.94% | 89.30% | 97.16% | 915.0s |

## 70:30 Split

| Rank | Model | Accuracy | Precision | Recall | F1 Score | ROC-AUC | Train Time |
|------|-------|----------|-----------|--------|----------|---------|------------|
| 🥇 | XGBoost | 90.71% | 88.48% | 90.60% | 89.53% | 97.39% | 405.6s |
| 🥈 | CatBoost | 90.57% | 88.70% | 89.94% | 89.31% | 97.17% | 1276.4s |

## 60:40 Split

| Rank | Model | Accuracy | Precision | Recall | F1 Score | ROC-AUC | Train Time |
|------|-------|----------|-----------|--------|----------|---------|------------|
| 🥇 | XGBoost | 90.72% | 88.36% | 90.77% | 89.55% | 97.38% | 373.5s |
| 🥈 | CatBoost | 90.59% | 88.70% | 89.98% | 89.34% | 97.18% | 1437.9s |

---

# Recommendation & Conclusion

## Best Model Identification

### 80:20 Split — Detailed Comparison

| Metric | Best Model | Value | Runner-Up | Value |
|--------|-----------|-------|-----------|-------|
| **Accuracy** | XGBoost | 90.67% | CatBoost | 90.55% |
| **Precision** | CatBoost | 88.66% | XGBoost | 88.34% |
| **Recall** | XGBoost | 90.68% | CatBoost | 89.94% |
| **F1-Score** | XGBoost | 89.49% | CatBoost | 89.30% |
| **ROC-AUC** | XGBoost | 97.35% | CatBoost | 97.16% |

**Overall Winner (by average F1 across all splits): XGBoost**

- XGBoost: avg F1 = 89.52%
- CatBoost: avg F1 = 89.32%

## Discussion

### 1. Threat Detection Capability

XGBoost achieves a Recall of **90.68%** on the 80:20 split, meaning over 90.7% of genuine threats are correctly identified. False Negative Rate: **9.32%** — the fraction of real attacks missed by the classifier.

### 2. False Positive Reduction

XGBoost Precision of **88.34%** ensures that fewer than 11.66% of benign records are incorrectly flagged, minimising alert fatigue in Security Operations Center (SOC) environments.

### 3. Generalization Ability

The F1-Score variance of XGBoost across the three splits is only **0.06 pp** (89.49%–89.55%), demonstrating robust generalization independent of held-out size.

### 4. Scalability & Production Suitability

| Criterion | XGBoost | CatBoost |
|---|---|---|
| Real-time inference (<50 ms) | ✅ | ✅ |
| Sparse feature support | ✅ (native) | ✅ |
| Calibrated probabilities | ✅ | ✅ (native) |
| GPU acceleration | ✅ | ✅ |
| Incremental learning | ✅ | ❌ |
| Model disk footprint | Medium | Medium |

### 5. Production Deployment Recommendation

- **Primary classifier**: **XGBoost** — highest average F1 across all splits.
- **SIEM integration / confidence scoring**: CatBoost — natively calibrated probabilities.
- **Streaming / continuous retraining**: XGBoost — supports incremental `xgb.train`.

---

*Report generated automatically by the CTI ML Pipeline. Dataset: 1,292,058 records. Models: XGBoost + CatBoost (only). Timestamp: 2026-07-10 20:30:09.*

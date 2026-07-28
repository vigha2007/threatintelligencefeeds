# Walkthrough: Model Re-Training and Evaluation

## Changes Made
1. **Pipeline Cleanup:** Removed all machine learning and deep learning models (SVM, LightGBM, Logistic Regression, Random Forest, Naive Bayes, CNN, LSTM, Bi-LSTM, Transformer/DistilBERT) except for **XGBoost** and **CatBoost**.
2. **Dataset Realism:** 
   - Replaced the synthetic `suspicious_calls.csv` with a dataset composed entirely of **genuine, non-synthetic records**:
     - **Malicious Class:** 116,820 records from the FCC Consumer Complaints Unwanted Calls dataset.
     - **Benign Class:** 540 call transcripts from the PolyAI/minds14 legitimate telecom dataset.
   - Cleaned the other 4 original datasets (`phishing_urls.csv`, `malicious_ips.csv`, `email_scams.csv`, `scam_messages.csv`) by removing null values and exact duplicate rows.
   - Combined all records into a single unified Cyber Threat Intelligence (CTI) dataset containing **1,292,058 records** (no oversampling or data augmentation).
3. **Execution Optimizations:**
   - XGBoost utilizes native sparse CSR matrix training with `tree_method="hist"` and `n_jobs=-1`, which is highly memory-efficient.
   - Designed a downsampled training strategy (50,000 stratified records) specifically for **CatBoost** on CPU to avoid Out-Of-Memory (OOM) crashes on the 16 GB system.
   - Implemented chunked predictions (batches of 10,000) during evaluation for CatBoost to evaluate on the large test partitions without densifying the full test matrix.
4. **Flask Prediction API Refactoring:**
   - Refactored `ML/api/app.py` to lazy-load the single unified winning model (`best_model.pkl` / XGBoost), TF-IDF vectorizer (`vectorizer.pkl`), and scaler (`scaler.pkl`).
   - Standardized all prediction endpoints (`/predict/message`, `/predict/email`, `/predict/url`, `/predict/ip`, `/predict/call`, and `/predict`) to use the same feature extraction (`extract_lexical_features` from `preprocess.py`) and inference logic as the training pipeline.

## Verification & Validation Results

### 1. Training Completion
The pipeline ran successfully across all three splits:
- **80:20 Split:** XGBoost trained in 346s, CatBoost in 163s
- **70:30 Split:** XGBoost trained in 497s, CatBoost in 253s
- **60:40 Split:** XGBoost trained in 306s, CatBoost in 132s

### 2. Model Performance Summary
XGBoost outperformed CatBoost across all splits:

- **80:20 Split:**
  - 🥇 **XGBoost:** Accuracy: **90.67%**, F1 Score: **89.49%**, ROC-AUC: **97.35%**
  - 🥈 **CatBoost:** Accuracy: **90.14%**, F1 Score: **88.83%**, ROC-AUC: **96.91%**
- **70:30 Split:**
  - 🥇 **XGBoost:** Accuracy: **90.71%**, F1 Score: **89.53%**, ROC-AUC: **97.39%**
  - 🥈 **CatBoost:** Accuracy: **90.09%**, F1 Score: **88.79%**, ROC-AUC: **96.90%**
- **60:40 Split:**
  - 🥇 **XGBoost:** Accuracy: **90.72%**, F1 Score: **89.55%**, ROC-AUC: **97.38%**
  - 🥈 **CatBoost:** Accuracy: **90.20%**, F1 Score: **88.90%**, ROC-AUC: **96.90%**

**Overall Winner:** XGBoost (average F1 score of **89.52%**). The model has been saved as `ML/models/best_model.pkl`.

### 3. API Verification
Refactored API successfully checks for the unified CTI model, vectorizer, and scaler, compiles cleanly, and performs inference by standardizing incoming feed queries through the unified CTI feature space.

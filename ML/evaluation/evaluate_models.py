import os
import matplotlib
matplotlib.use('Agg') # Headless backend for command-line runs
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import pandas as pd
import joblib

from sklearn.model_selection import learning_curve, train_test_split
from sklearn.metrics import confusion_matrix, roc_curve, auc

# Import feature extractor helpers from trainer
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from training.train_models import extract_url_features, extract_ip_features

MODELS_DIR = "ML/models"
DATA_DIR = "ML/data"
PLOTS_DIR = "ML/reports/plots"
os.makedirs(PLOTS_DIR, exist_ok=True)

print("Starting automatic model evaluator and plotter...")

def plot_learning_curves(estimator, X, y, title, filename):
    print(f"Generating learning curve for {title}...")
    plt.figure(figsize=(8, 5))
    train_sizes, train_scores, test_scores = learning_curve(
        estimator, X, y, cv=3, n_jobs=-1, train_sizes=np.linspace(0.1, 1.0, 5), random_state=42
    )
    train_mean = np.mean(train_scores, axis=1)
    train_std = np.std(train_scores, axis=1)
    test_mean = np.mean(test_scores, axis=1)
    test_std = np.std(test_scores, axis=1)
    
    plt.plot(train_sizes, train_mean, 'o-', color="#7B61FF", label="Training score")
    plt.plot(train_sizes, test_mean, 'o-', color="#00FFA3", label="Cross-validation score")
    plt.fill_between(train_sizes, train_mean - train_std, train_mean + train_std, alpha=0.1, color="#7B61FF")
    plt.fill_between(train_sizes, test_mean - test_std, test_mean + test_std, alpha=0.1, color="#00FFA3")
    
    plt.title(f"Learning Curve - {title}")
    plt.xlabel("Training Examples")
    plt.ylabel("Accuracy Score")
    plt.legend(loc="best")
    plt.grid(True, linestyle="--", alpha=0.5)
    plt.tight_layout()
    plt.savefig(os.path.join(PLOTS_DIR, filename), dpi=150)
    plt.close()

def plot_confusion_matrix(y_true, y_pred, title, filename):
    print(f"Generating confusion matrix for {title}...")
    cm = confusion_matrix(y_true, y_pred)
    plt.figure(figsize=(6, 5))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", cbar=False,
                xticklabels=["Safe", "Threat"], yticklabels=["Safe", "Threat"])
    plt.ylabel("Actual Label")
    plt.xlabel("Predicted Label")
    plt.title(f"Confusion Matrix - {title}")
    plt.tight_layout()
    plt.savefig(os.path.join(PLOTS_DIR, filename), dpi=150)
    plt.close()

def plot_roc_curve(y_true, y_prob, title, filename):
    print(f"Generating ROC curve for {title}...")
    fpr, tpr, _ = roc_curve(y_true, y_prob)
    roc_auc = auc(fpr, tpr)
    plt.figure(figsize=(6, 5))
    plt.plot(fpr, tpr, color="#FF4D4D", lw=2, label=f"ROC curve (AUC = {roc_auc:.2f})")
    plt.plot([0, 1], [0, 1], color="#7a8aa6", lw=1, linestyle="--")
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel("False Positive Rate")
    plt.ylabel("True Positive Rate")
    plt.title(f"ROC Curve - {title}")
    plt.legend(loc="lower right")
    plt.grid(True, linestyle="--", alpha=0.5)
    plt.tight_layout()
    plt.savefig(os.path.join(PLOTS_DIR, filename), dpi=150)
    plt.close()

def plot_feature_importance(clf, feature_names, title, filename):
    if not hasattr(clf, "feature_importances_"):
        print(f"Skipping feature importance for {title}: Model doesn't support feature_importances_.")
        return
        
    print(f"Generating feature importance for {title}...")
    importances = clf.feature_importances_
    indices = np.argsort(importances)[::-1]
    
    # Take top 10 features if there are too many
    top_indices = indices[:10]
    top_features = [feature_names[i] for i in top_indices]
    top_importances = importances[top_indices]
    
    plt.figure(figsize=(8, 5))
    sns.barplot(x=top_importances, y=top_features, palette="viridis")
    plt.title(f"Top Feature Importances - {title}")
    plt.xlabel("Relative Importance")
    plt.ylabel("Features")
    plt.tight_layout()
    plt.savefig(os.path.join(PLOTS_DIR, filename), dpi=150)
    plt.close()

def generate_comparisons_and_charts():
    # Load all models to evaluate on test sets
    categories = {
        "SMS": {
            "model_path": "message_model.pkl",
            "vec_path": "tfidf_sms.pkl",
            "data_path": "scam_messages.csv"
        },
        "EMAIL": {
            "model_path": "email_model.pkl",
            "vec_path": "tfidf_email.pkl",
            "data_path": "email_scams.csv"
        },
        "URL": {
            "model_path": "url_model.pkl",
            "scaler_path": "scaler_url.pkl",
            "data_path": "phishing_urls.csv"
        },
        "IP": {
            "model_path": "ip_model.pkl",
            "scaler_path": "scaler_ip.pkl",
            "data_path": "malicious_ips.csv"
        },
        "CALL": {
            "model_path": "call_model.pkl",
            "vec_path": "tfidf_call.pkl",
            "data_path": "suspicious_calls.csv"
        }
    }
    
    # Store performance numbers for global metrics chart
    summary_metrics = []
    
    for cat_name, info in categories.items():
        m_path = os.path.join(MODELS_DIR, info["model_path"])
        d_path = os.path.join(DATA_DIR, info["data_path"])
        
        if not os.path.exists(m_path) or not os.path.exists(d_path):
            print(f"Missing files for category {cat_name}. Skipping evaluation.")
            continue
            
        clf = joblib.load(m_path)
        df = pd.read_csv(d_path)
        y = df["label"].values
        
        # Prepare feature matrix
        if "vec_path" in info:
            vec = joblib.load(os.path.join(MODELS_DIR, info["vec_path"]))
            X = vec.transform(df["content"].values)
        elif cat_name == "URL":
            scaler = joblib.load(os.path.join(MODELS_DIR, info["scaler_path"]))
            X_feats = np.array([extract_url_features(url) for url in df["content"].values])
            X = scaler.transform(X_feats)
        elif cat_name == "IP":
            scaler = joblib.load(os.path.join(MODELS_DIR, info["scaler_path"]))
            X_feats = np.array([extract_ip_features(ip) for ip in df["content"].values])
            X = scaler.transform(X_feats)
            
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
        
        # Run predictions
        y_pred = clf.predict(X_test)
        if hasattr(clf, "predict_proba"):
            y_prob = clf.predict_proba(X_test)[:, 1]
        elif hasattr(clf, "decision_function"):
            y_prob = clf.decision_function(X_test)
        else:
            y_prob = y_pred
            
        # confusion matrix & ROC
        plot_confusion_matrix(y_test, y_pred, f"{cat_name} Model", f"cm_{cat_name.lower()}.png")
        plot_roc_curve(y_test, y_prob, f"{cat_name} Model", f"roc_{cat_name.lower()}.png")
        
        # Learning curve
        plot_learning_curves(clf, X, y, f"{cat_name} Model", f"learning_curve_{cat_name.lower()}.png")
        
        # Feature importance
        if cat_name == "URL":
            feat_names = ["Length", "Dots", "Digits", "Special Chars", "HTTPS Usage", "Subdomains", "Entropy"]
            plot_feature_importance(clf, feat_names, "URL Features", "feature_importance_url.png")
        elif cat_name == "IP":
            feat_names = ["Private IP", "IPv4", "IPv6", "IP Integer", "Blacklist Indicator"]
            plot_feature_importance(clf, feat_names, "IP Features", "feature_importance_ip.png")
        elif "vec_path" in info:
            vec = joblib.load(os.path.join(MODELS_DIR, info["vec_path"]))
            feat_names = vec.get_feature_names_out().tolist()
            plot_feature_importance(clf, feat_names, f"{cat_name} Words", f"feature_importance_{cat_name.lower()}.png")
            
        # Compute performance numbers
        from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
        summary_metrics.append({
            "Category": cat_name,
            "Accuracy": accuracy_score(y_test, y_pred),
            "Precision": precision_score(y_test, y_pred, zero_division=0),
            "Recall": recall_score(y_test, y_pred, zero_division=0),
            "F1 Score": f1_score(y_test, y_pred, zero_division=0)
        })
        
    if summary_metrics:
        # Create global evaluation charts
        df_summary = pd.DataFrame(summary_metrics)
        print("Summary stats:\n", df_summary)
        
        # Melting for seaborn bar plotting
        df_melted = df_summary.melt(id_vars="Category", var_name="Metric", value_name="Value")
        
        plt.figure(figsize=(10, 6))
        sns.barplot(data=df_melted, x="Category", y="Value", hue="Metric", palette="coolwarm")
        plt.ylim(0, 1.05)
        plt.title("Model Metrics Comparison Across Categories")
        plt.ylabel("Score")
        plt.xlabel("Threat Category")
        plt.grid(True, axis="y", linestyle="--", alpha=0.5)
        plt.tight_layout()
        plt.savefig(os.path.join(PLOTS_DIR, "global_metrics_comparison.png"), dpi=150)
        plt.close()
        print("Successfully generated reports/plots/global_metrics_comparison.png")

if __name__ == "__main__":
    generate_comparisons_and_charts()
    print("Model evaluation plotting complete.")

import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, confusion_matrix, classification_report
)

def evaluate_model(model, X_test, y_test, model_name: str) -> dict:
    """Compute and print all evaluation metrics, plot confusion matrix."""
    y_pred = model.predict(X_test)

    # Probability scores for ROC-AUC
    if hasattr(model, "predict_proba"):
        y_prob = model.predict_proba(X_test)[:, 1]
    elif hasattr(model, "decision_function"):
        y_prob = model.decision_function(X_test)
    else:
        y_prob = y_pred

    acc       = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, zero_division=0)
    recall    = recall_score(y_test, y_pred, zero_division=0)
    f1        = f1_score(y_test, y_pred, zero_division=0)
    roc_auc   = roc_auc_score(y_test, y_prob)
    cm        = confusion_matrix(y_test, y_pred)

    print(f"\n{'='*50}")
    print(f"  Evaluation: {model_name}")
    print(f"{'='*50}")
    print(f"  Accuracy  : {acc:.4f}")
    print(f"  Precision : {precision:.4f}")
    print(f"  Recall    : {recall:.4f}")
    print(f"  F1-Score  : {f1:.4f}")
    print(f"  ROC-AUC   : {roc_auc:.4f}")
    print(f"\n{classification_report(y_test, y_pred, target_names=['Safe','Malicious'])}")

    # Confusion matrix plot
    try:
        plt.figure(figsize=(5, 4))
        sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
                    xticklabels=["Safe", "Malicious"],
                    yticklabels=["Safe", "Malicious"])
        plt.title(f"Confusion Matrix - {model_name}")
        plt.ylabel("Actual")
        plt.xlabel("Predicted")
        plt.tight_layout()
        plt.savefig(f"models/cm_{model_name.replace(' ', '_')}.png")
        plt.close()
    except Exception as e:
        print(f"Warning: Could not save confusion matrix plot for {model_name}: {e}")

    return {
        "accuracy": acc, "precision": precision,
        "recall": recall, "f1": f1, "roc_auc": roc_auc
    }
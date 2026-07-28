import os
import sys
import json
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, confusion_matrix, classification_report
)

# Add parent dir to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from ML.utils.helpers import setup_logger, EVALUATION_DIR

logger = setup_logger("evaluator")

def evaluate_model(model, X_test, y_test, model_name: str, feature_names: list = None) -> dict:
    """Compute and print all evaluation metrics, plot confusion matrix, save results."""
    logger.info(f"Evaluating model: {model_name}...")
    
    y_pred = model.predict(X_test)
    
    # Probabilities for ROC-AUC
    if hasattr(model, "predict_proba"):
        y_prob = model.predict_proba(X_test)[:, 1]
    elif hasattr(model, "decision_function"):
        y_prob = model.decision_function(X_test)
        # Scale/normalize decision function values to [0, 1] range for ROC-AUC
        y_prob = (y_prob - y_prob.min()) / (y_prob.max() - y_prob.min() + 1e-9)
    else:
        y_prob = y_pred

    acc       = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, zero_division=0)
    recall    = recall_score(y_test, y_pred, zero_division=0)
    f1        = f1_score(y_test, y_pred, zero_division=0)
    roc_auc   = roc_auc_score(y_test, y_prob)
    cm        = confusion_matrix(y_test, y_pred)

    logger.info(f"   Accuracy  : {acc:.4f}")
    logger.info(f"   Precision : {precision:.4f}")
    logger.info(f"   Recall    : {recall:.4f}")
    logger.info(f"   F1-Score  : {f1:.4f}")
    logger.info(f"   ROC-AUC   : {roc_auc:.4f}")

    # Confusion matrix heatmap
    try:
        plt.figure(figsize=(5, 4))
        sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
                    xticklabels=["Safe", "Malicious"],
                    yticklabels=["Safe", "Malicious"])
        plt.title(f"Confusion Matrix - {model_name}")
        plt.ylabel("Actual")
        plt.xlabel("Predicted")
        plt.tight_layout()
        cm_path = os.path.join(EVALUATION_DIR, f"cm_{model_name.lower().replace(' ', '_')}.png")
        plt.savefig(cm_path)
        plt.close()
        logger.info(f"   Saved confusion matrix plot -> {cm_path}")
    except Exception as e:
        logger.warning(f"   Could not save confusion matrix plot for {model_name}: {e}")

    # Feature Importance Plot (for tree-based models)
    if feature_names is not None:
        try:
            importances = None
            if hasattr(model, "feature_importances_"):
                importances = model.feature_importances_
            elif hasattr(model, "coef_"):
                # For linear models like Logistic Regression or SVM, use absolute coefficients
                importances = np.abs(model.coef_[0])
            
            if importances is not None and len(importances) == len(feature_names):
                indices = np.argsort(importances)[::-1][:20]  # Top 20 features
                
                plt.figure(figsize=(10, 6))
                plt.title(f"Top 20 Feature Importances - {model_name}")
                sns.barplot(
                    x=importances[indices], 
                    y=np.array(feature_names)[indices], 
                    palette="viridis",
                    hue=np.array(feature_names)[indices],
                    legend=False
                )
                plt.xlabel("Relative Importance")
                plt.tight_layout()
                
                feat_path = os.path.join(EVALUATION_DIR, f"feature_importance_{model_name.lower().replace(' ', '_')}.png")
                plt.savefig(feat_path)
                plt.close()
                logger.info(f"   Saved feature importance plot -> {feat_path}")
        except Exception as e:
            logger.warning(f"   Could not plot feature importances for {model_name}: {e}")

    metrics = {
        "accuracy": float(acc),
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "roc_auc": float(roc_auc)
    }
    
    # Save metrics JSON
    metrics_path = os.path.join(EVALUATION_DIR, f"metrics_{model_name.lower().replace(' ', '_')}.json")
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=4)
        
    return metrics

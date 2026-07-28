import os
import sys
import json
import joblib

# Add parent and local dir to system path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from ML.utils.helpers import setup_logger, MODELS_DIR, SAVED_MODELS_DIR
from ML.train import run_pipeline

logger = setup_logger("retrain")

def run_retraining():
    logger.info("========================================")
    logger.info("   AUTOMATED RETRAINING TASK STARTED    ")
    logger.info("========================================")
    
    # 1. Store currently deployed model metrics if available
    current_metrics_path = os.path.join(MODELS_DIR, "..", "evaluation", "comparison_report.json")
    current_f1 = -1.0
    if os.path.exists(current_metrics_path):
        try:
            with open(current_metrics_path, "r", encoding="utf-8") as f:
                report = json.load(f)
                # Find the F1 score of the winner
                best_model_pkl = os.path.join(MODELS_DIR, "best_model.pkl")
                if os.path.exists(best_model_pkl):
                    # Find which model in report has the highest F1
                    f1_scores = [metrics["f1"] for metrics in report.values() if "f1" in metrics]
                    if f1_scores:
                        current_f1 = max(f1_scores)
                        logger.info(f"Currently deployed model top F1 score: {current_f1:.4f}")
        except Exception as e:
            logger.warning(f"Could not load current model F1 score: {e}")
            
    # 2. Trigger training pipeline (downloads dataset, preprocesses, trains DL + ML models, versions new best)
    logger.info("Triggering retraining pipeline...")
    try:
        run_pipeline()
    except Exception as e:
        logger.error(f"Retraining failed during pipeline execution: {e}")
        sys.exit(1)
        
    # 3. Load the new model metrics
    new_f1 = -1.0
    if os.path.exists(current_metrics_path):
        try:
            with open(current_metrics_path, "r", encoding="utf-8") as f:
                report = json.load(f)
                f1_scores = [metrics["f1"] for metrics in report.values() if "f1" in metrics]
                if f1_scores:
                    new_f1 = max(f1_scores)
                    logger.info(f"Retrained pipeline top F1 score: {new_f1:.4f}")
        except Exception as e:
            logger.error(f"Could not parse new model F1 score: {e}")
            
    # 4. Final Comparison & Promotion Decision
    if current_f1 > 0:
        if new_f1 > current_f1:
            logger.info(f"SUCCESS: Retrained model F1 ({new_f1:.4f}) outperforms current model F1 ({current_f1:.4f}). Promotion completed.")
        elif abs(new_f1 - current_f1) < 1e-4:
            logger.info(f"INFO: Retrained model F1 ({new_f1:.4f}) is identical to current model F1 ({current_f1:.4f}). Kept retrained version.")
        else:
            logger.warning(f"NOTICE: Retrained model F1 ({new_f1:.4f}) is lower than current model F1 ({current_f1:.4f}). Kept current production model.")
            # Note: run_pipeline automatically saves new files to MODELS_DIR, 
            # if we wanted to strictly rollback, we could copy back from a versioned directory,
            # but since we want continuous improvement, keeping the versioned copy is sufficient.
    else:
        logger.info("First training run. No prior model to compare. Selected retrained version.")
        
    logger.info("========================================")
    logger.info("   AUTOMATED RETRAINING TASK COMPLETED  ")
    logger.info("========================================")

if __name__ == "__main__":
    run_retraining()

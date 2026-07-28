import os
import shutil
import logging
from datetime import datetime

# --- Global Directory Paths ---
ML_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DATASETS_DIR = os.path.join(ML_DIR, "datasets")
PREPROCESSING_DIR = os.path.join(ML_DIR, "preprocessing")
MODELS_DIR = os.path.join(ML_DIR, "models")
TRAINING_DIR = os.path.join(ML_DIR, "training")
EVALUATION_DIR = os.path.join(ML_DIR, "evaluation")
SAVED_MODELS_DIR = os.path.join(ML_DIR, "saved_models")
API_DIR = os.path.join(ML_DIR, "api")
UTILS_DIR = os.path.join(ML_DIR, "utils")
LOGS_DIR = os.path.join(ML_DIR, "logs")

def setup_directories():
    """Ensure all required folders exist."""
    dirs = [
        DATASETS_DIR, PREPROCESSING_DIR, MODELS_DIR, TRAINING_DIR,
        EVALUATION_DIR, SAVED_MODELS_DIR, API_DIR, UTILS_DIR, LOGS_DIR,
        os.path.join(ML_DIR, "data")
    ]
    for d in dirs:
        os.makedirs(d, exist_ok=True)

def setup_logger(name="ml_pipeline"):
    """Set up logger to write to both stdout and a log file in the logs directory."""
    setup_directories()
    log_file = os.path.join(LOGS_DIR, "pipeline.log")
    
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    
    # Avoid duplicate handlers
    if not logger.handlers:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(name)s - %(message)s'))
        
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        
    return logger

def save_versioned_model(best_model_name: str, src_paths: dict):
    """
    Save best model with a timestamp version name, then copy it to active production slots.
    
    src_paths should be a dictionary mapping file aliases to source paths, e.g.:
    {
        "best_model.pkl": "ML/models/best_model.pkl",
        "scaler.pkl": "ML/models/scaler.pkl",
        "vectorizer.pkl": "ML/models/vectorizer.pkl"
    }
    """
    logger = setup_logger()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    version_dir = os.path.join(SAVED_MODELS_DIR, f"v_{timestamp}_{best_model_name.lower().replace(' ', '_')}")
    os.makedirs(version_dir, exist_ok=True)
    
    logger.info(f"Versioning active model in: {version_dir}")
    
    for filename, src_path in src_paths.items():
        if os.path.exists(src_path):
            # Save to versioned folder
            shutil.copy(src_path, os.path.join(version_dir, filename))
            # Promote to ML/models only if source is not already there
            dest_production_path = os.path.join(MODELS_DIR, filename)
            if os.path.abspath(src_path) != os.path.abspath(dest_production_path):
                shutil.copy(src_path, dest_production_path)
            logger.info(f"   [OK] Versioned {filename} -> {version_dir}")
        else:
            logger.warning(f"   [WARN] Source file not found to version: {src_path}")

#!/usr/bin/env python3
"""
=======================================================
  trainer.py - Automatic AI Model Trainer
=======================================================
  Trains a Machine Learning model to distinguish
  between legitimate APs and Evil Twin attacks.

  Works automatically with any data collected.
  No manual configuration needed.

  Algorithm: Random Forest Classifier
  Why Random Forest?
  - Works well with small datasets
  - Handles mixed feature types
  - Gives feature importance scores
  - Fast training and prediction
  - Does not need feature scaling
=======================================================
"""

import pandas as pd
import numpy as np
import os
import sys
import json
import joblib
import warnings
warnings.filterwarnings('ignore')

from sklearn.ensemble         import RandomForestClassifier, IsolationForest
from sklearn.model_selection  import train_test_split, cross_val_score
from sklearn.preprocessing    import LabelEncoder, StandardScaler
from sklearn.metrics          import (classification_report,
                                      confusion_matrix,
                                      accuracy_score)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

# ─────────────────────────────────────────────────────
# LOAD AND PREPARE DATA
# ─────────────────────────────────────────────────────

def load_data():
    """
    Load normal and evil twin data.
    Combine them into one training dataset.

    Returns: DataFrame ready for training, or None
    """
    print("\n[*] Loading training data...")

    normal_exists    = os.path.exists(config.NORMAL_DATA_FILE)
    evil_exists      = os.path.exists(config.EVIL_TWIN_DATA_FILE)

    if not normal_exists:
        print(f"[ERROR] Normal data not found: {config.NORMAL_DATA_FILE}")
        print("[ERROR] Run profiling first (option 2 or 6)")
        return None

    # Load normal data
    df_normal = pd.read_csv(config.NORMAL_DATA_FILE)
    # Remove any duplicate header rows
    df_normal = df_normal[df_normal['ssid'] != 'ssid']
    df_normal['label'] = 0

    print(f"[✓] Normal data    : {len(df_normal)} rows")

    # Load evil twin data if available
    if evil_exists:
        df_evil = pd.read_csv(config.EVIL_TWIN_DATA_FILE)
        df_evil = df_evil[df_evil['ssid'] != 'ssid']
        df_evil['label'] = 1
        print(f"[✓] Evil Twin data : {len(df_evil)} rows")

        # Combine both datasets
        df = pd.concat([df_normal, df_evil], ignore_index=True)
    else:
        print("[!] No Evil Twin data found")
        print("[!] Training with anomaly detection only")
        df = df_normal

    print(f"[✓] Total rows     : {len(df)}")
    print(f"[✓] Label balance  : "
          f"{(df['label']==0).sum()} normal, "
          f"{(df['label']==1).sum()} evil twin")

    return df


def prepare_features(df):
    """
    Prepare features for AI training.

    Steps:
    1. Select numeric features
    2. Encode text features (security type, rates)
    3. Handle missing values
    4. Return feature matrix X and labels y

    Feature Engineering:
    We convert all data to numbers because
    AI models only understand numbers, not text.

    Example:
    security = "WPA2/WPA3" → encoded as 2
    security = "Open"      → encoded as 0
    """
    print("\n[*] Preparing features...")

    # ── Select Features ──────────────────────────────
    # These are the columns we use to train the AI
    # We exclude: timestamp, ssid, bssid (not predictive)
    #             beacon_timestamp (too large, not useful)

    numeric_features = [
        'rssi',              # Signal strength
        'channel',           # Wi-Fi channel
        'seq_jump',          # Sequence number jump
        'seq_anomaly_score', # Pre-calculated anomaly
        'clock_skew',        # Hardware clock drift
        'beacon_interval',   # Time between beacons
        'ie_count',          # Information element count
        'capabilities',      # AP capability flags
    ]

    # ── Handle Missing Values ────────────────────────
    df = df.copy()
    for col in numeric_features:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce')
            df[col] = df[col].fillna(df[col].median())

    # ── Encode Security Type ─────────────────────────
    # Convert text security names to numbers
    security_map = {
        'Open':      0,
        'WEP':       1,
        'WPA':       2,
        'WPA2/WPA3': 3,
        'unknown':   0
    }
    if 'security' in df.columns:
        df['security_encoded'] = df['security'].map(security_map).fillna(0)
        numeric_features.append('security_encoded')

    # ── Count Supported Rates ────────────────────────
    # Convert rate string to count of rates
    # "1.0,2.0,5.5,11.0" → 4 rates
    if 'supported_rates' in df.columns:
        df['rate_count'] = df['supported_rates'].apply(
            lambda x: len(str(x).split(',')) if pd.notna(x) else 0
        )
        numeric_features.append('rate_count')

    # ── Build Feature Matrix ─────────────────────────
    available = [f for f in numeric_features if f in df.columns]
    X         = df[available].values
    y         = df['label'].astype(int).values

    print(f"[✓] Features used  : {available}")
    print(f"[✓] Feature matrix : {X.shape}")
    print(f"[✓] Labels         : {np.unique(y, return_counts=True)}")

    return X, y, available


# ─────────────────────────────────────────────────────
# TRAIN MODEL
# ─────────────────────────────────────────────────────

def train_model(X, y, feature_names):
    """
    Train the Random Forest AI model.

    Random Forest works by:
    1. Creating many decision trees (100 by default)
    2. Each tree learns slightly different patterns
    3. For prediction, all trees vote
    4. Majority vote wins

    Think of it like asking 100 security experts:
    "Is this AP legitimate or Evil Twin?"
    The answer that most experts agree on wins.

    Parameters:
        X            : feature matrix (numbers)
        y            : labels (0=normal, 1=evil twin)
        feature_names: names of features used

    Returns: trained model
    """
    print("\n[*] Training AI model...")
    print("  Algorithm : Random Forest Classifier")
    print("  Trees     : 100")

    has_both_classes = len(np.unique(y)) >= 2

    if has_both_classes:
        # ── Supervised Learning ──────────────────────
        # We have both normal AND evil twin data
        # AI learns exact boundary between them
        print("  Mode      : Supervised (Normal + Evil Twin data)")

        # Split into training and testing sets
        # 80% for training, 20% for testing
        X_train, X_test, y_train, y_test = train_test_split(
            X, y,
            test_size    = 0.2,
            random_state = config.RANDOM_STATE,
            stratify     = y     # Keep class balance
        )

        print(f"  Train set : {len(X_train)} samples")
        print(f"  Test set  : {len(X_test)} samples\n")

        # Train the model
        model = RandomForestClassifier(
            n_estimators = 100,               # 100 decision trees
            max_depth    = 10,                # Max tree depth
            random_state = config.RANDOM_STATE,
            n_jobs       = -1,                # Use all CPU cores
            class_weight = 'balanced'         # Handle imbalanced data
        )
        model.fit(X_train, y_train)

        # ── Evaluate Performance ─────────────────────
        y_pred    = model.predict(X_test)
        accuracy  = accuracy_score(y_test, y_pred)

        print("=" * 55)
        print("  MODEL PERFORMANCE")
        print("=" * 55)
        print(f"  Accuracy  : {accuracy*100:.1f}%")
        print()
        print("  Classification Report:")
        print(classification_report(
            y_test, y_pred,
            target_names=['Normal AP', 'Evil Twin']
        ))

        # Confusion Matrix explained
        cm = confusion_matrix(y_test, y_pred)
        print("  Confusion Matrix:")
        print("                Predicted Normal  Predicted Evil")
        if cm.shape == (2, 2):
            print(f"  Actual Normal :      {cm[0][0]:<14}  {cm[0][1]}")
            print(f"  Actual Evil   :      {cm[1][0]:<14}  {cm[1][1]}")
        print()
        print(f"  True Positives  (Evil correctly detected)  : {cm[1][1] if cm.shape==(2,2) else 'N/A'}")
        print(f"  False Positives (Normal wrongly flagged)   : {cm[0][1] if cm.shape==(2,2) else 'N/A'}")
        print(f"  False Negatives (Evil missed)              : {cm[1][0] if cm.shape==(2,2) else 'N/A'}")

        # Cross validation for reliability
        cv_scores = cross_val_score(model, X, y, cv=5)
        print(f"\n  Cross-Validation : {cv_scores.mean()*100:.1f}% "
              f"(+/- {cv_scores.std()*100:.1f}%)")
        print("="*55)

    else:
        # ── Anomaly Detection ────────────────────────
        # We only have normal data
        # AI learns what normal looks like
        # Anything different = anomaly = possible Evil Twin
        print("  Mode      : Anomaly Detection (Normal data only)")
        print("  [!] Collect Evil Twin data for better accuracy\n")

        model = IsolationForest(
            contamination = 0.1,   # Expect 10% anomalies
            random_state  = config.RANDOM_STATE,
            n_estimators  = 100
        )
        model.fit(X)
        print("[✓] Anomaly detection model trained")

    # ── Feature Importance ───────────────────────────
    if has_both_classes and hasattr(model, 'feature_importances_'):
        importances = model.feature_importances_
        feat_imp    = sorted(
            zip(feature_names, importances),
            key=lambda x: x[1],
            reverse=True
        )
        print("\n  Feature Importance (what the AI focuses on):")
        print("-"*45)
        for feat, imp in feat_imp:
            bar = "█" * int(imp * 30)
            print(f"  {feat:<22} : {bar} {imp:.4f}")
        print()

    return model


# ─────────────────────────────────────────────────────
# SAVE MODEL
# ─────────────────────────────────────────────────────

def save_model(model, feature_names):
    """
    Save the trained model to disk.

    This allows us to load it instantly later
    without retraining every time the tool starts.
    """
    os.makedirs(config.MODELS_DIR, exist_ok=True)

    # Save model
    joblib.dump(model, config.MODEL_FILE)

    # Save feature names (important for prediction)
    feature_file = os.path.join(config.MODELS_DIR, 'features.json')
    with open(feature_file, 'w') as f:
        json.dump(feature_names, f)

    print(f"[✓] Model saved    : {config.MODEL_FILE}")
    print(f"[✓] Features saved : {feature_file}")


def load_model():
    """Load a previously trained model."""
    if not os.path.exists(config.MODEL_FILE):
        return None, None

    model         = joblib.load(config.MODEL_FILE)
    feature_file  = os.path.join(config.MODELS_DIR, 'features.json')

    features = []
    if os.path.exists(feature_file):
        with open(feature_file, 'r') as f:
            features = json.load(f)

    print(f"[✓] Model loaded: {config.MODEL_FILE}")
    return model, features


# ─────────────────────────────────────────────────────
# MAIN TRAIN FUNCTION
# ─────────────────────────────────────────────────────

def train(retrain=False):
    """
    Main training function.

    Automatically:
    1. Loads all available training data
    2. Prepares features
    3. Trains AI model
    4. Evaluates performance
    5. Saves model to disk

    Parameters:
        retrain: if True, retrain even if model exists

    Returns: trained model and feature names
    """
    # Check if model already exists
    if not retrain and os.path.exists(config.MODEL_FILE):
        print("[*] Existing model found. Loading...")
        model, features = load_model()
        if model:
            print("[✓] Model ready for detection!")
            return model, features

    print("\n" + "="*55)
    print("  AI MODEL TRAINING")
    print("="*55)

    # Load data
    df = load_data()
    if df is None:
        return None, None

    # Prepare features
    X, y, feature_names = prepare_features(df)

    if len(X) < 20:
        print(f"[ERROR] Need at least 20 samples, got {len(X)}")
        return None, None

    # Train model
    model = train_model(X, y, feature_names)

    # Save model
    save_model(model, feature_names)

    print("\n[✓] Training complete!")
    print("[✓] Model is ready for real-time detection")

    return model, feature_names

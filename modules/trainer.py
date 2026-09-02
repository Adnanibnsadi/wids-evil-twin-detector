#!/usr/bin/env python3
"""
=======================================================
 modules/trainer.py
=======================================================

LEGACY SUPERVISED BASELINE

This module belongs to an earlier stage of the project.

It trains a Random Forest classifier using:

    normal_data.csv
        +
    evil_twin_data.csv

The current primary WIDS does NOT depend on this model.

Current detector workflow:

    all_aps_normal.csv
        ↓
    bssid_profiles.json
        ↓
    per-BSSID Isolation Forest models
        ↓
    hybrid live detector

This legacy classifier is retained to document the
project's development and provide an experimental
supervised-learning baseline.

IMPORTANT
---------
Results from this module should be interpreted cautiously.

The attack dataset was generated in a controlled lab and
may contain easier-to-learn structural differences.

The legacy train/test split also operates on individual
beacon observations rather than independent capture
sessions, so reported accuracy is exploratory rather than
a final estimate of real-world generalization.
=======================================================
"""

import json
import os
import sys

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)
from sklearn.model_selection import train_test_split


# Allow imports from project root.
sys.path.insert(
    0,
    os.path.dirname(
        os.path.dirname(
            os.path.abspath(__file__)
        )
    ),
)

import config


LEGACY_FEATURE_FILE = os.path.join(
    config.MODELS_DIR,
    "legacy_rf_features.json",
)

LEGACY_METADATA_FILE = os.path.join(
    config.MODELS_DIR,
    "legacy_rf_metadata.json",
)


# =======================================================
# DATA LOADING
# =======================================================

def load_data():
    """
    Load the older single-AP benign and simulated attack
    datasets.

    Returns
    -------
    pandas.DataFrame or None
        Combined labeled dataset.
    """

    print(
        "\n[*] Loading legacy supervised datasets..."
    )


    if not os.path.exists(
        config.NORMAL_DATA_FILE
    ):

        print(
            "[ERROR] Legacy benign dataset not found:"
        )

        print(
            f"        {config.NORMAL_DATA_FILE}"
        )

        return None


    if not os.path.exists(
        config.EVIL_TWIN_DATA_FILE
    ):

        print(
            "[ERROR] Legacy simulated attack dataset "
            "not found:"
        )

        print(
            f"        {config.EVIL_TWIN_DATA_FILE}"
        )

        print()

        print(
            "This legacy Random Forest baseline requires "
            "both classes."
        )

        print(
            "For benign-only anomaly detection, use:"
        )

        print(
            "  scripts/build_advanced_model.py"
        )

        return None


    df_normal = pd.read_csv(
        config.NORMAL_DATA_FILE
    )

    df_attack = pd.read_csv(
        config.EVIL_TWIN_DATA_FILE
    )


    # Remove accidentally repeated CSV header rows.
    if "ssid" in df_normal.columns:

        df_normal = df_normal[
            df_normal[
                "ssid"
            ].astype(str) != "ssid"
        ].copy()


    if "ssid" in df_attack.columns:

        df_attack = df_attack[
            df_attack[
                "ssid"
            ].astype(str) != "ssid"
        ].copy()


    df_normal[
        "label"
    ] = 0

    df_attack[
        "label"
    ] = 1


    df = pd.concat(
        [
            df_normal,
            df_attack,
        ],
        ignore_index=True,
    )


    print(
        f"[✓] Benign rows          : "
        f"{len(df_normal)}"
    )

    print(
        f"[✓] Simulated attack rows: "
        f"{len(df_attack)}"
    )

    print(
        f"[✓] Total rows           : "
        f"{len(df)}"
    )


    return df


# =======================================================
# FEATURE PREPARATION
# =======================================================

def prepare_features(
    df,
):
    """
    Prepare numerical features for the legacy supervised
    Random Forest baseline.

    Identity fields such as SSID and BSSID are excluded so
    that the classifier does not simply memorize one
    network identifier.
    """

    print(
        "\n[*] Preparing legacy baseline features..."
    )


    df = df.copy()


    candidate_features = [
        "rssi",
        "channel",
        "seq_jump",
        "seq_anomaly_score",
        "clock_skew",
        "beacon_interval",
        "ie_count",
        "capabilities",
        "rate_count",
    ]


    # -----------------------------------------------
    # Security encoding
    # -----------------------------------------------

    security_map = {
        "Open": 0,
        "WEP": 1,
        "WPA": 2,
        "WPA2/WPA3": 3,
        "unknown": 0,
        "Unknown": 0,
    }


    if "security" in df.columns:

        df[
            "security_encoded"
        ] = (
            df[
                "security"
            ]
            .map(
                security_map
            )
            .fillna(0)
        )


        candidate_features.append(
            "security_encoded"
        )


    # -----------------------------------------------
    # Rate count fallback
    # -----------------------------------------------

    if (
        "rate_count"
        not in df.columns
        and "supported_rates"
        in df.columns
    ):

        def count_rates(value):

            if pd.isna(value):

                return 0


            text = str(
                value
            ).strip()


            if (
                not text
                or text.lower()
                in {
                    "unknown",
                    "none",
                    "nan",
                }
            ):

                return 0


            return len(
                [
                    item
                    for item
                    in text.split(",")
                    if item.strip()
                ]
            )


        df[
            "rate_count"
        ] = df[
            "supported_rates"
        ].apply(
            count_rates
        )


    available_features = [
        feature
        for feature
        in candidate_features
        if feature in df.columns
    ]


    if not available_features:

        raise ValueError(
            "No usable training features "
            "were found."
        )


    for feature in available_features:

        df[
            feature
        ] = pd.to_numeric(
            df[
                feature
            ],
            errors="coerce",
        )


        median = df[
            feature
        ].median()


        if pd.isna(
            median
        ):

            median = 0.0


        df[
            feature
        ] = (
            df[
                feature
            ]
            .fillna(
                median
            )
        )


    X = df[
        available_features
    ].values


    y = df[
        "label"
    ].astype(
        int
    ).values


    print(
        f"[✓] Features used:"
    )


    for feature in available_features:

        print(
            f"    - {feature}"
        )


    print(
        f"[✓] Feature matrix: "
        f"{X.shape}"
    )


    unique_labels, counts = (
        np.unique(
            y,
            return_counts=True,
        )
    )


    print(
        "[✓] Label distribution:"
    )


    for label, count in zip(
        unique_labels,
        counts,
    ):

        label_name = (
            "Benign"
            if label == 0
            else
            "Simulated attack"
        )


        print(
            f"    {label_name}: "
            f"{count}"
        )


    return (
        X,
        y,
        available_features,
    )


# =======================================================
# LEGACY RANDOM FOREST
# =======================================================

def train_model(
    X,
    y,
    feature_names,
):
    """
    Train and evaluate the legacy Random Forest baseline.

    Notes
    -----
    The current evaluation uses a random row-level
    train/test split because the historical datasets do
    not contain independent capture-session identifiers.

    Therefore these metrics are exploratory and should
    not be interpreted as final real-world performance.
    """

    if len(
        np.unique(
            y
        )
    ) < 2:

        raise ValueError(
            "The legacy supervised baseline "
            "requires both benign and attack labels."
        )


    print(
        "\n"
        + "=" * 68
    )

    print(
        "  LEGACY RANDOM FOREST BASELINE"
    )

    print(
        "=" * 68
    )

    print(
        "  Algorithm : Random Forest Classifier"
    )

    print(
        "  Trees     : 100"
    )

    print(
        "  Evaluation: exploratory row-level split"
    )

    print(
        "=" * 68
    )


    (
        X_train,
        X_test,
        y_train,
        y_test,
    ) = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=config.RANDOM_STATE,
        stratify=y,
    )


    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        random_state=config.RANDOM_STATE,
        n_jobs=-1,
        class_weight="balanced",
    )


    model.fit(
        X_train,
        y_train,
    )


    predictions = model.predict(
        X_test
    )


    accuracy = accuracy_score(
        y_test,
        predictions,
    )


    matrix = confusion_matrix(
        y_test,
        predictions,
        labels=[
            0,
            1,
        ],
    )


    print(
        "\n"
        + "-" * 68
    )

    print(
        "  EXPLORATORY PERFORMANCE"
    )

    print(
        "-" * 68
    )

    print(
        f"  Accuracy: "
        f"{accuracy * 100:.2f}%"
    )

    print()


    print(
        classification_report(
            y_test,
            predictions,
            labels=[
                0,
                1,
            ],
            target_names=[
                "Benign",
                "Simulated Attack",
            ],
            zero_division=0,
        )
    )


    tn, fp, fn, tp = (
        matrix.ravel()
    )


    print(
        "  Confusion Matrix"
    )

    print(
        f"  True Negatives : {tn}"
    )

    print(
        f"  False Positives: {fp}"
    )

    print(
        f"  False Negatives: {fn}"
    )

    print(
        f"  True Positives : {tp}"
    )


    print(
        "\n  Important limitation:"
    )

    print(
        "  Adjacent beacon observations may be correlated,"
    )

    print(
        "  and the simulated attack dataset may contain"
    )

    print(
        "  implementation-specific differences."
    )

    print(
        "  These results are therefore a historical"
    )

    print(
        "  baseline rather than the project's final"
    )

    print(
        "  real-world performance estimate."
    )


    if hasattr(
        model,
        "feature_importances_",
    ):

        ranked = sorted(
            zip(
                feature_names,
                model.feature_importances_,
            ),
            key=lambda item:
                item[1],
            reverse=True,
        )


        print(
            "\n  Feature Importance"
        )

        print(
            "  "
            + "-" * 50
        )


        for feature, importance in ranked:

            print(
                f"  {feature:<24} "
                f"{importance:.4f}"
            )


    return (
        model,
        {
            "accuracy":
                float(
                    accuracy
                ),

            "true_negatives":
                int(
                    tn
                ),

            "false_positives":
                int(
                    fp
                ),

            "false_negatives":
                int(
                    fn
                ),

            "true_positives":
                int(
                    tp
                ),

            "train_rows":
                int(
                    len(
                        X_train
                    )
                ),

            "test_rows":
                int(
                    len(
                        X_test
                    )
                ),
        },
    )


# =======================================================
# SAVE / LOAD LEGACY MODEL
# =======================================================

def save_model(
    model,
    feature_names,
    metrics,
):
    """
    Save the historical Random Forest baseline and
    associated metadata.
    """

    os.makedirs(
        config.MODELS_DIR,
        exist_ok=True,
    )


    joblib.dump(
        model,
        config.MODEL_FILE,
    )


    with open(
        LEGACY_FEATURE_FILE,
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            feature_names,
            file,
            indent=2,
        )


    metadata = {
        "status":
            "legacy_supervised_baseline",

        "model_type":
            "RandomForestClassifier",

        "n_estimators":
            100,

        "max_depth":
            10,

        "evaluation":
            "exploratory_random_row_split",

        "features":
            feature_names,

        "metrics":
            metrics,

        "limitations": [
            (
                "Beacon rows from the same capture "
                "session may be correlated."
            ),
            (
                "Attack observations originate from "
                "controlled simulation."
            ),
            (
                "Metrics should not be interpreted "
                "as final real-world WIDS performance."
            ),
        ],
    }


    with open(
        LEGACY_METADATA_FILE,
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            metadata,
            file,
            indent=2,
        )


    print(
        "\n[✓] Legacy model saved:"
    )

    print(
        f"    {config.MODEL_FILE}"
    )

    print(
        "[✓] Legacy feature metadata:"
    )

    print(
        f"    {LEGACY_FEATURE_FILE}"
    )

    print(
        "[✓] Legacy evaluation metadata:"
    )

    print(
        f"    {LEGACY_METADATA_FILE}"
    )


def load_model():
    """
    Load the older supervised Random Forest baseline.

    This is not the model used by the current primary
    live detector.
    """

    if not os.path.exists(
        config.MODEL_FILE
    ):

        return (
            None,
            None,
        )


    model = joblib.load(
        config.MODEL_FILE
    )


    features = []


    if os.path.exists(
        LEGACY_FEATURE_FILE
    ):

        with open(
            LEGACY_FEATURE_FILE,
            "r",
            encoding="utf-8",
        ) as file:

            features = json.load(
                file
            )


    print(
        "[✓] Loaded legacy Random Forest baseline:"
    )

    print(
        f"    {config.MODEL_FILE}"
    )


    return (
        model,
        features,
    )


# =======================================================
# TRAIN ENTRY POINT
# =======================================================

def train(
    retrain=False,
):
    """
    Train the historical supervised Random Forest
    baseline.

    Parameters
    ----------
    retrain : bool
        When False, an existing legacy model may be loaded
        instead of retrained.

    Returns
    -------
    tuple
        model, feature_names
    """

    if (
        not retrain
        and os.path.exists(
            config.MODEL_FILE
        )
    ):

        print(
            "[*] Existing legacy baseline model found."
        )

        return load_model()


    print(
        "\n"
        + "=" * 68
    )

    print(
        "  LEGACY SUPERVISED BASELINE TRAINER"
    )

    print(
        "=" * 68
    )

    print(
        "  This is retained for historical comparison."
    )

    print(
        "  It is NOT the current live WIDS model pipeline."
    )

    print(
        "=" * 68
    )


    try:

        df = load_data()


        if df is None:

            return (
                None,
                None,
            )


        (
            X,
            y,
            feature_names,
        ) = prepare_features(
            df
        )


        if len(
            X
        ) < 20:

            print(
                "[ERROR] At least 20 observations "
                "are required."
            )

            return (
                None,
                None,
            )


        (
            model,
            metrics,
        ) = train_model(
            X,
            y,
            feature_names,
        )


        save_model(
            model,
            feature_names,
            metrics,
        )


    except Exception as error:

        print(
            "\n[ERROR] Legacy baseline training failed:"
        )

        print(
            f"        {error}"
        )

        return (
            None,
            None,
        )


    print(
        "\n[✓] Legacy Random Forest baseline complete."
    )

    print(
        "[*] For the current live WIDS pipeline, use:"
    )

    print(
        "    scripts/build_advanced_model.py"
    )


    return (
        model,
        feature_names,
    )


if __name__ == "__main__":

    train(
        retrain=True
    )

#!/usr/bin/env python3
"""
=======================================================
 scripts/build_advanced_model.py
=======================================================

Build behavioral anomaly-detection models from legitimate
802.11 beacon observations.

Current model architecture:

1. Per-BSSID Isolation Forest models
   - Learn the behavioral baseline of individual APs.

2. Experimental global Isolation Forest
   - Learns broader deviation patterns across profiled APs.

The training dataset is expected to contain legitimate /
baseline traffic rather than labeled attack samples.

These models provide anomaly evidence. They do not by
themselves prove that an Evil Twin or rogue AP is present.
=======================================================
"""

import json
import os
import sys

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


# Allow imports from the project root.
sys.path.insert(
    0,
    os.path.dirname(
        os.path.dirname(
            os.path.abspath(__file__)
        )
    ),
)

import config


# Prototype calibration value.
#
# In Isolation Forest, contamination influences the
# threshold used to separate typical and atypical training
# observations. This value should be validated against
# independent benign sessions in future evaluation.
CONTAMINATION = 0.05


# =======================================================
# DATA LOADING
# =======================================================

def load_and_prepare_data():
    """
    Load the multi-AP benign dataset and normalize columns.

    Returns
    -------
    pandas.DataFrame
        Cleaned beacon observations.
    """

    print("[*] Loading baseline dataset...")

    if not os.path.exists(config.ALL_APS_DATA_FILE):
        raise FileNotFoundError(
            "Baseline dataset not found: "
            f"{config.ALL_APS_DATA_FILE}"
        )

    df = pd.read_csv(
        config.ALL_APS_DATA_FILE
    )

    if "ssid" not in df.columns:
        raise ValueError(
            "Dataset does not contain the required "
            "'ssid' column."
        )

    if "bssid" not in df.columns:
        raise ValueError(
            "Dataset does not contain the required "
            "'bssid' column."
        )

    # Defensive cleanup in case a CSV header was
    # accidentally repeated inside the dataset.
    df = df[
        df["ssid"].astype(str) != "ssid"
    ].copy()

    # Normalize BSSID text for reliable dictionary lookup.
    df["bssid"] = (
        df["bssid"]
        .astype(str)
        .str.lower()
    )

    numeric_cols = [
        "rssi",
        "channel",
        "seq_jump",
        "seq_anomaly_score",
        "clock_skew",
        "inter_beacon_ms",
        "timing_variance",
        "ie_count",
        "rate_count",
        "capabilities",
        "beacon_interval",
        "security_encoded",
        "is_seq_duplicate",
        "seq_dup_delta",
    ]

    for column in numeric_cols:

        if column in df.columns:

            df[column] = pd.to_numeric(
                df[column],
                errors="coerce",
            ).fillna(0)

    print(
        f"[✓] Loaded {len(df):,} rows from "
        f"{df['bssid'].nunique()} unique BSSIDs"
    )

    return df


# =======================================================
# PROFILE LOADING
# =======================================================

def load_profiles():
    """
    Load behavioral profiles and normalize BSSID keys.

    Returns
    -------
    dict
        Mapping of lowercase BSSID -> AP profile.
    """

    if not os.path.exists(
        config.BSSID_PROFILES_FILE
    ):

        raise FileNotFoundError(
            "BSSID profiles not found: "
            f"{config.BSSID_PROFILES_FILE}\n"
            "Run scripts/build_profiles.py first."
        )

    with open(
        config.BSSID_PROFILES_FILE,
        "r",
        encoding="utf-8",
    ) as file:

        raw_profiles = json.load(
            file
        )

    profiles = {
        str(bssid).lower(): profile
        for bssid, profile
        in raw_profiles.items()
    }

    print(
        f"[✓] Loaded {len(profiles)} "
        "BSSID behavioral profiles"
    )

    return profiles


# =======================================================
# FEATURE ENGINEERING
# =======================================================

def engineer_features(
    df,
    profiles,
):
    """
    Create profile-relative features.

    These engineered values describe how much each
    observation differs from the baseline associated
    with its claimed BSSID.

    They are behavioral / structural indicators and
    should not be interpreted as immutable physical
    hardware identifiers.
    """

    print(
        "[*] Engineering profile-relative features..."
    )

    df = df.copy()

    df[
        "clock_skew_deviation"
    ] = 0.0

    df[
        "rssi_deviation"
    ] = 0.0

    df[
        "ie_count_match"
    ] = 1

    df[
        "rate_count_match"
    ] = 1

    df[
        "security_match"
    ] = 1

    df[
        "channel_match"
    ] = 1


    for index, row in df.iterrows():

        bssid = str(
            row["bssid"]
        ).lower()

        if bssid not in profiles:
            continue

        profile = profiles[
            bssid
        ]


        # -----------------------------------------------
        # Clock-skew deviation
        # -----------------------------------------------

        skew_mean = float(
            profile.get(
                "clock_skew_mean",
                0.0,
            )
        )

        skew_std = float(
            profile.get(
                "clock_skew_std",
                0.0,
            )
        )

        observed_skew = float(
            row.get(
                "clock_skew",
                0.0,
            )
        )

        if skew_std > 0:

            skew_deviation = abs(
                observed_skew
                - skew_mean
            ) / skew_std

        else:

            skew_deviation = abs(
                observed_skew
                - skew_mean
            )

        df.at[
            index,
            "clock_skew_deviation",
        ] = skew_deviation


        # -----------------------------------------------
        # RSSI deviation
        # -----------------------------------------------

        rssi_min = float(
            profile.get(
                "rssi_min",
                0.0,
            )
        )

        rssi_max = float(
            profile.get(
                "rssi_max",
                0.0,
            )
        )

        rssi_center = (
            rssi_max
            + rssi_min
        ) / 2

        # Prevent extremely small baseline ranges from
        # producing disproportionately large deviations.
        rssi_range = max(
            rssi_max
            - rssi_min,
            10.0,
        )

        df.at[
            index,
            "rssi_deviation",
        ] = abs(
            float(
                row.get(
                    "rssi",
                    0.0,
                )
            )
            - rssi_center
        ) / rssi_range


        # -----------------------------------------------
        # Structural / configuration comparisons
        # -----------------------------------------------

        df.at[
            index,
            "ie_count_match",
        ] = int(
            row.get(
                "ie_count"
            )
            == profile.get(
                "ie_count"
            )
        )

        df.at[
            index,
            "rate_count_match",
        ] = int(
            row.get(
                "rate_count"
            )
            == profile.get(
                "rate_count"
            )
        )

        df.at[
            index,
            "security_match",
        ] = int(
            row.get(
                "security"
            )
            == profile.get(
                "security"
            )
        )

        df.at[
            index,
            "channel_match",
        ] = int(
            row.get(
                "channel"
            )
            == profile.get(
                "channel"
            )
        )


    print(
        "[✓] Profile-relative features engineered"
    )

    return df


# =======================================================
# PER-BSSID MODELS
# =======================================================

def train_per_bssid_models(
    df,
    profiles,
):
    """
    Train one Isolation Forest for each sufficiently
    observed profiled BSSID.

    A per-BSSID model learns the normal feature
    distribution for one AP rather than forcing all
    APs into a single behavioral baseline.

    Returns
    -------
    tuple
        models, scalers, feature_names
    """

    print(
        "\n[*] Training per-BSSID "
        "Isolation Forest models..."
    )

    per_bssid_models = {}
    per_bssid_scalers = {}


    candidate_features = [
        "clock_skew",
        "rssi",
        "seq_jump",
        "inter_beacon_ms",
    ]


    available_features = [
        feature
        for feature
        in candidate_features
        if feature in df.columns
    ]


    if not available_features:

        raise ValueError(
            "No per-BSSID training features "
            "were found in the dataset."
        )


    for bssid, profile in profiles.items():

        bssid_data = df[
            df["bssid"] == bssid
        ]


        if len(bssid_data) < 20:

            print(
                "  [skip] "
                f"{profile.get('ssid', bssid)}: "
                "fewer than 20 observations"
            )

            continue


        X = (
            bssid_data[
                available_features
            ]
            .replace(
                [np.inf, -np.inf],
                np.nan,
            )
            .dropna()
            .values
        )


        if len(X) < 10:

            print(
                "  [skip] "
                f"{profile.get('ssid', bssid)}: "
                "fewer than 10 valid feature rows"
            )

            continue


        scaler = StandardScaler()

        X_scaled = scaler.fit_transform(
            X
        )


        model = IsolationForest(
            contamination=CONTAMINATION,
            n_estimators=100,
            random_state=config.RANDOM_STATE,
        )

        model.fit(
            X_scaled
        )


        per_bssid_models[
            bssid
        ] = model

        per_bssid_scalers[
            bssid
        ] = scaler


        ssid = profile.get(
            "ssid",
            "<Unknown>",
        )


        print(
            f"  [✓] {ssid[:25]:25} "
            f"| {len(X):5d} observations"
        )


    print(
        f"[✓] Trained "
        f"{len(per_bssid_models)} "
        "per-BSSID models"
    )


    return (
        per_bssid_models,
        per_bssid_scalers,
        available_features,
    )


# =======================================================
# GLOBAL EXPERIMENTAL MODEL
# =======================================================

def train_global_model(
    df,
):
    """
    Train an experimental global Isolation Forest.

    The global model uses both raw observations and
    profile-relative features across all available APs.

    The live detector currently emphasizes per-BSSID
    models and rule / fingerprint evidence. This global
    model is retained as a secondary experimental layer.

    Returns
    -------
    tuple
        model, scaler, feature_names
    """

    print(
        "\n[*] Training experimental "
        "global Isolation Forest..."
    )


    candidate_features = [
        "rssi",
        "channel",
        "seq_jump",
        "seq_anomaly_score",
        "clock_skew",
        "beacon_interval",
        "ie_count",
        "capabilities",
        "security_encoded",
        "rate_count",
        "clock_skew_deviation",
        "rssi_deviation",
        "ie_count_match",
        "rate_count_match",
        "security_match",
        "channel_match",
    ]


    available_features = [
        feature
        for feature
        in candidate_features
        if feature in df.columns
    ]


    if not available_features:

        raise ValueError(
            "No global-model features "
            "were found in the dataset."
        )


    clean_features = (
        df[
            available_features
        ]
        .replace(
            [np.inf, -np.inf],
            np.nan,
        )
        .fillna(0)
    )


    X = clean_features.values


    scaler = StandardScaler()

    X_scaled = scaler.fit_transform(
        X
    )


    model = IsolationForest(
        contamination=CONTAMINATION,
        n_estimators=200,
        random_state=config.RANDOM_STATE,
    )


    model.fit(
        X_scaled
    )


    scores = model.decision_function(
        X_scaled
    )


    print(
        f"  [✓] Global model trained on "
        f"{len(X):,} observations"
    )

    print(
        "  [✓] Training decision-score range: "
        f"{scores.min():.4f} to "
        f"{scores.max():.4f}"
    )

    print(
        f"  [✓] Features used: "
        f"{len(available_features)}"
    )


    return (
        model,
        scaler,
        available_features,
    )


# =======================================================
# MODEL SERIALIZATION
# =======================================================

def save_all_models(
    per_bssid_models,
    per_bssid_scalers,
    bssid_features,
    global_model,
    global_scaler,
    global_features,
):
    """
    Save trained anomaly models and metadata.
    """

    os.makedirs(
        config.MODELS_DIR,
        exist_ok=True,
    )


    per_bssid_path = os.path.join(
        config.MODELS_DIR,
        "per_bssid_models.pkl",
    )


    joblib.dump(
        {
            "models":
                per_bssid_models,

            "scalers":
                per_bssid_scalers,

            "features":
                bssid_features,

            "model_type":
                "IsolationForest",

            "contamination":
                CONTAMINATION,
        },
        per_bssid_path,
    )


    global_path = os.path.join(
        config.MODELS_DIR,
        "global_model.pkl",
    )


    joblib.dump(
        {
            "model":
                global_model,

            "scaler":
                global_scaler,

            "features":
                global_features,

            "model_type":
                "IsolationForest",

            "contamination":
                CONTAMINATION,

            "status":
                "experimental_secondary_model",
        },
        global_path,
    )


    print(
        "\n[✓] Per-BSSID model bundle: "
        f"{per_bssid_path}"
    )

    print(
        "[✓] Global model bundle    : "
        f"{global_path}"
    )


# =======================================================
# MAIN
# =======================================================

def main():
    """
    Build all behavioral anomaly models.
    """

    print(
        "\n"
        + "=" * 68
    )

    print(
        "  BEHAVIORAL ANOMALY MODEL BUILDER"
    )

    print(
        "=" * 68
    )

    print(
        "  Model type : Isolation Forest"
    )

    print(
        "  Training   : Legitimate baseline observations"
    )

    print(
        "  Strategy   : Per-BSSID + experimental global model"
    )

    print(
        "=" * 68
    )


    try:

        # Step 1
        df = load_and_prepare_data()


        # Step 2
        profiles = load_profiles()


        # Step 3
        df = engineer_features(
            df,
            profiles,
        )


        # Step 4
        (
            per_bssid_models,
            per_bssid_scalers,
            bssid_features,
        ) = train_per_bssid_models(
            df,
            profiles,
        )


        # Step 5
        (
            global_model,
            global_scaler,
            global_features,
        ) = train_global_model(
            df
        )


        # Step 6
        save_all_models(
            per_bssid_models,
            per_bssid_scalers,
            bssid_features,
            global_model,
            global_scaler,
            global_features,
        )


    except Exception as error:

        print(
            "\n[ERROR] Model build failed:"
        )

        print(
            f"        {error}"
        )

        sys.exit(
            1
        )


    print(
        "\n"
        + "=" * 68
    )

    print(
        "  MODEL BUILD COMPLETE"
    )

    print(
        "=" * 68
    )

    print(
        f"  Per-BSSID models : "
        f"{len(per_bssid_models)}"
    )

    print(
        "  Global models    : 1 experimental model"
    )

    print(
        "  Per-BSSID features:"
    )

    for feature in bssid_features:

        print(
            f"    - {feature}"
        )


    print(
        "  Global features  : "
        f"{len(global_features)}"
    )


    print(
        "\n  Detection support provided by these models:"
    )

    print(
        "  • Per-AP behavioral anomaly scoring"
    )

    print(
        "  • Timing and sequence-pattern deviation analysis"
    )

    print(
        "  • RSSI deviation as contextual evidence"
    )

    print(
        "  • Profile-relative structural deviations"
    )


    print(
        "\n  Important:"
    )

    print(
        "  These models identify statistical anomalies."
    )

    print(
        "  They do not independently confirm an Evil Twin."
    )

    print(
        "=" * 68
    )

    print(
        "\nNext step:"
    )

    print(
        "Run main.py and select the live detector."
    )


if __name__ == "__main__":
    main()

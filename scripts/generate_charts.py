#!/usr/bin/env python3
"""
=======================================================
 scripts/generate_charts.py
=======================================================

Generate presentation and research visualizations for the
Hybrid Wireless Intrusion Detection System.

Charts currently illustrate:

1. Clock-skew distributions across observed APs
2. Beacon Information Element count baselines
3. Illustrative sequence-stream interference
4. Heuristic detection-layer contributions

IMPORTANT
---------
These charts are primarily presentation aids.

The sequence-stream chart is synthetic / illustrative and
is not a direct replay of captured attack traffic.

AP labels are anonymized by default so charts can be used
more safely in public presentations.

Detection-layer values are heuristic threat-score
contributions and are NOT calibrated probabilities.
=======================================================
"""

import json
import os
import sys

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns


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


# =======================================================
# OUTPUT CONFIGURATION
# =======================================================

OUT_DIR = os.path.join(
    config.PROJECT_ROOT,
    "visualizations",
)

os.makedirs(
    OUT_DIR,
    exist_ok=True,
)


# Keep real SSIDs out of presentation charts by default.
ANONYMIZE_AP_LABELS = True


sns.set_theme(
    style="whitegrid",
    palette="muted",
)

plt.rcParams.update(
    {
        "font.sans-serif":
            "DejaVu Sans",

        "font.size":
            11,
    }
)


# =======================================================
# LABEL ANONYMIZATION
# =======================================================

def build_ap_label_map(
    ssids,
):
    """
    Create deterministic presentation labels for APs.

    Example
    -------
    HomeNetwork -> LAB_AP_01

    This prevents real SSIDs from being embedded in
    screenshots or presentation charts by default.
    """

    unique_ssids = []

    for ssid in ssids:

        text = str(
            ssid
        )

        if text not in unique_ssids:

            unique_ssids.append(
                text
            )


    return {
        ssid:
            f"LAB_AP_{index:02d}"
        for index, ssid
        in enumerate(
            unique_ssids,
            start=1,
        )
    }


def display_label(
    ssid,
    label_map,
):
    """
    Return either the anonymized label or original SSID.
    """

    if ANONYMIZE_AP_LABELS:

        return label_map.get(
            str(ssid),
            "LAB_AP_UNKNOWN",
        )

    return str(
        ssid
    )


# =======================================================
# 1. CLOCK-SKEW DISTRIBUTION
# =======================================================

def plot_clock_skew(
    df,
):
    """
    Plot observed clock-skew distributions for several APs.

    Clock-skew measurements are behavioral timing
    characteristics and can also be influenced by capture
    conditions such as virtualization, USB scheduling,
    packet loss, and channel hopping.
    """

    required_columns = {
        "ssid",
        "clock_skew",
    }


    if not required_columns.issubset(
        df.columns
    ):

        print(
            "[skip] Clock-skew chart: "
            "required columns missing"
        )

        return


    working = df.copy()


    working[
        "clock_skew"
    ] = pd.to_numeric(
        working[
            "clock_skew"
        ],
        errors="coerce",
    )


    working = working.dropna(
        subset=[
            "clock_skew",
            "ssid",
        ]
    )


    # Prefer observations whose timing measurement passed
    # the current validity filter when the column exists.
    if (
        "valid_skew"
        in working.columns
    ):

        valid_values = pd.to_numeric(
            working[
                "valid_skew"
            ],
            errors="coerce",
        ).fillna(0)


        valid_only = working[
            valid_values == 1
        ]


        if not valid_only.empty:

            working = valid_only


    # Exclude very large timing observations from this
    # presentation chart so the central distributions
    # remain readable.
    working = working[
        working[
            "clock_skew"
        ].abs() < 0.005
    ]


    if working.empty:

        print(
            "[skip] Clock-skew chart: "
            "no usable observations"
        )

        return


    top_aps = (
        working[
            "ssid"
        ]
        .value_counts()
        .head(5)
        .index
    )


    filtered = working[
        working[
            "ssid"
        ].isin(
            top_aps
        )
    ].copy()


    label_map = build_ap_label_map(
        filtered[
            "ssid"
        ]
    )


    filtered[
        "display_ap"
    ] = filtered[
        "ssid"
    ].map(
        lambda value:
            display_label(
                value,
                label_map,
            )
    )


    plt.figure(
        figsize=(
            10,
            5,
        )
    )


    sns.boxplot(
        data=filtered,
        x="display_ap",
        y="clock_skew",
    )


    plt.title(
        "Observed Clock-Skew Distributions Across Access Points",
        fontsize=14,
        fontweight="bold",
    )


    plt.xlabel(
        "Access Point",
        fontweight="bold",
    )


    plt.ylabel(
        "Relative Clock-Skew Estimate",
        fontweight="bold",
    )


    plt.xticks(
        rotation=15
    )


    plt.figtext(
        0.5,
        0.01,
        (
            "Timing observations are behavioral evidence "
            "and may also reflect capture-system jitter."
        ),
        ha="center",
        fontsize=9,
    )


    plt.tight_layout(
        rect=[
            0,
            0.04,
            1,
            1,
        ]
    )


    path = os.path.join(
        OUT_DIR,
        "1_clock_skew_fingerprints.png",
    )


    plt.savefig(
        path,
        dpi=300,
        bbox_inches="tight",
    )


    plt.close()


    print(
        f"[✓] Generated: {path}"
    )


# =======================================================
# 2. INFORMATION ELEMENT BASELINES
# =======================================================

def plot_ie_fingerprints(
    profiles,
):
    """
    Plot typical Information Element counts from AP
    behavioral profiles.

    IE count is treated as a structural baseline rather
    than an immutable hardware identifier.
    """

    if not profiles:

        print(
            "[skip] IE chart: "
            "no profiles available"
        )

        return


    profile_items = list(
        profiles.values()
    )[:8]


    ssids = [
        str(
            profile.get(
                "ssid",
                "<Unknown>",
            )
        )
        for profile
        in profile_items
    ]


    ie_counts = [
        int(
            profile.get(
                "ie_count",
                0,
            )
        )
        for profile
        in profile_items
    ]


    label_map = build_ap_label_map(
        ssids
    )


    labels = [
        display_label(
            ssid,
            label_map,
        )
        for ssid
        in ssids
    ]


    plt.figure(
        figsize=(
            10,
            5,
        )
    )


    bars = plt.barh(
        labels,
        ie_counts,
    )


    for bar, value in zip(
        bars,
        ie_counts,
    ):

        plt.text(
            value + 0.2,
            bar.get_y()
            + bar.get_height() / 2,
            str(
                value
            ),
            va="center",
        )


    plt.title(
        "Beacon Information Element Count Baselines",
        fontsize=14,
        fontweight="bold",
    )


    plt.xlabel(
        "Typical Number of Information Elements",
        fontweight="bold",
    )


    plt.ylabel(
        "Profiled Access Point",
        fontweight="bold",
    )


    plt.figtext(
        0.5,
        0.01,
        (
            "IE counts are structural baseline features "
            "and may change with firmware or configuration."
        ),
        ha="center",
        fontsize=9,
    )


    plt.tight_layout(
        rect=[
            0,
            0.04,
            1,
            1,
        ]
    )


    path = os.path.join(
        OUT_DIR,
        "2_ie_hardware_fingerprints.png",
    )


    plt.savefig(
        path,
        dpi=300,
        bbox_inches="tight",
    )


    plt.close()


    print(
        f"[✓] Generated: {path}"
    )


# =======================================================
# 3. ILLUSTRATIVE SEQUENCE-STREAM BEHAVIOR
# =======================================================

def plot_sequence_behavior():
    """
    Generate a synthetic illustration of sequence-stream
    interference during a BSSID-spoofing scenario.

    This chart is intentionally illustrative and is NOT
    derived from a live PCAP replay.
    """

    rng = np.random.default_rng(
        seed=42
    )


    time_points = np.linspace(
        0,
        10,
        100,
    )


    legitimate_sequence = (
        100
        + time_points * 10
    ) % 4096


    # Synthetic BSSID-spoofing interval.
    injected_time = np.linspace(
        5,
        8,
        30,
    )


    injected_sequence = (
        100
        + injected_time * 10
        + rng.integers(
            -15,
            15,
            len(
                injected_time
            ),
        )
    ) % 4096


    plt.figure(
        figsize=(
            11,
            5,
        )
    )


    plt.plot(
        time_points,
        legitimate_sequence,
        "o-",
        label=(
            "Illustrative Legitimate "
            "Sequence Stream"
        ),
        alpha=0.7,
    )


    plt.scatter(
        injected_time,
        injected_sequence,
        s=80,
        marker="x",
        label=(
            "Illustrative Competing "
            "Sequence Observations"
        ),
        zorder=5,
    )


    plt.title(
        "Illustrative Sequence Behavior During BSSID Spoofing",
        fontsize=14,
        fontweight="bold",
    )


    plt.xlabel(
        "Time Elapsed (seconds)",
        fontweight="bold",
    )


    plt.ylabel(
        "802.11 Sequence Number",
        fontweight="bold",
    )


    plt.legend(
        loc="upper left"
    )


    plt.figtext(
        0.5,
        0.01,
        (
            "Synthetic illustration only — "
            "not a direct capture replay."
        ),
        ha="center",
        fontsize=9,
    )


    plt.tight_layout(
        rect=[
            0,
            0.04,
            1,
            1,
        ]
    )


    path = os.path.join(
        OUT_DIR,
        "3_sequence_collision_proof.png",
    )


    plt.savefig(
        path,
        dpi=300,
        bbox_inches="tight",
    )


    plt.close()


    print(
        f"[✓] Generated: {path}"
    )


# =======================================================
# 4. DETECTION-LAYER THREAT-SCORE CONTRIBUTIONS
# =======================================================

def plot_layer_weights():
    """
    Visualize selected heuristic threat-score
    contributions used by the current prototype.

    These values are NOT probabilities or model feature
    importances.
    """

    layers = [
        "Duplicate Sequence\nActivity",
        "Unexpected BSSID\nfor Known SSID",
        "Beacon IE Count\nDeviation",
        "Security\nChange",
        "Clock-Skew\nDeviation",
        "Supported-Rate\nDeviation",
        "Per-BSSID\nIsolation Forest",
    ]


    weights = [
        90,
        85,
        70,
        60,
        35,
        30,
        25,
    ]


    plt.figure(
        figsize=(
            11,
            6,
        )
    )


    bars = plt.bar(
        layers,
        weights,
    )


    for bar, value in zip(
        bars,
        weights,
    ):

        plt.text(
            bar.get_x()
            + bar.get_width() / 2,
            value + 1,
            str(
                value
            ),
            ha="center",
            va="bottom",
        )


    plt.ylabel(
        "Heuristic Threat-Score Contribution",
        fontweight="bold",
    )


    plt.title(
        "Current Hybrid WIDS Evidence Weights",
        fontsize=14,
        fontweight="bold",
    )


    plt.ylim(
        0,
        100,
    )


    plt.xticks(
        rotation=20,
        ha="right",
    )


    plt.figtext(
        0.5,
        0.01,
        (
            "Prototype heuristic weights — "
            "not calibrated attack probabilities."
        ),
        ha="center",
        fontsize=9,
    )


    plt.tight_layout(
        rect=[
            0,
            0.05,
            1,
            1,
        ]
    )


    path = os.path.join(
        OUT_DIR,
        "4_detection_layer_weights.png",
    )


    plt.savefig(
        path,
        dpi=300,
        bbox_inches="tight",
    )


    plt.close()


    print(
        f"[✓] Generated: {path}"
    )


# =======================================================
# MAIN
# =======================================================

def main():

    print(
        "\n"
        + "=" * 68
    )

    print(
        "  GENERATING WIDS RESEARCH VISUALIZATIONS"
    )

    print(
        "=" * 68
    )

    print(
        f"  Output directory : {OUT_DIR}"
    )

    print(
        "  AP labels        : "
        + (
            "Anonymized"
            if ANONYMIZE_AP_LABELS
            else "Original SSIDs"
        )
    )

    print(
        "=" * 68
    )


    generated_count = 0


    # ---------------------------------------------------
    # Dataset-dependent clock-skew visualization
    # ---------------------------------------------------

    if os.path.exists(
        config.ALL_APS_DATA_FILE
    ):

        try:

            df = pd.read_csv(
                config.ALL_APS_DATA_FILE
            )


            if "ssid" in df.columns:

                df = df[
                    df[
                        "ssid"
                    ].astype(str)
                    != "ssid"
                ].copy()


            plot_clock_skew(
                df
            )

            generated_count += 1


        except Exception as error:

            print(
                "[!] Could not generate "
                "clock-skew chart:"
            )

            print(
                f"    {error}"
            )


    else:

        print(
            "[skip] Baseline dataset not found; "
            "clock-skew chart not generated."
        )


    # ---------------------------------------------------
    # Profile-dependent IE visualization
    # ---------------------------------------------------

    if os.path.exists(
        config.BSSID_PROFILES_FILE
    ):

        try:

            with open(
                config.BSSID_PROFILES_FILE,
                "r",
                encoding="utf-8",
            ) as file:

                profiles = json.load(
                    file
                )


            plot_ie_fingerprints(
                profiles
            )

            generated_count += 1


        except Exception as error:

            print(
                "[!] Could not generate "
                "IE baseline chart:"
            )

            print(
                f"    {error}"
            )


    else:

        print(
            "[skip] BSSID profiles not found; "
            "IE baseline chart not generated."
        )


    # ---------------------------------------------------
    # Dataset-independent presentation figures
    # ---------------------------------------------------

    try:

        plot_sequence_behavior()

        generated_count += 1

    except Exception as error:

        print(
            "[!] Could not generate "
            "sequence illustration:"
        )

        print(
            f"    {error}"
        )


    try:

        plot_layer_weights()

        generated_count += 1

    except Exception as error:

        print(
            "[!] Could not generate "
            "layer-weight chart:"
        )

        print(
            f"    {error}"
        )


    print(
        "\n"
        + "=" * 68
    )

    print(
        "  VISUALIZATION GENERATION COMPLETE"
    )

    print(
        "=" * 68
    )

    print(
        f"  Charts generated: "
        f"{generated_count}"
    )

    print(
        f"  Output directory: "
        f"{OUT_DIR}"
    )

    print(
        "=" * 68
        + "\n"
    )


if __name__ == "__main__":

    main()

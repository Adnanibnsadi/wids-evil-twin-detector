#!/usr/bin/env python3
"""
=======================================================
 scripts/build_profiles.py
=======================================================

Build per-BSSID behavioral profiles from collected
legitimate 802.11 beacon observations.

Profiles summarize:

- Information Element count
- Supported-rate count
- Advertised security
- Channel
- Beacon interval
- Capability flags
- Clock-skew statistics
- RSSI statistics
- Sequence-jump statistics

These values are treated as behavioral and structural
baseline characteristics.

They are not immutable hardware identifiers and should
not independently be interpreted as proof of a rogue or
Evil Twin access point.
=======================================================
"""

import json
import os
import sys

import pandas as pd


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
# HELPERS
# =======================================================

def safe_mode(series, default=None):
    """
    Return the most common non-null value in a Series.

    Parameters
    ----------
    series : pandas.Series
        Input values.

    default : any
        Value returned when no usable mode exists.
    """

    cleaned = series.dropna()

    if cleaned.empty:
        return default

    modes = cleaned.mode()

    if modes.empty:
        return cleaned.iloc[0]

    return modes.iloc[0]


# =======================================================
# PROFILE BUILDER
# =======================================================

def build_bssid_profiles(df):
    """
    Build a behavioral profile for each sufficiently
    observed BSSID.

    Structural / configuration characteristics:
    - IE count
    - supported-rate count
    - security
    - capability flags
    - channel
    - beacon interval
    - supported rates

    Statistical characteristics:
    - clock-skew distribution
    - RSSI distribution
    - sequence-jump distribution

    These characteristics may help distinguish unusual
    beacon behavior, but legitimate firmware,
    configuration, channel, or environmental changes can
    also alter them.
    """

    profiles = {}

    print(
        "\n"
        + "=" * 68
    )

    print(
        "  BUILDING BSSID BEHAVIORAL PROFILES"
    )

    print(
        "=" * 68
    )


    grouped = df.groupby(
        "bssid"
    )


    for bssid, group in grouped:

        ssid = str(
            safe_mode(
                group["ssid"],
                "<Unknown>",
            )
        )

        beacon_count = len(
            group
        )


        # Avoid creating profiles from extremely small
        # observation sets.
        if beacon_count < 10:

            print(
                f"  [skip] {ssid} ({bssid}) - "
                f"only {beacon_count} beacons"
            )

            continue


        # ------------------------------------------------
        # STRUCTURAL / CONFIGURATION BASELINE
        # ------------------------------------------------

        ie_count = int(
            safe_mode(
                group["ie_count"],
                0,
            )
        )

        rate_count = int(
            safe_mode(
                group["rate_count"],
                0,
            )
        )

        security = str(
            safe_mode(
                group["security"],
                "Unknown",
            )
        )

        capabilities = int(
            safe_mode(
                group["capabilities"],
                0,
            )
        )

        channel = int(
            safe_mode(
                group["channel"],
                0,
            )
        )

        beacon_interval = int(
            safe_mode(
                group["beacon_interval"],
                0,
            )
        )

        supported_rates = str(
            safe_mode(
                group["supported_rates"],
                "",
            )
        )


        # ------------------------------------------------
        # CLOCK-SKEW STATISTICS
        # ------------------------------------------------

        skew_data = (
            group["clock_skew"]
            .dropna()
        )


        # Remove extreme observations using the IQR
        # method before calculating the baseline.
        if len(skew_data) > 10:

            q1 = skew_data.quantile(
                0.25
            )

            q3 = skew_data.quantile(
                0.75
            )

            iqr = q3 - q1


            skew_clean = skew_data[
                (
                    skew_data
                    >= q1 - 1.5 * iqr
                )
                &
                (
                    skew_data
                    <= q3 + 1.5 * iqr
                )
            ]

        else:

            skew_clean = skew_data


        if len(skew_clean) > 0:

            clock_skew_mean = float(
                skew_clean.mean()
            )

            clock_skew_min = float(
                skew_clean.min()
            )

            clock_skew_max = float(
                skew_clean.max()
            )

        else:

            clock_skew_mean = 0.0
            clock_skew_min = 0.0
            clock_skew_max = 0.0


        if len(skew_clean) > 1:

            clock_skew_std = float(
                skew_clean.std()
            )

        else:

            clock_skew_std = 0.0


        # ------------------------------------------------
        # RSSI STATISTICS
        # ------------------------------------------------

        rssi_data = (
            group["rssi"]
            .dropna()
        )


        if len(rssi_data) > 0:

            rssi_mean = float(
                rssi_data.mean()
            )

            rssi_min = float(
                rssi_data.min()
            )

            rssi_max = float(
                rssi_data.max()
            )

        else:

            rssi_mean = 0.0
            rssi_min = 0.0
            rssi_max = 0.0


        if len(rssi_data) > 1:

            rssi_std = float(
                rssi_data.std()
            )

        else:

            rssi_std = 0.0


        # ------------------------------------------------
        # SEQUENCE-JUMP STATISTICS
        # ------------------------------------------------

        seq_jumps = (
            group["seq_jump"]
            .dropna()
        )


        # Large jumps can occur when frames are missed
        # during channel hopping, so the current prototype
        # excludes jumps >= 100 from the baseline summary.
        normal_jumps = seq_jumps[
            seq_jumps < 100
        ]


        if len(normal_jumps) > 0:

            seq_jump_mean = float(
                normal_jumps.mean()
            )

        else:

            seq_jump_mean = 0.0


        if len(normal_jumps) > 1:

            seq_jump_std = float(
                normal_jumps.std()
            )

        else:

            seq_jump_std = 0.0


        # ------------------------------------------------
        # BUILD PROFILE
        # ------------------------------------------------

        profile = {

            # Identity
            "ssid":
                ssid,

            "bssid":
                str(
                    bssid
                ).lower(),


            # Structural / configuration baseline
            "ie_count":
                ie_count,

            "rate_count":
                rate_count,

            "security":
                security,

            "capabilities":
                capabilities,

            "channel":
                channel,

            "beacon_interval":
                beacon_interval,

            "supported_rates":
                supported_rates,


            # Timing baseline
            "clock_skew_mean":
                clock_skew_mean,

            "clock_skew_std":
                clock_skew_std,

            "clock_skew_min":
                clock_skew_min,

            "clock_skew_max":
                clock_skew_max,


            # Signal baseline
            "rssi_mean":
                rssi_mean,

            "rssi_std":
                rssi_std,

            "rssi_min":
                rssi_min,

            "rssi_max":
                rssi_max,


            # Sequence behavior
            "seq_jump_mean":
                seq_jump_mean,

            "seq_jump_std":
                seq_jump_std,


            # Metadata
            "total_beacons":
                beacon_count,

            "profile_built":
                pd.Timestamp.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
        }


        profiles[
            str(bssid).lower()
        ] = profile


        # ------------------------------------------------
        # DISPLAY SUMMARY
        # ------------------------------------------------

        print(
            f"\n  [✓] {ssid} ({bssid})"
        )

        print(
            f"      Beacons      : "
            f"{beacon_count}"
        )

        print(
            f"      IE Count     : "
            f"{ie_count}"
        )

        print(
            f"      Rate Count   : "
            f"{rate_count}"
        )

        print(
            f"      Clock Skew   : "
            f"{clock_skew_mean:.8f} "
            f"± {clock_skew_std:.8f}"
        )

        print(
            f"      RSSI Range   : "
            f"{rssi_min:.1f} to "
            f"{rssi_max:.1f} dBm"
        )

        print(
            f"      Channel      : "
            f"{channel}"
        )

        print(
            f"      Security     : "
            f"{security}"
        )


    return profiles


# =======================================================
# MAIN
# =======================================================

def main():

    print(
        "\n"
        + "=" * 68
    )

    print(
        "  BSSID BEHAVIORAL PROFILE BUILDER"
    )

    print(
        "=" * 68
    )


    if not os.path.exists(
        config.ALL_APS_DATA_FILE
    ):

        print(
            "[ERROR] Baseline dataset not found:"
        )

        print(
            f"        {config.ALL_APS_DATA_FILE}"
        )

        print(
            "\nRun scripts/collect_all_aps.py first."
        )

        sys.exit(
            1
        )


    print(
        "[*] Loading baseline data from:"
    )

    print(
        f"    {config.ALL_APS_DATA_FILE}"
    )


    df = pd.read_csv(
        config.ALL_APS_DATA_FILE
    )


    required_columns = [
        "ssid",
        "bssid",
        "rssi",
        "channel",
        "seq_jump",
        "clock_skew",
        "ie_count",
        "rate_count",
        "capabilities",
        "beacon_interval",
        "security",
        "supported_rates",
    ]


    missing_columns = [
        column
        for column in required_columns
        if column not in df.columns
    ]


    if missing_columns:

        print(
            "\n[ERROR] Dataset is missing required columns:"
        )

        for column in missing_columns:

            print(
                f"  - {column}"
            )

        sys.exit(
            1
        )


    # Remove accidentally repeated CSV headers.
    df = df[
        df["ssid"].astype(str) != "ssid"
    ].copy()


    df["bssid"] = (
        df["bssid"]
        .astype(str)
        .str.lower()
    )


    numeric_columns = [
        "rssi",
        "channel",
        "seq_jump",
        "clock_skew",
        "inter_beacon_ms",
        "timing_variance",
        "ie_count",
        "rate_count",
        "capabilities",
        "beacon_interval",
    ]


    for column in numeric_columns:

        if column in df.columns:

            df[column] = pd.to_numeric(
                df[column],
                errors="coerce",
            )


    print(
        f"[✓] Loaded {len(df):,} beacon observations"
    )

    print(
        f"[✓] Unique BSSIDs: "
        f"{df['bssid'].nunique()}"
    )


    profiles = build_bssid_profiles(
        df
    )


    os.makedirs(
        config.DATA_DIR,
        exist_ok=True,
    )


    with open(
        config.BSSID_PROFILES_FILE,
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            profiles,
            file,
            indent=2,
        )


    print(
        "\n"
        + "=" * 68
    )

    print(
        "  PROFILE BUILDING COMPLETE"
    )

    print(
        "=" * 68
    )

    print(
        f"  Profiles built : "
        f"{len(profiles)}"
    )

    print(
        f"  Saved to       : "
        f"{config.BSSID_PROFILES_FILE}"
    )

    print()


    if profiles:

        print(
            f"  {'SSID':<25} "
            f"{'IE':>4} "
            f"{'Rates':>6} "
            f"{'Clock Skew Mean':>18} "
            f"{'Beacons':>8}"
        )

        print(
            "-" * 68
        )


        for _, profile in sorted(
            profiles.items(),
            key=lambda item:
                item[1][
                    "total_beacons"
                ],
            reverse=True,
        ):

            print(
                f"  "
                f"{profile['ssid'][:24]:<25} "
                f"{profile['ie_count']:>4} "
                f"{profile['rate_count']:>6} "
                f"{profile['clock_skew_mean']:>18.8f} "
                f"{profile['total_beacons']:>8}"
            )


    print(
        "=" * 68
    )

    print(
        "\n[✓] Behavioral profiles are ready."
    )

    print(
        "[*] Next step:"
    )

    print(
        "    python3 scripts/build_advanced_model.py"
    )


if __name__ == "__main__":
    main()

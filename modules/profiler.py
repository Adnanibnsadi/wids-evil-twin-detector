#!/usr/bin/env python3
"""
=======================================================
 modules/profiler.py
=======================================================

Legacy / experimental single-AP behavioral profiler.

This module belongs to an earlier generation of the
project in which one selected access point was observed
for a short period and stored in ap_profiles.json.

The current primary workflow uses:

    scripts/collect_all_aps.py
        ↓
    scripts/build_profiles.py
        ↓
    data/bssid_profiles.json
        ↓
    scripts/build_advanced_model.py

This file is retained for historical experimentation and
backward compatibility.

The profile values produced here are behavioral and
structural baselines. They are NOT immutable hardware
identifiers and should not independently be interpreted
as proof of an Evil Twin or rogue access point.
=======================================================
"""

import json
import os
import sys
import threading
import time

import pandas as pd
from scapy.all import sniff
from scapy.layers.dot11 import (
    Dot11,
    Dot11Beacon,
    Dot11Elt,
    RadioTap,
)


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
# GLOBAL STATE
# =======================================================

captured_beacons = []

hop_active = False

target_ssid = None
target_bssid = None
target_channel = None

seq_tracker = {}
ts_tracker = {}


# =======================================================
# FEATURE EXTRACTION
# =======================================================

def extract_features(
    packet,
    system_time,
):
    """
    Extract behavioral and structural characteristics
    from one 802.11 beacon frame.

    Returns
    -------
    dict or None
        Extracted beacon features.
    """

    try:

        bssid = packet[
            Dot11
        ].addr2


        if not bssid:

            return None


        bssid = bssid.lower()


        # ------------------------------------------------
        # SSID
        # ------------------------------------------------

        try:

            ssid = (
                packet[
                    Dot11Elt
                ]
                .info
                .decode(
                    "utf-8",
                    errors="replace",
                )
            )

        except Exception:

            ssid = "<Unknown>"


        if not ssid.strip():

            ssid = "<Hidden>"


        # ------------------------------------------------
        # RSSI
        # ------------------------------------------------

        rssi = 0


        if packet.haslayer(
            RadioTap
        ):

            try:

                signal = packet[
                    RadioTap
                ].dBm_AntSignal


                if signal is not None:

                    rssi = signal

            except Exception:

                pass


        # ------------------------------------------------
        # CHANNEL
        # ------------------------------------------------

        channel = 0


        element = packet[
            Dot11Elt
        ]


        while isinstance(
            element,
            Dot11Elt,
        ):

            if (
                element.ID == 3
                and element.info
            ):

                channel = element.info[0]
                break


            element = element.payload


        # ------------------------------------------------
        # SUPPORTED RATES
        # ------------------------------------------------

        rates = []


        element = packet[
            Dot11Elt
        ]


        while isinstance(
            element,
            Dot11Elt,
        ):

            if element.ID in (
                1,
                50,
            ):

                for rate in element.info:

                    rates.append(
                        (
                            rate & 0x7F
                        )
                        * 0.5
                    )


            element = element.payload


        unique_rates = sorted(
            set(
                rates
            )
        )


        supported_rates = (
            ",".join(
                map(
                    str,
                    unique_rates,
                )
            )
            if unique_rates
            else "unknown"
        )


        rate_count = len(
            unique_rates
        )


        # ------------------------------------------------
        # SECURITY CHARACTERISTICS
        # ------------------------------------------------

        security = "Open"

        has_rsn = False
        has_wpa = False


        element = packet[
            Dot11Elt
        ]


        while isinstance(
            element,
            Dot11Elt,
        ):

            if element.ID == 48:

                has_rsn = True


            if (
                element.ID == 221
                and element.info[:4]
                == b"\x00\x50\xf2\x01"
            ):

                has_wpa = True


            element = element.payload


        capabilities = int(
            packet[
                Dot11Beacon
            ].cap
        )


        if has_rsn:

            security = "WPA2/WPA3"

        elif has_wpa:

            security = "WPA"

        elif capabilities & 0x0010:

            security = "WEP"


        # ------------------------------------------------
        # BASIC BEACON VALUES
        # ------------------------------------------------

        seq_num = (
            packet[
                Dot11
            ].SC >> 4
        )


        beacon_timestamp = (
            packet[
                Dot11Beacon
            ].timestamp
        )


        beacon_interval = (
            packet[
                Dot11Beacon
            ].beacon_interval
        )


        # ------------------------------------------------
        # SEQUENCE BEHAVIOR
        # ------------------------------------------------

        seq_jump = 0

        seq_anomaly_score = 0.0


        if (
            bssid in seq_tracker
            and seq_tracker[bssid]
        ):

            previous_seq = (
                seq_tracker[
                    bssid
                ][-1]
            )


            if seq_num >= previous_seq:

                seq_jump = (
                    seq_num
                    - previous_seq
                )

            else:

                # 12-bit sequence field:
                # 0 through 4095.
                seq_jump = (
                    4096
                    - previous_seq
                    + seq_num
                )


            if seq_jump > 100:

                seq_anomaly_score = min(
                    1.0,
                    seq_jump / 1000,
                )

            elif seq_jump > 10:

                seq_anomaly_score = 0.3


        if bssid not in seq_tracker:

            seq_tracker[
                bssid
            ] = []


        seq_tracker[
            bssid
        ].append(
            seq_num
        )


        if len(
            seq_tracker[bssid]
        ) > 20:

            seq_tracker[
                bssid
            ].pop(0)


        # ------------------------------------------------
        # TIMING / CLOCK-SKEW ESTIMATE
        # ------------------------------------------------

        clock_skew = 0.0
        valid_skew = False


        if bssid not in ts_tracker:

            ts_tracker[
                bssid
            ] = []


        ts_tracker[
            bssid
        ].append(
            {
                "beacon_ts":
                    beacon_timestamp,

                "system_ts":
                    system_time,
            }
        )


        if len(
            ts_tracker[bssid]
        ) > 20:

            ts_tracker[
                bssid
            ].pop(0)


        if len(
            ts_tracker[bssid]
        ) >= 2:

            previous = (
                ts_tracker[
                    bssid
                ][-2]
            )

            current = (
                ts_tracker[
                    bssid
                ][-1]
            )


            system_gap = (
                current["system_ts"]
                - previous["system_ts"]
            )


            # The profiler normally locks to one channel,
            # but receiver-side timing noise can still
            # occur. Retain the same validity window used
            # elsewhere in the current prototype.
            if (
                0.05
                <= system_gap
                <= 0.25
            ):

                ap_difference = (
                    current["beacon_ts"]
                    - previous["beacon_ts"]
                )


                system_difference = (
                    system_gap
                    * 1_000_000
                )


                if system_difference > 0:

                    clock_skew = (
                        ap_difference
                        - system_difference
                    ) / system_difference

                    valid_skew = True


        # ------------------------------------------------
        # INFORMATION ELEMENT COUNT
        # ------------------------------------------------

        ie_count = 0


        element = packet[
            Dot11Elt
        ]


        while isinstance(
            element,
            Dot11Elt,
        ):

            ie_count += 1

            element = element.payload


        return {

            "timestamp":
                time.strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),

            "ssid":
                ssid,

            "bssid":
                bssid,

            "rssi":
                rssi,

            "channel":
                channel,

            "seq_num":
                seq_num,

            "seq_jump":
                seq_jump,

            "seq_anomaly_score":
                round(
                    seq_anomaly_score,
                    4,
                ),

            "beacon_timestamp":
                beacon_timestamp,

            "clock_skew":
                round(
                    clock_skew,
                    8,
                ),

            "valid_skew":
                int(
                    valid_skew
                ),

            "beacon_interval":
                beacon_interval,

            "capabilities":
                capabilities,

            "supported_rates":
                supported_rates,

            "rate_count":
                rate_count,

            "security":
                security,

            "ie_count":
                ie_count,

            "label":
                0,
        }


    except Exception:

        return None


# =======================================================
# PACKET HANDLER
# =======================================================

def profile_handler(
    packet,
):
    """
    Capture beacon frames belonging to the selected AP.
    """

    if not packet.haslayer(
        Dot11Beacon
    ):

        return


    try:

        bssid = packet[
            Dot11
        ].addr2


        if not bssid:

            return


        bssid = bssid.lower()


        try:

            ssid = (
                packet[
                    Dot11Elt
                ]
                .info
                .decode(
                    "utf-8",
                    errors="replace",
                )
            )

        except Exception:

            ssid = "<Unknown>"


        if target_bssid:

            if (
                bssid
                != target_bssid.lower()
            ):

                return


        if (
            target_ssid
            and ssid
            != target_ssid
        ):

            return


        features = extract_features(
            packet,
            time.time(),
        )


        if not features:

            return


        captured_beacons.append(
            features
        )


        count = len(
            captured_beacons
        )


        bar_filled = int(
            (
                count
                / config.MIN_SAMPLES_NEEDED
            )
            * 20
        )


        bar_filled = min(
            bar_filled,
            20,
        )


        bar = (
            "█" * bar_filled
            + "░"
            * (
                20
                - bar_filled
            )
        )


        percent = min(
            int(
                (
                    count
                    / config.MIN_SAMPLES_NEEDED
                )
                * 100
            ),
            100,
        )


        print(
            f"\r  [{bar}] "
            f"{percent}%  "
            f"Beacons: {count}  "
            f"RSSI: {features['rssi']} dBm  "
            f"Skew: "
            f"{features['clock_skew']:.6f}    ",
            end="",
            flush=True,
        )


    except Exception:

        pass


# =======================================================
# CHANNEL LOCK
# =======================================================

def channel_locker(
    interface,
    channel,
):
    """
    Keep the monitor interface on the selected channel.
    """

    global hop_active


    while hop_active:

        os.system(
            f"iwconfig {interface} "
            f"channel {channel} "
            "2>/dev/null"
        )

        time.sleep(
            5
        )


# =======================================================
# PROFILE BUILDER
# =======================================================

def build_profile(
    network_info,
):
    """
    Build a statistical baseline for the selected AP.

    The resulting profile contains:

    - RSSI statistics
    - Sequence-jump statistics
    - Valid clock-skew statistics
    - Typical IE count
    - Typical supported rates
    - Typical beacon interval
    - Advertised security
    - Capability flags

    These characteristics are expected baselines, not
    immutable hardware fingerprints.
    """

    if len(
        captured_beacons
    ) < 10:

        print(
            "\n[ERROR] Not enough beacons captured: "
            f"{len(captured_beacons)}"
        )

        print(
            "[ERROR] Need at least 10 beacons "
            "to build a profile."
        )

        return None


    df = pd.DataFrame(
        captured_beacons
    )


    # Prefer only timing observations that passed the
    # validity filter.
    if (
        "valid_skew"
        in df.columns
    ):

        valid_skew_df = df[
            df[
                "valid_skew"
            ] == 1
        ]

    else:

        valid_skew_df = df


    if len(
        valid_skew_df
    ) > 0:

        skew_mean = float(
            valid_skew_df[
                "clock_skew"
            ].mean()
        )

        skew_std = float(
            valid_skew_df[
                "clock_skew"
            ].std()
        )

    else:

        skew_mean = 0.0
        skew_std = 0.0


    # pandas std() can produce NaN when only one value
    # exists.
    if pd.isna(
        skew_std
    ):

        skew_std = 0.0


    rssi_std = float(
        df[
            "rssi"
        ].std()
    )


    if pd.isna(
        rssi_std
    ):

        rssi_std = 0.0


    seq_jump_std = float(
        df[
            "seq_jump"
        ].std()
    )


    if pd.isna(
        seq_jump_std
    ):

        seq_jump_std = 0.0


    profile = {

        # Identity
        "ssid":
            network_info[
                "ssid"
            ],

        "bssid":
            network_info[
                "bssid"
            ].lower(),

        "channel":
            network_info[
                "channel"
            ],


        # RSSI baseline
        "rssi_mean":
            float(
                df[
                    "rssi"
                ].mean()
            ),

        "rssi_std":
            rssi_std,

        "rssi_min":
            float(
                df[
                    "rssi"
                ].min()
            ),

        "rssi_max":
            float(
                df[
                    "rssi"
                ].max()
            ),


        # Sequence behavior
        "seq_jump_mean":
            float(
                df[
                    "seq_jump"
                ].mean()
            ),

        "seq_jump_std":
            seq_jump_std,

        "seq_jump_max":
            float(
                df[
                    "seq_jump"
                ].max()
            ),


        # Timing behavior
        "clock_skew_mean":
            skew_mean,

        "clock_skew_std":
            skew_std,

        "valid_skew_samples":
            int(
                len(
                    valid_skew_df
                )
            ),


        # Structural / configuration baseline
        "ie_count":
            int(
                df[
                    "ie_count"
                ].mode().iloc[0]
            ),

        "supported_rates":
            str(
                df[
                    "supported_rates"
                ].mode().iloc[0]
            ),

        "rate_count":
            int(
                df[
                    "rate_count"
                ].mode().iloc[0]
            ),

        "beacon_interval":
            int(
                df[
                    "beacon_interval"
                ].mode().iloc[0]
            ),

        "security":
            str(
                df[
                    "security"
                ].mode().iloc[0]
            ),

        "capabilities":
            int(
                df[
                    "capabilities"
                ].mode().iloc[0]
            ),


        # Metadata
        "total_beacons":
            len(
                df
            ),

        "profile_time":
            time.strftime(
                "%Y-%m-%d %H:%M:%S"
            ),

        "profile_type":
            "legacy_single_ap",

        "raw_data_file":
            config.NORMAL_DATA_FILE,
    }


    return profile


# =======================================================
# SAVE PROFILE
# =======================================================

def save_profile(
    profile,
):
    """
    Save the legacy single-AP profile to JSON.
    """

    os.makedirs(
        config.DATA_DIR,
        exist_ok=True,
    )


    profiles = {}


    if os.path.exists(
        config.AP_PROFILES_FILE
    ):

        try:

            with open(
                config.AP_PROFILES_FILE,
                "r",
                encoding="utf-8",
            ) as file:

                profiles = json.load(
                    file
                )

        except Exception:

            profiles = {}


    profiles[
        profile[
            "bssid"
        ]
    ] = profile


    with open(
        config.AP_PROFILES_FILE,
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            profiles,
            file,
            indent=2,
        )


    print(
        "\n[✓] Legacy profile saved:"
    )

    print(
        f"    {config.AP_PROFILES_FILE}"
    )


# =======================================================
# SAVE SINGLE-AP DATA
# =======================================================

def save_normal_data():
    """
    Save observations from the legacy single-AP
    profiling workflow.

    This dataset is not the primary dataset used by the
    current multi-AP detector.
    """

    if not captured_beacons:

        return


    df = pd.DataFrame(
        captured_beacons
    )


    os.makedirs(
        config.DATA_DIR,
        exist_ok=True,
    )


    if os.path.exists(
        config.NORMAL_DATA_FILE
    ):

        df.to_csv(
            config.NORMAL_DATA_FILE,
            mode="a",
            header=False,
            index=False,
        )

    else:

        df.to_csv(
            config.NORMAL_DATA_FILE,
            index=False,
        )


    print(
        "[✓] Legacy single-AP observations saved:"
    )

    print(
        f"    {config.NORMAL_DATA_FILE}"
    )

    print(
        f"[✓] Rows saved: {len(df)}"
    )


# =======================================================
# MAIN PROFILING FUNCTION
# =======================================================

def profile_network(
    interface,
    network_info,
    duration=config.PROFILE_DURATION,
):
    """
    Run the legacy single-AP profiling workflow.

    This function:

    1. Locks the monitor interface to the selected channel.
    2. Captures beacon frames from the selected AP.
    3. Builds a statistical behavioral baseline.
    4. Saves the legacy profile and observations.

    For the current multi-AP research workflow, use:

        scripts/collect_all_aps.py
        scripts/build_profiles.py
        scripts/build_advanced_model.py
    """

    global target_ssid
    global target_bssid
    global target_channel
    global hop_active
    global captured_beacons


    captured_beacons = []

    seq_tracker.clear()
    ts_tracker.clear()


    target_ssid = (
        network_info[
            "ssid"
        ]
    )

    target_bssid = (
        network_info[
            "bssid"
        ]
    )

    target_channel = (
        network_info[
            "channel"
        ]
    )


    print(
        "\n"
        + "=" * 60
    )

    print(
        "  LEGACY SINGLE-AP BEHAVIORAL PROFILER"
    )

    print(
        "=" * 60
    )

    print(
        f"  Network : {target_ssid}"
    )

    print(
        f"  BSSID   : {target_bssid}"
    )

    print(
        f"  Channel : {target_channel}"
    )

    print(
        f"  Duration: {duration} seconds"
    )

    print(
        "=" * 60
    )

    print(
        "  Collecting a benign behavioral baseline..."
    )

    print(
        "  Do not run attack simulations during profiling.\n"
    )


    hop_active = True


    locker = threading.Thread(
        target=channel_locker,
        args=(
            interface,
            target_channel,
        ),
        daemon=True,
    )


    locker.start()


    time.sleep(
        1
    )


    try:

        sniff(
            iface=interface,
            prn=profile_handler,
            timeout=duration,
            store=False,
        )

    finally:

        hop_active = False


    print(
        "\n\n[✓] Captured "
        f"{len(captured_beacons)} "
        "beacons"
    )


    if len(
        captured_beacons
    ) < 10:

        print(
            "[ERROR] Too few beacons captured."
        )

        print(
            f"[ERROR] Check that "
            f"'{target_ssid}' is nearby."
        )

        return None


    print(
        "[*] Building behavioral baseline..."
    )


    profile = build_profile(
        network_info
    )


    if profile:

        print(
            "\n"
            + "=" * 60
        )

        print(
            "  PROFILE SUMMARY"
        )

        print(
            "=" * 60
        )

        print(
            f"  SSID             : "
            f"{profile['ssid']}"
        )

        print(
            f"  BSSID            : "
            f"{profile['bssid']}"
        )

        print(
            f"  RSSI range       : "
            f"{profile['rssi_min']:.0f} "
            f"to "
            f"{profile['rssi_max']:.0f} dBm"
        )

        print(
            f"  Avg seq jump     : "
            f"{profile['seq_jump_mean']:.2f}"
        )

        print(
            f"  Clock skew avg   : "
            f"{profile['clock_skew_mean']:.6f}"
        )

        print(
            f"  Valid skew rows  : "
            f"{profile['valid_skew_samples']}"
        )

        print(
            f"  IE count         : "
            f"{profile['ie_count']}"
        )

        print(
            f"  Rate count       : "
            f"{profile['rate_count']}"
        )

        print(
            f"  Security         : "
            f"{profile['security']}"
        )

        print(
            f"  Beacon interval  : "
            f"{profile['beacon_interval']}"
        )

        print(
            f"  Beacons observed : "
            f"{profile['total_beacons']}"
        )

        print(
            "=" * 60
        )


        save_profile(
            profile
        )

        save_normal_data()


    return profile


# =======================================================
# LOAD LEGACY PROFILES
# =======================================================

def load_profiles():
    """
    Load profiles from the older single-AP profile file.
    """

    if not os.path.exists(
        config.AP_PROFILES_FILE
    ):

        return {}


    try:

        with open(
            config.AP_PROFILES_FILE,
            "r",
            encoding="utf-8",
        ) as file:

            profiles = json.load(
                file
            )


        print(
            f"[✓] Loaded {len(profiles)} "
            "legacy single-AP profiles"
        )


        return profiles


    except Exception as error:

        print(
            "[!] Could not load legacy profiles:"
        )

        print(
            f"    {error}"
        )

        return {}

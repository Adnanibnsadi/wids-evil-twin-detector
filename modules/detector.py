#!/usr/bin/env python3
"""
=======================================================
 modules/detector.py - Hybrid Evil Twin / Rogue AP WIDS
=======================================================

Passive 802.11 beacon monitoring and anomaly detection.

The detector combines:
- Known SSID/BSSID profile comparison
- Sequence-number behavior
- Beacon Information Element structure
- Advertised security characteristics
- Timing / clock-skew deviation
- Per-BSSID Isolation Forest anomaly models

Designed for research and controlled laboratory evaluation.

Important:
The generated threat score is a heuristic suspicion score.
It is not a calibrated probability that an attack is present.
=======================================================
"""

import datetime
import json
import os
import sys
import threading
import time

import joblib
import numpy as np
from scapy.all import sniff
from scapy.layers.dot11 import (
    Dot11,
    Dot11Beacon,
    Dot11Elt,
    RadioTap,
)

sys.path.insert(
    0,
    os.path.dirname(
        os.path.dirname(
            os.path.abspath(__file__)
        )
    ),
)

import config


# ─────────────────────────────────────────────────────
# GLOBAL STATE
# ─────────────────────────────────────────────────────

detection_running = False
hop_running = False

packet_count = 0
alert_count = 0


# Loaded profiles and anomaly models
bssid_profiles = {}
per_bssid_bundle = {}
global_bundle = {}


# Runtime tracking state
seq_tracker = {}
ts_tracker = {}

# {"bssid_sequence": system_time}
last_seen_seq = {}

# {bssid: system_time}
last_seen_bssid = {}

# {bssid: last_alert_time}
alert_cooldown = {}

# {bssid: consecutive_suspicious_frames}
suspicious_streak = {}


ALERT_COOLDOWN_SEC = 10

# Require multiple suspicious observations before alerting.
REQUIRED_STREAK = 2


# ─────────────────────────────────────────────────────
# RESOURCE LOADER
# ─────────────────────────────────────────────────────

def load_resources():
    """
    Load AP profiles and anomaly-detection models.

    Returns
    -------
    bool
        True when all required resources are available.
    """

    global bssid_profiles
    global per_bssid_bundle
    global global_bundle

    if os.path.exists(config.BSSID_PROFILES_FILE):
        with open(
            config.BSSID_PROFILES_FILE,
            "r",
            encoding="utf-8",
        ) as file:
            bssid_profiles = json.load(file)

        print(
            f"[✓] Loaded {len(bssid_profiles)} "
            "AP behavioral profiles"
        )

    else:
        print(
            "[ERROR] BSSID profiles not found at "
            f"{config.BSSID_PROFILES_FILE}"
        )
        return False

    per_bssid_path = os.path.join(
        config.MODELS_DIR,
        "per_bssid_models.pkl",
    )

    if os.path.exists(per_bssid_path):
        per_bssid_bundle = joblib.load(
            per_bssid_path
        )

        model_count = len(
            per_bssid_bundle.get(
                "models",
                {},
            )
        )

        print(
            f"[✓] Loaded {model_count} "
            "per-BSSID anomaly models"
        )

    else:
        print(
            "[ERROR] Per-BSSID models not found at "
            f"{per_bssid_path}"
        )
        return False

    global_path = os.path.join(
        config.MODELS_DIR,
        "global_model.pkl",
    )

    if os.path.exists(global_path):
        global_bundle = joblib.load(
            global_path
        )

        print(
            "[✓] Loaded global anomaly model"
        )

    else:
        print(
            "[ERROR] Global model not found at "
            f"{global_path}"
        )
        return False

    return True


# ─────────────────────────────────────────────────────
# FEATURE EXTRACTION
# ─────────────────────────────────────────────────────

def extract_features(packet, system_time):
    """
    Extract behavioral and structural features from one
    802.11 beacon frame.

    Timing-derived features are filtered to reduce the
    influence of channel hopping and VMware / USB jitter.
    """

    try:
        bssid = packet[Dot11].addr2

        if not bssid:
            return None

        bssid = bssid.lower()

        # ── SSID ──────────────────────────────────────

        try:
            ssid = packet[
                Dot11Elt
            ].info.decode(
                "utf-8",
                errors="replace",
            )

        except Exception:
            ssid = "<Hidden>"

        if not ssid.strip():
            ssid = "<Hidden>"


        # ── RSSI ──────────────────────────────────────

        rssi = 0

        if packet.haslayer(RadioTap):
            try:
                signal = packet[
                    RadioTap
                ].dBm_AntSignal

                if signal is not None:
                    rssi = signal

            except Exception:
                pass


        # ── CHANNEL ───────────────────────────────────

        channel = 0

        element = packet[Dot11Elt]

        while isinstance(element, Dot11Elt):

            if element.ID == 3 and element.info:
                channel = element.info[0]
                break

            element = element.payload


        # ── SUPPORTED RATES ───────────────────────────

        rates = []

        element = packet[Dot11Elt]

        while isinstance(element, Dot11Elt):

            if element.ID in (1, 50):

                for rate in element.info:
                    rates.append(
                        (rate & 0x7F) * 0.5
                    )

            element = element.payload

        rate_count = len(
            set(rates)
        )


        # ── SECURITY CHARACTERISTICS ──────────────────

        security = "Open"

        has_rsn = False
        has_wpa = False

        element = packet[Dot11Elt]

        while isinstance(element, Dot11Elt):

            if element.ID == 48:
                has_rsn = True

            if (
                element.ID == 221
                and element.info[:4]
                == b"\x00\x50\xf2\x01"
            ):
                has_wpa = True

            element = element.payload

        cap = packet[
            Dot11Beacon
        ].cap

        if has_rsn:
            security = "WPA2/WPA3"

        elif has_wpa:
            security = "WPA"

        elif bool(cap & 0x0010):
            security = "WEP"

        security_map = {
            "Open": 0,
            "WEP": 1,
            "WPA": 2,
            "WPA2/WPA3": 3,
        }

        security_encoded = security_map.get(
            security,
            0,
        )


        # ── BASIC BEACON FEATURES ─────────────────────

        seq_num = (
            packet[Dot11].SC >> 4
        )

        beacon_timestamp = packet[
            Dot11Beacon
        ].timestamp

        beacon_interval = packet[
            Dot11Beacon
        ].beacon_interval

        capabilities = int(
            cap
        )


        # ── INFORMATION ELEMENT COUNT ─────────────────

        ie_count = 0

        element = packet[Dot11Elt]

        while isinstance(
            element,
            Dot11Elt,
        ):
            ie_count += 1
            element = element.payload


        # ── SEQUENCE BEHAVIOR ─────────────────────────

        seq_jump = 0

        if (
            bssid in seq_tracker
            and seq_tracker[bssid]
        ):

            previous_seq = (
                seq_tracker[bssid][-1]
            )

            if seq_num >= previous_seq:

                seq_jump = (
                    seq_num
                    - previous_seq
                )

            else:
                # Sequence field wraps from 4095 → 0.
                seq_jump = (
                    4096
                    - previous_seq
                    + seq_num
                )

        if bssid not in seq_tracker:
            seq_tracker[bssid] = []

        seq_tracker[bssid].append(
            seq_num
        )

        if len(
            seq_tracker[bssid]
        ) > 20:

            seq_tracker[
                bssid
            ].pop(0)

        if seq_jump > 100:

            seq_anomaly_score = min(
                1.0,
                seq_jump / 1000,
            )

        else:
            seq_anomaly_score = 0.0


        # ── TIMING / CLOCK-SKEW ESTIMATE ──────────────

        skew = 0.0
        valid_skew = False

        if bssid not in ts_tracker:
            ts_tracker[bssid] = []

        ts_tracker[bssid].append(
            {
                "beacon_ts":
                    beacon_timestamp,

                "sys_ts":
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
                ts_tracker[bssid][-2]
            )

            current = (
                ts_tracker[bssid][-1]
            )

            time_gap = (
                current["sys_ts"]
                - previous["sys_ts"]
            )

            # Accept timing evidence only when the capture
            # interval is sufficiently tight to reduce
            # channel-hop / virtualization jitter.
            if 0.05 <= time_gap <= 0.25:

                ap_difference = (
                    current["beacon_ts"]
                    - previous["beacon_ts"]
                )

                system_difference = (
                    time_gap
                    * 1_000_000
                )

                if system_difference > 0:

                    skew = (
                        ap_difference
                        - system_difference
                    ) / system_difference

                    valid_skew = True


        # ── INTER-BEACON ARRIVAL TIME ─────────────────

        inter_beacon_ms = 0.0

        if bssid in last_seen_bssid:

            inter_beacon_ms = (
                system_time
                - last_seen_bssid[bssid]
            ) * 1000

        last_seen_bssid[
            bssid
        ] = system_time


        # ── DUPLICATE SEQUENCE OBSERVATION ────────────

        duplicate_key = (
            f"{bssid}_{seq_num}"
        )

        is_seq_duplicate = 0

        if duplicate_key in last_seen_seq:

            duplicate_gap = (
                system_time
                - last_seen_seq[
                    duplicate_key
                ]
            )

            # Duplicate sequence activity in a short
            # interval is treated as strong suspicious
            # evidence, not absolute proof of two radios.
            if (
                0.001
                < duplicate_gap
                < 0.5
            ):
                is_seq_duplicate = 1

        last_seen_seq[
            duplicate_key
        ] = system_time


        return {
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
                    skew,
                    8,
                ),

            "valid_skew":
                valid_skew,

            "beacon_interval":
                beacon_interval,

            "capabilities":
                capabilities,

            "security":
                security,

            "security_encoded":
                security_encoded,

            "ie_count":
                ie_count,

            "rate_count":
                rate_count,

            "inter_beacon_ms":
                inter_beacon_ms,

            "is_seq_duplicate":
                is_seq_duplicate,
        }

    except Exception:
        return None


# ─────────────────────────────────────────────────────
# MULTI-LAYER EVALUATOR
# ─────────────────────────────────────────────────────

def evaluate_packet(feat):
    """
    Compare one beacon observation against known AP
    profiles and anomaly models.

    Returns
    -------
    tuple
        (
            is_suspicious,
            evidence_reasons,
            threat_score
        )

    The threat score is heuristic and is not a calibrated
    attack probability.
    """

    bssid = feat[
        "bssid"
    ]

    ssid = feat[
        "ssid"
    ]

    matched_profile = None
    target_bssid = None


    # ── PROFILE LOOKUP ────────────────────────────────

    if bssid in bssid_profiles:

        matched_profile = (
            bssid_profiles[bssid]
        )

        target_bssid = bssid

    else:

        # Search for an already-profiled AP advertising
        # the same SSID from a different BSSID.
        for (
            profiled_bssid,
            profile,
        ) in bssid_profiles.items():

            if (
                profile["ssid"].lower()
                == ssid.lower()
                and ssid != "<Hidden>"
            ):

                matched_profile = (
                    profile
                )

                target_bssid = (
                    profiled_bssid
                )

                break


    # Ignore APs that are not represented in the
    # current baseline.
    if not matched_profile:

        return (
            False,
            [],
            0.0,
        )


    evidence_reasons = []

    strong_evidence_count = 0

    threat_score = 0.0


    # ── STRONG EVIDENCE 1:
    # SHORT-INTERVAL DUPLICATE SEQUENCE ACTIVITY
    # ─────────────────────────────────────────────────

    if (
        feat[
            "is_seq_duplicate"
        ]
        == 1
    ):

        threat_score += 0.90

        strong_evidence_count += 1

        evidence_reasons.append(
            "Duplicate sequence activity: "
            f"sequence {feat['seq_num']} "
            "was observed again for the same "
            "BSSID within the configured "
            "short timing window."
        )


    # ── STRONG EVIDENCE 2:
    # KNOWN SSID FROM DIFFERENT BSSID
    # ─────────────────────────────────────────────────

    if bssid != target_bssid:

        threat_score += 0.85

        strong_evidence_count += 1

        evidence_reasons.append(
            "SSID/BSSID inconsistency: "
            f"known SSID '{ssid}' observed from "
            f"{bssid}; profiled BSSID is "
            f"{target_bssid}."
        )


    # ── STRONG EVIDENCE 3:
    # BEACON IE STRUCTURAL DEVIATION
    # ─────────────────────────────────────────────────

    ie_difference = abs(
        feat[
            "ie_count"
        ]
        - matched_profile[
            "ie_count"
        ]
    )

    # Allow small structural variation in this
    # prototype before treating the observation
    # as strong evidence.
    if ie_difference >= 3:

        threat_score += 0.70

        strong_evidence_count += 1

        evidence_reasons.append(
            "Beacon IE count deviation: "
            f"observed {feat['ie_count']} "
            "Information Elements; "
            f"baseline {matched_profile['ie_count']} "
            f"(Δ={ie_difference})."
        )


    # ── STRONG EVIDENCE 4:
    # SECURITY CHARACTERISTIC CHANGE
    # ─────────────────────────────────────────────────

    if (
        feat["security"]
        != matched_profile[
            "security"
        ]
    ):

        threat_score += 0.60

        strong_evidence_count += 1

        evidence_reasons.append(
            "Advertised security change: "
            f"observed {feat['security']}; "
            "baseline "
            f"{matched_profile['security']}."
        )


    # ── SUPPORTING EVIDENCE 1:
    # SUPPORTED-RATE DEVIATION
    # ─────────────────────────────────────────────────

    rate_difference = abs(
        feat[
            "rate_count"
        ]
        - matched_profile[
            "rate_count"
        ]
    )

    if rate_difference >= 3:

        threat_score += 0.30

        evidence_reasons.append(
            "Supported-rate deviation: "
            f"observed {feat['rate_count']} "
            "unique rates; "
            f"baseline "
            f"{matched_profile['rate_count']}."
        )


    # ── SUPPORTING EVIDENCE 2:
    # TIMING / CLOCK-SKEW DEVIATION
    # ─────────────────────────────────────────────────

    profile_skew_std = matched_profile.get(
        "clock_skew_std",
        0,
    )

    if (
        feat[
            "valid_skew"
        ]
        and profile_skew_std > 0
    ):

        profile_skew_mean = (
            matched_profile.get(
                "clock_skew_mean",
                0,
            )
        )

        z_skew = abs(
            feat[
                "clock_skew"
            ]
            - profile_skew_mean
        ) / profile_skew_std

        if (
            z_skew > 10.0
            and abs(
                feat[
                    "clock_skew"
                ]
            ) > 0.0005
        ):

            threat_score += 0.35

            evidence_reasons.append(
                "Timing deviation: "
                f"clock-skew estimate "
                f"{feat['clock_skew']:.6f} "
                "differs strongly from the "
                "profiled timing baseline "
                f"({z_skew:.1f}σ)."
            )


    # ── SUPPORTING EVIDENCE 3:
    # PER-BSSID ISOLATION FOREST
    # ─────────────────────────────────────────────────

    models = per_bssid_bundle.get(
        "models",
        {},
    )

    scalers = per_bssid_bundle.get(
        "scalers",
        {},
    )

    features_order = (
        per_bssid_bundle.get(
            "features",
            [],
        )
    )

    if (
        target_bssid in models
        and target_bssid in scalers
        and features_order
        and feat["valid_skew"]
    ):

        model = models[
            target_bssid
        ]

        scaler = scalers[
            target_bssid
        ]

        raw_features = np.array(
            [
                [
                    feat.get(
                        feature,
                        0.0,
                    )
                    for feature
                    in features_order
                ]
            ]
        )

        scaled_features = (
            scaler.transform(
                raw_features
            )
        )

        anomaly_score = (
            model.decision_function(
                scaled_features
            )[0]
        )

        # Threshold retained from the current
        # prototype calibration.
        if anomaly_score < -0.12:

            threat_score += 0.25

            evidence_reasons.append(
                "Per-BSSID anomaly model: "
                f"Isolation Forest decision "
                f"score {anomaly_score:.3f} "
                "fell below the configured "
                "prototype threshold."
            )


    # ── DECISION LOGIC ────────────────────────────────

    # Current prototype policy:
    # - at least one strong evidence condition
    #   OR
    # - aggregated score >= 0.75
    is_suspicious = (
        strong_evidence_count >= 1
        or threat_score >= 0.75
    )

    return (
        is_suspicious,
        evidence_reasons,
        min(
            1.0,
            threat_score,
        ),
    )


# ─────────────────────────────────────────────────────
# ALERT DISPATCHER
# ─────────────────────────────────────────────────────

def handle_detection(
    feat,
    is_suspicious,
    reasons,
    threat_score,
):
    """
    Apply streak confirmation and cooldown before
    generating a detector alert.
    """

    global alert_count

    bssid = feat[
        "bssid"
    ]

    now = time.time()


    if is_suspicious:

        suspicious_streak[
            bssid
        ] = (
            suspicious_streak.get(
                bssid,
                0,
            )
            + 1
        )


        if (
            suspicious_streak[
                bssid
            ]
            >= REQUIRED_STREAK
        ):

            if (
                bssid
                in alert_cooldown
                and (
                    now
                    - alert_cooldown[
                        bssid
                    ]
                )
                < ALERT_COOLDOWN_SEC
            ):
                return


            alert_cooldown[
                bssid
            ] = now

            alert_count += 1


            RED = "\033[91m"
            YELLOW = "\033[93m"
            BOLD = "\033[1m"
            RESET = "\033[0m"


            timestamp = (
                datetime.datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
            )


            print(
                "\n"
                + f"{RED}"
                + "=" * 70
                + f"{RESET}"
            )

            print(
                f"{RED}{BOLD}"
                f"  🚨 [ALERT #{alert_count}] "
                "SUSPICIOUS ACCESS POINT "
                f"ACTIVITY DETECTED 🚨"
                f"{RESET}"
            )

            print(
                f"{RED}"
                + "=" * 70
                + f"{RESET}"
            )

            print(
                f"  {BOLD}Timestamp    :"
                f"{RESET} {timestamp}"
            )

            print(
                f"  {BOLD}Observed SSID:"
                f"{RESET} {feat['ssid']}"
            )

            print(
                f"  {BOLD}Observed BSSID:"
                f"{RESET} {feat['bssid']}"
            )

            print(
                f"  {BOLD}Channel      :"
                f"{RESET} {feat['channel']} | "
                f"{BOLD}RSSI:"
                f"{RESET} {feat['rssi']} dBm"
            )

            print(
                f"  {BOLD}Threat Score :"
                f"{RESET} "
                f"{RED}"
                f"{threat_score * 100:.1f}/100"
                f"{RESET}"
            )

            print(
                f"{YELLOW}"
                + "-" * 70
                + f"{RESET}"
            )

            print(
                f"  {BOLD}"
                "Detection Evidence:"
                f"{RESET}"
            )


            for (
                index,
                reason,
            ) in enumerate(
                reasons,
                1,
            ):

                print(
                    f"   {RED}"
                    f"[{index}]"
                    f"{RESET} "
                    f"{reason}"
                )


            print(
                f"{RED}"
                + "=" * 70
                + f"{RESET}\n"
            )


            os.makedirs(
                config.LOGS_DIR,
                exist_ok=True,
            )


            with open(
                config.ALERT_LOG_FILE,
                "a",
                encoding="utf-8",
            ) as file:

                file.write(
                    f"[{timestamp}] "
                    f"ALERT #{alert_count} | "
                    f"SSID: {feat['ssid']} | "
                    f"BSSID: {feat['bssid']} | "
                    "Threat Score: "
                    f"{threat_score * 100:.1f}/100\n"
                )

                for reason in reasons:

                    file.write(
                        f"  - {reason}\n"
                    )

                file.write(
                    "\n"
                )


    else:

        # A benign observation resets the
        # consecutive-suspicion streak.
        suspicious_streak[
            bssid
        ] = 0


# ─────────────────────────────────────────────────────
# PACKET CONSUMER
# ─────────────────────────────────────────────────────

def packet_consumer(packet):
    """
    Process captured beacon frames.
    """

    global packet_count


    if not packet.haslayer(
        Dot11Beacon
    ):
        return


    features = extract_features(
        packet,
        time.time(),
    )


    if not features:
        return


    packet_count += 1


    (
        is_suspicious,
        reasons,
        threat_score,
    ) = evaluate_packet(
        features
    )


    handle_detection(
        features,
        is_suspicious,
        reasons,
        threat_score,
    )


    if (
        not is_suspicious
        and packet_count % 20 == 0
    ):

        print(
            "\r"
            "  [🛡️ Active Monitor] "
            f"Packets: {packet_count:5d} | "
            f"Alerts: {alert_count:2d} | "
            "Evaluating: "
            f"{features['ssid'][:18]:<18} "
            f"({features['bssid']})",
            end="",
            flush=True,
        )


# ─────────────────────────────────────────────────────
# CHANNEL CONTROL
# ─────────────────────────────────────────────────────

def channel_cycler(
    interface,
    locked_channel=None,
):
    """
    Lock to one channel or cycle through configured
    wireless channels.
    """

    global hop_running


    if locked_channel:

        os.system(
            f"iwconfig {interface} "
            f"channel {locked_channel} "
            "2>/dev/null"
        )

        while hop_running:
            time.sleep(5)


    else:

        while hop_running:

            for channel in config.ALL_CHANNELS:

                if not hop_running:
                    break

                os.system(
                    f"iwconfig {interface} "
                    f"channel {channel} "
                    "2>/dev/null"
                )

                time.sleep(
                    config.HOP_INTERVAL
                )


# ─────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────

def start_detection(
    interface,
    target_network=None,
):
    """
    Start passive Evil Twin / rogue AP monitoring.
    """

    global detection_running
    global hop_running
    global packet_count
    global alert_count
    global suspicious_streak


    packet_count = 0
    alert_count = 0

    suspicious_streak.clear()


    print(
        "\n[*] Initializing hybrid "
        "wireless detection engine..."
    )


    if not load_resources():
        return


    locked_channel = (
        target_network.get(
            "channel"
        )
        if target_network
        else None
    )


    print(
        "\n"
        + "=" * 70
    )

    print(
        "  🛡️ HYBRID ROGUE AP & "
        "EVIL TWIN WIRELESS MONITOR"
    )

    print(
        "=" * 70
    )

    print(
        f"  Interface       : "
        f"{interface}"
    )

    print(
        f"  AP Profiles     : "
        f"{len(bssid_profiles)}"
    )

    print(
        "  Channel Mode    : "
        + (
            "Locked on CH "
            f"{locked_channel}"
            if locked_channel
            else
            "Channel Hopping "
            "(All Configured Channels)"
        )
    )

    print(
        f"  Alert Log       : "
        f"{config.ALERT_LOG_FILE}"
    )

    print(
        "=" * 70
    )

    print(
        "  Listening for 802.11 "
        "beacon frames..."
    )

    print(
        "  Press Ctrl+C to halt.\n"
    )


    hop_running = True


    hopper = threading.Thread(
        target=channel_cycler,
        args=(
            interface,
            locked_channel,
        ),
        daemon=True,
    )

    hopper.start()


    detection_running = True


    try:

        sniff(
            iface=interface,
            prn=packet_consumer,
            store=False,
        )


    except KeyboardInterrupt:

        pass


    finally:

        hop_running = False
        detection_running = False


        print(
            "\n\n"
            + "=" * 70
        )

        print(
            "  DETECTION SESSION FINISHED"
        )

        print(
            f"  Total Beacons Evaluated: "
            f"{packet_count}"
        )

        print(
            f"  Alerts Generated       : "
            f"{alert_count}"
        )

        print(
            f"  Log File               : "
            f"{config.ALERT_LOG_FILE}"
        )

        print(
            "=" * 70
            + "\n"
        )

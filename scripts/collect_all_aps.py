#!/usr/bin/env python3
"""
=======================================================
 scripts/collect_all_aps.py
=======================================================

Collect legitimate IEEE 802.11 beacon observations from
multiple nearby access points for behavioral profiling.

The collector records:

- SSID / BSSID
- RSSI
- Channel
- Sequence behavior
- Beacon timestamp / TSF
- Timing characteristics
- Information Element count
- Supported rates
- Security characteristics
- Beacon interval
- Capability flags

IMPORTANT
---------
This script is intended to build a BENIGN BASELINE.

Do not intentionally run an Evil Twin / rogue-AP
simulation while collecting training data.

Timing and sequence-derived measurements are behavioral
signals. They are not immutable hardware identifiers and
should not independently be treated as proof that multiple
physical transmitters are present.
=======================================================
"""

import datetime
import os
import signal
import sys
import threading
import time

import numpy as np
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
# CONFIGURATION
# =======================================================

INTERFACE = (
    config.find_monitor_interface()
    or "wlan0mon"
)

OUTPUT_FILE = (
    config.ALL_APS_DATA_FILE
)

# None = collect until Ctrl+C.
DURATION = None


# =======================================================
# GLOBAL STATE
# =======================================================

captured_data = []

packet_count = 0

stop_flag = False


# Sequence history per BSSID.
seq_tracker = {}


# TSF / system-time history per BSSID.
ts_tracker = {}


# Inter-beacon timing history per BSSID.
timing_tracker = {}


# Last system arrival time for each BSSID.
last_beacon_time = {}


# Last observation time for each BSSID + sequence pair.
last_sequence_time = {}


# Display statistics.
network_stats = {}


# =======================================================
# INTER-BEACON TIMING
# =======================================================

def calculate_inter_beacon_timing(
    bssid,
    system_time,
):
    """
    Calculate receiver-observed time between consecutive
    captured beacons from one BSSID.

    Returns
    -------
    tuple
        inter_beacon_ms, timing_variance

    Notes
    -----
    These values are influenced by more than the AP.

    Channel hopping, packet loss, USB scheduling,
    virtualization, drivers, and receiver scheduling can
    all affect observed inter-beacon timing.

    Timing is therefore treated as contextual behavioral
    evidence rather than a hardware identifier.
    """

    inter_beacon_ms = 0.0
    timing_variance = 0.0


    if bssid in last_beacon_time:

        inter_beacon_ms = (
            system_time
            - last_beacon_time[bssid]
        ) * 1000


        if bssid not in timing_tracker:

            timing_tracker[bssid] = []


        timing_tracker[
            bssid
        ].append(
            inter_beacon_ms
        )


        # Keep a short rolling history.
        if len(
            timing_tracker[bssid]
        ) > 20:

            timing_tracker[
                bssid
            ].pop(0)


        if len(
            timing_tracker[bssid]
        ) >= 5:

            timing_variance = float(
                np.var(
                    timing_tracker[
                        bssid
                    ]
                )
            )


    last_beacon_time[
        bssid
    ] = system_time


    return (
        round(
            inter_beacon_ms,
            3,
        ),
        round(
            timing_variance,
            6,
        ),
    )


# =======================================================
# DUPLICATE SEQUENCE OBSERVATION
# =======================================================

def check_sequence_duplicate(
    bssid,
    seq_num,
    system_time,
):
    """
    Check whether the same BSSID + sequence number was
    observed again within a short period.

    A short-interval repeated sequence value may be useful
    suspicious evidence in a BSSID-spoofing experiment.

    It is NOT treated as absolute proof of two physical
    transmitters because packet capture behavior,
    retransmission-related effects, frame loss, and other
    implementation details can complicate interpretation.

    Returns
    -------
    tuple
        is_duplicate, time_delta
    """

    key = (
        bssid,
        seq_num,
    )


    if key not in last_sequence_time:

        last_sequence_time[
            key
        ] = system_time

        return (
            False,
            0.0,
        )


    time_delta = (
        system_time
        - last_sequence_time[
            key
        ]
    )


    last_sequence_time[
        key
    ] = system_time


    # Current prototype threshold.
    #
    # The live detector uses a tighter 0.5-second window.
    # This collector records the signal for later analysis.
    is_duplicate = (
        0.001
        < time_delta
        < 0.5
    )


    return (
        is_duplicate,
        round(
            time_delta,
            6,
        ),
    )


# =======================================================
# CLOCK-SKEW ESTIMATE
# =======================================================

def calculate_clock_skew(
    bssid,
    beacon_timestamp,
    system_time,
):
    """
    Estimate relative TSF/system timing deviation.

    Returns
    -------
    tuple
        skew, valid_skew

    The estimate is only considered valid when consecutive
    captured beacons arrive within the configured timing
    window.

    This reduces some of the distortion caused by channel
    hopping, VMware scheduling, USB buffering, packet loss,
    and receiver-side delays.
    """

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
    ) < 2:

        return (
            0.0,
            False,
        )


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


    # Timing window retained from the detector's current
    # VMware/channel-hopping calibration.
    if not (
        0.05
        <= system_gap
        <= 0.25
    ):

        return (
            0.0,
            False,
        )


    ap_difference = (
        current["beacon_ts"]
        - previous["beacon_ts"]
    )


    system_difference = (
        system_gap
        * 1_000_000
    )


    if system_difference <= 0:

        return (
            0.0,
            False,
        )


    skew = (
        ap_difference
        - system_difference
    ) / system_difference


    return (
        round(
            skew,
            8,
        ),
        True,
    )


# =======================================================
# SEQUENCE JUMP
# =======================================================

def calculate_seq_jump(
    bssid,
    seq_num,
):
    """
    Calculate the forward sequence-number difference from
    the previous observation for the same BSSID.

    802.11 sequence numbers use a 12-bit field:
    0 through 4095.
    """

    if bssid not in seq_tracker:

        seq_tracker[
            bssid
        ] = []


    jump = 0


    if seq_tracker[
        bssid
    ]:

        previous_seq = (
            seq_tracker[
                bssid
            ][-1]
        )


        if seq_num >= previous_seq:

            jump = (
                seq_num
                - previous_seq
            )

        else:

            # Correct 12-bit wrap:
            # 4095 -> 0 represents a forward jump of 1.
            jump = (
                4096
                - previous_seq
                + seq_num
            )


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


    return jump


# =======================================================
# FEATURE EXTRACTION
# =======================================================

def extract_all_features(
    packet,
    system_time,
):
    """
    Extract structural, signal, sequence, and timing
    characteristics from one 802.11 beacon frame.
    """

    try:

        bssid = (
            packet[
                Dot11
            ].addr2
        )


        if not bssid:

            return None


        bssid = (
            bssid.lower()
        )


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

                signal_value = (
                    packet[
                        RadioTap
                    ].dBm_AntSignal
                )


                if signal_value is not None:

                    rssi = (
                        signal_value
                    )

            except Exception:

                pass


        # ------------------------------------------------
        # CHANNEL
        # ------------------------------------------------

        channel = 0


        element = (
            packet[
                Dot11Elt
            ]
        )


        while isinstance(
            element,
            Dot11Elt,
        ):

            if (
                element.ID == 3
                and element.info
            ):

                channel = (
                    element.info[0]
                )

                break


            element = (
                element.payload
            )


        # ------------------------------------------------
        # SUPPORTED RATES
        # ------------------------------------------------

        rates = []


        element = (
            packet[
                Dot11Elt
            ]
        )


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
                            rate
                            & 0x7F
                        )
                        * 0.5
                    )


            element = (
                element.payload
            )


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


        element = (
            packet[
                Dot11Elt
            ]
        )


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


            element = (
                element.payload
            )


        cap = (
            packet[
                Dot11Beacon
            ].cap
        )


        has_privacy = bool(
            cap
            & 0x0010
        )


        if has_rsn:

            security = (
                "WPA2/WPA3"
            )

        elif has_wpa:

            security = "WPA"

        elif has_privacy:

            security = "WEP"


        security_map = {
            "Open": 0,
            "WEP": 1,
            "WPA": 2,
            "WPA2/WPA3": 3,
            "unknown": 0,
        }


        security_encoded = (
            security_map.get(
                security,
                0,
            )
        )


        # ------------------------------------------------
        # BASIC BEACON FIELDS
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


        capabilities = int(
            packet[
                Dot11Beacon
            ].cap
        )


        # ------------------------------------------------
        # INFORMATION ELEMENT COUNT
        # ------------------------------------------------

        ie_count = 0


        element = (
            packet[
                Dot11Elt
            ]
        )


        while isinstance(
            element,
            Dot11Elt,
        ):

            ie_count += 1

            element = (
                element.payload
            )


        # ------------------------------------------------
        # SEQUENCE CHARACTERISTICS
        # ------------------------------------------------

        seq_jump = (
            calculate_seq_jump(
                bssid,
                seq_num,
            )
        )


        seq_anomaly = 0.0


        if seq_jump > 100:

            seq_anomaly = min(
                1.0,
                seq_jump / 1000,
            )

        elif seq_jump > 10:

            seq_anomaly = 0.3


        # ------------------------------------------------
        # TIMING CHARACTERISTICS
        # ------------------------------------------------

        (
            clock_skew,
            valid_skew,
        ) = calculate_clock_skew(
            bssid,
            beacon_timestamp,
            system_time,
        )


        (
            inter_beacon_ms,
            timing_variance,
        ) = calculate_inter_beacon_timing(
            bssid,
            system_time,
        )


        # ------------------------------------------------
        # DUPLICATE SEQUENCE OBSERVATION
        # ------------------------------------------------

        (
            is_seq_duplicate,
            seq_dup_delta,
        ) = check_sequence_duplicate(
            bssid,
            seq_num,
            system_time,
        )


        # ------------------------------------------------
        # FEATURE RECORD
        # ------------------------------------------------

        return {

            "timestamp":
                datetime.datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S.%f"
                ),

            "ssid":
                ssid,

            "bssid":
                bssid,


            # Signal / channel
            "rssi":
                rssi,

            "channel":
                channel,


            # Sequence behavior
            "seq_num":
                seq_num,

            "seq_jump":
                seq_jump,

            "seq_anomaly_score":
                round(
                    seq_anomaly,
                    4,
                ),

            "is_seq_duplicate":
                int(
                    is_seq_duplicate
                ),

            "seq_dup_delta":
                seq_dup_delta,


            # Timing behavior
            "beacon_timestamp":
                beacon_timestamp,

            "clock_skew":
                clock_skew,

            "valid_skew":
                int(
                    valid_skew
                ),

            "inter_beacon_ms":
                inter_beacon_ms,

            "timing_variance":
                timing_variance,


            # Structural / configuration characteristics
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

            "security_encoded":
                security_encoded,

            "ie_count":
                ie_count,


            # Baseline class.
            "label":
                0,
        }


    except Exception:

        return None


# =======================================================
# PACKET HANDLER
# =======================================================

def packet_handler(
    packet,
):
    """
    Process one captured beacon frame.
    """

    global packet_count


    if not packet.haslayer(
        Dot11Beacon
    ):

        return


    system_time = (
        time.time()
    )


    features = (
        extract_all_features(
            packet,
            system_time,
        )
    )


    if not features:

        return


    captured_data.append(
        features
    )


    packet_count += 1


    bssid = (
        features[
            "bssid"
        ]
    )


    ssid = (
        features[
            "ssid"
        ]
    )


    if bssid not in network_stats:

        network_stats[
            bssid
        ] = {
            "ssid":
                ssid,

            "count":
                0,

            "rssi":
                0,
        }


    network_stats[
        bssid
    ][
        "count"
    ] += 1


    network_stats[
        bssid
    ][
        "rssi"
    ] = features[
        "rssi"
    ]


    if packet_count % 100 == 0:

        unique_aps = len(
            network_stats
        )


        print(
            "\r  [📡] "
            f"Beacons: {packet_count:5d} | "
            f"APs: {unique_aps:2d} | "
            f"Latest: {ssid[:20]:<20} | "
            f"RSSI: {features['rssi']:4d} dBm",
            end="",
            flush=True,
        )


    # Periodically flush buffered records to disk.
    if packet_count % 500 == 0:

        save_data()


        print(
            f"\n  [💾] Auto-saved after "
            f"{packet_count} captured beacons"
        )


# =======================================================
# CHANNEL HOPPER
# =======================================================

def channel_hopper():
    """
    Cycle through configured Wi-Fi channels.
    """

    global stop_flag


    while not stop_flag:

        for channel in config.ALL_CHANNELS:

            if stop_flag:

                break


            os.system(
                f"iwconfig {INTERFACE} "
                f"channel {channel} "
                "2>/dev/null"
            )


            time.sleep(
                config.HOP_INTERVAL
            )


# =======================================================
# SAVE DATA
# =======================================================

def save_data():
    """
    Append buffered beacon observations to the baseline
    CSV and clear the in-memory buffer.
    """

    if not captured_data:

        return


    df = pd.DataFrame(
        captured_data
    )


    os.makedirs(
        config.DATA_DIR,
        exist_ok=True,
    )


    if os.path.exists(
        OUTPUT_FILE
    ):

        df.to_csv(
            OUTPUT_FILE,
            mode="a",
            header=False,
            index=False,
        )

    else:

        df.to_csv(
            OUTPUT_FILE,
            index=False,
        )


    captured_data.clear()


# =======================================================
# FINAL SUMMARY
# =======================================================

def print_summary():

    print(
        "\n"
        + "=" * 68
    )

    print(
        "  BASELINE COLLECTION SUMMARY"
    )

    print(
        "=" * 68
    )

    print(
        f"  Total beacons : "
        f"{packet_count}"
    )

    print(
        f"  Unique BSSIDs : "
        f"{len(network_stats)}"
    )

    print(
        f"  Saved to      : "
        f"{OUTPUT_FILE}"
    )

    print()


    if network_stats:

        print(
            "  Networks observed:"
        )

        print(
            "-" * 68
        )


        sorted_networks = sorted(
            network_stats.items(),
            key=lambda item:
                item[1][
                    "count"
                ],
            reverse=True,
        )


        for bssid, stats in sorted_networks:

            print(
                f"  "
                f"{stats['ssid'][:24]:<25} "
                f"BSSID: {bssid}  "
                f"Beacons: {stats['count']:5d}  "
                f"RSSI: {stats['rssi']:4d} dBm"
            )


    print(
        "=" * 68
    )


# =======================================================
# SIGNAL HANDLER
# =======================================================

def signal_handler(
    _signal_number,
    _frame,
):
    """
    Gracefully stop collection and save buffered data.
    """

    global stop_flag


    print(
        "\n\n[*] Stopping baseline collection..."
    )


    stop_flag = True


    save_data()


    print_summary()


    sys.exit(
        0
    )


# =======================================================
# MAIN
# =======================================================

def main():

    global stop_flag


    if os.geteuid() != 0:

        print(
            "[ERROR] Monitor-mode capture normally "
            "requires root privileges."
        )

        print()

        print(
            "Run:"
        )

        print(
            "  sudo ./venv/bin/python3 "
            "scripts/collect_all_aps.py"
        )

        sys.exit(
            1
        )


    signal.signal(
        signal.SIGINT,
        signal_handler,
    )


    print(
        "\n"
        + "=" * 68
    )

    print(
        "  MULTI-AP BENIGN BASELINE COLLECTOR"
    )

    print(
        "=" * 68
    )

    print(
        f"  Interface : {INTERFACE}"
    )

    print(
        f"  Output    : {OUTPUT_FILE}"
    )

    print(
        "  Duration  : Until Ctrl+C"
    )

    print(
        f"  Channels  : "
        f"{len(config.ALL_CHANNELS)}"
    )

    print(
        "=" * 68
    )

    print(
        "  IMPORTANT:"
    )

    print(
        "  Collect this dataset during a period you believe "
        "to represent normal / benign network behavior."
    )

    print(
        "  Do not run the project lab simulator during "
        "baseline collection."
    )

    print(
        "=" * 68
    )

    print(
        "\n[*] For research-quality datasets, prefer "
        "multiple independent collection sessions "
        "rather than one extremely long capture."
    )

    print(
        "[*] Press Ctrl+C when finished.\n"
    )


    hopper = threading.Thread(
        target=channel_hopper,
        daemon=True,
    )


    hopper.start()


    time.sleep(
        1
    )


    try:

        sniff(
            iface=INTERFACE,
            prn=packet_handler,
            store=False,
        )


    except KeyboardInterrupt:

        # SIGINT normally invokes the registered handler,
        # but retain this fallback for clean shutdown.
        signal_handler(
            None,
            None,
        )


    finally:

        stop_flag = True


if __name__ == "__main__":
    main()

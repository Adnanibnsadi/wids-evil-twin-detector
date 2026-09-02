#!/usr/bin/env python3
"""
=======================================================
 scripts/sniffer.py
=======================================================

LEGACY / EARLY BEACON SNIFFER

This script represents an earlier stage of the WIDS
project. It captures IEEE 802.11 beacon frames, displays
selected features, and can save observations to the older
single-AP baseline dataset.

The current primary data-collection workflow is:

    scripts/collect_all_aps.py

followed by:

    scripts/build_profiles.py
    scripts/build_advanced_model.py

This file is retained for historical experimentation and
basic beacon inspection.

Timing, RSSI, sequence behavior, supported rates, and
Information Element characteristics are behavioral or
structural observations. None should independently be
treated as proof of a rogue access point.
=======================================================
"""

import datetime
import os
import signal
import sys
import threading
import time

import pandas as pd
from scapy.all import get_if_list, sniff
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

OUTPUT_FILE = config.NORMAL_DATA_FILE

MAX_PACKETS = None

TARGET_SSID = None

ALL_CHANNELS = config.ALL_CHANNELS

HOP_INTERVAL = config.HOP_INTERVAL


# =======================================================
# GLOBAL STATE
# =======================================================

captured_data = []

packet_count = 0

sequence_tracker = {}

timestamp_tracker = {}

stop_hopper = False


# =======================================================
# CHANNEL HOPPING
# =======================================================

def channel_hopper():
    """
    Cycle through configured Wi-Fi channels.

    Channel hopping increases coverage but also introduces
    gaps in observations from individual BSSIDs, which is
    important when interpreting timing-derived features.
    """

    global stop_hopper

    print(
        "[*] Legacy channel hopper started..."
    )

    while not stop_hopper:

        for channel in ALL_CHANNELS:

            if stop_hopper:
                break

            os.system(
                f"iwconfig {INTERFACE} "
                f"channel {channel} "
                "2>/dev/null"
            )

            time.sleep(
                HOP_INTERVAL
            )

    print(
        "[*] Channel hopper stopped."
    )


# =======================================================
# FEATURE HELPERS
# =======================================================

def extract_rssi(packet):
    """
    Extract receiver-observed signal strength.

    RSSI is highly environment-dependent and is treated as
    contextual information rather than transmitter proof.
    """

    try:

        if packet.haslayer(
            RadioTap
        ):

            signal = packet[
                RadioTap
            ].dBm_AntSignal

            if signal is not None:
                return signal

    except Exception:
        pass

    return 0


def extract_channel(packet):
    """
    Extract the DS Parameter Set channel when present.
    """

    try:

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

                return element.info[0]

            element = element.payload

    except Exception:
        pass

    return 0


def extract_supported_rates(packet):
    """
    Extract advertised supported rates.

    Supported-rate combinations can contribute to a
    structural/configuration baseline but are not immutable
    hardware identifiers.
    """

    rates = []

    try:

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

    except Exception:
        pass


    if not rates:
        return "unknown"


    return ",".join(
        map(
            str,
            sorted(
                set(
                    rates
                )
            ),
        )
    )


def extract_security(packet):
    """
    Extract simplified advertised security category.
    """

    try:

        element = packet[
            Dot11Elt
        ]

        has_rsn = False
        has_wpa = False


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
            return "WPA2/WPA3"

        if has_wpa:
            return "WPA"

        if capabilities & 0x0010:
            return "WEP"

        return "Open"

    except Exception:

        return "unknown"


# =======================================================
# SEQUENCE BEHAVIOR
# =======================================================

def calculate_seq_anomaly(
    bssid,
    current_seq,
):
    """
    Calculate forward sequence-number movement.

    Large jumps may be interesting during analysis but can
    also arise because frames were missed while the receiver
    was tuned to another channel.

    Returns
    -------
    tuple
        sequence_jump, heuristic_anomaly_score
    """

    if bssid not in sequence_tracker:

        sequence_tracker[
            bssid
        ] = []


    history = sequence_tracker[
        bssid
    ]

    seq_jump = 0
    anomaly_score = 0.0


    if history:

        previous_seq = history[
            -1
        ]


        if current_seq >= previous_seq:

            seq_jump = (
                current_seq
                - previous_seq
            )

        else:

            # 12-bit sequence numbers span 0..4095.
            # Therefore 4095 -> 0 is a forward jump of 1.
            seq_jump = (
                4096
                - previous_seq
                + current_seq
            )


        if seq_jump > 100:

            anomaly_score = min(
                1.0,
                seq_jump / 1000,
            )

        elif seq_jump > 10:

            anomaly_score = 0.3


    history.append(
        current_seq
    )


    if len(
        history
    ) > 20:

        history.pop(
            0
        )


    return (
        seq_jump,
        anomaly_score,
    )


# =======================================================
# TIMING ESTIMATE
# =======================================================

def calculate_timestamp_skew(
    bssid,
    beacon_timestamp,
    system_time,
):
    """
    Estimate short-term TSF/system timing deviation.

    Returns
    -------
    tuple
        clock_skew, valid_skew

    Receiver timing can be affected by channel hopping,
    virtualization, USB scheduling, drivers, buffering,
    and packet loss. The value is therefore accepted only
    when consecutive observations fall within the current
    prototype timing window.
    """

    if bssid not in timestamp_tracker:

        timestamp_tracker[
            bssid
        ] = []


    history = timestamp_tracker[
        bssid
    ]


    history.append(
        {
            "beacon_ts":
                beacon_timestamp,

            "system_ts":
                system_time,
        }
    )


    if len(
        history
    ) > 20:

        history.pop(
            0
        )


    if len(
        history
    ) < 2:

        return (
            0.0,
            False,
        )


    previous = history[
        -2
    ]

    current = history[
        -1
    ]


    system_gap = (
        current[
            "system_ts"
        ]
        - previous[
            "system_ts"
        ]
    )


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
        current[
            "beacon_ts"
        ]
        - previous[
            "beacon_ts"
        ]
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
# PACKET HANDLER
# =======================================================

def handle_packet(packet):
    """
    Extract and display selected features from beacon
    frames.
    """

    global packet_count


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


        if not ssid.strip():

            ssid = "<Hidden>"


        if (
            TARGET_SSID
            and ssid != TARGET_SSID
        ):

            return


        system_time = (
            time.time()
        )


        timestamp = (
            datetime.datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S.%f"
            )
        )


        rssi = extract_rssi(
            packet
        )

        channel = extract_channel(
            packet
        )

        supported_rates = (
            extract_supported_rates(
                packet
            )
        )

        security = extract_security(
            packet
        )


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


        (
            seq_jump,
            seq_anomaly_score,
        ) = calculate_seq_anomaly(
            bssid,
            seq_num,
        )


        (
            clock_skew,
            valid_skew,
        ) = calculate_timestamp_skew(
            bssid,
            beacon_timestamp,
            system_time,
        )


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


        rate_count = 0


        if supported_rates != "unknown":

            rate_count = len(
                supported_rates.split(
                    ","
                )
            )


        data_entry = {

            "timestamp":
                timestamp,

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
                clock_skew,

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


        captured_data.append(
            data_entry
        )


        packet_count += 1


        if packet_count % 20 == 1:

            print(
                "\n"
                + "=" * 108
            )

            print(
                f"{'#':<6}"
                f"{'SSID':<22}"
                f"{'BSSID':<20}"
                f"{'RSSI':<7}"
                f"{'CH':<5}"
                f"{'SEQ':<7}"
                f"{'JUMP':<8}"
                f"{'SECURITY':<14}"
                f"{'IE':<5}"
                f"{'SKEW'}"
            )

            print(
                "=" * 108
            )


        print(
            f"{packet_count:<6}"
            f"{ssid[:21]:<22}"
            f"{bssid:<20}"
            f"{rssi:<7}"
            f"{channel:<5}"
            f"{seq_num:<7}"
            f"{seq_jump:<8}"
            f"{security:<14}"
            f"{ie_count:<5}"
            f"{clock_skew}"
        )


        if packet_count % 50 == 0:

            save_data()

            print(
                f"\n[💾] Saved legacy observations "
                f"after {packet_count} beacons\n"
            )


    except Exception:

        return


# =======================================================
# CSV STORAGE
# =======================================================

def save_data():
    """
    Append buffered observations to the older
    normal_data.csv dataset.

    This CSV is retained for legacy experiments and is not
    the primary dataset used by the current multi-AP WIDS.
    """

    if not captured_data:

        return


    df = pd.DataFrame(
        captured_data
    )


    os.makedirs(
        os.path.dirname(
            OUTPUT_FILE
        ),
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
# EXIT HANDLER
# =======================================================

def signal_handler(
    _signal_number,
    _frame,
):
    """
    Stop channel hopping and save buffered observations.
    """

    global stop_hopper


    print(
        "\n\n[*] Stopping legacy beacon capture..."
    )


    stop_hopper = True


    time.sleep(
        0.5
    )


    save_data()


    print(
        f"[✓] Total beacon observations: "
        f"{packet_count}"
    )

    print(
        f"[✓] Data file: "
        f"{OUTPUT_FILE}"
    )


    sys.exit(
        0
    )


# =======================================================
# MAIN
# =======================================================

def main():

    global stop_hopper


    signal.signal(
        signal.SIGINT,
        signal_handler,
    )


    print(
        "\n"
        + "=" * 68
    )

    print(
        "  LEGACY IEEE 802.11 BEACON SNIFFER"
    )

    print(
        "=" * 68
    )

    print(
        "  Status    : Historical / experimental utility"
    )

    print(
        f"  Interface : {INTERFACE}"
    )

    print(
        f"  Output    : {OUTPUT_FILE}"
    )

    print(
        f"  Target    : "
        f"{TARGET_SSID or 'All observed networks'}"
    )

    print(
        f"  Channels  : "
        f"{len(ALL_CHANNELS)}"
    )

    print(
        "=" * 68
    )

    print(
        "\nFor the current multi-AP research workflow use:"
    )

    print(
        "  scripts/collect_all_aps.py"
    )

    print(
        "\nPress Ctrl+C to stop and save.\n"
    )


    available_interfaces = (
        get_if_list()
    )


    if INTERFACE not in available_interfaces:

        print(
            f"[ERROR] Interface "
            f"'{INTERFACE}' not found."
        )

        print(
            "Available interfaces:"
        )

        for interface in available_interfaces:

            print(
                f"  - {interface}"
            )

        print()

        print(
            "Example monitor-mode setup:"
        )

        print(
            "  sudo airmon-ng check kill"
        )

        print(
            "  sudo airmon-ng start wlan0"
        )

        sys.exit(
            1
        )


    os.makedirs(
        os.path.dirname(
            OUTPUT_FILE
        ),
        exist_ok=True,
    )


    stop_hopper = False


    hopper = threading.Thread(
        target=channel_hopper,
        daemon=True,
    )


    hopper.start()


    time.sleep(
        1
    )


    sniff(
        iface=INTERFACE,
        prn=handle_packet,
        count=MAX_PACKETS or 0,
        store=False,
    )


if __name__ == "__main__":

    if os.geteuid() != 0:

        print(
            "[ERROR] Monitor-mode packet capture normally "
            "requires root privileges."
        )

        print(
            "Run:"
        )

        print(
            "  sudo ./venv/bin/python3 scripts/sniffer.py"
        )

        sys.exit(
            1
        )


    main()

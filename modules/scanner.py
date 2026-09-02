#!/usr/bin/env python3
"""
=======================================================
 modules/scanner.py - Nearby Wi-Fi Network Scanner
=======================================================

Passive IEEE 802.11 beacon scanner used by the WIDS CLI.

The scanner:

- Captures nearby beacon frames
- Extracts SSID / BSSID
- Estimates signal strength
- Reads advertised channel information when available
- Classifies basic advertised security
- Counts observed beacon frames
- Allows the user to select an AP for focused monitoring

A monitor-mode Wi-Fi interface is required.

Channel availability and capture behavior depend on the
wireless adapter, driver, regulatory domain, and operating
environment.
=======================================================
"""

import os
import subprocess
import sys
import threading
import time

from scapy.all import sniff
from scapy.layers.dot11 import (
    Dot11,
    Dot11Beacon,
    Dot11Elt,
    RadioTap,
)


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


# =======================================================
# RUNTIME STATE
# =======================================================

discovered_networks = {}

hop_running = False


# =======================================================
# CHANNEL CONTROL
# =======================================================

def set_channel(
    interface,
    channel,
):
    """
    Attempt to tune the wireless interface to one channel.

    Unsupported channels may fail depending on the adapter
    and regulatory configuration. Such failures are ignored
    during passive scanning so the hopper can continue.
    """

    try:

        subprocess.run(
            [
                "iwconfig",
                interface,
                "channel",
                str(channel),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )

    except OSError:

        pass


def channel_hopper(
    interface,
):
    """
    Cycle through configured Wi-Fi channels while scanning.
    """

    global hop_running


    while hop_running:

        for channel in config.ALL_CHANNELS:

            if not hop_running:
                break


            set_channel(
                interface,
                channel,
            )


            time.sleep(
                config.HOP_INTERVAL
            )


# =======================================================
# FEATURE EXTRACTION
# =======================================================

def extract_ssid(
    packet,
):
    """
    Extract the SSID from the first SSID Information
    Element.
    """

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


        if not ssid.strip():

            return "<Hidden>"


        return ssid


    except Exception:

        return "<Hidden>"


def extract_channel(
    packet,
):
    """
    Extract the advertised DS Parameter Set channel.

    Returns 0 when the beacon does not contain an
    immediately usable channel element.
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

                return int(
                    element.info[0]
                )


            element = element.payload


    except Exception:

        pass


    return 0


def extract_rssi(
    packet,
):
    """
    Extract receiver-observed signal strength when
    provided by the capture adapter / driver.
    """

    try:

        if packet.haslayer(
            RadioTap
        ):

            signal = packet[
                RadioTap
            ].dBm_AntSignal


            if signal is not None:

                return int(
                    signal
                )


    except Exception:

        pass


    return 0


def extract_security(
    packet,
):
    """
    Classify the basic security configuration advertised
    by the beacon.

    Current simplified categories:

    - Open
    - WEP
    - WPA
    - WPA2/WPA3

    WPA2 and WPA3 are currently grouped because the
    scanner only performs lightweight beacon inspection.
    """

    has_rsn = False
    has_wpa = False


    try:

        element = packet[
            Dot11Elt
        ]


        while isinstance(
            element,
            Dot11Elt,
        ):

            if element.ID == 48:

                has_rsn = True


            elif (
                element.ID == 221
                and element.info[:4]
                == b"\x00\x50\xf2\x01"
            ):

                has_wpa = True


            element = element.payload


        capabilities = str(
            packet[
                Dot11Beacon
            ].cap
        ).lower()


        has_privacy = (
             "privacy"
              in capabilities
        )


        if has_rsn:

            return "WPA2/WPA3"


        if has_wpa:

            return "WPA"


        if has_privacy:

            return "WEP"


    except Exception:

        pass


    return "Open"


# =======================================================
# PACKET HANDLER
# =======================================================

def scan_handler(
    packet,
):
    """
    Process one beacon frame and update the current scan
    result for its BSSID.
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


        ssid = extract_ssid(
            packet
        )


        channel = extract_channel(
            packet
        )


        rssi = extract_rssi(
            packet
        )


        security = extract_security(
            packet
        )


        if bssid not in discovered_networks:

            discovered_networks[
                bssid
            ] = {

                "ssid":
                    ssid,

                "bssid":
                    bssid,

                "channel":
                    channel,

                "rssi":
                    rssi,

                "security":
                    security,

                "beacons":
                    1,

                "first_seen":
                    time.strftime(
                        "%H:%M:%S"
                    ),

                "last_seen":
                    time.strftime(
                        "%H:%M:%S"
                    ),
            }


        else:

            network = discovered_networks[
                bssid
            ]


            network[
                "beacons"
            ] += 1


            network[
                "rssi"
            ] = rssi


            network[
                "security"
            ] = security


            network[
                "last_seen"
            ] = time.strftime(
                "%H:%M:%S"
            )


            # Do not overwrite a previously known channel
            # with zero when the current beacon lacks a
            # usable DS Parameter Set element.
            if channel:

                network[
                    "channel"
                ] = channel


            # A previously hidden SSID may later appear in
            # a decodable beacon / probe-related context.
            if (
                network[
                    "ssid"
                ] == "<Hidden>"
                and ssid != "<Hidden>"
            ):

                network[
                    "ssid"
                ] = ssid


    except Exception:

        return


# =======================================================
# DISPLAY
# =======================================================

def sorted_networks(
    networks=None,
):
    """
    Return network records sorted by RSSI, strongest first.
    """

    source = (
        networks
        if networks is not None
        else discovered_networks
    )


    return sorted(
        source.values(),
        key=lambda item:
            item.get(
                "rssi",
                -999,
            ),
        reverse=True,
    )


def display_networks(
    networks=None,
):
    """
    Display discovered networks in signal-strength order.
    """

    source = (
        networks
        if networks is not None
        else discovered_networks
    )


    if not source:

        print(
            "\n  No networks were observed "
            "during this scan."
        )

        return


    ordered = sorted_networks(
        source
    )


    print(
        "\n"
        + "=" * 92
    )


    print(
        f"  "
        f"{'#':<4}"
        f"{'SSID':<25}"
        f"{'BSSID':<20}"
        f"{'CH':<5}"
        f"{'RSSI':<8}"
        f"{'SECURITY':<14}"
        f"{'BEACONS':<9}"
    )


    print(
        "=" * 92
    )


    for index, network in enumerate(
        ordered,
        start=1,
    ):

        rssi = network.get(
            "rssi",
            0,
        )


        if rssi == 0:

            color = "\033[0m"

        elif rssi > -50:

            color = "\033[92m"

        elif rssi > -70:

            color = "\033[93m"

        else:

            color = "\033[91m"


        reset = "\033[0m"


        print(
            f"  {color}"
            f"{index:<4}"
            f"{network['ssid'][:24]:<25}"
            f"{network['bssid']:<20}"
            f"{network['channel']:<5}"
            f"{network['rssi']:<8}"
            f"{network['security']:<14}"
            f"{network['beacons']:<9}"
            f"{reset}"
        )


    print(
        "=" * 92
    )


    print(
        f"  Total unique BSSIDs observed: "
        f"{len(source)}"
    )


# =======================================================
# MAIN SCAN FUNCTION
# =======================================================

def scan_networks(
    interface,
    duration=30,
):
    """
    Scan nearby access points for a fixed period.

    Each call starts with a fresh result set.

    Parameters
    ----------
    interface : str
        Monitor-mode interface.

    duration : int or float
        Capture duration in seconds.

    Returns
    -------
    dict
        Mapping of BSSID -> observed network information.
    """

    global hop_running


    # A new scan should never contain stale results from a
    # previous invocation.
    discovered_networks.clear()


    print(
        "\n"
        + "=" * 64
    )


    print(
        "  PASSIVE NEARBY WI-FI SCAN"
    )


    print(
        "=" * 64
    )


    print(
        f"  Interface : {interface}"
    )


    print(
        f"  Duration  : {duration} seconds"
    )


    print(
        f"  Configured channels: "
        f"{len(config.ALL_CHANNELS)}"
    )


    print(
        "=" * 64
    )


    print(
        "  Listening for 802.11 beacon frames...\n"
    )


    hop_running = True


    hopper = threading.Thread(
        target=channel_hopper,
        args=(
            interface,
        ),
        daemon=True,
    )


    hopper.start()


    try:

        sniff(
            iface=interface,
            prn=scan_handler,
            timeout=duration,
            store=False,
        )


    except PermissionError:

        print(
            "\n[ERROR] Packet capture permission denied."
        )


    except OSError as error:

        print(
            "\n[ERROR] Scanner could not use "
            f"interface '{interface}':"
        )

        print(
            f"        {error}"
        )


    finally:

        hop_running = False


        hopper.join(
            timeout=1.0
        )


    # Return a copy so a later scan cannot unexpectedly
    # mutate the caller's previous result.
    results = {
        bssid:
            dict(
                network
            )
        for bssid, network
        in discovered_networks.items()
    }


    display_networks(
        results
    )


    return results


# =======================================================
# NETWORK SELECTION
# =======================================================

def select_network(
    networks_dict,
):
    """
    Allow the user to select one observed AP.

    Returning None represents either:

    - monitoring all profiled networks, or
    - cancelling the selection.

    Callers that require one specific AP should therefore
    verify the return value.
    """

    if not networks_dict:

        print(
            "\n[!] No networks available for selection."
        )

        return None


    ordered = sorted_networks(
        networks_dict
    )


    print(
        "\n"
        + "=" * 64
    )


    print(
        "  SELECT NETWORK"
    )


    print(
        "=" * 64
    )


    print(
        "  Select a network you own or are authorized "
        "to monitor."
    )


    print(
        "=" * 64
    )


    for index, network in enumerate(
        ordered,
        start=1,
    ):

        print(
            f"  [{index}] "
            f"{network['ssid'][:25]:<25} "
            f"CH:{network['channel']:<4} "
            f"{network['rssi']:>4} dBm  "
            f"{network['security']}"
        )


    print(
        "  [0] Monitor all profiled networks"
    )


    print(
        "=" * 64
    )


    while True:

        try:

            choice = input(
                "\n  Enter your choice: "
            ).strip()


            choice = int(
                choice
            )


            if choice == 0:

                print(
                    "\n  [✓] No single AP selected."
                )

                print(
                    "  [✓] Detector may monitor "
                    "all available profiles."
                )

                return None


            if (
                1
                <= choice
                <= len(
                    ordered
                )
            ):

                selected = ordered[
                    choice - 1
                ]


                print(
                    f"\n  [✓] Selected SSID : "
                    f"{selected['ssid']}"
                )

                print(
                    f"  [✓] BSSID        : "
                    f"{selected['bssid']}"
                )

                print(
                    f"  [✓] Channel      : "
                    f"{selected['channel']}"
                )


                return selected


            print(
                f"  [!] Enter a value from 0 to "
                f"{len(ordered)}."
            )


        except ValueError:

            print(
                "  [!] Please enter a number."
            )


        except KeyboardInterrupt:

            print(
                "\n  [!] Selection cancelled."
            )

            return None

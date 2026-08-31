#!/usr/bin/env python3
"""=======================================================
  Evil Twin Detector : Wi-Fi Beacon Sniffer
=======================================================
  What this script does:
  - Puts your Wi-Fi card in monitor mode listening state
  - Captures all Beacon Frames from nearby Access Points
  - Extracts important features from each beacon
  - Displays them in real-time on screen
  - Saves everything to a CSV file for AI training later

  Author: Adnan
  Project: AI-Enabled Rogue Access Point Detector
=======================================================
"""
# ─────────────────────────────────────────────────────
# IMPORTS
# ─────────────────────────────────────────────────────
from scapy.all import *
from scapy.layers.dot11 import (
    Dot11,
    Dot11Beacon,
    Dot11Elt,
    RadioTap
)
import pandas as pd
import numpy as np
import datetime
import os
import sys
import signal
import time
import threading

# ─────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────

INTERFACE = "wlan0mon"

# FIXED PATH - Always points to kali user's folder
# regardless of whether we run with sudo or not
BASE_DIR    = "/home/user/Desktop/evil_twin_detector"
OUTPUT_FILE = f"{BASE_DIR}/data/normal_data.csv"

MAX_PACKETS = None
TARGET_SSID = None

CHANNELS_2GHZ = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
CHANNELS_5GHZ = [36, 40, 44, 48, 52, 56, 60, 64, 100, 149, 153, 157, 161]
ALL_CHANNELS  = CHANNELS_2GHZ + CHANNELS_5GHZ
HOP_INTERVAL  = 0.5
# ─────────────────────────────────────────────────────
# GLOBAL VARIABLES
# ─────────────────────────────────────────────────────
captured_data     = []
packet_count      = 0
sequence_tracker  = {}
timestamp_tracker = {}
stop_hopper       = False

# ─────────────────────────────────────────────────────
# CHANNEL HOPPER
# ─────────────────────────────────────────────────────

def channel_hopper():
    """
    Runs in background thread.
    Cycles through all Wi-Fi channels so we
    can capture beacons from ALL nearby networks.
    
    Without this, the card stays on ONE channel
    and misses everything on other channels.
    """
    global stop_hopper
    print("[*] Channel hopper started in background...")

    while not stop_hopper:
        for channel in ALL_CHANNELS:
            if stop_hopper:
                break
            try:
                os.system(
                    f"iwconfig {INTERFACE} channel {channel} 2>/dev/null"
                )
                time.sleep(HOP_INTERVAL)
            except Exception:
                pass

    print("[*] Channel hopper stopped.")

# ─────────────────────────────────────────────────────
# FEATURE EXTRACTION FUNCTIONS
# ─────────────────────────────────────────────────────

def extract_rssi(packet):
    """
    Extract signal strength in dBm.
    
    dBm Scale:
    -30 = Amazing (very close)
    -50 = Excellent
    -60 = Good
    -70 = Fair
    -80 = Weak
    -90 = Very weak
    
    Evil Twin often has unusually strong signal
    because attacker is physically close to victim.
    """
    try:
        if packet.haslayer(RadioTap):
            return packet[RadioTap].dBm_AntSignal
    except Exception:
        pass
    return 0


def extract_channel(packet):
    """
    Extract channel number from beacon.
    
    2.4GHz channels: 1-13
    5.0GHz channels: 36,40,44,48...
    
    Evil Twin might broadcast on different channel
    than the real AP to avoid interference.
    """
    try:
        element = packet[Dot11Elt]
        while element:
            if element.ID == 3:
                return ord(element.info)
            element = element.payload
    except Exception:
        pass
    return 0


def extract_supported_rates(packet):
    """
    Extract data rates AP supports (Mbps).
    
    Example rates: 1.0, 2.0, 5.5, 6.0, 9.0, 11.0, 24.0, 54.0
    
    WHY THIS MATTERS:
    Different hardware = different rate combinations.
    A real Netgear router and a fake Raspberry Pi
    hotspot will advertise different rates.
    This is like a hardware fingerprint.
    """
    try:
        rates   = []
        element = packet[Dot11Elt]
        while element:
            if element.ID in [1, 50]:
                for rate in element.info:
                    actual_rate = (rate & 0x7F) * 0.5
                    rates.append(actual_rate)
            element = element.payload
        if rates:
            return ",".join(map(str, sorted(set(rates))))
    except Exception:
        pass
    return "unknown"


def extract_security(packet):
    """
    Extract security protocol.
    
    Returns: Open, WEP, WPA, WPA2/WPA3
    
    WHY THIS MATTERS:
    Evil Twins sometimes drop security to Open
    so victims connect without a password prompt.
    Or they use different security than real AP.
    """
    try:
        element  = packet[Dot11Elt]
        has_rsn  = False
        has_wpa  = False

        while element:
            if element.ID == 48:
                has_rsn = True
            if element.ID == 221:
                if element.info[:4] == b'\x00\x50\xf2\x01':
                    has_wpa = True
            element = element.payload

        capability  = packet[Dot11Beacon].cap
        has_privacy = bool(capability & 0x0010)

        if has_rsn:
            return "WPA2/WPA3"
        elif has_wpa:
            return "WPA"
        elif has_privacy:
            return "WEP"
        else:
            return "Open"
    except Exception:
        pass
    return "unknown"


def calculate_seq_anomaly(bssid, current_seq):
    """
    Detect sequence number anomalies.
    
    HOW SEQUENCE NUMBERS WORK:
    Every beacon frame gets a number: 0, 1, 2, 3...
    up to 4095, then wraps back to 0.
    
    NORMAL (one real AP):
    We see: 100, 101, 102, 103, 104
    Jump between each = 1 (normal)
    
    EVIL TWIN (two devices, same BSSID):
    Real AP sends:      100, 101, 102
    Evil Twin sends:    800, 801, 802
    We receive mixed:   100, 800, 101, 801
    Jump we calculate:  700! (very suspicious)
    
    Returns:
      seq_jump      = how big the jump was
      anomaly_score = 0.0 (normal) to 1.0 (very suspicious)
    """
    if bssid not in sequence_tracker:
        sequence_tracker[bssid] = []

    history       = sequence_tracker[bssid]
    seq_jump      = 0
    anomaly_score = 0.0

    if len(history) > 0:
        last_seq = history[-1]

        # Calculate jump (handle wrap-around at 4095)
        if current_seq >= last_seq:
            seq_jump = current_seq - last_seq
        else:
            seq_jump = (4095 - last_seq) + current_seq

        # Score the anomaly
        if seq_jump > 100:
            anomaly_score = min(1.0, seq_jump / 1000)
        elif seq_jump > 10:
            anomaly_score = 0.3
        else:
            anomaly_score = 0.0

    # Keep only last 10 sequence numbers per BSSID
    history.append(current_seq)
    if len(history) > 10:
        history.pop(0)

    return seq_jump, anomaly_score


def calculate_timestamp_skew(bssid, beacon_timestamp, system_time):
    """
    Calculate hardware clock skew.
    
    WHAT IS CLOCK SKEW?
    Every router has an internal clock counting
    microseconds since it was turned on.
    
    No clock is 100% perfect.
    - Router A clock: runs at 99.9998% speed
    - Router B clock: runs at 100.0003% speed
    
    This tiny difference is a HARDWARE FINGERPRINT.
    
    WHY EVIL TWIN CANNOT FAKE THIS:
    Even if attacker copies SSID, BSSID, and settings,
    their hardware has a DIFFERENT clock speed.
    Over time, the skew value will be clearly different
    from the real AP's skew value.
    
    Returns: float (drift in microseconds per second)
    """
    if bssid not in timestamp_tracker:
        timestamp_tracker[bssid] = []

    history = timestamp_tracker[bssid]
    skew    = 0.0

    entry = {
        'beacon_ts': beacon_timestamp,
        'system_ts': system_time
    }
    history.append(entry)

    if len(history) >= 2:
        first         = history[0]
        last          = history[-1]
        ap_time_diff  = last['beacon_ts'] - first['beacon_ts']
        sys_time_diff = (last['system_ts'] - first['system_ts']) * 1_000_000

        if sys_time_diff > 0:
            skew = (ap_time_diff - sys_time_diff) / sys_time_diff

    if len(history) > 20:
        history.pop(0)

    return round(skew, 6)

# ─────────────────────────────────────────────────────
# MAIN PACKET HANDLER
# ─────────────────────────────────────────────────────

def handle_packet(packet):
    """
    Called by Scapy for EVERY packet captured.
    
    FLOW:
    Packet arrives → Is it a Beacon? → Extract features
    → Calculate anomaly scores → Store in list → Display
    
    Non-beacon packets (data frames, probe requests)
    are ignored immediately.
    """
    global packet_count

    # Only process Beacon frames
    # Beacon = AP announcement broadcast
    if not packet.haslayer(Dot11Beacon):
        return

    try:
        # ── Basic Information ───────────────────────────
        bssid = packet[Dot11].addr2

        try:
            ssid = packet[Dot11Elt].info.decode('utf-8', errors='replace')
        except Exception:
            ssid = "unknown"

        # Handle hidden networks
        if not ssid or ssid.strip() == "":
            ssid = "<Hidden>"

        # Apply SSID filter if configured
        if TARGET_SSID and ssid != TARGET_SSID:
            return

        # ── Timestamps ──────────────────────────────────
        system_time = time.time()
        timestamp   = datetime.datetime.now().strftime(
                          "%Y-%m-%d %H:%M:%S.%f"
                      )

        # ── Extract All Features ────────────────────────
        rssi             = extract_rssi(packet)
        channel          = extract_channel(packet)
        supported_rates  = extract_supported_rates(packet)
        security         = extract_security(packet)
        seq_num          = packet[Dot11].SC >> 4
        beacon_timestamp = packet[Dot11Beacon].timestamp
        beacon_interval  = packet[Dot11Beacon].beacon_interval
        capabilities     = packet[Dot11Beacon].cap

        # ── Advanced Features ───────────────────────────
        seq_jump, seq_anomaly_score = calculate_seq_anomaly(
                                          bssid, seq_num
                                      )
        clock_skew = calculate_timestamp_skew(
                         bssid, beacon_timestamp, system_time
                     )

        # Count Information Elements in beacon
        # More IEs = more complex/modern AP
        ie_count = 0
        element  = packet[Dot11Elt]
        while element and isinstance(element, Dot11Elt):
            ie_count += 1
            element   = element.payload

        # ── Build Data Entry (one row in our CSV) ───────
        data_entry = {
            'timestamp':         timestamp,
            'ssid':              ssid,
            'bssid':             bssid,
            'rssi':              rssi,
            'channel':           channel,
            'seq_num':           seq_num,
            'seq_jump':          seq_jump,
            'seq_anomaly_score': round(seq_anomaly_score, 4),
            'beacon_timestamp':  beacon_timestamp,
            'clock_skew':        clock_skew,
            'beacon_interval':   beacon_interval,
            'capabilities':      capabilities,
            'supported_rates':   supported_rates,
            'security':          security,
            'ie_count':          ie_count,
            'label':             0   # 0=Normal  1=Evil Twin
        }

        captured_data.append(data_entry)
        packet_count += 1

        # ── Display on Screen ───────────────────────────
        RED    = "\033[91m"
        YELLOW = "\033[93m"
        GREEN  = "\033[92m"
        RESET  = "\033[0m"

        # Print header every 20 packets
        if packet_count % 20 == 1:
            print("\n" + "="*100)
            print(f"{'#':<5} {'SSID':<22} {'BSSID':<20} {'RSSI':<7}"
                  f"{'CH':<5} {'SEQ':<6} {'JUMP':<7} {'SECURITY':<12}"
                  f"{'IE':<5} {'SKEW'}")
            print("="*100)

        # Color based on suspicion level
        color = (RED    if seq_anomaly_score > 0.5 else
                 YELLOW if seq_anomaly_score > 0.1 else
                 GREEN)

        print(f"{color}"
              f"{packet_count:<5}"
              f"{ssid[:21]:<22}"
              f"{bssid:<20}"
              f"{rssi:<7}"
              f"{channel:<5}"
              f"{seq_num:<6}"
              f"{seq_jump:<7}"
              f"{security:<12}"
              f"{ie_count:<5}"
              f"{clock_skew}"
              f"{RESET}")

        # Auto-save every 50 packets
        if packet_count % 50 == 0:
            save_data()
            print(f"\n  [💾] Auto-saved {packet_count} packets"
                  f" → {OUTPUT_FILE}\n")

    except Exception:
        pass

# ─────────────────────────────────────────────────────
# SAVE DATA TO CSV
# ─────────────────────────────────────────────────────

def save_data():
    """
    Save captured data to CSV file.
    
    CSV file is what our AI model will train on.
    Each row = one beacon frame
    Each column = one feature
    Last column (label) = 0 for normal, 1 for evil twin
    
    We append to existing file so data accumulates
    across multiple runs of the script.
    """
    if captured_data:
        df = pd.DataFrame(captured_data)

        # Create data folder if it doesn't exist
        os.makedirs(
            os.path.dirname(OUTPUT_FILE),
            exist_ok=True
        )

        # Append if file exists, create if not
        if os.path.exists(OUTPUT_FILE):
            df.to_csv(OUTPUT_FILE, mode='a', header=False, index=False)
        else:
            df.to_csv(OUTPUT_FILE, index=False)

        captured_data.clear()
        

# ─────────────────────────────────────────────────────
# GRACEFUL EXIT HANDLER
# ─────────────────────────────────────────────────────

def signal_handler(sig, frame):
    """
    Handles Ctrl+C cleanly.
    Stops channel hopper thread.
    Saves all remaining data before exiting.
    """
    global stop_hopper

    print("\n\n" + "="*55)
    print("  [!] Stopping capture...")
    stop_hopper = True
    time.sleep(1)
    print(f"  [✓] Total packets captured : {packet_count}")
    save_data()
    print(f"  [💾] Data saved to         : {OUTPUT_FILE}")
    print("="*55 + "\n")
    sys.exit(0)

# ─────────────────────────────────────────────────────
# MAIN FUNCTION
# ─────────────────────────────────────────────────────

def main():
    global stop_hopper

    # Register Ctrl+C handler
    signal.signal(signal.SIGINT, signal_handler)

    # ── Startup Banner ──────────────────────────────
    print("\n" + "="*60)
    print("   AI-ENABLED EVIL TWIN DETECTOR")
    print("   Phase 1: Data Collection (Beacon Sniffer) v3")
    print("="*60)
    print(f"  Interface   : {INTERFACE}")
    print(f"  Project Dir : {BASE_DIR}")
    print(f"  Output File : {OUTPUT_FILE}")
    print(f"  Target SSID : {TARGET_SSID or 'ALL Networks'}")
    print(f"  Data Label  : 0 (Normal / Legitimate)")
    print(f"  Channels    : {len(ALL_CHANNELS)} channels")
    print(f"  Hop Interval: {HOP_INTERVAL}s per channel")
    print("="*60)
    print("  Press Ctrl+C to stop and save")
    print("="*60 + "\n")

    # ── Verify Interface ────────────────────────────
    if INTERFACE not in get_if_list():
        print(f"[ERROR] Interface '{INTERFACE}' not found!")
        print(f"Available interfaces: {get_if_list()}")
        print("\nFix: sudo airmon-ng start wlan0")
        sys.exit(1)

    # ── Verify Output Directory ─────────────────────
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    print(f"[✓] Output directory ready: {os.path.dirname(OUTPUT_FILE)}")

    # ── Start Channel Hopper Thread ─────────────────
    hopper_thread = threading.Thread(
        target=channel_hopper,
        daemon=True
    )
    hopper_thread.start()

    # Give hopper time to set first channel
    print("[*] Waiting for channel hopper to initialize...")
    time.sleep(2)

    # ── Start Sniffing ──────────────────────────────
    print(f"[*] Starting packet capture on {INTERFACE}...")
    print("[*] Listening for Wi-Fi beacon frames...\n")

    sniff(
        iface=INTERFACE,
        prn=handle_packet,
        count=MAX_PACKETS or 0,
        store=False
        # NOTE: monitor=True is intentionally removed
        # It causes 0 packets issue in VMware
    )

# ─────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────

if __name__ == "__main__":
    # Must run as root for packet sniffing
    if os.geteuid() != 0:
        print("[ERROR] This script must be run as root!")
        print("Use: sudo python3 sniffer.py")
        sys.exit(1)
    main()

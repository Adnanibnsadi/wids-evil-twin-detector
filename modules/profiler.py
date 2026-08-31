#!/usr/bin/env python3
"""
=======================================================
  profiler.py - Automatic AP Behavior Profiler
=======================================================
  This module automatically learns what a NORMAL
  legitimate AP looks like by observing it for
  a short period of time.

  It builds a "behavioral fingerprint" for each AP
  that includes:
  - Signal strength patterns
  - Sequence number behavior
  - Clock skew signature
  - Beacon timing consistency
  - Information Element fingerprint

  No manual configuration needed.
  Works for ANY network anywhere.
=======================================================
"""

from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap
import pandas as pd
import numpy as np
import json
import os
import sys
import time
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

# ─────────────────────────────────────────────────────
# GLOBAL VARIABLES
# ─────────────────────────────────────────────────────
captured_beacons  = []       # Raw beacon data during profiling
profiling_active  = False    # Is profiling running?
hop_active        = False    # Is channel hopper running?
target_ssid       = None     # SSID we are profiling
target_bssid      = None     # BSSID we are profiling
target_channel    = None     # Channel to lock on

# Sequence and timestamp tracking
seq_tracker       = {}
ts_tracker        = {}

# ─────────────────────────────────────────────────────
# FEATURE EXTRACTION (Same as sniffer but standalone)
# ─────────────────────────────────────────────────────

def extract_features(packet, system_time):
    """
    Extract all features from a single beacon frame.
    Returns a dictionary of features or None if failed.
    """
    try:
        bssid = packet[Dot11].addr2

        try:
            ssid = packet[Dot11Elt].info.decode('utf-8', errors='replace')
        except Exception:
            ssid = "unknown"

        # RSSI
        rssi = 0
        try:
            if packet.haslayer(RadioTap):
                rssi = packet[RadioTap].dBm_AntSignal
        except Exception:
            pass

        # Channel
        channel = 0
        element = packet[Dot11Elt]
        while element:
            if element.ID == 3:
                channel = ord(element.info)
                break
            element = element.payload

        # Supported rates
        rates   = []
        element = packet[Dot11Elt]
        while element:
            if element.ID in [1, 50]:
                for rate in element.info:
                    rates.append((rate & 0x7F) * 0.5)
            element = element.payload
        supported_rates = ",".join(map(str, sorted(set(rates)))) if rates else "unknown"

        # Security
        security  = "Open"
        element   = packet[Dot11Elt]
        has_rsn   = False
        has_wpa   = False
        while element:
            if element.ID == 48:
                has_rsn = True
            if element.ID == 221:
                if element.info[:4] == b'\x00\x50\xf2\x01':
                    has_wpa = True
            element = element.payload
        cap         = packet[Dot11Beacon].cap
        has_privacy = bool(cap & 0x0010)
        if has_rsn:
            security = "WPA2/WPA3"
        elif has_wpa:
            security = "WPA"
        elif has_privacy:
            security = "WEP"

        # Sequence number
        seq_num          = packet[Dot11].SC >> 4
        beacon_timestamp = packet[Dot11Beacon].timestamp
        beacon_interval  = packet[Dot11Beacon].beacon_interval
        capabilities     = packet[Dot11Beacon].cap

        # Sequence jump
        seq_jump      = 0
        anomaly_score = 0.0
        if bssid in seq_tracker and seq_tracker[bssid]:
            last_seq = seq_tracker[bssid][-1]
            if seq_num >= last_seq:
                seq_jump = seq_num - last_seq
            else:
                seq_jump = (4095 - last_seq) + seq_num
            if seq_jump > 100:
                anomaly_score = min(1.0, seq_jump / 1000)
            elif seq_jump > 10:
                anomaly_score = 0.3
        if bssid not in seq_tracker:
            seq_tracker[bssid] = []
        seq_tracker[bssid].append(seq_num)
        if len(seq_tracker[bssid]) > 10:
            seq_tracker[bssid].pop(0)

        # Clock skew
        skew = 0.0
        if bssid not in ts_tracker:
            ts_tracker[bssid] = []
        ts_tracker[bssid].append({
            'beacon_ts': beacon_timestamp,
            'system_ts': system_time
        })
        if len(ts_tracker[bssid]) >= 2:
            first         = ts_tracker[bssid][0]
            last          = ts_tracker[bssid][-1]
            ap_diff       = last['beacon_ts'] - first['beacon_ts']
            sys_diff      = (last['system_ts'] - first['system_ts']) * 1_000_000
            if sys_diff > 0:
                skew = (ap_diff - sys_diff) / sys_diff
        if len(ts_tracker[bssid]) > 20:
            ts_tracker[bssid].pop(0)

        # IE count
        ie_count = 0
        element  = packet[Dot11Elt]
        while element and isinstance(element, Dot11Elt):
            ie_count += 1
            element   = element.payload

        return {
            'timestamp':         time.strftime("%Y-%m-%d %H:%M:%S"),
            'ssid':              ssid,
            'bssid':             bssid,
            'rssi':              rssi,
            'channel':           channel,
            'seq_num':           seq_num,
            'seq_jump':          seq_jump,
            'seq_anomaly_score': round(anomaly_score, 4),
            'beacon_timestamp':  beacon_timestamp,
            'clock_skew':        round(skew, 6),
            'beacon_interval':   beacon_interval,
            'capabilities':      capabilities,
            'supported_rates':   supported_rates,
            'security':          security,
            'ie_count':          ie_count,
            'label':             0    # Normal data
        }

    except Exception:
        return None


# ─────────────────────────────────────────────────────
# PACKET HANDLER
# ─────────────────────────────────────────────────────

def profile_handler(packet):
    """
    Handle packets during profiling phase.
    Only captures beacons from our target network.
    """
    if not packet.haslayer(Dot11Beacon):
        return

    try:
        bssid = packet[Dot11].addr2
        try:
            ssid = packet[Dot11Elt].info.decode('utf-8', errors='replace')
        except Exception:
            ssid = "unknown"

        # Filter: only capture our target network
        if target_bssid and bssid != target_bssid:
            return
        if target_ssid and ssid != target_ssid:
            return

        system_time = time.time()
        features    = extract_features(packet, system_time)

        if features:
            captured_beacons.append(features)
            count = len(captured_beacons)

            # Progress display
            bar_filled = int((count / config.MIN_SAMPLES_NEEDED) * 20)
            bar_filled = min(bar_filled, 20)
            bar        = "█" * bar_filled + "░" * (20 - bar_filled)
            pct        = min(int((count / config.MIN_SAMPLES_NEEDED) * 100), 100)

            print(f"\r  [{bar}] {pct}%  "
                  f"Beacons: {count}  "
                  f"RSSI: {features['rssi']} dBm  "
                  f"Skew: {features['clock_skew']:.6f}    ",
                  end='', flush=True)

    except Exception:
        pass


# ─────────────────────────────────────────────────────
# CHANNEL LOCKER
# ─────────────────────────────────────────────────────

def channel_locker(interface, channel):
    """
    Lock the interface on target channel during profiling.
    Checks every 5 seconds to ensure it stays locked.
    """
    global hop_active
    while hop_active:
        os.system(f"iwconfig {interface} channel {channel} 2>/dev/null")
        time.sleep(5)


# ─────────────────────────────────────────────────────
# BUILD PROFILE
# ─────────────────────────────────────────────────────

def build_profile(network_info):
    """
    Build a statistical behavioral profile for an AP.

    This profile captures the NORMAL behavior of the AP.
    Later, when detecting, we compare live beacons to
    this profile. If behavior deviates too much = ALERT!

    Profile contains:
    - Mean and std of RSSI
    - Mean and std of sequence jumps
    - Mean and std of clock skew
    - Exact IE count (hardware fingerprint)
    - Exact supported rates (hardware fingerprint)
    - Exact beacon interval
    - Exact security type

    Parameters:
        network_info: dict with ssid, bssid, channel

    Returns:
        profile dict or None if failed
    """
    if len(captured_beacons) < 10:
        print(f"\n[ERROR] Not enough beacons captured: {len(captured_beacons)}")
        print("[ERROR] Need at least 10 beacons to build profile")
        return None

    df = pd.DataFrame(captured_beacons)

    # Statistical profile of each feature
    profile = {
        # Identity
        'ssid':    network_info['ssid'],
        'bssid':   network_info['bssid'],
        'channel': network_info['channel'],

        # RSSI statistics
        # Real AP has consistent RSSI from fixed location
        'rssi_mean':  float(df['rssi'].mean()),
        'rssi_std':   float(df['rssi'].std()),
        'rssi_min':   float(df['rssi'].min()),
        'rssi_max':   float(df['rssi'].max()),

        # Sequence number statistics
        # Normal jumps are small (1-5)
        # Large jumps = possible Evil Twin
        'seq_jump_mean': float(df['seq_jump'].mean()),
        'seq_jump_std':  float(df['seq_jump'].std()),
        'seq_jump_max':  float(df['seq_jump'].max()),

        # Clock skew statistics
        # Each hardware has unique clock drift pattern
        'clock_skew_mean': float(df['clock_skew'].mean()),
        'clock_skew_std':  float(df['clock_skew'].std()),

        # Hardware fingerprints (should be EXACT same)
        # If different = definitely different hardware = Evil Twin!
        'ie_count':       int(df['ie_count'].mode()[0]),
        'supported_rates': str(df['supported_rates'].mode()[0]),
        'beacon_interval': int(df['beacon_interval'].mode()[0]),
        'security':        str(df['security'].mode()[0]),
        'capabilities':    int(df['capabilities'].mode()[0]),

        # Metadata
        'total_beacons':  len(df),
        'profile_time':   time.strftime("%Y-%m-%d %H:%M:%S"),
        'raw_data_file':  config.NORMAL_DATA_FILE
    }

    return profile


# ─────────────────────────────────────────────────────
# SAVE PROFILE AND DATA
# ─────────────────────────────────────────────────────

def save_profile(profile):
    """Save AP profile to JSON file."""
    os.makedirs(config.DATA_DIR, exist_ok=True)

    # Load existing profiles
    profiles = {}
    if os.path.exists(config.AP_PROFILES_FILE):
        try:
            with open(config.AP_PROFILES_FILE, 'r') as f:
                profiles = json.load(f)
        except Exception:
            profiles = {}

    # Add/update this network's profile
    # Use BSSID as key (unique identifier)
    profiles[profile['bssid']] = profile

    # Save all profiles
    with open(config.AP_PROFILES_FILE, 'w') as f:
        json.dump(profiles, f, indent=2)

    print(f"\n[✓] Profile saved: {config.AP_PROFILES_FILE}")


def save_normal_data():
    """Save captured beacons to CSV for AI training."""
    if not captured_beacons:
        return

    df = pd.DataFrame(captured_beacons)
    os.makedirs(config.DATA_DIR, exist_ok=True)

    if os.path.exists(config.NORMAL_DATA_FILE):
        df.to_csv(config.NORMAL_DATA_FILE, mode='a',
                  header=False, index=False)
    else:
        df.to_csv(config.NORMAL_DATA_FILE, index=False)

    print(f"[✓] Training data saved: {config.NORMAL_DATA_FILE}")
    print(f"[✓] Total rows saved: {len(df)}")


# ─────────────────────────────────────────────────────
# MAIN PROFILE FUNCTION
# ─────────────────────────────────────────────────────

def profile_network(interface, network_info,
                    duration=config.PROFILE_DURATION):
    """
    Main function to profile a network.

    Automatically:
    1. Locks on correct channel
    2. Captures beacons for specified duration
    3. Builds statistical profile
    4. Saves profile and training data

    Parameters:
        interface    : monitor mode interface
        network_info : dict with ssid, bssid, channel
        duration     : seconds to observe (default 60)

    Returns:
        profile dict or None
    """
    global target_ssid, target_bssid, target_channel
    global hop_active, captured_beacons

    # Reset
    captured_beacons = []
    seq_tracker.clear()
    ts_tracker.clear()

    target_ssid    = network_info['ssid']
    target_bssid   = network_info['bssid']
    target_channel = network_info['channel']

    print("\n" + "="*55)
    print("  BUILDING NETWORK PROFILE")
    print("="*55)
    print(f"  Network : {target_ssid}")
    print(f"  BSSID   : {target_bssid}")
    print(f"  Channel : {target_channel}")
    print(f"  Duration: {duration} seconds")
    print("="*55)
    print("  Observing normal behavior...")
    print("  (Do not simulate any attacks now)\n")

    # Lock on target channel
    hop_active     = True
    locker         = threading.Thread(
                        target=channel_locker,
                        args=(interface, target_channel),
                        daemon=True
                    )
    locker.start()
    time.sleep(1)

    # Capture beacons
    sniff(
        iface=interface,
        prn=profile_handler,
        timeout=duration,
        store=False
    )

    hop_active = False
    print(f"\n\n[✓] Captured {len(captured_beacons)} beacons")

    if len(captured_beacons) < 10:
        print("[ERROR] Too few beacons captured!")
        print(f"[ERROR] Check that '{target_ssid}' is nearby")
        return None

    # Build profile
    print("[*] Building behavioral profile...")
    profile = build_profile(network_info)

    if profile:
        # Print profile summary
        print("\n" + "="*55)
        print("  PROFILE SUMMARY")
        print("="*55)
        print(f"  SSID           : {profile['ssid']}")
        print(f"  BSSID          : {profile['bssid']}")
        print(f"  RSSI range     : {profile['rssi_min']:.0f}"
              f" to {profile['rssi_max']:.0f} dBm")
        print(f"  Avg seq jump   : {profile['seq_jump_mean']:.2f}")
        print(f"  Clock skew avg : {profile['clock_skew_mean']:.6f}")
        print(f"  IE count       : {profile['ie_count']}")
        print(f"  Security       : {profile['security']}")
        print(f"  Beacon interval: {profile['beacon_interval']}")
        print(f"  Beacons seen   : {profile['total_beacons']}")
        print("="*55)

        # Save everything
        save_profile(profile)
        save_normal_data()

    return profile


# ─────────────────────────────────────────────────────
# LOAD EXISTING PROFILES
# ─────────────────────────────────────────────────────

def load_profiles():
    """
    Load previously saved AP profiles.
    This allows the tool to remember networks
    across multiple runs without re-profiling.
    """
    if not os.path.exists(config.AP_PROFILES_FILE):
        return {}

    try:
        with open(config.AP_PROFILES_FILE, 'r') as f:
            profiles = json.load(f)
        print(f"[✓] Loaded {len(profiles)} saved profiles")
        return profiles
    except Exception as e:
        print(f"[!] Could not load profiles: {e}")
        return {}

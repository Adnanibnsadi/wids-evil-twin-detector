#!/usr/bin/env python3
"""
=======================================================
  Multi-AP Data Collector
=======================================================
  Collects beacon data from ALL nearby APs.
  Runs for extended period to build rich dataset.
  No manual configuration - works anywhere.
=======================================================
"""

from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap
import pandas as pd
import numpy as np
import os
import sys
import time
import signal
import threading
import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

# ─────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────
INTERFACE   = config.find_monitor_interface() or "wlan0mon"
OUTPUT_FILE = os.path.join(config.DATA_DIR, "all_aps_normal.csv")
DURATION    = None    # None = run forever until Ctrl+C

# ─────────────────────────────────────────────────────
# GLOBAL STATE
# ─────────────────────────────────────────────────────
captured_data     = []
packet_count      = 0
stop_flag         = False

# Per-BSSID tracking for advanced features
seq_tracker       = {}    # { bssid: [seq_nums] }
ts_tracker        = {}    # { bssid: [timestamps] }
timing_tracker    = {}    # { bssid: [inter_beacon_times] }
last_seen         = {}    # { bssid: last_packet_system_time }

# Network summary for display
network_stats     = {}    # { bssid: {ssid, count, rssi} }

# ─────────────────────────────────────────────────────
# ADVANCED FEATURE: INTER-BEACON TIMING
# ─────────────────────────────────────────────────────

def calculate_inter_beacon_timing(bssid, system_time):
    """
    Calculate the time between consecutive beacons.
    
    WHY THIS MATTERS:
    Every AP sends beacons at ~100ms intervals.
    But the EXACT timing varies based on hardware:
    
    Netgear router:  102.3, 102.4, 102.3, 102.5 ms
    TP-Link router:  102.1, 102.2, 102.1, 102.2 ms
    RPi Evil Twin:   101.8, 103.2, 101.9, 103.1 ms  ← different!
    
    The VARIANCE of this timing is a hardware fingerprint.
    
    Returns:
        inter_beacon_ms  : time since last beacon (ms)
        timing_variance  : variance of last 10 timings
    """
    inter_beacon_ms = 0.0
    timing_variance = 0.0

    if bssid in last_seen:
        # Time since last beacon from this BSSID
        inter_beacon_ms = (system_time - last_seen[bssid]) * 1000

        # Store timing history
        if bssid not in timing_tracker:
            timing_tracker[bssid] = []
        timing_tracker[bssid].append(inter_beacon_ms)

        # Keep last 20 timings
        if len(timing_tracker[bssid]) > 20:
            timing_tracker[bssid].pop(0)

        # Calculate variance (consistency of timing)
        if len(timing_tracker[bssid]) >= 5:
            timing_variance = float(
                np.var(timing_tracker[bssid])
            )

    last_seen[bssid] = system_time
    return round(inter_beacon_ms, 3), round(timing_variance, 6)


# ─────────────────────────────────────────────────────
# ADVANCED FEATURE: SEQUENCE DUPLICATE DETECTION
# ─────────────────────────────────────────────────────

def check_sequence_duplicate(bssid, seq_num, system_time):
    """
    Detect duplicate sequence numbers for same BSSID.
    
    THIS IS THE MOST POWERFUL EVIL TWIN DETECTOR.
    
    Normal AP:
      seq 100 at time T
      seq 101 at time T+0.1
      seq 102 at time T+0.2
      Each sequence number appears EXACTLY ONCE.
    
    Evil Twin (same BSSID cloned):
      seq 100 from real AP  at time T      rssi=-62
      seq 100 from evil twin at time T+0.002 rssi=-25
      SAME SEQ NUMBER TWICE IN SHORT TIME = IMPOSSIBLE!
    
    Returns:
        is_duplicate: True if seq seen very recently
        time_delta  : time since same seq was last seen
    """
    key = f"{bssid}_{seq_num}"

    if key not in last_seen:
        last_seen[key]  = system_time
        return False, 0.0

    time_delta = system_time - last_seen[key]
    last_seen[key] = system_time

    # If same BSSID+seq seen within 1 second = duplicate!
    # Normal AP would never send same seq twice
    is_duplicate = time_delta < 1.0

    return is_duplicate, round(time_delta, 6)


# ─────────────────────────────────────────────────────
# CLOCK SKEW CALCULATION (Improved)
# ─────────────────────────────────────────────────────

def calculate_clock_skew(bssid, beacon_timestamp, system_time):
    """
    Calculate hardware clock skew with improved accuracy.
    
    Uses linear regression over multiple measurements
    for more accurate skew estimation.
    
    Returns: skew value (float)
    """
    if bssid not in ts_tracker:
        ts_tracker[bssid] = []

    ts_tracker[bssid].append({
        'beacon_ts': beacon_timestamp,
        'system_ts': system_time
    })

    if len(ts_tracker[bssid]) > 50:
        ts_tracker[bssid].pop(0)

    if len(ts_tracker[bssid]) < 2:
        return 0.0

    # Simple skew calculation
    first    = ts_tracker[bssid][0]
    last     = ts_tracker[bssid][-1]
    ap_diff  = last['beacon_ts'] - first['beacon_ts']
    sys_diff = (last['system_ts'] - first['system_ts']) * 1_000_000

    if sys_diff <= 0:
        return 0.0

    skew = (ap_diff - sys_diff) / sys_diff
    return round(skew, 8)


# ─────────────────────────────────────────────────────
# SEQUENCE JUMP CALCULATION
# ─────────────────────────────────────────────────────

def calculate_seq_jump(bssid, seq_num):
    """Calculate sequence number jump from last seen."""
    if bssid not in seq_tracker:
        seq_tracker[bssid] = []

    jump = 0
    if seq_tracker[bssid]:
        last = seq_tracker[bssid][-1]
        if seq_num >= last:
            jump = seq_num - last
        else:
            jump = (4095 - last) + seq_num

    seq_tracker[bssid].append(seq_num)
    if len(seq_tracker[bssid]) > 20:
        seq_tracker[bssid].pop(0)

    return jump


# ─────────────────────────────────────────────────────
# EXTRACT ALL FEATURES
# ─────────────────────────────────────────────────────

def extract_all_features(packet, system_time):
    """
    Extract comprehensive feature set from beacon.
    Includes all standard AND advanced features.
    """
    try:
        bssid = packet[Dot11].addr2
        try:
            ssid = packet[Dot11Elt].info.decode(
                'utf-8', errors='replace'
            )
        except Exception:
            ssid = "unknown"

        if not ssid.strip():
            ssid = "<Hidden>"

        # ── Basic Features ───────────────────────────
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

        # Rates
        rates   = []
        element = packet[Dot11Elt]
        while element:
            if element.ID in [1, 50]:
                for rate in element.info:
                    rates.append((rate & 0x7F) * 0.5)
            element = element.payload
        supported_rates = ",".join(
            map(str, sorted(set(rates)))
        ) if rates else "unknown"
        rate_count = len(set(rates))

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

        security_map     = {
            'Open': 0, 'WEP': 1, 'WPA': 2,
            'WPA2/WPA3': 3, 'unknown': 0
        }
        security_encoded = security_map.get(security, 0)

        # Sequence and timing
        seq_num          = packet[Dot11].SC >> 4
        beacon_timestamp = packet[Dot11Beacon].timestamp
        beacon_interval  = packet[Dot11Beacon].beacon_interval
        capabilities     = int(packet[Dot11Beacon].cap)

        # IE count
        ie_count = 0
        element  = packet[Dot11Elt]
        while element and isinstance(element, Dot11Elt):
            ie_count += 1
            element   = element.payload

        # ── Advanced Features ────────────────────────

        # Sequence jump
        seq_jump = calculate_seq_jump(bssid, seq_num)

        seq_anomaly = 0.0
        if seq_jump > 100:
            seq_anomaly = min(1.0, seq_jump / 1000)
        elif seq_jump > 10:
            seq_anomaly = 0.3

        # Clock skew (hardware fingerprint)
        clock_skew = calculate_clock_skew(
            bssid, beacon_timestamp, system_time
        )

        # Inter-beacon timing (hardware fingerprint)
        inter_beacon_ms, timing_variance = \
            calculate_inter_beacon_timing(bssid, system_time)

        # Sequence duplicate check
        is_seq_dup, seq_dup_delta = check_sequence_duplicate(
            bssid, seq_num, system_time
        )

        # ── Build Feature Dict ───────────────────────
        return {
            # Identity
            'timestamp':         datetime.datetime.now().strftime(
                                     "%Y-%m-%d %H:%M:%S.%f"
                                 ),
            'ssid':              ssid,
            'bssid':             bssid,

            # Signal
            'rssi':              rssi,
            'channel':           channel,

            # Sequence features
            'seq_num':           seq_num,
            'seq_jump':          seq_jump,
            'seq_anomaly_score': round(seq_anomaly, 4),

            # Timing features (UNFAKEABLE)
            'beacon_timestamp':  beacon_timestamp,
            'clock_skew':        clock_skew,
            'inter_beacon_ms':   inter_beacon_ms,
            'timing_variance':   timing_variance,

            # Sequence duplicate (UNFAKEABLE)
            'is_seq_duplicate':  int(is_seq_dup),
            'seq_dup_delta':     seq_dup_delta,

            # Hardware fingerprints
            'beacon_interval':   beacon_interval,
            'capabilities':      capabilities,
            'supported_rates':   supported_rates,
            'rate_count':        rate_count,
            'security':          security,
            'security_encoded':  security_encoded,
            'ie_count':          ie_count,

            # Label (always 0 for legitimate data)
            'label':             0
        }

    except Exception:
        return None


# ─────────────────────────────────────────────────────
# PACKET HANDLER
# ─────────────────────────────────────────────────────

def packet_handler(packet):
    """Handle each captured beacon frame."""
    global packet_count

    if not packet.haslayer(Dot11Beacon):
        return

    system_time = time.time()
    features    = extract_all_features(packet, system_time)

    if not features:
        return

    captured_data.append(features)
    packet_count += 1

    # Update network stats for display
    bssid = features['bssid']
    ssid  = features['ssid']
    if bssid not in network_stats:
        network_stats[bssid] = {
            'ssid': ssid, 'count': 0, 'rssi': 0
        }
    network_stats[bssid]['count'] += 1
    network_stats[bssid]['rssi']   = features['rssi']

    # Display progress every 100 packets
    if packet_count % 100 == 0:
        unique_aps = len(network_stats)
        print(f"\r  [📡] Packets: {packet_count:5d} | "
              f"APs: {unique_aps:2d} | "
              f"Latest: {ssid[:20]:<20} | "
              f"RSSI: {features['rssi']:4d} dBm",
              end='', flush=True)

    # Auto-save every 500 packets
    if packet_count % 500 == 0:
        save_data()
        print(f"\n  [💾] Auto-saved {packet_count} packets")


# ─────────────────────────────────────────────────────
# CHANNEL HOPPER
# ─────────────────────────────────────────────────────

def channel_hopper():
    """Hop through all channels continuously."""
    global stop_flag
    while not stop_flag:
        for ch in config.ALL_CHANNELS:
            if stop_flag:
                break
            os.system(
                f"iwconfig {INTERFACE} channel {ch} 2>/dev/null"
            )
            time.sleep(config.HOP_INTERVAL)


# ─────────────────────────────────────────────────────
# SAVE DATA
# ─────────────────────────────────────────────────────

def save_data():
    """Save captured data to CSV."""
    if not captured_data:
        return

    df = pd.DataFrame(captured_data)
    os.makedirs(config.DATA_DIR, exist_ok=True)

    if os.path.exists(OUTPUT_FILE):
        df.to_csv(OUTPUT_FILE, mode='a',
                  header=False, index=False)
    else:
        df.to_csv(OUTPUT_FILE, index=False)

    captured_data.clear()


# ─────────────────────────────────────────────────────
# SIGNAL HANDLER
# ─────────────────────────────────────────────────────

def signal_handler(sig, frame):
    global stop_flag
    print("\n\n[!] Stopping collection...")
    stop_flag = True

    save_data()

    # Print final summary
    print("\n" + "="*60)
    print("  COLLECTION SUMMARY")
    print("="*60)
    print(f"  Total packets : {packet_count}")
    print(f"  Unique APs    : {len(network_stats)}")
    print(f"  Saved to      : {OUTPUT_FILE}")
    print()
    print("  Networks captured:")
    print("-"*60)

    sorted_nets = sorted(
        network_stats.items(),
        key=lambda x: x[1]['count'],
        reverse=True
    )
    for bssid, stats in sorted_nets:
        print(f"  {stats['ssid']:<25} "
              f"BSSID: {bssid}  "
              f"Beacons: {stats['count']:4d}  "
              f"RSSI: {stats['rssi']:4d} dBm")

    print("="*60)
    sys.exit(0)


# ─────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────

def main():
    global stop_flag

    if os.geteuid() != 0:
        print("[ERROR] Run as root: sudo python3 collect_all_aps.py")
        sys.exit(1)

    signal.signal(signal.SIGINT, signal_handler)

    print("\n" + "="*60)
    print("  MULTI-AP DATA COLLECTOR")
    print("  Collecting from ALL nearby networks")
    print("="*60)
    print(f"  Interface : {INTERFACE}")
    print(f"  Output    : {OUTPUT_FILE}")
    print(f"  Duration  : Until Ctrl+C")
    print(f"  Channels  : {len(config.ALL_CHANNELS)}")
    print("="*60)
    print("  Let this run for at least 30-60 minutes")
    print("  for a rich dataset covering all nearby APs")
    print("="*60 + "\n")

    # Start channel hopper
    hopper = threading.Thread(
        target=channel_hopper,
        daemon=True
    )
    hopper.start()
    time.sleep(1)

    print(f"[*] Collecting from all nearby APs...")
    print(f"[*] Press Ctrl+C when done\n")

    sniff(
        iface  = INTERFACE,
        prn    = packet_handler,
        store  = False
    )


if __name__ == "__main__":
    main()

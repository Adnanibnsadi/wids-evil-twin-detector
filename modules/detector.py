#!/usr/bin/env python3
"""
=======================================================
  modules/detector.py - Calibrated AI Evil Twin Detector
=======================================================
  Calibrated for real-world RF environments & VMware.
  Includes jitter filtering and multi-frame confirmation.
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
import datetime
import joblib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

# ─────────────────────────────────────────────────────
# GLOBAL STATE
# ─────────────────────────────────────────────────────
detection_running  = False
hop_running        = False
packet_count       = 0
alert_count        = 0

# Loaded models and profiles
bssid_profiles     = {}
per_bssid_bundle   = {}
global_bundle      = {}

# Dynamic trackers
seq_tracker        = {}
ts_tracker         = {}
last_seen_seq      = {}  # { "bssid_seq": system_time }
last_seen_bssid    = {}  # { bssid: system_time }
alert_cooldown     = {}  # { bssid: last_alert_time }
suspicious_streak  = {}  # { bssid: count_of_consecutive_suspicious_frames }

ALERT_COOLDOWN_SEC = 10
REQUIRED_STREAK    = 2   # Require 2 consecutive suspicious frames to confirm

# ─────────────────────────────────────────────────────
# RESOURCE LOADER
# ─────────────────────────────────────────────────────

def load_resources():
    global bssid_profiles, per_bssid_bundle, global_bundle
    
    if os.path.exists(config.BSSID_PROFILES_FILE):
        with open(config.BSSID_PROFILES_FILE, 'r') as f:
            bssid_profiles = json.load(f)
        print(f"[✓] Loaded {len(bssid_profiles)} AP profiles from bssid_profiles.json")
    else:
        print(f"[ERROR] Profiles not found at {config.BSSID_PROFILES_FILE}")
        return False
        
    per_bssid_path = os.path.join(config.MODELS_DIR, 'per_bssid_models.pkl')
    if os.path.exists(per_bssid_path):
        per_bssid_bundle = joblib.load(per_bssid_path)
        print(f"[✓] Loaded {len(per_bssid_bundle['models'])} Per-BSSID AI models")
    else:
        print(f"[ERROR] Per-BSSID models not found at {per_bssid_path}")
        return False
        
    global_path = os.path.join(config.MODELS_DIR, 'global_model.pkl')
    if os.path.exists(global_path):
        global_bundle = joblib.load(global_path)
        print(f"[✓] Loaded Global Anomaly AI model")
    else:
        print(f"[ERROR] Global model not found at {global_path}")
        return False
        
    return True

# ─────────────────────────────────────────────────────
# FEATURE EXTRACTION (WITH JITTER FILTER)
# ─────────────────────────────────────────────────────

def extract_features(packet, system_time):
    try:
        bssid = packet[Dot11].addr2.lower()
        
        try:
            ssid = packet[Dot11Elt].info.decode('utf-8', errors='replace')
        except Exception:
            ssid = "<Hidden>"
        if not ssid.strip():
            ssid = "<Hidden>"
            
        rssi = 0
        if packet.haslayer(RadioTap):
            try:
                rssi = packet[RadioTap].dBm_AntSignal
            except Exception:
                pass
                
        channel = 0
        element = packet[Dot11Elt]
        while element:
            if element.ID == 3:
                channel = ord(element.info)
                break
            element = element.payload
            
        rates = []
        element = packet[Dot11Elt]
        while element:
            if element.ID in [1, 50]:
                for rate in element.info:
                    rates.append((rate & 0x7F) * 0.5)
            element = element.payload
        rate_count = len(set(rates))
        
        # Security
        security = "Open"
        has_rsn, has_wpa = False, False
        element = packet[Dot11Elt]
        while element:
            if element.ID == 48:
                has_rsn = True
            if element.ID == 221 and element.info[:4] == b'\x00\x50\xf2\x01':
                has_wpa = True
            element = element.payload
        cap = packet[Dot11Beacon].cap
        if has_rsn:
            security = "WPA2/WPA3"
        elif has_wpa:
            security = "WPA"
        elif bool(cap & 0x0010):
            security = "WEP"
            
        sec_map = {'Open': 0, 'WEP': 1, 'WPA': 2, 'WPA2/WPA3': 3}
        security_encoded = sec_map.get(security, 0)
        
        seq_num = packet[Dot11].SC >> 4
        beacon_ts = packet[Dot11Beacon].timestamp
        beacon_int = packet[Dot11Beacon].beacon_interval
        capabilities = int(cap)
        
        ie_count = 0
        element = packet[Dot11Elt]
        while element and isinstance(element, Dot11Elt):
            ie_count += 1
            element = element.payload
            
        # Sequence Jump
        seq_jump = 0
        if bssid in seq_tracker and seq_tracker[bssid]:
            last_seq = seq_tracker[bssid][-1]
            if seq_num >= last_seq:
                seq_jump = seq_num - last_seq
            else:
                seq_jump = (4095 - last_seq) + seq_num
        if bssid not in seq_tracker:
            seq_tracker[bssid] = []
        seq_tracker[bssid].append(seq_num)
        if len(seq_tracker[bssid]) > 20:
            seq_tracker[bssid].pop(0)
            
        seq_anomaly_score = min(1.0, seq_jump / 1000) if seq_jump > 100 else 0.0
        
        # ── STABILIZED CLOCK SKEW CALCULATION ────────
        # Only compute skew if consecutive frames arrived in tight timing window (<250ms)
        skew = 0.0
        valid_skew = False
        
        if bssid not in ts_tracker:
            ts_tracker[bssid] = []
            
        ts_tracker[bssid].append({'beacon_ts': beacon_ts, 'sys_ts': system_time})
        if len(ts_tracker[bssid]) > 20:
            ts_tracker[bssid].pop(0)
            
        if len(ts_tracker[bssid]) >= 2:
            prev = ts_tracker[bssid][-2]
            curr = ts_tracker[bssid][-1]
            time_gap = curr['sys_ts'] - prev['sys_ts']
            
            # If frames arrived within 250ms (no channel hop interruption)
            if 0.05 <= time_gap <= 0.25:
                ap_diff = curr['beacon_ts'] - prev['beacon_ts']
                sys_diff = time_gap * 1_000_000
                if sys_diff > 0:
                    skew = (ap_diff - sys_diff) / sys_diff
                    valid_skew = True
                
        # Inter-beacon timing
        inter_beacon_ms = 0.0
        if bssid in last_seen_bssid:
            inter_beacon_ms = (system_time - last_seen_bssid[bssid]) * 1000
        last_seen_bssid[bssid] = system_time
        
        # Duplicate sequence check (Simultaneous presence)
        dup_key = f"{bssid}_{seq_num}"
        is_seq_dup = 0
        if dup_key in last_seen_seq:
            # If the EXACT same sequence number was seen from this BSSID within 500ms
            if 0.001 < (system_time - last_seen_seq[dup_key]) < 0.5:
                is_seq_dup = 1
        last_seen_seq[dup_key] = system_time
        
        return {
            'ssid': ssid, 'bssid': bssid, 'rssi': rssi, 'channel': channel,
            'seq_num': seq_num, 'seq_jump': seq_jump, 'seq_anomaly_score': round(seq_anomaly_score, 4),
            'beacon_timestamp': beacon_ts, 'clock_skew': round(skew, 8), 'valid_skew': valid_skew,
            'beacon_interval': beacon_int, 'capabilities': capabilities,
            'security': security, 'security_encoded': security_encoded,
            'ie_count': ie_count, 'rate_count': rate_count,
            'inter_beacon_ms': inter_beacon_ms, 'is_seq_duplicate': is_seq_dup
        }
    except Exception:
        return None

# ─────────────────────────────────────────────────────
# CALIBRATED MULTI-LAYER EVALUATOR
# ─────────────────────────────────────────────────────

def evaluate_packet(feat):
    bssid = feat['bssid']
    ssid = feat['ssid']
    
    matched_profile = None
    target_bssid = None
    
    # 1. Profile Lookup
    if bssid in bssid_profiles:
        matched_profile = bssid_profiles[bssid]
        target_bssid = bssid
    else:
        # Check if an attacker is broadcasting a known SSID on a fake MAC
        for pb, prof in bssid_profiles.items():
            if prof['ssid'].lower() == ssid.lower() and ssid != "<Hidden>":
                matched_profile = prof
                target_bssid = pb
                break
                
    if not matched_profile:
        return False, [], 0.0  # Unprofiled network

    threat_reasons = []
    hard_evidence_count = 0
    threat_score = 0.0

    # ── HARD EVIDENCE 1: Simultaneous Presence / Duplicate Sequence ──
    if feat['is_seq_duplicate'] == 1:
        threat_score += 0.90
        hard_evidence_count += 1
        threat_reasons.append(f"CRITICAL: Duplicate sequence number ({feat['seq_num']}) seen simultaneously. Two transmitters are using this BSSID.")

    # ── HARD EVIDENCE 2: Rogue MAC with Cloned SSID ──────────────────
    if bssid != target_bssid:
        threat_score += 0.85
        hard_evidence_count += 1
        threat_reasons.append(f"Rogue BSSID: Spoofing SSID '{ssid}' using unregistered MAC {bssid} (Legitimate: {target_bssid})")

    # ── HARD EVIDENCE 3: Major Structural IE Discrepancy ────────────
    # Allow tolerance of ±2 for normal router dynamic updates
    ie_diff = abs(feat['ie_count'] - matched_profile['ie_count'])
    if ie_diff >= 3:
        threat_score += 0.70
        hard_evidence_count += 1
        threat_reasons.append(f"Hardware IE Structural Mismatch: Transmitted {feat['ie_count']} IEs (Baseline: {matched_profile['ie_count']}, Δ={ie_diff})")

    # ── HARD EVIDENCE 4: Security Alteration ─────────────────────────
    if feat['security'] != matched_profile['security']:
        threat_score += 0.60
        hard_evidence_count += 1
        threat_reasons.append(f"Security Protocol Alteration: {feat['security']} (Baseline: {matched_profile['security']})")

    # ── SOFT EVIDENCE 1: Chipset Rate Set ────────────────────────────
    if abs(feat['rate_count'] - matched_profile['rate_count']) >= 3:
        threat_score += 0.30
        threat_reasons.append(f"Chipset Rate Discrepancy: {feat['rate_count']} rates (Baseline: {matched_profile['rate_count']})")

    # ── SOFT EVIDENCE 2: Validated Clock Skew Drift ──────────────────
    if feat['valid_skew'] and matched_profile['clock_skew_std'] > 0:
        z_skew = abs(feat['clock_skew'] - matched_profile['clock_skew_mean']) / matched_profile['clock_skew_std']
        # Only evaluate if we have a stable measurement
        if z_skew > 10.0 and abs(feat['clock_skew']) > 0.0005:
            threat_score += 0.35
            threat_reasons.append(f"Hardware Clock Drift: Skew {feat['clock_skew']:.6f} deviates from physical crystal profile ({z_skew:.1f}σ)")

    # ── SOFT EVIDENCE 3: Per-BSSID ML Model ──────────────────────────
    if target_bssid in per_bssid_bundle['models'] and feat['valid_skew']:
        model = per_bssid_bundle['models'][target_bssid]
        scaler = per_bssid_bundle['scalers'][target_bssid]
        features_order = per_bssid_bundle['features']
        
        X_raw = np.array([[feat.get(f, 0.0) for f in features_order]])
        X_scaled = scaler.transform(X_raw)
        
        ml_score = model.decision_function(X_scaled)[0]
        # Only flag if heavily anomalous
        if ml_score < -0.12:
            threat_score += 0.25
            threat_reasons.append(f"Per-BSSID AI Anomaly: Deviation score {ml_score:.3f}")

    # DECISION LOGIC:
    # Must have either at least 1 piece of HARD evidence OR threat_score >= 0.75
    is_suspicious = (hard_evidence_count >= 1) or (threat_score >= 0.75)
    
    return is_suspicious, threat_reasons, min(1.0, threat_score)

# ─────────────────────────────────────────────────────
# ALERT DISPATCHER (WITH MULTI-FRAME CONFIRMATION)
# ─────────────────────────────────────────────────────

def handle_detection(feat, is_suspicious, reasons, confidence):
    global alert_count
    bssid = feat['bssid']
    now = time.time()
    
    if is_suspicious:
        suspicious_streak[bssid] = suspicious_streak.get(bssid, 0) + 1
        
        # Check if confirmed across multiple frames
        if suspicious_streak[bssid] >= REQUIRED_STREAK:
            if bssid in alert_cooldown and (now - alert_cooldown[bssid]) < ALERT_COOLDOWN_SEC:
                return
                
            alert_cooldown[bssid] = now
            alert_count += 1
            
            RED    = "\033[91m"
            YELLOW = "\033[93m"
            BOLD   = "\033[1m"
            RESET  = "\033[0m"
            
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            print("\n" + f"{RED}{'='*70}{RESET}")
            print(f"{RED}{BOLD}  🚨 [ALERT #{alert_count}] EVIL TWIN ATTACK CONFIRMED! 🚨{RESET}")
            print(f"{RED}{'='*70}{RESET}")
            print(f"  {BOLD}Timestamp   :{RESET} {timestamp}")
            print(f"  {BOLD}Target SSID :{RESET} {feat['ssid']}")
            print(f"  {BOLD}Rogue BSSID :{RESET} {feat['bssid']}")
            print(f"  {BOLD}Channel     :{RESET} {feat['channel']} | {BOLD}RSSI:{RESET} {feat['rssi']} dBm")
            print(f"  {BOLD}AI Confidence Score :{RESET} {RED}{confidence*100:.1f}%{RESET}")
            print(f"{YELLOW}{'-'*70}{RESET}")
            print(f"  {BOLD}Confirmed Forensic Evidence:{RESET}")
            for idx, reason in enumerate(reasons, 1):
                print(f"   {RED}[{idx}]{RESET} {reason}")
            print(f"{RED}{'='*70}{RESET}\n")
            
            os.makedirs(config.LOGS_DIR, exist_ok=True)
            with open(config.ALERT_LOG_FILE, 'a') as f:
                f.write(f"[{timestamp}] ALERT #{alert_count} | SSID: {feat['ssid']} | BSSID: {feat['bssid']} | Score: {confidence*100:.1f}%\n")
                for r in reasons:
                    f.write(f"  - {r}\n")
                f.write("\n")
    else:
        # Reset streak if frame is clean
        suspicious_streak[bssid] = 0

# ─────────────────────────────────────────────────────
# PACKET CONSUMER & HOPPER
# ─────────────────────────────────────────────────────

def packet_consumer(packet):
    global packet_count
    
    if not packet.haslayer(Dot11Beacon):
        return
        
    feat = extract_features(packet, time.time())
    if not feat:
        return
        
    packet_count += 1
    
    is_suspicious, reasons, confidence = evaluate_packet(feat)
    handle_detection(feat, is_suspicious, reasons, confidence)
    
    if not is_suspicious and packet_count % 20 == 0:
        print(f"\r  [🛡️ Active Monitor] Packets: {packet_count:5d} | Alerts: {alert_count:2d} | Validating: {feat['ssid'][:18]:<18} ({feat['bssid']})", end='', flush=True)

def channel_cycler(interface, locked_channel=None):
    global hop_running
    if locked_channel:
        os.system(f"iwconfig {interface} channel {locked_channel} 2>/dev/null")
        while hop_running:
            time.sleep(5)
    else:
        while hop_running:
            for ch in config.ALL_CHANNELS:
                if not hop_running:
                    break
                os.system(f"iwconfig {interface} channel {ch} 2>/dev/null")
                time.sleep(config.HOP_INTERVAL)

# ─────────────────────────────────────────────────────
# ENTRYPOINT
# ─────────────────────────────────────────────────────

def start_detection(interface, target_network=None):
    global detection_running, hop_running, packet_count, alert_count, suspicious_streak
    
    packet_count = 0
    alert_count = 0
    suspicious_streak.clear()
    
    print("\n[*] Initializing Detection Engine & Loading Models...")
    if not load_resources():
        return
        
    locked_ch = target_network.get('channel') if target_network else None
    
    print("\n" + "="*70)
    print("  🛡️  AI-ENABLED ROGUE AP & EVIL TWIN REAL-TIME DEFENSE")
    print("="*70)
    print(f"  Interface      : {interface}")
    print(f"  Protected Base : {len(bssid_profiles)} AP Fingerprints")
    print(f"  Channel Mode   : {'Locked on CH ' + str(locked_ch) if locked_ch else 'Channel Hopping (All BSSIDs)'}")
    print(f"  Alert Log      : {config.ALERT_LOG_FILE}")
    print("="*70)
    print("  Listening for 802.11 Beacon frames... Press Ctrl+C to halt.\n")
    
    hop_running = True
    hopper = threading.Thread(target=channel_cycler, args=(interface, locked_ch), daemon=True)
    hopper.start()
    
    detection_running = True
    try:
        sniff(iface=interface, prn=packet_consumer, store=False)
    except KeyboardInterrupt:
        pass
    finally:
        hop_running = False
        detection_running = False
        print(f"\n\n{'='*70}")
        print("  DETECTION AUDIT FINISHED")
        print(f"  Total Packets Evaluated: {packet_count}")
        print(f"  Attacks Intercepted    : {alert_count}")
        print(f"  Log File               : {config.ALERT_LOG_FILE}")
        print(f"{'='*70}\n")

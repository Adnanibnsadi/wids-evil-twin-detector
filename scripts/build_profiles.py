#!/usr/bin/env python3
"""
=======================================================
  build_profiles.py
  
  Builds a detailed behavioral profile for every
  AP seen in our collected dataset.
  
  Each profile contains:
  - Clock skew fingerprint (unfakeable)
  - IE count (hardware fingerprint)
  - Rate count (chipset fingerprint)
  - RSSI statistics
  - Sequence behavior
  - Timing statistics
  
  These profiles are used during detection to
  identify Evil Twins even when they perfectly
  clone SSID, BSSID and all visible parameters.
=======================================================
"""

import pandas as pd
import numpy as np
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

def is_randomized_mac(bssid):
    """
    Detect if a MAC address is randomized/locally administered.
    
    IEEE standard: if bit 1 of first octet is set = local MAC
    In hex: second digit is 2, 6, A, or E = randomized
    
    Real routers: globally unique MACs (manufacturer assigned)
    Phones/VMs:   often use randomized MACs
    Attackers:    might accidentally use randomized MAC
    
    Examples:
      6c:14:6e  → 6 = 0110, bit1=1 → RANDOMIZED ⚠️
      b4:0f:3b  → b = 1011, bit1=0 → GLOBAL ✅
      2a:53:4e  → 2 = 0010, bit1=1 → RANDOMIZED ⚠️
    """
    try:
        first_octet = int(bssid.split(':')[0], 16)
        # Check bit 1 (second least significant bit)
        is_local = bool(first_octet & 0x02)
        return is_local
    except Exception:
        return False

def get_vendor(bssid, vendor_db):
    """Look up vendor from MAC OUI (first 3 octets)."""
    oui = ':'.join(bssid.split(':')[:3]).lower()
    return vendor_db.get('vendor_oui', {}).get(oui, 'Unknown')


def build_bssid_profiles(df):
    """
    Build a behavioral profile for each unique BSSID.
    
    For each AP we calculate:
    
    HARD FINGERPRINTS (should never change):
      - ie_count      : always exact same for same hardware
      - rate_count    : always exact same for same chipset
      - security      : should not change
      - capabilities  : hardware capability flags
    
    SOFT FINGERPRINTS (statistical patterns):
      - clock_skew    : mean and std of hardware clock drift
      - rssi          : signal strength statistics
      - seq_jump      : sequence number jump behavior
    
    TIMING FINGERPRINTS:
      - beacon_interval: advertised interval
    """
    profiles = {}
    
    print("\n" + "="*65)
    print("  BUILDING BSSID BEHAVIORAL PROFILES")
    print("="*65)
    
    # Group data by BSSID
    grouped = df.groupby('bssid')
    
    for bssid, group in grouped:
        ssid     = group['ssid'].mode()[0]
        n        = len(group)
        
        # Skip APs with too few beacons
        if n < 10:
            print(f"  ⚠️  Skipping {ssid} ({bssid}) - only {n} beacons")
            continue
        
        # ── Hard Fingerprints ──────────────────────────
        ie_count    = int(group['ie_count'].mode()[0])
        rate_count  = int(group['rate_count'].mode()[0])
        security    = str(group['security'].mode()[0])
        capabilities = int(group['capabilities'].mode()[0])
        channel     = int(group['channel'].mode()[0])
        beacon_interval = int(group['beacon_interval'].mode()[0])
        supported_rates = str(group['supported_rates'].mode()[0])
        
        # ── Clock Skew Fingerprint ─────────────────────
        # Remove outliers using IQR method
        skew_data = group['clock_skew'].dropna()
        if len(skew_data) > 10:
            Q1          = skew_data.quantile(0.25)
            Q3          = skew_data.quantile(0.75)
            IQR         = Q3 - Q1
            skew_clean  = skew_data[
                (skew_data >= Q1 - 1.5*IQR) &
                (skew_data <= Q3 + 1.5*IQR)
            ]
        else:
            skew_clean = skew_data
        
        clock_skew_mean = float(skew_clean.mean()) if len(skew_clean) > 0 else 0.0
        clock_skew_std  = float(skew_clean.std())  if len(skew_clean) > 1 else 0.0
        clock_skew_min  = float(skew_clean.min())  if len(skew_clean) > 0 else 0.0
        clock_skew_max  = float(skew_clean.max())  if len(skew_clean) > 0 else 0.0
        
        # ── RSSI Statistics ────────────────────────────
        rssi_mean = float(group['rssi'].mean())
        rssi_std  = float(group['rssi'].std())
        rssi_min  = float(group['rssi'].min())
        rssi_max  = float(group['rssi'].max())
        
        # ── Sequence Jump Statistics ───────────────────
        seq_jumps = group['seq_jump']
        # Normal jumps (exclude large misses due to hopping)
        normal_jumps   = seq_jumps[seq_jumps < 100]
        seq_jump_mean  = float(normal_jumps.mean()) if len(normal_jumps) > 0 else 0.0
        seq_jump_std   = float(normal_jumps.std())  if len(normal_jumps) > 1 else 0.0
        
        # ── Build Profile ──────────────────────────────
        profile = {
            # Identity
            'ssid':              ssid,
            'bssid':             bssid,
            
            # Hard fingerprints
            'ie_count':          ie_count,
            'rate_count':        rate_count,
            'security':          security,
            'capabilities':      capabilities,
            'channel':           channel,
            'beacon_interval':   beacon_interval,
            'supported_rates':   supported_rates,
            
            # Clock skew fingerprint
            'clock_skew_mean':   clock_skew_mean,
            'clock_skew_std':    clock_skew_std,
            'clock_skew_min':    clock_skew_min,
            'clock_skew_max':    clock_skew_max,
            
            # RSSI statistics
            'rssi_mean':         rssi_mean,
            'rssi_std':          rssi_std,
            'rssi_min':          rssi_min,
            'rssi_max':          rssi_max,
            
            # Sequence behavior
            'seq_jump_mean':     seq_jump_mean,
            'seq_jump_std':      seq_jump_std,
            
            # Metadata
            'total_beacons':     n,
            'profile_built':     pd.Timestamp.now().strftime(
                                     "%Y-%m-%d %H:%M:%S"
                                 )
        }
        
        profiles[bssid] = profile
        
        # Display profile summary
        print(f"\n  ✅ {ssid} ({bssid})")
        print(f"     Beacons    : {n}")
        print(f"     IE Count   : {ie_count}  (exact fingerprint)")
        print(f"     Rate Count : {rate_count}  (chipset fingerprint)")
        print(f"     Clock Skew : {clock_skew_mean:.8f} "
              f"± {clock_skew_std:.8f}")
        print(f"     RSSI Range : {rssi_min:.1f} to {rssi_max:.1f} dBm")
        print(f"     Channel    : {channel}")
        print(f"     Security   : {security}")
    
    return profiles


def main():
    print("\n" + "="*65)
    print("  BSSID PROFILE BUILDER")
    print("="*65)
    
    # Load collected data
    if not os.path.exists(config.ALL_APS_DATA_FILE):
        print(f"[ERROR] Data file not found: {config.ALL_APS_DATA_FILE}")
        print("[ERROR] Run collect_all_aps.py first")
        sys.exit(1)
    
    print(f"[*] Loading data from: {config.ALL_APS_DATA_FILE}")
    df = pd.read_csv(config.ALL_APS_DATA_FILE)
    
    # Clean data
    df = df[df['ssid'] != 'ssid']  # Remove duplicate headers
    
    # Convert numeric columns
    numeric_cols = [
        'rssi', 'channel', 'seq_jump', 'clock_skew',
        'inter_beacon_ms', 'timing_variance', 'ie_count',
        'rate_count', 'capabilities', 'beacon_interval'
    ]
    for col in numeric_cols:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce')
    
    print(f"[✓] Loaded {len(df):,} rows")
    print(f"[✓] Unique APs: {df['bssid'].nunique()}")
    
    # Build profiles
    profiles = build_bssid_profiles(df)
    
    # Save profiles
    os.makedirs(config.DATA_DIR, exist_ok=True)
    with open(config.BSSID_PROFILES_FILE, 'w') as f:
        json.dump(profiles, f, indent=2)
    
    print("\n" + "="*65)
    print("  PROFILE BUILDING COMPLETE")
    print("="*65)
    print(f"  Profiles built : {len(profiles)}")
    print(f"  Saved to       : {config.BSSID_PROFILES_FILE}")
    print()
    
    # Summary table
    print(f"  {'SSID':<25} {'IE':>4} {'Rates':>6} "
          f"{'Clock Skew Mean':>18} {'Beacons':>8}")
    print("-"*65)
    for bssid, p in sorted(
        profiles.items(),
        key=lambda x: x[1]['total_beacons'],
        reverse=True
    ):
        print(f"  {p['ssid'][:24]:<25} "
              f"{p['ie_count']:>4} "
              f"{p['rate_count']:>6} "
              f"{p['clock_skew_mean']:>18.8f} "
              f"{p['total_beacons']:>8}")
    print("="*65)
    print()
    print("  ✅ Profiles ready for AI training and detection!")
    print("  Next step: Run build_advanced_model.py")


if __name__ == "__main__":
    main()

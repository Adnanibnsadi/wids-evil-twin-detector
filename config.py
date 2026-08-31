#!/usr/bin/env python3
"""
=======================================================
  config.py - Smart Auto-Configuration
=======================================================
  This file automatically configures the tool
  based on the system it is running on.
  
  NO HARDCODED VALUES.
  Everything is detected automatically.
=======================================================
"""

import os
import sys
import subprocess

# ─────────────────────────────────────────────────────
# AUTO-DETECT PROJECT PATHS
# ─────────────────────────────────────────────────────

def get_project_root():
    """
    Resolve the project root as the directory that contains this file.

    Works regardless of:
    - Username
    - Install location (Desktop, home, /opt, etc.)
    - Whether the process is started with sudo

    config.py is expected to live at the repository root.
    """
    return os.path.dirname(os.path.abspath(__file__))


def get_real_user():
    """
    Return the login name of the user who invoked the tool.

    Under sudo, USER/USERNAME is often root. SUDO_USER keeps the
    original invoking user (when sudo set it).

    Used for display/logging only — paths should use get_project_root(),
    not /home/<user>/... hardcoding.
    """
    return (
        os.environ.get("SUDO_USER")
        or os.environ.get("USER")
        or os.environ.get("USERNAME")
        or "unknown"
    )


# ─────────────────────────────────────────────────────
# AUTO-DETECT WIRELESS INTERFACE
# ─────────────────────────────────────────────────────

def find_monitor_interface():
    """
    Automatically find which wireless interface
    is in monitor mode.
    
    Checks all interfaces and returns the first one
    that is in Monitor mode.
    
    Returns: interface name (e.g., 'wlan0mon')
             or None if not found
    """
    try:
        # Run iwconfig and parse output
        result = subprocess.run(
            ['iwconfig'],
            capture_output=True,
            text=True
        )
        
        current_interface = None
        for line in result.stdout.split('\n'):
            # Lines starting with a letter = interface name
            if line and line[0].isalpha():
                current_interface = line.split()[0]
            # Check if this interface is in Monitor mode
            if 'Mode:Monitor' in line and current_interface:
                return current_interface
    except Exception:
        pass
    return None


def find_wireless_interfaces():
    """
    Find ALL wireless interfaces on the system.
    Returns list of interface names.
    """
    interfaces = []
    try:
        result = subprocess.run(
            ['iwconfig'],
            capture_output=True,
            text=True
        )
        for line in result.stdout.split('\n'):
            if line and line[0].isalpha():
                iface = line.split()[0]
                # Exclude loopback and ethernet
                if iface not in ['lo', 'eth0', 'eth1']:
                    interfaces.append(iface)
    except Exception:
        pass
    return interfaces


def enable_monitor_mode(interface=None):
    """
    Automatically enable monitor mode on the
    best available wireless interface.
    
    Steps:
    1. Find wireless interface if not specified
    2. Kill interfering processes
    3. Enable monitor mode
    4. Return new monitor interface name
    
    Returns: monitor interface name or None if failed
    """
    # First check if monitor mode already active
    existing = find_monitor_interface()
    if existing:
        print(f"[✓] Monitor mode already active: {existing}")
        return existing
    
    # Find wireless interface to use
    if not interface:
        interfaces = find_wireless_interfaces()
        if not interfaces:
            print("[ERROR] No wireless interfaces found!")
            return None
        interface = interfaces[0]
        print(f"[*] Using interface: {interface}")
    
    print(f"[*] Enabling monitor mode on {interface}...")
    
    # Kill interfering processes
    subprocess.run(
        ['airmon-ng', 'check', 'kill'],
        capture_output=True
    )
    
    # Enable monitor mode
    result = subprocess.run(
        ['airmon-ng', 'start', interface],
        capture_output=True,
        text=True
    )
    
    # Find the new monitor interface
    import time
    time.sleep(2)
    monitor = find_monitor_interface()
    
    if monitor:
        print(f"[✓] Monitor mode enabled: {monitor}")
        return monitor
    else:
        print("[ERROR] Failed to enable monitor mode!")
        return None


# ─────────────────────────────────────────────────────
# PROJECT CONFIGURATION (ALL AUTO-DETECTED)
# ─────────────────────────────────────────────────────

# Project paths - all relative to project root
PROJECT_ROOT  = get_project_root()
DATA_DIR      = os.path.join(PROJECT_ROOT, 'data')
MODELS_DIR    = os.path.join(PROJECT_ROOT, 'models')
LOGS_DIR      = os.path.join(PROJECT_ROOT, 'logs')
REPORTS_DIR   = os.path.join(PROJECT_ROOT, 'reports')
MODULES_DIR   = os.path.join(PROJECT_ROOT, 'modules')

# Data files
NORMAL_DATA_FILE     = os.path.join(DATA_DIR, 'normal_data.csv')
EVIL_TWIN_DATA_FILE  = os.path.join(DATA_DIR, 'evil_twin_data.csv')
COMBINED_DATA_FILE   = os.path.join(DATA_DIR, 'combined_data.csv')
AP_PROFILES_FILE     = os.path.join(DATA_DIR, 'ap_profiles.json')

# NEW: Multi-AP dataset
ALL_APS_DATA_FILE    = os.path.join(DATA_DIR, 'all_aps_normal.csv')
BSSID_PROFILES_FILE  = os.path.join(DATA_DIR, 'bssid_profiles.json')

# Model files
MODEL_FILE           = os.path.join(MODELS_DIR, 'detector_model.pkl')
SCALER_FILE          = os.path.join(MODELS_DIR, 'scaler.pkl')
ENCODER_FILE         = os.path.join(MODELS_DIR, 'encoder.pkl')

# Log files
ALERT_LOG_FILE       = os.path.join(LOGS_DIR, 'alerts.log')
DETECTION_LOG_FILE   = os.path.join(LOGS_DIR, 'detections.log')

# User info
REAL_USER = get_real_user()

# Channel settings
CHANNELS_2GHZ = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
CHANNELS_5GHZ = [36, 40, 44, 48, 52, 56, 60, 64,
                 100, 104, 108, 112, 116, 149, 153, 157, 161]
ALL_CHANNELS  = CHANNELS_2GHZ + CHANNELS_5GHZ

# Timing settings
HOP_INTERVAL         = 0.5    # Seconds per channel
PROFILE_DURATION     = 60     # Seconds to build AP profile
BEACON_DELAY         = 0.1    # Seconds between fake beacons

# AI Model settings
MIN_SAMPLES_NEEDED   = 50     # Minimum beacons to build profile
ANOMALY_THRESHOLD    = 0.6    # 0.0-1.0, higher = more strict
RANDOM_STATE         = 42     # For reproducible AI results

# ─────────────────────────────────────────────────────
# AUTO-CREATE DIRECTORIES
# ─────────────────────────────────────────────────────

def setup_directories():
    """
    Create all necessary directories automatically.
    Called once at startup.
    """
    dirs = [DATA_DIR, MODELS_DIR, LOGS_DIR,
            REPORTS_DIR, MODULES_DIR]
    for d in dirs:
        os.makedirs(d, exist_ok=True)
    print(f"[✓] Project directories ready")


# ─────────────────────────────────────────────────────
# PRINT CONFIGURATION SUMMARY
# ─────────────────────────────────────────────────────

def print_config():
    """Print current configuration for verification."""
    print("\n" + "="*55)
    print("  SYSTEM CONFIGURATION (Auto-Detected)")
    print("="*55)
    print(f"  Real User     : {REAL_USER}")
    print(f"  Project Root  : {PROJECT_ROOT}")
    print(f"  Data Dir      : {DATA_DIR}")
    print(f"  Models Dir    : {MODELS_DIR}")
    monitor = find_monitor_interface()
    print(f"  Monitor Iface : {monitor or 'Not found'}")
    print("="*55 + "\n")

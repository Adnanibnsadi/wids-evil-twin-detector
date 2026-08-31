#!/usr/bin/env python3
"""
=======================================================
  main.py - AI-Enabled Evil Twin Detector
=======================================================
  USAGE: sudo python3 main.py
  Works anywhere. Zero configuration needed.
=======================================================
"""

import os
import sys
import time

if os.geteuid() != 0:
    print("\n[ERROR] Must run as root: sudo python3 main.py\n")
    sys.exit(1)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import config
from modules.scanner   import scan_networks, select_network
from modules.profiler  import profile_network, load_profiles
from modules.trainer   import train, load_model
from modules.simulator import simulate_evil_twin

# ─────────────────────────────────────────────────────
# BANNER
# ─────────────────────────────────────────────────────

def print_banner():
    print("\n" + "="*60)
    print("   ██████████ ██     ██ ██ ███    ██")
    print("   ██         ██     ██ ██ ████   ██")
    print("   █████████  ██  █  ██ ██ ██ ██  ██")
    print("   ██         ██ ███ ██ ██ ██  ██ ██")
    print("   ██████████  ███ ███  ██ ██   ████")
    print()
    print("   AI-ENABLED EVIL TWIN DETECTOR")
    print("   Rogue Access Point Detection System")
    print("="*60)
    print(f"   User    : {config.REAL_USER}")
    print(f"   Project : {config.PROJECT_ROOT}")
    print("="*60)


# ─────────────────────────────────────────────────────
# MENU
# ─────────────────────────────────────────────────────

def show_menu():
    print("\n" + "="*45)
    print("  MAIN MENU")
    print("="*45)
    print("  [1] Scan nearby networks")
    print("  [2] Learn network behavior (profile)")
    print("  [3] Start Evil Twin detection")
    print("  [4] Simulate Evil Twin (generate training data)")
    print("  [5] Train AI model")
    print("  [6] Full auto mode (RECOMMENDED)")
    print("  [0] Exit")
    print("="*45)


# ─────────────────────────────────────────────────────
# INDIVIDUAL MODES
# ─────────────────────────────────────────────────────

def mode_scan(interface):
    """Scan and show nearby networks."""
    return scan_networks(interface, duration=20)


def mode_profile(interface):
    """Profile a selected network."""
    print("\n[*] First, let's scan to find available networks...")
    networks = scan_networks(interface, duration=20)
    if not networks:
        print("[ERROR] No networks found!")
        return None
    selected = select_network(networks)
    if not selected:
        return None
    return profile_network(interface, selected, duration=60)


def mode_simulate(interface):
    """Simulate Evil Twin for training data collection."""
    print("\n[*] Scanning for networks to clone...")
    networks = scan_networks(interface, duration=20)
    if not networks:
        print("[ERROR] No networks found!")
        return
    selected = select_network(networks)
    if not selected:
        return

    print(f"\n[!] WARNING: About to simulate Evil Twin of '{selected['ssid']}'")
    print("[!] Only do this on networks YOU OWN!")
    confirm = input("\n  Type 'YES' to confirm: ").strip()
    if confirm != 'YES':
        print("[*] Cancelled.")
        return

    simulate_evil_twin(interface, selected, duration=120)


def mode_train():
    """Train the AI model."""
    model, features = train(retrain=True)
    if model:
        print("\n[✓] AI model trained and saved!")
        print("[✓] Ready for real-time detection")
    else:
        print("\n[ERROR] Training failed!")
        print("[ERROR] Collect more data first (options 2 and 4)")

def mode_detect(interface):
    """Start real-time Evil Twin detection."""
    from modules.detector import start_detection

    print("\n[*] Starting real-time detection...")
    print("[*] The AI will monitor for Evil Twin attacks")

    # Ask if user wants to scan for target first
    choice = input("\n  Scan for target network first? (y/n): ").strip().lower()

    target = None
    if choice == 'y':
        networks = scan_networks(interface, duration=20)
        if networks:
            target = select_network(networks)

    start_detection(interface, target_network=target)

# ─────────────────────────────────────────────────────
# FULL AUTO MODE
# ─────────────────────────────────────────────────────

def mode_full_auto(interface):
    """
    Full automatic mode - works anywhere with zero config.

    Complete flow:
    1. Scan nearby networks
    2. User selects network to protect
    3. Learn normal behavior (60 seconds)
    4. Simulate Evil Twin (120 seconds)
    5. Train AI model automatically
    6. Start live detection
    """
    print("\n" + "="*55)
    print("  FULL AUTO MODE")
    print("="*55)
    print("  Complete automated Evil Twin detection")
    print()
    print("  STEPS:")
    print("  1. Scan nearby networks        (~30 sec)")
    print("  2. Select network to protect")
    print("  3. Learn normal behavior       (~60 sec)")
    print("  4. Simulate Evil Twin          (~120 sec)")
    print("  5. Train AI model              (~10 sec)")
    print("  6. Start live detection        (ongoing)")
    print("="*55)
    input("\n  Press ENTER to begin...\n")

    # ── STEP 1: Scan ─────────────────────────────────
    print("\n" + "─"*55)
    print("  STEP 1/6: Scanning nearby networks")
    print("─"*55)
    networks = scan_networks(interface, duration=30)

    if not networks:
        print("[ERROR] No networks found!")
        return

    # ── STEP 2: Select Network ────────────────────────
    print("\n" + "─"*55)
    print("  STEP 2/6: Select network to protect")
    print("─"*55)
    selected = select_network(networks)

    if not selected:
        print("[*] No network selected. Exiting auto mode.")
        return

    print(f"\n[✓] Protecting: {selected['ssid']}")
    print(f"[✓] BSSID     : {selected['bssid']}")
    print(f"[✓] Channel   : {selected['channel']}")

    # ── STEP 3: Profile Normal Behavior ──────────────
    print("\n" + "─"*55)
    print("  STEP 3/6: Learning normal behavior")
    print("─"*55)
    print(f"  Watching '{selected['ssid']}' for 60 seconds...")
    print("  Building behavioral fingerprint of the REAL AP\n")

    profile = profile_network(interface, selected, duration=60)

    if not profile:
        print("[ERROR] Profiling failed!")
        print(f"[ERROR] Make sure '{selected['ssid']}' is nearby")
        return

    print(f"\n[✓] Profile built for '{selected['ssid']}'")

    # ── STEP 4: Simulate Evil Twin ────────────────────
    print("\n" + "─"*55)
    print("  STEP 4/6: Simulating Evil Twin attack")
    print("─"*55)
    print("  This creates training data for the AI")
    print("  A fake AP will broadcast with same SSID")
    print("  but different hardware characteristics\n")

    input("  Press ENTER to start Evil Twin simulation...\n")

    simulate_evil_twin(interface, selected, duration=120)

    # ── STEP 5: Train AI Model ────────────────────────
    print("\n" + "─"*55)
    print("  STEP 5/6: Training AI model")
    print("─"*55)

    model, features = train(retrain=True)

    if not model:
        print("[ERROR] Training failed!")
        print("[ERROR] Trying anomaly detection mode...")
        model, features = train(retrain=True)
        if not model:
            return

    print("\n[✓] AI model trained successfully!")
   

# ── STEP 6: Start Detection ───────────────────────
    print("\n" + "─"*55)
    print("  STEP 6/6: Starting live detection")
    print("─"*55)

    from modules.detector import start_detection
    start_detection(interface, target_network=selected)

# MAIN
# ─────────────────────────────────────────────────────

def main():
    config.setup_directories()
    config.print_config()
    print_banner()

    # Auto-detect monitor interface
    print("[*] Checking for monitor mode interface...")
    interface = config.find_monitor_interface()

    if not interface:
        print("[*] Enabling monitor mode automatically...")
        interface = config.enable_monitor_mode()

    if not interface:
        print("[ERROR] Cannot find monitor mode interface!")
        print("Fix: sudo airmon-ng start wlan0")
        sys.exit(1)

    print(f"[✓] Interface: {interface}\n")

    # Main loop
    while True:
        show_menu()
        try:
            choice = input("\n  Enter choice: ").strip()

            if   choice == '1':
                mode_scan(interface)
            elif choice == '2':
                mode_profile(interface)
            elif choice == '3':
                mode_detect(interface)
            elif choice == '4':
                mode_simulate(interface)
            elif choice == '5':
                mode_train()
            elif choice == '6':
                mode_full_auto(interface)
            elif choice == '0':
                print("\n[*] Goodbye!\n")
                sys.exit(0)
            else:
                print("\n[!] Invalid choice. Enter 0-6")

        except KeyboardInterrupt:
            print("\n\n[*] Goodbye!\n")
            sys.exit(0)


if __name__ == "__main__":
    main()

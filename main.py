#!/usr/bin/env python3
"""
=======================================================
 main.py - Hybrid Wireless Intrusion Detection System
=======================================================

Main command-line interface for the current research
prototype.

Current workflow:

1. Scan nearby wireless networks.
2. Collect benign multi-AP beacon observations.
3. Build per-BSSID behavioral profiles.
4. Train Isolation Forest anomaly models.
5. Start passive live detection.
6. Optionally run the authorized lab simulator.

The live detector uses the advanced multi-AP profile and
Isolation Forest workflow rather than the older supervised
Random Forest baseline.
=======================================================
"""

import os
import subprocess
import sys

import config
from modules.scanner import (
    scan_networks,
    select_network,
)
from modules.simulator import simulate_evil_twin


# =======================================================
# STARTUP CHECK
# =======================================================

def require_root():
    """
    Live 802.11 monitor-mode operations normally require
    elevated privileges.
    """

    if os.geteuid() != 0:

        print(
            "\n[ERROR] This workflow requires root "
            "privileges for monitor-mode capture."
        )

        print(
            "Run with:"
        )

        print(
            "  sudo ./venv/bin/python3 main.py\n"
        )

        sys.exit(1)


# =======================================================
# BANNER
# =======================================================

def print_banner():

    print(
        "\n"
        + "=" * 68
    )

    print(
        "   ██████████ ██     ██ ██ ███    ██"
    )

    print(
        "   ██         ██     ██ ██ ████   ██"
    )

    print(
        "   █████████  ██  █  ██ ██ ██ ██  ██"
    )

    print(
        "   ██         ██ ███ ██ ██ ██  ██ ██"
    )

    print(
        "   ██████████  ███ ███  ██ ██   ████"
    )

    print()

    print(
        "   HYBRID WIRELESS INTRUSION DETECTION SYSTEM"
    )

    print(
        "   Evil Twin & Rogue Access Point Research Prototype"
    )

    print(
        "=" * 68
    )

    print(
        f"   User       : {config.REAL_USER}"
    )

    print(
        f"   Project    : {config.PROJECT_ROOT}"
    )

    print(
        "=" * 68
    )


# =======================================================
# MENU
# =======================================================

def show_menu():

    print(
        "\n"
        + "=" * 58
    )

    print(
        "  MAIN MENU"
    )

    print(
        "=" * 58
    )

    print(
        "  [1] Scan nearby networks"
    )

    print(
        "  [2] Collect multi-AP benign baseline"
    )

    print(
        "  [3] Build profiles and anomaly models"
    )

    print(
        "  [4] Start live WIDS detection"
    )

    print(
        "  [5] Run authorized Evil Twin lab simulator"
    )

    print(
        "  [6] Check project resource status"
    )

    print(
        "  [0] Exit"
    )

    print(
        "=" * 58
    )


# =======================================================
# RESOURCE PATHS
# =======================================================

def advanced_resource_paths():

    return {
        "baseline":
            config.ALL_APS_DATA_FILE,

        "profiles":
            config.BSSID_PROFILES_FILE,

        "per_bssid_models":
            os.path.join(
                config.MODELS_DIR,
                "per_bssid_models.pkl",
            ),

        "global_model":
            os.path.join(
                config.MODELS_DIR,
                "global_model.pkl",
            ),
    }


# =======================================================
# MODE 1 - SCAN
# =======================================================

def mode_scan(interface):

    print(
        "\n[*] Scanning nearby wireless networks..."
    )

    return scan_networks(
        interface,
        duration=20,
    )


# =======================================================
# MODE 2 - COLLECT BENIGN MULTI-AP BASELINE
# =======================================================

def mode_collect_baseline():

    collector_script = os.path.join(
        config.PROJECT_ROOT,
        "scripts",
        "collect_all_aps.py",
    )


    print(
        "\n"
        + "=" * 68
    )

    print(
        "  MULTI-AP BENIGN BASELINE COLLECTION"
    )

    print(
        "=" * 68
    )

    print(
        "This mode records beacon observations from nearby APs."
    )

    print(
        "The environment should be treated as benign during "
        "baseline collection."
    )

    print()

    print(
        "Do NOT run the lab Evil Twin simulator while "
        "collecting baseline data."
    )

    print()

    print(
        "Press Ctrl+C inside the collector when you have "
        "finished gathering data."
    )

    print(
        "=" * 68
        + "\n"
    )


    input(
        "Press ENTER to begin baseline collection..."
    )


    try:

        subprocess.run(
            [
                sys.executable,
                collector_script,
            ],
            check=False,
        )


    except KeyboardInterrupt:

        print(
            "\n[*] Baseline collection stopped."
        )


# =======================================================
# MODE 3 - BUILD PROFILES & MODELS
# =======================================================

def mode_build_models():

    paths = advanced_resource_paths()


    if not os.path.exists(
        paths["baseline"]
    ):

        print(
            "\n[ERROR] Multi-AP baseline dataset "
            "was not found."
        )

        print(
            f"Expected:"
        )

        print(
            f"  {paths['baseline']}"
        )

        print()

        print(
            "Run menu option [2] first."
        )

        return


    profile_script = os.path.join(
        config.PROJECT_ROOT,
        "scripts",
        "build_profiles.py",
    )


    model_script = os.path.join(
        config.PROJECT_ROOT,
        "scripts",
        "build_advanced_model.py",
    )


    print(
        "\n"
        + "=" * 68
    )

    print(
        "  BUILDING BSSID PROFILES"
    )

    print(
        "=" * 68
    )


    result = subprocess.run(
        [
            sys.executable,
            profile_script,
        ],
        check=False,
    )


    if result.returncode != 0:

        print(
            "\n[ERROR] Profile building failed."
        )

        return


    print(
        "\n"
        + "=" * 68
    )

    print(
        "  BUILDING ANOMALY MODELS"
    )

    print(
        "=" * 68
    )


    result = subprocess.run(
        [
            sys.executable,
            model_script,
        ],
        check=False,
    )


    if result.returncode != 0:

        print(
            "\n[ERROR] Model building failed."
        )

        return


    print(
        "\n[✓] Advanced detector resources built successfully."
    )


# =======================================================
# RESOURCE VALIDATION
# =======================================================

def detector_resources_ready():

    paths = advanced_resource_paths()


    required = [
        "profiles",
        "per_bssid_models",
        "global_model",
    ]


    missing = [
        key
        for key in required
        if not os.path.exists(
            paths[key]
        )
    ]


    if not missing:

        return True


    print(
        "\n[ERROR] Live detector resources are incomplete."
    )

    print(
        "\nMissing:"
    )


    for key in missing:

        print(
            f"  - {key}: "
            f"{paths[key]}"
        )


    print(
        "\nRun:"
    )

    print(
        "  [2] Collect multi-AP benign baseline"
    )

    print(
        "  [3] Build profiles and anomaly models"
    )

    return False


# =======================================================
# MODE 4 - LIVE DETECTION
# =======================================================

def mode_detect(interface):

    if not detector_resources_ready():
        return


    from modules.detector import start_detection


    print(
        "\n[*] Starting passive live WIDS monitoring..."
    )

    print(
        "[*] The detector will compare beacon observations "
        "against learned AP baselines."
    )


    target = None


    choice = input(
        "\nLock monitoring to one selected AP/channel? "
        "(y/n): "
    ).strip().lower()


    if choice == "y":

        networks = scan_networks(
            interface,
            duration=20,
        )


        if networks:

            target = select_network(
                networks
            )


    start_detection(
        interface,
        target_network=target,
    )


# =======================================================
# MODE 5 - AUTHORIZED LAB SIMULATOR
# =======================================================

def mode_simulate(interface):

    print(
        "\n"
        + "=" * 68
    )

    print(
        "  AUTHORIZED EVIL TWIN LAB SIMULATOR"
    )

    print(
        "=" * 68
    )

    print(
        "This feature injects synthetic 802.11 beacon frames."
    )

    print()

    print(
        "Use it only with wireless networks and hardware "
        "that you own or have explicit permission to test."
    )

    print(
        "=" * 68
        + "\n"
    )


    networks = scan_networks(
        interface,
        duration=20,
    )


    if not networks:

        print(
            "[ERROR] No networks found."
        )

        return


    selected = select_network(
        networks
    )


    if not selected:
        return


    print()

    print(
        f"Selected SSID : {selected['ssid']}"
    )

    print(
        f"Selected BSSID: {selected['bssid']}"
    )

    print(
        f"Channel       : {selected['channel']}"
    )

    print()

    print(
        "Simulation mode:"
    )

    print(
        "  [1] Same SSID with different BSSID"
    )

    print(
        "  [2] BSSID-spoofed lab transmitter"
    )


    mode = input(
        "\nSelect mode (1/2): "
    ).strip()


    if mode not in {
        "1",
        "2",
    }:

        print(
            "[ERROR] Invalid simulation mode."
        )

        return


    print()

    print(
        "[!] Authorization confirmation required."
    )

    confirm = input(
        "Type AUTHORIZED to continue: "
    ).strip()


    if confirm != "AUTHORIZED":

        print(
            "[*] Simulation cancelled."
        )

        return


    bssid_clone = (
        mode == "2"
    )


    simulate_evil_twin(
        interface,
        selected,
        duration=120,
        bssid_clone=bssid_clone,
    )


# =======================================================
# MODE 6 - RESOURCE STATUS
# =======================================================

def mode_status(interface):

    paths = advanced_resource_paths()


    print(
        "\n"
        + "=" * 68
    )

    print(
        "  PROJECT RESOURCE STATUS"
    )

    print(
        "=" * 68
    )


    monitor_status = (
        "READY"
        if interface
        else
        "NOT FOUND"
    )


    print(
        f"  Monitor interface : "
        f"{monitor_status}"
    )


    labels = {
        "baseline":
            "Multi-AP baseline",

        "profiles":
            "BSSID profiles",

        "per_bssid_models":
            "Per-BSSID models",

        "global_model":
            "Global model",
    }


    for key, path in paths.items():

        status = (
            "READY"
            if os.path.exists(path)
            else
            "MISSING"
        )

        print(
            f"  {labels[key]:18}: "
            f"{status}"
        )


    print(
        "\nDetailed paths:"
    )


    for key, path in paths.items():

        print(
            f"  {labels[key]:18}: "
            f"{path}"
        )


    print(
        "=" * 68
    )


# =======================================================
# MONITOR INTERFACE
# =======================================================

def get_monitor_interface():

    print(
        "[*] Checking for a monitor-mode interface..."
    )


    interface = (
        config.find_monitor_interface()
    )


    if interface:

        print(
            f"[✓] Monitor interface found: "
            f"{interface}"
        )

        return interface


    print(
        "[*] No monitor interface detected."
    )

    print(
        "[*] Attempting to enable monitor mode..."
    )


    interface = (
        config.enable_monitor_mode()
    )


    if not interface:

        print(
            "\n[ERROR] Unable to create a "
            "monitor-mode interface."
        )

        print()

        print(
            "Example manual setup:"
        )

        print(
            "  sudo airmon-ng check kill"
        )

        print(
            "  sudo airmon-ng start wlan0"
        )

        sys.exit(1)


    return interface


# =======================================================
# MAIN
# =======================================================

def main():

    require_root()


    config.setup_directories()


    interface = (
        get_monitor_interface()
    )


    print_banner()


    while True:

        show_menu()


        try:

            choice = input(
                "\nEnter choice: "
            ).strip()


            if choice == "1":

                mode_scan(
                    interface
                )


            elif choice == "2":

                mode_collect_baseline()


            elif choice == "3":

                mode_build_models()


            elif choice == "4":

                mode_detect(
                    interface
                )


            elif choice == "5":

                mode_simulate(
                    interface
                )


            elif choice == "6":

                mode_status(
                    interface
                )


            elif choice == "0":

                print(
                    "\n[*] Goodbye.\n"
                )

                sys.exit(0)


            else:

                print(
                    "\n[!] Invalid choice. "
                    "Enter a number from 0 to 6."
                )


        except KeyboardInterrupt:

            print(
                "\n\n[*] Returning to menu."
            )


if __name__ == "__main__":
    main()

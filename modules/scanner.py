#!/usr/bin/env python3
"""
=======================================================
  scanner.py - Automatic Network Scanner
=======================================================
  Scans all nearby Wi-Fi networks automatically.
  No configuration needed.
  Works anywhere in the world.
=======================================================
"""

from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap
import sys
import os
import time
import threading

# Import our auto-config
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

# ─────────────────────────────────────────────────────
# GLOBAL VARIABLES
# ─────────────────────────────────────────────────────

# Dictionary to store discovered networks
# Format: { "BSSID": { network details } }
discovered_networks = {}
scan_running        = False
hop_running         = False

# ─────────────────────────────────────────────────────
# CHANNEL HOPPER
# ─────────────────────────────────────────────────────

def channel_hopper(interface):
    """Hop through all channels during scanning."""
    global hop_running
    while hop_running:
        for ch in config.ALL_CHANNELS:
            if not hop_running:
                break
            os.system(f"iwconfig {interface} channel {ch} 2>/dev/null")
            time.sleep(config.HOP_INTERVAL)


# ─────────────────────────────────────────────────────
# PACKET HANDLER
# ─────────────────────────────────────────────────────

def scan_handler(packet):
    """
    Process each beacon frame during scanning.
    Builds a dictionary of all nearby networks.
    """
    if not packet.haslayer(Dot11Beacon):
        return

    try:
        bssid = packet[Dot11].addr2

        try:
            ssid = packet[Dot11Elt].info.decode('utf-8', errors='replace')
        except Exception:
            ssid = "<Hidden>"

        if not ssid.strip():
            ssid = "<Hidden>"

        # Extract channel
        channel = 0
        element = packet[Dot11Elt]
        while element:
            if element.ID == 3:
                channel = ord(element.info)
                break
            element = element.payload

        # Extract RSSI
        rssi = 0
        try:
            if packet.haslayer(RadioTap):
                rssi = packet[RadioTap].dBm_AntSignal
        except Exception:
            pass

        # Extract security
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

        # Store or update network info
        if bssid not in discovered_networks:
            discovered_networks[bssid] = {
                'ssid':     ssid,
                'bssid':    bssid,
                'channel':  channel,
                'rssi':     rssi,
                'security': security,
                'beacons':  1,
                'first_seen': time.strftime("%H:%M:%S")
            }
        else:
            # Update with latest info
            discovered_networks[bssid]['beacons'] += 1
            discovered_networks[bssid]['rssi']     = rssi
            discovered_networks[bssid]['channel']  = channel

    except Exception:
        pass


# ─────────────────────────────────────────────────────
# DISPLAY NETWORKS
# ─────────────────────────────────────────────────────

def display_networks():
    """
    Display all discovered networks in a clean table.
    Sorted by signal strength (strongest first).
    """
    if not discovered_networks:
        print("  No networks found yet...")
        return

    # Sort by RSSI (higher value = stronger signal)
    sorted_nets = sorted(
        discovered_networks.values(),
        key=lambda x: x['rssi'],
        reverse=True
    )

    print("\n" + "="*85)
    print(f"  {'#':<4} {'SSID':<25} {'BSSID':<20} {'CH':<5}"
          f"{'RSSI':<8} {'SECURITY':<12} {'BEACONS'}")
    print("="*85)

    for i, net in enumerate(sorted_nets, 1):
        # Color based on signal strength
        if net['rssi'] > -50:
            color = "\033[92m"   # Green  = strong
        elif net['rssi'] > -70:
            color = "\033[93m"   # Yellow = medium
        else:
            color = "\033[91m"   # Red    = weak

        reset = "\033[0m"

        print(f"  {color}"
              f"{i:<4}"
              f"{net['ssid'][:24]:<25}"
              f"{net['bssid']:<20}"
              f"{net['channel']:<5}"
              f"{net['rssi']:<8}"
              f"{net['security']:<12}"
              f"{net['beacons']}"
              f"{reset}")

    print("="*85)
    print(f"  Total networks found: {len(discovered_networks)}")


# ─────────────────────────────────────────────────────
# MAIN SCAN FUNCTION
# ─────────────────────────────────────────────────────

def scan_networks(interface, duration=30):
    """
    Scan for all nearby Wi-Fi networks.
    
    This is the FIRST thing the tool does when started.
    It discovers what networks exist in the area
    so the user can choose which one to protect.
    
    Parameters:
        interface : monitor mode interface name
        duration  : how long to scan in seconds
    
    Returns:
        dict of discovered networks
    """
    global scan_running, hop_running

    print("\n" + "="*55)
    print("  AUTO-SCANNING NEARBY NETWORKS")
    print("="*55)
    print(f"  Interface : {interface}")
    print(f"  Duration  : {duration} seconds")
    print(f"  Channels  : {len(config.ALL_CHANNELS)}")
    print("="*55)
    print("  Scanning... please wait\n")

    # Start channel hopper in background
    hop_running    = True
    hopper         = threading.Thread(
                        target=channel_hopper,
                        args=(interface,),
                        daemon=True
                    )
    hopper.start()

    # Start sniffing
    scan_running = True
    sniff(
        iface=interface,
        prn=scan_handler,
        timeout=duration,
        store=False
    )

    # Stop hopper
    hop_running  = False
    scan_running = False

    # Display results
    display_networks()

    return discovered_networks


# ─────────────────────────────────────────────────────
# LET USER SELECT NETWORK TO PROTECT
# ─────────────────────────────────────────────────────

def select_network(networks_dict):
    """
    Let user interactively select which network
    they want to monitor and protect.
    
    Returns selected network details or None.
    
    This makes the tool work anywhere:
    - At home: user selects home network
    - At office: user selects office network
    - Presenting: user selects any nearby network
    """
    sorted_nets = sorted(
        networks_dict.values(),
        key=lambda x: x['rssi'],
        reverse=True
    )

    print("\n" + "="*55)
    print("  SELECT NETWORK TO PROTECT")
    print("="*55)
    print("  Enter the NUMBER of the network")
    print("  you want to monitor for Evil Twin attacks.")
    print("  Choose a network YOU OWN or have permission")
    print("  to monitor.")
    print("="*55)

    # Display networks with numbers
    for i, net in enumerate(sorted_nets, 1):
        print(f"  [{i}] {net['ssid']:<25} "
              f"Ch:{net['channel']:<4} "
              f"{net['rssi']} dBm  "
              f"{net['security']}")

    print(f"  [0] Protect ALL networks (detect any Evil Twin)")
    print("="*55)

    while True:
        try:
            choice = input("\n  Enter your choice: ").strip()
            choice = int(choice)

            if choice == 0:
                print("\n  [✓] Monitoring ALL networks")
                return None   # None means monitor everything

            if 1 <= choice <= len(sorted_nets):
                selected = sorted_nets[choice - 1]
                print(f"\n  [✓] Selected: {selected['ssid']}")
                print(f"  [✓] BSSID   : {selected['bssid']}")
                print(f"  [✓] Channel : {selected['channel']}")
                return selected

            print(f"  [!] Please enter 1-{len(sorted_nets)} or 0")

        except ValueError:
            print("  [!] Please enter a number")
        except KeyboardInterrupt:
            print("\n  [!] Cancelled")
            return None

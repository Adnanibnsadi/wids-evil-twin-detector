#!/usr/bin/env python3
"""
=======================================================
  modules/simulator.py - Evil Twin Attack Generator
=======================================================
  Used for controlled testing and demonstrations.
  Allows simulating:
  - Mode 1: Clone with Spoofed MAC (Different IE count)
  - Mode 2: "Perfect" Clone (Same MAC, Same SSID, Same Channel)
=======================================================
"""

from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap
import os, sys, time, random

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

def build_attack_frame(ssid, bssid, channel, seq_num, perfect_clone=False):
    radiotap = RadioTap()
    
    dot11 = Dot11(
        type=0, subtype=8,
        addr1="02:92:7a:c5:19:ac",
        addr2=bssid,
        addr3=bssid,
        SC=seq_num << 4
    )
    
    # Fake AP hardware clock will have different microsecond timestamp
    fake_ts = int(time.time() * 1_000_000) + random.randint(100, 5000)
    beacon = Dot11Beacon(timestamp=fake_ts, beacon_interval=100, cap=0x0411)
    
    ssid_ie = Dot11Elt(ID=0, info=ssid.encode())
    
    if perfect_clone:
        # Attacker tries to mimic rates and standard parameters
        rates_ie = Dot11Elt(ID=1, info=b'\x82\x84\x8b\x96\x0c\x12\x18\x24')
        channel_ie = Dot11Elt(ID=3, info=bytes([channel]))
        # But attack tool produces fewer overall IEs (e.g., 4 instead of router's 20)
        ext_rates_ie = Dot11Elt(ID=50, info=b'\x30\x48\x60\x6c')
        frame = radiotap / dot11 / beacon / ssid_ie / rates_ie / channel_ie / ext_rates_ie
    else:
        # Standard airbase-ng / hostapd profile (only 3-4 IEs)
        rates_ie = Dot11Elt(ID=1, info=b'\x82\x84\x8b\x96')
        channel_ie = Dot11Elt(ID=3, info=bytes([channel]))
        frame = radiotap / dot11 / beacon / ssid_ie / rates_ie / channel_ie
        
    return frame

def simulate_evil_twin(interface, network_info, duration=60, perfect_clone=True):
    ssid = network_info['ssid']
    channel = int(network_info['channel'])
    
    if perfect_clone:
        # Uses the EXACT same MAC address
        bssid = network_info['bssid']
        print(f"\n[🔥 Attack Simulator] Launching 'PERFECT' Evil Twin Clone!")
        print(f"  Target SSID : {ssid}")
        print(f"  Spoofed MAC : {bssid} (Exact match to legitimate AP!)")
    else:
        # Uses slightly altered rogue MAC
        parts = network_info['bssid'].split(':')
        parts[-1] = 'ee'
        bssid = ':'.join(parts)
        print(f"\n[🔥 Attack Simulator] Launching Rogue AP Simulator!")
        print(f"  Target SSID : {ssid}")
        print(f"  Rogue MAC   : {bssid}")

    print(f"  Channel     : {channel}")
    print(f"  Duration    : {duration} seconds\n")
    
    os.system(f"iwconfig {interface} channel {channel} 2>/dev/null")
    time.sleep(0.5)
    
    seq = 100
    end_time = time.time() + duration
    count = 0
    
    try:
        while time.time() < end_time:
            pkt = build_attack_frame(ssid, bssid, channel, seq, perfect_clone)
            sendp(pkt, iface=interface, verbose=False)
            count += 1
            seq = (seq + 1) % 4096
            
            remaining = int(end_time - time.time())
            print(f"\r  [Injecting Attack Frames] Sent: {count:4d} | Remaining: {remaining:2d}s", end='', flush=True)
            time.sleep(0.1) # 10 beacons/sec
    except KeyboardInterrupt:
        pass
        
    print(f"\n[✓] Simulation completed. Injected {count} frames.\n")

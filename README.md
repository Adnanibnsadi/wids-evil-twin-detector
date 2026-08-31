# 🛡️ Hybrid WIDS: AI-Enabled Rogue AP & Evil Twin Detector (v0.8)

**Status:** Research prototype / working lab system.

A passive 802.11 monitoring prototype that builds **local behavioral baselines** for nearby access points and raises alerts when live beacons diverge. It uses **rule-based RF/protocol checks** plus **per-BSSID anomaly models** (Isolation Forest) to detect BSSID-spoofed Evil Twin attacks.

---

## 🔬 How Our AI Solves This (The 4-Layer Defense Engine)

Traditional Wi-Fi security relies on MAC whitelists, which attackers easily spoof. Our system monitors features that cannot be spoofed purely in software:

1. **Simultaneous Presence & Duplicate Sequence Detection**  
   Detects two physical APs using the same MAC at once (Sequence Collisions).
2. **Hardware Information Element (IE) Fingerprinting**  
   Compares physical capabilities and chipset rates (Attack tools usually have fewer IEs).
3. **Hardware Clock Skew Analysis (Crystal Oscillator Drift)**  
   Calculates physical hardware microsecond drift: `Skew = (Δ AP_Timestamp - Δ System_Time) / Δ System_Time`
4. **Per-BSSID Machine Learning Models (Isolation Forest)**  
   Dedicated anomaly detectors trained on the specific RF baseline of every local router.

---

## 🚀 Quick Start

**Requirements:** Linux (Kali recommended) and an external Wi-Fi Adapter with **Monitor Mode** support.

```bash
git clone https://github.com/YOUR_USERNAME/wids-evil-twin-detector.git
cd wids-evil-twin-detector
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Enable Monitor Mode
sudo airmon-ng check kill
sudo airmon-ng start wlan0   # Your interface name may vary

# Run the system
sudo venv/bin/python3 main.py
📊 Demonstrated Lab Results
False Positive Rate: 0.0% across 1,300+ continuous production frames in a benign lab baseline.
Attack Detection: Successfully intercepted controlled BSSID-spoofed clone attacks via duplicate sequence overlaps and IE structural mismatches.
🛠️ Limitations & Future Work
Limitations (v0.8): Baselines are location-specific; moving the system requires retraining. The lab injector used for testing is not a full-IE clone.
Planned Improvements (v1.0): Implement sliding-window sequence analysis, session-based evaluation metrics (Precision/Recall), and higher-fidelity attack simulations.
Disclaimer: Use only on networks you own or have explicit authorization to monitor/test.

# 🛡️ Hybrid WIDS: Evil Twin & Rogue Access Point Detector

> **Version 0.8 — Research Prototype / Working Lab System**
> [![Tests](https://github.com/Adnanibnsadi/wids-evil-twin-detector/actions/workflows/tests.yml/badge.svg)](https://github.com/Adnanibnsadi/wids-evil-twin-detector/actions/workflows/tests.yml)

A passive wireless intrusion detection system for Linux that profiles nearby IEEE 802.11 access points and detects suspicious or BSSID-spoofed access points using a combination of:

- 802.11 beacon fingerprinting
- Sequence-number behavior
- Information Element (IE) analysis
- Security configuration checks
- Timing / clock-skew analysis
- Per-BSSID Isolation Forest anomaly detection

The project is designed as a **hybrid detection system** rather than a purely machine-learning classifier. Deterministic wireless evidence and behavioral anomaly detection are combined to produce more explainable alerts.

---

## 🎯 Project Objective

Traditional Evil Twin detection often relies heavily on SSID and MAC/BSSID comparison.

However, an attacker can advertise:

- the same SSID,
- a similar security configuration,
- and even the same BSSID as a legitimate access point.

This project explores a harder question:

> **Can passive 802.11 beacon characteristics help distinguish a legitimate access point from another transmitter claiming the same logical identity?**

The detector therefore builds behavioral profiles for legitimate APs and compares live beacon traffic against those profiles.

---

## 🔬 Detection Architecture

```text
              Nearby IEEE 802.11 Beacon Frames
                           │
                           ▼
                  ┌──────────────────┐
                  │  Beacon Capture  │
                  │      Scapy       │
                  └────────┬─────────┘
                           │
                           ▼
                ┌──────────────────────┐
                │   Feature Extraction │
                │                      │
                │ SSID / BSSID         │
                │ RSSI / Channel       │
                │ Sequence Number      │
                │ Beacon Timestamp     │
                │ Security             │
                │ IE Count             │
                │ Rate Count           │
                │ Timing Features      │
                └──────────┬───────────┘
                           │
                           ▼
               ┌────────────────────────┐
               │ Known AP Profile       │
               │ Comparison             │
               └───────────┬────────────┘
                           │
          ┌────────────────┼────────────────┐
          │                │                │
          ▼                ▼                ▼
  Sequence Analysis   IE / Security    Timing Analysis
          │            Fingerprints          │
          └────────────────┬────────────────┘
                           │
                           ▼
                 Per-BSSID Isolation
                     Forest Model
                           │
                           ▼
                    Evidence Scoring
                           │
                           ▼
              Consecutive Suspicion Check
                           │
                           ▼
                         ALERT
```

---

## 🧠 Why a Hybrid Detector?

The machine-learning model is **one component** of the detector rather than the sole decision maker.

Different detection layers provide different types of evidence.

| Detection Layer | Type | Purpose |
|---|---|---|
| Duplicate / conflicting sequence behavior | Strong evidence | Detects suspicious sequence activity associated with the same BSSID |
| Same SSID with unexpected BSSID | Strong evidence | Detects conventional Evil Twin / rogue AP scenarios |
| Information Element deviation | Strong evidence | Detects changes in beacon structure |
| Security configuration change | Strong evidence | Detects differences in advertised security |
| Supported-rate deviation | Supporting evidence | Helps identify implementation or configuration differences |
| Clock-skew / timing anomaly | Supporting evidence | Looks for unusual transmitter timing behavior |
| Per-BSSID Isolation Forest | Supporting ML evidence | Detects abnormal behavior relative to the AP's learned baseline |

The detector combines these characteristics because reproducing several independent behavioral and structural properties consistently can be more difficult than simply copying an SSID or BSSID.

---

## 🔎 Features Extracted from Beacons

The system extracts features such as:

- SSID
- BSSID
- RSSI
- Channel
- Sequence number
- Sequence jump
- Beacon timestamp / TSF
- Clock-skew estimate
- Beacon interval
- Capabilities
- Security type
- Information Element count
- Supported-rate count
- Inter-beacon timing
- Duplicate-sequence indicators

---

## 📡 Per-Access-Point Profiling

Instead of assuming that all routers behave identically, the system builds profiles for individual BSSIDs.

A profile may contain:

- Expected IE count
- Expected supported-rate count
- Security configuration
- Channel
- Beacon interval
- Clock-skew statistics
- RSSI statistics
- Sequence-jump statistics
- Number of observed beacons

This allows the detector to ask:

> **Is this behavior unusual for this specific access point?**

rather than simply asking whether the frame looks unusual compared with every AP in the environment.

---

## 🤖 Machine Learning Layer

The current advanced detector uses **Isolation Forest** models trained separately for sufficiently observed BSSIDs.

Current ML features include:

```python
[
    "clock_skew",
    "rssi",
    "seq_jump",
    "inter_beacon_ms"
]
```

Each AP receives its own scaler and anomaly model.

The ML layer is deliberately treated as **supporting evidence** because RF and timing measurements can be noisy in real environments.

A secondary global Isolation Forest model is also available for engineered deviation features.

---

## ⚠️ Timing & VMware Considerations

Development and testing were performed primarily using:

- Kali Linux
- VMware
- External USB Wi-Fi adapter
- Monitor mode

Virtualization and USB scheduling introduce timing noise.

Channel hopping can also create large gaps between consecutive captured beacons, which initially produced unreliable clock-skew measurements.

To reduce these false alerts, clock-skew evidence is only trusted when consecutive beacon observations fall within a limited timing window.

This timing filter significantly improved benign monitoring stability in the development environment.

---

## 🚨 Alert Logic

The detector does not alert on every isolated anomaly.

The current design uses:

- Strong and supporting evidence
- Aggregated suspicion scoring
- A minimum suspicious-frame streak
- Per-BSSID alert cooldowns

This helps prevent individual noisy measurements from immediately creating alerts.

The current implementation requires multiple consecutive suspicious observations before generating an alert.

---

## 📊 Demonstrated Lab Results

The following results were obtained during controlled development experiments.

### Multi-AP Baseline Dataset

A local benign capture contained approximately:

- **9,500 beacon observations**
- **15 unique BSSIDs**
- approximately **20 minutes of monitoring**

Twelve AP profiles were generated after excluding very low-observation BSSIDs.

> The original neighborhood capture is not included in the public repository because it contains real wireless-network identifiers.

---

### Benign Monitoring

After timing-jitter calibration:

> **No false alerts were observed across more than 1,300 beacon frames during a controlled benign monitoring session.**

This is an observed baseline result and **should not be interpreted as a formally established 0% false-positive rate**.

Broader multi-session evaluation is planned.

---

### Controlled BSSID-Spoofing Experiment

A controlled laboratory Evil Twin simulation advertising the same BSSID as a profiled AP triggered the detector.

Observed evidence included combinations of:

- Duplicate sequence activity
- Beacon Information Element differences
- Security configuration differences
- Timing / clock-skew anomalies
- ML anomaly evidence

The experiment demonstrates detection of a **BSSID-spoofed laboratory transmitter**, but the current injector is not a full high-fidelity clone of every beacon field emitted by the legitimate access point.

---

## 📈 Visualizations

The project includes a chart-generation script for analyzing locally collected wireless data.

Available visualizations include:

- Clock-skew fingerprints
- Information Element (IE) fingerprints
- Sequence-collision illustrations
- Detection-layer weight analysis

To generate charts for your own environment:

```bash
sudo ./venv/bin/python3 scripts/generate_charts.py
```
Generated charts are stored in the `visualizations/` directory.

> **Privacy note:** Real development visualizations are not included in the public repository because they were generated from local wireless-network observations that may contain identifying SSIDs, BSSIDs, or environment-specific information.

> **Evaluation note:** The sequence-collision chart produced by the current visualization script is illustrative and should not be interpreted as a direct PCAP replay.

Future releases will include sanitized or synthetic example visualizations that can be safely published.

---

## 📁 Repository Structure

```text
wids-evil-twin-detector/
│
├── main.py
├── config.py
├── requirements.txt
├── README.md
├── CHANGELOG.md
├── LICENSE
│
├── modules/
│   ├── scanner.py
│   ├── profiler.py
│   ├── simulator.py
│   ├── trainer.py
│   └── detector.py
│   
│
├── scripts/
│   ├── sniffer.py
│   ├── collect_all_aps.py
│   ├── build_profiles.py
│   ├── build_advanced_model.py
│   ├── generate_charts.py
│   └── sanitize_for_public.py
│
├── data/
│   └── samples/
│       └── bssid_profiles.example.json
│   
│
├── models/
│   └── .gitkeep
│
└── visualizations/
  
    └── README.md
```

Real captures, generated profiles, logs, and trained models are intentionally excluded from the public repository where they may contain environment-specific or identifying information.

---

# 🚀 Installation

## Requirements

### Operating System

Linux is required for the intended wireless-monitoring workflow.

Development was performed on:

```text
Kali Linux running inside VMware
```

### Hardware

A Wi-Fi adapter capable of:

```text
Monitor Mode
```

is required for live 802.11 beacon capture.

USB adapters used inside VMware must be passed through to the virtual machine.

### Software

The project uses:

- Python 3
- Scapy
- pandas
- NumPy
- scikit-learn
- joblib
- matplotlib
- seaborn

Aircrack-ng tools are also useful for enabling monitor mode.

---

## 1. Clone the Repository

```bash
git clone https://github.com/Adnanibnsadi/wids-evil-twin-detector.git
cd wids-evil-twin-detector
```

---

## 2. Create a Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
```

Install the Python dependencies:

```bash
pip install -r requirements.txt
```

---

## 3. Enable Monitor Mode

Identify your wireless interface:

```bash
iwconfig
```

Then, for example:

```bash
sudo airmon-ng check kill
sudo airmon-ng start wlan0
```

The resulting interface may appear as:

```text
wlan0mon
```

Interface names vary between systems.

---

## 4. Run the Main Interface

```bash
sudo ./venv/bin/python3 main.py
```

The CLI provides options for:

```text
[1] Scan nearby networks
[2] Collect multi-AP benign baseline
[3] Build profiles and anomaly models
[4] Start live WIDS detection
[5] Run authorised Evil Twin lab simulator
[6] Check project resource status
[0] Exit
```

>The main CLI now follows the current multi-AP research workflow. The older
single-AP profiling and supervised Random Forest components remain in the
repository as legacy experimental baselines but are not part of the primary
live detection pipeline.
>  Attack simulation must only be used in a controlled environment on networks and hardware you own or are explicitly authorized to test.

---

# 🧪 Testing

The repository includes hardware-independent unit tests for the main WIDS components.

Current automated coverage includes:

- Synthetic 802.11 beacon construction
- SSID and channel parsing
- Basic security classification
- Scanner state handling
- BSSID / SSID inconsistency detection
- Duplicate sequence activity
- Information Element deviations
- Security changes
- Timing-based evidence
- Per-BSSID anomaly-model evidence
- Threat-score aggregation and threshold behavior

The test suite does not require:

- Root privileges
- Monitor mode
- A wireless adapter
- Live packet capture
- Packet transmission

## Run Tests Locally

Install the development dependencies:

```bash
python -m pip install -r requirements-dev.txt
```

Check Python syntax:

```bash
python -m compileall -q main.py config.py modules scripts tests
```

Run the full test suite:

```bash
python -m pytest -v
```

The current suite contains **32 tests**.

## Continuous Integration

GitHub Actions automatically runs the syntax checks and pytest suite on:

- Pushes to `main`
- Pull requests
- Manual workflow runs

The CI workflow currently runs on Python 3.12.

The hardware-independent test suite has also been verified locally on Kali Linux with Python 3.14.

---

# 🧪 Advanced Multi-AP Workflow

The newer research workflow supports collecting legitimate traffic from multiple nearby APs and building individual behavioral profiles.

## Collect Baseline Traffic

```bash
sudo ./venv/bin/python3 scripts/collect_all_aps.py
```

This generates a local multi-AP dataset.

---

## Build BSSID Profiles

```bash
sudo ./venv/bin/python3 scripts/build_profiles.py
```

This creates behavioral profiles for APs with sufficient observations.

---

## Build Advanced Models

```bash
sudo ./venv/bin/python3 scripts/build_advanced_model.py
```

This trains per-BSSID Isolation Forest models and the secondary global anomaly model.

Generated datasets, profiles, and model files are intentionally excluded from the public repository and should be rebuilt from the user's own environment.

---

# 🧩 Current Research Questions

This prototype is being developed around two main questions:

> **How effectively can passive 802.11 beacon fingerprints distinguish a legitimate access point from an increasingly high-fidelity BSSID-spoofed Evil Twin?**

and

> **Which combination of sequence behavior, beacon structure, timing characteristics, and anomaly detection provides useful attack detection while maintaining a low false-alert rate?**

---

# ⚠️ Current Limitations

Version 0.8 is a research prototype and has several important limitations.

### Limited Dataset Diversity

Current experiments were conducted in a limited number of environments.

A larger evaluation should contain:

- Multiple locations
- Multiple capture sessions
- Different days and times
- More AP manufacturers
- Different wireless adapters

---

### Correlated Beacon Observations

Thousands of beacon frames do not necessarily represent thousands of statistically independent observations.

Future ML evaluation will therefore separate training and testing by **capture session** rather than randomly splitting neighboring beacon rows.

---

### Timing Noise

Clock-skew and inter-beacon measurements are affected by:

- Channel hopping
- USB latency
- Virtual-machine scheduling
- Driver buffering
- Packet loss
- Receiver scheduling

Timing characteristics are therefore used as supporting evidence rather than definitive transmitter identity.

---

### RSSI Variability

RSSI can change due to:

- Distance
- Physical obstacles
- Multipath propagation
- Antenna orientation
- Environmental movement

RSSI is therefore treated as a weak contextual feature.

---

### Simulator Fidelity

The current laboratory simulator can reproduce selected Evil Twin characteristics, including BSSID spoofing, but it does **not** yet reproduce every Information Element and implementation detail of the legitimate AP.

For this reason, results are described as **BSSID-spoofed Evil Twin detection**, not proof of detection against a fully identical beacon implementation.

---

### Heuristic Threat Weights

Current detection weights and thresholds were empirically selected during prototype calibration.

They are **threat / suspicion scores**, not statistically calibrated attack probabilities.

Future versions will evaluate and tune these parameters using independent validation sessions.

---

# 🗺️ Roadmap to v1.0

Planned improvements include:

- [ ] Structured Information Element fingerprinting
- [ ] IE ordering and length analysis
- [ ] Vendor-specific IE fingerprinting
- [ ] Sliding-window sequence-stream analysis
- [ ] Detection of competing sequence trajectories
- [ ] Improved timing feature validation
- [ ] Higher-fidelity authorized lab simulations
- [ ] Multi-session benign datasets
- [ ] Session-separated train / validation / test evaluation
- [ ] True Positive Rate measurement
- [ ] False Positive Rate measurement
- [ ] Precision, Recall, and F1 evaluation
- [ ] Detection-latency measurement
- [ ] Attack-fidelity evaluation
- [ ] Ablation study
- [ ] Threat-score calibration
- [ ] Synthetic reproducible public test dataset
- [ ] Unit tests with pytest
- [ ] GitHub Actions continuous integration
- [ ] Improved documentation and architecture diagrams

---

# 🧪 Planned Evaluation Strategy

Future evaluation will test progressively more challenging attacker configurations.

Example progression:

```text
Level 1
Same SSID, different BSSID

Level 2
Same SSID with similar security configuration

Level 3
Copied beacon structure

Level 4
Same SSID and BSSID

Level 5
Same BSSID with higher-fidelity IE structure

Level 6
Improved sequence behavior

Level 7
Higher-fidelity beacon reproduction
```

The objective is to determine which detection layers remain useful as attacker fidelity increases.

---

# 🔬 Planned Ablation Study

The hybrid architecture will also be evaluated by removing individual detection components.

Planned comparisons include:

```text
Full hybrid detector

Without sequence analysis

Without IE fingerprinting

Without timing analysis

Without Isolation Forest

Rule-based layers only

ML layer only
```

This will help measure the contribution of each component rather than assuming that every feature improves detection.

---

# 🔒 Privacy & Public Dataset Policy

Wireless captures can contain real:

- SSIDs
- BSSIDs / MAC addresses
- Network characteristics
- Environmental information

For privacy reasons, real neighborhood captures and generated profiles are not included in the public repository.

Public examples should use synthetic or anonymized identifiers such as:

```text
LAB_AP_01
AA:BB:CC:DD:EE:FF
```

Future releases are planned to include synthetic datasets that allow detector logic to be tested without exposing real nearby networks.

---

# ⚖️ Ethical Use

This project is intended for:

- Cybersecurity education
- Wireless-security research
- Defensive monitoring
- Controlled laboratory experimentation
- Networks owned by the researcher
- Environments where explicit authorization has been granted

Do not use the simulation or packet-injection functionality against networks or devices you do not own or have explicit permission to test.

---

# 📌 Project Status

**Current Version:** `v0.8`

**Status:** Research prototype / working laboratory system

The project currently demonstrates:

- Live 802.11 beacon monitoring
- Multi-AP behavioral profiling
- BSSID-spoofing detection
- Sequence-behavior analysis
- IE and security fingerprint comparison
- Timing analysis with jitter filtering
- Per-BSSID Isolation Forest models
- Real-time evidence-based alerting

The next development phase focuses on **stronger experimental validation, higher-fidelity testing, reproducibility, and automated testing**.

---

# 📜 License

This project is released under the **MIT License**.

See [`LICENSE`](LICENSE) for details.

---

# 👤 Author

**Adnan Sadi**

BS Computer Science  
University of Agriculture Peshawar

Areas of interest:

- Cybersecurity
- Network Security
- Wireless Security
- Cloud Security
- Intrusion Detection
- AI-assisted Cybersecurity

GitHub: [@Adnanibnsadi](https://github.com/Adnanibnsadi)

---

> ⭐ This repository documents an ongoing undergraduate cybersecurity research and engineering project. Feedback, technical discussion, and research suggestions are welcome.

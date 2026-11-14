# Wireless Intrusion Detection System (WIDS)

**Version:** 0.8 | **Status:** Research Prototype

This project explores how Wi-Fi beacon characteristics can be used to detect Evil Twin and BSSID-spoofing attacks.

I developed a Python-based wireless intrusion detection prototype that uses Scapy to capture IEEE 802.11 beacon frames and compare them against previously collected access-point profiles.

The detector combines sequence-number analysis, basic beacon Information Element comparisons, security-configuration checks, timing measurements, and per-BSSID Isolation Forest models to identify suspicious activity.

## Why I started this project

An Evil Twin access point can imitate the SSID of a legitimate wireless network. More advanced attacks can also copy its BSSID, making identification based on network names and MAC addresses less reliable.

I wanted to investigate whether other characteristics of beacon traffic could help distinguish between legitimate access points and devices impersonating them.

During development, I encountered challenges with timing measurements, particularly when collecting traffic through a USB Wi-Fi adapter in Kali Linux running inside VMware.

The project is still experimental. My current focus is improving detection reliability, reducing false alerts, and evaluating the system under more varied network conditions.

## Detection Architecture

The detector follows a five-stage workflow, from capturing Wi-Fi beacon frames to generating security alerts.

### 1. Beacon Capture

Scapy captures IEEE 802.11 beacon frames using a compatible Wi-Fi adapter in monitor mode.

### 2. Feature Extraction

The system extracts information such as SSID, BSSID, channel, signal strength (RSSI), sequence numbers, beacon timestamps, security configuration, and Information Element counts.

### 3. Access Point Profiling

Captured observations are compared against previously collected profiles of known access points. Each profile represents the expected characteristics of a particular BSSID.

### 4. Suspicious Behavior Detection

The detector combines multiple checks:

- Sequence-number inconsistencies
- Unexpected BSSID or security-configuration changes
- Beacon Information Element deviations
- Timing anomalies
- Per-BSSID Isolation Forest anomaly scores, where a trained model is available

These checks provide different types of evidence. An unusual observation alone does not necessarily indicate an attack.

### 5. Evidence Scoring and Alerts

The system combines suspicious indicators into a threat score.

To reduce alerts caused by isolated or noisy observations, the detector uses a consecutive-suspicion threshold and per-BSSID alert cooldowns.

When the configured conditions are met, it generates an alert for further investigation.

**Note:** The system is a research prototype. Its alerts indicate potentially suspicious wireless behavior, not confirmed attacker identity.

## Why a Hybrid Detector?

I chose a hybrid approach because relying on a single characteristic of Wi-Fi beacon traffic can produce misleading results.

For example, two legitimate access points may share the same SSID, while changes in signal strength or beacon timing can occur without an attack.

The detector therefore uses several indicators rather than relying entirely on one rule or machine-learning prediction.

### Detection Methods

| Detection method | What it checks |
|---|---|
| Sequence-number analysis | Looks for unexpected sequence behavior, including duplicate or conflicting observations associated with a BSSID. |
| SSID and BSSID comparison | Identifies access points that differ from previously recorded network profiles. |
| Information Element comparison | Checks for differences in beacon structure, currently using basic characteristics such as IE counts. |
| Security configuration | Compares advertised security characteristics with the known AP profile. |
| Supported-rate comparison | Looks for differences in supported-rate counts. |
| Timing analysis | Examines unusual beacon timing and clock-skew estimates, while accounting for measurement noise. |
| Isolation Forest | Identifies observations that differ from the behavioral baseline learned for an individual BSSID. |

### How the Results Are Combined

The rule-based checks provide interpretable indicators, while Isolation Forest adds another way to identify unusual behavior that may not be captured by fixed rules.

These indicators contribute to a combined suspicion score. The detector also requires consecutive suspicious observations before generating an alert.

The current weights and thresholds were selected during prototype development. They are not statistically calibrated attack probabilities.

This approach helps investigate suspicious wireless activity, but an alert alone cannot confirm that an Evil Twin attack has occurred. Broader testing is still needed to understand false alerts and detection reliability.
## Features Extracted from Beacon Frames

The detector uses information from IEEE 802.11 beacon frames to study the behavior of nearby access points.

Some features are extracted directly from captured frames, while others are calculated by comparing observations collected over time.

### Beacon Information

| Feature | Purpose |
|---|---|
| SSID | Identifies the advertised wireless network name. |
| BSSID | Identifies the access point's advertised MAC address. |
| RSSI | Records received signal strength as contextual information. |
| Channel | Identifies the advertised wireless channel. |
| Sequence number | Helps examine changes and inconsistencies in frame sequence behavior. |
| Beacon timestamp (TSF) | Provides timing information advertised by the transmitter. |
| Beacon interval | Describes the advertised interval between beacon transmissions. |
| Security configuration | Supports comparisons with known access-point characteristics. |
| Information Element count | Provides a basic measure of beacon structure. |
| Supported-rate count | Helps identify differences in advertised capabilities. |

### Derived Features

The detector also calculates behavioral indicators from successive observations:

- **Sequence jumps:** Changes between observed sequence numbers.
- **Duplicate-sequence indicators:** Potentially conflicting sequence observations associated with the same BSSID.
- **Inter-beacon timing:** Elapsed time between captured beacon observations.
- **Clock-skew estimates:** Timing-related deviations calculated from beacon observations.

These measurements have limitations. For example, missing frames and channel hopping can affect sequence and timing calculations, while RSSI can change because of movement or environmental conditions.

For this reason, individual feature deviations are treated as evidence for further analysis rather than automatic proof of an attack.



## Per-Access-Point Profiling

Different access points can have different beacon characteristics, even when they belong to the same wireless network.

Instead of comparing every captured frame against one general baseline, the project builds behavioral profiles for individual BSSIDs.

The profiling workflow collects observations from known access points and summarizes their expected characteristics, including beacon structure, security configuration, sequence behavior, and timing measurements.

These profiles provide a reference for evaluating new observations.

For example, if an access point normally advertises a particular security configuration and beacon structure, unexpected changes may contribute to the detector's suspicion score.

The goal is to identify behavior that differs from an access point's observed baseline, rather than assuming that every unusual frame represents an Evil Twin attack.

**Current limitation:** A BSSID is an advertised identifier, not proof of a device's physical identity. Profiles can also be affected by noisy measurements, limited observation periods, or changes in legitimate access-point configuration.

## Machine Learning Layer

I use Isolation Forest as an additional detection method alongside the rule-based checks.

The idea is to learn the normal behavior of a known access point and identify observations that differ from that baseline.

### Model Training

The current workflow uses observations collected from known access points during baseline monitoring.

For BSSIDs with sufficient observations, the system trains a separate Isolation Forest model and stores its associated feature scaler.

The model uses four behavioral features:

| Feature | Description |
|---|---|
| `clock_skew` | Estimated timing deviation derived from beacon observations. |
| `rssi` | Received signal strength of the observed beacon. |
| `seq_jump` | Difference between successive observed sequence numbers. |
| `inter_beacon_ms` | Time between successive captured beacon observations, in milliseconds. |

Training models separately allows the detector to compare an access point's behavior against its own collected baseline rather than treating every AP as identical.

### Anomaly Detection

During monitoring, the system can evaluate new observations using the corresponding BSSID's trained model.

Isolation Forest identifies patterns that differ from the training data. An anomalous prediction may contribute to the detector's combined suspicion score.

The model does not directly identify an Evil Twin attacker. It detects unusual behavior that may have several possible explanations.

### Secondary Model

The research workflow also includes a separate global Isolation Forest model trained on engineered deviation features.

The per-BSSID models remain the primary focus of the current ML-assisted detection approach.

### Current Limitations

The machine-learning component is experimental.

In particular:

- RSSI can change because of movement, distance, or interference.
- Timing measurements can be affected by packet loss, channel hopping, and virtualization.
- A limited training dataset may not represent normal behavior across different environments.
- An anomaly score is not the probability that an attack has occurred.
- The current prototype has not undergone sufficiently broad independent testing to establish reliable detection and false-positive rates.

My next goal is to evaluate the models using separate capture sessions and compare the results with the rule-based detector.

This should help determine whether machine learning provides a measurable improvement rather than assuming that adding it automatically makes detection more accurate.

## Timing & VMware Considerations

One of the challenges I encountered during development was obtaining reliable timing measurements from Wi-Fi beacon frames.

Most of my testing was performed using Kali Linux inside VMware, with an external USB Wi-Fi adapter operating in monitor mode.

### The Problem

The detector uses beacon timestamps and the intervals between observations to identify unusual timing behavior.

However, several factors can affect these measurements:

- **Channel hopping:** The adapter may miss beacons while monitoring other channels.
- **USB and VMware scheduling:** Delays can affect when captured packets reach the monitoring application.
- **Packet loss:** Missing frames can create unexpectedly large gaps between observations.
- **Receiver and driver behaviour:** Local processing delays can introduce additional measurement noise.

During initial testing, some legitimate access points produced suspicious timing readings even when no attack was being performed.

### How I Addressed It

I introduced a timing filter that limits when clock-skew evidence is considered reliable.

The detector uses timing evidence only when consecutive captured beacon observations fall within a defined time window. Observations separated by larger gaps are not treated as equally reliable for clock-skew analysis.

This reduced the influence of channel-hopping gaps and timing noise during my development tests.

### What I Learned

These experiments showed me that unusual timing measurements do not necessarily indicate malicious activity.

The monitoring environment itself can influence the observations, especially when wireless capture is performed through a virtual machine.

For this reason, timing anomalies are treated as supporting evidence rather than proof of transmitter impersonation.

### Remaining Work

I still need to evaluate how consistently this filtering approach performs across different Wi-Fi adapters, capture sessions, and monitoring environments.

A useful next experiment would compare timing measurements collected inside VMware with those collected directly on Linux hardware under similar conditions.

## Alert Logic

The detector does not generate an alert whenever it encounters an unusual beacon frame.

During development, I found that individual measurements can be affected by packet loss, channel hopping, or changes in normal access-point behavior. To reduce unnecessary alerts, the system combines several indicators and checks whether suspicious observations persist.

### 1. Evidence Scoring

The detector evaluates indicators such as sequence-number inconsistencies, beacon-structure deviations, security-configuration changes, timing anomalies, and machine-learning results.

These indicators contribute to a combined suspicion score using predefined weights.

The score represents the strength of the observed evidence. It is not a statistically calibrated probability of an attack.

### 2. Suspicious Observation Streak

A suspicious score from a single observation is not normally sufficient to generate an alert.

The detector tracks consecutive suspicious observations and uses a configurable streak threshold before triggering an alert.

This helps prevent isolated anomalies from immediately being reported as security incidents.

### 3. Per-BSSID Alert Cooldown

After an alert is generated, a cooldown mechanism limits repeated alerts associated with the same BSSID.

This reduces repetitive notifications when suspicious observations continue over a short period.

### 4. Alert Interpretation

An alert indicates that the observed beacon behaviour differs from the expected access-point profile or contains other suspicious characteristics.

It does not independently confirm an Evil Twin attack or identify the physical device responsible.

### Current Limitations

The scoring weights, thresholds, and cooldown settings are part of the current prototype configuration.

Further testing is needed to determine how these settings affect detection sensitivity, false alerts, and detection latency across different wireless environments.

## Demonstrated Lab Results

The following observations were recorded during local development and controlled laboratory testing.

These are preliminary experimental results, not a comprehensive evaluation of detection accuracy.

### 1. Multi-AP Baseline Collection

During baseline collection, I recorded approximately:

- 9,500 beacon observations
- 15 unique BSSIDs
- 20 minutes of monitoring

After filtering access points with insufficient observations, 12 AP profiles were generated.

These profiles were used to establish reference characteristics for subsequent detection experiments.

The original capture data is not publicly distributed because it contains information about nearby wireless networks.

### 2. Benign Monitoring

After adjusting the timing filter to reduce capture-related noise, I monitored more than 1,300 beacon observations during a controlled benign session.

No alerts were observed during that session.

This is a limited experimental observation. It should not be interpreted as a validated 0% false-positive rate.

Additional independent sessions are needed to evaluate how the detector behaves under different network conditions.

### 3. Controlled BSSID-Spoofing Experiment

I tested the detector using a laboratory transmitter configured to advertise the same BSSID as an access point in the baseline.

The detector generated an alert during this experiment.

The observed suspicious indicators included combinations of:

- Duplicate sequence-number activity
- Beacon Information Element count differences
- Advertised security-configuration differences
- Timing deviations
- Machine-learning anomaly evidence

The experiment demonstrates that the prototype can identify the tested spoofing scenario.

However, the simulated transmitter did not reproduce every characteristic of the legitimate access point. This result therefore does not establish reliable detection of highly sophisticated or perfectly cloned Evil Twin attacks.

### 4. Evaluation Limitations

The current experiments are limited by:

- A relatively small number of monitoring sessions
- A single primary development environment
- Limited attack scenarios
- Wireless timing noise and packet loss
- Lack of an independently evaluated test dataset

The raw development captures and complete experimental logs are not currently available in this public repository.

### 5. Next Evaluation Goals

I plan to expand testing using separate benign and attack sessions.

Future evaluation will focus on:

- Detection rate across different spoofing scenarios
- False alerts during independent benign sessions
- Detection latency
- Performance with multiple legitimate APs sharing an SSID
- The contribution of each detection method through ablation testing

My goal is to understand which indicators provide reliable evidence under realistic wireless conditions, rather than relying on isolated successful demonstrations.
## Visualizations

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

## Repository Structure

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

# Installation

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

# Testing

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
- Threat-score aggregation and threshold behaviour

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

# Advanced Multi-AP Workflow

The newer research workflow supports collecting legitimate traffic from multiple nearby APs and building individual behavioural profiles.

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

This creates behavioural profiles for APs with sufficient observations.

---

## Build Advanced Models

```bash
sudo ./venv/bin/python3 scripts/build_advanced_model.py
```

This trains per-BSSID Isolation Forest models and the secondary global anomaly model.

Generated datasets, profiles, and model files are intentionally excluded from the public repository and should be rebuilt from the user's own environment.

---

# Current Research Questions

This prototype is being developed around two main questions:

> **How effectively can passive 802.11 beacon fingerprints distinguish a legitimate access point from an increasingly high-fidelity BSSID-spoofed Evil Twin?**

and

> **Which combination of sequence behaviour, beacon structure, timing characteristics, and anomaly detection provides useful attack detection while maintaining a low false-alert rate?**

---

# Current Limitations

Version 0.8 is a research prototype and has several important limitations.

### Limited Dataset Diversity

Current experiments were conducted in a limited number of environments.

A larger evaluation should include:

- Multiple locations
- Multiple capture sessions
- Different days and times
- More AP manufacturers
- Different wireless adapters

---

### Correlated Beacon Observations

Thousands of beacon frames do not necessarily represent thousands of statistically independent observations.

Future ML evaluation will therefore separate training and testing by **capture session** rather than randomly splitting neighbouring beacon rows.

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

They are **threat/suspicion scores**, not statistically calibrated attack probabilities.

Future versions will evaluate and tune these parameters using independent validation sessions.

---

# Roadmap to v1.0

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

# Planned Evaluation Strategy

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
Improved sequence behaviour

Level 7
Higher-fidelity beacon reproduction
```

The objective is to determine which detection layers remain useful as attacker fidelity increases.

---

# Planned Ablation Study

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

# Privacy & Public Dataset Policy

Wireless captures can contain real:

- SSIDs
- BSSIDs / MAC addresses
- Network characteristics
- Environmental information

For privacy reasons, real neighbourhood captures and generated profiles are not included in the public repository.

Public examples should use synthetic or anonymized identifiers such as:

```text
LAB_AP_01
AA:BB:CC:DD:EE:FF
```

Future releases are planned to include synthetic datasets that allow detector logic to be tested without exposing real nearby networks.

---

# Ethical Use

This project is intended for:

- Cybersecurity education
- Wireless-security research
- Defensive monitoring
- Controlled laboratory experimentation
- Networks owned by the researcher
- Environments where explicit authorization has been granted

Do not use the simulation or packet-injection functionality against networks or devices you do not own or have explicit permission to test.

---

# Project Status

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

# License

This project is released under the **MIT License**.

See [`LICENSE`](LICENSE) for details.

---

# Author

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

> This repository documents an ongoing undergraduate cybersecurity research and engineering project. Feedback, technical discussion, and research suggestions are welcome.
